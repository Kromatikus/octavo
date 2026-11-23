//! Dudect-style constant-time timing harness for the N3 portable Rust block function.
//!
//! Source under test: a *writable copy* of frozen /workspace/octavo_n3_001
//! at /workspace/octavo_n3_dudect1. The freeze itself is not modified.
//!
//! Methodology (Oreparaz, Balasch, Faust, CHES 2018 / dudect):
//!   - two input classes, randomly interleaved in a balanced list
//!   - cycle counts via lfence + rdtsc (constant_tsc CPU)
//!   - Welch's t-test on raw times and on times cropped at the pooled 99th percentile
//!   - verdict: |t| > 4.5 "likely leak", |t| > 10 "definite leak"
//!
//! Dudect can detect a leak; it cannot prove the absence of one.
//!
//! Timed regions never include key-schedule construction except in the explicit
//! `schedule-key` experiment, which is expected to leak (rejection sampling).
//! N3 has no sealed-file / tag-compare API in this draft, so there is no v9 test.

#![deny(unused_must_use)]

use octavo_n3_draft3::{gfni_available, Cipher, BLOCK_LEN, NONCE_LEN, SEED_LEN};
use std::env;
use std::fs;
use std::hint::black_box;
use std::io::{self, Write};
use std::process;
use std::time::{Duration, Instant};

const POOL: usize = 16;
const WARMUP: usize = 2048;
fn backend_label() -> &'static str {
    octavo_n3_draft3::Backend::detect().name()
}

// --------------------------- RNG (xoshiro256**) ---------------------------

struct Rng {
    s: [u64; 4],
}

impl Rng {
    fn seed(mut x: u64) -> Self {
        fn splitmix(x: &mut u64) -> u64 {
            *x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = *x;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        Self {
            s: [
                splitmix(&mut x),
                splitmix(&mut x),
                splitmix(&mut x),
                splitmix(&mut x),
            ],
        }
    }
    fn next_u64(&mut self) -> u64 {
        let result = self.s[1]
            .wrapping_mul(5)
            .rotate_left(7)
            .wrapping_mul(9);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        result
    }
    fn fill(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i + 8 <= buf.len() {
            buf[i..i + 8].copy_from_slice(&self.next_u64().to_le_bytes());
            i += 8;
        }
        if i < buf.len() {
            let r = self.next_u64().to_le_bytes();
            let n = buf.len() - i;
            buf[i..].copy_from_slice(&r[..n]);
        }
    }
    fn seed_bytes(&mut self, out: &mut [u8; SEED_LEN]) {
        self.fill(out);
        if out.iter().all(|&b| b == 0) {
            out[0] = 1;
        }
    }
}

// --------------------------- cycle timer ---------------------------

#[inline(always)]
fn cycles() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_mm_mfence();
        core::arch::x86_64::_mm_lfence();
        let t = core::arch::x86_64::_rdtsc();
        core::arch::x86_64::_mm_lfence();
        t
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

fn calibrate_hz() -> f64 {
    let wall0 = Instant::now();
    let c0 = cycles();
    while wall0.elapsed() < Duration::from_millis(80) {
        core::hint::spin_loop();
    }
    let c1 = cycles();
    let dt = wall0.elapsed().as_secs_f64();
    (c1 - c0) as f64 / dt
}

// --------------------------- stats ---------------------------

struct Welford {
    n: u64,
    mean: f64,
    m2: f64,
}

impl Welford {
    fn new() -> Self {
        Self {
            n: 0,
            mean: 0.0,
            m2: 0.0,
        }
    }
    fn push(&mut self, x: f64) {
        self.n += 1;
        let d = x - self.mean;
        self.mean += d / self.n as f64;
        let d2 = x - self.mean;
        self.m2 += d * d2;
    }
    fn var(&self) -> f64 {
        if self.n < 2 {
            0.0
        } else {
            self.m2 / (self.n - 1) as f64
        }
    }
}

fn welch_t(a: &Welford, b: &Welford) -> f64 {
    if a.n < 2 || b.n < 2 {
        return 0.0;
    }
    let va = a.var() / a.n as f64;
    let vb = b.var() / b.n as f64;
    let den = (va + vb).sqrt();
    if den == 0.0 {
        0.0
    } else {
        (a.mean - b.mean) / den
    }
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

struct Report {
    experiment: String,
    backend: String,
    class0_name: String,
    class1_name: String,
    n0: usize,
    n1: usize,
    n0_crop: usize,
    n1_crop: usize,
    mean0: f64,
    mean1: f64,
    mean0_crop: f64,
    mean1_crop: f64,
    std0: f64,
    std1: f64,
    std0_crop: f64,
    std1_crop: f64,
    median0: f64,
    median1: f64,
    p99_pooled: u64,
    t_raw: f64,
    t_crop: f64,
    hz: f64,
    elapsed_s: f64,
    notes: String,
}

impl Report {
    fn verdict_str(t: f64) -> &'static str {
        let a = t.abs();
        if a > 10.0 {
            "DEFINITE_LEAK"
        } else if a > 4.5 {
            "LIKELY_LEAK"
        } else {
            "NO_EVIDENCE"
        }
    }
    fn to_json(&self) -> String {
        format!(
            concat!(
                "{{\n",
                "  \"experiment\": \"{}\",\n",
                "  \"backend\": \"{}\",\n",
                "  \"class0\": \"{}\",\n",
                "  \"class1\": \"{}\",\n",
                "  \"n0\": {},\n",
                "  \"n1\": {},\n",
                "  \"n0_crop\": {},\n",
                "  \"n1_crop\": {},\n",
                "  \"mean0_cycles\": {:.4},\n",
                "  \"mean1_cycles\": {:.4},\n",
                "  \"mean0_crop_cycles\": {:.4},\n",
                "  \"mean1_crop_cycles\": {:.4},\n",
                "  \"std0_cycles\": {:.4},\n",
                "  \"std1_cycles\": {:.4},\n",
                "  \"std0_crop_cycles\": {:.4},\n",
                "  \"std1_crop_cycles\": {:.4},\n",
                "  \"median0_cycles\": {:.4},\n",
                "  \"median1_cycles\": {:.4},\n",
                "  \"p99_pooled_cycles\": {},\n",
                "  \"t_raw\": {:.6},\n",
                "  \"t_crop\": {:.6},\n",
                "  \"abs_t_crop\": {:.6},\n",
                "  \"verdict\": \"{}\",\n",
                "  \"hz\": {:.1},\n",
                "  \"elapsed_s\": {:.3},\n",
                "  \"notes\": {}\n",
                "}}\n"
            ),
            escape(&self.experiment),
            escape(&self.backend),
            escape(&self.class0_name),
            escape(&self.class1_name),
            self.n0,
            self.n1,
            self.n0_crop,
            self.n1_crop,
            self.mean0,
            self.mean1,
            self.mean0_crop,
            self.mean1_crop,
            self.std0,
            self.std1,
            self.std0_crop,
            self.std1_crop,
            self.median0,
            self.median1,
            self.p99_pooled,
            self.t_raw,
            self.t_crop,
            self.t_crop.abs(),
            Self::verdict_str(self.t_crop),
            self.hz,
            self.elapsed_s,
            json_str(&self.notes),
        )
    }
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
fn json_str(s: &str) -> String {
    format!("\"{}\"", escape(s))
}

fn finish_stats(
    times0: &[u64],
    times1: &[u64],
    crop_at: u64,
) -> (Welford, Welford, Welford, Welford, usize, usize) {
    let mut raw0 = Welford::new();
    let mut raw1 = Welford::new();
    let mut c0 = Welford::new();
    let mut c1 = Welford::new();
    let mut n0c = 0usize;
    let mut n1c = 0usize;
    for &t in times0 {
        raw0.push(t as f64);
        if t <= crop_at {
            c0.push(t as f64);
            n0c += 1;
        }
    }
    for &t in times1 {
        raw1.push(t as f64);
        if t <= crop_at {
            c1.push(t as f64);
            n1c += 1;
        }
    }
    (raw0, raw1, c0, c1, n0c, n1c)
}

fn median_of(mut v: Vec<u64>) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.sort_unstable();
    let n = v.len();
    if n % 2 == 0 {
        (v[n / 2 - 1] as f64 + v[n / 2] as f64) / 2.0
    } else {
        v[n / 2] as f64
    }
}

fn make_report(
    experiment: &str,
    backend: &str,
    class0: &str,
    class1: &str,
    times0: &[u64],
    times1: &[u64],
    hz: f64,
    elapsed_s: f64,
    notes: &str,
) -> Report {
    let mut pooled: Vec<u64> = Vec::with_capacity(times0.len() + times1.len());
    pooled.extend_from_slice(times0);
    pooled.extend_from_slice(times1);
    pooled.sort_unstable();
    let p99 = percentile(&pooled, 0.99);
    let (r0, r1, c0, c1, n0c, n1c) = finish_stats(times0, times1, p99);
    Report {
        experiment: experiment.to_string(),
        backend: backend.to_string(),
        class0_name: class0.to_string(),
        class1_name: class1.to_string(),
        n0: times0.len(),
        n1: times1.len(),
        n0_crop: n0c,
        n1_crop: n1c,
        mean0: r0.mean,
        mean1: r1.mean,
        mean0_crop: c0.mean,
        mean1_crop: c1.mean,
        std0: r0.var().sqrt(),
        std1: r1.var().sqrt(),
        std0_crop: c0.var().sqrt(),
        std1_crop: c1.var().sqrt(),
        median0: median_of(times0.to_vec()),
        median1: median_of(times1.to_vec()),
        p99_pooled: p99,
        t_raw: welch_t(&r0, &r1),
        t_crop: welch_t(&c0, &c1),
        hz,
        elapsed_s,
        notes: notes.to_string(),
    }
}

// --------------------------- experiment engine ---------------------------

struct Args {
    experiment: String,
    seconds: f64,
    max_samples: usize,
    out: Option<String>,
}

fn parse_args() -> Args {
    let mut experiment = String::new();
    let mut seconds = 30.0;
    let mut max_samples: usize = 2_000_000;
    let mut out = None;
    let mut it = env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--experiment" | "-e" => experiment = it.next().expect("missing --experiment value"),
            "--backend" | "-b" => {
                let _ = it.next();
            }
            "--seconds" | "-s" => {
                seconds = it
                    .next()
                    .expect("missing --seconds")
                    .parse()
                    .expect("bad --seconds")
            }
            "--max-samples" => {
                max_samples = it
                    .next()
                    .expect("missing --max-samples")
                    .parse()
                    .expect("bad --max-samples")
            }
            "--out" | "-o" => out = Some(it.next().expect("missing --out value")),
            "--help" | "-h" => {
                eprint_help();
                process::exit(0);
            }
            other => {
                eprintln!("unknown arg: {other}");
                eprint_help();
                process::exit(2);
            }
        }
    }
    if experiment.is_empty() {
        eprintln!("--experiment is required");
        eprint_help();
        process::exit(2);
    }
    Args {
        experiment,
        seconds,
        max_samples,
        out,
    }
}

fn eprint_help() {
    eprintln!(
        "octavo-n3-dudect --experiment enc-pt|enc-key|enc-key-interleaved|enc-key-twokey|dec-pt|dec-key|schedule-key|enc-pt-batch16|dec-pt-batch16|enc-key-batch16|enc-pt-batch32|dec-pt-batch32|enc-key-batch32|enc-pt-batch64|dec-pt-batch64|enc-key-batch64|dec-key-batch64\n\
         \t--seconds N --max-samples N --out path.json"
    );
}

fn fixed_seed() -> [u8; SEED_LEN] {
    let mut s = [0u8; SEED_LEN];
    for (i, b) in s.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(17).wrapping_add(0xA5);
    }
    s
}

fn fixed_nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    for (i, b) in n.iter_mut().enumerate() {
        *b = (i as u8).wrapping_add(1);
    }
    n
}

fn fixed_block() -> [u8; BLOCK_LEN] {
    let mut b = [0u8; BLOCK_LEN];
    for (i, x) in b.iter_mut().enumerate() {
        *x = (i as u8).wrapping_mul(3).wrapping_add(0x11);
    }
    b
}

/// Balanced, shuffled class bits of length n (n even).
fn class_bits(n: usize, rng: &mut Rng) -> Vec<u8> {
    let mut v = vec![0u8; n];
    for i in 0..n / 2 {
        v[i] = 1;
    }
    for i in (1..n).rev() {
        let j = (rng.next_u64() as usize) % (i + 1);
        v.swap(i, j);
    }
    v
}

fn run_loop<F>(
    seconds: f64,
    max_samples: usize,
    mut rng: Rng,
    mut body: F,
) -> (Vec<u64>, Vec<u64>, f64)
where
    F: FnMut(u8, &mut Rng) -> u64,
{
    let n = (max_samples.max(2) / 2) * 2;
    let classes = class_bits(n, &mut rng);
    for &c in classes.iter().take(WARMUP.min(n)) {
        let _ = body(c, &mut rng);
    }
    let mut t0 = Vec::with_capacity(n / 2);
    let mut t1 = Vec::with_capacity(n / 2);
    let wall = Instant::now();
    let budget = Duration::from_secs_f64(seconds);
    for &c in &classes {
        if wall.elapsed() >= budget && (t0.len() + t1.len()) >= 20_000 {
            break;
        }
        let dt = body(c, &mut rng);
        if c == 0 {
            t0.push(dt);
        } else {
            t1.push(dt);
        }
    }
    (t0, t1, wall.elapsed().as_secs_f64())
}

fn measure_enc_pt(seconds: f64, max_samples: usize, hz: f64) -> Report {
    let seed = fixed_seed();
    let nonce = fixed_nonce();
    let cipher = Cipher::new(&seed, &nonce);
    let fixed = fixed_block();
    let mut rng = Rng::seed(0xD1DE_C700_0000_0001);
    let mut rand_blocks = vec![[0u8; BLOCK_LEN]; 4096];
    for b in rand_blocks.iter_mut() {
        rng.fill(b);
    }
    let mut idx = 0usize;
    let (t0, t1, elapsed) = run_loop(seconds, max_samples, rng, |class, _| {
        let block = if class == 0 {
            fixed
        } else {
            let b = rand_blocks[idx % rand_blocks.len()];
            idx += 1;
            b
        };
        let s = cycles();
        let out = black_box(&cipher).encrypt_block(black_box(&block));
        let e = cycles();
        black_box(out);
        e.wrapping_sub(s)
    });
    make_report(
        "enc-pt",
        backend_label(),
        "fixed plaintext",
        "random plaintext",
        &t0,
        &t1,
        hz,
        elapsed,
        "Fixed schedule (outside the timed region). Times encrypt_block only.",
    )
}

fn measure_dec_pt(seconds: f64, max_samples: usize, hz: f64) -> Report {
    let seed = fixed_seed();
    let nonce = fixed_nonce();
    let cipher = Cipher::new(&seed, &nonce);
    let fixed = cipher.encrypt_block(&fixed_block());
    let mut rng = Rng::seed(0xD1DE_C700_0000_0002);
    let mut rand_blocks = vec![[0u8; BLOCK_LEN]; 4096];
    for b in rand_blocks.iter_mut() {
        rng.fill(b);
    }
    let mut idx = 0usize;
    let (t0, t1, elapsed) = run_loop(seconds, max_samples, rng, |class, _| {
        let block = if class == 0 {
            fixed
        } else {
            let b = rand_blocks[idx % rand_blocks.len()];
            idx += 1;
            b
        };
        let s = cycles();
        let out = black_box(&cipher).decrypt_block(black_box(&block));
        let e = cycles();
        black_box(out);
        e.wrapping_sub(s)
    });
    make_report(
        "dec-pt",
        backend_label(),
        "fixed ciphertext",
        "random block",
        &t0,
        &t1,
        hz,
        elapsed,
        "Fixed schedule (outside the timed region). Times decrypt_block only.",
    )
}

/// Equal-footprint key pools: class 0 is POOL copies of the same seed,
/// class 1 is POOL distinct random seeds. Each trial picks a slot uniformly.
/// Schedules are built before timing starts.
fn build_key_pools(rng: &mut Rng) -> (Vec<Cipher>, Vec<Cipher>) {
    let nonce = fixed_nonce();
    let fixed = fixed_seed();
    let mut pool0 = Vec::with_capacity(POOL);
    for _ in 0..POOL {
        pool0.push(Cipher::new(&fixed, &nonce));
    }
    let mut pool1 = Vec::with_capacity(POOL);
    for _ in 0..POOL {
        let mut seed = [0u8; SEED_LEN];
        rng.seed_bytes(&mut seed);
        pool1.push(Cipher::new(&seed, &nonce));
    }
    (pool0, pool1)
}

fn measure_enc_key(seconds: f64, max_samples: usize, hz: f64) -> Report {
    let mut rng = Rng::seed(0xD1DE_C700_0000_0010);
    let (pool0, pool1) = build_key_pools(&mut rng);
    let pt = fixed_block();
    let mut slot = 0usize;
    let (t0, t1, elapsed) = run_loop(seconds, max_samples, rng, |class, _| {
        let i = slot % POOL;
        slot += 1;
        let block = pt;
        let cipher = if class == 0 { &pool0[i] } else { &pool1[i] };
        let s = cycles();
        let out = black_box(cipher).encrypt_block(black_box(&block));
        let e = cycles();
        black_box(out);
        e.wrapping_sub(s)
    });
    make_report(
        "enc-key",
        backend_label(),
        "fixed key (16 cached copies)",
        "16 random keys (cached)",
        &t0,
        &t1,
        hz,
        elapsed,
        "Schedules precomputed. Equal-footprint pools so cache residency is matched. Times encrypt_block only.",
    )
}

fn measure_dec_key(seconds: f64, max_samples: usize, hz: f64) -> Report {
    let mut rng = Rng::seed(0xD1DE_C700_0000_0011);
    let (pool0, pool1) = build_key_pools(&mut rng);
    let mut ct = fixed_block();
    ct[0] ^= 0xFF;
    let mut slot = 0usize;
    let (t0, t1, elapsed) = run_loop(seconds, max_samples, rng, |class, _| {
        let i = slot % POOL;
        slot += 1;
        let block = ct;
        let cipher = if class == 0 { &pool0[i] } else { &pool1[i] };
        let s = cycles();
        let out = black_box(cipher).decrypt_block(black_box(&block));
        let e = cycles();
        black_box(out);
        e.wrapping_sub(s)
    });
    make_report(
        "dec-key",
        backend_label(),
        "fixed key (16 cached copies)",
        "16 random keys (cached)",
        &t0,
        &t1,
        hz,
        elapsed,
        "Schedules precomputed. Equal-footprint pools so cache residency is matched. Times decrypt_block only.",
    )
}

/// Interleaved layout follow-up: one slot from each pool, alternating in memory.
fn measure_enc_key_interleaved(seconds: f64, max_samples: usize, hz: f64) -> Report {
    let mut rng = Rng::seed(0xD1DE_C700_0000_0012);
    let (pool0, pool1) = build_key_pools(&mut rng);
    let pt = fixed_block();
    let mut slot = 0usize;
    let (t0, t1, elapsed) = run_loop(seconds, max_samples, rng, |class, _| {
        let i = slot % POOL;
        slot += 1;
        let block = pt;
        let cipher = if class == 0 { &pool0[i] } else { &pool1[i] };
        let s = cycles();
        let out = black_box(cipher).encrypt_block(black_box(&block));
        let e = cycles();
        black_box(out);
        e.wrapping_sub(s)
    });
    make_report(
        "enc-key-interleaved",
        backend_label(),
        "fixed key (16 cached copies)",
        "16 random keys (cached)",
        &t0,
        &t1,
        hz,
        elapsed,
        "Follow-up for a flagged enc-key. Schedules precomputed; same equal-footprint pools, fresh RNG seed.",
    )
}

/// Two equally hot keys (not one vs many).
fn measure_enc_key_twokey(seconds: f64, max_samples: usize, hz: f64) -> Report {
    let nonce = fixed_nonce();
    let mut rng = Rng::seed(0xD1DE_C700_0000_0013);
    let mut seed1 = [0u8; SEED_LEN];
    rng.seed_bytes(&mut seed1);
    let mut pool0 = Vec::with_capacity(POOL);
    let mut pool1 = Vec::with_capacity(POOL);
    for _ in 0..POOL {
        pool0.push(Cipher::new(&fixed_seed(), &nonce));
        pool1.push(Cipher::new(&seed1, &nonce));
    }
    let pt = fixed_block();
    let mut slot = 0usize;
    let (t0, t1, elapsed) = run_loop(seconds, max_samples, rng, |class, _| {
        let i = slot % POOL;
        slot += 1;
        let block = pt;
        let cipher = if class == 0 { &pool0[i] } else { &pool1[i] };
        let s = cycles();
        let out = black_box(cipher).encrypt_block(black_box(&block));
        let e = cycles();
        black_box(out);
        e.wrapping_sub(s)
    });
    make_report(
        "enc-key-twokey",
        backend_label(),
        "key A (16 cached copies)",
        "key B (16 cached copies)",
        &t0,
        &t1,
        hz,
        elapsed,
        "Follow-up: two equally hot keys, equal footprint. Times encrypt_block only.",
    )
}


fn measure_enc_pt_batch(seconds: f64, max_samples: usize, hz: f64, width: usize) -> Report {
    let seed = fixed_seed();
    let nonce = fixed_nonce();
    let cipher = Cipher::new(&seed, &nonce);
    let fixed = vec![fixed_block(); width];
    let mut rng = Rng::seed(0xD1DE_C700_00B0_0001 ^ (width as u64));
    let mut rand_pool = vec![vec![[0u8; BLOCK_LEN]; width]; 256];
    for batch in rand_pool.iter_mut() {
        for b in batch.iter_mut() {
            rng.fill(b);
        }
    }
    let mut work = vec![[0u8; BLOCK_LEN]; width];
    let mut idx = 0usize;
    let (t0, t1, elapsed) = run_loop(seconds, max_samples, rng, |class, _| {
        if class == 0 {
            work.copy_from_slice(&fixed);
        } else {
            work.copy_from_slice(&rand_pool[idx % rand_pool.len()]);
            idx += 1;
        }
        let s = cycles();
        black_box(&cipher).encrypt_blocks(black_box(&mut work));
        let e = cycles();
        black_box(&work);
        e.wrapping_sub(s)
    });
    make_report(
        &format!("enc-pt-batch{width}"),
        backend_label(),
        "fixed plaintext batch",
        "random plaintext batch",
        &t0,
        &t1,
        hz,
        elapsed,
        &format!("Fixed schedule (outside the timed region). Times encrypt_blocks on {width} independent blocks."),
    )
}

fn measure_dec_pt_batch(seconds: f64, max_samples: usize, hz: f64, width: usize) -> Report {
    let seed = fixed_seed();
    let nonce = fixed_nonce();
    let cipher = Cipher::new(&seed, &nonce);
    let mut fixed = vec![fixed_block(); width];
    cipher.encrypt_blocks(&mut fixed);
    let mut rng = Rng::seed(0xD1DE_C700_00B0_0002 ^ (width as u64));
    let mut rand_pool = vec![vec![[0u8; BLOCK_LEN]; width]; 256];
    for batch in rand_pool.iter_mut() {
        for b in batch.iter_mut() {
            rng.fill(b);
        }
        cipher.encrypt_blocks(batch);
    }
    let mut work = vec![[0u8; BLOCK_LEN]; width];
    let mut idx = 0usize;
    let (t0, t1, elapsed) = run_loop(seconds, max_samples, rng, |class, _| {
        if class == 0 {
            work.copy_from_slice(&fixed);
        } else {
            work.copy_from_slice(&rand_pool[idx % rand_pool.len()]);
            idx += 1;
        }
        let s = cycles();
        black_box(&cipher).decrypt_blocks(black_box(&mut work));
        let e = cycles();
        black_box(&work);
        e.wrapping_sub(s)
    });
    make_report(
        &format!("dec-pt-batch{width}"),
        backend_label(),
        "fixed ciphertext batch",
        "random ciphertext batch",
        &t0,
        &t1,
        hz,
        elapsed,
        &format!("Fixed schedule (outside the timed region). Times decrypt_blocks on {width} independent blocks."),
    )
}

fn measure_dec_key_batch(seconds: f64, max_samples: usize, hz: f64, width: usize) -> Report {
    let mut rng = Rng::seed(0xD1DE_C700_00B0_0011 ^ (width as u64));
    let (pool0, pool1) = build_key_pools(&mut rng);
    let pt = vec![fixed_block(); width];
    let mut cts0 = vec![vec![[0u8; BLOCK_LEN]; width]; POOL];
    let mut cts1 = vec![vec![[0u8; BLOCK_LEN]; width]; POOL];
    for i in 0..POOL {
        cts0[i].copy_from_slice(&pt);
        pool0[i].encrypt_blocks(&mut cts0[i]);
        cts1[i].copy_from_slice(&pt);
        pool1[i].encrypt_blocks(&mut cts1[i]);
    }
    let mut work = vec![[0u8; BLOCK_LEN]; width];
    let mut slot = 0usize;
    let (t0, t1, elapsed) = run_loop(seconds, max_samples, rng, |class, _| {
        let i = slot % POOL;
        slot += 1;
        if class == 0 {
            work.copy_from_slice(&cts0[i]);
        } else {
            work.copy_from_slice(&cts1[i]);
        }
        let cipher = if class == 0 { &pool0[i] } else { &pool1[i] };
        let s = cycles();
        black_box(cipher).decrypt_blocks(black_box(&mut work));
        let e = cycles();
        black_box(&work);
        e.wrapping_sub(s)
    });
    make_report(
        &format!("dec-key-batch{width}"),
        backend_label(),
        "fixed key (16 cached copies)",
        "16 random keys (cached)",
        &t0,
        &t1,
        hz,
        elapsed,
        &format!("Schedules and ciphertexts precomputed. Times decrypt_blocks on {width} independent blocks."),
    )
}

fn measure_enc_key_batch(seconds: f64, max_samples: usize, hz: f64, width: usize) -> Report {
    let mut rng = Rng::seed(0xD1DE_C700_00B0_0010 ^ (width as u64));
    let (pool0, pool1) = build_key_pools(&mut rng);
    let pt = vec![fixed_block(); width];
    let mut work = vec![[0u8; BLOCK_LEN]; width];
    let mut slot = 0usize;
    let (t0, t1, elapsed) = run_loop(seconds, max_samples, rng, |class, _| {
        let i = slot % POOL;
        slot += 1;
        work.copy_from_slice(&pt);
        let cipher = if class == 0 { &pool0[i] } else { &pool1[i] };
        let s = cycles();
        black_box(cipher).encrypt_blocks(black_box(&mut work));
        let e = cycles();
        black_box(&work);
        e.wrapping_sub(s)
    });
    make_report(
        &format!("enc-key-batch{width}"),
        backend_label(),
        "fixed key (16 cached copies)",
        "16 random keys (cached)",
        &t0,
        &t1,
        hz,
        elapsed,
        &format!("Schedules precomputed. Times encrypt_blocks on {width} independent blocks."),
    )
}

fn measure_schedule_key(seconds: f64, max_samples: usize, hz: f64) -> Report {
    let nonce = fixed_nonce();
    let fixed = fixed_seed();
    let mut rng = Rng::seed(0xD1DE_C700_0000_0050);
    let mut seeds = vec![[0u8; SEED_LEN]; 1024];
    for s in seeds.iter_mut() {
        rng.seed_bytes(s);
    }
    let mut idx = 0usize;
    let (t0, t1, elapsed) = run_loop(seconds, max_samples, rng, |class, _| {
        let seed = if class == 0 {
            fixed
        } else {
            let s = seeds[idx % seeds.len()];
            idx += 1;
            s
        };
        let s = cycles();
        let c = Cipher::new(black_box(&seed), black_box(&nonce));
        let e = cycles();
        black_box(c);
        e.wrapping_sub(s)
    });
    make_report(
        "schedule-key",
        backend_label(),
        "fixed seed",
        "random seed",
        &t0,
        &t1,
        hz,
        elapsed,
        "EXPECTED leak: Cipher::new uses key-dependent rejection sampling (invertible bit-matrices, S2 != S, S_mid distinct from both) and rebuilds the public Field tables each time. Documented as not constant-time in the key.",
    )
}

fn main() {
    let args = parse_args();
    if !gfni_available() {
        eprintln!("GFNI/AVX-512 not available; cannot run GFNI dudect");
        process::exit(3);
    }
    let hz = calibrate_hz();
    eprintln!("calibrated {:.3} GHz  experiment={}", hz / 1e9, args.experiment);
    let report = match args.experiment.as_str() {
        "enc-pt" => measure_enc_pt(args.seconds, args.max_samples, hz),
        "enc-key" => measure_enc_key(args.seconds, args.max_samples, hz),
        "enc-key-interleaved" => measure_enc_key_interleaved(args.seconds, args.max_samples, hz),
        "enc-key-twokey" => measure_enc_key_twokey(args.seconds, args.max_samples, hz),
        "dec-pt" => measure_dec_pt(args.seconds, args.max_samples, hz),
        "dec-key" => measure_dec_key(args.seconds, args.max_samples, hz),
        "enc-pt-batch16" => measure_enc_pt_batch(args.seconds, args.max_samples, hz, 16),
        "dec-pt-batch16" => measure_dec_pt_batch(args.seconds, args.max_samples, hz, 16),
        "enc-key-batch16" => measure_enc_key_batch(args.seconds, args.max_samples, hz, 16),
        "enc-pt-batch32" => measure_enc_pt_batch(args.seconds, args.max_samples, hz, 32),
        "dec-pt-batch32" => measure_dec_pt_batch(args.seconds, args.max_samples, hz, 32),
        "enc-key-batch32" => measure_enc_key_batch(args.seconds, args.max_samples, hz, 32),
        "enc-pt-batch64" => measure_enc_pt_batch(args.seconds, args.max_samples, hz, 64),
        "dec-pt-batch64" => measure_dec_pt_batch(args.seconds, args.max_samples, hz, 64),
        "enc-key-batch64" => measure_enc_key_batch(args.seconds, args.max_samples, hz, 64),
        "dec-key-batch64" => measure_dec_key_batch(args.seconds, args.max_samples, hz, 64),
        "schedule-key" => measure_schedule_key(args.seconds, args.max_samples, hz),
        other => {
            eprintln!("unknown experiment {other}");
            eprint_help();
            process::exit(2);
        }
    };

    let json = report.to_json();
    print!("{json}");
    io::stdout().flush().ok();
    if let Some(path) = args.out {
        if let Some(dir) = std::path::Path::new(&path).parent() {
            if !dir.as_os_str().is_empty() {
                fs::create_dir_all(dir).expect("create out dir");
            }
        }
        fs::write(&path, &json).expect("write out");
        eprintln!("wrote {path}");
    }
    eprintln!(
        "n0={} n1={} n0_crop={} n1_crop={} mean0={:.1} mean1={:.1} t_raw={:.3} t_crop={:.3} verdict={}",
        report.n0,
        report.n1,
        report.n0_crop,
        report.n1_crop,
        report.mean0,
        report.mean1,
        report.t_raw,
        report.t_crop,
        Report::verdict_str(report.t_crop)
    );
}
