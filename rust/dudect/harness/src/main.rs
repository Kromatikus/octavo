//! Dudect-style constant-time timing harness for the Octavo rust/ tree.
//! Ported from the earlier local dudect work; new: batched data path, VPSLLVW rotation hooks, bow layers,
//! streaming open (1 thread and the 2-thread overlap path).
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
//! `schedule-key` experiment, which is *expected* to leak (rejection sampling).

#![deny(unused_must_use)]

use octavo_core::backend::{force_backend, selected_backend, BackendKind};
use octavo_core::formats::stream::{open_stream, seal_stream, StreamOptions};
use octavo_core::formats::{open_rehearsal, seal_rehearsal};
use octavo_core::simd::dudect_hooks as hooks;
use octavo_core::{Cipher, BLOCK_LEN, NONCE_LEN, SEED_LEN};
use std::env;
use std::fs;
use std::hint::black_box;
use std::io::{self, Write};
use std::process;
use std::time::{Duration, Instant};

const POOL: usize = 16;
const WARMUP: usize = 2048;

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
    fn next_u8(&mut self) -> u8 {
        (self.next_u64() >> 3) as u8
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
        // avoid the all-zero seed used as a weak-key reject in the app layer
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
        // fallback, should not run on the intended target CPU
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

fn finish_stats(times0: &[u64], times1: &[u64], crop_at: u64) -> (Welford, Welford, Welford, Welford, usize, usize) {
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
    backend: String,
    seconds: f64,
    max_samples: usize,
    out: Option<String>,
}

fn parse_args() -> Args {
    let mut experiment = String::new();
    let mut backend = String::from("auto");
    let mut seconds = 40.0;
    let mut max_samples: usize = 8_000_000;
    let mut out = None;
    let mut it = env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--experiment" | "-e" => experiment = it.next().expect("missing --experiment value"),
            "--backend" | "-b" => backend = it.next().expect("missing --backend value"),
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
        backend,
        seconds,
        max_samples,
        out,
    }
}

fn eprint_help() {
    eprintln!(
        "octavo-dudect --experiment ENC_PT|ENC_KEY|ENC_KEY_INTERLEAVED|ENC_KEY_TWOKEY|DEC_PT|DEC_KEY|V9_TAG_POS|V9_VALID_TAMPER|SCHEDULE_KEY\n\
         \t--backend gfni-simd|gfni-512|gfni-256|gfni-128|aes-ni|ct-soft|auto\n\
         \t--seconds N --max-samples N --out path.json"
    );
}

fn select_backend(name: &str) -> BackendKind {
    if name == "auto" {
        let k = BackendKind::detect();
        force_backend(None);
        return k;
    }
    let k = BackendKind::from_name(name).unwrap_or_else(|| {
        eprintln!("unknown backend {name}");
        process::exit(2);
    });
    if !k.available() {
        eprintln!("backend {name} is not available on this CPU");
        process::exit(3);
    }
    force_backend(Some(k));
    k
}

fn fixed_seed() -> [u8; SEED_LEN] {
    let mut s = [0u8; SEED_LEN];
    // distinctive, not all-zero, stable across runs
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

fn new_cipher(seed: &[u8; SEED_LEN], nonce: &[u8; NONCE_LEN]) -> Cipher {
    Cipher::new(seed, nonce)
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
    // warmup with the same body, discarded
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

fn measure_enc_pt(kind: BackendKind, seconds: f64, max_samples: usize, hz: f64) -> Report {
    let seed = fixed_seed();
    let nonce = fixed_nonce();
    let cipher = new_cipher(&seed, &nonce);
    assert_eq!(selected_backend(), kind);
    let fixed = fixed_block();
    // pre-generate a ring of random blocks so the RNG is outside the timed region
    let mut rng = Rng::seed(0xD1DE_C700_0000_0001);
    let mut rand_blocks = vec![[0u8; BLOCK_LEN]; 4096];
    for b in rand_blocks.iter_mut() {
        rng.fill(b);
    }
    let mut idx = 0usize;
    let (t0, t1, elapsed) = run_loop(seconds, max_samples, rng, |class, _| {
        let mut block = if class == 0 {
            fixed
        } else {
            let b = rand_blocks[idx % rand_blocks.len()];
            idx += 1;
            b
        };
        let s = cycles();
        black_box(&cipher).encrypt_block(black_box(&mut block));
        let e = cycles();
        black_box(block);
        e.wrapping_sub(s)
    });
    make_report(
        "enc-pt",
        kind.name(),
        "fixed plaintext",
        "random plaintext",
        &t0,
        &t1,
        hz,
        elapsed,
        "Fixed schedule (outside the timed region). Times encrypt_block only.",
    )
}

fn measure_dec_pt(kind: BackendKind, seconds: f64, max_samples: usize, hz: f64) -> Report {
    let seed = fixed_seed();
    let nonce = fixed_nonce();
    let cipher = new_cipher(&seed, &nonce);
    // class 0: a fixed ciphertext (encrypt of the fixed block). class 1: random blocks,
    // which are valid inputs to the permutation even if they are not a real ciphertext.
    let mut fixed = fixed_block();
    cipher.encrypt_block(&mut fixed);
    let mut rng = Rng::seed(0xD1DE_C700_0000_0002);
    let mut rand_blocks = vec![[0u8; BLOCK_LEN]; 4096];
    for b in rand_blocks.iter_mut() {
        rng.fill(b);
    }
    let mut idx = 0usize;
    let (t0, t1, elapsed) = run_loop(seconds, max_samples, rng, |class, _| {
        let mut block = if class == 0 {
            fixed
        } else {
            let b = rand_blocks[idx % rand_blocks.len()];
            idx += 1;
            b
        };
        let s = cycles();
        black_box(&cipher).decrypt_block(black_box(&mut block));
        let e = cycles();
        black_box(block);
        e.wrapping_sub(s)
    });
    make_report(
        "dec-pt",
        kind.name(),
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
        pool0.push(new_cipher(&fixed, &nonce));
    }
    let mut pool1 = Vec::with_capacity(POOL);
    for _ in 0..POOL {
        let mut seed = [0u8; SEED_LEN];
        rng.seed_bytes(&mut seed);
        pool1.push(new_cipher(&seed, &nonce));
    }
    (pool0, pool1)
}

fn measure_enc_key(kind: BackendKind, seconds: f64, max_samples: usize, hz: f64) -> Report {
    let mut rng = Rng::seed(0xD1DE_C700_0000_0010);
    let (pool0, pool1) = build_key_pools(&mut rng);
    let pt = fixed_block();
    let mut slot = 0usize;
    let (t0, t1, elapsed) = run_loop(seconds, max_samples, rng, |class, _| {
        let i = slot % POOL;
        slot += 1;
        let mut block = pt;
        let cipher = if class == 0 { &pool0[i] } else { &pool1[i] };
        let s = cycles();
        black_box(cipher).encrypt_block(black_box(&mut block));
        let e = cycles();
        black_box(block);
        e.wrapping_sub(s)
    });
    make_report(
        "enc-key",
        kind.name(),
        "fixed key (16 cached copies)",
        "16 random keys (cached)",
        &t0,
        &t1,
        hz,
        elapsed,
        "Schedules precomputed. Equal-footprint pools so cache residency is matched. Times encrypt_block only.",
    )
}

fn measure_dec_key(kind: BackendKind, seconds: f64, max_samples: usize, hz: f64) -> Report {
    let mut rng = Rng::seed(0xD1DE_C700_0000_0011);
    let (pool0, pool1) = build_key_pools(&mut rng);
    // decrypt a fixed 128-byte buffer (contents do not need to be a valid CT)
    let ct = {
        let mut b = fixed_block();
        // scramble a bit so it is not a typical low-hamming plaintext
        b[0] ^= 0xFF;
        b
    };
    let mut slot = 0usize;
    let (t0, t1, elapsed) = run_loop(seconds, max_samples, rng, |class, _| {
        let i = slot % POOL;
        slot += 1;
        let mut block = ct;
        let cipher = if class == 0 { &pool0[i] } else { &pool1[i] };
        let s = cycles();
        black_box(cipher).decrypt_block(black_box(&mut block));
        let e = cycles();
        black_box(block);
        e.wrapping_sub(s)
    });
    make_report(
        "dec-key",
        kind.name(),
        "fixed key (16 cached copies)",
        "16 random keys (cached)",
        &t0,
        &t1,
        hz,
        elapsed,
        "Schedules precomputed. Equal-footprint pools so cache residency is matched. Times decrypt_block only.",
    )
}

fn make_v9_blob() -> ([u8; SEED_LEN], Vec<u8>) {
    let seed = fixed_seed();
    let pickup = [0x51u8; 16];
    let nonce = fixed_nonce();
    let msg = b"dudect v9 tag-compare message";
    let (blob, _tag) = seal_rehearsal(&seed, msg, &pickup, &nonce, 128, b"ad")
        .expect("seal_rehearsal");
    assert!(blob.len() >= 72 + 160);
    (seed, blob)
}

fn measure_v9_tag_pos(kind: BackendKind, seconds: f64, max_samples: usize, hz: f64) -> Report {
    let (seed, blob) = make_v9_blob();
    // class 0: flip first tag byte; class 1: flip last tag byte. Both must fail Auth.
    let mut first = blob.clone();
    let mut last = blob.clone();
    let n = first.len();
    first[n - 32] ^= 0x01;
    last[n - 1] ^= 0x01;
    // confirm both fail (untimed)
    assert!(open_rehearsal(&seed, &first, b"ad").is_err());
    assert!(open_rehearsal(&seed, &last, b"ad").is_err());
    let rng = Rng::seed(0xD1DE_C700_0000_0090);
    let (t0, t1, elapsed) = run_loop(seconds, max_samples, rng, |class, _| {
        let buf = if class == 0 { &first } else { &last };
        let s = cycles();
        let r = open_rehearsal(black_box(&seed), black_box(buf), black_box(b"ad"));
        let e = cycles();
        black_box(r.err());
        e.wrapping_sub(s)
    });
    make_report(
        "v9-tag-pos",
        kind.name(),
        "tag wrong at first byte",
        "tag wrong at last byte",
        &t0,
        &t1,
        hz,
        elapsed,
        "Both classes fail the chunk MAC and return before schedule/decrypt. This isolates whether the MAC compare short-circuits on the first differing byte.",
    )
}

fn measure_v9_valid_tamper(kind: BackendKind, seconds: f64, max_samples: usize, hz: f64) -> Report {
    let (seed, blob) = make_v9_blob();
    let mut bad = blob.clone();
    let n = bad.len();
    bad[n - 1] ^= 0x01;
    assert!(open_rehearsal(&seed, &blob, b"ad").is_ok());
    assert!(open_rehearsal(&seed, &bad, b"ad").is_err());
    let rng = Rng::seed(0xD1DE_C700_0000_0091);
    let (t0, t1, elapsed) = run_loop(seconds, max_samples, rng, |class, _| {
        let buf = if class == 0 { &blob } else { &bad };
        let s = cycles();
        let r = open_rehearsal(black_box(&seed), black_box(buf), black_box(b"ad"));
        let e = cycles();
        black_box(r.ok().map(|v| v.len()));
        e.wrapping_sub(s)
    });
    make_report(
        "v9-valid-tamper",
        kind.name(),
        "valid tag (then decrypts)",
        "tampered tag (Auth, no decrypt)",
        &t0,
        &t1,
        hz,
        elapsed,
        "EXPECTED large |t|: open_rehearsal verifies the tag chain first and only then builds the schedule and decrypts. A gap here is early-exit after a failed MAC, not a leak in ct_eq itself. See v9-tag-pos for the compare.",
    )
}

fn measure_schedule_key(_kind: BackendKind, seconds: f64, max_samples: usize, hz: f64) -> Report {
    // Backend is selected so prepare() is part of Cipher::new, which is what we time.
    let nonce = fixed_nonce();
    let fixed = fixed_seed();
    // pre-generate a ring of random seeds so RNG is outside the timed region
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
        let c: Cipher = Cipher::new(black_box(&seed), black_box(&nonce));
        let e = cycles();
        black_box(c.rounds());
        e.wrapping_sub(s)
    });
    make_report(
        "schedule-key",
        selected_backend().name(),
        "fixed seed",
        "random seed",
        &t0,
        &t1,
        hz,
        elapsed,
        "EXPECTED leak: Schedule::new uses key-dependent rejection sampling and S2≠S retries, then Auto::prepare. This is documented as not constant-time with respect to the key.",
    )
}


fn measure_enc_key_interleaved(kind: BackendKind, seconds: f64, max_samples: usize, hz: f64) -> Report {
    let mut rng = Rng::seed(0xD1DE_C700_0000_0020);
    let nonce = fixed_nonce();
    let fixed = fixed_seed();
    let mut pairs: Vec<(Cipher, Cipher)> = Vec::with_capacity(POOL);
    for _ in 0..POOL {
        let mut seed = [0u8; SEED_LEN];
        rng.seed_bytes(&mut seed);
        pairs.push((new_cipher(&fixed, &nonce), new_cipher(&seed, &nonce)));
    }
    let pt = fixed_block();
    let mut slot = 0usize;
    let (t0, t1, elapsed) = run_loop(seconds, max_samples, rng, |class, _| {
        let i = slot % POOL;
        slot += 1;
        let mut block = pt;
        let cipher = if class == 0 { &pairs[i].0 } else { &pairs[i].1 };
        let s = cycles();
        black_box(cipher).encrypt_block(black_box(&mut block));
        let e = cycles();
        black_box(block);
        e.wrapping_sub(s)
    });
    make_report(
        "enc-key-interleaved",
        kind.name(),
        "fixed key (paired layout)",
        "random key (paired layout)",
        &t0,
        &t1,
        hz,
        elapsed,
        "Follow-up for enc-key: 16 (fixed, random) pairs in one Vec so pool addresses are interleaved. Times encrypt_block only.",
    )
}

fn measure_enc_key_twokey(kind: BackendKind, seconds: f64, max_samples: usize, hz: f64) -> Report {
    let mut rng = Rng::seed(0xD1DE_C700_0000_0021);
    let nonce = fixed_nonce();
    let seed0 = fixed_seed();
    let mut seed1 = [0u8; SEED_LEN];
    rng.seed_bytes(&mut seed1);
    let c0 = new_cipher(&seed0, &nonce);
    let c1 = new_cipher(&seed1, &nonce);
    let pt = fixed_block();
    let (t0, t1, elapsed) = run_loop(seconds, max_samples, rng, |class, _| {
        let mut block = pt;
        let cipher = if class == 0 { &c0 } else { &c1 };
        let s = cycles();
        black_box(cipher).encrypt_block(black_box(&mut block));
        let e = cycles();
        black_box(block);
        e.wrapping_sub(s)
    });
    make_report(
        "enc-key-twokey",
        kind.name(),
        "key A (fixed seed)",
        "key B (one random seed)",
        &t0,
        &t1,
        hz,
        elapsed,
        "Follow-up for enc-key: only two precomputed ciphers, used equally. A gap here is a value-dependent timing difference, not a many-key cache-residency effect.",
    )
}


// =========================== merged-tree experiments ===========================

const BATCH: usize = 8;

fn rand_ring(rng: &mut Rng, n: usize, len: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|_| {
            let mut v = vec![0u8; len];
            rng.fill(&mut v);
            v
        })
        .collect()
}

fn measure_batch_pt(kind: BackendKind, seconds: f64, max_samples: usize, hz: f64, decrypt: bool) -> Report {
    let cipher = new_cipher(&fixed_seed(), &fixed_nonce());
    assert_eq!(selected_backend(), kind);
    let mut fixed = [[0u8; BLOCK_LEN]; BATCH];
    for (j, b) in fixed.iter_mut().enumerate() {
        *b = fixed_block();
        b[0] ^= j as u8;
    }
    if decrypt {
        cipher.encrypt_blocks(&mut fixed);
    }
    let mut rng = Rng::seed(0xD1DE_C700_0000_0101 + decrypt as u64);
    let mut ring = vec![[[0u8; BLOCK_LEN]; BATCH]; 1024];
    for g in ring.iter_mut() {
        for b in g.iter_mut() {
            rng.fill(b);
        }
    }
    let mut idx = 0usize;
    let (t0, t1, elapsed) = run_loop(seconds, max_samples, rng, |class, _| {
        let mut blocks = if class == 0 {
            fixed
        } else {
            idx += 1;
            ring[idx % ring.len()]
        };
        let s = cycles();
        if decrypt {
            black_box(&cipher).decrypt_blocks(black_box(&mut blocks[..]));
        } else {
            black_box(&cipher).encrypt_blocks(black_box(&mut blocks[..]));
        }
        let e = cycles();
        black_box(blocks);
        e.wrapping_sub(s)
    });
    make_report(
        if decrypt { "dec-batch-pt" } else { "enc-batch-pt" },
        kind.name(),
        if decrypt { "8 fixed ciphertext blocks" } else { "8 fixed plaintext blocks" },
        "8 random blocks",
        &t0,
        &t1,
        hz,
        elapsed,
        "Fixed schedule. Times encrypt_blocks/decrypt_blocks on 8 blocks (gfni-simd: two 4-block packed zmm chains, the path v9 uses).",
    )
}

fn need_simd(kind: BackendKind) {
    if !octavo_core::simd::available() {
        eprintln!("gfni-simd hooks need GFNI + AVX-512 BW/VL/VBMI");
        process::exit(3);
    }
    let _ = kind;
}

/// VPSLLVW rotation: class 0 = fixed amounts (all 1 or `fixed_amt`), class 1 = random amounts
/// (1..=7 per byte) or all 7. Data fixed in both classes, so only the shift counts differ.
fn measure_vrot(kind: BackendKind, seconds: f64, max_samples: usize, hz: f64, wide: bool, extreme: bool) -> Report {
    need_simd(kind);
    let iters: u32 = env::var("OCTAVO_DUDECT_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(512);
    let mut rng = Rng::seed(0xD1DE_C700_0000_0200 + 2 * wide as u64 + extreme as u64);
    let mut x0 = [0u8; 64];
    rng.fill(&mut x0);
    // matched memory path: both classes read their amounts from a 4096-entry ring at the same index
    let ring0 = vec![[1u8; 64]; 4096];
    let mut ring = vec![[0u8; 64]; 4096];
    // A/A control (OCTAVO_DUDECT_AA=1): class 1 goes through the same ring but holds class-0 data
    let aa = env::var("OCTAVO_DUDECT_AA").map(|v| v == "1").unwrap_or(false);
    for r in ring.iter_mut() {
        if aa {
            *r = [1u8; 64];
        } else if extreme {
            *r = [7u8; 64];
        } else {
            for b in r.iter_mut() {
                *b = 1 + (rng.next_u8() % 7);
            }
        }
    }
    let mut idx = 0usize;
    let (t0, t1, elapsed) = run_loop(seconds, max_samples, rng, |class, _| {
        idx += 1;
        let r = if class == 0 { ring0[idx % ring0.len()] } else { ring[idx % ring.len()] };
        let mut x = x0;
        let s;
        let e;
        if wide {
            s = cycles();
            hooks::vrot_chain512(black_box(&mut x), black_box(&r), iters);
            e = cycles();
        } else {
            let mut x16: [u8; 16] = x[..16].try_into().unwrap();
            let r16: [u8; 16] = r[..16].try_into().unwrap();
            s = cycles();
            hooks::vrot_chain128(black_box(&mut x16), black_box(&r16), iters);
            e = cycles();
            black_box(x16);
        }
        black_box(x);
        e.wrapping_sub(s)
    });
    let name = match (wide, extreme) {
        (true, false) => "vrot512-amt",
        (true, true) => "vrot512-1v7",
        (false, false) => "vrot128-amt",
        (false, true) => "vrot128-1v7",
    };
    make_report(
        name,
        kind.name(),
        "all rotation amounts = 1",
        if extreme { "all rotation amounts = 7" } else { "random amounts 1..7 per byte" },
        &t0,
        &t1,
        hz,
        elapsed,
        &format!("Direct test of the bow rotation (PSHUFB byte-dup + VPSLLVW + blend): {iters} dependent rotations per sample, same data, only the per-byte shift counts differ."),
    )
}

/// Whole bow / unbow layer (7 strokes, amounts derived from the state): fixed state vs random state.
fn measure_bow(kind: BackendKind, seconds: f64, max_samples: usize, hz: f64, wide: bool, inverse: bool) -> Report {
    need_simd(kind);
    let sch = octavo_core::schedule::Schedule::new(&fixed_seed(), &fixed_nonce());
    let key = octavo_core::simd::SimdKey::new(&sch).expect("simd key");
    let mut rng = Rng::seed(0xD1DE_C700_0000_0300 + 2 * wide as u64 + inverse as u64);
    let len = if wide { 4 * BLOCK_LEN } else { BLOCK_LEN };
    // matched memory path: both classes copy their state from a 4096-entry ring at the same index
    let ring0 = vec![vec![0u8; len]; 4096];
    let mut ring = rand_ring(&mut rng, 4096, len);
    // A/A control (OCTAVO_DUDECT_AA=1): class 1 goes through the same ring but holds class-0 data
    if env::var("OCTAVO_DUDECT_AA").map(|v| v == "1").unwrap_or(false) {
        ring.iter_mut().for_each(|r| r.fill(0));
    }
    let reps: u32 = env::var("OCTAVO_DUDECT_REPS").ok().and_then(|v| v.parse().ok()).unwrap_or(32);
    let mut idx = 0usize;
    let (t0, t1, elapsed) = run_loop(seconds, max_samples, rng, |class, _| {
        idx += 1;
        let src = if class == 0 { &ring0[idx % ring0.len()] } else { &ring[idx % ring.len()] };
        let (s, e);
        if wide {
            let mut st = [0u8; 4 * BLOCK_LEN];
            st.copy_from_slice(src);
            s = cycles();
            hooks::bow_layer512(black_box(&key), black_box(&mut st), inverse, reps);
            e = cycles();
            black_box(st);
        } else {
            let mut st = [0u8; BLOCK_LEN];
            st.copy_from_slice(src);
            s = cycles();
            hooks::bow_layer128(black_box(&key), black_box(&mut st), inverse, reps);
            e = cycles();
            black_box(st);
        }
        e.wrapping_sub(s)
    });
    let name = match (wide, inverse) {
        (false, false) => "bow128-state",
        (false, true) => "unbow128-state",
        (true, false) => "bow512-state",
        (true, true) => "unbow512-state",
    };
    make_report(
        name,
        kind.name(),
        "all-zero state (all amounts 1)",
        "random state (data-dependent amounts)",
        &t0,
        &t1,
        hz,
        elapsed,
        &format!("{reps} dependent bow/unbow layers on a caller-chosen state (zero is a fixed point: amounts stay 1); the rotation amounts come from the state, so this times the data-dependent VPSLLVW rotations in context."),
    )
}

const S_PICKUP: [u8; 16] = [0x51; 16];
const S_CS: usize = 1024;
const S_LEN: usize = 3 * S_CS + 500; // 4 chunks, last one partial

fn stream_seal(seed: &[u8; SEED_LEN], msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    seal_stream(seed, &mut &msg[..], &mut out, &S_PICKUP, &fixed_nonce(), b"ad", &StreamOptions { chunk_size: S_CS, threads: 1, batch_chunks: 8 }).expect("seal_stream");
    out
}

/// Streaming open of valid blobs: fixed message vs random messages (same key, pickup, nonce and
/// length, so the per-stream schedule is identical; last byte forced non-zero in both classes so
/// the padding scan length matches).
fn measure_stream_open_pt(kind: BackendKind, seconds: f64, max_samples: usize, hz: f64, threads: usize) -> Report {
    let seed = fixed_seed();
    let mut fixed_msg: Vec<u8> = (0..S_LEN).map(|i| (i as u8).wrapping_mul(7).wrapping_add(3)).collect();
    fixed_msg[S_LEN - 1] = 0x5a;
    let fixed_blob = stream_seal(&seed, &fixed_msg);
    let mut rng = Rng::seed(0xD1DE_C700_0000_0400 + threads as u64);
    let ring: Vec<Vec<u8>> = (0..256)
        .map(|_| {
            let mut m = vec![0u8; S_LEN];
            rng.fill(&mut m);
            m[S_LEN - 1] |= 1;
            stream_seal(&seed, &m)
        })
        .collect();
    let opts = StreamOptions { chunk_size: S_CS, threads, batch_chunks: 8 };
    let mut sink = Vec::with_capacity(S_LEN + 1024);
    // sanity (untimed)
    open_stream(&seed, &mut &fixed_blob[..], &mut sink, b"ad", &opts).expect("open fixed");
    assert_eq!(sink, fixed_msg);
    let mut idx = 0usize;
    let (t0, t1, elapsed) = run_loop(seconds, max_samples, rng, |class, _| {
        let blob = if class == 0 {
            &fixed_blob
        } else {
            idx += 1;
            &ring[idx % ring.len()]
        };
        sink.clear();
        let s = cycles();
        let r = open_stream(black_box(&seed), &mut &blob[..], &mut sink, b"ad", &opts);
        let e = cycles();
        black_box(r.is_ok());
        e.wrapping_sub(s)
    });
    make_report(
        if threads > 1 { "stream-open-pt-mt" } else { "stream-open-pt" },
        kind.name(),
        "valid stream, fixed message",
        "valid stream, random messages",
        &t0,
        &t1,
        hz,
        elapsed,
        &format!("open_stream (feature stream) over a 4-chunk v9 blob, chunk 1024, threads={threads} (threads>1 = decrypt overlapped with the tag chain). Includes per-stream schedule setup (identical for both classes)."),
    )
}

/// Streaming open, both classes forged: chunk-0 tag wrong at its first vs last byte.
fn measure_stream_tag_pos(kind: BackendKind, seconds: f64, max_samples: usize, hz: f64, threads: usize) -> Report {
    let seed = fixed_seed();
    let msg: Vec<u8> = (0..S_LEN).map(|i| (i as u8) ^ 0x3c).collect();
    let blob = stream_seal(&seed, &msg);
    let tag0 = 72 + S_CS; // chunk 0 tag offset
    let mut first = blob.clone();
    let mut last = blob.clone();
    first[tag0] ^= 1;
    last[tag0 + 31] ^= 1;
    let opts = StreamOptions { chunk_size: S_CS, threads, batch_chunks: 8 };
    let mut sink = Vec::new();
    assert!(open_stream(&seed, &mut &first[..], &mut sink, b"ad", &opts).is_err());
    assert!(open_stream(&seed, &mut &last[..], &mut sink, b"ad", &opts).is_err());
    assert!(sink.is_empty(), "forged stream released plaintext");
    let rng = Rng::seed(0xD1DE_C700_0000_0500 + threads as u64);
    let (t0, t1, elapsed) = run_loop(seconds, max_samples, rng, |class, _| {
        let b = if class == 0 { &first } else { &last };
        sink.clear();
        let s = cycles();
        let r = open_stream(black_box(&seed), &mut &b[..], &mut sink, b"ad", &opts);
        let e = cycles();
        black_box(r.is_err());
        e.wrapping_sub(s)
    });
    make_report(
        if threads > 1 { "stream-tag-pos-mt" } else { "stream-tag-pos" },
        kind.name(),
        "chunk-0 tag wrong at first byte",
        "chunk-0 tag wrong at last byte",
        &t0,
        &t1,
        hz,
        elapsed,
        &format!("open_stream, threads={threads}; both classes fail Auth. Isolates the streaming tag compare."),
    )
}

fn main() {
    let args = parse_args();
    let kind = select_backend(&args.backend);
    eprintln!(
        "octavo-dudect experiment={} backend={} (requested {}) seconds={} max_samples={}",
        args.experiment,
        kind.name(),
        args.backend,
        args.seconds,
        args.max_samples
    );
    eprintln!("calibrating TSC...");
    let hz = calibrate_hz();
    eprintln!("TSC ≈ {:.3} GHz", hz / 1e9);

    let exp = args.experiment.to_lowercase().replace('_', "-");
    let report = match exp.as_str() {
        "enc-pt" => measure_enc_pt(kind, args.seconds, args.max_samples, hz),
        "enc-key" => measure_enc_key(kind, args.seconds, args.max_samples, hz),
        "enc-key-interleaved" => measure_enc_key_interleaved(kind, args.seconds, args.max_samples, hz),
        "enc-key-twokey" => measure_enc_key_twokey(kind, args.seconds, args.max_samples, hz),
        "dec-pt" => measure_dec_pt(kind, args.seconds, args.max_samples, hz),
        "dec-key" => measure_dec_key(kind, args.seconds, args.max_samples, hz),
        "v9-tag-pos" => measure_v9_tag_pos(kind, args.seconds, args.max_samples, hz),
        "v9-valid-tamper" => measure_v9_valid_tamper(kind, args.seconds, args.max_samples, hz),
        "schedule-key" => measure_schedule_key(kind, args.seconds, args.max_samples, hz),
        "enc-batch-pt" => measure_batch_pt(kind, args.seconds, args.max_samples, hz, false),
        "dec-batch-pt" => measure_batch_pt(kind, args.seconds, args.max_samples, hz, true),
        "vrot512-amt" => measure_vrot(kind, args.seconds, args.max_samples, hz, true, false),
        "vrot512-1v7" => measure_vrot(kind, args.seconds, args.max_samples, hz, true, true),
        "vrot128-amt" => measure_vrot(kind, args.seconds, args.max_samples, hz, false, false),
        "vrot128-1v7" => measure_vrot(kind, args.seconds, args.max_samples, hz, false, true),
        "bow128-state" => measure_bow(kind, args.seconds, args.max_samples, hz, false, false),
        "unbow128-state" => measure_bow(kind, args.seconds, args.max_samples, hz, false, true),
        "bow512-state" => measure_bow(kind, args.seconds, args.max_samples, hz, true, false),
        "unbow512-state" => measure_bow(kind, args.seconds, args.max_samples, hz, true, true),
        "stream-open-pt" => measure_stream_open_pt(kind, args.seconds, args.max_samples, hz, 1),
        "stream-open-pt-mt" => measure_stream_open_pt(kind, args.seconds, args.max_samples, hz, 2),
        "stream-tag-pos" => measure_stream_tag_pos(kind, args.seconds, args.max_samples, hz, 1),
        "stream-tag-pos-mt" => measure_stream_tag_pos(kind, args.seconds, args.max_samples, hz, 2),
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
