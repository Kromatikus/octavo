//! Dudect-style timing test for N3 AEAD seal/open (0x1C PMAC-SIV or EXPERIMENTAL 0x1E POLYVAL-SIV),
//! including the threaded CTR path. |t| > 4.5 = evidence of a leak.
//! usage: n3dudect_pv <seal|open> [seconds] [threads] [msg_bytes] [1c|1d|1e]
//! Class 0 = fixed message; class 1 = random message of the same length.
//! Homemade; for real secrets use AES-GCM-SIV, age, or libsodium.

use octavo_n3_draft3::aead::Aead;
use octavo_n3_draft3::aead_pv::AeadPv;
use octavo_n3_draft3::{Backend, SEED_LEN};
use std::hint::black_box;
use std::time::Instant;

#[inline(always)]
fn ticks() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_mm_lfence();
        let t = core::arch::x86_64::_rdtsc();
        core::arch::x86_64::_mm_lfence();
        t
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        static T0: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
        T0.get_or_init(Instant::now).elapsed().as_nanos() as u64
    }
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let b = self.next().to_le_bytes();
            chunk.copy_from_slice(&b[..chunk.len()]);
        }
    }
}

#[derive(Default, Clone, Copy)]
struct W {
    n: f64,
    mean: f64,
    m2: f64,
}
impl W {
    fn push(&mut self, x: f64) {
        self.n += 1.0;
        let d = x - self.mean;
        self.mean += d / self.n;
        self.m2 += d * (x - self.mean);
    }
    fn t(a: &W, b: &W) -> f64 {
        if a.n < 2.0 || b.n < 2.0 {
            return 0.0;
        }
        let va = a.m2 / (a.n - 1.0);
        let vb = b.m2 / (b.n - 1.0);
        (a.mean - b.mean) / (va / a.n + vb / b.n).sqrt()
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("seal");
    let secs: f64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(30.0);
    let threads: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(1);
    let msg_len: usize = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(262144);
    let variant = args.get(5).map(|s| s.as_str()).unwrap_or("1d").to_string();
    if variant != "1c" && variant != "1d" && variant != "1e" {
        eprintln!("variant must be 1c, 1d, or 1e (1d/1e = POLYVAL-SIV)");
        std::process::exit(2);
    }
    if mode != "seal" && mode != "open" {
        eprintln!("usage: n3dudect_aead <seal|open> [seconds] [threads] [msg_bytes]");
        std::process::exit(2);
    }

    let mut r = Rng(0xAead_0001);
    let seed: [u8; SEED_LEN] = core::array::from_fn(|i| (i as u8).wrapping_mul(17).wrapping_add(0xA5));
    let nonce = *b"dudect-aead-0001";
    let ad = b"dudect-ad";
    let backend = Backend::detect();
    let old = Aead::with_backend(&seed, backend).expect("backend").with_threads(threads);
    let pv = AeadPv::with_backend(&seed, backend).expect("backend").with_threads(threads);
    let is_pv = variant == "1d" || variant == "1e";
    struct Dyn<'a> { old: &'a Aead, pv: &'a AeadPv, is_pv: bool }
    impl Dyn<'_> {
        fn seal(&self, n: &[u8; 16], ad: &[u8], m: &[u8]) -> Result<Vec<u8>, octavo_n3_draft3::aead::AeadError> {
            if self.is_pv { self.pv.seal(n, ad, m) } else { self.old.seal(n, ad, m) }
        }
        fn open(&self, ad: &[u8], b: &[u8]) -> Result<Vec<u8>, octavo_n3_draft3::aead::AeadError> {
            if self.is_pv { self.pv.open(ad, b) } else { self.old.open(ad, b) }
        }
    }
    let aead = Dyn { old: &old, pv: &pv, is_pv };

    // Equal-footprint pools (same idea as n3dudect enc-key): both classes have
    // POOL independently allocated buffers, accessed by the same index. A single
    // shared "fixed" buffer stays cache-hot and produces a false dudect leak.
    const POOL: usize = 16;
    let mut template = vec![0u8; msg_len];
    r.fill(&mut template);
    let mut fixed_pt = vec![vec![0u8; msg_len]; POOL];
    let mut rand_pt = vec![vec![0u8; msg_len]; POOL];
    for p in fixed_pt.iter_mut() {
        p.copy_from_slice(&template);
    }
    for p in rand_pt.iter_mut() {
        r.fill(p);
    }
    let fixed_blob: Vec<Vec<u8>> = fixed_pt
        .iter()
        .map(|p| aead.seal(&nonce, ad, p).expect("seal fixed"))
        .collect();
    let rand_blob: Vec<Vec<u8>> = rand_pt
        .iter()
        .map(|p| aead.seal(&nonce, ad, p).expect("seal rand"))
        .collect();

    // warmup: touch every pool slot
    for i in 0..POOL {
        let _ = black_box(aead.seal(&nonce, ad, &fixed_pt[i]));
        let _ = black_box(aead.seal(&nonce, ad, &rand_pt[i]));
        let _ = black_box(aead.open(ad, &fixed_blob[i]));
        let _ = black_box(aead.open(ad, &rand_blob[i]));
    }

    let batch = if msg_len >= 64 * 1024 { 200 } else { 2_000 };
    let pcts = [1.0f64, 0.99, 0.95, 0.9, 0.8, 0.5];
    let mut acc = vec![[W::default(); 2]; pcts.len()];
    let mut thr: Vec<f64> = vec![];
    let t0 = Instant::now();
    let mut total = 0u64;
    let mut slot = 0usize;
    while t0.elapsed().as_secs_f64() < secs {
        let mut samples = Vec::with_capacity(batch);
        for _ in 0..batch {
            let class = (r.next() & 1) as usize;
            let i = slot % POOL;
            slot += 1;
            let dt = if mode == "seal" {
                let pt = if class == 0 { &fixed_pt[i] } else { &rand_pt[i] };
                let s = ticks();
                let blob = black_box(aead.seal(black_box(&nonce), black_box(&ad[..]), black_box(pt))).expect("seal");
                let e = ticks();
                black_box(blob);
                e - s
            } else {
                let blob = if class == 0 { &fixed_blob[i] } else { &rand_blob[i] };
                let s = ticks();
                let pt = black_box(aead.open(black_box(&ad[..]), black_box(blob))).expect("open");
                let e = ticks();
                black_box(pt);
                e - s
            };
            samples.push((class, dt as f64));
        }
        if thr.is_empty() {
            let mut v: Vec<f64> = samples.iter().map(|s| s.1).collect();
            v.sort_by(|a, b| a.partial_cmp(b).unwrap());
            thr = pcts
                .iter()
                .map(|&p| {
                    if p >= 1.0 {
                        f64::INFINITY
                    } else {
                        v[((v.len() - 1) as f64 * p) as usize]
                    }
                })
                .collect();
            continue;
        }
        for (c, x) in samples {
            for (k, &th) in thr.iter().enumerate() {
                if x <= th {
                    acc[k][c].push(x);
                }
            }
        }
        total += batch as u64;
    }

    let mut maxt = 0f64;
    for (k, p) in pcts.iter().enumerate() {
        let t = W::t(&acc[k][0], &acc[k][1]);
        if t.abs() > maxt.abs() {
            maxt = t;
        }
        println!(
            "crop<=p{:<4} n0={:>9.0} n1={:>9.0} mean0={:>10.1} mean1={:>10.1} t={:+.2}",
            (p * 100.0) as u32,
            acc[k][0].n,
            acc[k][1].n,
            acc[k][0].mean,
            acc[k][1].mean,
            t
        );
    }
    let verdict = if maxt.abs() > 4.5 {
        "EVIDENCE OF LEAK"
    } else {
        "no evidence of leak"
    };
    println!(
        "variant={variant} mode={mode} threads={threads} msg={msg_len} backend={} measurements={total} max|t|={:.2} => {verdict}",
        backend.name(),
        maxt.abs()
    );
}
