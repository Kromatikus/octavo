//! keysetup1: dudect-style timing test for Cipher::with_backend (key setup).
//! usage: n3dudect_setup <fixed|random> [seconds]
//!   fixed  : two fixed seeds (class 0 vs class 1)
//!   random : one fixed seed (class 0) vs a fresh random seed (class 1)
//! |t| > 4.5 = evidence of a leak. Homemade; for real secrets use AES-GCM-SIV, age, or libsodium.
use octavo_n3_draft3::{Backend, Cipher, NONCE_LEN, SEED_LEN};
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
}

#[derive(Default, Clone, Copy)]
struct W { n: f64, mean: f64, m2: f64 }
impl W {
    fn push(&mut self, x: f64) {
        self.n += 1.0;
        let d = x - self.mean;
        self.mean += d / self.n;
        self.m2 += d * (x - self.mean);
    }
    fn t(a: &W, b: &W) -> f64 {
        if a.n < 2.0 || b.n < 2.0 { return 0.0; }
        let va = a.m2 / (a.n - 1.0);
        let vb = b.m2 / (b.n - 1.0);
        (a.mean - b.mean) / (va / a.n + vb / b.n).sqrt()
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("fixed");
    let secs: f64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(15.0);
    let mut r = Rng(0x51E2);
    let seed_a: [u8; SEED_LEN] = core::array::from_fn(|i| (i as u8).wrapping_mul(13).wrapping_add(1));
    let seed_b: [u8; SEED_LEN] = core::array::from_fn(|i| (i as u8).wrapping_mul(29).wrapping_add(7));
    let nonce: [u8; NONCE_LEN] = *b"dudect-setup-001";
    let backend = Backend::detect();
    // warmup so OnceLocks (public tables, PHI inverse) are filled
    let _ = Cipher::with_backend(&seed_a, &nonce, backend).unwrap();
    let _ = Cipher::with_backend(&seed_b, &nonce, backend).unwrap();
    let batch = 400;
    let pcts = [1.0f64, 0.95, 0.9, 0.8, 0.7, 0.5, 0.3];
    let mut acc = vec![[W::default(); 2]; pcts.len()];
    let mut thr: Vec<f64> = vec![];
    let t0 = Instant::now();
    let mut total = 0u64;
    while t0.elapsed().as_secs_f64() < secs {
        let mut samples = Vec::with_capacity(batch);
        for _ in 0..batch {
            let class = (r.next() & 1) as usize;
            let mut seed = [0u8; SEED_LEN];
            for (i, x) in seed.iter_mut().enumerate() {
                let rv = r.next() as u8;
                *x = black_box(if mode == "random" && class == 1 {
                    rv
                } else if class == 0 {
                    seed_a[i]
                } else {
                    seed_b[i]
                });
            }
            let s = ticks();
            let ciph = black_box(Cipher::with_backend(black_box(&seed), black_box(&nonce), backend).unwrap());
            let e = ticks();
            black_box(ciph);
            samples.push((class, (e - s) as f64));
        }
        if thr.is_empty() {
            let mut v: Vec<f64> = samples.iter().map(|s| s.1).collect();
            v.sort_by(|a, b| a.partial_cmp(b).unwrap());
            thr = pcts.iter().map(|&p| if p >= 1.0 { f64::INFINITY } else { v[((v.len() - 1) as f64 * p) as usize] }).collect();
            continue;
        }
        for (class, dt) in samples {
            for (i, &t) in thr.iter().enumerate() {
                if dt <= t {
                    acc[i][class].push(dt);
                }
            }
            total += 1;
        }
    }
    let mut max_t = 0.0f64;
    for (i, &p) in pcts.iter().enumerate() {
        let a = &acc[i][0];
        let b = &acc[i][1];
        let tv = W::t(a, b);
        max_t = max_t.max(tv.abs());
        let label = if p >= 1.0 { "crop<=p100".to_string() } else { format!("crop<=p{:.0}", p * 100.0) };
        println!("{label:12} n0={:8.0} n1={:8.0} mean0={:10.1} mean1={:10.1} t={:+.2}", a.n, b.n, a.mean, b.mean, tv);
    }
    let verdict = if max_t > 4.5 { "EVIDENCE OF LEAK" } else { "no evidence of leak" };
    println!("mode={mode} backend={:?} measurements={total} max|t|={max_t:.2} => {verdict}", backend);
}
