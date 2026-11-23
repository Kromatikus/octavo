//! fix2: dudect-style timing test for the AEAD tag check. Welch t-test between two
//! interleaved classes, with dudect's percentile cropping. |t| > 4.5 = evidence of a leak.
//! usage: n3dudect_tag <cteq|open> [seconds]
//!   cteq : ct_eq(32-byte tag) where the mismatch is in byte 0 (class 0) vs only byte 31 (class 1)
//!   open : Aead::open on a 300-byte blob whose tag is wrong in byte 0 vs only byte 31
//!   eqne : ct_eq with equal tags (class 0) vs random tags (class 1)
use octavo_n3_draft3::aead::{ct_eq, Aead};
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
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("cteq");
    let secs: f64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(15.0);
    let mut r = Rng(0xD0DE);
    let seed: [u8; 128] = core::array::from_fn(|i| (i as u8).wrapping_mul(13).wrapping_add(1));
    let aead = Aead::new(&seed);
    let nonce = *b"dudect-nonce-001";
    let msg: Vec<u8> = (0..300).map(|i| i as u8).collect();
    let good = aead.seal(&nonce, b"ad", &msg).unwrap();
    let tag_ref: [u8; 32] = core::array::from_fn(|i| good[22 + i]);
    // samples: (class, ticks); crop thresholds computed from a warm-up batch
    let batch = if mode == "open" { 2_000 } else { 200_000 };
    let pcts = [1.0f64, 0.95, 0.9, 0.8, 0.7, 0.5, 0.3];
    let mut acc = vec![[W::default(); 2]; pcts.len()];
    let mut thr: Vec<f64> = vec![];
    let t0 = Instant::now();
    let mut total = 0u64;
    while t0.elapsed().as_secs_f64() < secs {
        let mut samples = Vec::with_capacity(batch);
        for _ in 0..batch {
            let class = (r.next() & 1) as usize;
            let dt = match mode {
                "open" => {
                    let mut b = good.clone();
                    let pos = if class == 0 { 22 } else { 22 + 31 };
                    b[pos] ^= 1 + (r.next() % 255) as u8;
                    let s = ticks();
                    let res = black_box(aead.open(black_box(b"ad"), black_box(&b)));
                    let e = ticks();
                    assert!(res.is_err());
                    e - s
                }
                "eqne" => {
                    // both classes fill the 32 bytes the same way (byte stores) so the
                    // harness itself has no class-dependent store-forwarding behaviour
                    let mut t = [0u8; 32];
                    for (i, x) in t.iter_mut().enumerate() {
                        let rv = r.next() as u8;
                        *x = black_box(if class == 1 { rv } else { tag_ref[i] });
                    }
                    let s = ticks();
                    let res = black_box(ct_eq(black_box(&t), black_box(&tag_ref)));
                    let e = ticks();
                    black_box(res);
                    e - s
                }
                _ => {
                    let mut t = tag_ref;
                    let pos = if class == 0 { 0 } else { 31 };
                    t[pos] ^= 1 + (r.next() % 255) as u8;
                    let s = ticks();
                    let res = black_box(ct_eq(black_box(&t), black_box(&tag_ref)));
                    let e = ticks();
                    assert!(!res);
                    e - s
                }
            };
            samples.push((class, dt as f64));
        }
        if thr.is_empty() {
            let mut v: Vec<f64> = samples.iter().map(|s| s.1).collect();
            v.sort_by(|a, b| a.partial_cmp(b).unwrap());
            thr = pcts.iter().map(|&p| if p >= 1.0 { f64::INFINITY } else { v[((v.len() - 1) as f64 * p) as usize] }).collect();
            continue; // warm-up batch discarded
        }
        for (c, x) in samples {
            for (k, &th) in thr.iter().enumerate() {
                if x <= th { acc[k][c].push(x); }
            }
        }
        total += batch as u64;
    }
    let mut maxt = 0f64;
    for (k, p) in pcts.iter().enumerate() {
        let t = W::t(&acc[k][0], &acc[k][1]);
        if t.abs() > maxt.abs() { maxt = t; }
        println!("crop<=p{:<4} n0={:>9} n1={:>9} mean0={:>8.1} mean1={:>8.1} t={:+.2}", (p * 100.0) as u32, acc[k][0].n, acc[k][1].n, acc[k][0].mean, acc[k][1].mean, t);
    }
    println!("mode={mode} measurements={total} max|t|={:.2} => {}", maxt.abs(), if maxt.abs() > 4.5 { "EVIDENCE OF LEAK" } else { "no evidence of leak" });
}
