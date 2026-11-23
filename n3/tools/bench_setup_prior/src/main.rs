//! Time Cipher::new from the unmodified ct1 crate (read-only path dep).
use octavo_n3_draft3::{Cipher, NONCE_LEN, SEED_LEN};
use std::hint::black_box;
use std::time::Instant;

fn cycles() -> u64 {
    unsafe {
        core::arch::x86_64::_mm_mfence();
        core::arch::x86_64::_mm_lfence();
        let t = core::arch::x86_64::_rdtsc();
        core::arch::x86_64::_mm_lfence();
        t
    }
}

fn main() {
    let mut seed = [0u8; SEED_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    for i in 0..SEED_LEN {
        seed[i] = (i as u8).wrapping_mul(17).wrapping_add(0xA5);
    }
    for i in 0..NONCE_LEN {
        nonce[i] = (i as u8).wrapping_add(1);
    }
    for _ in 0..16 {
        black_box(Cipher::new(&seed, &nonce));
    }
    let n = 200;
    let wall = Instant::now();
    let c0 = cycles();
    for _ in 0..n {
        black_box(Cipher::new(black_box(&seed), black_box(&nonce)));
    }
    let c1 = cycles();
    let dt = wall.elapsed().as_secs_f64();
    println!(
        "key setup ct1             n={n:7}  {us:.1} µs/key  {cyc:.0} cycles",
        us = dt * 1e6 / n as f64,
        cyc = (c1.wrapping_sub(c0)) as f64 / n as f64
    );
}
