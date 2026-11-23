//! Micro-bench for portable vs GFNI N3 block function. Lab only.

use octavo_n3_draft3::{gfni_available, Cipher, BLOCK_LEN, NONCE_LEN, SEED_LEN};
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

fn seed_from(n: u64) -> ([u8; SEED_LEN], [u8; NONCE_LEN], [u8; BLOCK_LEN]) {
    let mut seed = [0u8; SEED_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    let mut pt = [0u8; BLOCK_LEN];
    for i in 0..SEED_LEN {
        seed[i] = (i as u8).wrapping_mul(17).wrapping_add(n as u8);
    }
    for i in 0..NONCE_LEN {
        nonce[i] = (i as u8).wrapping_add(1);
    }
    for i in 0..BLOCK_LEN {
        pt[i] = (i as u8).wrapping_mul(3).wrapping_add(0x11);
    }
    (seed, nonce, pt)
}

fn us_per(total_s: f64, n: usize) -> f64 {
    total_s * 1e6 / n as f64
}

fn bench_single(label: &str, n: usize, mut body: impl FnMut()) {
    for _ in 0..256 {
        body();
    }
    let wall = Instant::now();
    let c0 = cycles();
    for _ in 0..n {
        body();
    }
    let c1 = cycles();
    let dt = wall.elapsed().as_secs_f64();
    let cyc = (c1.wrapping_sub(c0)) as f64 / n as f64;
    println!(
        "{label:24} n={n:7}  {us:.3} µs/block  {cyc:.0} cycles  ({hz:.3} GHz wall)",
        us = us_per(dt, n),
        hz = (c1.wrapping_sub(c0)) as f64 / dt / 1e9
    );
}

fn main() {
    let (seed, nonce, pt0) = seed_from(0xA5);
    let c = Cipher::new(&seed, &nonce);
    println!("gfni_available={} uses_gfni={}", gfni_available(), c.uses_gfni());

    // confirm one block still matches before timing
    let ct_p = c.encrypt_block_portable(&pt0);
    let ct = c.encrypt_block(&pt0);
    assert_eq!(ct, ct_p);
    assert_eq!(c.decrypt_block(&ct), pt0);

    let n_port = 8_000;
    let n_gfni = 40_000;

    let mut pt = pt0;
    bench_single("portable enc", n_port, || {
        pt = black_box(c.encrypt_block_portable(black_box(&pt)));
    });
    let mut pt = pt0;
    bench_single("portable dec", n_port, || {
        pt = black_box(c.decrypt_block_portable(black_box(&pt)));
    });

    if c.uses_gfni() {
        let mut pt = pt0;
        bench_single("gfni enc", n_gfni, || {
            pt = black_box(c.encrypt_block(black_box(&pt)));
        });
        let mut pt = pt0;
        bench_single("gfni dec", n_gfni, || {
            pt = black_box(c.decrypt_block(black_box(&pt)));
        });

        // Batched widths: 8, 16, 32 independent blocks through encrypt_blocks /
        // decrypt_blocks. Target work is about 64,000 blocks per measurement.
        fn bench_batch(label: &str, c: &Cipher, pt0: &[u8; BLOCK_LEN], width: usize, encrypt: bool) {
            let mut blocks = vec![[0u8; BLOCK_LEN]; width];
            for (i, b) in blocks.iter_mut().enumerate() {
                *b = *pt0;
                b[0] = i as u8;
            }
            let n_batch = (64_000 / width).max(2_000);
            for _ in 0..32 {
                if encrypt {
                    c.encrypt_blocks(&mut blocks);
                } else {
                    c.decrypt_blocks(&mut blocks);
                }
            }
            let wall = Instant::now();
            let c0 = cycles();
            for _ in 0..n_batch {
                if encrypt {
                    c.encrypt_blocks(black_box(&mut blocks));
                } else {
                    c.decrypt_blocks(black_box(&mut blocks));
                }
            }
            let c1 = cycles();
            let dt = wall.elapsed().as_secs_f64();
            let nblk = n_batch * width;
            println!(
                "{label:24} n={n:7}  {us:.3} µs/block  {cyc:.0} cycles  (batch of {width})",
                n = nblk,
                us = us_per(dt, nblk),
                cyc = (c1.wrapping_sub(c0)) as f64 / nblk as f64
            );
        }
        for width in [8, 16, 32, 64, 128] {
            bench_batch(&format!("gfni enc batched-{width}"), &c, &pt0, width, true);
            bench_batch(&format!("gfni dec batched-{width}"), &c, &pt0, width, false);
        }
    }

    // Key setup (Cipher::new), not the data path.
    let (seed, nonce, _) = seed_from(0xA5);
    for _ in 0..16 {
        black_box(Cipher::new(&seed, &nonce));
    }
    let n_setup = 200;
    let wall = Instant::now();
    let c0 = cycles();
    for _ in 0..n_setup {
        black_box(Cipher::new(black_box(&seed), black_box(&nonce)));
    }
    let c1 = cycles();
    let dt = wall.elapsed().as_secs_f64();
    println!(
        "{label:24} n={n:7}  {us:.1} µs/key  {cyc:.0} cycles",
        label = "key setup (fixed seed)",
        n = n_setup,
        us = dt * 1e6 / n_setup as f64,
        cyc = (c1.wrapping_sub(c0)) as f64 / n_setup as f64
    );
}
