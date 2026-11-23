//! Portable Rust encrypt_block timing: draft-1 vs draft-2, same machine.
//! Does not write into the draft-1 tree's target; cargo uses this crate's target.

use std::hint::black_box;
use std::time::Instant;

const N_WARM: u32 = 2_000;
const N_ITERS: u32 = 50_000;
const N_BATCHES: u32 = 9;

fn time_draft1(seed: &[u8; 128], nonce: &[u8; 16], pt: &[u8; 128]) -> Vec<f64> {
    let c = octavo_n3_draft1::Cipher::new(seed, nonce);
    for _ in 0..N_WARM {
        black_box(c.encrypt_block(black_box(pt)));
    }
    (0..N_BATCHES)
        .map(|_| {
            let t0 = Instant::now();
            for _ in 0..N_ITERS {
                black_box(c.encrypt_block(black_box(pt)));
            }
            t0.elapsed().as_secs_f64() / f64::from(N_ITERS)
        })
        .collect()
}

fn time_draft2(seed: &[u8; 128], nonce: &[u8; 16], pt: &[u8; 128]) -> Vec<f64> {
    let c = octavo_n3_draft2::Cipher::new(seed, nonce);
    for _ in 0..N_WARM {
        black_box(c.encrypt_block(black_box(pt)));
    }
    (0..N_BATCHES)
        .map(|_| {
            let t0 = Instant::now();
            for _ in 0..N_ITERS {
                black_box(c.encrypt_block(black_box(pt)));
            }
            t0.elapsed().as_secs_f64() / f64::from(N_ITERS)
        })
        .collect()
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn mean(v: &[f64]) -> f64 {
    v.iter().sum::<f64>() / v.len() as f64
}

fn main() {
    let mut seed = [0u8; 128];
    let mut nonce = [0u8; 16];
    let mut pt = [0u8; 128];
    for i in 0..128 {
        seed[i] = (17u8.wrapping_mul(i as u8)).wrapping_add(3);
        pt[i] = (13u8.wrapping_mul(i as u8)).wrapping_add(7);
    }
    for i in 0..16 {
        nonce[i] = i as u8;
    }

    // Time each crate separately so one does not warm the other's icache only.
    let d1 = time_draft1(&seed, &nonce, &pt);
    let d2 = time_draft2(&seed, &nonce, &pt);
    let m1 = median(d1.clone());
    let m2 = median(d2.clone());
    let ratio = m2 / m1;
    println!("portable rust encrypt_block, {N_ITERS} iters x {N_BATCHES} batches");
    println!(
        "draft1: median {:.3} us/block  mean {:.3}  batches_us {:?}",
        m1 * 1e6,
        mean(&d1) * 1e6,
        d1.iter().map(|x| format!("{:.3}", x * 1e6)).collect::<Vec<_>>()
    );
    println!(
        "draft2: median {:.3} us/block  mean {:.3}  batches_us {:?}",
        m2 * 1e6,
        mean(&d2) * 1e6,
        d2.iter().map(|x| format!("{:.3}", x * 1e6)).collect::<Vec<_>>()
    );
    println!(
        "draft2/draft1 = {:.4}  ({:+.2}% vs draft1)",
        ratio,
        (ratio - 1.0) * 100.0
    );
    // JSON last line for the recorder
    println!(
        "JSON {{\"draft1_us\":{:.6},\"draft2_us\":{:.6},\"ratio\":{:.6},\"pct_vs_draft1\":{:.4},\"iters\":{},\"batches\":{}}}",
        m1 * 1e6,
        m2 * 1e6,
        ratio,
        (ratio - 1.0) * 100.0,
        N_ITERS,
        N_BATCHES
    );
}
