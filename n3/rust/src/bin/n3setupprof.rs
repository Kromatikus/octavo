//! Key-setup timing: Cipher::with_backend, all backends.
//! Homemade; for real secrets use AES-GCM-SIV, age, or libsodium.
use octavo_n3_draft3::{Backend, Cipher, NONCE_LEN, SEED_LEN};
use std::time::Instant;

fn main() {
    let seed = [7u8; SEED_LEN];
    let nonce = [1u8; NONCE_LEN];
    let backends = [
        Backend::Avx512Gfni,
        Backend::Avx2Gfni,
        Backend::Avx2,
        Backend::Portable,
        Backend::Table,
    ];
    println!("# n3setupprof totals (Cipher::with_backend, min of 3 x 80, µs)");
    for b in backends {
        if !b.supported() {
            println!("{:12} unsupported", b.name());
            continue;
        }
        for _ in 0..15 {
            std::hint::black_box(Cipher::with_backend(&seed, &nonce, b).unwrap());
        }
        let mut best = f64::INFINITY;
        for _ in 0..3 {
            let t = Instant::now();
            for _ in 0..80 {
                std::hint::black_box(Cipher::with_backend(&seed, &nonce, b).unwrap());
            }
            let us = t.elapsed().as_secs_f64() * 1e6 / 80.0;
            if us < best {
                best = us;
            }
        }
        println!("{:12} {best:.1}", b.name());
    }
}
