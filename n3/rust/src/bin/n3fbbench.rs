//! fallback1 bench: single and batch speed per backend, plus key setup.
use octavo_n3_draft3::{Backend, Cipher, BLOCK_LEN, NONCE_LEN, SEED_LEN};
use std::hint::black_box;
use std::time::Instant;

fn main() {
    let mut seed = [0u8; SEED_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    for i in 0..SEED_LEN {
        seed[i] = (i as u8).wrapping_mul(17).wrapping_add(0xA5);
    }
    for i in 0..NONCE_LEN {
        nonce[i] = i as u8 + 1;
    }
    let pt0: [u8; BLOCK_LEN] = core::array::from_fn(|i| (i as u8).wrapping_mul(3).wrapping_add(0x11));
    let only: Vec<Backend> = std::env::args().skip(1).filter_map(|a| Backend::parse(&a)).collect();
    for b in Backend::ALL {
        if !b.supported() || (!only.is_empty() && !only.contains(&b)) {
            continue;
        }
        let c = Cipher::with_backend(&seed, &nonce, b).unwrap();
        // target ~0.4 s per measurement
        let t = Instant::now();
        let mut x = pt0;
        let mut n = 0;
        while t.elapsed().as_secs_f64() < 0.05 {
            x = c.encrypt_block(&x);
            n += 1;
        }
        let per = 0.05 / n as f64;
        let reps = ((0.4 / per) as usize).max(50);
        for enc in [true, false] {
            let mut x = pt0;
            let t = Instant::now();
            for _ in 0..reps {
                x = black_box(if enc { c.encrypt_block(black_box(&x)) } else { c.decrypt_block(black_box(&x)) });
            }
            let us = t.elapsed().as_secs_f64() * 1e6 / reps as f64;
            println!("{:11} {} single      {:9.3} us/block", b.name(), if enc { "enc" } else { "dec" }, us);
        }
        for width in [4usize, 8, 32, 64] {
            for enc in [true, false] {
                let mut blocks = vec![pt0; width];
                let breps = (reps / width).max(20);
                let t = Instant::now();
                for _ in 0..breps {
                    if enc {
                        c.encrypt_blocks(black_box(&mut blocks));
                    } else {
                        c.decrypt_blocks(black_box(&mut blocks));
                    }
                }
                let us = t.elapsed().as_secs_f64() * 1e6 / (breps * width) as f64;
                println!("{:11} {} batch-{:<4} {:9.3} us/block", b.name(), if enc { "enc" } else { "dec" }, width, us);
            }
        }
        let n_setup = 100;
        let t = Instant::now();
        for _ in 0..n_setup {
            black_box(Cipher::with_backend(black_box(&seed), black_box(&nonce), b).unwrap());
        }
        println!("{:11} key setup        {:9.1} us/key", b.name(), t.elapsed().as_secs_f64() * 1e6 / n_setup as f64);
    }
}
