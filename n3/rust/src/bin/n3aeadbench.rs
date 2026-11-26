//! Lab bench: n3aead seal/open at 1 vs N threads (in memory). Output bytes are compared too.
//! Homemade; for real secrets use AES-GCM-SIV, age, or libsodium.
use octavo_n3_draft3::aead::{default_threads, Aead};
use std::hint::black_box;
use std::time::Instant;

fn main() {
    let seed: [u8; 128] = core::array::from_fn(|i| (i as u8).wrapping_mul(17).wrapping_add(0xA5));
    let nonce = [1u8; 16];
    let def = default_threads();
    println!("default_threads={def} backend={}", Aead::new(&seed).backend().name());
    let sizes: Vec<usize> = std::env::args().skip(1).filter_map(|a| a.parse::<usize>().ok()).map(|m| m << 20).collect();
    let sizes = if sizes.is_empty() { vec![1 << 20, 16 << 20, 64 << 20] } else { sizes };
    for n in sizes {
        let msg: Vec<u8> = (0..n).map(|i| (i as u8).wrapping_mul(3).wrapping_add(0x11)).collect();
        let mut ref_blob = Vec::new();
        for th in [1usize, 2, 4, def] {
            if th > def && th != 1 { continue; }
            let a = Aead::new(&seed).with_threads(th);
            let blob = a.seal(&nonce, b"", &msg).unwrap();
            if th == 1 { ref_blob = blob.clone(); } else { assert_eq!(blob, ref_blob, "bytes differ at {th} threads"); }
            let reps = ((1.0 / (n as f64 / 1e8)) as usize).clamp(3, 40);
            let t = Instant::now();
            for _ in 0..reps { black_box(a.seal(&nonce, b"", black_box(&msg)).unwrap()); }
            let s = t.elapsed().as_secs_f64() / reps as f64;
            let t = Instant::now();
            for _ in 0..reps { black_box(a.open(b"", black_box(&blob)).unwrap()); }
            let o = t.elapsed().as_secs_f64() / reps as f64;
            println!("{:>3} MiB  threads={th:<2} seal {:>7.1} MB/s  open {:>7.1} MB/s  (reps {reps}, blob identical to 1T)", n >> 20, n as f64 / 1e6 / s, n as f64 / 1e6 / o);
        }
    }
}
