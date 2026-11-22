//! Rough rates of the v9 pieces (single thread): keystream sponge, HMAC-SHA256, raw cipher batch.
use std::time::Instant;
fn main() {
    let seed = [5u8; 128];
    let info = [7u8; 83];
    let mut out = vec![0u8; 32 + 65536];
    let t = Instant::now();
    let reps = 64;
    for _ in 0..reps {
        octavo_core::sponge::sponge(b"R", &seed, &info, &mut out);
        std::hint::black_box(&out);
    }
    let e = t.elapsed().as_secs_f64();
    println!("keystream sponge: {:.0} MB/s", (reps * 65536) as f64 / e / 1e6);
    use hmac::{Hmac, Mac};
    let data = vec![1u8; 4 << 20];
    let t = Instant::now();
    let mut m = <Hmac<sha2::Sha256> as Mac>::new_from_slice(&[1u8; 32]).unwrap();
    m.update(&data);
    std::hint::black_box(m.finalize());
    println!("HMAC-SHA256: {:.0} MB/s", data.len() as f64 / t.elapsed().as_secs_f64() / 1e6);
    let c: octavo_core::Cipher = octavo_core::Cipher::new(&seed, &[1u8; 16]);
    let mut blocks = vec![[3u8; 128]; 512];
    for (name, dec) in [("encrypt_blocks", false), ("decrypt_blocks", true)] {
        let t = Instant::now();
        for _ in 0..64 {
            if dec { c.decrypt_blocks(&mut blocks) } else { c.encrypt_blocks(&mut blocks) }
        }
        println!("{name}: {:.0} MB/s", (64 * 512 * 128) as f64 / t.elapsed().as_secs_f64() / 1e6);
    }
}
