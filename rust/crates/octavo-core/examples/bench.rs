//! Benchmark per backend: cargo run --release --all-features --example bench
use octavo_core::{force_backend, Auto, BackendKind, Cipher, SboxBackend, Schedule};
use std::hint::black_box;
use std::time::Instant;

fn seed() -> [u8; 128] {
    core::array::from_fn(|i| ((i as u32).wrapping_mul(2654435761) >> 13) as u8)
}

fn main() {
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let s = seed();
    // optional filter, e.g. OCTAVO_BENCH_BACKENDS=gfni-simd,aes-ni
    let only: Option<Vec<String>> = std::env::var("OCTAVO_BENCH_BACKENDS").ok().map(|v| v.split(',').map(|x| x.to_string()).collect());
    println!("| backend | enc 1 block | dec 1 block | enc batched/block | dec batched/block | key setup | v9 seal 1T | v9 open 1T | v9 seal {threads}T | v9 open {threads}T |");
    println!("|---|---|---|---|---|---|---|---|---|---|");
    for k in BackendKind::ALL {
        if let Some(o) = &only {
            if !o.iter().any(|x| x == k.name()) {
                continue;
            }
        }
        if !k.available() {
            println!("| {} | n/a |", k.name());
            continue;
        }
        force_backend(Some(k));
        let n = 500;
        let t = Instant::now();
        for i in 0..n {
            let mut nn = [7u8; 16];
            nn[0] = i as u8;
            nn[1] = (i >> 8) as u8;
            let sc = Schedule::new(&s, &nn);
            black_box(Auto::prepare(&sc));
        }
        let setup = t.elapsed().as_secs_f64() / n as f64 * 1e6;
        let c: Cipher = Cipher::new(&s, &[7u8; 16]);
        let mut blk = [0x5au8; 128];
        // time-budgeted: repeat until ~0.4 s, report µs per call
        let time = |f: &mut dyn FnMut()| {
            for _ in 0..20 { f(); }
            let mut it = 1u64;
            loop {
                let t = Instant::now();
                for _ in 0..it { f(); }
                let e = t.elapsed().as_secs_f64();
                if e > 0.4 { return e / it as f64 * 1e6; }
                it *= 2;
            }
        };
        let e1 = time(&mut || c.encrypt_block(black_box(&mut blk)));
        let d1 = time(&mut || c.decrypt_block(black_box(&mut blk)));
        let mut many = vec![[0x33u8; 128]; 64];
        let eb = time(&mut || c.encrypt_blocks(black_box(&mut many[..]))) / 64.0;
        let db = time(&mut || c.decrypt_blocks(black_box(&mut many[..]))) / 64.0;
        let msg = vec![0x42u8; 4 << 20];
        // fixed-duration: repeat each v9 run until >= 0.5 s, report mean MB/s
        let rate = |f: &mut dyn FnMut()| {
            f();
            let t = Instant::now();
            let mut reps = 0u32;
            while t.elapsed().as_secs_f64() < 0.5 {
                f();
                reps += 1;
            }
            reps as f64 * msg.len() as f64 / t.elapsed().as_secs_f64() / 1e6
        };
        let seal = |th: usize| octavo_core::formats::seal_rehearsal_threads(&s, &msg, &[1; 16], &[2; 16], 65536, b"", th).unwrap().0;
        let blob = seal(1);
        assert!(seal(threads) == blob, "thread count changed the bytes");
        let s1 = rate(&mut || { black_box(seal(1)); });
        let o1 = rate(&mut || { black_box(octavo_core::formats::open_rehearsal_threads(&s, &blob, b"", 1).unwrap()); });
        let sn = rate(&mut || { black_box(seal(threads)); });
        let on = rate(&mut || { black_box(octavo_core::formats::open_rehearsal_threads(&s, &blob, b"", threads).unwrap()); });
        println!(
            "| {} | {:.2} µs | {:.2} µs | {:.2} µs | {:.2} µs | {:.0} µs | {:.1} MB/s | {:.1} MB/s | {:.1} MB/s | {:.1} MB/s |",
            k.name(), e1, d1, eb, db, setup, s1, o1, sn, on
        );
    }
    force_backend(None);
    println!("auto-detected default: {}", BackendKind::detect().name());

    // Reference point: AES-256-GCM (RustCrypto aes-gcm, runtime AES-NI + CLMUL), same box
    {
        use aes_gcm::aead::{AeadInPlace, KeyInit};
        use aes_gcm::{Aes256Gcm, Nonce};
        let cipher = Aes256Gcm::new_from_slice(&[9u8; 32]).unwrap();
        let mut buf = vec![0x42u8; 8 << 20];
        let nonce = Nonce::from_slice(&[1u8; 12]);
        let _ = cipher.encrypt_in_place_detached(nonce, b"", &mut buf).unwrap();
        let t = Instant::now();
        let reps = 8;
        for _ in 0..reps {
            black_box(cipher.encrypt_in_place_detached(nonce, b"", &mut buf).unwrap());
        }
        let e = t.elapsed().as_secs_f64();
        println!("AES-256-GCM (aes-gcm 0.10, 1 thread, 8 MiB): {:.0} MB/s  (v9 runs above use 4 MiB, chunk 64 KiB)", (reps * buf.len()) as f64 / e / 1e6);
    }
}
