//! Lab bench: 0x1C PMAC-SIV vs EXPERIMENTAL 0x1E POLYVAL-SIV vs raw N3 cipher, in memory.
//! Variants are interleaved per trial; each trial averages REPS runs; the median of TRIALS is shown.
//! usage: n3pvbench [mib=16] [trials=3] [reps=3]
use octavo_n3_draft3::aead::Aead;
use octavo_n3_draft3::aead_pv::AeadPv;
use octavo_n3_draft3::{Backend, Cipher, BLOCK_LEN};
use std::hint::black_box;
use std::time::Instant;

fn median(v: &mut Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}
fn time<F: FnMut()>(reps: usize, mut f: F) -> f64 {
    let t = Instant::now();
    for _ in 0..reps { f(); }
    t.elapsed().as_secs_f64() / reps as f64
}
fn raw(c: &Cipher, buf: &mut [u8], th: usize) {
    let enc = |part: &mut [u8]| {
        for ch in part.chunks_mut(64 * BLOCK_LEN) {
            let nb = ch.len() / BLOCK_LEN;
            let blocks: &mut [[u8; BLOCK_LEN]] = unsafe { core::slice::from_raw_parts_mut(ch.as_mut_ptr() as *mut [u8; BLOCK_LEN], nb) };
            c.encrypt_blocks(blocks);
        }
    };
    if th <= 1 { return enc(buf); }
    let per = ((buf.len() / (64 * BLOCK_LEN) + th - 1) / th) * 64 * BLOCK_LEN;
    std::thread::scope(|s| { for p in buf.chunks_mut(per) { s.spawn(|| enc(p)); } });
}

fn main() {
    let a: Vec<usize> = std::env::args().skip(1).filter_map(|x| x.parse().ok()).collect();
    let mib = *a.first().unwrap_or(&16);
    let trials = *a.get(1).unwrap_or(&3);
    let reps = *a.get(2).unwrap_or(&3);
    let n = mib << 20;
    let seed: [u8; 128] = core::array::from_fn(|i| (i as u8).wrapping_mul(17).wrapping_add(0xA5));
    let nonce = [1u8; 16];
    let msg: Vec<u8> = (0..n).map(|i| (i as u8).wrapping_mul(3).wrapping_add(0x11)).collect();
    let cipher = Cipher::with_backend(&seed, &[7u8; 16], Backend::detect()).unwrap();
    println!("backend={} msg={mib} MiB trials={trials} reps/trial={reps} (median)", Backend::detect().name());
    println!("{:<28} {:>3}T {:>10}", "variant", "", "MB/s");
    for th in [1usize, 8] {
        let old = Aead::new(&seed).with_threads(th);
        let pv = AeadPv::new(&seed).with_threads(th);
        let old_blob = old.seal(&nonce, b"", &msg).unwrap();
        let pv_blob = pv.seal(&nonce, b"", &msg).unwrap();
        assert_eq!(pv.open(b"", &pv_blob).unwrap(), msg);
        assert_eq!(old.open(b"", &old_blob).unwrap(), msg);
        let mut buf = msg.clone();
        let mut r: [Vec<f64>; 5] = Default::default();
        for _ in 0..trials {
            r[0].push(time(reps, || { black_box(old.seal(&nonce, b"", black_box(&msg)).unwrap()); }));
            r[1].push(time(reps, || { black_box(pv.seal(&nonce, b"", black_box(&msg)).unwrap()); }));
            r[2].push(time(reps, || { black_box(old.open(b"", black_box(&old_blob)).unwrap()); }));
            r[3].push(time(reps, || { black_box(pv.open(b"", black_box(&pv_blob)).unwrap()); }));
            r[4].push(time(reps, || { raw(&cipher, black_box(&mut buf), th); }));
        }
        let names = ["0x1C PMAC-SIV seal", "0x1E POLYVAL-SIV seal", "0x1C PMAC-SIV open", "0x1E POLYVAL-SIV open", "raw N3 cipher (enc blocks)"];
        for (i, nm) in names.iter().enumerate() {
            println!("{:<28} {:>3}T {:>10.1}", nm, th, n as f64 / 1e6 / median(&mut r[i]));
        }
    }
}
