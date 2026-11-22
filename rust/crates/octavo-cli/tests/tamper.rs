//! Tamper detection on the streaming open path (exhaustive bit flips, truncations, extensions,
//! chunk swaps, wrong key / AD / header fields).
mod common;
use common::*;
use octavo_cli::{open_stream, seal_stream, StreamOptions};

fn seal(seed: &[u8; 128], msg: &[u8], cs: usize, ad: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    seal_stream(seed, &mut &msg[..], &mut out, &[7; 16], &[9; 16], ad, &StreamOptions { chunk_size: cs, threads: 2, batch_chunks: 2 }).unwrap();
    out
}
fn opens(seed: &[u8; 128], blob: &[u8], ad: &[u8]) -> bool {
    let mut out = Vec::new();
    open_stream(seed, &mut &blob[..], &mut out, ad, &StreamOptions { chunk_size: 0, threads: 2, batch_chunks: 2 }).is_ok()
}

#[test]
fn every_single_bit_flip_rejected() {
    let mut rng = Rng(11);
    let seed = good_seed(&mut rng);
    let msg = rng.bytes(700); // cs 256: 2 full chunks + final (188 -> 256) = 3 chunks
    let ad = b"tamper-test";
    let blob = seal(&seed, &msg, 256, ad);
    assert!(opens(&seed, &blob, ad));
    let mut n = 0;
    for i in 0..blob.len() {
        for bit in 0..8 {
            let mut t = blob.clone();
            t[i] ^= 1 << bit;
            assert!(!opens(&seed, &t, ad), "flip byte {i} bit {bit} accepted");
            n += 1;
        }
    }
    println!("single-bit flips rejected: {n}/{n} (blob {} bytes)", blob.len());
}

#[test]
fn truncation_extension_reorder_rejected() {
    let mut rng = Rng(12);
    let seed = good_seed(&mut rng);
    let msg = rng.bytes(1000);
    let blob = seal(&seed, &msg, 256, b"");
    let mut n = 0;
    for cut in 0..blob.len() {
        assert!(!opens(&seed, &blob[..cut], b""), "truncation to {cut} accepted");
        n += 1;
    }
    for extra in [1usize, 31, 32, 128, 160, 288] {
        let mut t = blob.clone();
        t.extend(rng.bytes(extra));
        assert!(!opens(&seed, &t, b""));
        n += 1;
    }
    // chunk units after the 72-byte header: 288 bytes each (256 ct + 32 tag)
    let unit = 288;
    let mut sw = blob.clone();
    let (a, b) = (72, 72 + unit);
    let c0 = blob[a..a + unit].to_vec();
    let c1 = blob[b..b + unit].to_vec();
    sw[a..a + unit].copy_from_slice(&c1);
    sw[b..b + unit].copy_from_slice(&c0);
    assert!(!opens(&seed, &sw, b""));
    // drop a whole middle chunk, duplicate a chunk
    let mut dropped = blob[..b].to_vec();
    dropped.extend_from_slice(&blob[b + unit..]);
    assert!(!opens(&seed, &dropped, b""));
    let mut dup = blob[..b + unit].to_vec();
    dup.extend_from_slice(&blob[b..]);
    assert!(!opens(&seed, &dup, b""));
    n += 3;
    // splice: header from another stream
    let other = seal(&seed, &msg, 256, b"");
    let mut sp = other[..72].to_vec();
    sp.extend_from_slice(&blob[72..]);
    assert!(sp == blob || !opens(&seed, &sp, b""));
    n += 1;
    println!("truncations/extensions/reorders rejected: {n}/{n}");
}

#[test]
fn wrong_key_ad_and_header_rejected() {
    let mut rng = Rng(13);
    let seed = good_seed(&mut rng);
    let seed2 = good_seed(&mut rng);
    let msg = rng.bytes(5000);
    let blob = seal(&seed, &msg, 1024, b"ad");
    assert!(opens(&seed, &blob, b"ad"));
    assert!(!opens(&seed2, &blob, b"ad"));
    assert!(!opens(&seed, &blob, b""));
    assert!(!opens(&seed, &blob, b"ae"));
    let mut v = blob.clone();
    v[0] = 6;
    assert!(!opens(&seed, &v, b"ad"));
    let mut cs = blob.clone();
    cs[68..72].copy_from_slice(&2048u32.to_be_bytes());
    assert!(!opens(&seed, &cs, b"ad"));
    assert!(!opens(&seed, b"", b""));
    assert!(!opens(&seed, &[9u8; 71], b""));
}

#[test]
fn empty_message_streams() {
    let mut rng = Rng(14);
    let seed = good_seed(&mut rng);
    let blob = seal(&seed, b"", 128, b"");
    assert_eq!(blob.len(), 72 + 128 + 32);
    let mut out = Vec::new();
    open_stream(&seed, &mut &blob[..], &mut out, b"", &StreamOptions::default()).unwrap();
    assert!(out.is_empty());
}
