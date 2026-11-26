//! SN3F v1 container tests: roundtrips, thread-count byte identity, tamper rejection.
use octavo_n3_draft3::aead::Aead;
use octavo_n3_file::format::{self, FileError, FILE_HEADER_LEN};

const TAG: usize = 32;

fn seed(k: u8) -> [u8; 128] {
    let mut s = [0u8; 128];
    for (i, b) in s.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(17).wrapping_add(0xA5) ^ k;
    }
    s
}
fn data(n: usize) -> Vec<u8> {
    let mut x: u64 = 0x9E3779B97F4A7C15;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}
const NONCE: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

fn seal(a: &Aead, pt: &[u8], cs: usize, ad: &[u8], t: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let s = format::seal_stream(a, pt, &mut out, cs, ad, &NONCE, t).unwrap();
    assert_eq!(s.bytes, pt.len() as u64);
    out
}
fn open(a: &Aead, ct: &[u8], ad: &[u8], t: usize) -> Result<Vec<u8>, FileError> {
    let mut out = Vec::new();
    format::open_stream(a, ct, &mut out, ad, t).map(|_| out)
}
fn aead(k: u8) -> Aead {
    Aead::new(&seed(k)).with_threads(1)
}
fn expected_len(n: usize, cs: usize) -> usize {
    let chunks = if n == 0 { 1 } else { n.div_ceil(cs) };
    FILE_HEADER_LEN + n + chunks * TAG
}

#[test]
fn roundtrip_sizes() {
    let a = aead(0);
    let cs = 1024;
    for n in [0, 1, cs - 1, cs, cs + 1, 2 * cs, 7 * cs + 5, 33 * cs] {
        let pt = data(n);
        for t in [1, 3] {
            let ct = seal(&a, &pt, cs, b"ad", t);
            assert_eq!(ct.len(), expected_len(n, cs), "n={n}");
            assert_eq!(open(&a, &ct, b"ad", t).unwrap(), pt, "n={n} t={t}");
        }
    }
}

#[test]
fn roundtrip_64mib_default_chunk() {
    let a = aead(0);
    let n = 64 * 1048576 + 77;
    let pt = data(n);
    let ct = seal(&a, &pt, format::DEFAULT_CHUNK, b"", 8);
    assert_eq!(ct.len(), expected_len(n, format::DEFAULT_CHUNK));
    assert_eq!(open(&a, &ct, b"", 8).unwrap(), pt);
}

#[test]
fn thread_count_byte_identity() {
    let a = aead(0);
    for (n, cs) in [(0, 128), (5000, 128), (100_000, 1024), (3 * 65536 + 9, 65536)] {
        let pt = data(n);
        let r = seal(&a, &pt, cs, b"x", 1);
        for t in [2, 3, 5, 8, 16] {
            assert_eq!(seal(&a, &pt, cs, b"x", t), r, "n={n} cs={cs} t={t}");
        }
        // and opening with any thread count gives the plaintext back
        for t in [1, 4, 8] {
            assert_eq!(open(&a, &r, b"x", t).unwrap(), pt);
        }
    }
}

#[test]
fn nonce_and_ad_change_everything() {
    let a = aead(0);
    let pt = data(3000);
    let x = seal(&a, &pt, 1024, b"x", 1);
    let y = seal(&a, &pt, 1024, b"y", 1);
    let mut z = Vec::new();
    format::seal_stream(&a, &pt[..], &mut z, 1024, b"x", &[9u8; 16], 1).unwrap();
    assert_ne!(x[FILE_HEADER_LEN..FILE_HEADER_LEN + 64], y[FILE_HEADER_LEN..FILE_HEADER_LEN + 64]);
    assert_ne!(x[FILE_HEADER_LEN..FILE_HEADER_LEN + 64], z[FILE_HEADER_LEN..FILE_HEADER_LEN + 64]);
}

/// Every tampered variant must be rejected (Err), whatever the thread count.
#[test]
fn tamper_rejected() {
    let a = aead(0);
    let cs = 1024;
    let rec = TAG + cs;
    let n = 4 * cs + 300; // 5 chunks, last one short
    let pt = data(n);
    let ct = seal(&a, &pt, cs, b"ad", 1);
    let h = FILE_HEADER_LEN;
    let r = |i: usize| h + i * rec; // start of record i
    let mut cases: Vec<(String, Vec<u8>)> = Vec::new();
    // header: every byte (magic, version, chunk size, file nonce)
    for i in 0..h {
        let mut v = ct.clone();
        v[i] ^= 0x01;
        cases.push((format!("header byte {i}"), v));
    }
    // a valid but different chunk size in the header
    let mut v = ct.clone();
    v[6..10].copy_from_slice(&2048u32.to_le_bytes());
    cases.push(("chunk size 2048".into(), v));
    // tag bytes and ciphertext bytes of every chunk
    for c in 0..5 {
        for off in [0, 31, 32, 33, 500] {
            let p = r(c) + off;
            if p < ct.len() {
                let mut v = ct.clone();
                v[p] ^= 0x80;
                cases.push((format!("chunk {c} offset {off}"), v));
            }
        }
    }
    let mut v = ct.clone();
    *v.last_mut().unwrap() ^= 1;
    cases.push(("last byte".into(), v));
    // swap chunks 0 and 1; swap 2 and 3
    for (x, y) in [(0, 1), (2, 3)] {
        let mut v = ct.clone();
        let (cx, cy) = (ct[r(x)..r(x) + rec].to_vec(), ct[r(y)..r(y) + rec].to_vec());
        v[r(x)..r(x) + rec].copy_from_slice(&cy);
        v[r(y)..r(y) + rec].copy_from_slice(&cx);
        cases.push((format!("swap {x}<->{y}"), v));
    }
    // drop the last chunk; drop a middle chunk
    cases.push(("drop last chunk".into(), ct[..r(4)].to_vec()));
    let mut v = ct[..r(2)].to_vec();
    v.extend_from_slice(&ct[r(3)..]);
    cases.push(("drop chunk 2".into(), v));
    // duplicate chunk 1
    let mut v = ct[..r(2)].to_vec();
    v.extend_from_slice(&ct[r(1)..r(2)]);
    v.extend_from_slice(&ct[r(2)..]);
    cases.push(("duplicate chunk 1".into(), v));
    // truncation at every length from 0 up to the full length - 1 (step keeps it quick)
    let mut cuts: Vec<usize> = (0..ct.len()).step_by(97).collect();
    cuts.extend([h - 1, h, h + 1, h + TAG, r(1), r(1) + 1, r(4), r(4) + TAG, ct.len() - 1]);
    for cut in cuts {
        cases.push((format!("truncate to {cut}"), ct[..cut].to_vec()));
    }
    // appending: one byte, a tag's worth, a copy of the last record, a fresh full record
    for (name, extra) in [
        ("append 1 byte", vec![0u8]),
        ("append 32 bytes", vec![0u8; 32]),
        ("append last record", ct[r(4)..].to_vec()),
        ("append record 0", ct[r(0)..r(1)].to_vec()),
    ] {
        let mut v = ct.clone();
        v.extend_from_slice(&extra);
        cases.push((name.into(), v));
    }
    // splice: chunk 0 from a different file (other nonce) under the same key/AD
    let mut other = Vec::new();
    format::seal_stream(&a, &pt[..], &mut other, cs, b"ad", &[7u8; 16], 1).unwrap();
    let mut v = ct.clone();
    v[r(0)..r(1)].copy_from_slice(&other[r(0)..r(1)]);
    cases.push(("splice chunk from other file".into(), v));

    for (name, v) in &cases {
        for t in [1, 4] {
            assert!(open(&a, v, b"ad", t).is_err(), "accepted tampered file: {name} (t={t})");
        }
    }
    // wrong AD, wrong key
    assert!(matches!(open(&a, &ct, b"aD", 1), Err(FileError::Auth(0))));
    assert!(matches!(open(&a, &ct, b"", 1), Err(FileError::Auth(0))));
    assert!(matches!(open(&aead(1), &ct, b"ad", 1), Err(FileError::Auth(0))));
    // and the untouched file still opens
    assert_eq!(open(&a, &ct, b"ad", 4).unwrap(), pt);
    eprintln!("{} tampered variants rejected", cases.len());
}

#[test]
fn exact_multiple_has_no_empty_tail_and_truncation_at_boundary_fails() {
    let a = aead(0);
    let cs = 1024;
    let pt = data(3 * cs);
    let ct = seal(&a, &pt, cs, b"", 1);
    assert_eq!(ct.len(), FILE_HEADER_LEN + 3 * (TAG + cs));
    // cutting at the chunk-2 boundary leaves a well-formed-looking 2-chunk file: must fail
    assert!(matches!(open(&a, &ct[..FILE_HEADER_LEN + 2 * (TAG + cs)], b"", 1), Err(FileError::Auth(1))));
}
