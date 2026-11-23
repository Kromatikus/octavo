//! fix2 AEAD tests (SN3C/ 0x1C PMAC-SIV blobs). Homemade; for real secrets use AES-GCM-SIV, age, or libsodium.
use crate::aead::*;
use crate::{Backend, SEED_LEN};
use std::sync::OnceLock;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

fn seed(tag: u8) -> [u8; SEED_LEN] {
    core::array::from_fn(|i| (i as u8).wrapping_mul(29).wrapping_add(tag))
}

fn aead() -> &'static Aead {
    static A: OnceLock<Aead> = OnceLock::new();
    A.get_or_init(|| Aead::new(&seed(7)))
}

const N1: [u8; 16] = *b"nonce-0000000001";

#[test]
fn aead_roundtrip_lengths() {
    let a = aead();
    let mut r = Rng(1);
    for &len in &[0usize, 1, 31, 54, 73, 74, 75, 127, 128, 129, 201, 202, 203, 255, 256, 257, 1000, 64 * 128, 64 * 128 + 5, 200 * 128 + 77] {
        let m = r.bytes(len);
        let ad = r.bytes(len % 300);
        let b = a.seal(&N1, &ad, &m).unwrap();
        assert_eq!(b.len(), OVERHEAD + len);
        assert_eq!(&b[..5], b"SN3C/");
        assert_eq!(b[5], AEAD_FORMAT);
        assert_eq!(a.open(&ad, &b).unwrap(), m, "len {len}");
        if len > 0 {
            assert_ne!(&b[OVERHEAD..], &m[..], "ciphertext equals plaintext at len {len}");
        }
    }
}

#[test]
fn aead_large_message() {
    let a = aead();
    let m = Rng(2).bytes(1 << 20);
    let b = a.seal(&N1, b"big", &m).unwrap();
    assert_eq!(a.open(b"big", &b).unwrap(), m);
    let mut t = b.clone();
    let n = t.len();
    t[n / 2] ^= 0x10;
    assert_eq!(a.open(b"big", &t), Err(AeadError::AuthFailed));
}

#[test]
fn aead_tamper_every_bit_rejected() {
    let a = aead();
    for &len in &[0usize, 40, 128, 130] {
        let m = Rng(3 + len as u64).bytes(len);
        let b = a.seal(&N1, b"ad", &m).unwrap();
        for bit in 0..b.len() * 8 {
            let mut t = b.clone();
            t[bit / 8] ^= 1 << (bit % 8);
            assert!(a.open(b"ad", &t).is_err(), "bit {bit} len {len} accepted");
        }
    }
}

#[test]
fn aead_truncation_and_extension_rejected() {
    let a = aead();
    let m = Rng(4).bytes(300);
    let b = a.seal(&N1, b"", &m).unwrap();
    for cut in 0..b.len() {
        let e = a.open(b"", &b[..cut]).unwrap_err();
        if cut < OVERHEAD {
            assert_eq!(e, AeadError::TooShort);
        } else {
            assert_eq!(e, AeadError::AuthFailed);
        }
    }
    let mut x = b.clone();
    x.push(0);
    assert_eq!(a.open(b"", &x), Err(AeadError::AuthFailed));
}

#[test]
fn aead_header_errors() {
    let a = aead();
    let b = a.seal(&N1, b"", b"hello").unwrap();
    assert_eq!(b[5], AEAD_FORMAT);
    let mut p = b.clone();
    p[0] = b'X';
    assert_eq!(a.open(b"", &p), Err(AeadError::BadPrefix));
    let mut f = b.clone();
    f[5] = 0x1A;
    assert_eq!(a.open(b"", &f), Err(AeadError::BadFormat));
    // fix1 blobs must not parse as this lab format
    let mut old = b.clone();
    old[5] = 0x1B;
    assert_eq!(a.open(b"", &old), Err(AeadError::BadFormat));
    assert_eq!(parse_blob(&old).unwrap_err(), AeadError::BadFormat);
    assert_eq!(parse_blob(&[]).unwrap_err(), AeadError::TooShort);
}

#[test]
fn aead_ad_binding() {
    let a = aead();
    let b = a.seal(&N1, b"header-A", b"msg").unwrap();
    assert_eq!(a.open(b"header-B", &b), Err(AeadError::AuthFailed));
    assert_eq!(a.open(b"", &b), Err(AeadError::AuthFailed));
    let e = a.seal(&N1, b"", b"msg").unwrap();
    let z = a.seal(&N1, &[0u8], b"msg").unwrap();
    assert_ne!(e, z, "empty AD and one zero byte must differ");
    assert_eq!(a.open(&[0u8], &e), Err(AeadError::AuthFailed));
    // swapping AD and message content must not collide
    let s1 = a.seal(&N1, b"xy", b"").unwrap();
    let s2 = a.seal(&N1, b"", b"xy").unwrap();
    assert_ne!(s1[22..54], s2[22..54]);
}

#[test]
fn aead_block_reorder_rejected() {
    let a = aead();
    // Two 128-byte message halves: swapped content must produce a different tag.
    let left = Rng(11).bytes(128);
    let right = Rng(12).bytes(128);
    let mut m1 = left.clone();
    m1.extend_from_slice(&right);
    let mut m2 = right.clone();
    m2.extend_from_slice(&left);
    let b1 = a.seal(&N1, b"", &m1).unwrap();
    let b2 = a.seal(&N1, b"", &m2).unwrap();
    assert_ne!(&b1[22..54], &b2[22..54], "swapped 128-byte message blocks must not share a tag");
    assert_eq!(a.open(b"", &b1).unwrap(), m1);
    assert_eq!(a.open(b"", &b2).unwrap(), m2);

    // Swapping the two ciphertext blocks of b1 must fail to open.
    let mut swapped = b1.clone();
    let c = &mut swapped[OVERHEAD..];
    let (x, y) = c.split_at_mut(128);
    x.swap_with_slice(&mut y[..128]);
    assert_eq!(a.open(b"", &swapped), Err(AeadError::AuthFailed));

    // Stronger: with |AD| = 74 the length-prefixed transcript is 128 + |M|, so
    // |M| = 256 makes the two message halves into PMAC blocks 1 and 2 exactly
    // (block 0 is the header/AD/nonce prefix; the whole transcript is three
    // full blocks, last finalized with 3L). Swapping those halves must change the tag.
    let ad = Rng(13).bytes(74);
    let x = Rng(14).bytes(128);
    let yb = Rng(15).bytes(128);
    let mut mx = x.clone();
    mx.extend_from_slice(&yb);
    let mut my = yb.clone();
    my.extend_from_slice(&x);
    let tx = a.seal(&N1, &ad, &mx).unwrap();
    let ty = a.seal(&N1, &ad, &my).unwrap();
    assert_ne!(&tx[22..54], &ty[22..54], "swapped transcript blocks 1 and 2 must not share a tag");
    assert_eq!(a.open(&ad, &tx).unwrap(), mx);
    assert_eq!(a.open(&ad, &ty).unwrap(), my);
}

#[test]
fn aead_wrong_key_rejected() {
    let b = aead().seal(&N1, b"", b"secret").unwrap();
    let other = Aead::new(&seed(8));
    assert_eq!(other.open(b"", &b), Err(AeadError::AuthFailed));
}

#[test]
fn aead_nonce_reuse_leaks_only_equality() {
    let a = aead();
    let m1 = Rng(5).bytes(500);
    let mut m2 = m1.clone();
    m2[499] ^= 1; // differ only in the last byte
    let b1 = a.seal(&N1, b"", &m1).unwrap();
    let b1b = a.seal(&N1, b"", &m1).unwrap();
    let b2 = a.seal(&N1, b"", &m2).unwrap();
    assert_eq!(b1, b1b, "deterministic: identical inputs give identical blobs");
    assert_ne!(b1[22..54], b2[22..54], "different messages, same nonce: different tags");
    // no keystream reuse: ct1 ^ ct2 must not equal m1 ^ m2 (would hold with reused CTR)
    let c1 = &b1[OVERHEAD..];
    let c2 = &b2[OVERHEAD..];
    let same_prefix = (0..499).filter(|&i| c1[i] ^ c2[i] == 0).count();
    assert!(same_prefix < 20, "ciphertexts share {same_prefix} of 499 equal bytes");
    // different nonce, same message -> different blob
    let b3 = a.seal(b"nonce-0000000002", b"", &m1).unwrap();
    assert_ne!(b1[22..], b3[22..]);
}

#[test]
fn aead_all_backends_agree() {
    let mut r = Rng(6);
    let m = r.bytes(64 * 128 + 33);
    let ad = r.bytes(77);
    let reference = Aead::with_backend(&seed(9), Backend::Table).unwrap().seal(&N1, &ad, &m).unwrap();
    assert_eq!(reference[5], AEAD_FORMAT);
    let mut n = 0;
    for b in Backend::ALL {
        if !b.supported() {
            continue;
        }
        let a = Aead::with_backend(&seed(9), b).unwrap();
        assert_eq!(a.seal(&N1, &ad, &m).unwrap(), reference, "backend {:?}", b);
        assert_eq!(a.open(&ad, &reference).unwrap(), m);
        n += 1;
    }
    // This box should have all five (avx512gfni, avx2gfni, avx2, portable, table).
    assert_eq!(n, Backend::ALL.len(), "expected every backend, got {n}");
}

#[test]
fn aead_fuzz_parser_no_panics() {
    let a = aead();
    let mut r = Rng(10);
    let good = a.seal(&N1, b"f", b"fuzz me please").unwrap();
    let mut accepted = 0;
    for i in 0..20_000 {
        let blob = match i % 4 {
            0 => {
                let n = (r.next() % 200) as usize;
                r.bytes(n)
            }
            1 => {
                let mut v = b"SN3C/".to_vec();
                v.push(if r.next() & 1 == 0 { AEAD_FORMAT } else { r.next() as u8 });
                let n = (r.next() % 120) as usize;
                v.extend(r.bytes(n));
                v
            }
            2 => {
                let mut v = good.clone();
                for _ in 0..1 + r.next() % 4 {
                    let p = (r.next() as usize) % v.len();
                    v[p] = r.next() as u8;
                }
                v
            }
            _ => {
                let mut v = good.clone();
                let cut = (r.next() as usize) % (v.len() + 1);
                v.truncate(cut);
                v
            }
        };
        let _ = parse_blob(&blob);
        if a.open(b"f", &blob).is_ok() {
            accepted += 1;
            assert_eq!(blob, good);
        }
    }
    assert!(accepted <= 5_000);
}

#[test]
fn dbl_matches_integer_shift() {
    // dbl(1) = 2; dbl(x^1023) = x^19 + x^6 + x + 1
    let mut one = [0u8; 128];
    one[127] = 1;
    let d = crate::aead::dbl_pub(&one);
    let mut two = [0u8; 128];
    two[127] = 2;
    assert_eq!(d, two);
    let mut top = [0u8; 128];
    top[0] = 0x80;
    let d = crate::aead::dbl_pub(&top);
    let mut red = [0u8; 128];
    red[127] = 0x43;
    red[125] = 0x08;
    assert_eq!(d, red);
}

#[test]
fn pmac_offsets_match_closed_form_and_3l_5l() {
    let a = aead();
    let lpow = a.lpow_ref();
    // Recurrence starting at Δ_0 = L[1], then Δ_k = Δ_{k-1} ⊕ L[ntz(k+1)+1]
    let mut rec = lpow[1];
    for k in 0..40u64 {
        let closed = crate::aead::gray_delta_pub(lpow, k);
        assert_eq!(rec, closed, "delta mismatch at k={k}");
        if k + 1 < 40 {
            let i = k + 2;
            let tz = i.trailing_zeros() as usize + 1;
            for (x, y) in rec.iter_mut().zip(lpow[tz].iter()) {
                *x ^= *y;
            }
        }
    }
    // 3L = L ⊕ 2L, 5L = L ⊕ 4L
    let mut three = lpow[0];
    for (x, y) in three.iter_mut().zip(lpow[1].iter()) {
        *x ^= *y;
    }
    let mut five = lpow[0];
    for (x, y) in five.iter_mut().zip(lpow[2].iter()) {
        *x ^= *y;
    }
    assert_eq!(&three, a.k_full_ref());
    assert_eq!(&five, a.k_part_ref());
}

#[test]
fn aead_kat_matches_file() {
    // Known-answer vectors cross-checked by tools/aead_ref.py (independent Python implementation).
    let raw = include_str!("../../vectors/aead_fix2_vectors.txt");
    let mut n = 0;
    for line in raw.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()) {
        let f: Vec<&str> = line.split_whitespace().collect();
        let h = |s: &str| -> Vec<u8> {
            if s == "-" { return vec![]; }
            (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
        };
        let sd: [u8; SEED_LEN] = h(f[0]).try_into().unwrap();
        let nonce: [u8; 16] = h(f[1]).try_into().unwrap();
        let (ad, m, blob) = (h(f[2]), h(f[3]), h(f[4]));
        let a = Aead::new(&sd);
        let got = a.seal(&nonce, &ad, &m).unwrap();
        assert_eq!(got[5], AEAD_FORMAT);
        assert_eq!(got, blob);
        assert_eq!(a.open(&ad, &blob).unwrap(), m);
        n += 1;
    }
    assert!(n >= 4);
}
