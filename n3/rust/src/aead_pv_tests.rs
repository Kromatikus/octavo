//! Tests for the EXPERIMENTAL 0x1D POLYVAL-SIV AEAD. Homemade; for real secrets use AES-GCM-SIV, age, or libsodium.
use crate::aead::{Aead, AeadError, OVERHEAD};
use crate::aead_pv::*;
use crate::SEED_LEN;
use polyval::universal_hash::{KeyInit, UniversalHash};
use polyval::Polyval;

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
fn hx(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}
const N1: [u8; 16] = *b"nonce-0000000001";
const N2: [u8; 16] = *b"nonce-0000000002";

#[test]
fn polyval_rfc8452_vector() {
    // RFC 8452 Appendix A: POLYVAL test vector.
    let h = hx("25629347589242761d31f826ba4b757b");
    let mut p = Polyval::new((&h[..]).into());
    p.update_padded(&hx("4f4f95668c83dfb6401762bb2d01a262d1a24ddd2721d006bbe45f20d3c9f362"));
    let out: [u8; 16] = p.finalize().into();
    assert_eq!(out.to_vec(), hx("f7a3b47b846119fae5b7866cf5e5b77e"));
}

#[test]
fn pv_roundtrip_sizes() {
    let a = AeadPv::new(&seed(7));
    let mut r = Rng(1);
    let big = 256 * 1024;
    for &len in &[0usize, 1, 15, 16, 17, 127, 128, 129, 255, 256, 257, 8192, big - 1, big, big + 1, 16 << 20] {
        let m = r.bytes(len);
        let ad = r.bytes(len % 300);
        let b = a.seal(&N1, &ad, &m).unwrap();
        assert_eq!(b.len(), OVERHEAD + len);
        assert_eq!(&b[..5], b"SN3C/");
        assert_eq!(b[5], PV_FORMAT);
        assert_eq!(a.open(&ad, &b).unwrap(), m, "len {len}");
        if len > 0 {
            assert_ne!(&b[OVERHEAD..], &m[..]);
        }
    }
}

#[test]
fn pv_tamper_ad_truncate_rejected() {
    let a = AeadPv::new(&seed(7));
    let mut r = Rng(2);
    for &len in &[0usize, 1, 127, 128, 129, 5000, 300_000] {
        let m = r.bytes(len);
        let b = a.seal(&N1, b"ad", &m).unwrap();
        assert_eq!(a.open(b"ad", &b).unwrap(), m);
        assert_eq!(a.open(b"ae", &b), Err(AeadError::AuthFailed));
        assert_eq!(a.open(b"", &b), Err(AeadError::AuthFailed));
        // every header/tag byte, and sampled ciphertext bytes, one bit flipped
        let mut pos: Vec<usize> = (6..OVERHEAD).collect();
        for k in 0..len.min(40) {
            pos.push(OVERHEAD + (k * 7919) % len.max(1));
        }
        if len > 0 {
            pos.push(b.len() - 1);
        }
        for p in pos {
            let mut t = b.clone();
            t[p] ^= 1 << (p % 8);
            assert_eq!(a.open(b"ad", &t), Err(AeadError::AuthFailed), "len {len} pos {p}");
        }
        // truncation / extension
        if len > 0 {
            assert_eq!(a.open(b"ad", &b[..b.len() - 1]), Err(AeadError::AuthFailed));
        }
        let mut e = b.clone();
        e.push(0);
        assert_eq!(a.open(b"ad", &e), Err(AeadError::AuthFailed));
        if b.len() > OVERHEAD {
            assert_eq!(a.open(b"ad", &b[..OVERHEAD]), Err(AeadError::AuthFailed));
        }
        assert_eq!(a.open(b"ad", &b[..OVERHEAD - 1]), Err(AeadError::TooShort));
    }
    // wrong key
    let b = a.seal(&N1, b"", b"hello").unwrap();
    assert_eq!(AeadPv::new(&seed(8)).open(b"", &b), Err(AeadError::AuthFailed));
    // prefix / format byte
    let mut t = b.clone();
    t[0] ^= 1;
    assert_eq!(a.open(b"", &t), Err(AeadError::BadPrefix));
    let mut t = b.clone();
    t[5] = 0x1C;
    assert_eq!(a.open(b"", &t), Err(AeadError::BadFormat));
}

#[test]
fn pv_nonce_reuse_equality_only() {
    let a = AeadPv::new(&seed(7));
    let mut r = Rng(3);
    let m1 = r.bytes(1000);
    let mut m2 = m1.clone();
    m2[500] ^= 1;
    // identical triple -> identical blob (the only leak)
    assert_eq!(a.seal(&N1, b"x", &m1).unwrap(), a.seal(&N1, b"x", &m1).unwrap());
    let b1 = a.seal(&N1, b"x", &m1).unwrap();
    let b2 = a.seal(&N1, b"x", &m2).unwrap();
    // one-bit-different messages under the SAME nonce: different tag, unrelated keystream
    assert_ne!(&b1[22..54], &b2[22..54]);
    let x: Vec<u8> = b1[OVERHEAD..].iter().zip(&b2[OVERHEAD..]).map(|(p, q)| p ^ q).collect();
    let mx: Vec<u8> = m1.iter().zip(&m2).map(|(p, q)| p ^ q).collect();
    assert_ne!(x, mx, "keystream reused across different messages");
    let differing = x.iter().filter(|&&v| v != 0).count();
    assert!(differing > 900, "ciphertexts not independent: {differing}");
    // different AD alone changes tag too
    assert_ne!(&b1[22..54], &a.seal(&N1, b"y", &m1).unwrap()[22..54]);
    // different nonce, same msg: different tag and ciphertext
    let b3 = a.seal(&N2, b"x", &m1).unwrap();
    assert_ne!(&b1[22..54], &b3[22..54]);
    assert_ne!(&b1[OVERHEAD..], &b3[OVERHEAD..]);
    // AD/message boundary shifts do not collide
    let c1 = a.seal(&N1, b"ab", b"cd").unwrap();
    let c2 = a.seal(&N1, b"a", b"bcd").unwrap();
    let c3 = a.seal(&N1, b"abc", b"d").unwrap();
    assert_ne!(&c1[22..54], &c2[22..54]);
    assert_ne!(&c1[22..54], &c3[22..54]);
    // all blobs still open
    assert_eq!(a.open(b"x", &b1).unwrap(), m1);
    assert_eq!(a.open(b"x", &b2).unwrap(), m2);
}

#[test]
fn pv_threads_equal_single() {
    let mut r = Rng(4);
    for &len in &[0usize, 127, 128 * 64, 128 * 64 * 3 + 77, 1 << 20, (1 << 20) + 5, 3 << 20] {
        let m = r.bytes(len);
        let a1 = AeadPv::new(&seed(7)).with_threads(1).with_par_min(0);
        let ref_blob = a1.seal(&N1, b"ad", &m).unwrap();
        for th in [2usize, 3, 4, 8, 16] {
            let at = AeadPv::new(&seed(7)).with_threads(th).with_par_min(0);
            assert_eq!(at.seal(&N1, b"ad", &m).unwrap(), ref_blob, "len {len} threads {th}");
            assert_eq!(at.open(b"ad", &ref_blob).unwrap(), m);
        }
    }
}

#[test]
fn pv_fallback_backend_identical() {
    use crate::Backend;
    let m = Rng(5).bytes(70_000);
    let best = AeadPv::new(&seed(7)).seal(&N1, b"ad", &m).unwrap();
    for be in Backend::ALL {
        if !be.supported() {
            continue;
        }
        let a = AeadPv::with_backend(&seed(7), be).unwrap();
        assert_eq!(a.seal(&N1, b"ad", &m).unwrap(), best, "backend {}", be.name());
    }
}

#[test]
fn pv_separate_from_0x1c() {
    let m = Rng(6).bytes(500);
    let old = Aead::new(&seed(7));
    let pv = AeadPv::new(&seed(7));
    let bo = old.seal(&N1, b"ad", &m).unwrap();
    let bp = pv.seal(&N1, b"ad", &m).unwrap();
    assert_eq!(bo[5], 0x1C);
    assert_eq!(bp[5], 0x1D);
    assert_eq!(old.open(b"ad", &bp), Err(AeadError::BadFormat));
    assert_eq!(pv.open(b"ad", &bo), Err(AeadError::BadFormat));
    assert_ne!(&bo[22..54], &bp[22..54]);
}

#[test]
fn pv_kat_stable() {
    // Pin the construction: any change to the derivation/tag/CTR layout changes this digest.
    use sha2::{Digest, Sha256};
    let a = AeadPv::new(&seed(7));
    let mut h = Sha256::new();
    for &len in &[0usize, 1, 128, 129, 1000] {
        let m: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(5).wrapping_add(3)).collect();
        h.update(a.seal(&N1, b"kat-ad", &m).unwrap());
    }
    let d: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(d, KAT_DIGEST, "0x1D construction changed");
}
const KAT_DIGEST: &str = "9b338b2a9d8b275a390821205ca50ef6de4494e0e39a9f69cd6226d5a1af48d4";
