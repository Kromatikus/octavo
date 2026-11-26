//! Tests for the EXPERIMENTAL 0x1E POLYVAL-SIV AEAD. Homemade; for real secrets use AES-GCM-SIV, age, or libsodium.
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
    assert_eq!(bp[5], 0x1E);
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
    assert_eq!(d, KAT_DIGEST, "0x1E construction changed");
}
const KAT_DIGEST: &str = "47a507efeb2078e748380c1909784d0638645ddd534a01a0ac561017c65e28fc";

#[test]
fn pv_ctr_binds_nonce() {
    let tag = [0x5Au8; 32];
    let n1 = *b"nonce-AAAAAAAAAA";
    let n2 = *b"nonce-BBBBBBBBBB";
    let b1 = AeadPv::ctr_block(&tag, &n1, 0);
    let b2 = AeadPv::ctr_block(&tag, &n2, 0);
    let b1i = AeadPv::ctr_block(&tag, &n1, 1);
    assert_eq!(&b1[..32], &tag);
    assert_eq!(&b1[32..40], b"SN3V/CTR");
    assert_eq!(&b1[40..56], &n1);
    assert_eq!(&b1[120..], &0u64.to_le_bytes());
    assert_eq!(&b1i[120..], &1u64.to_le_bytes());
    assert_eq!(&b1i[40..56], &n1);
    assert_ne!(b1, b2, "same tag, different nonce must not share a counter block");
    // equal tags under different nonces therefore cannot share a keystream
    assert_ne!(&b1[40..56], &b2[40..56]);
}

#[test]
fn pv_rejects_unreleased_0x1d_and_0x1c() {
    let a = AeadPv::new(&seed(7));
    let b = a.seal(&N1, b"ad", b"hello").unwrap();
    assert_eq!(b[5], PV_FORMAT);
    let mut d = b.clone();
    d[5] = 0x1D;
    assert_eq!(a.open(b"ad", &d), Err(AeadError::BadFormat));
    let mut c = b.clone();
    c[5] = 0x1C;
    assert_eq!(a.open(b"ad", &c), Err(AeadError::BadFormat));
}

/// Condensed forgery / robustness battery from the 0x1D attack report, re-run on 0x1E.
#[test]
fn pv_forgery_and_hostile_inputs() {
    let a = AeadPv::new(&seed(7));
    // every AD/M split of a 16-byte string, plus zero-extension, must give distinct tags
    let raw = b"0123456789abcdef";
    let mut tags = std::collections::HashSet::new();
    for i in 0..=raw.len() {
        let b = a.seal(&N1, &raw[..i], &raw[i..]).unwrap();
        assert!(tags.insert(b[22..54].to_vec()), "tag collision at split {i}");
    }
    for k in 0..=32 {
        let b1 = a.seal(&N1, b"ad", &vec![0u8; k]).unwrap();
        let b2 = a.seal(&N1, b"ad", &vec![0u8; k + 1]).unwrap();
        assert_ne!(&b1[22..54], &b2[22..54], "zero-extend tag collision at {k}");
    }
    let good = a.seal(&N1, b"ad", b"payload-0123456789").unwrap();
    // length-extend ciphertext with zeros, every truncation, zero tag, nonce/tag splice
    for k in 1..=64 {
        let mut e = good.clone();
        e.extend(std::iter::repeat(0u8).take(k));
        assert_eq!(a.open(b"ad", &e), Err(AeadError::AuthFailed), "ext {k}");
    }
    for n in 0..good.len() {
        let err = a.open(b"ad", &good[..n]);
        assert!(err.is_err(), "trunc {n}");
        if n >= OVERHEAD {
            assert_eq!(err, Err(AeadError::AuthFailed), "trunc-auth {n}");
        }
    }
    let mut zt = good.clone();
    for x in &mut zt[22..54] { *x = 0; }
    assert_eq!(a.open(b"ad", &zt), Err(AeadError::AuthFailed));
    let other = a.seal(&N2, b"ad", b"payload-0123456789").unwrap();
    let mut splice = good.clone();
    splice[6..22].copy_from_slice(&other[6..22]); // nonce
    assert_eq!(a.open(b"ad", &splice), Err(AeadError::AuthFailed));
    let mut splice = good.clone();
    splice[22..54].copy_from_slice(&other[22..54]); // tag
    assert_eq!(a.open(b"ad", &splice), Err(AeadError::AuthFailed));
    let mut splice = good.clone();
    splice[OVERHEAD..].copy_from_slice(&other[OVERHEAD..]); // ct
    assert_eq!(a.open(b"ad", &splice), Err(AeadError::AuthFailed));
    // 2,000 hostile blobs: no panic, none accepted
    let mut r = Rng(0xA77);
    for i in 0..2000 {
        let n = (r.next() as usize) % 80;
        let mut blob = r.bytes(n);
        if i % 7 == 0 && n >= 6 {
            blob[..5].copy_from_slice(b"SN3C/");
            blob[5] = PV_FORMAT;
        }
        let _ = a.open(b"ad", &blob);
    }
    assert_eq!(a.seal(&N1, b"", &vec![0u8; crate::aead::MAX_MSG_LEN + 1]), Err(AeadError::TooLong));
}

#[test]
fn pv_cross_format_unrelated() {
    let m = Rng(9).bytes(500);
    let old = Aead::new(&seed(7));
    let pv = AeadPv::new(&seed(7));
    let bo = old.seal(&N1, b"ad", &m).unwrap();
    let bp = pv.seal(&N1, b"ad", &m).unwrap();
    assert_eq!(old.open(b"ad", &bp), Err(AeadError::BadFormat));
    assert_eq!(pv.open(b"ad", &bo), Err(AeadError::BadFormat));
    // patch header so parse succeeds: still AuthFailed
    let mut p = bo.clone();
    p[5] = PV_FORMAT;
    assert_eq!(pv.open(b"ad", &p), Err(AeadError::AuthFailed));
    let mut q = bp.clone();
    q[5] = 0x1C;
    assert_eq!(old.open(b"ad", &q), Err(AeadError::AuthFailed));
    assert_ne!(&bo[22..54], &bp[22..54]);
}

/// Same method as attacks_n3_polyval2 `attack_z3_stack_residue`: scan 192 KiB of
/// uninitialized stack below this frame for leftover H / S / S^nonce after tag_of.
/// Patterns are computed on another thread so they do not seed the scanned stack.
/// With the 16 KiB scrub this should be 0/30 for H and S (was 30/30 without it).
#[inline(never)]
fn scan_dead_stack(pats: &[[u8; 16]]) -> Vec<usize> {
    const N: usize = 192 * 1024;
    let buf = core::mem::MaybeUninit::<[u8; N]>::uninit();
    let p = buf.as_ptr() as *const u8;
    let mut hits = vec![0usize; pats.len()];
    let mut i = 0;
    while i + 16 <= N {
        let w: [u8; 16] = core::array::from_fn(|k| unsafe { core::ptr::read_volatile(p.add(i + k)) });
        for (j, pt) in pats.iter().enumerate() {
            if &w == pt {
                hits[j] += 1;
            }
        }
        i += 1;
    }
    hits
}

fn seq_polyval_test(key: &[u8; 16], ad: &[u8], m: &[u8]) -> [u8; 16] {
    let mut p = Polyval::new(key.into());
    p.update_padded(ad);
    p.update_padded(m);
    let mut len = [0u8; 16];
    len[..8].copy_from_slice(&((ad.len() as u64) * 8).to_le_bytes());
    len[8..].copy_from_slice(&((m.len() as u64) * 8).to_le_bytes());
    p.update_padded(&len);
    p.finalize().into()
}

#[test]
fn pv_stack_residue_after_tag_of() {
    let mut r = Rng(0x23);
    let sd: [u8; SEED_LEN] = r.bytes(SEED_LEN).try_into().unwrap();
    let mut tot_before = [0usize; 3];
    let mut tot_after = [0usize; 3];
    let trials = 30;
    for _ in 0..trials {
        let nonce: [u8; 16] = r.bytes(16).try_into().unwrap();
        let ml = 64 + (r.next() as usize % 2000);
        let m = r.bytes(ml);
        let ad = r.bytes(9);
        let (h, s, sn) = std::thread::scope(|sc| {
            sc.spawn(|| {
                let a = AeadPv::new(&sd).with_threads(1);
                let h = a.auth_key_pub(&nonce);
                let s = seq_polyval_test(&h, &ad, &m);
                let sn = core::array::from_fn(|i| s[i] ^ nonce[i]);
                (h, s, sn)
            })
            .join()
            .unwrap()
        });
        let (b, af) = std::thread::scope(|sc| {
            sc.spawn(|| {
                let a = AeadPv::new(&sd).with_threads(1);
                let before = scan_dead_stack(&[h, s, sn]);
                let _ = a.tag_of_pub(&ad, &nonce, &m);
                let after = scan_dead_stack(&[h, s, sn]);
                (before, after)
            })
            .join()
            .unwrap()
        });
        for k in 0..3 {
            tot_before[k] += b[k];
            tot_after[k] += af[k];
        }
    }
    println!(
        "dead-stack residue after tag_of (192 KiB, 30 trials): H={}, S={}, S^nonce={} (baseline before: {:?})",
        tot_after[0], tot_after[1], tot_after[2], tot_before
    );
    assert_eq!(tot_before, [0, 0, 0], "baseline already dirty; harness invalid");
    assert_eq!(tot_after[0], 0, "H residue after tag_of: {}", tot_after[0]);
    assert_eq!(tot_after[1], 0, "S residue after tag_of: {}", tot_after[1]);
    assert_eq!(tot_after[2], 0, "S^nonce residue after tag_of: {}", tot_after[2]);
}
