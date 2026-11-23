//! fallback1 tests: every backend forced, against the SN3C/ 0x1B vectors,
//! against each other on random keys/blocks, and the Benes router variants.

use super::*;

struct R(u64);
impl R {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn fill(&mut self, b: &mut [u8]) {
        for x in b.iter_mut() {
            *x = self.next() as u8;
        }
    }
}

fn hex<const N: usize>(s: &str) -> [u8; N] {
    let mut a = [0u8; N];
    for i in 0..N {
        a[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    a
}

fn vectors() -> Vec<(String, [u8; SEED_LEN], [u8; NONCE_LEN], [u8; BLOCK_LEN], [u8; BLOCK_LEN])> {
    let raw = include_str!("../../vectors/fix1_vectors.json");
    let keys = ["name", "seed", "nonce", "pt", "ct"];
    let toks: Vec<&str> = raw.split('"').collect();
    let mut out = Vec::new();
    let mut cur: [String; 5] = Default::default();
    let mut have = 0u8;
    for i in 0..toks.len().saturating_sub(2) {
        if let Some(k) = keys.iter().position(|&x| x == toks[i]) {
            cur[k] = toks[i + 2].to_string();
            have |= 1 << k;
            if have == 0b11111 {
                out.push((cur[0].clone(), hex(&cur[1]), hex(&cur[2]), hex(&cur[3]), hex(&cur[4])));
                have = 0;
            }
        }
    }
    assert!(out.len() >= 5);
    out
}

fn supported() -> Vec<Backend> {
    let v: Vec<Backend> = Backend::ALL.iter().copied().filter(|b| b.supported()).collect();
    eprintln!("supported backends: {:?}", v);
    v
}

#[test]
fn fb_vectors_every_backend() {
    for b in supported() {
        for (name, seed, nonce, pt, ct) in vectors() {
            let c = Cipher::with_backend(&seed, &nonce, b).unwrap();
            assert_eq!(c.backend(), b);
            assert_eq!(c.encrypt_block(&pt), ct, "{} enc mismatch on {name}", b.name());
            assert_eq!(c.decrypt_block(&ct), pt, "{} dec mismatch on {name}", b.name());
            // batch API, odd sizes (partial 4-block groups)
            for n in [1usize, 2, 3, 5, 7, 64] {
                let mut blocks = vec![pt; n];
                c.encrypt_blocks(&mut blocks);
                assert!(blocks.iter().all(|x| *x == ct), "{} batch-{n} on {name}", b.name());
                c.decrypt_blocks(&mut blocks);
                assert!(blocks.iter().all(|x| *x == pt), "{} batch-{n} dec on {name}", b.name());
            }
        }
    }
}

#[test]
fn fb_random_cross_backend() {
    let bs = supported();
    let mut r = R(0xFA11_BAC1);
    for key in 0..24 {
        let mut seed = [0u8; SEED_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        r.fill(&mut seed);
        r.fill(&mut nonce);
        let n = 1 + (key % 11);
        let mut blocks = vec![[0u8; BLOCK_LEN]; n];
        for b in blocks.iter_mut() {
            r.fill(b);
        }
        let reference = Cipher::with_backend(&seed, &nonce, Backend::Table).unwrap();
        let mut want = blocks.clone();
        reference.encrypt_blocks(&mut want);
        for &b in &bs {
            let c = Cipher::with_backend(&seed, &nonce, b).unwrap();
            let mut got = blocks.clone();
            c.encrypt_blocks(&mut got);
            assert_eq!(got, want, "{} batch enc differs (key {key})", b.name());
            for i in 0..n {
                assert_eq!(c.encrypt_block(&blocks[i]), want[i], "{} single enc", b.name());
                assert_eq!(c.decrypt_block(&want[i]), blocks[i], "{} single dec", b.name());
            }
            c.decrypt_blocks(&mut got);
            assert_eq!(got, blocks, "{} batch dec (key {key})", b.name());
        }
    }
}

#[test]
fn fb_env_override_and_errors() {
    assert_eq!(Backend::parse("AVX2"), Some(Backend::Avx2));
    assert_eq!(Backend::parse("avx2gfni"), Some(Backend::Avx2Gfni));
    assert_eq!(Backend::parse("portable"), Some(Backend::Portable));
    assert_eq!(Backend::parse("nope"), None);
    assert!(Backend::best().supported());
    assert_ne!(Backend::best(), Backend::Table);
    for b in Backend::ALL {
        let r = Cipher::with_backend(&[1u8; SEED_LEN], &[2u8; NONCE_LEN], b);
        assert_eq!(r.is_ok(), b.supported());
    }
}

#[test]
fn fb_soft_router_matches_avx512_router() {
    #[cfg(target_arch = "x86_64")]
    {
        if !gfni_available() {
            eprintln!("no AVX-512 here; skipping router cross-check");
            return;
        }
        let mut r = R(0xBE5E5);
        for n in 0..300 {
            let mut p: [u8; 64] = core::array::from_fn(|i| i as u8);
            if n > 0 {
                for i in (1..64).rev() {
                    let j = (r.next() % (i as u64 + 1)) as usize;
                    p.swap(i, j);
                }
            }
            let (hw, sw) = crate::gfni::benes_route_both(&p);
            assert_eq!(hw[..], sw[..], "soft PEXT differs from hardware PEXT");
            let bits = crate::benes_soft::benes_route_bits(&p);
            for st in 0..11 {
                for k in 0..32 {
                    let want = hw[st * 32 + k] != 0;
                    assert_eq!((bits[st] >> k) & 1 == 1, want, "perm {n} stage {st} switch {k}");
                }
            }
            // and the row-layout masks realise out[c] = in[p[c]] on the upper half
            let masks = crate::fallback::benes_row_masks(&bits);
            let mut v: [u8; 64] = core::array::from_fn(|i| i as u8);
            let mut w = [0u64; 8];
            for i in 0..8 {
                w[i] = u64::from_le_bytes(v[8 * i..8 * i + 8].try_into().unwrap());
            }
            for st in 0..11 {
                let m = crate::fallback::BENES_STRIDES[st];
                if m >= 8 {
                    let d = m / 8;
                    let mut q = 0;
                    for x in 0..8 {
                        if x & d == 0 {
                            let t = (w[x] ^ w[x + d]) & masks[st][q];
                            w[x] ^= t;
                            w[x + d] ^= t;
                            q += 1;
                        }
                    }
                } else {
                    let s = 8 * m as u32;
                    for x in 0..8 {
                        let t = ((w[x] >> s) ^ w[x]) & masks[st][x];
                        w[x] ^= t ^ (t << s);
                    }
                }
            }
            for i in 0..8 {
                v[8 * i..8 * i + 8].copy_from_slice(&w[i].to_le_bytes());
            }
            for c in 0..64 {
                assert_eq!(v[c], p[c], "row Benes perm {n} pos {c}");
            }
        }
    }
}
