//! Fast one-shot StaffSponge squeeze: SHA-256(b"SN2/" || domain || ctr32_be || seed || nonce) for
//! ctr = 0, 1, 2, ... Same bytes as `StaffSponge::fill`, only faster:
//! - the message is padded once into a template; per counter only the 4 counter bytes change;
//! - on CPUs with AVX-512F, 16 counters are hashed at once (one u32 lane each, 16-lane SHA-256);
//!   blocks after the one holding the counter are identical across lanes, so their message
//!   schedule (+K) is computed once and broadcast;
//! - otherwise `sha2::compress256` (SHA-NI when present) runs on the template.
//! SHA-256 has no data-dependent branches or lookups, and neither does this code.
#![allow(unsafe_code)]

use alloc::vec::Vec;
use sha2::digest::generic_array::GenericArray;

const IV: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
#[cfg_attr(not(all(target_arch = "x86_64", feature = "std")), allow(dead_code))]
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Padded message template with the counter at `ctr_at`.
struct Template {
    msg: Vec<u8>,
    ctr_at: usize,
}
impl Template {
    fn new(domain: &[u8], seed: &[u8], nonce: &[u8]) -> Template {
        let mut msg = Vec::with_capacity(4 + domain.len() + 4 + seed.len() + nonce.len() + 72);
        msg.extend_from_slice(b"SN2/");
        msg.extend_from_slice(domain);
        let ctr_at = msg.len();
        msg.extend_from_slice(&[0; 4]);
        msg.extend_from_slice(seed);
        msg.extend_from_slice(nonce);
        let bits = (msg.len() as u64) * 8;
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bits.to_be_bytes());
        Template { msg, ctr_at }
    }
}
// The template holds the seed: wipe it on drop (feature `zeroize`, best effort).
#[cfg(feature = "zeroize")]
impl Drop for Template {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.msg.zeroize();
    }
}

/// Fill `out` exactly like `StaffSponge::new(domain, seed, nonce).fill(out)`.
pub fn squeeze(domain: &[u8], seed: &[u8], nonce: &[u8], out: &mut [u8]) {
    squeeze_impl(domain, seed, nonce, out, true)
}
fn squeeze_impl(domain: &[u8], seed: &[u8], nonce: &[u8], out: &mut [u8], allow_mb: bool) {
    let _ = allow_mb; // unused without std
    let mut t = Template::new(domain, seed, nonce);
    let mut ctr: u32 = 0;
    let mut pos = 0;
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    if allow_mb && t.ctr_at + 4 <= 64 && out.len() >= 128 && std::is_x86_feature_detected!("avx512f") {
        // SAFETY: AVX-512F checked just above.
        unsafe { mb16(&t, &mut ctr, &mut pos, out) };
    }
    if pos == out.len() {
        return;
    }
    let nblk = t.msg.len() / 64;
    let mut blocks: Vec<GenericArray<u8, _>> = (0..nblk).map(|b| *GenericArray::from_slice(&t.msg[64 * b..64 * b + 64])).collect();
    while pos < out.len() {
        t.msg[t.ctr_at..t.ctr_at + 4].copy_from_slice(&ctr.to_be_bytes());
        for b in 0..nblk {
            if t.ctr_at < 64 * b + 64 && t.ctr_at + 4 > 64 * b {
                blocks[b].copy_from_slice(&t.msg[64 * b..64 * b + 64]);
            }
        }
        let mut st = IV;
        sha2::compress256(&mut st, &blocks);
        let mut h = [0u8; 32];
        for (i, w) in st.iter().enumerate() {
            h[4 * i..4 * i + 4].copy_from_slice(&w.to_be_bytes());
        }
        let n = (out.len() - pos).min(32);
        out[pos..pos + n].copy_from_slice(&h[..n]);
        pos += n;
        ctr += 1;
    }
    #[cfg(feature = "zeroize")]
    for b in blocks.iter_mut() {
        zeroize::Zeroize::zeroize(b.as_mut_slice());
    }
}

#[cfg(all(target_arch = "x86_64", feature = "std"))]
#[target_feature(enable = "avx512f")]
unsafe fn mb16(t: &Template, ctr: &mut u32, pos: &mut usize, out: &mut [u8]) {
    use core::arch::x86_64::*;
    let nblk = t.msg.len() / 64;
    let word = |b: usize, i: usize| u32::from_be_bytes(t.msg[64 * b + 4 * i..64 * b + 4 * i + 4].try_into().unwrap());
    // blocks 1.. are the same in every lane: schedule + K once
    let mut wk_tail: Vec<[u32; 64]> = Vec::with_capacity(nblk - 1);
    for b in 1..nblk {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = word(b, i);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        for i in 0..64 {
            w[i] = w[i].wrapping_add(K[i]);
        }
        wk_tail.push(w);
    }
    // block 0 words; the counter occupies bytes ctr_at..ctr_at+4 (one or two words)
    let base: [u32; 16] = core::array::from_fn(|i| word(0, i));
    let (w_lo, sh) = (t.ctr_at / 4, (t.ctr_at % 4) * 8);
    #[inline]
    #[target_feature(enable = "avx512f")]
    fn add(a: __m512i, b: __m512i) -> __m512i {
        _mm512_add_epi32(a, b)
    }
    #[inline]
    #[target_feature(enable = "avx512f")]
    fn x3(a: __m512i, b: __m512i, c: __m512i) -> __m512i {
        _mm512_ternarylogic_epi32::<0x96>(a, b, c)
    }
    let lanes = _mm512_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    while out.len() - *pos >= 128 {
        let need = (out.len() - *pos).div_ceil(32).min(16);
        let cv = _mm512_add_epi32(_mm512_set1_epi32(*ctr as i32), lanes);
        let mut w: [__m512i; 16] = core::array::from_fn(|i| _mm512_set1_epi32(base[i] as i32));
        // splice the big-endian counter into the template words (template bytes there are zero)
        if sh == 0 {
            w[w_lo] = cv;
        } else {
            w[w_lo] = _mm512_or_si512(w[w_lo], _mm512_srlv_epi32(cv, _mm512_set1_epi32(sh as i32)));
            w[w_lo + 1] = _mm512_or_si512(w[w_lo + 1], _mm512_sllv_epi32(cv, _mm512_set1_epi32((32 - sh) as i32)));
        }
        let mut st: [__m512i; 8] = core::array::from_fn(|i| _mm512_set1_epi32(IV[i] as i32));
        // block 0: full vector schedule
        {
            let mut ws = [_mm512_setzero_si512(); 64];
            ws[..16].copy_from_slice(&w);
            for i in 16..64 {
                let a = ws[i - 15];
                let s0 = x3(_mm512_ror_epi32::<7>(a), _mm512_ror_epi32::<18>(a), _mm512_srli_epi32::<3>(a));
                let b = ws[i - 2];
                let s1 = x3(_mm512_ror_epi32::<17>(b), _mm512_ror_epi32::<19>(b), _mm512_srli_epi32::<10>(b));
                ws[i] = add(add(ws[i - 16], s0), add(ws[i - 7], s1));
            }
            let wk: [__m512i; 64] = core::array::from_fn(|i| add(ws[i], _mm512_set1_epi32(K[i] as i32)));
            st = rounds(st, &wk);
        }
        for wkt in &wk_tail {
            let wk: [__m512i; 64] = core::array::from_fn(|i| _mm512_set1_epi32(wkt[i] as i32));
            st = rounds(st, &wk);
        }
        let mut sv = [[0u32; 16]; 8];
        for i in 0..8 {
            _mm512_storeu_si512(sv[i].as_mut_ptr() as *mut _, st[i]);
        }
        for l in 0..need {
            let n = (out.len() - *pos).min(32);
            let mut h = [0u8; 32];
            for i in 0..8 {
                h[4 * i..4 * i + 4].copy_from_slice(&sv[i][l].to_be_bytes());
            }
            out[*pos..*pos + n].copy_from_slice(&h[..n]);
            *pos += n;
        }
        *ctr += need as u32;
    }
    // the per-block schedules are derived from the seed: wipe them (feature `zeroize`, best effort)
    #[cfg(feature = "zeroize")]
    for w in wk_tail.iter_mut() {
        zeroize::Zeroize::zeroize(&mut w[..]);
    }

    #[inline]
    #[target_feature(enable = "avx512f")]
    fn rounds(s: [__m512i; 8], wk: &[__m512i; 64]) -> [__m512i; 8] {
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = s;
        for i in 0..64 {
            let s1 = _mm512_ternarylogic_epi32::<0x96>(_mm512_ror_epi32::<6>(e), _mm512_ror_epi32::<11>(e), _mm512_ror_epi32::<25>(e));
            let ch = _mm512_ternarylogic_epi32::<0xCA>(e, f, g);
            let t1 = _mm512_add_epi32(_mm512_add_epi32(h, s1), _mm512_add_epi32(ch, wk[i]));
            let s0 = _mm512_ternarylogic_epi32::<0x96>(_mm512_ror_epi32::<2>(a), _mm512_ror_epi32::<13>(a), _mm512_ror_epi32::<22>(a));
            let maj = _mm512_ternarylogic_epi32::<0xE8>(a, b, c);
            h = g;
            g = f;
            f = e;
            e = _mm512_add_epi32(d, t1);
            d = c;
            c = b;
            b = a;
            a = _mm512_add_epi32(t1, _mm512_add_epi32(s0, maj));
        }
        [
            _mm512_add_epi32(a, s[0]),
            _mm512_add_epi32(b, s[1]),
            _mm512_add_epi32(c, s[2]),
            _mm512_add_epi32(d, s[3]),
            _mm512_add_epi32(e, s[4]),
            _mm512_add_epi32(f, s[5]),
            _mm512_add_epi32(g, s[6]),
            _mm512_add_epi32(h, s[7]),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sponge::StaffSponge;
    #[test]
    fn squeeze_matches_staff_sponge() {
        let seed: Vec<u8> = (0..128u32).map(|i| (i * 37 + 11) as u8).collect();
        for domain in [&b"R"[..], b"M", b"", b"abc", b"longdomain"] {
            for nlen in [0usize, 16, 32, 83, 100, 200] {
                let nonce: Vec<u8> = (0..nlen as u32).map(|i| (i * 13 + 5) as u8).collect();
                for len in [0usize, 1, 31, 32, 33, 127, 128, 129, 511, 512, 513, 1000, 4096 + 32, 65536 + 32] {
                    let mut a = alloc::vec![0u8; len];
                    let mut b = alloc::vec![0u8; len];
                    let mut c = alloc::vec![0u8; len];
                    StaffSponge::new(domain, &seed, &nonce).fill(&mut a);
                    squeeze(domain, &seed, &nonce, &mut b);
                    squeeze_impl(domain, &seed, &nonce, &mut c, false); // template + compress256 path only
                    assert_eq!(a, b, "domain {domain:?} nonce {nlen} len {len}");
                    assert_eq!(a, c, "scalar path: domain {domain:?} nonce {nlen} len {len}");
                }
            }
        }
    }
}
