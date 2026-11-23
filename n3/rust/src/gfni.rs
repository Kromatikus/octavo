//! AVX-512 + GFNI backend for the N3 block function (gfni slice: position layout).
//!
//! Single-block and leftover groups still use the gfni3 register-resident layout.
//! Batches of 64 (and 32) are transposed once on entry so each register holds
//! the same byte position across the group; linear layers then run as
//! multiply-by-constant + XOR with no per-round shuffles, S-boxes as
//! GF2P8AFFINEINVQB, and the bow as lane-wise ARX. The group is transposed
//! back on exit. Output is bit-identical to the portable path.
//!
//! Homemade; for real secrets use AES-GCM-SIV, age, or libsodium.

#![allow(unsafe_code)]

use crate::iso::{gfni_qword, mulc_qword, rotl_qword, AesForm};
use crate::{Field, Round, BLOCK_LEN, NR};
use core::arch::x86_64::*;

pub fn available() -> bool {
    std::is_x86_feature_detected!("gfni")
        && std::is_x86_feature_detected!("avx512f")
        && std::is_x86_feature_detected!("avx512bw")
        && std::is_x86_feature_detected!("avx512vl")
        && std::is_x86_feature_detected!("avx512vbmi")
        && std::is_x86_feature_detected!("bmi1")
        && std::is_x86_feature_detected!("bmi2")
}

#[derive(Clone, Copy, Default)]
struct Sb {
    pre: u64,
    pre_c: u8,
    post: u64,
    post_c: u8,
}
impl Sb {
    fn new(f: &AesForm) -> Sb {
        Sb {
            pre: gfni_qword(&f.p_mat),
            pre_c: f.p,
            post: gfni_qword(&f.q_mat),
            post_c: f.q,
        }
    }
}

struct RoundK {
    rk: [u8; BLOCK_LEN],
    s: Sb,
    sm: Sb,
    s2: Sb,
    si: Sb,
    sim: Sb,
    si2: Sb,
    br_idx: [u8; 64],
    br_inv: [u8; 64],
    benes: [u32; BENES_WORDS],
    even: bool,
}

struct Consts {
    m2: u64,
    minv3: u64,
    rot: [u64; 8],
}

pub struct GfniKey {
    rounds: Box<[RoundK; NR]>,
    white: [u8; BLOCK_LEN],
    c: Consts,
}

fn invert64(p: &[u8; 64]) -> [u8; 64] {
    crate::key_ct::invert_perm64_ct(p)
}

impl GfniKey {
    pub fn new(field: &Field, rounds: &[Round], white: &[u8; BLOCK_LEN]) -> Option<Box<GfniKey>> {
        if !available() {
            return None;
        }
        let mut rk_out: [RoundK; NR] = core::array::from_fn(|_| RoundK {
            rk: [0; BLOCK_LEN],
            s: Sb::default(),
            sm: Sb::default(),
            s2: Sb::default(),
            si: Sb::default(),
            sim: Sb::default(),
            si2: Sb::default(),
            br_idx: [0; 64],
            br_inv: [0; 64],
            benes: [0; BENES_WORDS],
            even: true,
        });
        for (r, rk) in rounds.iter().enumerate() {
            let mut br_idx = [0u8; 64];
            br_idx.copy_from_slice(&rk.bridge);
            let br_inv = invert64(&br_idx);
            rk_out[r] = RoundK {
                rk: rk.rk,
                s: Sb::new(&AesForm::forward(&rk.ks)),
                sm: Sb::new(&AesForm::forward(&rk.ksm)),
                s2: Sb::new(&AesForm::forward(&rk.ks2)),
                si: Sb::new(&AesForm::inverse(&rk.ks)),
                sim: Sb::new(&AesForm::inverse(&rk.ksm)),
                si2: Sb::new(&AesForm::inverse(&rk.ks2)),
                br_idx,
                br_inv,
                // SAFETY: available() checked AVX-512 VBMI above; BMI1/2 are implied on these CPUs.
                benes: unsafe { benes_route(&br_idx) },
                even: r % 2 == 0,
            };
        }
        debug_assert_eq!(field.inv3, crate::gf::INV3);
        let _ = mulc_qword; // used by generated layers via the same encoding
        let c = Consts {
            m2: mulc_qword(2),
            minv3: mulc_qword(crate::gf::INV3),
            rot: core::array::from_fn(rotl_qword),
        };
        Some(Box::new(GfniKey {
            rounds: Box::new(rk_out),
            white: *white,
            c,
        }))
    }

    pub fn encrypt_block(&self, pt: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
        let mut b = *pt;
        unsafe { encrypt_one(self, &mut b) }
        b
    }
    pub fn decrypt_block(&self, ct: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
        let mut b = *ct;
        unsafe { decrypt_one(self, &mut b) }
        b
    }

    /// Independent blocks, same schedule. Prefers a 64-block position-sliced
    /// group, then a 32-block sliced group, then the gfni3 16/8/4 packs,
    /// then single-block remainders.
    pub fn encrypt_blocks(&self, blocks: &mut [[u8; BLOCK_LEN]]) {
        dispatch_blocks(self, blocks, true);
    }
    pub fn decrypt_blocks(&self, blocks: &mut [[u8; BLOCK_LEN]]) {
        dispatch_blocks(self, blocks, false);
    }
}

// ----------------------------------------------------------------- intrinsics

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn loadz(p: *const u8) -> __m512i {
    _mm512_loadu_si512(p as *const _)
}
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn storez(p: *mut u8, z: __m512i) {
    _mm512_storeu_si512(p as *mut _, z);
}
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn load_block(b: &[u8; BLOCK_LEN]) -> (__m512i, __m512i) {
    (loadz(b.as_ptr()), loadz(b.as_ptr().add(64)))
}
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn store_block(b: &mut [u8; BLOCK_LEN], z0: __m512i, z1: __m512i) {
    storez(b.as_mut_ptr(), z0);
    storez(b.as_mut_ptr().add(64), z1);
}
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn aff512(x: __m512i, m: u64) -> __m512i {
    _mm512_gf2p8affine_epi64_epi8::<0>(x, _mm512_set1_epi64(m as i64))
}
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn aff256(x: __m256i, m: u64) -> __m256i {
    _mm256_gf2p8affine_epi64_epi8::<0>(x, _mm256_set1_epi64x(m as i64))
}
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn aff128(x: __m128i, m: u64) -> __m128i {
    _mm_gf2p8affine_epi64_epi8::<0>(x, _mm_set1_epi64x(m as i64))
}
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn sbox512(x: __m512i, s: &Sb) -> __m512i {
    let y = _mm512_xor_si512(aff512(x, s.pre), _mm512_set1_epi8(s.pre_c as i8));
    _mm512_xor_si512(
        _mm512_gf2p8affineinv_epi64_epi8::<0>(y, _mm512_set1_epi64(s.post as i64)),
        _mm512_set1_epi8(s.post_c as i8),
    )
}
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn sbox_block(z0: __m512i, z1: __m512i, s: &Sb) -> (__m512i, __m512i) {
    (sbox512(z0, s), sbox512(z1, s))
}
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn xor_rk(z0: __m512i, z1: __m512i, rk: &[u8; BLOCK_LEN]) -> (__m512i, __m512i) {
    (
        _mm512_xor_si512(z0, loadz(rk.as_ptr())),
        _mm512_xor_si512(z1, loadz(rk.as_ptr().add(64))),
    )
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn bridges(
    z0: __m512i,
    z1: __m512i,
    rk: &RoundK,
    c: &Consts,
    inverse: bool,
) -> (__m512i, __m512i) {
    let idx = loadz(rk.br_idx.as_ptr());
    let inv = loadz(rk.br_inv.as_ptr());
    let gathered = _mm512_permutexvar_epi8(idx, z1);
    if !inverse {
        if rk.even {
            let a = z0;
            let b = gathered;
            let a2 = _mm512_xor_si512(a, b);
            let b2 = _mm512_xor_si512(a, aff512(b, c.m2));
            (a2, _mm512_permutexvar_epi8(inv, b2))
        } else {
            let a = gathered;
            let b = z0;
            let a2 = _mm512_xor_si512(a, b);
            let b2 = _mm512_xor_si512(a, aff512(b, c.m2));
            (b2, _mm512_permutexvar_epi8(inv, a2))
        }
    } else if rk.even {
        let ap = z0;
        let bp = gathered;
        let v = aff512(_mm512_xor_si512(ap, bp), c.minv3);
        let u = _mm512_xor_si512(ap, v);
        (u, _mm512_permutexvar_epi8(inv, v))
    } else {
        let ap = gathered;
        let bp = z0;
        let v = aff512(_mm512_xor_si512(ap, bp), c.minv3);
        let u = _mm512_xor_si512(ap, v);
        (v, _mm512_permutexvar_epi8(inv, u))
    }
}

/// 16x16 byte transpose (involution). Sequential unpack lo/hi at strides 1,2,4,8.
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn transpose_16x16(m: &mut [__m128i; 16]) {
    {
        let s = *m;
        m[0] = _mm_unpacklo_epi8(s[0], s[1]);
        m[1] = _mm_unpackhi_epi8(s[0], s[1]);
        m[2] = _mm_unpacklo_epi8(s[2], s[3]);
        m[3] = _mm_unpackhi_epi8(s[2], s[3]);
        m[4] = _mm_unpacklo_epi8(s[4], s[5]);
        m[5] = _mm_unpackhi_epi8(s[4], s[5]);
        m[6] = _mm_unpacklo_epi8(s[6], s[7]);
        m[7] = _mm_unpackhi_epi8(s[6], s[7]);
        m[8] = _mm_unpacklo_epi8(s[8], s[9]);
        m[9] = _mm_unpackhi_epi8(s[8], s[9]);
        m[10] = _mm_unpacklo_epi8(s[10], s[11]);
        m[11] = _mm_unpackhi_epi8(s[10], s[11]);
        m[12] = _mm_unpacklo_epi8(s[12], s[13]);
        m[13] = _mm_unpackhi_epi8(s[12], s[13]);
        m[14] = _mm_unpacklo_epi8(s[14], s[15]);
        m[15] = _mm_unpackhi_epi8(s[14], s[15]);
    }
    {
        let s = *m;
        m[0] = _mm_unpacklo_epi16(s[0], s[2]);
        m[1] = _mm_unpackhi_epi16(s[0], s[2]);
        m[2] = _mm_unpacklo_epi16(s[1], s[3]);
        m[3] = _mm_unpackhi_epi16(s[1], s[3]);
        m[4] = _mm_unpacklo_epi16(s[4], s[6]);
        m[5] = _mm_unpackhi_epi16(s[4], s[6]);
        m[6] = _mm_unpacklo_epi16(s[5], s[7]);
        m[7] = _mm_unpackhi_epi16(s[5], s[7]);
        m[8] = _mm_unpacklo_epi16(s[8], s[10]);
        m[9] = _mm_unpackhi_epi16(s[8], s[10]);
        m[10] = _mm_unpacklo_epi16(s[9], s[11]);
        m[11] = _mm_unpackhi_epi16(s[9], s[11]);
        m[12] = _mm_unpacklo_epi16(s[12], s[14]);
        m[13] = _mm_unpackhi_epi16(s[12], s[14]);
        m[14] = _mm_unpacklo_epi16(s[13], s[15]);
        m[15] = _mm_unpackhi_epi16(s[13], s[15]);
    }
    {
        let s = *m;
        m[0] = _mm_unpacklo_epi32(s[0], s[4]);
        m[1] = _mm_unpackhi_epi32(s[0], s[4]);
        m[2] = _mm_unpacklo_epi32(s[1], s[5]);
        m[3] = _mm_unpackhi_epi32(s[1], s[5]);
        m[4] = _mm_unpacklo_epi32(s[2], s[6]);
        m[5] = _mm_unpackhi_epi32(s[2], s[6]);
        m[6] = _mm_unpacklo_epi32(s[3], s[7]);
        m[7] = _mm_unpackhi_epi32(s[3], s[7]);
        m[8] = _mm_unpacklo_epi32(s[8], s[12]);
        m[9] = _mm_unpackhi_epi32(s[8], s[12]);
        m[10] = _mm_unpacklo_epi32(s[9], s[13]);
        m[11] = _mm_unpackhi_epi32(s[9], s[13]);
        m[12] = _mm_unpacklo_epi32(s[10], s[14]);
        m[13] = _mm_unpackhi_epi32(s[10], s[14]);
        m[14] = _mm_unpacklo_epi32(s[11], s[15]);
        m[15] = _mm_unpackhi_epi32(s[11], s[15]);
    }
    {
        let s = *m;
        m[0] = _mm_unpacklo_epi64(s[0], s[8]);
        m[1] = _mm_unpackhi_epi64(s[0], s[8]);
        m[2] = _mm_unpacklo_epi64(s[1], s[9]);
        m[3] = _mm_unpackhi_epi64(s[1], s[9]);
        m[4] = _mm_unpacklo_epi64(s[2], s[10]);
        m[5] = _mm_unpackhi_epi64(s[2], s[10]);
        m[6] = _mm_unpacklo_epi64(s[3], s[11]);
        m[7] = _mm_unpackhi_epi64(s[3], s[11]);
        m[8] = _mm_unpacklo_epi64(s[4], s[12]);
        m[9] = _mm_unpackhi_epi64(s[4], s[12]);
        m[10] = _mm_unpacklo_epi64(s[5], s[13]);
        m[11] = _mm_unpackhi_epi64(s[5], s[13]);
        m[12] = _mm_unpacklo_epi64(s[6], s[14]);
        m[13] = _mm_unpackhi_epi64(s[6], s[14]);
        m[14] = _mm_unpacklo_epi64(s[7], s[15]);
        m[15] = _mm_unpackhi_epi64(s[7], s[15]);
    }
}

/// Split two face-major shells into 16 face vectors (8 beats in the low half).
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn split_faces(z0: __m512i, z1: __m512i) -> [__m128i; 16] {
    let mut f = [_mm_setzero_si128(); 16];
    let put = |f: &mut [__m128i; 16], base: usize, z: __m512i| {
        let p = [
            _mm512_extracti32x4_epi32::<0>(z),
            _mm512_extracti32x4_epi32::<1>(z),
            _mm512_extracti32x4_epi32::<2>(z),
            _mm512_extracti32x4_epi32::<3>(z),
        ];
        for i in 0..4 {
            f[base + 2 * i] = _mm_move_epi64(p[i]);
            f[base + 2 * i + 1] = _mm_srli_si128::<8>(p[i]);
        }
    };
    put(&mut f, 0, z0);
    put(&mut f, 8, z1);
    f
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn join_faces(f: &[__m128i; 16]) -> (__m512i, __m512i) {
    let pack = |base: usize| {
        let a = _mm_unpacklo_epi64(f[base], f[base + 1]);
        let b = _mm_unpacklo_epi64(f[base + 2], f[base + 3]);
        let c = _mm_unpacklo_epi64(f[base + 4], f[base + 5]);
        let d = _mm_unpacklo_epi64(f[base + 6], f[base + 7]);
        let x = _mm512_castsi128_si512(a);
        let x = _mm512_inserti32x4::<1>(x, b);
        let x = _mm512_inserti32x4::<2>(x, c);
        _mm512_inserti32x4::<3>(x, d)
    };
    (pack(0), pack(8))
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn faces_to_cols(f: &[__m128i; 16]) -> [__m128i; 8] {
    let mut m = *f;
    transpose_16x16(&mut m);
    let mut cols = [_mm_setzero_si128(); 8];
    cols.copy_from_slice(&m[..8]);
    cols
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn cols_to_faces(cols: &[__m128i; 8]) -> [__m128i; 16] {
    let mut m = [_mm_setzero_si128(); 16];
    m[..8].copy_from_slice(cols);
    transpose_16x16(&mut m);
    m
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn pack4_xmm(a: __m128i, b: __m128i, c: __m128i, d: __m128i) -> __m512i {
    let x = _mm512_castsi128_si512(a);
    let x = _mm512_inserti32x4::<1>(x, b);
    let x = _mm512_inserti32x4::<2>(x, c);
    _mm512_inserti32x4::<3>(x, d)
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn split_faces4(z: [(__m512i, __m512i); 4]) -> [__m256i; 16] {
    let mut fx = [[_mm_setzero_si128(); 16]; 4];
    for b in 0..4 {
        fx[b] = split_faces(z[b].0, z[b].1);
    }
    let mut out = [_mm256_setzero_si256(); 16];
    for f in 0..16 {
        let ab = _mm_unpacklo_epi64(fx[0][f], fx[1][f]);
        let cd = _mm_unpacklo_epi64(fx[2][f], fx[3][f]);
        out[f] = _mm256_set_m128i(cd, ab);
    }
    out
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn join_faces4(fy: &[__m256i; 16]) -> [(__m512i, __m512i); 4] {
    let mut fx = [[_mm_setzero_si128(); 16]; 4];
    for f in 0..16 {
        let lo = _mm256_castsi256_si128(fy[f]);
        let hi = _mm256_extracti128_si256::<1>(fy[f]);
        fx[0][f] = _mm_move_epi64(lo);
        fx[1][f] = _mm_srli_si128::<8>(lo);
        fx[2][f] = _mm_move_epi64(hi);
        fx[3][f] = _mm_srli_si128::<8>(hi);
    }
    let mut z = [(_mm512_setzero_si512(), _mm512_setzero_si512()); 4];
    for b in 0..4 {
        z[b] = join_faces(&fx[b]);
    }
    z
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn faces_to_cols4(fy: &[__m256i; 16]) -> [__m512i; 8] {
    let mut fx = [[_mm_setzero_si128(); 16]; 4];
    for f in 0..16 {
        let lo = _mm256_castsi256_si128(fy[f]);
        let hi = _mm256_extracti128_si256::<1>(fy[f]);
        fx[0][f] = _mm_move_epi64(lo);
        fx[1][f] = _mm_srli_si128::<8>(lo);
        fx[2][f] = _mm_move_epi64(hi);
        fx[3][f] = _mm_srli_si128::<8>(hi);
    }
    let mut cols4 = [[_mm_setzero_si128(); 8]; 4];
    for b in 0..4 {
        cols4[b] = faces_to_cols(&fx[b]);
    }
    let mut cols = [_mm512_setzero_si512(); 8];
    for t in 0..8 {
        cols[t] = pack4_xmm(cols4[0][t], cols4[1][t], cols4[2][t], cols4[3][t]);
    }
    cols
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn cols_to_faces4(cols: &[__m512i; 8]) -> [__m256i; 16] {
    let mut fx = [[_mm_setzero_si128(); 16]; 4];
    for b in 0..4 {
        let mut c = [_mm_setzero_si128(); 8];
        for t in 0..8 {
            c[t] = match b {
                0 => _mm512_extracti32x4_epi32::<0>(cols[t]),
                1 => _mm512_extracti32x4_epi32::<1>(cols[t]),
                2 => _mm512_extracti32x4_epi32::<2>(cols[t]),
                _ => _mm512_extracti32x4_epi32::<3>(cols[t]),
            };
        }
        fx[b] = cols_to_faces(&c);
    }
    let mut fy = [_mm256_setzero_si256(); 16];
    for f in 0..16 {
        let ab = _mm_unpacklo_epi64(fx[0][f], fx[1][f]);
        let cd = _mm_unpacklo_epi64(fx[2][f], fx[3][f]);
        fy[f] = _mm256_set_m128i(cd, ab);
    }
    fy
}

// VPSLLVW-style bow, 16 faces (xmm) or 64 lanes (zmm = 4 blocks x 16 faces).

// fix1 (format 0x1B): 8-stroke bow, full diffusion in both directions (OHLO's choice over the
// 10-stroke sawtooth, kept in lab/sawtooth10).
const BOW_STROKES: [(usize, usize, usize); 8] =
    [(2, 3, 4), (5, 7, 1), (0, 7, 3), (4, 7, 6), (1, 6, 0), (1, 7, 2), (2, 5, 4), (0, 3, 1)];
const BOW_PRESSURE_ROT: [usize; 8] = [0; 8];

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn bow_amounts(view: __m128i) -> (__m128i, __m128i) {
    let seven = _mm_set1_epi8(7);
    let one = _mm_set1_epi8(1);
    let d0 = _mm_and_si128(view, seven);
    let d1 = _mm_and_si128(_mm_srli_epi16::<3>(view), seven);
    let d2 = _mm_and_si128(_mm_srli_epi16::<6>(view), _mm_set1_epi8(3));
    let w = _mm_add_epi8(d1, d2);
    let mut s = _mm_add_epi8(w, d0);
    s = _mm_min_epu8(s, _mm_sub_epi8(s, seven));
    s = _mm_min_epu8(s, _mm_sub_epi8(s, seven));
    let w = _mm_min_epu8(w, _mm_sub_epi8(w, seven));
    (_mm_add_epi8(s, one), _mm_add_epi8(w, one))
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn vrot(x: __m128i, r: __m128i) -> __m128i {
    const DUP_E: [u8; 16] = [0, 0, 2, 2, 4, 4, 6, 6, 8, 8, 10, 10, 12, 12, 14, 14];
    const DUP_O: [u8; 16] = [1, 1, 3, 3, 5, 5, 7, 7, 9, 9, 11, 11, 13, 13, 15, 15];
    let re = _mm_and_si128(r, _mm_set1_epi16(0x00ff));
    let ro = _mm_srli_epi16::<8>(r);
    let se = _mm_sllv_epi16(
        _mm_shuffle_epi8(x, _mm_loadu_si128(DUP_E.as_ptr() as *const _)),
        re,
    );
    let so = _mm_sllv_epi16(
        _mm_shuffle_epi8(x, _mm_loadu_si128(DUP_O.as_ptr() as *const _)),
        ro,
    );
    _mm_mask_blend_epi8(0xAAAA, _mm_srli_epi16::<8>(se), so)
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn bow_cols(cols: &mut [__m128i; 8], c: &Consts, inverse: bool) {
    if !inverse {
        for (&(i, j, p), &rot) in BOW_STROKES.iter().zip(BOW_PRESSURE_ROT.iter()) {
            let view = if rot == 0 {
                cols[p]
            } else {
                aff128(cols[p], c.rot[rot])
            };
            let (r1, r2) = bow_amounts(view);
            let u = _mm_add_epi8(cols[i], vrot(cols[j], r1));
            let v = _mm_xor_si128(cols[j], vrot(u, r2));
            cols[i] = u;
            cols[j] = v;
        }
    } else {
        for (&(i, j, p), &rot) in BOW_STROKES.iter().zip(BOW_PRESSURE_ROT.iter()).rev() {
            let view = if rot == 0 {
                cols[p]
            } else {
                aff128(cols[p], c.rot[rot])
            };
            let (r1, r2) = bow_amounts(view);
            let v = _mm_xor_si128(cols[j], vrot(cols[i], r2));
            let u = _mm_sub_epi8(cols[i], vrot(v, r1));
            cols[i] = u;
            cols[j] = v;
        }
    }
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn bow_amounts512(view: __m512i) -> (__m512i, __m512i) {
    let seven = _mm512_set1_epi8(7);
    let one = _mm512_set1_epi8(1);
    let d0 = _mm512_and_si512(view, seven);
    let d1 = _mm512_and_si512(_mm512_srli_epi16::<3>(view), seven);
    let d2 = _mm512_and_si512(_mm512_srli_epi16::<6>(view), _mm512_set1_epi8(3));
    let w = _mm512_add_epi8(d1, d2);
    let mut s = _mm512_add_epi8(w, d0);
    s = _mm512_min_epu8(s, _mm512_sub_epi8(s, seven));
    s = _mm512_min_epu8(s, _mm512_sub_epi8(s, seven));
    let w = _mm512_min_epu8(w, _mm512_sub_epi8(w, seven));
    (_mm512_add_epi8(s, one), _mm512_add_epi8(w, one))
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn vrot512(x: __m512i, r: __m512i) -> __m512i {
    const DUP_E: [u8; 16] = [0, 0, 2, 2, 4, 4, 6, 6, 8, 8, 10, 10, 12, 12, 14, 14];
    const DUP_O: [u8; 16] = [1, 1, 3, 3, 5, 5, 7, 7, 9, 9, 11, 11, 13, 13, 15, 15];
    let de = _mm512_broadcast_i32x4(_mm_loadu_si128(DUP_E.as_ptr() as *const _));
    let dov = _mm512_broadcast_i32x4(_mm_loadu_si128(DUP_O.as_ptr() as *const _));
    let re = _mm512_and_si512(r, _mm512_set1_epi16(0x00ff));
    let ro = _mm512_srli_epi16::<8>(r);
    let se = _mm512_sllv_epi16(_mm512_shuffle_epi8(x, de), re);
    let so = _mm512_sllv_epi16(_mm512_shuffle_epi8(x, dov), ro);
    _mm512_mask_blend_epi8(0xAAAA_AAAA_AAAA_AAAA, _mm512_srli_epi16::<8>(se), so)
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn bow_cols512(cols: &mut [__m512i; 8], c: &Consts, inverse: bool) {
    if !inverse {
        for (&(i, j, p), &rot) in BOW_STROKES.iter().zip(BOW_PRESSURE_ROT.iter()) {
            let view = if rot == 0 {
                cols[p]
            } else {
                aff512(cols[p], c.rot[rot])
            };
            let (r1, r2) = bow_amounts512(view);
            let u = _mm512_add_epi8(cols[i], vrot512(cols[j], r1));
            let v = _mm512_xor_si512(cols[j], vrot512(u, r2));
            cols[i] = u;
            cols[j] = v;
        }
    } else {
        for (&(i, j, p), &rot) in BOW_STROKES.iter().zip(BOW_PRESSURE_ROT.iter()).rev() {
            let view = if rot == 0 {
                cols[p]
            } else {
                aff512(cols[p], c.rot[rot])
            };
            let (r1, r2) = bow_amounts512(view);
            let v = _mm512_xor_si512(cols[j], vrot512(cols[i], r2));
            let u = _mm512_sub_epi8(cols[i], vrot512(v, r1));
            cols[i] = u;
            cols[j] = v;
        }
    }
}

include!("gfni_layers.rs");
include!("gfni_ct.rs");
include!("gfni_slice.rs");
include!("gfni_benes.rs");

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn encrypt_one(key: &GfniKey, block: &mut [u8; BLOCK_LEN]) {
    let c = &key.c;
    let (mut z0, mut z1) = load_block(block);
    for r in 0..NR {
        let rk = &key.rounds[r];
        (z0, z1) = xor_rk(z0, z1, &rk.rk);
        (z0, z1) = sbox_block(z0, z1, &rk.s);
        let mut faces = split_faces(z0, z1);
        let mut cols = faces_to_cols(&faces);
        staff_fwd_x(&mut cols);
        faces = cols_to_faces(&cols);
        faces_fwd_x(&mut faces);
        (z0, z1) = join_faces(&faces);
        (z0, z1) = bridges(z0, z1, rk, c, false);
        let mut faces = split_faces(z0, z1);
        let mut cols = faces_to_cols(&faces);
        trip_fwd_x(&mut cols);
        bow_cols(&mut cols, c, false);
        faces = cols_to_faces(&cols);
        (z0, z1) = join_faces(&faces);
        (z0, z1) = sbox_block(z0, z1, &rk.sm);
        let mut faces = split_faces(z0, z1);
        cross_fwd_x(&mut faces);
        (z0, z1) = join_faces(&faces);
        (z0, z1) = sbox_block(z0, z1, &rk.s2);
    }
    (z0, z1) = xor_rk(z0, z1, &key.white);
    store_block(block, z0, z1);
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn decrypt_one(key: &GfniKey, block: &mut [u8; BLOCK_LEN]) {
    let c = &key.c;
    let (mut z0, mut z1) = load_block(block);
    (z0, z1) = xor_rk(z0, z1, &key.white);
    for r in (0..NR).rev() {
        let rk = &key.rounds[r];
        (z0, z1) = sbox_block(z0, z1, &rk.si2);
        let mut faces = split_faces(z0, z1);
        cross_inv_x(&mut faces);
        (z0, z1) = join_faces(&faces);
        (z0, z1) = sbox_block(z0, z1, &rk.sim);
        let mut faces = split_faces(z0, z1);
        let mut cols = faces_to_cols(&faces);
        bow_cols(&mut cols, c, true);
        trip_inv_x(&mut cols);
        faces = cols_to_faces(&cols);
        (z0, z1) = join_faces(&faces);
        (z0, z1) = bridges(z0, z1, rk, c, true);
        let mut faces = split_faces(z0, z1);
        faces_inv_x(&mut faces);
        let mut cols = faces_to_cols(&faces);
        staff_inv_x(&mut cols);
        faces = cols_to_faces(&cols);
        (z0, z1) = join_faces(&faces);
        (z0, z1) = sbox_block(z0, z1, &rk.si);
        (z0, z1) = xor_rk(z0, z1, &rk.rk);
    }
    store_block(block, z0, z1);
}

fn dispatch_blocks(key: &GfniKey, blocks: &mut [[u8; BLOCK_LEN]], encrypt: bool) {
    let mut it64 = blocks.chunks_exact_mut(64);
    for g in &mut it64 {
        let arr: &mut [[u8; BLOCK_LEN]; 64] = g.try_into().unwrap();
        unsafe { crypt_slice64(key, arr, encrypt) }
    }
    let mut it32 = it64.into_remainder().chunks_exact_mut(32);
    for g in &mut it32 {
        let arr: &mut [[u8; BLOCK_LEN]; 32] = g.try_into().unwrap();
        unsafe { crypt_slice32(key, arr, encrypt) }
    }
    let mut it16 = it32.into_remainder().chunks_exact_mut(16);
    for g in &mut it16 {
        let arr: &mut [[u8; BLOCK_LEN]; 16] = g.try_into().unwrap();
        unsafe {
            if encrypt {
                crypt_g::<4>(key, arr, true)
            } else {
                crypt_g::<4>(key, arr, false)
            }
        }
    }
    let mut it8 = it16.into_remainder().chunks_exact_mut(8);
    for g in &mut it8 {
        let arr: &mut [[u8; BLOCK_LEN]; 8] = g.try_into().unwrap();
        unsafe {
            if encrypt {
                crypt_g::<2>(key, arr, true)
            } else {
                crypt_g::<2>(key, arr, false)
            }
        }
    }
    let mut it4 = it8.into_remainder().chunks_exact_mut(4);
    for g in &mut it4 {
        let arr: &mut [[u8; BLOCK_LEN]; 4] = g.try_into().unwrap();
        unsafe {
            if encrypt {
                crypt_g::<1>(key, arr, true)
            } else {
                crypt_g::<1>(key, arr, false)
            }
        }
    }
    for b in it4.into_remainder() {
        unsafe {
            if encrypt {
                encrypt_one(key, b)
            } else {
                decrypt_one(key, b)
            }
        }
    }
}

/// Four independent blocks packed for the 256/512-bit layers.
type Pack4 = [(__m512i, __m512i); 4];

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn pack4_xor_s(z: &mut Pack4, rk: &[u8; BLOCK_LEN], s: &Sb) {
    for b in 0..4 {
        let (a, d) = xor_rk(z[b].0, z[b].1, rk);
        z[b] = sbox_block(a, d, s);
    }
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn pack4_s(z: &mut Pack4, s: &Sb) {
    for b in 0..4 {
        z[b] = sbox_block(z[b].0, z[b].1, s);
    }
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn pack4_s_xor(z: &mut Pack4, s: &Sb, rk: &[u8; BLOCK_LEN]) {
    for b in 0..4 {
        let (a, d) = sbox_block(z[b].0, z[b].1, s);
        z[b] = xor_rk(a, d, rk);
    }
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn pack4_chord_fwd(z: &mut Pack4) {
    let mut faces = split_faces4(*z);
    let mut cols = faces_to_cols4(&faces);
    staff_fwd_z(&mut cols);
    faces = cols_to_faces4(&cols);
    faces_fwd_y(&mut faces);
    *z = join_faces4(&faces);
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn pack4_chord_inv(z: &mut Pack4) {
    let mut faces = split_faces4(*z);
    faces_inv_y(&mut faces);
    let mut cols = faces_to_cols4(&faces);
    staff_inv_z(&mut cols);
    faces = cols_to_faces4(&cols);
    *z = join_faces4(&faces);
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn pack4_bridges(z: &mut Pack4, rk: &RoundK, c: &Consts, inverse: bool) {
    for b in 0..4 {
        z[b] = bridges(z[b].0, z[b].1, rk, c, inverse);
    }
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn pack4_trip_bow_fwd(z: &mut Pack4, c: &Consts) {
    let mut faces = split_faces4(*z);
    let mut cols = faces_to_cols4(&faces);
    trip_fwd_z(&mut cols);
    bow_cols512(&mut cols, c, false);
    faces = cols_to_faces4(&cols);
    *z = join_faces4(&faces);
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn pack4_bow_trip_inv(z: &mut Pack4, c: &Consts) {
    let mut faces = split_faces4(*z);
    let mut cols = faces_to_cols4(&faces);
    bow_cols512(&mut cols, c, true);
    trip_inv_z(&mut cols);
    faces = cols_to_faces4(&cols);
    *z = join_faces4(&faces);
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn pack4_cross_fwd(z: &mut Pack4) {
    let mut faces = split_faces4(*z);
    cross_fwd_y(&mut faces);
    *z = join_faces4(&faces);
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn pack4_cross_inv(z: &mut Pack4) {
    let mut faces = split_faces4(*z);
    cross_inv_y(&mut faces);
    *z = join_faces4(&faces);
}

/// G independent 4-block packs, layer by layer so the core can overlap them.
/// G=1 is 4 blocks, G=2 is 8, G=4 is 16, G=8 is 32.
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn crypt_g<const G: usize>(key: &GfniKey, blocks: &mut [[u8; BLOCK_LEN]], encrypt: bool) {
    debug_assert_eq!(blocks.len(), 4 * G);
    let mut packs: [Pack4; G] =
        [[(_mm512_setzero_si512(), _mm512_setzero_si512()); 4]; G];
    for g in 0..G {
        for b in 0..4 {
            packs[g][b] = load_block(&blocks[4 * g + b]);
        }
    }
    if encrypt {
        encrypt_packs::<G>(key, &mut packs);
    } else {
        decrypt_packs::<G>(key, &mut packs);
    }
    for g in 0..G {
        for b in 0..4 {
            store_block(&mut blocks[4 * g + b], packs[g][b].0, packs[g][b].1);
        }
    }
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn encrypt_packs<const G: usize>(key: &GfniKey, packs: &mut [Pack4; G]) {
    let c = &key.c;
    for r in 0..NR {
        let rk = &key.rounds[r];
        for g in 0..G {
            pack4_xor_s(&mut packs[g], &rk.rk, &rk.s);
        }
        for g in 0..G {
            pack4_chord_fwd(&mut packs[g]);
        }
        for g in 0..G {
            pack4_bridges(&mut packs[g], rk, c, false);
        }
        for g in 0..G {
            pack4_trip_bow_fwd(&mut packs[g], c);
        }
        for g in 0..G {
            pack4_s(&mut packs[g], &rk.sm);
        }
        for g in 0..G {
            pack4_cross_fwd(&mut packs[g]);
        }
        for g in 0..G {
            pack4_s(&mut packs[g], &rk.s2);
        }
    }
    for g in 0..G {
        for b in 0..4 {
            packs[g][b] = xor_rk(packs[g][b].0, packs[g][b].1, &key.white);
        }
    }
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn decrypt_packs<const G: usize>(key: &GfniKey, packs: &mut [Pack4; G]) {
    let c = &key.c;
    for g in 0..G {
        for b in 0..4 {
            packs[g][b] = xor_rk(packs[g][b].0, packs[g][b].1, &key.white);
        }
    }
    for r in (0..NR).rev() {
        let rk = &key.rounds[r];
        for g in 0..G {
            pack4_s(&mut packs[g], &rk.si2);
        }
        for g in 0..G {
            pack4_cross_inv(&mut packs[g]);
        }
        for g in 0..G {
            pack4_s(&mut packs[g], &rk.sim);
        }
        for g in 0..G {
            pack4_bow_trip_inv(&mut packs[g], c);
        }
        for g in 0..G {
            pack4_bridges(&mut packs[g], rk, c, true);
        }
        for g in 0..G {
            pack4_chord_inv(&mut packs[g]);
        }
        for g in 0..G {
            pack4_s_xor(&mut packs[g], &rk.si, &rk.rk);
        }
    }
}


#[cfg(test)]
mod transpose_tests {
    use super::*;
    #[test]
    fn transpose_16x16_is_involution_and_transposes() {
        if !available() {
            return;
        }
        unsafe {
            let mut m = [_mm_setzero_si128(); 16];
            for i in 0..16 {
                let mut b = [0u8; 16];
                for j in 0..16 {
                    b[j] = (i * 16 + j) as u8;
                }
                m[i] = _mm_loadu_si128(b.as_ptr() as *const _);
            }
            transpose_16x16(&mut m);
            for i in 0..16 {
                let mut b = [0u8; 16];
                _mm_storeu_si128(b.as_mut_ptr() as *mut _, m[i]);
                for j in 0..16 {
                    assert_eq!(b[j], (j * 16 + i) as u8, "i={i} j={j}");
                }
            }
            transpose_16x16(&mut m);
            for i in 0..16 {
                let mut b = [0u8; 16];
                _mm_storeu_si128(b.as_mut_ptr() as *mut _, m[i]);
                for j in 0..16 {
                    assert_eq!(b[j], (i * 16 + j) as u8);
                }
            }
        }
    }

    #[test]
    fn transpose_64x64_is_involution_and_transposes() {
        if !available() {
            return;
        }
        unsafe {
            let mut m = [_mm512_setzero_si512(); 64];
            for i in 0..64usize {
                let mut b = [0u8; 64];
                for j in 0..64usize {
                    b[j] = (i.wrapping_mul(3).wrapping_add(j).wrapping_mul(5)) as u8;
                }
                m[i] = _mm512_loadu_si512(b.as_ptr() as *const _);
            }
            let orig = m;
            transpose_64x64_z(&mut m);
            for i in 0..64 {
                let mut b = [0u8; 64];
                _mm512_storeu_si512(b.as_mut_ptr() as *mut _, m[i]);
                for j in 0..64usize {
                    let expect = (j.wrapping_mul(3).wrapping_add(i).wrapping_mul(5)) as u8;
                    assert_eq!(b[j], expect, "T[{i},{j}]");
                }
            }
            transpose_64x64_z(&mut m);
            for i in 0..64 {
                let mut a = [0u8; 64];
                let mut b = [0u8; 64];
                _mm512_storeu_si512(a.as_mut_ptr() as *mut _, orig[i]);
                _mm512_storeu_si512(b.as_mut_ptr() as *mut _, m[i]);
                assert_eq!(a, b, "involution row {i}");
            }
        }
    }

    #[test]
    fn slice64_transpose_roundtrip_and_layout() {
        if !available() {
            return;
        }
        unsafe {
            let mut blocks = [[0u8; BLOCK_LEN]; 64];
            for b in 0..64 {
                for p in 0..BLOCK_LEN {
                    blocks[b][p] = (b.wrapping_mul(13).wrapping_add(p).wrapping_add(3)) as u8;
                }
            }
            let orig = blocks;
            let mut pos = [_mm512_setzero_si512(); 128];
            slice64_load(&blocks, &mut pos);
            for p in 0..BLOCK_LEN {
                let mut lane = [0u8; 64];
                _mm512_storeu_si512(lane.as_mut_ptr() as *mut _, pos[p]);
                for b in 0..64 {
                    assert_eq!(lane[b], orig[b][p], "pos {p} block {b}");
                }
            }
            let mut out = [[0u8; BLOCK_LEN]; 64];
            slice64_store(&pos, &mut out);
            assert_eq!(out, orig);
        }
    }

    #[test]
    fn slice32_transpose_roundtrip_and_layout() {
        if !available() {
            return;
        }
        unsafe {
            let mut blocks = [[0u8; BLOCK_LEN]; 32];
            for b in 0..32 {
                for p in 0..BLOCK_LEN {
                    blocks[b][p] = (b.wrapping_mul(17).wrapping_add(p).wrapping_add(9)) as u8;
                }
            }
            let orig = blocks;
            let mut pos = [_mm256_setzero_si256(); 128];
            slice32_load(&blocks, &mut pos);
            for p in 0..BLOCK_LEN {
                let mut lane = [0u8; 32];
                _mm256_storeu_si256(lane.as_mut_ptr() as *mut _, pos[p]);
                for b in 0..32 {
                    assert_eq!(lane[b], orig[b][p], "pos {p} block {b}");
                }
            }
            let mut out = [[0u8; BLOCK_LEN]; 32];
            slice32_store(&pos, &mut out);
            assert_eq!(out, orig);
        }
    }

    #[test]
    fn bitonic_realizes_all_tested_perms() {
        // Identity, reversal, a simple cycle, and a few LCG permutations.
        let mut cases = Vec::new();
        let mut id = [0u8; 64];
        for i in 0..64 {
            id[i] = i as u8;
        }
        cases.push(id);
        let mut rev = [0u8; 64];
        for i in 0..64 {
            rev[i] = (63 - i) as u8;
        }
        cases.push(rev);
        let mut cyc = [0u8; 64];
        for i in 0..64 {
            cyc[i] = ((i + 17) % 64) as u8;
        }
        cases.push(cyc);
        let mut st = 0xC0FF_EE64u64;
        for _ in 0..8 {
            let mut p = [0u8; 64];
            for i in 0..64 {
                p[i] = i as u8;
            }
            for i in (1..64).rev() {
                st = st.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
                let j = (st as usize) % (i + 1);
                p.swap(i, j);
            }
            cases.push(p);
        }
        for pi in cases {
            let (gather, scatter) = bridge_bitonic_masks(&pi);
            let mut v = [0u8; 64];
            for i in 0..64 {
                v[i] = 200u8.wrapping_add(i as u8);
            }
            let orig = v;
            bitonic_apply_u8(&mut v, &gather);
            for i in 0..64 {
                assert_eq!(v[i], orig[pi[i] as usize], "gather pi={pi:?} i={i}");
            }
            bitonic_apply_u8(&mut v, &scatter);
            assert_eq!(v, orig, "scatter must invert gather");
        }
    }

    #[test]
    fn benes_realizes_random_perms_scalar_and_z() {
        if !available() {
            return;
        }
        let mut cases = Vec::new();
        let id: [u8; 64] = ID64;
        cases.push(id);
        let mut rev = [0u8; 64];
        for i in 0..64 {
            rev[i] = (63 - i) as u8;
        }
        cases.push(rev);
        let mut st = 0xBE4E_5u64;
        for _ in 0..2000 {
            let mut p = id;
            for i in (1..64).rev() {
                st = st.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
                let j = ((st >> 33) as usize) % (i + 1);
                p.swap(i, j);
            }
            cases.push(p);
        }
        for pi in cases {
            let mk = unsafe { benes_route(&pi) };
            // scalar model of the network
            let mut v = [0u8; 64];
            for i in 0..64 {
                v[i] = 100u8.wrapping_add(i as u8);
            }
            let orig = v;
            let stage = |v: &mut [u8; 64], st: usize| {
                let m = BENES_STRIDES[st];
                for x in 0..64 {
                    if x & m == 0 && mk[st * 32 + benes_k(x, m)] != 0 {
                        v.swap(x, x + m);
                    }
                }
            };
            for st in 0..BENES_STAGES {
                stage(&mut v, st);
            }
            for i in 0..64 {
                assert_eq!(v[i], orig[pi[i] as usize]);
            }
            for st in (0..BENES_STAGES).rev() {
                stage(&mut v, st);
            }
            assert_eq!(v, orig);
            // vector path, unfused and fused-pass order
            unsafe {
                let mut h = [_mm512_setzero_si512(); 64];
                for i in 0..64 {
                    h[i] = _mm512_set1_epi8((i as u8 ^ 0x5A) as i8);
                }
                let h0 = h;
                benes_apply_z(&mut h, &mk, true);
                let mut b = [0u8; 64];
                for i in 0..64 {
                    storez(b.as_mut_ptr(), h[i]);
                    assert!(b.iter().all(|&x| x == (pi[i] ^ 0x5A)));
                }
                benes_apply_z(&mut h, &mk, false);
                for i in 0..64 {
                    storez(b.as_mut_ptr(), h[i]);
                    let mut c = [0u8; 64];
                    storez(c.as_mut_ptr(), h0[i]);
                    assert_eq!(b, c);
                }
            }
        }
    }
}

/// fallback1 test hook: AVX-512 router with hardware PEXT and with the
/// branch-free public-mask PEXT.
#[cfg(test)]
pub(crate) fn benes_route_both(src: &[u8; 64]) -> ([u32; BENES_WORDS], [u32; BENES_WORDS]) {
    unsafe { (benes_route_hw(src), benes_route_softpext(src)) }
}
