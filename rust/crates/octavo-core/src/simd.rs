//! Full-round SIMD engine (x86-64, GFNI + AVX-512 F/BW/VL/VBMI). Performance only: every output
//! byte is identical to `round.rs`.
//!
//! Layout trick: the round never needs the face-major order.
//! - The per-row layers (bar mix, triplets, bow, odd restack, cross-staff) run in COLUMN-MAJOR order:
//!   8 xmm registers, column t holding beat t of all 16 faces. Every per-row step is then one
//!   instruction across 16 faces. Constant field multiplies in GF(2^8)/0x1F5 are GF2P8AFFINEQB with
//!   an 8x8 bit matrix, triplet multiplies are add-chains, and the bow's data-dependent rotations
//!   are a 3-stage barrel of GFNI rotations selected with AVX-512 byte masks.
//! - The weave, staff butterfly and shell bridges are pair mixes on key-scheduled cell pairs. Each
//!   becomes a 128-byte gather (2x VPERMI2B, indices precomputed at key setup) into a "pair layout"
//!   (a cells in zmm0, partner b cells in zmm1), followed by one vector mix2. The weave itself is
//!   just folded into the first gather.
//! - The S-boxes are GF2P8AFFINEQB + GF2P8AFFINEINVQB (see `iso`).
//! No data-dependent branches, memory addresses, or table lookups. The key-dependent gather indices
//! are register operands.
#![allow(unsafe_code)]
#![allow(unused_unsafe)]

use crate::affine::Mat8;
use crate::iso::{gfni_qword, AesForm};
use crate::schedule::Schedule;
use crate::{BLOCK_LEN, NR};
use alloc::boxed::Box;
use core::arch::x86_64::*;

pub fn available() -> bool {
    #[cfg(feature = "std")]
    {
        std::is_x86_feature_detected!("gfni")
            && std::is_x86_feature_detected!("avx512f")
            && std::is_x86_feature_detected!("avx512bw")
            && std::is_x86_feature_detected!("avx512vl")
            && std::is_x86_feature_detected!("avx512vbmi")
    }
    #[cfg(not(feature = "std"))]
    {
        cfg!(all(
            target_feature = "gfni",
            target_feature = "avx512f",
            target_feature = "avx512bw",
            target_feature = "avx512vl",
            target_feature = "avx512vbmi"
        ))
    }
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
        Sb { pre: gfni_qword(&f.p_mat), pre_c: f.p, post: gfni_qword(&f.q_mat), post_c: f.q }
    }
}

#[derive(Clone, Copy)]
struct RoundK {
    rk: [u8; BLOCK_LEN], // round key in COL layout
    sb: [Sb; 4],         // S, S2, S^-1, S2^-1
    enc_g: [[u8; BLOCK_LEN]; 5],
    dec_g: [[u8; BLOCK_LEN]; 5],
}

struct Consts {
    m2: u64,
    minv3: u64,
    bars: [[[u64; 2]; 2]; 7],
    bars_inv: [[[u64; 2]; 2]; 7],
    rot: [u64; 8], // rotl by k
}

pub struct SimdKey {
    rounds: Box<[RoundK; NR]>,
    white: [u8; BLOCK_LEN],
    to_col: [u8; BLOCK_LEN],
    to_fm: [u8; BLOCK_LEN],
    c: Consts,
}

// ---------------------------------------------------------------- layouts (phys -> logical cell 8f+t)
fn col_layout() -> [u8; BLOCK_LEN] {
    let mut y = [0u8; BLOCK_LEN];
    for t in 0..8 {
        for f in 0..16 {
            y[16 * t + f] = (8 * f + t) as u8;
        }
    }
    y
}
fn inverse(y: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
    let mut inv = [0u8; BLOCK_LEN];
    for (p, &c) in y.iter().enumerate() {
        inv[c as usize] = p as u8;
    }
    inv
}
/// Gather index taking layout X (old logical frame) to layout Y (new frame), where
/// new_logical[c] = old_logical[m[c]].
fn gather(x: &[u8; BLOCK_LEN], y: &[u8; BLOCK_LEN], m: Option<&[u8; BLOCK_LEN]>) -> [u8; BLOCK_LEN] {
    let xi = inverse(x);
    let mut g = [0u8; BLOCK_LEN];
    for p in 0..BLOCK_LEN {
        let c = y[p] as usize;
        let old = m.map_or(c, |m| m[c] as usize);
        g[p] = xi[old];
    }
    g
}
fn mulc_mat(c: u8) -> Mat8 {
    let mut cols = [0u8; 8];
    for j in 0..8 {
        cols[j] = crate::gf::const_mul(c, 1 << j);
    }
    Mat8 { cols }
}
const BARS: [[[u8; 2]; 2]; 7] =
    [[[0, 0], [0, 0]], [[1, 1], [1, 2]], [[3, 5], [1, 2]], [[1, 3], [1, 4]], [[5, 2], [2, 1]], [[2, 1], [1, 1]], [[3, 1], [2, 1]]];
const BARS_INV: [[[u8; 2]; 2]; 7] = [
    [[0, 0], [0, 0]],
    [[173, 172], [172, 172]],
    [[173, 3], [172, 1]],
    [[75, 74], [149, 149]],
    [[1, 2], [2, 5]],
    [[172, 172], [172, 173]],
    [[1, 1], [2, 3]],
];
#[allow(dead_code)] // reference tables: generated / unrolled code is tested against them
const TRIPLETS: [[[u8; 3]; 3]; 6] = [
    [[5, 1, 1], [2, 3, 1], [5, 5, 2]],
    [[1, 3, 1], [3, 5, 2], [3, 2, 1]],
    [[2, 1, 1], [1, 3, 1], [3, 3, 2]],
    [[3, 3, 1], [2, 5, 3], [1, 3, 2]],
    [[1, 1, 1], [1, 3, 2], [3, 2, 3]],
    [[2, 1, 3], [3, 1, 3], [1, 2, 5]],
];
#[allow(dead_code)] // reference tables: generated / unrolled code is tested against them
const TRIPLETS_INV: [[[u8; 3]; 3]; 6] = [
    [[1, 3, 254], [1, 5, 253], [251, 236, 13]],
    [[1, 255, 1], [3, 254, 1], [247, 7, 252]],
    [[3, 1, 254], [1, 1, 255], [250, 253, 5]],
    [[1, 253, 4], [255, 5, 249], [1, 250, 9]],
    [[5, 255, 255], [3, 0, 255], [249, 1, 2]],
    [[255, 1, 0], [244, 7, 3], [5, 253, 255]],
];
#[allow(dead_code)] // reference tables: generated / unrolled code is tested against them
const BOW_STROKES: [(usize, usize, usize); 7] = [(0, 1, 2), (2, 3, 4), (4, 5, 0), (6, 7, 0), (1, 2, 3), (3, 4, 5), (5, 6, 0)];
#[allow(dead_code)] // reference tables: generated / unrolled code is tested against them
const BOW_ROT: [usize; 7] = [0, 0, 0, 3, 0, 0, 5];

/// Cross-staff layers as (partner shuffle index, b-lane mask, touched-lane mask) over 16 faces.
const CROSS: [[(u8, u8); 8]; 4] = [
    [(0, 4), (1, 5), (2, 6), (3, 7), (8, 12), (9, 13), (10, 14), (11, 15)],
    [(0, 8), (1, 9), (2, 10), (3, 11), (4, 12), (5, 13), (6, 14), (7, 15)],
    [(0, 1), (2, 3), (4, 5), (6, 7), (8, 9), (10, 11), (12, 13), (14, 15)],
    [(1, 2), (5, 6), (9, 10), (13, 14), (255, 255), (255, 255), (255, 255), (255, 255)],
];
struct CrossL {
    idx: [u8; 16],   // partner index (identity on untouched lanes)
    idx_z: [u8; 16], // partner index, 0x80 (PSHUFB -> zero) on untouched lanes
    a_vec: [u8; 16], // 0xff on a lanes
    b_mask: u16,
    touched: u16,
}
const fn cross_layers() -> [CrossL; 4] {
    let mut out = [
        CrossL { idx: [0; 16], idx_z: [0x80; 16], a_vec: [0; 16], b_mask: 0, touched: 0 },
        CrossL { idx: [0; 16], idx_z: [0x80; 16], a_vec: [0; 16], b_mask: 0, touched: 0 },
        CrossL { idx: [0; 16], idx_z: [0x80; 16], a_vec: [0; 16], b_mask: 0, touched: 0 },
        CrossL { idx: [0; 16], idx_z: [0x80; 16], a_vec: [0; 16], b_mask: 0, touched: 0 },
    ];
    let mut l = 0;
    while l < 4 {
        let mut f = 0;
        while f < 16 {
            out[l].idx[f] = f as u8;
            f += 1;
        }
        let mut k = 0;
        while k < 8 {
            let (a, b) = CROSS[l][k];
            if a != 255 {
                out[l].idx[a as usize] = b;
                out[l].idx[b as usize] = a;
                out[l].idx_z[a as usize] = b;
                out[l].idx_z[b as usize] = a;
                out[l].a_vec[a as usize] = 0xff;
                out[l].b_mask |= 1 << b;
                out[l].touched |= (1 << a) | (1 << b);
            }
            k += 1;
        }
        l += 1;
    }
    out
}
const CROSS_L: [CrossL; 4] = cross_layers();

impl SimdKey {
    pub fn new(sch: &Schedule) -> Option<Box<SimdKey>> {
        if !available() {
            return None;
        }
        let col = col_layout();
        let to_col = gather(&core::array::from_fn(|i| i as u8), &col, None);
        let to_fm = gather(&col, &core::array::from_fn(|i| i as u8), None);
        let coli = inverse(&col);
        let mut rounds = Box::new(
            [RoundK { rk: [0; BLOCK_LEN], sb: [Sb::default(); 4], enc_g: [[0; BLOCK_LEN]; 5], dec_g: [[0; BLOCK_LEN]; 5] }; NR],
        );
        for (r, rk) in sch.rounds.iter().enumerate() {
            let mut rkc = [0u8; BLOCK_LEN];
            for p in 0..BLOCK_LEN {
                rkc[p] = rk.rk[col[p] as usize];
            }
            // weave as a gather map: new[c] = old[w[c]]
            let mut w = [0u8; BLOCK_LEN];
            for f in 0..16 {
                for t in 0..8 {
                    let fp = (f + 16 - rk.sv[t] as usize) % 16;
                    w[8 * f + t] = (8 * fp + (t + rk.sh[fp] as usize) % 8) as u8;
                }
            }
            let winv = inverse(&w);
            let bfly = |m: usize| {
                let mut y = [0u8; BLOCK_LEN];
                for f in 0..16 {
                    let mut j = 0;
                    for i in 0..8 {
                        if i & m == 0 {
                            let q = 4 * f + j;
                            y[q] = (8 * f + rk.sigma[f][i] as usize) as u8;
                            y[64 + q] = (8 * f + rk.sigma[f][i | m] as usize) as u8;
                            j += 1;
                        }
                    }
                }
                y
            };
            let (b1, b2, b4) = (bfly(1), bfly(2), bfly(4));
            let mut br = [0u8; BLOCK_LEN];
            for c in 0..64 {
                let (i, o) = (c as u8, 64 + rk.bridge[c]);
                if r % 2 == 0 {
                    br[c] = i;
                    br[64 + c] = o;
                } else {
                    br[c] = o;
                    br[64 + c] = i;
                }
            }
            let enc_g = [
                gather(&col, &b1, Some(&w)),
                gather(&b1, &b2, None),
                gather(&b2, &b4, None),
                gather(&b4, &br, None),
                gather(&br, &col, None),
            ];
            let dec_g = [
                gather(&col, &br, None),
                gather(&br, &b4, None),
                gather(&b4, &b2, None),
                gather(&b2, &b1, None),
                gather(&b1, &col, Some(&winv)),
            ];
            let _ = coli;
            rounds[r] = RoundK {
                rk: rkc,
                sb: [
                    Sb::new(&AesForm::forward(&rk.s)),
                    Sb::new(&AesForm::forward(&rk.s2)),
                    Sb::new(&AesForm::inverse(&rk.s)),
                    Sb::new(&AesForm::inverse(&rk.s2)),
                ],
                enc_g,
                dec_g,
            };
        }
        let mut white = [0u8; BLOCK_LEN];
        for p in 0..BLOCK_LEN {
            white[p] = sch.white[col[p] as usize];
        }
        let q = |c: u8| gfni_qword(&mulc_mat(c));
        let bars = core::array::from_fn(|k| core::array::from_fn(|i| core::array::from_fn(|j| q(BARS[k][i][j]))));
        let bars_inv = core::array::from_fn(|k| core::array::from_fn(|i| core::array::from_fn(|j| q(BARS_INV[k][i][j]))));
        let rot = core::array::from_fn(|k| {
            let mut cols = [0u8; 8];
            for j in 0..8 {
                cols[j] = 1u8 << ((j + k) % 8);
            }
            gfni_qword(&Mat8 { cols })
        });
        let c = Consts { m2: q(2), minv3: q(crate::gf::INV3), bars, bars_inv, rot };
        Some(Box::new(SimdKey { rounds, white, to_col, to_fm, c }))
    }

    /// Encrypt independent blocks (same schedule), 4 interleaved at a time.
    pub fn encrypt_blocks(&self, blocks: &mut [[u8; BLOCK_LEN]], rounds: usize) {
        let mut it8 = blocks.chunks_exact_mut(8);
        for g in &mut it8 {
            // SAFETY: SimdKey::new checked the CPU features.
            unsafe { enc_n::<8>(self, g.try_into().unwrap(), rounds) }
        }
        let mut it = it8.into_remainder().chunks_exact_mut(4);
        for g in &mut it {
            unsafe { enc_n::<4>(self, g.try_into().unwrap(), rounds) }
        }
        for b in it.into_remainder() {
            unsafe { enc_n::<1>(self, core::slice::from_mut(b).try_into().unwrap(), rounds) }
        }
    }
    pub fn decrypt_blocks(&self, blocks: &mut [[u8; BLOCK_LEN]], rounds: usize) {
        let mut it8 = blocks.chunks_exact_mut(8);
        for g in &mut it8 {
            // SAFETY: SimdKey::new checked the CPU features.
            unsafe { dec_n::<8>(self, g.try_into().unwrap(), rounds) }
        }
        let mut it = it8.into_remainder().chunks_exact_mut(4);
        for g in &mut it {
            unsafe { dec_n::<4>(self, g.try_into().unwrap(), rounds) }
        }
        for b in it.into_remainder() {
            unsafe { dec_n::<1>(self, core::slice::from_mut(b).try_into().unwrap(), rounds) }
        }
    }
}

// ---------------------------------------------------------------- vector helpers
type Z = [__m512i; 2];
type C = [__m128i; 8];


#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
fn load(b: &[u8; BLOCK_LEN]) -> Z {
    unsafe { [_mm512_loadu_si512(b.as_ptr() as *const _), _mm512_loadu_si512(b.as_ptr().add(64) as *const _)] }
}
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
fn store(z: &Z, b: &mut [u8; BLOCK_LEN]) {
    unsafe {
        _mm512_storeu_si512(b.as_mut_ptr() as *mut _, z[0]);
        _mm512_storeu_si512(b.as_mut_ptr().add(64) as *mut _, z[1]);
    }
}
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
fn perm(z: &Z, idx: &[u8; BLOCK_LEN]) -> Z {
    let i = load(idx);
    [_mm512_permutex2var_epi8(z[0], i[0], z[1]), _mm512_permutex2var_epi8(z[0], i[1], z[1])]
}
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
fn xorz(z: &Z, k: &[u8; BLOCK_LEN]) -> Z {
    let kk = load(k);
    [_mm512_xor_si512(z[0], kk[0]), _mm512_xor_si512(z[1], kk[1])]
}
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
fn aff512(x: __m512i, m: u64) -> __m512i {
    _mm512_gf2p8affine_epi64_epi8::<0>(x, _mm512_set1_epi64(m as i64))
}
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
fn sbox512(x: __m512i, s: &Sb) -> __m512i {
    let y = _mm512_xor_si512(aff512(x, s.pre), _mm512_set1_epi8(s.pre_c as i8));
    _mm512_xor_si512(_mm512_gf2p8affineinv_epi64_epi8::<0>(y, _mm512_set1_epi64(s.post as i64)), _mm512_set1_epi8(s.post_c as i8))
}
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
fn split(z: &Z) -> C {
    [
        _mm512_extracti32x4_epi32::<0>(z[0]),
        _mm512_extracti32x4_epi32::<1>(z[0]),
        _mm512_extracti32x4_epi32::<2>(z[0]),
        _mm512_extracti32x4_epi32::<3>(z[0]),
        _mm512_extracti32x4_epi32::<0>(z[1]),
        _mm512_extracti32x4_epi32::<1>(z[1]),
        _mm512_extracti32x4_epi32::<2>(z[1]),
        _mm512_extracti32x4_epi32::<3>(z[1]),
    ]
}
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
fn join(c: &C) -> Z {
    let lo = |a, b, c2, d| {
        let x = _mm512_castsi128_si512(a);
        let x = _mm512_inserti32x4::<1>(x, b);
        let x = _mm512_inserti32x4::<2>(x, c2);
        _mm512_inserti32x4::<3>(x, d)
    };
    [lo(c[0], c[1], c[2], c[3]), lo(c[4], c[5], c[6], c[7])]
}

// pair-layout mixes
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
fn mix2z(z: &Z, k: &Consts) -> Z {
    [_mm512_xor_si512(z[0], z[1]), _mm512_xor_si512(z[0], aff512(z[1], k.m2))]
}
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
fn mix2z_inv(z: &Z, k: &Consts) -> Z {
    let v = aff512(_mm512_xor_si512(z[0], z[1]), k.minv3);
    [_mm512_xor_si512(z[0], v), v]
}

// ---------------------------------------------------------------- column-major per-row layers
// Written once (simd_layers.rs) and compiled for two widths.
mod w128 {
    use super::*;
    include!("ops128.rs");
    include!("simd_layers.rs");
}
mod w512 {
    use super::*;
    include!("ops512.rs");
    include!("simd_layers.rs");
}
type C4 = [__m512i; 8];

/// 4x4 transpose of 128-bit lanes (an involution): [a b c d] rows -> columns.
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
fn t4(a: __m512i, b: __m512i, c: __m512i, d: __m512i) -> [__m512i; 4] {
    let t0 = _mm512_shuffle_i64x2::<0x44>(a, b);
    let t1 = _mm512_shuffle_i64x2::<0xEE>(a, b);
    let t2 = _mm512_shuffle_i64x2::<0x44>(c, d);
    let t3 = _mm512_shuffle_i64x2::<0xEE>(c, d);
    [
        _mm512_shuffle_i64x2::<0x88>(t0, t2),
        _mm512_shuffle_i64x2::<0xDD>(t0, t2),
        _mm512_shuffle_i64x2::<0x88>(t1, t3),
        _mm512_shuffle_i64x2::<0xDD>(t1, t3),
    ]
}
/// Blocks 4g..4g+3 (column-major Z each) -> packed columns: c4[t] lane n = column t of block 4g+n.
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
fn pack4(z: &[Z], g: usize) -> C4 {
    let lo = t4(z[4 * g][0], z[4 * g + 1][0], z[4 * g + 2][0], z[4 * g + 3][0]);
    let hi = t4(z[4 * g][1], z[4 * g + 1][1], z[4 * g + 2][1], z[4 * g + 3][1]);
    [lo[0], lo[1], lo[2], lo[3], hi[0], hi[1], hi[2], hi[3]]
}
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
fn unpack4(c: &C4, z: &mut [Z], g: usize) {
    let lo = t4(c[0], c[1], c[2], c[3]);
    let hi = t4(c[4], c[5], c[6], c[7]);
    for n in 0..4 {
        z[4 * g + n] = [lo[n], hi[n]];
    }
}
/// The per-row part of a round for N blocks: N == 1 uses 128-bit columns; N a multiple of 4 packs
/// four blocks per zmm and runs N/4 independent chains.
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
fn rows_n<const N: usize>(z: &mut [Z; N], rk: &RoundK, k: &Consts, decrypt: bool) {
    if N % 4 == 0 {
        let mut c: [C4; 2] = [[_mm512_setzero_si512(); 8]; 2];
        let g_n = N / 4;
        assert!(g_n <= 2);
        for g in 0..g_n {
            c[g] = pack4(&z[..], g);
        }
        // separate loops keep the chains independent so they overlap
        if decrypt {
            if g_n == 2 {
                let (a, b) = c.split_at_mut(1);
                rows2(&mut a[0], &mut b[0], rk, k, true);
            } else {
                w512::dec_rows(&mut c[0], rk, k);
            }
        } else if g_n == 2 {
            let (a, b) = c.split_at_mut(1);
            rows2(&mut a[0], &mut b[0], rk, k, false);
        } else {
            w512::enc_rows(&mut c[0], rk, k);
        }
        for g in 0..g_n {
            unpack4(&c[g], &mut z[..], g);
        }
    } else {
        for n in 0..N {
            let mut c = split(&z[n]);
            if decrypt { w128::dec_rows(&mut c, rk, k) } else { w128::enc_rows(&mut c, rk, k) }
            z[n] = join(&c);
        }
    }
}
/// Two packed chains (8 blocks), layer by layer so the out-of-order core can overlap them.
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
fn rows2(a: &mut C4, b: &mut C4, rk: &RoundK, k: &Consts, decrypt: bool) {
    use w512::*;
    if decrypt {
        for half in [1, 0] {
            uncross(a, k); uncross(b, k);
            unodd(a, rk, k); unodd(b, rk, k);
            unbow(a, k); unbow(b, k);
            untrip(a); untrip(b);
            bar_unmix(a, rk, k); bar_unmix(b, rk, k);
            if half == 1 {
                for t in 0..8 {
                    a[t] = sbox(a[t], &rk.sb[3]);
                    b[t] = sbox(b[t], &rk.sb[3]);
                }
            }
        }
    } else {
        for half in 0..2 {
            if half == 1 {
                for t in 0..8 {
                    a[t] = sbox(a[t], &rk.sb[1]);
                    b[t] = sbox(b[t], &rk.sb[1]);
                }
            }
            bar_mix(a, rk, k); bar_mix(b, rk, k);
            trip(a); trip(b);
            bow(a, k); bow(b, k);
            odd(a, rk, k); odd(b, rk, k);
            cross(a, k); cross(b, k);
        }
    }
}

// ---------------------------------------------------------------- whole rounds, N blocks interleaved
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
fn enc_n<const N: usize>(key: &SimdKey, blocks: &mut [[u8; BLOCK_LEN]; N], rounds: usize) {
    let k = &key.c;
    let mut z: [Z; N] = core::array::from_fn(|n| perm(&load(&blocks[n]), &key.to_col));
    for r in 0..rounds {
        let rk = &key.rounds[r];
        for n in 0..N {
            let a = xorz(&z[n], &rk.rk);
            z[n] = [sbox512(a[0], &rk.sb[0]), sbox512(a[1], &rk.sb[0])];
            for g in 0..4 {
                z[n] = mix2z(&perm(&z[n], &rk.enc_g[g]), k);
            }
            z[n] = perm(&z[n], &rk.enc_g[4]);
        }
        rows_n::<N>(&mut z, rk, k, false);
    }
    for n in 0..N {
        let w = xorz(&z[n], &key.white);
        store(&perm(&w, &key.to_fm), &mut blocks[n]);
    }
}

#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
fn dec_n<const N: usize>(key: &SimdKey, blocks: &mut [[u8; BLOCK_LEN]; N], rounds: usize) {
    let k = &key.c;
    let mut z: [Z; N] = core::array::from_fn(|n| xorz(&perm(&load(&blocks[n]), &key.to_col), &key.white));
    for r in (0..rounds).rev() {
        let rk = &key.rounds[r];
        rows_n::<N>(&mut z, rk, k, true);
        for n in 0..N {
            let mut zz = z[n];
            for g in 0..4 {
                zz = mix2z_inv(&perm(&zz, &rk.dec_g[g]), k);
            }
            zz = perm(&zz, &rk.dec_g[4]);
            let s = [sbox512(zz[0], &rk.sb[2]), sbox512(zz[1], &rk.sb[2])];
            z[n] = xorz(&s, &rk.rk);
        }
    }
    for n in 0..N {
        store(&perm(&z[n], &key.to_fm), &mut blocks[n]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::w128::{bow_amounts, trip, untrip, vrot};
    /// The generated straight-line triplet code equals the table definition (and its inverse undoes it).
    #[test]
    fn generated_triplets_match_tables() {
        if !available() {
            return;
        }
        #[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
        fn run() {
            let mut x = 0x1234_5678_9abc_def1u64;
            for _ in 0..200 {
                let mut b = [[0u8; 16]; 8];
                for r in b.iter_mut() {
                    for v in r.iter_mut() {
                        x ^= x << 13;
                        x ^= x >> 7;
                        x ^= x << 17;
                        *v = x as u8;
                    }
                }
                let mut want = b;
                for j in 0..6 {
                    let m = &TRIPLETS[j];
                    for f in 0..16 {
                        let v = [want[j][f], want[j + 1][f], want[j + 2][f]];
                        for i in 0..3 {
                            want[j + i][f] = (0..3).fold(0u8, |a, q| a.wrapping_add(m[i][q].wrapping_mul(v[q])));
                        }
                    }
                }
                let mut c: C = core::array::from_fn(|t| unsafe { _mm_loadu_si128(b[t].as_ptr() as *const _) });
                trip(&mut c);
                let mut got = [[0u8; 16]; 8];
                for t in 0..8 {
                    unsafe { _mm_storeu_si128(got[t].as_mut_ptr() as *mut _, c[t]) };
                }
                assert_eq!(got, want);
                untrip(&mut c);
                for t in 0..8 {
                    unsafe { _mm_storeu_si128(got[t].as_mut_ptr() as *mut _, c[t]) };
                }
                assert_eq!(got, b);
            }
        }
        unsafe { run() }
    }
    /// vrot and bow_amounts, exhaustive over every byte value and amount.
    #[test]
    fn vrot_and_amounts_exhaustive() {
        if !available() {
            return;
        }
        #[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
        fn run() {
            let seed = [3u8; 128];
            let key = SimdKey::new(&Schedule::new(&seed, &[1u8; 16])).unwrap();
            for base in (0..256).step_by(16) {
                let xs: [u8; 16] = core::array::from_fn(|i| (base + i) as u8);
                let x = unsafe { _mm_loadu_si128(xs.as_ptr() as *const _) };
                let (a1, a2) = bow_amounts(x);
                let (mut g1, mut g2) = ([0u8; 16], [0u8; 16]);
                unsafe {
                    _mm_storeu_si128(g1.as_mut_ptr() as *mut _, a1);
                    _mm_storeu_si128(g2.as_mut_ptr() as *mut _, a2);
                }
                for i in 0..16 {
                    assert_eq!(g1[i], 1 + xs[i] % 7);
                    assert_eq!(g2[i], 1 + (xs[i] >> 3) % 7);
                }
                for r0 in 1..=7u8 {
                    // mixed amounts per lane
                    let rs: [u8; 16] = core::array::from_fn(|i| 1 + ((r0 as usize + i) % 7) as u8);
                    let r = unsafe { _mm_loadu_si128(rs.as_ptr() as *const _) };
                    let mut g = [0u8; 16];
                    unsafe { _mm_storeu_si128(g.as_mut_ptr() as *mut _, { let _ = &key.c; vrot(x, r) }) };
                    for i in 0..16 {
                        assert_eq!(g[i], xs[i].rotate_left(rs[i] as u32));
                    }
                }
            }
        }
        unsafe { run() }
    }
    /// The unrolled bow macros follow BOW_STROKES / BOW_ROT.
    #[test]
    fn bow_tables_match() {
        let src = include_str!("simd_layers.rs");
        let mut fwd = std::vec::Vec::new();
        for (s, &(i, j, p)) in BOW_STROKES.iter().enumerate() {
            fwd.push(std::format!("    bow_stroke!(c, k, {i}, {j}, {p}, {});", BOW_ROT[s]));
        }
        let rev: std::vec::Vec<_> = BOW_STROKES.iter().enumerate().rev().map(|(s, &(i, j, p))| std::format!("    unbow_stroke!(c, k, {i}, {j}, {p}, {});", BOW_ROT[s])).collect();
        assert!(src.contains(&fwd.join("\n")), "bow strokes out of sync");
        assert!(src.contains(&rev.join("\n")), "unbow strokes out of sync");
    }
    #[test]
    fn bow_amount_formula() {
        for v in 0..=255u32 {
            let d0 = v & 7;
            let d1 = (v >> 3) & 7;
            let d2 = v >> 6;
            let mut s = d0 + d1 + d2;
            if s > 6 { s -= 7 }
            if s > 6 { s -= 7 }
            let mut w = d1 + d2;
            if w > 6 { w -= 7 }
            assert_eq!(s, v % 7);
            assert_eq!(w, (v >> 3) % 7);
        }
    }
}


/// Timing-test hooks (feature `dudect-hooks`, off by default; used only by the dudect harness).
/// They expose the VPSLLVW per-byte rotation and the bow / unbow layers on caller-chosen data, so
/// the data-dependent rotation amounts can be timed directly. Callers must check
/// [`available`] first (GFNI + AVX-512 BW/VL/VBMI).
#[cfg(feature = "dudect-hooks")]
#[doc(hidden)]
pub mod dudect_hooks {
    use super::*;
    /// `iters` dependent rotations of 64 bytes on the zmm path: `x = vrot(x, r)` (r bytes in 1..=7).
    pub fn vrot_chain512(x: &mut [u8; 64], r: &[u8; 64], iters: u32) {
        assert!(available());
        unsafe { vrot512(x, r, iters) }
    }
    /// Same on the xmm path (the one-block route used by `encrypt_block`).
    pub fn vrot_chain128(x: &mut [u8; 16], r: &[u8; 16], iters: u32) {
        assert!(available());
        unsafe { vrot128(x, r, iters) }
    }
    /// `reps` dependent bow (or unbow) layers of `key` on a raw 8-row x 16-byte column state (xmm
    /// path). The all-zero state is a fixed point (every amount stays 1).
    pub fn bow_layer128(key: &SimdKey, state: &mut [u8; BLOCK_LEN], inverse: bool, reps: u32) {
        assert!(available());
        unsafe { bow128(key, state, inverse, reps) }
    }
    /// One bow (or unbow) layer on four such states packed one per 128-bit lane (zmm path, as in
    /// the 4/8-block batches). `state` row r = 64 bytes (lane n = block n).
    pub fn bow_layer512(key: &SimdKey, state: &mut [u8; 4 * BLOCK_LEN], inverse: bool, reps: u32) {
        assert!(available());
        unsafe { bow512(key, state, inverse, reps) }
    }
    #[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
    unsafe fn vrot512(x: &mut [u8; 64], r: &[u8; 64], iters: u32) {
        let mut v = _mm512_loadu_si512(x.as_ptr() as *const _);
        let rv = _mm512_loadu_si512(r.as_ptr() as *const _);
        for _ in 0..iters {
            v = w512::vrot(v, rv);
        }
        _mm512_storeu_si512(x.as_mut_ptr() as *mut _, v);
    }
    #[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
    unsafe fn vrot128(x: &mut [u8; 16], r: &[u8; 16], iters: u32) {
        let mut v = _mm_loadu_si128(x.as_ptr() as *const _);
        let rv = _mm_loadu_si128(r.as_ptr() as *const _);
        for _ in 0..iters {
            v = w128::vrot(v, rv);
        }
        _mm_storeu_si128(x.as_mut_ptr() as *mut _, v);
    }
    #[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
    unsafe fn bow128(key: &SimdKey, st: &mut [u8; BLOCK_LEN], inverse: bool, reps: u32) {
        let mut c: [__m128i; 8] = core::array::from_fn(|i| _mm_loadu_si128(st[16 * i..].as_ptr() as *const _));
        for _ in 0..reps {
            if inverse { w128::unbow(&mut c, &key.c) } else { w128::bow(&mut c, &key.c) }
        }
        for i in 0..8 {
            _mm_storeu_si128(st[16 * i..].as_mut_ptr() as *mut _, c[i]);
        }
    }
    #[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
    unsafe fn bow512(key: &SimdKey, st: &mut [u8; 4 * BLOCK_LEN], inverse: bool, reps: u32) {
        let mut c: [__m512i; 8] = core::array::from_fn(|i| _mm512_loadu_si512(st[64 * i..].as_ptr() as *const _));
        for _ in 0..reps {
            if inverse { w512::unbow(&mut c, &key.c) } else { w512::bow(&mut c, &key.c) }
        }
        for i in 0..8 {
            _mm512_storeu_si512(st[64 * i..].as_mut_ptr() as *mut _, c[i]);
        }
    }
}

/// Per-layer latency profile (ns per call, dependent chain, one block). Diagnostics only.
#[cfg(feature = "std")]
#[doc(hidden)]
pub fn profile_layers(key: &SimdKey) -> std::vec::Vec<(&'static str, f64)> {
    unsafe { profile_inner(key) }
}
#[cfg(feature = "std")]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
fn profile_inner(key: &SimdKey) -> std::vec::Vec<(&'static str, f64)> {
    use std::hint::black_box;
    use std::time::Instant;
    use w128::*;
    let k = &key.c;
    let rk = &key.rounds[3];
    let mut out = std::vec::Vec::new();
    let blk = [0x5au8; BLOCK_LEN];
    let iters = 200_000u32;
    macro_rules! layer {
        ($name:expr, |$c:ident| $body:block) => {{
            let mut $c = split(&load(&blk));
            let t = Instant::now();
            for _ in 0..iters {
                $body
                $c = black_box($c);
            }
            out.push(($name, t.elapsed().as_nanos() as f64 / iters as f64));
        }};
    }
    layer!("bar_mix", |c| { bar_mix(&mut c, rk, k) });
    layer!("bar_unmix", |c| { bar_unmix(&mut c, rk, k) });
    layer!("trip", |c| { trip(&mut c) });
    layer!("untrip", |c| { untrip(&mut c) });
    layer!("bow", |c| { bow(&mut c, k) });
    layer!("unbow", |c| { unbow(&mut c, k) });
    layer!("odd", |c| { odd(&mut c, rk, k) });
    layer!("unodd", |c| { unodd(&mut c, rk, k) });
    layer!("cross", |c| { cross(&mut c, k) });
    layer!("uncross", |c| { uncross(&mut c, k) });
    layer!("sbox8", |c| { for t in 0..8 { c[t] = sbox(c[t], &rk.sb[1]) } });
    layer!("enc_round", |c| {
        let mut b = [[0u8; BLOCK_LEN]; 1];
        store(&join(&c), &mut b[0]);
        enc_n::<1>(key, &mut b, 1);
        c = split(&load(&b[0]));
    });
    layer!("dec_round", |c| {
        let mut b = [[0u8; BLOCK_LEN]; 1];
        store(&join(&c), &mut b[0]);
        dec_n::<1>(key, &mut b, 1);
        c = split(&load(&b[0]));
    });
    layer!("zpart_enc", |c| {
        let a = xorz(&join(&c), &rk.rk);
        let mut z = [sbox512(a[0], &rk.sb[0]), sbox512(a[1], &rk.sb[0])];
        for g in 0..4 { z = mix2z(&perm(&z, &rk.enc_g[g]), k); }
        c = split(&perm(&z, &rk.enc_g[4]));
    });
    layer!("zpart_dec", |c| {
        let mut zz = join(&c);
        for g in 0..4 { zz = mix2z_inv(&perm(&zz, &rk.dec_g[g]), k); }
        zz = perm(&zz, &rk.dec_g[4]);
        let s = [sbox512(zz[0], &rk.sb[2]), sbox512(zz[1], &rk.sb[2])];
        c = split(&xorz(&s, &rk.rk));
    });
    out
}

// wipe the round tables on drop (feature `zeroize`).
#[cfg(feature = "zeroize")]
impl Drop for SimdKey {
    fn drop(&mut self) {
        use crate::wipe::wipe_flat;
        wipe_flat(&mut *self.rounds);
        wipe_flat(&mut self.white);
        wipe_flat(&mut self.to_col);
        wipe_flat(&mut self.to_fm);
        wipe_flat(&mut self.c.m2);
        wipe_flat(&mut self.c.minv3);
        wipe_flat(&mut self.c.bars);
        wipe_flat(&mut self.c.bars_inv);
        wipe_flat(&mut self.c.rot);
    }
}
