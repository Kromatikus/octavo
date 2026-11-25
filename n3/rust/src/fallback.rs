//! fallback1: data paths for CPUs without AVX-512 + GFNI.
//!
//! One generic "row layout" kernel. A block is 16 64-bit words (word f = face
//! f, byte t = beat t). Every layer is lane-wise on bytes, a combination of
//! whole words (multiply-by-public-constant + XOR), an 8x8 byte transpose with
//! fixed shifts and masks, or a Benes network with key-derived masks (same
//! switch settings as perm1). No secret-dependent branches or addresses.
//!
//! Lane backends (the `Ops` trait):
//!   * `Swar64`   portable u64 SWAR, 1 block per pass (any CPU, any arch).
//!   * `Avx2Soft` AVX2 only, 4 blocks per pass (one block per 64-bit lane).
//!                S-box = Mout * t^254 * ... with a 4-multiply chain; linear
//!                maps by VPSHUFB nibble tables (register-resident tables,
//!                index = secret, address = public).
//!   * `Avx2Gfni` AVX2 + GFNI (VEX 256-bit GF2P8AFFINE[INV]QB), 4 blocks/pass.
//!
//! Homemade; for real secrets use AES-GCM-SIV, age, or libsodium.

#![allow(clippy::needless_range_loop)]

use crate::affine::Mat8;
use crate::gf::const_mul;
use crate::iso::{gfni_qword, AesForm};
use crate::sbox_aff::KeyedSbox;
use crate::{Field, Round, BLOCK_LEN, NR};

const L1: u64 = 0x0101_0101_0101_0101;

// ------------------------------------------------------------ key material

#[derive(Clone, Copy, Default)]
pub(crate) struct Aff {
    cols: [u8; 8],  // Mat8 columns (image of bit j)
    c: u8,          // XOR constant
    nib: [u8; 32],  // nib[n] = M*n ^ c, nib[16+n] = M*(n<<4)
}

impl Aff {
    fn new(m: &Mat8, c: u8) -> Aff {
        let mut nib = [0u8; 32];
        for n in 0..16u8 {
            nib[n as usize] = m.apply(n) ^ c;
            nib[16 + n as usize] = m.apply(n << 4);
        }
        Aff { cols: m.cols, c, nib }
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct SbData {
    pre: Aff,
    post: Aff,
    // AES-field form for GF2P8AFFINEINVQB
    q_pre: u64,
    q_pre_c: u8,
    q_post: u64,
    q_post_c: u8,
}

fn sb_data(ks: &KeyedSbox, inverse: bool) -> SbData {
    let (pre_m, pre_c, post_m, post_c, af) = if !inverse {
        (ks.m_in, ks.c_in, ks.m_out, ks.c_out, AesForm::forward(ks))
    } else {
        let (mi, ci, mo, co) = ks.inverse_parts();
        (*mo, mo.apply(co), *mi, mi.apply(ci), AesForm::inverse(ks))
    };
    SbData {
        pre: Aff::new(&pre_m, pre_c),
        post: Aff::new(&post_m, post_c),
        q_pre: gfni_qword(&af.p_mat),
        q_pre_c: af.p,
        q_post: gfni_qword(&af.q_mat),
        q_post_c: af.q,
    }
}

/// x -> x^(2^k) in GF(2^8)/0x1F5 (linear over GF(2)).
fn frob_mat(k: u32) -> Mat8 {
    let mut cols = [0u8; 8];
    for j in 0..8 {
        let mut v = 1u8 << j;
        for _ in 0..k {
            v = const_mul(v, v);
        }
        cols[j] = v;
    }
    Mat8 { cols }
}

fn mulc_mat(c: u8) -> Mat8 {
    let mut cols = [0u8; 8];
    for j in 0..8 {
        cols[j] = const_mul(c, 1 << j);
    }
    Mat8 { cols }
}

pub(crate) const BENES_STRIDES: [usize; 11] = [32, 16, 8, 4, 2, 1, 2, 4, 8, 16, 32];

pub(crate) struct FbRound {
    rk: [u64; 16],
    s: SbData,
    sm: SbData,
    s2: SbData,
    si: SbData,
    sim: SbData,
    si2: SbData,
    /// Row-layout Benes masks: [stage][word or word-pair]
    benes: [[u64; 8]; 11],
    even: bool,
}

pub(crate) struct FbKey {
    rounds: Vec<FbRound>,
    white: [u64; 16],
    chord: [[u8; 8]; 8],
    chord_inv: [[u8; 8]; 8],
    cross: [[u8; 16]; 16],
    cross_inv: [[u8; 16]; 16],
    trip: [[[u8; 3]; 3]; 6],
    trip_inv: [[[u8; 3]; 3]; 6],
    inv3: u8,
    // public per-constant tables
    mulc_q: [u64; 256],
    mulc_nib: [[u8; 32]; 256],
    rotl_q: [u64; 8],
    frob: [Aff; 3], // x^2, x^4, x^16
}

fn words_of(b: &[u8; BLOCK_LEN]) -> [u64; 16] {
    let mut w = [0u64; 16];
    for f in 0..16 {
        let mut a = [0u8; 8];
        a.copy_from_slice(&b[8 * f..8 * f + 8]);
        w[f] = u64::from_le_bytes(a);
    }
    w
}

/// Benes switch bits (bit k of stage st = switch k) -> row-layout masks.
pub(crate) fn benes_row_masks(bits: &[u32; 11]) -> [[u64; 8]; 11] {
    let mut out = [[0u64; 8]; 11];
    for st in 0..11 {
        let m = BENES_STRIDES[st];
        if m >= 8 {
            let d = m / 8;
            let mut p = 0;
            for w in 0..8 {
                if w & d != 0 {
                    continue;
                }
                let mut mk = 0u64;
                for t in 0..8 {
                    let x = 8 * w + t;
                    let k = benes_k(x, m);
                    let bit = ((bits[st] >> k) & 1) as u64;
                    mk |= (0u64.wrapping_sub(bit) & 0xFF) << (8 * t);
                }
                out[st][p] = mk;
                p += 1;
            }
        } else {
            for w in 0..8 {
                let mut mk = 0u64;
                for t in 0..8 {
                    if t & m != 0 {
                        continue;
                    }
                    let x = 8 * w + t;
                    let k = benes_k(x, m);
                    let bit = ((bits[st] >> k) & 1) as u64;
                    mk |= (0u64.wrapping_sub(bit) & 0xFF) << (8 * t);
                }
                out[st][w] = mk;
            }
        }
    }
    out
}

#[inline(always)]
pub(crate) const fn benes_k(x: usize, m: usize) -> usize {
    ((x >> 1) & !(m - 1)) | (x & (m - 1))
}


struct PublicTables {
    mulc_q: [u64; 256],
    mulc_nib: [[u8; 32]; 256],
    rotl_q: [u64; 8],
    frob: [Aff; 3],
}

/// Key-independent fallback tables, built once per process.
fn public_tables() -> &'static PublicTables {
    static T: std::sync::OnceLock<PublicTables> = std::sync::OnceLock::new();
    T.get_or_init(|| {
        let mut mulc_q = [0u64; 256];
        let mut mulc_nib = [[0u8; 32]; 256];
        for c in 0..256 {
            let m = mulc_mat(c as u8);
            mulc_q[c] = gfni_qword(&m);
            mulc_nib[c] = Aff::new(&m, 0).nib;
        }
        PublicTables {
            mulc_q,
            mulc_nib,
            rotl_q: core::array::from_fn(crate::iso::rotl_qword),
            frob: [
                Aff::new(&frob_mat(1), 0),
                Aff::new(&frob_mat(2), 0),
                Aff::new(&frob_mat(4), 0),
            ],
        }
    })
}

impl FbKey {
    pub(crate) fn new(field: &Field, rounds: &[Round], white: &[u8; BLOCK_LEN]) -> Box<FbKey> {
        let mut rs = Vec::with_capacity(NR);
        for (r, rd) in rounds.iter().enumerate() {
            let bits = crate::benes_soft::benes_route_bits(&rd.bridge);
            rs.push(FbRound {
                rk: words_of(&rd.rk),
                s: sb_data(&rd.ks, false),
                sm: sb_data(&rd.ksm, false),
                s2: sb_data(&rd.ks2, false),
                si: sb_data(&rd.ks, true),
                sim: sb_data(&rd.ksm, true),
                si2: sb_data(&rd.ks2, true),
                benes: benes_row_masks(&bits),
                even: r % 2 == 0,
            });
        }
        let pubt = public_tables();
        Box::new(FbKey {
            rounds: rs,
            white: words_of(white),
            chord: field.chord,
            chord_inv: field.chord_inv,
            cross: field.cross,
            cross_inv: field.cross_inv,
            trip: field.trip,
            trip_inv: field.trip_inv,
            inv3: field.inv3,
            mulc_q: pubt.mulc_q,
            mulc_nib: pubt.mulc_nib,
            rotl_q: pubt.rotl_q,
            frob: pubt.frob,
        })
    }
}

// ------------------------------------------------------------ lane trait

pub(crate) trait Ops {
    type V: Copy;
    type Pre: Copy;
    unsafe fn splat(x: u64) -> Self::V;
    unsafe fn xor(a: Self::V, b: Self::V) -> Self::V;
    unsafe fn and(a: Self::V, b: Self::V) -> Self::V;
    unsafe fn or(a: Self::V, b: Self::V) -> Self::V;
    /// 64-bit lane shifts by a public count.
    unsafe fn shl(a: Self::V, s: u32) -> Self::V;
    unsafe fn shr(a: Self::V, s: u32) -> Self::V;
    unsafe fn add64(a: Self::V, b: Self::V) -> Self::V;
    unsafe fn sub64(a: Self::V, b: Self::V) -> Self::V;
    unsafe fn add8(a: Self::V, b: Self::V) -> Self::V;
    unsafe fn sub8(a: Self::V, b: Self::V) -> Self::V;
    /// 0xFF in each byte whose bit `b` is set.
    unsafe fn bitmask8(x: Self::V, b: u32) -> Self::V;
    unsafe fn affine(x: Self::V, a: &Aff) -> Self::V;
    unsafe fn pre(x: Self::V) -> Self::Pre;
    unsafe fn mulc(p: &Self::Pre, c: u8, k: &FbKey) -> Self::V;

    #[inline(always)]
    unsafe fn rotl8(x: Self::V, kk: u32, _k: &FbKey) -> Self::V {
        if kk == 0 {
            return x;
        }
        let hi = (0xFFu8 << kk) as u64 * L1;
        let lo = (0xFFu8 >> (8 - kk)) as u64 * L1;
        Self::or(
            Self::and(Self::shl(x, kk), Self::splat(hi)),
            Self::and(Self::shr(x, 8 - kk), Self::splat(lo)),
        )
    }
    #[inline(always)]
    unsafe fn xtime(a: Self::V) -> Self::V {
        Self::xor(
            Self::and(Self::shl(a, 1), Self::splat(0xFEFE_FEFE_FEFE_FEFE)),
            Self::and(Self::bitmask8(a, 7), Self::splat(0xF5F5_F5F5_F5F5_F5F5)),
        )
    }
    #[inline(always)]
    unsafe fn gfmul(a: Self::V, b: Self::V) -> Self::V {
        let mut a = a;
        let mut r = Self::and(a, Self::bitmask8(b, 0));
        for i in 1..8 {
            a = Self::xtime(a);
            r = Self::xor(r, Self::and(a, Self::bitmask8(b, i)));
        }
        r
    }
    /// Keyed S-box: post( t^254 ), t = pre(x), all in GF(2^8)/0x1F5.
    #[inline(always)]
    unsafe fn sbox(x: Self::V, sb: &SbData, k: &FbKey) -> Self::V {
        let t = Self::affine(x, &sb.pre);
        let x2 = Self::affine(t, &k.frob[0]);
        let x3 = Self::gfmul(x2, t);
        let x12 = Self::affine(x3, &k.frob[1]);
        let x14 = Self::gfmul(x12, x2);
        let x15 = Self::gfmul(x12, x3);
        let x240 = Self::affine(x15, &k.frob[2]);
        let x254 = Self::gfmul(x240, x14);
        Self::affine(x254, &sb.post)
    }
}

// ------------------------------------------------------------ generic kernel

#[inline(always)]
unsafe fn tr8<O: Ops>(w: &mut [O::V; 16], base: usize) {
    for &(s, m, d) in &[
        (8u32, 0x00FF_00FF_00FF_00FFu64, 1usize),
        (16, 0x0000_FFFF_0000_FFFF, 2),
        (32, 0x0000_0000_FFFF_FFFF, 4),
    ] {
        for i in 0..8 {
            if i & d == 0 {
                let a = w[base + i];
                let b = w[base + i + d];
                let t = O::and(O::xor(O::shr(a, s), b), O::splat(m));
                w[base + i + d] = O::xor(b, t);
                w[base + i] = O::xor(a, O::shl(t, s));
            }
        }
    }
}

#[inline(always)]
unsafe fn matvec<O: Ops, const N: usize>(m: &[[u8; N]; N], x: &mut [O::V], k: &FbKey) {
    let mut pre: [core::mem::MaybeUninit<O::Pre>; N] = [const { core::mem::MaybeUninit::uninit() }; N];
    for j in 0..N {
        pre[j].write(O::pre(x[j]));
    }
    for i in 0..N {
        let mut acc = O::mulc(pre[0].assume_init_ref(), m[i][0], k);
        for j in 1..N {
            acc = O::xor(acc, O::mulc(pre[j].assume_init_ref(), m[i][j], k));
        }
        x[i] = acc;
    }
}

#[inline(always)]
unsafe fn sbox_all<O: Ops>(w: &mut [O::V; 16], sb: &SbData, k: &FbKey) {
    for f in 0..16 {
        w[f] = O::sbox(w[f], sb, k);
    }
}

#[inline(always)]
unsafe fn chord<O: Ops>(w: &mut [O::V; 16], k: &FbKey, inv: bool) {
    let m = if inv { &k.chord_inv } else { &k.chord };
    for base in [0usize, 8] {
        if !inv {
            tr8::<O>(w, base);
            matvec::<O, 8>(m, &mut w[base..base + 8], k);
            tr8::<O>(w, base);
            matvec::<O, 8>(m, &mut w[base..base + 8], k);
        } else {
            matvec::<O, 8>(m, &mut w[base..base + 8], k);
            tr8::<O>(w, base);
            matvec::<O, 8>(m, &mut w[base..base + 8], k);
            tr8::<O>(w, base);
        }
    }
}

#[inline(always)]
unsafe fn benes_stage<O: Ops>(h: &mut [O::V], mk: &[u64; 8], m: usize) {
    if m >= 8 {
        let d = m / 8;
        let mut p = 0;
        for w in 0..8 {
            if w & d == 0 {
                let a = h[w];
                let b = h[w + d];
                let t = O::and(O::xor(a, b), O::splat(mk[p]));
                h[w] = O::xor(a, t);
                h[w + d] = O::xor(b, t);
                p += 1;
            }
        }
    } else {
        let s = 8 * m as u32;
        for w in 0..8 {
            let x = h[w];
            let t = O::and(O::xor(O::shr(x, s), x), O::splat(mk[w]));
            h[w] = O::xor(x, O::xor(t, O::shl(t, s)));
        }
    }
}

#[inline(always)]
unsafe fn bridges<O: Ops>(w: &mut [O::V; 16], rk: &FbRound, k: &FbKey, inv: bool) {
    let (lo, hi) = w.split_at_mut(8);
    for st in 0..11 {
        benes_stage::<O>(hi, &rk.benes[st], BENES_STRIDES[st]);
    }
    for i in 0..8 {
        let (a, b) = if rk.even { (lo[i], hi[i]) } else { (hi[i], lo[i]) };
        let (x, y) = if !inv {
            (O::xor(a, b), O::xor(a, O::xtime(b)))
        } else {
            let v = O::mulc(&O::pre(O::xor(a, b)), k.inv3, k);
            (O::xor(a, v), v)
        };
        if rk.even {
            lo[i] = x;
            hi[i] = y;
        } else {
            hi[i] = x;
            lo[i] = y;
        }
    }
    for st in (0..11).rev() {
        benes_stage::<O>(hi, &rk.benes[st], BENES_STRIDES[st]);
    }
}

#[inline(always)]
unsafe fn triplets<O: Ops>(w: &mut [O::V; 16], k: &FbKey, inv: bool) {
    for base in [0usize, 8] {
        for s in 0..6 {
            let t = if inv { 5 - s } else { s };
            let m = if inv { &k.trip_inv[t] } else { &k.trip[t] };
            matvec::<O, 3>(m, &mut w[base + t..base + t + 3], k);
        }
    }
}

// fix1 (format 0x1B): 8-stroke bow, full diffusion in both directions (OHLO's choice over the
// 10-stroke sawtooth, kept in lab/sawtooth10).
const BOW_STROKES: [(usize, usize, usize); 8] =
    [(2, 3, 4), (5, 7, 1), (0, 7, 3), (4, 7, 6), (1, 6, 0), (1, 7, 2), (2, 5, 4), (0, 3, 1)];
const BOW_PRESSURE_ROT: [u32; 8] = [0; 8];

/// p mod 7 for every byte (p in 0..=255), branch-free.
#[inline(always)]
unsafe fn mod7<O: Ops>(p: O::V) -> O::V {
    let m7 = O::splat(0x0707_0707_0707_0707);
    let m3 = O::splat(0x0303_0303_0303_0303);
    let one = O::splat(L1);
    let s = O::add64(
        O::add64(O::and(p, m7), O::and(O::shr(p, 3), m7)),
        O::and(O::shr(p, 6), m3),
    );
    let s = O::add64(O::and(s, m7), O::and(O::shr(s, 3), m3));
    let ge = O::and(O::shr(O::add64(s, one), 3), one);
    O::sub64(s, O::sub64(O::shl(ge, 3), ge))
}

/// Rotate each byte of x left by the matching byte of r (r in 1..=7).
#[inline(always)]
unsafe fn rotv<O: Ops>(x: O::V, r: O::V, k: &FbKey) -> O::V {
    let mut x = x;
    for b in 0..3u32 {
        let m = O::bitmask8(r, b);
        let y = O::rotl8(x, 1 << b, k);
        x = O::xor(x, O::and(O::xor(x, y), m));
    }
    x
}

#[inline(always)]
unsafe fn bow<O: Ops>(w: &mut [O::V; 16], k: &FbKey, inv: bool) {
    let one = O::splat(L1);
    let m1f = O::splat(0x1F1F_1F1F_1F1F_1F1F);
    for base in [0usize, 8] {
        for s in 0..BOW_STROKES.len() {
            let si = if inv { BOW_STROKES.len() - 1 - s } else { s };
            let (i, j, p) = BOW_STROKES[si];
            let pp = O::rotl8(w[base + p], BOW_PRESSURE_ROT[si], k);
            let r1 = O::add64(mod7::<O>(pp), one);
            let r2 = O::add64(mod7::<O>(O::and(O::shr(pp, 3), m1f)), one);
            if !inv {
                let u = O::add8(w[base + i], rotv::<O>(w[base + j], r1, k));
                let v = O::xor(w[base + j], rotv::<O>(u, r2, k));
                w[base + i] = u;
                w[base + j] = v;
            } else {
                let u = w[base + i];
                let v = O::xor(w[base + j], rotv::<O>(u, r2, k));
                let u = O::sub8(u, rotv::<O>(v, r1, k));
                w[base + i] = u;
                w[base + j] = v;
            }
        }
    }
}

#[inline(always)]
unsafe fn add_key<O: Ops>(w: &mut [O::V; 16], rk: &[u64; 16]) {
    for f in 0..16 {
        w[f] = O::xor(w[f], O::splat(rk[f]));
    }
}

#[inline(always)]
pub(crate) unsafe fn encrypt_rows<O: Ops>(w: &mut [O::V; 16], k: &FbKey) {
    for r in 0..NR {
        let rk = &k.rounds[r];
        add_key::<O>(w, &rk.rk);
        sbox_all::<O>(w, &rk.s, k);
        chord::<O>(w, k, false);
        bridges::<O>(w, rk, k, false);
        tr8::<O>(w, 0);
        tr8::<O>(w, 8);
        triplets::<O>(w, k, false);
        bow::<O>(w, k, false);
        sbox_all::<O>(w, &rk.sm, k);
        tr8::<O>(w, 0);
        tr8::<O>(w, 8);
        matvec::<O, 16>(&k.cross, &mut w[..], k);
        sbox_all::<O>(w, &rk.s2, k);
    }
    add_key::<O>(w, &k.white);
}

#[inline(always)]
pub(crate) unsafe fn decrypt_rows<O: Ops>(w: &mut [O::V; 16], k: &FbKey) {
    add_key::<O>(w, &k.white);
    for r in (0..NR).rev() {
        let rk = &k.rounds[r];
        sbox_all::<O>(w, &rk.si2, k);
        matvec::<O, 16>(&k.cross_inv, &mut w[..], k);
        tr8::<O>(w, 0);
        tr8::<O>(w, 8);
        sbox_all::<O>(w, &rk.sim, k);
        bow::<O>(w, k, true);
        triplets::<O>(w, k, true);
        tr8::<O>(w, 0);
        tr8::<O>(w, 8);
        bridges::<O>(w, rk, k, true);
        chord::<O>(w, k, true);
        sbox_all::<O>(w, &rk.si, k);
        add_key::<O>(w, &rk.rk);
    }
}

// ------------------------------------------------------------ portable SWAR

pub(crate) struct Swar64;

impl Ops for Swar64 {
    type V = u64;
    type Pre = [u64; 8];
    #[inline(always)]
    unsafe fn splat(x: u64) -> u64 {
        x
    }
    #[inline(always)]
    unsafe fn xor(a: u64, b: u64) -> u64 {
        a ^ b
    }
    #[inline(always)]
    unsafe fn and(a: u64, b: u64) -> u64 {
        a & b
    }
    #[inline(always)]
    unsafe fn or(a: u64, b: u64) -> u64 {
        a | b
    }
    #[inline(always)]
    unsafe fn shl(a: u64, s: u32) -> u64 {
        a << s
    }
    #[inline(always)]
    unsafe fn shr(a: u64, s: u32) -> u64 {
        a >> s
    }
    #[inline(always)]
    unsafe fn add64(a: u64, b: u64) -> u64 {
        a.wrapping_add(b)
    }
    #[inline(always)]
    unsafe fn sub64(a: u64, b: u64) -> u64 {
        a.wrapping_sub(b)
    }
    #[inline(always)]
    unsafe fn add8(a: u64, b: u64) -> u64 {
        const H: u64 = 0x8080_8080_8080_8080;
        ((a & !H).wrapping_add(b & !H)) ^ ((a ^ b) & H)
    }
    #[inline(always)]
    unsafe fn sub8(a: u64, b: u64) -> u64 {
        const H: u64 = 0x8080_8080_8080_8080;
        ((a | H).wrapping_sub(b & !H)) ^ ((a ^ !b) & H)
    }
    #[inline(always)]
    unsafe fn bitmask8(x: u64, b: u32) -> u64 {
        let t = (x >> b) & L1;
        (t << 8).wrapping_sub(t)
    }
    #[inline(always)]
    unsafe fn affine(x: u64, a: &Aff) -> u64 {
        let mut r = (a.c as u64).wrapping_mul(L1);
        for j in 0..8 {
            r ^= (a.cols[j] as u64).wrapping_mul(L1) & Self::bitmask8(x, j as u32);
        }
        r
    }
    #[inline(always)]
    unsafe fn pre(x: u64) -> [u64; 8] {
        let mut p = [x; 8];
        for i in 1..8 {
            p[i] = Self::xtime(p[i - 1]);
        }
        p
    }
    #[inline(always)]
    unsafe fn mulc(p: &[u64; 8], c: u8, _k: &FbKey) -> u64 {
        // c is a public constant: branch-free select anyway.
        let mut r = 0u64;
        for i in 0..8 {
            r ^= p[i] & 0u64.wrapping_sub(((c >> i) & 1) as u64);
        }
        r
    }
}

pub(crate) fn swar_encrypt(k: &FbKey, b: &mut [u8; BLOCK_LEN]) {
    let mut w = words_of(b);
    unsafe { encrypt_rows::<Swar64>(&mut w, k) };
    for f in 0..16 {
        b[8 * f..8 * f + 8].copy_from_slice(&w[f].to_le_bytes());
    }
}

pub(crate) fn swar_decrypt(k: &FbKey, b: &mut [u8; BLOCK_LEN]) {
    let mut w = words_of(b);
    unsafe { decrypt_rows::<Swar64>(&mut w, k) };
    for f in 0..16 {
        b[8 * f..8 * f + 8].copy_from_slice(&w[f].to_le_bytes());
    }
}

// ------------------------------------------------------------ AVX2 lanes

#[cfg(target_arch = "x86_64")]
pub(crate) mod avx2 {
    use super::*;
    use core::arch::x86_64::*;

    macro_rules! common_ops {
        () => {
            type V = __m256i;
            #[inline(always)]
            unsafe fn splat(x: u64) -> __m256i {
                _mm256_set1_epi64x(x as i64)
            }
            #[inline(always)]
            unsafe fn xor(a: __m256i, b: __m256i) -> __m256i {
                _mm256_xor_si256(a, b)
            }
            #[inline(always)]
            unsafe fn and(a: __m256i, b: __m256i) -> __m256i {
                _mm256_and_si256(a, b)
            }
            #[inline(always)]
            unsafe fn or(a: __m256i, b: __m256i) -> __m256i {
                _mm256_or_si256(a, b)
            }
            #[inline(always)]
            unsafe fn shl(a: __m256i, s: u32) -> __m256i {
                _mm256_sll_epi64(a, _mm_cvtsi32_si128(s as i32))
            }
            #[inline(always)]
            unsafe fn shr(a: __m256i, s: u32) -> __m256i {
                _mm256_srl_epi64(a, _mm_cvtsi32_si128(s as i32))
            }
            #[inline(always)]
            unsafe fn add64(a: __m256i, b: __m256i) -> __m256i {
                _mm256_add_epi64(a, b)
            }
            #[inline(always)]
            unsafe fn sub64(a: __m256i, b: __m256i) -> __m256i {
                _mm256_sub_epi64(a, b)
            }
            #[inline(always)]
            unsafe fn add8(a: __m256i, b: __m256i) -> __m256i {
                _mm256_add_epi8(a, b)
            }
            #[inline(always)]
            unsafe fn sub8(a: __m256i, b: __m256i) -> __m256i {
                _mm256_sub_epi8(a, b)
            }
            #[inline(always)]
            unsafe fn bitmask8(x: __m256i, b: u32) -> __m256i {
                let y = _mm256_sll_epi16(x, _mm_cvtsi32_si128((7 - b) as i32));
                _mm256_cmpgt_epi8(_mm256_setzero_si256(), y)
            }
            #[inline(always)]
            unsafe fn xtime(a: __m256i) -> __m256i {
                let a2 = _mm256_add_epi8(a, a);
                let m = _mm256_cmpgt_epi8(_mm256_setzero_si256(), a);
                _mm256_xor_si256(a2, _mm256_and_si256(m, _mm256_set1_epi8(0xF5u8 as i8)))
            }
        };
    }

    #[inline(always)]
    unsafe fn nib_tab(t: &[u8; 32]) -> (__m256i, __m256i) {
        (
            _mm256_broadcastsi128_si256(_mm_loadu_si128(t.as_ptr() as *const __m128i)),
            _mm256_broadcastsi128_si256(_mm_loadu_si128(t.as_ptr().add(16) as *const __m128i)),
        )
    }
    #[inline(always)]
    unsafe fn nibs(x: __m256i) -> (__m256i, __m256i) {
        let m = _mm256_set1_epi8(0x0F);
        (_mm256_and_si256(x, m), _mm256_and_si256(_mm256_srli_epi16::<4>(x), m))
    }
    #[inline(always)]
    unsafe fn nib_apply(p: &(__m256i, __m256i), t: &[u8; 32]) -> __m256i {
        let (tl, th) = nib_tab(t);
        _mm256_xor_si256(_mm256_shuffle_epi8(tl, p.0), _mm256_shuffle_epi8(th, p.1))
    }

    /// AVX2 without GFNI.
    pub(crate) struct Avx2Soft;
    impl Ops for Avx2Soft {
        type Pre = (__m256i, __m256i);
        common_ops!();
        #[inline(always)]
        unsafe fn affine(x: __m256i, a: &Aff) -> __m256i {
            nib_apply(&nibs(x), &a.nib)
        }
        #[inline(always)]
        unsafe fn pre(x: __m256i) -> (__m256i, __m256i) {
            nibs(x)
        }
        #[inline(always)]
        unsafe fn mulc(p: &(__m256i, __m256i), c: u8, k: &FbKey) -> __m256i {
            nib_apply(p, &k.mulc_nib[c as usize])
        }
    }

    /// AVX2 + GFNI (VEX-256).
    pub(crate) struct Avx2Gfni;
    impl Ops for Avx2Gfni {
        type Pre = __m256i;
        common_ops!();
        #[inline(always)]
        unsafe fn affine(x: __m256i, a: &Aff) -> __m256i {
            nib_apply(&nibs(x), &a.nib)
        }
        #[inline(always)]
        unsafe fn pre(x: __m256i) -> __m256i {
            x
        }
        #[inline(always)]
        unsafe fn mulc(p: &__m256i, c: u8, k: &FbKey) -> __m256i {
            _mm256_gf2p8affine_epi64_epi8::<0>(*p, _mm256_set1_epi64x(k.mulc_q[c as usize] as i64))
        }
        #[inline(always)]
        unsafe fn rotl8(x: __m256i, kk: u32, k: &FbKey) -> __m256i {
            if kk == 0 {
                return x;
            }
            _mm256_gf2p8affine_epi64_epi8::<0>(x, _mm256_set1_epi64x(k.rotl_q[kk as usize] as i64))
        }
        #[inline(always)]
        unsafe fn sbox(x: __m256i, sb: &SbData, _k: &FbKey) -> __m256i {
            let y = _mm256_xor_si256(
                _mm256_gf2p8affine_epi64_epi8::<0>(x, _mm256_set1_epi64x(sb.q_pre as i64)),
                _mm256_set1_epi8(sb.q_pre_c as i8),
            );
            _mm256_xor_si256(
                _mm256_gf2p8affineinv_epi64_epi8::<0>(y, _mm256_set1_epi64x(sb.q_post as i64)),
                _mm256_set1_epi8(sb.q_post_c as i8),
            )
        }
    }

    #[inline(always)]
    unsafe fn load4(blocks: &[[u8; BLOCK_LEN]]) -> [__m256i; 16] {
        let n = blocks.len();
        debug_assert!(n >= 1 && n <= 4);
        let mut ws = [[0u64; 16]; 4];
        for b in 0..n {
            ws[b] = words_of(&blocks[b]);
        }
        core::array::from_fn(|f| {
            _mm256_set_epi64x(ws[3][f] as i64, ws[2][f] as i64, ws[1][f] as i64, ws[0][f] as i64)
        })
    }
    #[inline(always)]
    unsafe fn store4(blocks: &mut [[u8; BLOCK_LEN]], w: &[__m256i; 16]) {
        let n = blocks.len();
        for f in 0..16 {
            let mut lanes = [0u64; 4];
            _mm256_storeu_si256(lanes.as_mut_ptr() as *mut __m256i, w[f]);
            for b in 0..n {
                blocks[b][8 * f..8 * f + 8].copy_from_slice(&lanes[b].to_le_bytes());
            }
        }
    }

    #[target_feature(enable = "avx2")]
    pub(crate) unsafe fn soft_blocks(k: &FbKey, blocks: &mut [[u8; BLOCK_LEN]], enc: bool) {
        for g in blocks.chunks_mut(4) {
            let mut w = load4(g);
            if enc {
                encrypt_rows::<Avx2Soft>(&mut w, k);
            } else {
                decrypt_rows::<Avx2Soft>(&mut w, k);
            }
            store4(g, &w);
        }
    }

    #[target_feature(enable = "avx2,gfni,avx")]
    pub(crate) unsafe fn gfni_blocks(k: &FbKey, blocks: &mut [[u8; BLOCK_LEN]], enc: bool) {
        for g in blocks.chunks_mut(4) {
            let mut w = load4(g);
            if enc {
                encrypt_rows::<Avx2Gfni>(&mut w, k);
            } else {
                decrypt_rows::<Avx2Gfni>(&mut w, k);
            }
            store4(g, &w);
        }
    }
}
