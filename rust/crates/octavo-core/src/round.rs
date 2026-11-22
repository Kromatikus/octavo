//! Round layers on the 16 faces x 8 beats grid; cell (f, t) is byte 8*f + t.
//! Layer order and inverses mirror sneak_n2.round_enc / round_dec exactly.
//!
//! Data-path constant-time notes: all field multiplies are by public constants (branch-free
//! xtime), triplets are integer mod-256 multiplies, the bow uses data-dependent ROTATIONS
//! (`rotate_left`, a single constant-time instruction on x86-64/AArch64), and S-boxes go through
//! the backend. The weave / butterfly / bridge index patterns are KEY-dependent (per message)
//! but data-independent; they permute a 128-byte state that spans two cache lines.

use crate::backend::SboxBackend;
#[cfg(test)]
use crate::gf::mul;
use crate::gf::{xtime, INV3};
use crate::schedule::{RoundKey, Schedule};
use crate::{BLOCK_LEN, NB, NF};

type State = [u8; BLOCK_LEN];

#[inline(always)]
fn idx(f: usize, t: usize) -> usize {
    8 * f + t
}

// ---- two-cell field mix (1 1; 1 2) over 0x1F5 ----
#[inline(always)]
fn mix2(u: u8, v: u8) -> (u8, u8) {
    (u ^ v, u ^ xtime(v))
}
#[inline(always)]
#[cfg_attr(not(test), allow(dead_code))] // scalar reference for mix2_rows
fn mix2_inv(a: u8, b: u8) -> (u8, u8) {
    let v = mulc(&INV3_COLS, a ^ b);
    (a ^ v, v)
}

/// Multiplication by a public constant c is GF(2)-linear: columns c·x^j, applied with masks.
const fn mulc_cols(c: u8) -> [u8; 8] {
    let mut cols = [0u8; 8];
    let mut j = 0;
    while j < 8 {
        cols[j] = crate::gf::const_mul(c, 1 << j);
        j += 1;
    }
    cols
}
#[inline(always)]
fn mulc(cols: &[u8; 8], x: u8) -> u8 {
    let mut r = 0u8;
    let mut j = 0;
    while j < 8 {
        r ^= cols[j] & crate::gf::mask(x >> j);
        j += 1;
    }
    r
}
const INV3_COLS: [u8; 8] = mulc_cols(INV3);

// ---- 8 cells at once (SWAR in a u64): same maps, no branches or lookups ----
const LO: u64 = 0x0101_0101_0101_0101;
#[inline(always)]
fn xtime64(y: u64) -> u64 {
    ((y & (0x7f * LO)) << 1) ^ (((y >> 7) & LO) * 0xF5)
}
#[inline(always)]
fn mulc64(cols: &[u8; 8], x: u64) -> u64 {
    let mut r = 0u64;
    let mut j = 0;
    while j < 8 {
        r ^= (((x >> j) & LO) * 0xff) & (cols[j] as u64 * LO);
        j += 1;
    }
    r
}
#[inline(always)]
fn ld(b: &[u8]) -> u64 {
    u64::from_le_bytes(b[..8].try_into().unwrap())
}
#[inline(always)]
fn st(b: &mut [u8], v: u64) {
    b[..8].copy_from_slice(&v.to_le_bytes());
}
/// (u, v) <- mix2 or mix2_inv on equal-length slices (length a multiple of 8), 8 pairs per step.
#[inline(always)]
fn mix2_rows(u: &mut [u8], v: &mut [u8], inv: bool) {
    for (a, b) in u.chunks_exact_mut(8).zip(v.chunks_exact_mut(8)) {
        let (x, y) = (ld(a), ld(b));
        if inv {
            let w = mulc64(&INV3_COLS, x ^ y);
            st(a, x ^ w);
            st(b, w);
        } else {
            st(a, x ^ y);
            st(b, x ^ xtime64(y));
        }
    }
}
const fn bars_cols(m: [[[u8; 2]; 2]; 7]) -> [[[[u8; 8]; 2]; 2]; 7] {
    let mut o = [[[[0u8; 8]; 2]; 2]; 7];
    let mut k = 0;
    while k < 7 {
        let mut i = 0;
        while i < 2 {
            let mut j = 0;
            while j < 2 {
                o[k][i][j] = mulc_cols(m[k][i][j]);
                j += 1;
            }
            i += 1;
        }
        k += 1;
    }
    o
}

const BARS: [[[u8; 2]; 2]; 7] = [
    [[0, 0], [0, 0]],
    [[1, 1], [1, 2]],
    [[3, 5], [1, 2]],
    [[1, 3], [1, 4]],
    [[5, 2], [2, 1]],
    [[2, 1], [1, 1]],
    [[3, 1], [2, 1]],
];
const BARS_INV: [[[u8; 2]; 2]; 7] = [
    [[0, 0], [0, 0]],
    [[173, 172], [172, 172]],
    [[173, 3], [172, 1]],
    [[75, 74], [149, 149]],
    [[1, 2], [2, 5]],
    [[172, 172], [172, 173]],
    [[1, 1], [2, 3]],
];
const BARS_C: [[[[u8; 8]; 2]; 2]; 7] = bars_cols(BARS);
const BARS_INV_C: [[[[u8; 8]; 2]; 2]; 7] = bars_cols(BARS_INV);
#[inline(always)]
fn bar_apply_c(m: &[[[u8; 8]; 2]; 2], u: u8, v: u8) -> (u8, u8) {
    (mulc(&m[0][0], u) ^ mulc(&m[0][1], v), mulc(&m[1][0], u) ^ mulc(&m[1][1], v))
}
#[cfg(test)]
fn bar_apply(m: &[[u8; 2]; 2], u: u8, v: u8) -> (u8, u8) {
    (mul(m[0][0], u) ^ mul(m[0][1], v), mul(m[1][0], u) ^ mul(m[1][1], v))
}

const TRIPLETS: [[[u8; 3]; 3]; 6] = [
    [[5, 1, 1], [2, 3, 1], [5, 5, 2]],
    [[1, 3, 1], [3, 5, 2], [3, 2, 1]],
    [[2, 1, 1], [1, 3, 1], [3, 3, 2]],
    [[3, 3, 1], [2, 5, 3], [1, 3, 2]],
    [[1, 1, 1], [1, 3, 2], [3, 2, 3]],
    [[2, 1, 3], [3, 1, 3], [1, 2, 5]],
];
const TRIPLETS_INV: [[[u8; 3]; 3]; 6] = [
    [[1, 3, 254], [1, 5, 253], [251, 236, 13]],
    [[1, 255, 1], [3, 254, 1], [247, 7, 252]],
    [[3, 1, 254], [1, 1, 255], [250, 253, 5]],
    [[1, 253, 4], [255, 5, 249], [1, 250, 9]],
    [[5, 255, 255], [3, 0, 255], [249, 1, 2]],
    [[255, 1, 0], [244, 7, 3], [5, 253, 255]],
];

const BOW_STROKES: [(usize, usize, usize); 7] =
    [(0, 1, 2), (2, 3, 4), (4, 5, 0), (6, 7, 0), (1, 2, 3), (3, 4, 5), (5, 6, 0)];
const BOW_ROT: [u32; 7] = [0, 0, 0, 3, 0, 0, 5];

const CROSS0: [(usize, usize); 8] = [(0, 4), (1, 5), (2, 6), (3, 7), (8, 12), (9, 13), (10, 14), (11, 15)];
const CROSS1: [(usize, usize); 8] = [(0, 8), (1, 9), (2, 10), (3, 11), (4, 12), (5, 13), (6, 14), (7, 15)];
const CROSS2: [(usize, usize); 8] = [(0, 1), (2, 3), (4, 5), (6, 7), (8, 9), (10, 11), (12, 13), (14, 15)];
const CROSS3: [(usize, usize); 4] = [(1, 2), (5, 6), (9, 10), (13, 14)];

// ---- layers ----
fn xor_key(g: &mut State, k: &[u8; BLOCK_LEN]) {
    for i in 0..BLOCK_LEN {
        g[i] ^= k[i];
    }
}

fn sub<B: SboxBackend>(g: &mut State, b: &B, rk: &RoundKey, r: usize, second: bool) {
    b.s_batch(rk, r, second, g);
}
fn unsub<B: SboxBackend>(g: &mut State, b: &B, rk: &RoundKey, r: usize, second: bool) {
    b.si_batch(rk, r, second, g);
}

fn weave(g: &mut State, sh: &[u8; NF], sv: &[u8; NB]) {
    let mut h = [0u8; BLOCK_LEN];
    for f in 0..NF {
        let s = sh[f] as usize;
        for t in 0..NB {
            h[idx(f, t)] = g[idx(f, (t + s) % 8)];
        }
    }
    for t in 0..NB {
        let s = sv[t] as usize;
        for f in 0..NF {
            g[idx(f, t)] = h[idx((f + 16 - s) % 16, t)];
        }
    }
}
fn unweave(g: &mut State, sh: &[u8; NF], sv: &[u8; NB]) {
    let mut h = [0u8; BLOCK_LEN];
    for t in 0..NB {
        let s = sv[t] as usize;
        for f in 0..NF {
            h[idx((f + 16 - s) % 16, t)] = g[idx(f, t)];
        }
    }
    for f in 0..NF {
        let s = sh[f] as usize;
        for t in 0..NB {
            g[idx(f, (t + s) % 8)] = h[idx(f, t)];
        }
    }
}

fn butterfly(g: &mut State, sigma: &[[u8; NB]; NF]) {
    for f in 0..NF {
        let s = &sigma[f];
        for m in [1usize, 2, 4] {
            for i in 0..8 {
                if i & m == 0 {
                    let (a, b) = (idx(f, s[i] as usize), idx(f, s[i | m] as usize));
                    (g[a], g[b]) = mix2(g[a], g[b]);
                }
            }
        }
    }
}
fn unbutterfly(g: &mut State, sigma: &[[u8; NB]; NF]) {
    // faces are independent and the 4 pairs of one stage are disjoint, so each stage is gathered
    // over all 16 faces (64 pairs) and inverted 8 at a time
    for m in [4usize, 2, 1] {
        let (mut ia, mut ib) = ([0usize; 64], [0usize; 64]);
        let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
        let mut q = 0;
        for f in 0..NF {
            let s = &sigma[f];
            for i in 0..8 {
                if i & m == 0 {
                    ia[q] = idx(f, s[i] as usize);
                    ib[q] = idx(f, s[i | m] as usize);
                    q += 1;
                }
            }
        }
        for q in 0..64 {
            a[q] = g[ia[q]];
            b[q] = g[ib[q]];
        }
        mix2_rows(&mut a, &mut b, true);
        for q in 0..64 {
            g[ia[q]] = a[q];
            g[ib[q]] = b[q];
        }
    }
}

fn bridges(g: &mut State, br: &[u8; 64], r: usize, inv: bool) {
    // inner cells 0..64 are contiguous; outer partners 64 + br[c] are gathered
    let mut inner = [0u8; 64];
    let mut outer = [0u8; 64];
    inner.copy_from_slice(&g[..64]);
    for c in 0..64 {
        outer[c] = g[64 + br[c] as usize];
    }
    if r % 2 == 0 {
        mix2_rows(&mut inner, &mut outer, inv);
    } else {
        mix2_rows(&mut outer, &mut inner, inv);
    }
    g[..64].copy_from_slice(&inner);
    for c in 0..64 {
        g[64 + br[c] as usize] = outer[c];
    }
}

fn bar_mix<B: SboxBackend>(g: &mut State, b: &B, rk: &RoundKey, r: usize) {
    // latin pair on beats (0,1) of every face, batched (faces are independent)
    let mut x = [0u8; NF];
    let mut y = [0u8; NF];
    for f in 0..NF {
        let (u, v) = (g[idx(f, 0)], g[idx(f, 1)]);
        x[f] = u ^ v;
        y[f] = u ^ xtime(v);
    }
    b.s_batch(rk, r, false, &mut x);
    b.s_batch(rk, r, true, &mut y);
    for f in 0..NF {
        let row = &mut g[8 * f..8 * f + 8];
        row[0] = x[f];
        row[1] = y[f];
        for k in 1..7 {
            (row[k], row[k + 1]) = bar_apply_c(&BARS_C[k], row[k], row[k + 1]);
        }
    }
}
fn bar_unmix<B: SboxBackend>(g: &mut State, b: &B, rk: &RoundKey, r: usize) {
    let mut x = [0u8; NF];
    let mut y = [0u8; NF];
    for f in 0..NF {
        let row = &mut g[8 * f..8 * f + 8];
        for k in (1..7).rev() {
            (row[k], row[k + 1]) = bar_apply_c(&BARS_INV_C[k], row[k], row[k + 1]);
        }
        x[f] = row[0];
        y[f] = row[1];
    }
    b.si_batch(rk, r, false, &mut x);
    b.si_batch(rk, r, true, &mut y);
    mix2_rows(&mut x, &mut y, true);
    for f in 0..NF {
        g[idx(f, 0)] = x[f];
        g[idx(f, 1)] = y[f];
    }
}

#[inline(always)]
fn trip_apply(m: &[[u8; 3]; 3], row: &mut [u8]) {
    let x = [row[0], row[1], row[2]];
    for i in 0..3 {
        row[i] = m[i][0]
            .wrapping_mul(x[0])
            .wrapping_add(m[i][1].wrapping_mul(x[1]))
            .wrapping_add(m[i][2].wrapping_mul(x[2]));
    }
}
fn trip(g: &mut State) {
    for f in 0..NF {
        let row = &mut g[8 * f..8 * f + 8];
        for k in 0..6 {
            trip_apply(&TRIPLETS[k], &mut row[k..k + 3]);
        }
    }
}
fn untrip(g: &mut State) {
    for f in 0..NF {
        let row = &mut g[8 * f..8 * f + 8];
        for k in (0..6).rev() {
            trip_apply(&TRIPLETS_INV[k], &mut row[k..k + 3]);
        }
    }
}

#[inline(always)]
fn bow_amounts(p: u8, k: usize) -> (u32, u32) {
    let view = p.rotate_left(BOW_ROT[k]);
    (1 + (view % 7) as u32, 1 + ((view >> 3) % 7) as u32)
}
fn bow(g: &mut State) {
    for f in 0..NF {
        let row = &mut g[8 * f..8 * f + 8];
        for k in 0..7 {
            let (i, j, p) = BOW_STROKES[k];
            let (r1, r2) = bow_amounts(row[p], k);
            let u = row[i].wrapping_add(row[j].rotate_left(r1));
            let v = row[j] ^ u.rotate_left(r2);
            row[i] = u;
            row[j] = v;
        }
    }
}
fn unbow(g: &mut State) {
    for f in 0..NF {
        let row = &mut g[8 * f..8 * f + 8];
        for k in (0..7).rev() {
            let (i, j, p) = BOW_STROKES[k];
            let (r1, r2) = bow_amounts(row[p], k);
            let v = row[j] ^ row[i].rotate_left(r2);
            let u = row[i].wrapping_sub(v.rotate_left(r1));
            row[i] = u;
            row[j] = v;
        }
    }
}

// odd-beat restack: latin pairs on beats (0,1),(2,3),(4,5),(6,7) of every face — 64 disjoint
// pairs, so all 64 S lookups and all 64 S2 lookups are batched.
fn odd<B: SboxBackend>(g: &mut State, b: &B, rk: &RoundKey, r: usize) {
    let mut x = [0u8; 64];
    let mut y = [0u8; 64];
    for p in 0..64 {
        let (u, v) = (g[2 * p], g[2 * p + 1]);
        x[p] = u ^ v;
        y[p] = u ^ xtime(v);
    }
    b.s_batch(rk, r, false, &mut x);
    b.s_batch(rk, r, true, &mut y);
    for p in 0..64 {
        g[2 * p] = x[p];
        g[2 * p + 1] = y[p];
    }
}
fn unodd<B: SboxBackend>(g: &mut State, b: &B, rk: &RoundKey, r: usize) {
    let mut x = [0u8; 64];
    let mut y = [0u8; 64];
    for p in 0..64 {
        x[p] = g[2 * p];
        y[p] = g[2 * p + 1];
    }
    b.si_batch(rk, r, false, &mut x);
    b.si_batch(rk, r, true, &mut y);
    mix2_rows(&mut x, &mut y, true);
    for p in 0..64 {
        g[2 * p] = x[p];
        g[2 * p + 1] = y[p];
    }
}

fn cross_layer(g: &mut State, pairs: &[(usize, usize)], inv: bool) {
    // a face's 8 beats are contiguous: one u64 per face
    for &(a, b) in pairs {
        debug_assert!(a < b);
        let (lo, hi) = g.split_at_mut(8 * b);
        mix2_rows(&mut lo[8 * a..8 * a + 8], &mut hi[..8], inv);
    }
}
fn cross(g: &mut State) {
    cross_layer(g, &CROSS0, false);
    cross_layer(g, &CROSS1, false);
    cross_layer(g, &CROSS2, false);
    cross_layer(g, &CROSS3, false);
}
fn uncross(g: &mut State) {
    cross_layer(g, &CROSS3, true);
    cross_layer(g, &CROSS2, true);
    cross_layer(g, &CROSS1, true);
    cross_layer(g, &CROSS0, true);
}

pub fn round_enc<B: SboxBackend>(g: &mut State, b: &B, rk: &RoundKey, r: usize) {
    xor_key(g, &rk.rk); // 1. add round key
    sub(g, b, rk, r, false); // 2. keyed S
    weave(g, &rk.sh, &rk.sv); // 3. face-beat weave
    butterfly(g, &rk.sigma); // 4. staff butterfly
    bridges(g, &rk.bridge, r, false); // 5. shell bridges
    for enc in 0..2 {
        if enc == 1 {
            sub(g, b, rk, r, true); // 8. late second coloring
        }
        bar_mix(g, b, rk, r);
        trip(g);
        bow(g);
        odd(g, b, rk, r);
        cross(g);
    }
}

pub fn round_dec<B: SboxBackend>(g: &mut State, b: &B, rk: &RoundKey, r: usize) {
    for enc in [1, 0] {
        uncross(g);
        unodd(g, b, rk, r);
        unbow(g);
        untrip(g);
        bar_unmix(g, b, rk, r);
        if enc == 1 {
            unsub(g, b, rk, r, true);
        }
    }
    bridges(g, &rk.bridge, r, true);
    unbutterfly(g, &rk.sigma);
    unweave(g, &rk.sh, &rk.sv);
    unsub(g, b, rk, r, false);
    xor_key(g, &rk.rk);
}

pub fn encrypt_block<B: SboxBackend>(sch: &Schedule, b: &B, block: &mut State, rounds: usize) {
    for r in 0..rounds {
        round_enc(block, b, &sch.rounds[r], r);
    }
    xor_key(block, &sch.white);
}

pub fn decrypt_block<B: SboxBackend>(sch: &Schedule, b: &B, block: &mut State, rounds: usize) {
    xor_key(block, &sch.white);
    for r in (0..rounds).rev() {
        round_dec(block, b, &sch.rounds[r], r);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn swar_mixes_match_scalar() {
        let mut x = 0x243f_6a88_85a3_08d3u64;
        for _ in 0..2000 {
            let mut u = [0u8; 16];
            let mut v = [0u8; 16];
            for k in 0..16 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                u[k] = x as u8;
                v[k] = (x >> 8) as u8;
            }
            for inv in [false, true] {
                let (mut a, mut b) = (u, v);
                mix2_rows(&mut a, &mut b, inv);
                for k in 0..16 {
                    let want = if inv { mix2_inv(u[k], v[k]) } else { mix2(u[k], v[k]) };
                    assert_eq!((a[k], b[k]), want);
                }
            }
        }
    }
    #[test]
    fn const_inverses() {
        for k in 1..7 {
            for u in [0u8, 1, 7, 200, 255] {
                for v in [0u8, 3, 99, 254] {
                    let (a, b) = bar_apply(&BARS[k], u, v);
                    assert_eq!(bar_apply(&BARS_INV[k], a, b), (u, v));
                }
            }
        }
        for k in 1..7 {
            for u in [0u8, 9, 255] {
                for v in [1u8, 77] {
                    assert_eq!(bar_apply_c(&BARS_C[k], u, v), bar_apply(&BARS[k], u, v));
                    assert_eq!(bar_apply_c(&BARS_INV_C[k], u, v), bar_apply(&BARS_INV[k], u, v));
                }
            }
        }
        for k in 0..6 {
            let mut row = [11u8, 222, 37];
            trip_apply(&TRIPLETS[k], &mut row);
            trip_apply(&TRIPLETS_INV[k], &mut row);
            assert_eq!(row, [11, 222, 37]);
        }
        for u in 0..=255u8 {
            let (a, b) = mix2(u, u.wrapping_mul(31));
            assert_eq!(mix2_inv(a, b), (u, u.wrapping_mul(31)));
        }
    }
}

#[cfg(test)]
mod layer_timing {
    use super::*;
    use crate::backend::CtSoft;
    use std::hint::black_box;
    use std::time::Instant;
    #[test]
    #[ignore]
    fn layer_timings() {
        let sch = Schedule::new(&[0x33u8; 128], &[1u8; 16]);
        let rk = &sch.rounds[0];
        crate::force_backend(Some(crate::BackendKind::Gfni512));
        let b = <crate::Auto as SboxBackend>::prepare(&sch);
        let _ = CtSoft;
        let mut g = [0x5au8; 128];
        let n = 200_000;
        macro_rules! t {
            ($name:expr, $e:expr) => {{
                let t0 = Instant::now();
                for _ in 0..n { $e; black_box(&mut g); }
                println!("{:12} {:8.1} ns", $name, t0.elapsed().as_secs_f64() / n as f64 * 1e9);
            }};
        }
        t!("sub", sub(&mut g, &b, rk, 0, false));
        t!("weave", weave(&mut g, &rk.sh, &rk.sv));
        t!("butterfly", butterfly(&mut g, &rk.sigma));
        t!("bridges", bridges(&mut g, &rk.bridge, 0, false));
        t!("bar_mix", bar_mix(&mut g, &b, rk, 0));
        t!("trip", trip(&mut g));
        t!("bow", bow(&mut g));
        t!("odd", odd(&mut g, &b, rk, 0));
        t!("cross", cross(&mut g));
        t!("trip", trip(&mut g));
        t!("untrip", untrip(&mut g));
        t!("unbow", unbow(&mut g));
        t!("bar_unmix", bar_unmix(&mut g, &b, rk, 0));
        t!("unodd", unodd(&mut g, &b, rk, 0));
        t!("unbutterfly", unbutterfly(&mut g, &rk.sigma));
        t!("uncross", uncross(&mut g));
        t!("round_enc", round_enc(&mut g, &b, rk, 0));
        t!("round_dec", round_dec(&mut g, &b, rk, 0));
    }
}
