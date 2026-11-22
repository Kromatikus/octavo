// Column-major per-row layers, written once over the vector ops of the including module
// (`w128`: one block, 16 faces per xmm; `w512`: four blocks, 4 x 16 faces per zmm, one 128-bit lane
// per block). Included by simd.rs. All indices / constants are public; no data-dependent branches,
// addresses or table lookups.

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
pub(super) fn sbox(x: V, s: &Sb) -> V {
    let y = v_xor(v_aff(x, s.pre), v_set1(s.pre_c as i8));
    v_xor(v_affinv(y, s.post), v_set1(s.post_c as i8))
}
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
fn latin(u: V, v: V, rk: &RoundK, k: &Consts) -> (V, V) {
    let x = v_xor(u, v);
    let y = v_xor(u, v_aff(v, k.m2));
    (sbox(x, &rk.sb[0]), sbox(y, &rk.sb[1]))
}
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
fn unlatin(u: V, v: V, rk: &RoundK, k: &Consts) -> (V, V) {
    let x = sbox(u, &rk.sb[2]);
    let y = sbox(v, &rk.sb[3]);
    let v0 = v_aff(v_xor(x, y), k.minv3);
    (v_xor(x, v0), v0)
}
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
pub(super) fn bar_mix(c: &mut CV, rk: &RoundK, k: &Consts) {
    (c[0], c[1]) = latin(c[0], c[1], rk, k);
    for j in 1..7 {
        let m = &k.bars[j];
        let (u, v) = (c[j], c[j + 1]);
        c[j] = v_xor(v_aff(u, m[0][0]), v_aff(v, m[0][1]));
        c[j + 1] = v_xor(v_aff(u, m[1][0]), v_aff(v, m[1][1]));
    }
}
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
pub(super) fn bar_unmix(c: &mut CV, rk: &RoundK, k: &Consts) {
    for j in (1..7).rev() {
        let m = &k.bars_inv[j];
        let (u, v) = (c[j], c[j + 1]);
        c[j] = v_xor(v_aff(u, m[0][0]), v_aff(v, m[0][1]));
        c[j + 1] = v_xor(v_aff(u, m[1][0]), v_aff(v, m[1][1]));
    }
    (c[0], c[1]) = unlatin(c[0], c[1], rk, k);
}

include!("trip_gen.rs");
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
pub(super) fn trip(c: &mut CV) {
    trip_fwd(c)
}
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
pub(super) fn untrip(c: &mut CV) {
    trip_inv(c)
}

/// Rotation amounts (1 + view % 7, 1 + (view >> 3) % 7) per byte, branch-free: 8 ≡ 1 (mod 7), so
/// view % 7 is the octal digit sum mod 7. Each "mod 7" step is x -> min_u8(x, x - 7): when x < 7 the
/// subtraction wraps to >= 249, so min keeps x. No compares, masks or lookups.
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
pub(super) fn bow_amounts(view: V) -> (V, V) {
    let seven = v_set1(7);
    let one = v_set1(1);
    let d0 = v_and(view, seven);
    let d1 = v_and(v_srli16::<3>(view), seven);
    let d2 = v_and(v_srli16::<6>(view), v_set1(3));
    let w = v_add(d1, d2); // <= 10
    let mut s = v_add(w, d0); // <= 17
    s = v_min(s, v_sub(s, seven));
    s = v_min(s, v_sub(s, seven));
    let w = v_min(w, v_sub(w, seven));
    (v_add(s, one), v_add(w, one))
}
/// Per-byte rotate left by r (1..=7), constant time: each byte is duplicated into a 16-bit word
/// (PSHUFB with a fixed index), shifted with VPSLLVW (fixed latency for any count), and the high
/// byte kept. Even and odd bytes go through separate words.
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
pub(super) fn vrot(x: V, r: V) -> V {
    const DUP_E: [u8; 16] = [0, 0, 2, 2, 4, 4, 6, 6, 8, 8, 10, 10, 12, 12, 14, 14];
    const DUP_O: [u8; 16] = [1, 1, 3, 3, 5, 5, 7, 7, 9, 9, 11, 11, 13, 13, 15, 15];
    let re = v_and(r, v_set1_16(0x00ff));
    let ro = v_srli16::<8>(r);
    let se = v_sllv16(v_shuf(x, v_bcast16(&DUP_E)), re);
    let so = v_sllv16(v_shuf(x, v_bcast16(&DUP_O)), ro);
    v_blend(v_mask(0xAAAA), v_srli16::<8>(se), so)
}
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
fn view_rot(x: V, rot: usize, k: &Consts) -> V {
    if rot == 0 { x } else { v_aff(x, k.rot[rot]) } // rot is a literal per stroke
}
/// One bow stroke (i, j, p, view rotation): all public compile-time constants.
macro_rules! bow_stroke {
    ($c:ident, $k:ident, $i:literal, $j:literal, $p:literal, $rot:literal) => {{
        let (r1, r2) = bow_amounts(view_rot($c[$p], $rot, $k));
        let u = v_add($c[$i], vrot($c[$j], r1));
        let v = v_xor($c[$j], vrot(u, r2));
        $c[$i] = u;
        $c[$j] = v;
    }};
}
macro_rules! unbow_stroke {
    ($c:ident, $k:ident, $i:literal, $j:literal, $p:literal, $rot:literal) => {{
        let (r1, r2) = bow_amounts(view_rot($c[$p], $rot, $k));
        let v = v_xor($c[$j], vrot($c[$i], r2));
        let u = v_sub($c[$i], vrot(v, r1));
        $c[$i] = u;
        $c[$j] = v;
    }};
}
// keep in sync with BOW_STROKES / BOW_ROT (checked by the bow_tables_match test)
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
pub(super) fn bow(c: &mut CV, k: &Consts) {
    bow_stroke!(c, k, 0, 1, 2, 0);
    bow_stroke!(c, k, 2, 3, 4, 0);
    bow_stroke!(c, k, 4, 5, 0, 0);
    bow_stroke!(c, k, 6, 7, 0, 3);
    bow_stroke!(c, k, 1, 2, 3, 0);
    bow_stroke!(c, k, 3, 4, 5, 0);
    bow_stroke!(c, k, 5, 6, 0, 5);
}
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
pub(super) fn unbow(c: &mut CV, k: &Consts) {
    unbow_stroke!(c, k, 5, 6, 0, 5);
    unbow_stroke!(c, k, 3, 4, 5, 0);
    unbow_stroke!(c, k, 1, 2, 3, 0);
    unbow_stroke!(c, k, 6, 7, 0, 3);
    unbow_stroke!(c, k, 4, 5, 0, 0);
    unbow_stroke!(c, k, 2, 3, 4, 0);
    unbow_stroke!(c, k, 0, 1, 2, 0);
}
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
pub(super) fn odd(c: &mut CV, rk: &RoundK, k: &Consts) {
    for t in [0usize, 2, 4, 6] {
        (c[t], c[t + 1]) = latin(c[t], c[t + 1], rk, k);
    }
}
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
pub(super) fn unodd(c: &mut CV, rk: &RoundK, k: &Consts) {
    for t in [6usize, 4, 2, 0] {
        (c[t], c[t + 1]) = unlatin(c[t], c[t + 1], rk, k);
    }
}
/// Cross-staff pair layer (a, b) -> (a ^ b, a ^ 2b) on the touched lanes:
/// partner = PSHUFB(col, idx_z) (zero on untouched lanes), col' = 2*col on b lanes only (masked
/// GF2P8AFFINEQB), out = col' ^ partner. Untouched lanes: col ^ 0 = col.
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
pub(super) fn cross(c: &mut CV, k: &Consts) {
    for l in &CROSS_L {
        let idx = v_bcast16(&l.idx_z);
        let bm = v_mask(l.b_mask);
        for t in 0..8 {
            let col = c[t];
            c[t] = v_xor(v_mask_aff(col, bm, col, k.m2), v_shuf(col, idx));
        }
    }
}
/// Inverse: (a', b') -> b = (a' ^ b') / 3, a = a' ^ b. t = col ^ partner (= col on untouched
/// lanes), u = t * 3^-1 on touched lanes only, out = u ^ (col & a_lanes).
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
pub(super) fn uncross(c: &mut CV, k: &Consts) {
    for l in CROSS_L.iter().rev() {
        let idx = v_bcast16(&l.idx_z);
        let av = v_bcast16(&l.a_vec);
        let tm = v_mask(l.touched);
        for t in 0..8 {
            let col = c[t];
            let x = v_xor(col, v_shuf(col, idx));
            c[t] = v_xor(v_mask_aff(x, tm, x, k.minv3), v_and(col, av));
        }
    }
}

/// Everything between the two pair-mix stages of an encryption round (both halves).
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
pub(super) fn enc_rows(c: &mut CV, rk: &RoundK, k: &Consts) {
    for half in 0..2 {
        if half == 1 {
            for t in 0..8 {
                c[t] = sbox(c[t], &rk.sb[1]);
            }
        }
        bar_mix(c, rk, k);
        trip(c);
        bow(c, k);
        odd(c, rk, k);
        cross(c, k);
    }
}
/// Exact inverse of [`enc_rows`].
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
pub(super) fn dec_rows(c: &mut CV, rk: &RoundK, k: &Consts) {
    for half in [1, 0] {
        uncross(c, k);
        unodd(c, rk, k);
        unbow(c, k);
        untrip(c);
        bar_unmix(c, rk, k);
        if half == 1 {
            for t in 0..8 {
                c[t] = sbox(c[t], &rk.sb[3]);
            }
        }
    }
}
