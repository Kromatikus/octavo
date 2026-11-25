// perm1: constant-time Benes network for the key-derived 64-register bridge
// permutation, replacing (64x64 transpose, VPERMB, 64x64 transpose).
//
// 11 stages with strides 32,16,8,4,2,1,2,4,8,16,32; 32 switches per stage.
// Each switch is two VPTERNLOGD selects against a broadcast 0 / all-ones
// word. Wiring and addresses are public; only the mask *values* are secret.
// The inverse permutation is the same network run backwards with the same
// masks, so one table serves gather and scatter.
//
// Routing (key setup) is the classic looping algorithm made branch-free with
// VPERMB: orbit minima by pointer doubling, colours by comparing an orbit's
// minimum with its partner orbit's, bits extracted with PEXT. Fixed trip
// counts; no secret-dependent branches or addresses.

const BENES_STAGES: usize = 11;
const BENES_STRIDES: [usize; BENES_STAGES] = [32, 16, 8, 4, 2, 1, 2, 4, 8, 16, 32];
const BENES_WORDS: usize = BENES_STAGES * 32;

const ID64: [u8; 64] = {
    let mut a = [0u8; 64];
    let mut i = 0;
    while i < 64 {
        a[i] = i as u8;
        i += 1;
    }
    a
};

/// Switch number (0..32) of the low element x of a stride-m pair.
#[inline(always)]
const fn benes_k(x: usize, m: usize) -> usize {
    ((x >> 1) & !(m - 1)) | (x & (m - 1))
}

/// Constant-time inverse of a 64-permutation held in a vector.
#[inline(always)]
unsafe fn benes_inv_vec(s: __m512i) -> __m512i {
    let mut out = [0u8; 64];
    for x in 0..64 {
        let k = _mm512_cmpeq_epi8_mask(s, _mm512_set1_epi8(x as i8));
        out[x] = _tzcnt_u64(k) as u8;
    }
    _mm512_loadu_si512(out.as_ptr() as *const _)
}

/// Switch masks for out[j] = in[src[j]]. masks[st*32 + k] is 0 or !0.
unsafe fn benes_route(src: &[u8; 64]) -> [u32; BENES_WORDS] {
    // fallback1: hardware PEXT only where it is fast and data-independent.
    if crate::benes_soft::hw_pext_ok() {
        benes_route_hw(src)
    } else {
        benes_route_softpext(src)
    }
}

#[target_feature(enable = "avx512f,avx512bw,avx512vbmi,bmi1,bmi2")]
unsafe fn benes_route_hw(src: &[u8; 64]) -> [u32; BENES_WORDS] {
    benes_route_core(src, |x, m| _pext_u64(x, m))
}

#[target_feature(enable = "avx512f,avx512bw,avx512vbmi,bmi1")]
unsafe fn benes_route_softpext(src: &[u8; 64]) -> [u32; BENES_WORDS] {
    benes_route_core(src, crate::benes_soft::pext_pub)
}

/// Switch masks for out[j] = in[src[j]]; `pext` is only ever called with a
/// public mask.
#[inline(always)]
unsafe fn benes_route_core(src: &[u8; 64], pext: impl Fn(u64, u64) -> u64) -> [u32; BENES_WORDS] {
    let id = _mm512_loadu_si512(ID64.as_ptr() as *const _);
    let mut s = _mm512_loadu_si512(src.as_ptr() as *const _);
    let mut bits = [0u32; BENES_STAGES];
    let (mut lo, mut hi) = (0usize, BENES_STAGES - 1);
    let mut m = 32usize;
    while m >= 2 {
        let mv = _mm512_set1_epi8(m as i8);
        let partner = _mm512_xor_si512(id, mv);
        let sinv = benes_inv_vec(s);
        // f(x) = s[sinv[x] ^ m] ^ m keeps the subnet colour.
        let f = _mm512_xor_si512(_mm512_permutexvar_epi8(_mm512_xor_si512(sinv, mv), s), mv);
        let mut c = id;
        let mut g = f;
        for _ in 0..6 {
            c = _mm512_min_epu8(c, _mm512_permutexvar_epi8(g, c));
            g = _mm512_permutexvar_epi8(g, g);
        }
        let cp = _mm512_permutexvar_epi8(partner, c);
        let col: u64 = _mm512_cmpgt_epu8_mask(c, cp); // 1 = bottom subnet
        let lowpos: u64 = _mm512_testn_epi8_mask(id, mv);
        bits[lo] = pext(col, lowpos) as u32;
        let colv = _mm512_movm_epi8(col);
        let cs: u64 = _mm512_test_epi8_mask(
            _mm512_permutexvar_epi8(s, colv),
            _mm512_permutexvar_epi8(s, colv),
        ); // colour of s[j]
        bits[hi] = pext(cs, lowpos) as u32;
        let sp = _mm512_permutexvar_epi8(partner, s);
        let pick = _mm512_mask_blend_epi8(cs ^ !lowpos, s, sp);
        let base = _mm512_and_si512(id, _mm512_set1_epi8(!(m as u8 - 1) as i8));
        s = _mm512_or_si512(base, _mm512_and_si512(pick, _mm512_set1_epi8((m - 1) as i8)));
        lo += 1;
        hi -= 1;
        m /= 2;
    }
    debug_assert_eq!(lo, 5);
    let neq: u64 = _mm512_cmpneq_epi8_mask(s, id);
    bits[5] = pext(neq, 0x5555_5555_5555_5555) as u32;
    let mut out = [0u32; BENES_WORDS];
    for st in 0..BENES_STAGES {
        for k in 0..32 {
            out[st * 32 + k] = 0u32.wrapping_sub((bits[st] >> k) & 1);
        }
    }
    out
}

#[inline(always)]
unsafe fn benes_sw(v: &mut [__m512i; 8], t: usize, u: usize, w: u32) {
    let mk = _mm512_set1_epi32(w as i32);
    let a = v[t];
    let b = v[u];
    v[t] = _mm512_ternarylogic_epi32::<0xD8>(a, b, mk); // mk ? b : a
    v[u] = _mm512_ternarylogic_epi32::<0xE4>(a, b, mk); // mk ? a : b
}

/// One stage on an 8-register group whose register t sits at base + step*t;
/// d is the register distance of a stride-m pair inside the group.
#[inline(always)]
unsafe fn benes_stage8(
    v: &mut [__m512i; 8],
    mk: &[u32; BENES_WORDS],
    st: usize,
    base: usize,
    step: usize,
    d: usize,
) {
    let m = BENES_STRIDES[st];
    for t in 0..8 {
        if t & d == 0 {
            let x = base + step * t;
            benes_sw(v, t, t + d, mk[st * 32 + benes_k(x, m)]);
        }
    }
}

// Passes: A = stages 0..3 on groups {r + 8t}; B = stages 3..8 on groups
// {8g + t}; C = stages 8..11 on groups {r + 8t}.
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn benes_pass_a(h: &mut [__m512i; 64], mk: &[u32; BENES_WORDS], fwd: bool) {
    for r in 0..8 {
        let mut v = [_mm512_setzero_si512(); 8];
        for t in 0..8 {
            v[t] = h[r + 8 * t];
        }
        if fwd {
            benes_stage8(&mut v, mk, 0, r, 8, 4);
            benes_stage8(&mut v, mk, 1, r, 8, 2);
            benes_stage8(&mut v, mk, 2, r, 8, 1);
        } else {
            benes_stage8(&mut v, mk, 2, r, 8, 1);
            benes_stage8(&mut v, mk, 1, r, 8, 2);
            benes_stage8(&mut v, mk, 0, r, 8, 4);
        }
        for t in 0..8 {
            h[r + 8 * t] = v[t];
        }
    }
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn benes_pass_b(h: &mut [__m512i; 64], mk: &[u32; BENES_WORDS], fwd: bool) {
    for g in 0..8 {
        let mut v = [_mm512_setzero_si512(); 8];
        for t in 0..8 {
            v[t] = h[8 * g + t];
        }
        if fwd {
            benes_stage8(&mut v, mk, 3, 8 * g, 1, 4);
            benes_stage8(&mut v, mk, 4, 8 * g, 1, 2);
            benes_stage8(&mut v, mk, 5, 8 * g, 1, 1);
            benes_stage8(&mut v, mk, 6, 8 * g, 1, 2);
            benes_stage8(&mut v, mk, 7, 8 * g, 1, 4);
        } else {
            benes_stage8(&mut v, mk, 7, 8 * g, 1, 4);
            benes_stage8(&mut v, mk, 6, 8 * g, 1, 2);
            benes_stage8(&mut v, mk, 5, 8 * g, 1, 1);
            benes_stage8(&mut v, mk, 4, 8 * g, 1, 2);
            benes_stage8(&mut v, mk, 3, 8 * g, 1, 4);
        }
        for t in 0..8 {
            h[8 * g + t] = v[t];
        }
    }
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn benes_pass_c(h: &mut [__m512i; 64], mk: &[u32; BENES_WORDS], fwd: bool) {
    for r in 0..8 {
        let mut v = [_mm512_setzero_si512(); 8];
        for t in 0..8 {
            v[t] = h[r + 8 * t];
        }
        if fwd {
            benes_stage8(&mut v, mk, 8, r, 8, 1);
            benes_stage8(&mut v, mk, 9, r, 8, 2);
            benes_stage8(&mut v, mk, 10, r, 8, 4);
        } else {
            benes_stage8(&mut v, mk, 10, r, 8, 4);
            benes_stage8(&mut v, mk, 9, r, 8, 2);
            benes_stage8(&mut v, mk, 8, r, 8, 1);
        }
        for t in 0..8 {
            h[r + 8 * t] = v[t];
        }
    }
}

/// Gather h[c] <- h[src[c]] (fwd) or its inverse scatter (!fwd).
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn benes_apply_z(h: &mut [__m512i; 64], mk: &[u32; BENES_WORDS], fwd: bool) {
    if fwd {
        benes_pass_a(h, mk, true);
        benes_pass_b(h, mk, true);
        benes_pass_c(h, mk, true);
    } else {
        benes_pass_c(h, mk, false);
        benes_pass_b(h, mk, false);
        benes_pass_a(h, mk, false);
    }
}

#[inline(always)]
unsafe fn bridge_mix_z(l: &mut __m512i, h: &mut __m512i, even: bool, c: &Consts, inv: bool) {
    let (a, b) = if even { (*l, *h) } else { (*h, *l) };
    let (x, y) = if !inv {
        (_mm512_xor_si512(a, b), _mm512_xor_si512(a, aff512(b, c.m2)))
    } else {
        let v = aff512(_mm512_xor_si512(a, b), c.minv3);
        (_mm512_xor_si512(a, v), v)
    };
    if even {
        *l = x;
        *h = y;
    } else {
        *h = x;
        *l = y;
    }
}

/// Bridges on the 64-block sliced layout: Benes gather, pair mix, Benes
/// scatter. The last forward pass, the mix and the first inverse pass share
/// one load/store of each register group.
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn slice64_bridges_benes(pos: &mut [__m512i; 128], rk: &RoundK, c: &Consts, inv: bool) {
    let (lo, hi) = pos.split_at_mut(64);
    let lo: &mut [__m512i; 64] = lo.try_into().unwrap();
    let hi: &mut [__m512i; 64] = hi.try_into().unwrap();
    let mk = &rk.benes;
    benes_pass_a(hi, mk, true);
    benes_pass_b(hi, mk, true);
    for r in 0..8 {
        let mut v = [_mm512_setzero_si512(); 8];
        for t in 0..8 {
            v[t] = hi[r + 8 * t];
        }
        benes_stage8(&mut v, mk, 8, r, 8, 1);
        benes_stage8(&mut v, mk, 9, r, 8, 2);
        benes_stage8(&mut v, mk, 10, r, 8, 4);
        for t in 0..8 {
            bridge_mix_z(&mut lo[r + 8 * t], &mut v[t], rk.even, c, inv);
        }
        benes_stage8(&mut v, mk, 10, r, 8, 4);
        benes_stage8(&mut v, mk, 9, r, 8, 2);
        benes_stage8(&mut v, mk, 8, r, 8, 1);
        for t in 0..8 {
            hi[r + 8 * t] = v[t];
        }
    }
    benes_pass_b(hi, mk, false);
    benes_pass_a(hi, mk, false);
}
