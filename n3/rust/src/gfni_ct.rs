// Constant-time permutation of 64 registers via a Batcher bitonic network.
// Addresses and the compare/swap wiring are public. Only the swap masks
// (computed once from the key's bridge permutation) are secret, and they
// are applied with AND/XOR, no key-dependent loads, stores, or branches.

#[cfg(test)]
const BITONIC_STAGES: usize = 21; // 1+2+...+6 for n=64

#[cfg(test)]
fn bitonic_masks(dest: &[u8; 64]) -> [u32; BITONIC_STAGES] {
    let mut d = *dest;
    let mut masks = [0u32; BITONIC_STAGES];
    let mut stage = 0usize;
    let mut k = 2u32;
    while k <= 64 {
        let mut j = k / 2;
        while j > 0 {
            let mut mask = 0u32;
            let mut bit = 0u32;
            for i in 0..64 {
                let l = i ^ j as usize;
                if l > i {
                    let upward = (i as u32 & k) == 0;
                    let should = if upward { d[i] > d[l] } else { d[i] < d[l] };
                    if should {
                        d.swap(i, l);
                        mask |= 1 << bit;
                    }
                    bit += 1;
                }
            }
            debug_assert_eq!(bit, 32);
            masks[stage] = mask;
            stage += 1;
            j /= 2;
        }
        k *= 2;
    }
    debug_assert_eq!(stage, BITONIC_STAGES);
    masks
}

#[cfg(test)]
fn invert_perm64(p: &[u8; 64]) -> [u8; 64] {
    let mut inv = [0u8; 64];
    for i in 0..64 {
        inv[p[i] as usize] = i as u8;
    }
    inv
}

/// gather[i] = in[π[i]], scatter puts them back: out[π[i]] = gathered[i].
#[cfg(test)]
fn bridge_bitonic_masks(pi: &[u8; 64]) -> ([u32; BITONIC_STAGES], [u32; BITONIC_STAGES]) {
    let inv = invert_perm64(pi);
    (bitonic_masks(&inv), bitonic_masks(pi))
}



#[cfg(test)]
fn bitonic_apply_u8(v: &mut [u8; 64], masks: &[u32; BITONIC_STAGES]) {
    let mut stage = 0usize;
    let mut k = 2u32;
    while k <= 64 {
        let mut j = k / 2;
        while j > 0 {
            let mask = masks[stage];
            let mut bit = 0u32;
            for i in 0..64 {
                let l = i ^ j as usize;
                if l > i {
                    if (mask >> bit) & 1 == 1 {
                        v.swap(i, l);
                    }
                    bit += 1;
                }
            }
            stage += 1;
            j /= 2;
        }
        k *= 2;
    }
}


#[cfg(test)]
/// 8x8 transpose of the 64-bit lanes in eight ZMM registers, via a
/// three-level vpermt2q merge. Addresses and indices are public.
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn transpose_8x8_epi64(v: &mut [__m512i; 8]) {
    let pair_lo = _mm512_setr_epi64(0, 8, 1, 9, 2, 10, 3, 11);
    let pair_hi = _mm512_setr_epi64(4, 12, 5, 13, 6, 14, 7, 15);
    let ab_lo = _mm512_permutex2var_epi64(v[0], pair_lo, v[1]);
    let ab_hi = _mm512_permutex2var_epi64(v[0], pair_hi, v[1]);
    let cd_lo = _mm512_permutex2var_epi64(v[2], pair_lo, v[3]);
    let cd_hi = _mm512_permutex2var_epi64(v[2], pair_hi, v[3]);
    let ef_lo = _mm512_permutex2var_epi64(v[4], pair_lo, v[5]);
    let ef_hi = _mm512_permutex2var_epi64(v[4], pair_hi, v[5]);
    let gh_lo = _mm512_permutex2var_epi64(v[6], pair_lo, v[7]);
    let gh_hi = _mm512_permutex2var_epi64(v[6], pair_hi, v[7]);

    let q4_lo = _mm512_setr_epi64(0, 1, 8, 9, 2, 3, 10, 11);
    let q4_hi = _mm512_setr_epi64(4, 5, 12, 13, 6, 7, 14, 15);
    let abcd_01 = _mm512_permutex2var_epi64(ab_lo, q4_lo, cd_lo);
    let abcd_23 = _mm512_permutex2var_epi64(ab_lo, q4_hi, cd_lo);
    let abcd_45 = _mm512_permutex2var_epi64(ab_hi, q4_lo, cd_hi);
    let abcd_67 = _mm512_permutex2var_epi64(ab_hi, q4_hi, cd_hi);
    let efgh_01 = _mm512_permutex2var_epi64(ef_lo, q4_lo, gh_lo);
    let efgh_23 = _mm512_permutex2var_epi64(ef_lo, q4_hi, gh_lo);
    let efgh_45 = _mm512_permutex2var_epi64(ef_hi, q4_lo, gh_hi);
    let efgh_67 = _mm512_permutex2var_epi64(ef_hi, q4_hi, gh_hi);

    let q8_lo = _mm512_setr_epi64(0, 1, 2, 3, 8, 9, 10, 11);
    let q8_hi = _mm512_setr_epi64(4, 5, 6, 7, 12, 13, 14, 15);
    v[0] = _mm512_permutex2var_epi64(abcd_01, q8_lo, efgh_01);
    v[1] = _mm512_permutex2var_epi64(abcd_01, q8_hi, efgh_01);
    v[2] = _mm512_permutex2var_epi64(abcd_23, q8_lo, efgh_23);
    v[3] = _mm512_permutex2var_epi64(abcd_23, q8_hi, efgh_23);
    v[4] = _mm512_permutex2var_epi64(abcd_45, q8_lo, efgh_45);
    v[5] = _mm512_permutex2var_epi64(abcd_45, q8_hi, efgh_45);
    v[6] = _mm512_permutex2var_epi64(abcd_67, q8_lo, efgh_67);
    v[7] = _mm512_permutex2var_epi64(abcd_67, q8_hi, efgh_67);
}

#[cfg(test)]
/// In-place 8x8 byte transpose of each 8x8 tile in eight ZMM rows.
/// Packs each 8-byte column-group with an 8x8 qword transpose, VPERMBs
/// with a fixed 8x8 byte pattern, and unpacks the same way.
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn transpose_8x8_tiles_epi8(r: &mut [__m512i; 8]) {
    // idx[8*c + row] = 8*row + c: fixed involution on one packed 8x8 tile.
    const TILE8_PERM: [u8; 64] = {
        let mut pat = [0u8; 64];
        let mut c = 0;
        while c < 8 {
            let mut row = 0;
            while row < 8 {
                pat[8 * c + row] = (8 * row + c) as u8;
                row += 1;
            }
            c += 1;
        }
        pat
    };
    let idx = _mm512_loadu_si512(TILE8_PERM.as_ptr() as *const _);
    transpose_8x8_epi64(r);
    for i in 0..8 {
        r[i] = _mm512_permutexvar_epi8(idx, r[i]);
    }
    transpose_8x8_epi64(r);
}

#[cfg(test)]
/// 64x64 byte transpose of 64 ZMM rows. First an 8x8 byte transpose inside
/// each 8-byte tile, then an 8x8 qword transpose of the tile grid (64-byte
/// / 8-byte lanes). All addresses and permute indices are public. An involution.
#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn transpose_64x64_z(m: &mut [__m512i; 64]) {
    for g in 0..8 {
        let mut r = [_mm512_setzero_si512(); 8];
        for i in 0..8 {
            r[i] = m[8 * g + i];
        }
        transpose_8x8_tiles_epi8(&mut r);
        for i in 0..8 {
            m[8 * g + i] = r[i];
        }
    }
    for r0 in 0..8 {
        let mut t = [_mm512_setzero_si512(); 8];
        for g in 0..8 {
            t[g] = m[8 * g + r0];
        }
        transpose_8x8_epi64(&mut t);
        for g in 0..8 {
            m[8 * g + r0] = t[g];
        }
    }
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn y64_to_z64(y: &[__m256i; 64]) -> [__m512i; 64] {
    let mut z = [_mm512_setzero_si512(); 64];
    for i in 0..64 {
        z[i] = _mm512_castsi256_si512(y[i]);
    }
    z
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn z64_to_y64(z: &[__m512i; 64]) -> [__m256i; 64] {
    let mut y = [_mm256_setzero_si256(); 64];
    for i in 0..64 {
        y[i] = _mm512_castsi512_si256(z[i]);
    }
    y
}
