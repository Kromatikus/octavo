// Position-sliced batch path (gfni3 idea 2).
// Transpose a group of 64 (or 32) independent blocks once so pos[p] holds
// byte p of every block. Linear layers are then mul-by-constant + XOR on
// whole registers with no per-round shuffles; S-boxes are GF2P8AFFINEINVQB
// per register; the bow is lane-wise ARX. Transpose back on the way out.
// Bridge pairing is key-derived. The sliced path applies it with a
// bitonic network (public addresses, mask-select swaps) so the data
// path has no key-dependent loads, stores, or branches.

#[inline]
fn pidx(face: usize, beat: usize) -> usize {
    8 * face + beat
}

// ---- 256-bit helpers for the 32-block slice ----

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn sbox256(x: __m256i, s: &Sb) -> __m256i {
    let y = _mm256_xor_si256(aff256(x, s.pre), _mm256_set1_epi8(s.pre_c as i8));
    _mm256_xor_si256(
        _mm256_gf2p8affineinv_epi64_epi8::<0>(y, _mm256_set1_epi64x(s.post as i64)),
        _mm256_set1_epi8(s.post_c as i8),
    )
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn bow_amounts256(view: __m256i) -> (__m256i, __m256i) {
    let seven = _mm256_set1_epi8(7);
    let one = _mm256_set1_epi8(1);
    let d0 = _mm256_and_si256(view, seven);
    let d1 = _mm256_and_si256(_mm256_srli_epi16::<3>(view), seven);
    let d2 = _mm256_and_si256(_mm256_srli_epi16::<6>(view), _mm256_set1_epi8(3));
    let w = _mm256_add_epi8(d1, d2);
    let mut s = _mm256_add_epi8(w, d0);
    s = _mm256_min_epu8(s, _mm256_sub_epi8(s, seven));
    s = _mm256_min_epu8(s, _mm256_sub_epi8(s, seven));
    let w = _mm256_min_epu8(w, _mm256_sub_epi8(w, seven));
    (_mm256_add_epi8(s, one), _mm256_add_epi8(w, one))
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn vrot256(x: __m256i, r: __m256i) -> __m256i {
    const DUP_E: [u8; 16] = [0, 0, 2, 2, 4, 4, 6, 6, 8, 8, 10, 10, 12, 12, 14, 14];
    const DUP_O: [u8; 16] = [1, 1, 3, 3, 5, 5, 7, 7, 9, 9, 11, 11, 13, 13, 15, 15];
    let de = _mm256_broadcastsi128_si256(_mm_loadu_si128(DUP_E.as_ptr() as *const _));
    let dov = _mm256_broadcastsi128_si256(_mm_loadu_si128(DUP_O.as_ptr() as *const _));
    let re = _mm256_and_si256(r, _mm256_set1_epi16(0x00ff));
    let ro = _mm256_srli_epi16::<8>(r);
    let se = _mm256_sllv_epi16(_mm256_shuffle_epi8(x, de), re);
    let so = _mm256_sllv_epi16(_mm256_shuffle_epi8(x, dov), ro);
    _mm256_mask_blend_epi8(0xAAAA_AAAA, _mm256_srli_epi16::<8>(se), so)
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn bow_cols256(cols: &mut [__m256i; 8], c: &Consts, inverse: bool) {
    if !inverse {
        for (&(i, j, p), &rot) in BOW_STROKES.iter().zip(BOW_PRESSURE_ROT.iter()) {
            let view = if rot == 0 {
                cols[p]
            } else {
                aff256(cols[p], c.rot[rot])
            };
            let (r1, r2) = bow_amounts256(view);
            let u = _mm256_add_epi8(cols[i], vrot256(cols[j], r1));
            let v = _mm256_xor_si256(cols[j], vrot256(u, r2));
            cols[i] = u;
            cols[j] = v;
        }
    } else {
        for (&(i, j, p), &rot) in BOW_STROKES.iter().zip(BOW_PRESSURE_ROT.iter()).rev() {
            let view = if rot == 0 {
                cols[p]
            } else {
                aff256(cols[p], c.rot[rot])
            };
            let (r1, r2) = bow_amounts256(view);
            let v = _mm256_xor_si256(cols[j], vrot256(cols[i], r2));
            let u = _mm256_sub_epi8(cols[i], vrot256(v, r1));
            cols[i] = u;
            cols[j] = v;
        }
    }
}

// ---- 64-block transpose (tiled 16x16, an involution on each tile) ----

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn slice64_load(blocks: &[[u8; BLOCK_LEN]], pos: &mut [__m512i; 128]) {
    debug_assert_eq!(blocks.len(), 64);
    for pos_base in (0..BLOCK_LEN).step_by(16) {
        for blk_base in (0..64).step_by(16) {
            let mut m = [_mm_setzero_si128(); 16];
            for i in 0..16 {
                m[i] = _mm_loadu_si128(blocks[blk_base + i].as_ptr().add(pos_base) as *const _);
            }
            transpose_16x16(&mut m);
            let base = pos.as_mut_ptr() as *mut u8;
            for j in 0..16 {
                _mm_storeu_si128(base.add((pos_base + j) * 64 + blk_base) as *mut _, m[j]);
            }
        }
    }
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn slice64_store(pos: &[__m512i; 128], blocks: &mut [[u8; BLOCK_LEN]]) {
    debug_assert_eq!(blocks.len(), 64);
    for pos_base in (0..BLOCK_LEN).step_by(16) {
        for blk_base in (0..64).step_by(16) {
            let mut m = [_mm_setzero_si128(); 16];
            let base = pos.as_ptr() as *const u8;
            for j in 0..16 {
                m[j] = _mm_loadu_si128(base.add((pos_base + j) * 64 + blk_base) as *const _);
            }
            transpose_16x16(&mut m);
            for i in 0..16 {
                _mm_storeu_si128(
                    blocks[blk_base + i].as_mut_ptr().add(pos_base) as *mut _,
                    m[i],
                );
            }
        }
    }
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn slice32_load(blocks: &[[u8; BLOCK_LEN]], pos: &mut [__m256i; 128]) {
    debug_assert_eq!(blocks.len(), 32);
    for pos_base in (0..BLOCK_LEN).step_by(16) {
        for blk_base in (0..32).step_by(16) {
            let mut m = [_mm_setzero_si128(); 16];
            for i in 0..16 {
                m[i] = _mm_loadu_si128(blocks[blk_base + i].as_ptr().add(pos_base) as *const _);
            }
            transpose_16x16(&mut m);
            let base = pos.as_mut_ptr() as *mut u8;
            for j in 0..16 {
                _mm_storeu_si128(base.add((pos_base + j) * 32 + blk_base) as *mut _, m[j]);
            }
        }
    }
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn slice32_store(pos: &[__m256i; 128], blocks: &mut [[u8; BLOCK_LEN]]) {
    debug_assert_eq!(blocks.len(), 32);
    for pos_base in (0..BLOCK_LEN).step_by(16) {
        for blk_base in (0..32).step_by(16) {
            let mut m = [_mm_setzero_si128(); 16];
            let base = pos.as_ptr() as *const u8;
            for j in 0..16 {
                m[j] = _mm_loadu_si128(base.add((pos_base + j) * 32 + blk_base) as *const _);
            }
            transpose_16x16(&mut m);
            for i in 0..16 {
                _mm_storeu_si128(
                    blocks[blk_base + i].as_mut_ptr().add(pos_base) as *mut _,
                    m[i],
                );
            }
        }
    }
}

// ---- shared layer kernels, 64-wide ----

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn slice64_xor(pos: &mut [__m512i; 128], k: &[u8; BLOCK_LEN]) {
    for p in 0..BLOCK_LEN {
        pos[p] = _mm512_xor_si512(pos[p], _mm512_set1_epi8(k[p] as i8));
    }
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn slice64_s(pos: &mut [__m512i; 128], s: &Sb) {
    let mut p = 0;
    while p < BLOCK_LEN {
        pos[p] = sbox512(pos[p], s);
        pos[p + 1] = sbox512(pos[p + 1], s);
        pos[p + 2] = sbox512(pos[p + 2], s);
        pos[p + 3] = sbox512(pos[p + 3], s);
        p += 4;
    }
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn slice64_staff(pos: &mut [__m512i; 128], inv: bool) {
    for base in [0usize, 8] {
        for t in 0..8 {
            let mut v = [_mm512_setzero_si512(); 8];
            for i in 0..8 {
                v[i] = pos[pidx(base + i, t)];
            }
            if inv {
                staff_inv_z(&mut v);
            } else {
                staff_fwd_z(&mut v);
            }
            for i in 0..8 {
                pos[pidx(base + i, t)] = v[i];
            }
        }
    }
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn slice64_faces(pos: &mut [__m512i; 128], inv: bool) {
    for f in 0..16 {
        let mut v = [_mm512_setzero_si512(); 8];
        for t in 0..8 {
            v[t] = pos[pidx(f, t)];
        }
        if inv {
            staff_inv_z(&mut v);
        } else {
            staff_fwd_z(&mut v);
        }
        for t in 0..8 {
            pos[pidx(f, t)] = v[t];
        }
    }
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn slice64_chord(pos: &mut [__m512i; 128], inv: bool) {
    if !inv {
        slice64_staff(pos, false);
        slice64_faces(pos, false);
    } else {
        slice64_faces(pos, true);
        slice64_staff(pos, true);
    }
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn slice64_trip_bow(pos: &mut [__m512i; 128], c: &Consts, inv: bool) {
    for f in 0..16 {
        let mut v = [_mm512_setzero_si512(); 8];
        for t in 0..8 {
            v[t] = pos[pidx(f, t)];
        }
        if !inv {
            trip_fwd_z(&mut v);
            bow_cols512(&mut v, c, false);
        } else {
            bow_cols512(&mut v, c, true);
            trip_inv_z(&mut v);
        }
        for t in 0..8 {
            pos[pidx(f, t)] = v[t];
        }
    }
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn slice64_cross(pos: &mut [__m512i; 128], inv: bool) {
    for t in 0..8 {
        let mut v = [_mm512_setzero_si512(); 16];
        for f in 0..16 {
            v[f] = pos[pidx(f, t)];
        }
        if inv {
            cross_inv_z(&mut v);
        } else {
            cross_fwd_z(&mut v);
        }
        for f in 0..16 {
            pos[pidx(f, t)] = v[f];
        }
    }
}

#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn crypt_slice64(key: &GfniKey, blocks: &mut [[u8; BLOCK_LEN]], encrypt: bool) {
    debug_assert_eq!(blocks.len(), 64);
    let mut pos = [_mm512_setzero_si512(); 128];
    slice64_load(blocks, &mut pos);
    let c = &key.c;
    if encrypt {
        for r in 0..NR {
            let rk = &key.rounds[r];
            slice64_xor(&mut pos, &rk.rk);
            slice64_s(&mut pos, &rk.s);
            slice64_chord(&mut pos, false);
            slice64_bridges_benes(&mut pos, rk, c, false);
            slice64_trip_bow(&mut pos, c, false);
            slice64_s(&mut pos, &rk.sm);
            slice64_cross(&mut pos, false);
            slice64_s(&mut pos, &rk.s2);
        }
        slice64_xor(&mut pos, &key.white);
    } else {
        slice64_xor(&mut pos, &key.white);
        for r in (0..NR).rev() {
            let rk = &key.rounds[r];
            slice64_s(&mut pos, &rk.si2);
            slice64_cross(&mut pos, true);
            slice64_s(&mut pos, &rk.sim);
            slice64_trip_bow(&mut pos, c, true);
            slice64_bridges_benes(&mut pos, rk, c, true);
            slice64_chord(&mut pos, true);
            slice64_s(&mut pos, &rk.si);
            slice64_xor(&mut pos, &rk.rk);
        }
    }
    slice64_store(&pos, blocks);
}

// ---- 32-block (ymm) kernels, same layout ----

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn slice32_xor(pos: &mut [__m256i; 128], k: &[u8; BLOCK_LEN]) {
    for p in 0..BLOCK_LEN {
        pos[p] = _mm256_xor_si256(pos[p], _mm256_set1_epi8(k[p] as i8));
    }
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn slice32_s(pos: &mut [__m256i; 128], s: &Sb) {
    let mut p = 0;
    while p < BLOCK_LEN {
        pos[p] = sbox256(pos[p], s);
        pos[p + 1] = sbox256(pos[p + 1], s);
        pos[p + 2] = sbox256(pos[p + 2], s);
        pos[p + 3] = sbox256(pos[p + 3], s);
        p += 4;
    }
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn slice32_staff(pos: &mut [__m256i; 128], inv: bool) {
    for base in [0usize, 8] {
        for t in 0..8 {
            let mut v = [_mm256_setzero_si256(); 8];
            for i in 0..8 {
                v[i] = pos[pidx(base + i, t)];
            }
            if inv {
                staff_inv_y(&mut v);
            } else {
                staff_fwd_y(&mut v);
            }
            for i in 0..8 {
                pos[pidx(base + i, t)] = v[i];
            }
        }
    }
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn slice32_faces(pos: &mut [__m256i; 128], inv: bool) {
    for f in 0..16 {
        let mut v = [_mm256_setzero_si256(); 8];
        for t in 0..8 {
            v[t] = pos[pidx(f, t)];
        }
        if inv {
            staff_inv_y(&mut v);
        } else {
            staff_fwd_y(&mut v);
        }
        for t in 0..8 {
            pos[pidx(f, t)] = v[t];
        }
    }
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn slice32_chord(pos: &mut [__m256i; 128], inv: bool) {
    if !inv {
        slice32_staff(pos, false);
        slice32_faces(pos, false);
    } else {
        slice32_faces(pos, true);
        slice32_staff(pos, true);
    }
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn slice32_bridges(pos: &mut [__m256i; 128], rk: &RoundK, c: &Consts, inv: bool) {
    let (lo, hi) = pos.split_at_mut(64);
    let lo: &mut [__m256i; 64] = lo.try_into().unwrap();
    let hi: &mut [__m256i; 64] = hi.try_into().unwrap();
    let mut hz = y64_to_z64(hi);
    benes_apply_z(&mut hz, &rk.benes, true);
    *hi = z64_to_y64(&hz);
    for cidx in 0..64 {
        let (a, b) = if rk.even {
            (lo[cidx], hi[cidx])
        } else {
            (hi[cidx], lo[cidx])
        };
        if !inv {
            let a2 = _mm256_xor_si256(a, b);
            let b2 = _mm256_xor_si256(a, aff256(b, c.m2));
            if rk.even {
                lo[cidx] = a2;
                hi[cidx] = b2;
            } else {
                hi[cidx] = a2;
                lo[cidx] = b2;
            }
        } else {
            let v = aff256(_mm256_xor_si256(a, b), c.minv3);
            let u = _mm256_xor_si256(a, v);
            if rk.even {
                lo[cidx] = u;
                hi[cidx] = v;
            } else {
                hi[cidx] = u;
                lo[cidx] = v;
            }
        }
    }
    let mut hz = y64_to_z64(hi);
    benes_apply_z(&mut hz, &rk.benes, false);
    *hi = z64_to_y64(&hz);
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn slice32_trip_bow(pos: &mut [__m256i; 128], c: &Consts, inv: bool) {
    for f in 0..16 {
        let mut v = [_mm256_setzero_si256(); 8];
        for t in 0..8 {
            v[t] = pos[pidx(f, t)];
        }
        if !inv {
            trip_fwd_y(&mut v);
            bow_cols256(&mut v, c, false);
        } else {
            bow_cols256(&mut v, c, true);
            trip_inv_y(&mut v);
        }
        for t in 0..8 {
            pos[pidx(f, t)] = v[t];
        }
    }
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn slice32_cross(pos: &mut [__m256i; 128], inv: bool) {
    for t in 0..8 {
        let mut v = [_mm256_setzero_si256(); 16];
        for f in 0..16 {
            v[f] = pos[pidx(f, t)];
        }
        if inv {
            cross_inv_y(&mut v);
        } else {
            cross_fwd_y(&mut v);
        }
        for f in 0..16 {
            pos[pidx(f, t)] = v[f];
        }
    }
}

#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn crypt_slice32(key: &GfniKey, blocks: &mut [[u8; BLOCK_LEN]], encrypt: bool) {
    debug_assert_eq!(blocks.len(), 32);
    let mut pos = [_mm256_setzero_si256(); 128];
    slice32_load(blocks, &mut pos);
    let c = &key.c;
    if encrypt {
        for r in 0..NR {
            let rk = &key.rounds[r];
            slice32_xor(&mut pos, &rk.rk);
            slice32_s(&mut pos, &rk.s);
            slice32_chord(&mut pos, false);
            slice32_bridges(&mut pos, rk, c, false);
            slice32_trip_bow(&mut pos, c, false);
            slice32_s(&mut pos, &rk.sm);
            slice32_cross(&mut pos, false);
            slice32_s(&mut pos, &rk.s2);
        }
        slice32_xor(&mut pos, &key.white);
    } else {
        slice32_xor(&mut pos, &key.white);
        for r in (0..NR).rev() {
            let rk = &key.rounds[r];
            slice32_s(&mut pos, &rk.si2);
            slice32_cross(&mut pos, true);
            slice32_s(&mut pos, &rk.sim);
            slice32_trip_bow(&mut pos, c, true);
            slice32_bridges(&mut pos, rk, c, true);
            slice32_chord(&mut pos, true);
            slice32_s(&mut pos, &rk.si);
            slice32_xor(&mut pos, &rk.rk);
        }
    }
    slice32_store(&pos, blocks);
}
