//! Constant-time key-schedule helpers for N3 format 0x1A/0x1B (prefix SN3C/).
//! No key-dependent branches, loop counts, or addresses.
//! Homemade; for real secrets use AES-GCM-SIV, age, or libsodium.

use crate::gf;
use crate::sbox_aff::KeyedSbox;
#[cfg(test)]
use crate::SM4_SBOX;

pub(crate) const GL2_LEN: usize = 72; // 4 (L) + 4 (U) + 8*8 (row-perm tags)
pub(crate) const PERM64_LEN: usize = 64 * 8;

#[inline(always)]
pub(crate) fn ct_eq_u8(a: u8, b: u8) -> u8 {
    // 0xFF if a == b, else 0.
    let x = a ^ b;
    ((x as u16).wrapping_sub(1) >> 8) as u8
}

#[inline(always)]
fn u64_gt(a: u64, b: u64) -> u8 {
    // 1 if a > b, else 0. Underflow of (b - a) as u128 sets bit 127.
    (((b as u128).wrapping_sub(a as u128)) >> 127) as u8
}

#[inline(always)]
fn u8_gt(a: u8, b: u8) -> u8 {
    (((b as u16).wrapping_sub(a as u16)) >> 15) as u8
}

#[inline(always)]
fn ct_gt_tag(a_tag: u64, a_i: u8, b_tag: u64, b_i: u8) -> u8 {
    let tag_gt = u64_gt(a_tag, b_tag);
    let tag_lt = u64_gt(b_tag, a_tag);
    let tag_eq = 1 ^ tag_gt ^ tag_lt;
    let idx_gt = u8_gt(a_i, b_i);
    tag_gt | (tag_eq & idx_gt)
}

#[inline(always)]
fn ct_cond_swap_u64_at(a: &mut [u64], i: usize, l: usize, swap: u8) {
    let m = 0u64.wrapping_sub(swap as u64);
    let t = (a[i] ^ a[l]) & m;
    a[i] ^= t;
    a[l] ^= t;
}

#[inline(always)]
fn ct_cond_swap_u8_at(a: &mut [u8], i: usize, l: usize, swap: u8) {
    let m = swap.wrapping_neg();
    let t = (a[i] ^ a[l]) & m;
    a[i] ^= t;
    a[l] ^= t;
}

/// Bitonic sort of (tag, original index). Returns a permutation: out[i] is the
/// original index that lands in position i (sorted by tag, then index).
pub(crate) fn shuffle_from_tags<const N: usize>(tags: &[u64; N]) -> [u8; N] {
    debug_assert!(N.is_power_of_two() && N > 0 && N <= 256);
    let mut tag = *tags;
    let mut idx = [0u8; N];
    for i in 0..N {
        idx[i] = i as u8;
    }
    let mut k = 2usize;
    while k <= N {
        let mut j = k / 2;
        while j > 0 {
            for i in 0..N {
                let l = i ^ j;
                if l > i {
                    let upward = (i & k) == 0;
                    let gt_al = ct_gt_tag(tag[i], idx[i], tag[l], idx[l]);
                    let gt_la = ct_gt_tag(tag[l], idx[l], tag[i], idx[i]);
                    let swap = if upward { gt_al } else { gt_la };
                    ct_cond_swap_u64_at(&mut tag, i, l, swap);
                    ct_cond_swap_u8_at(&mut idx, i, l, swap);
                }
            }
            j /= 2;
        }
        k *= 2;
    }
    idx
}

pub(crate) fn tags_from_bytes<const N: usize>(bytes: &[u8]) -> [u64; N] {
    debug_assert_eq!(bytes.len(), N * 8);
    let mut tags = [0u64; N];
    for i in 0..N {
        let mut t = 0u64;
        for k in 0..8 {
            t = (t << 8) | bytes[8 * i + k] as u64;
        }
        tags[i] = t;
    }
    tags
}

/// Unit lower-triangular 8×8 over GF(2). Bits fill entries (i, j) for j < i,
/// row-major, least bit of `bits` first. Diagonal is 1, strictly-upper is 0.
pub(crate) fn unit_lower(bits: u32) -> [u8; 8] {
    let mut rows = [0u8; 8];
    let mut k = 0u32;
    for i in 0..8 {
        let mut row = 1u8 << i;
        for j in 0..i {
            row |= (((bits >> k) & 1) as u8) << j;
            k += 1;
        }
        rows[i] = row;
    }
    rows
}

/// Unit upper-triangular 8×8 over GF(2). Bits fill (i, j) for j > i, row-major.
pub(crate) fn unit_upper(bits: u32) -> [u8; 8] {
    let mut rows = [0u8; 8];
    let mut k = 0u32;
    for i in 0..8 {
        let mut row = 1u8 << i;
        for j in (i + 1)..8 {
            row |= (((bits >> k) & 1) as u8) << j;
            k += 1;
        }
        rows[i] = row;
    }
    rows
}

pub(crate) fn bitmat_mul(a: &[u8; 8], b: &[u8; 8]) -> [u8; 8] {
    let mut c = [0u8; 8];
    for i in 0..8 {
        let mut acc = 0u8;
        for k in 0..8 {
            let m = 0u8.wrapping_sub((a[i] >> k) & 1);
            acc ^= b[k] & m;
        }
        c[i] = acc;
    }
    c
}

#[cfg(test)]
pub(crate) fn bitmat_apply_ct(rows: &[u8; 8], x: u8) -> u8 {
    let mut out = 0u8;
    for i in 0..8 {
        out |= ((rows[i] & x).count_ones() as u8 & 1) << i;
    }
    out
}

fn load_u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// Rejection-free invertible 8×8 over GF(2): A = P · L · U, with L, U unit
/// triangular and P a row permutation from a tag sort.
pub(crate) fn gl2_from_bytes(bytes: &[u8; GL2_LEN]) -> [u8; 8] {
    let l = unit_lower(load_u32_le(&bytes[0..4]));
    let u = unit_upper(load_u32_le(&bytes[4..8]));
    let lu = bitmat_mul(&l, &u);
    let tags = tags_from_bytes::<8>(&bytes[8..72]);
    let perm = shuffle_from_tags(&tags);
    let mut out = [0u8; 8];
    for i in 0..8 {
        let mut row = 0u8;
        for k in 0..8 {
            row |= lu[k] & ct_eq_u8(k as u8, perm[i]);
        }
        out[i] = row;
    }
    out
}

#[cfg(test)]
fn ct_load256(table: &[u8; 256], idx: u8) -> u8 {
    let mut acc = 0u8;
    for i in 0..256 {
        acc |= table[i] & ct_eq_u8(i as u8, idx);
    }
    acc
}

/// Build forward and inverse 256-byte tables from the affine form
/// S(x) = Mout·inv(Min·x ⊕ cin) ⊕ cout over GF(2^8)/0x1F5, which is exactly
/// the keyed SM4 map. The input x (or y) is a public counter; the field
/// inverse is table-free and constant-time. Bit-identical to the old
/// 256×256 masked-scan construction, but much faster, and with no HashSet.
pub(crate) fn tables_from_keyed(ks: &KeyedSbox) -> ([u8; 256], [u8; 256]) {
    let mut fwd = [0u8; 256];
    for x in 0..256 {
        let u = ks.m_in.apply(x as u8) ^ ks.c_in;
        fwd[x] = ks.m_out.apply(gf::inv(u)) ^ ks.c_out;
    }
    let (minv, cin, mout_inv, cout) = ks.inverse_parts();
    let mut inv = [0u8; 256];
    for y in 0..256 {
        // x = Min^{-1} · (inv(Mout^{-1}·(y ⊕ cout)) ⊕ cin)
        let u = mout_inv.apply((y as u8) ^ cout);
        inv[y] = minv.apply(gf::inv(u) ^ cin);
    }
    (fwd, inv)
}

pub(crate) fn keyed_sbox_ct(a1: &[u8; 8], b1: u8, a2: &[u8; 8], b2: u8) -> ([u8; 256], [u8; 256]) {
    tables_from_keyed(&KeyedSbox::new(a1, b1, a2, b2))
}

/// Previous masked-scan construction, kept so tests can prove bit-identity.
#[cfg(test)]
pub(crate) fn keyed_sbox_ct_scan(a1: &[u8; 8], b1: u8, a2: &[u8; 8], b2: u8) -> ([u8; 256], [u8; 256]) {
    let mut fwd = [0u8; 256];
    for x in 0..256 {
        let inner = bitmat_apply_ct(a1, x as u8) ^ b1;
        let y = bitmat_apply_ct(a2, ct_load256(&SM4_SBOX, inner)) ^ b2;
        fwd[x] = y;
    }
    let mut inv = [0u8; 256];
    for y in 0..256 {
        let mut xout = 0u8;
        for x in 0..256 {
            xout |= (x as u8) & ct_eq_u8(fwd[x], y as u8);
        }
        inv[y] = xout;
    }
    (fwd, inv)
}

/// 1 if tables are equal, else 0. Branchless.
pub(crate) fn ct_tables_equal(a: &[u8; 256], b: &[u8; 256]) -> u8 {
    let mut acc = 0u8;
    for i in 0..256 {
        acc |= a[i] ^ b[i];
    }
    (((acc as u16).wrapping_sub(1)) >> 8) as u8
}

/// Smallest d in {0,1,2,3} such that (sm ⊕ d) differs from both s and s2.
/// Always tries all four, then constant-time-selects the first that works.
pub(crate) fn sbox_distinct_delta(s: &[u8; 256], s2: &[u8; 256], sm: &[u8; 256]) -> u8 {
    let mut chosen = 3u8;
    let mut have = 0u8;
    for d in 0..4u8 {
        let mut acc_s = 0u8;
        let mut acc_s2 = 0u8;
        for i in 0..256 {
            let y = sm[i] ^ d;
            acc_s |= y ^ s[i];
            acc_s2 |= y ^ s2[i];
        }
        let ne_s = 1 ^ ((((acc_s as u16).wrapping_sub(1)) >> 8) as u8);
        let ne_s2 = 1 ^ ((((acc_s2 as u16).wrapping_sub(1)) >> 8) as u8);
        let ok = ne_s & ne_s2;
        let take = ok & (1 ^ have);
        let m = take.wrapping_neg();
        chosen = (d & m) | (chosen & !m);
        have |= ok;
    }
    chosen
}

/// Inverse of a 64-permutation with public-address stores only.
pub(crate) fn invert_perm64_ct(p: &[u8; 64]) -> [u8; 64] {
    let mut inv = [0u8; 64];
    for dest in 0..64 {
        let mut val = 0u8;
        for i in 0..64 {
            val |= (i as u8) & ct_eq_u8(p[i], dest as u8);
        }
        inv[dest] = val;
    }
    inv
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitmat_invertible;

    #[test]
    fn shuffle_is_perm_and_sorts() {
        let mut tags = [0u64; 8];
        for i in 0..8 {
            tags[i] = 1000 - 10 * i as u64;
        }
        let p = shuffle_from_tags(&tags);
        let mut seen = [false; 8];
        for i in 0..8 {
            seen[p[i] as usize] = true;
        }
        assert!(seen.iter().all(|&s| s));
        for i in 1..8 {
            assert!(tags[p[i] as usize] > tags[p[i - 1] as usize]);
        }
        // identity tags (ties broken by index) stay in order
        let id = shuffle_from_tags(&[7u64; 8]);
        assert_eq!(id, [0, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn tables_match_scan_and_sm4() {
        // Identity affine → public SM4 table, and inverse is a left inverse.
        let id = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80];
        let (fwd, inv) = keyed_sbox_ct(&id, 0, &id, 0);
        assert_eq!(fwd, crate::SM4_SBOX);
        for x in 0..256 {
            assert_eq!(inv[fwd[x] as usize], x as u8);
        }
        // Random-looking GL(2) bytes: formula tables match the scan construction.
        let mut raw = [0u8; GL2_LEN];
        for i in 0..GL2_LEN {
            raw[i] = (i as u8).wrapping_mul(19).wrapping_add(7);
        }
        let a1 = gl2_from_bytes(&raw);
        for i in 0..GL2_LEN {
            raw[i] = raw[i].wrapping_add(11);
        }
        let a2 = gl2_from_bytes(&raw);
        let (f1, i1) = keyed_sbox_ct(&a1, 0xA5, &a2, 0x3C);
        let (f2, i2) = keyed_sbox_ct_scan(&a1, 0xA5, &a2, 0x3C);
        assert_eq!(f1, f2);
        assert_eq!(i1, i2);
        assert_eq!(gf::mul(3, gf::inv(3)), 1);
        assert_eq!(gf::inv(0), 0);
        assert_eq!(gf::inv(3), crate::gf::INV3);
    }

    #[test]
    fn gl2_always_invertible_and_lu_unit() {
        let l = unit_lower(0x0A5A_5A5A);
        let u = unit_upper(0x3C3C_3C3C);
        assert_eq!(l[0], 1);
        assert_eq!(u[7], 0x80);
        assert!(bitmat_invertible(&l));
        assert!(bitmat_invertible(&u));
        assert!(bitmat_invertible(&bitmat_mul(&l, &u)));
        for n in 0..200u32 {
            let mut b = [0u8; GL2_LEN];
            for i in 0..GL2_LEN {
                b[i] = n.wrapping_mul(17).wrapping_add(i as u32).wrapping_mul(0x9E) as u8;
            }
            let a = gl2_from_bytes(&b);
            assert!(bitmat_invertible(&a), "singular at n={n}");
        }
    }
}
