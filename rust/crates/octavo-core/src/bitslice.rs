//! Bitsliced, constant-time keyed S-box evaluation on up to 64 bytes at once.
//! 64 bytes are transposed into 8 u64 bit-planes (plane j = bit j of every lane), then the
//! affine maps, the GF(2^8)/0x1F5 inversion (x^254), and the output affine map are computed with
//! plain AND/XOR on whole planes. No tables, no data-dependent branches or addresses.

use crate::sbox::KeyedSbox;
use crate::affine::Mat8;

type Planes = [u64; 8];

/// Transpose the 8x8 bit matrix held in a u64 (byte i = row i): result byte j holds bit j of each row.
#[inline(always)]
fn t8x8(mut x: u64) -> u64 {
    let mut t;
    t = (x ^ (x >> 7)) & 0x00AA_00AA_00AA_00AA;
    x ^= t ^ (t << 7);
    t = (x ^ (x >> 14)) & 0x0000_CCCC_0000_CCCC;
    x ^= t ^ (t << 14);
    t = (x ^ (x >> 28)) & 0x0000_0000_F0F0_F0F0;
    x ^= t ^ (t << 28);
    x
}

#[inline(always)]
fn to_planes(b: &[u8; 64]) -> Planes {
    let mut p = [0u64; 8];
    for w in 0..8 {
        let word = u64::from_le_bytes(b[8 * w..8 * w + 8].try_into().unwrap());
        let t = t8x8(word);
        for j in 0..8 {
            p[j] |= ((t >> (8 * j)) & 0xff) << (8 * w);
        }
    }
    p
}

#[inline(always)]
fn from_planes(p: &Planes, b: &mut [u8; 64]) {
    for w in 0..8 {
        let mut t = 0u64;
        for j in 0..8 {
            t |= ((p[j] >> (8 * w)) & 0xff) << (8 * j);
        }
        b[8 * w..8 * w + 8].copy_from_slice(&t8x8(t).to_le_bytes());
    }
}

#[inline(always)]
fn m64(bit: u8) -> u64 {
    0u64.wrapping_sub((bit & 1) as u64)
}

/// y = M·x ⊕ c on planes.
#[inline(always)]
fn affine(m: &Mat8, c: u8, x: &Planes) -> Planes {
    let mut y = [0u64; 8];
    for i in 0..8 {
        let mut acc = m64(c >> i);
        for j in 0..8 {
            acc ^= m64(m.cols[j] >> i) & x[j];
        }
        y[i] = acc;
    }
    y
}

#[inline(always)]
fn gmul(a: &Planes, b: &Planes) -> Planes {
    let mut p = [0u64; 15];
    for i in 0..8 {
        for j in 0..8 {
            p[i + j] ^= a[i] & b[j];
        }
    }
    // reduce mod x^8 + x^7 + x^6 + x^5 + x^4 + x^2 + 1
    for k in (8..15).rev() {
        let v = p[k];
        let b = k - 8;
        p[b + 7] ^= v;
        p[b + 6] ^= v;
        p[b + 5] ^= v;
        p[b + 4] ^= v;
        p[b + 2] ^= v;
        p[b] ^= v;
    }
    [p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]]
}

#[inline(always)]
fn gsq(a: &Planes) -> Planes {
    // squaring is linear: (sum a_i x^i)^2 = sum a_i x^(2i); reduce as in gmul.
    let mut p = [0u64; 15];
    for i in 0..8 {
        p[2 * i] = a[i];
    }
    for k in (8..15).rev() {
        let v = p[k];
        let b = k - 8;
        p[b + 7] ^= v;
        p[b + 6] ^= v;
        p[b + 5] ^= v;
        p[b + 4] ^= v;
        p[b + 2] ^= v;
        p[b] ^= v;
    }
    [p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]]
}

#[inline(always)]
fn ginv(x: &Planes) -> Planes {
    let x3 = gmul(&gsq(x), x);
    let x7 = gmul(&gsq(&x3), x);
    let x15 = gmul(&gsq(&x7), x);
    let x31 = gmul(&gsq(&x15), x);
    let x63 = gmul(&gsq(&x31), x);
    let x127 = gmul(&gsq(&x63), x);
    gsq(&x127)
}

/// Apply the keyed S-box (or its inverse) to all 64 lanes in place.
pub fn sbox64(sb: &KeyedSbox, lanes: &mut [u8; 64], inverse: bool) {
    let x = to_planes(lanes);
    let y = if inverse {
        let (mi, ci, mo, co) = sb.inverse_parts();
        // SI(y) = Min^-1·(inv(Mout^-1·(y ⊕ cout)) ⊕ cin)  =  Min^-1·inv(Mout^-1·y ⊕ Mout^-1·cout) ⊕ Min^-1·cin
        let z = affine(mo, mo.apply(co), &x);
        affine(mi, mi.apply(ci), &ginv(&z))
    } else {
        affine(&sb.m_out, sb.c_out, &ginv(&affine(&sb.m_in, sb.c_in, &x)))
    };
    from_planes(&y, lanes);
}

/// Apply to an arbitrary-length slice (chunks of 64, short tail padded internally).
pub fn sbox_slice(sb: &KeyedSbox, xs: &mut [u8], inverse: bool) {
    for chunk in xs.chunks_mut(64) {
        let mut buf = [0u8; 64];
        buf[..chunk.len()].copy_from_slice(chunk);
        sbox64(sb, &mut buf, inverse);
        chunk.copy_from_slice(&buf[..chunk.len()]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bitsliced_matches_scalar() {
        let sb = KeyedSbox::new(&[0xa7, 0x4f, 0x9e, 0x3d, 0x7a, 0xf4, 0xe9, 0xd3], 0x5e, &[0x03, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80], 0xa9);
        for base in [0u16, 64, 128, 192] {
            let mut lanes: [u8; 64] = core::array::from_fn(|i| (base as usize + i) as u8);
            let orig = lanes;
            sbox64(&sb, &mut lanes, false);
            for i in 0..64 {
                assert_eq!(lanes[i], sb.fwd(orig[i]));
            }
            sbox64(&sb, &mut lanes, true);
            assert_eq!(lanes, orig);
        }
    }
}
