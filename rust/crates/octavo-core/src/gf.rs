//! GF(2^8) arithmetic over the SM4 field polynomial 0x1F5 (x^8+x^7+x^6+x^5+x^4+x^2+1).
//! Everything here is branch-free and table-free (constant time for data-dependent inputs).

/// Expand bit 0 of `b` into an all-ones / all-zeros mask without branching.
#[inline(always)]
pub(crate) fn mask(b: u8) -> u8 {
    0u8.wrapping_sub(b & 1)
}

/// Multiply by x (i.e. by 2) modulo 0x1F5.
#[inline(always)]
pub fn xtime(a: u8) -> u8 {
    (a << 1) ^ (0xF5 & mask(a >> 7))
}

/// Constant-time multiplication in GF(2^8)/0x1F5.
#[inline(always)]
pub fn mul(mut a: u8, b: u8) -> u8 {
    let mut r = 0u8;
    let mut i = 0;
    while i < 8 {
        r ^= a & mask(b >> i);
        a = xtime(a);
        i += 1;
    }
    r
}

/// Squaring is GF(2)-linear; columns of the squaring matrix are (2^j)^2.
const SQ_COLS: [u8; 8] = {
    let mut c = [0u8; 8];
    let mut j = 0;
    while j < 8 {
        let e = 1u8 << j;
        c[j] = const_mul(e, e);
        j += 1;
    }
    c
};

pub(crate) const fn const_mul(mut a: u8, mut b: u8) -> u8 {
    let mut r = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            r ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0xF5;
        }
        b >>= 1;
    }
    r
}

#[inline(always)]
fn sq(x: u8) -> u8 {
    let mut r = 0u8;
    let mut j = 0;
    while j < 8 {
        r ^= SQ_COLS[j] & mask(x >> j);
        j += 1;
    }
    r
}

/// Constant-time inversion x -> x^254 (maps 0 to 0, matching the SM4/AES convention).
#[inline(always)]
pub fn inv(x: u8) -> u8 {
    let x2 = sq(x);
    let x3 = mul(x2, x);
    let x7 = mul(sq(x3), x);
    let x15 = mul(sq(x7), x);
    let x31 = mul(sq(x15), x);
    let x63 = mul(sq(x31), x);
    let x127 = mul(sq(x63), x);
    sq(x127)
}

/// Multiplicative inverse of 3 in this field (0xAC = 172).
pub const INV3: u8 = 172;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mul_matches_reference() {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(mul(a, b), const_mul(a, b));
            }
        }
    }
    #[test]
    fn inverse() {
        assert_eq!(inv(0), 0);
        for a in 1..=255u8 {
            assert_eq!(mul(a, inv(a)), 1, "a={a}");
        }
        assert_eq!(mul(3, INV3), 1);
    }
}
