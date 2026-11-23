#![allow(dead_code)]
//! GF(2^8) arithmetic over the SM4 field polynomial 0x1F5 (x^8+x^7+x^6+x^5+x^4+x^2+1).
//! Branch-free and table-free (constant time for data-dependent inputs).

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

/// Multiplicative inverse of 3 in this field (0xAC = 172).
pub const INV3: u8 = 172;

/// Square in GF(2^8)/0x1F5.
#[inline(always)]
pub fn square(a: u8) -> u8 {
    mul(a, a)
}

/// Multiplicative inverse via a^{254}, with inv(0) = 0. No tables, fixed steps.
#[inline(always)]
pub fn inv(a: u8) -> u8 {
    let x2 = square(a);
    let x4 = square(x2);
    let x8 = square(x4);
    let x16 = square(x8);
    let x32 = square(x16);
    let x64 = square(x32);
    let x128 = square(x64);
    // a^{254} = a^{128+64+32+16+8+4+2}
    mul(x128, mul(x64, mul(x32, mul(x16, mul(x8, mul(x4, x2))))))
}
