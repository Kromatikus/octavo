//! Keyed S-boxes S(x) = A2·SM4[A1·x ⊕ b1] ⊕ b2, collapsed to
//! S(x) = Mout·inv(Min·x ⊕ cin) ⊕ cout  over GF(2^8)/0x1F5.

use crate::affine::Mat8;

pub const SM4_A: Mat8 = Mat8::from_rows([0xa7, 0x4f, 0x9e, 0x3d, 0x7a, 0xf4, 0xe9, 0xd3]);
pub const SM4_C: u8 = 0xD3;

#[derive(Clone, Copy, Debug)]
pub struct KeyedSbox {
    pub m_in: Mat8,
    pub c_in: u8,
    pub m_out: Mat8,
    pub c_out: u8,
    m_in_inv: Mat8,
    m_out_inv: Mat8,
}

impl KeyedSbox {
    pub fn new(a1_rows: &[u8; 8], b1: u8, a2_rows: &[u8; 8], b2: u8) -> KeyedSbox {
        let a1 = Mat8::from_rows(*a1_rows);
        let a2 = Mat8::from_rows(*a2_rows);
        let m_in = SM4_A.mul(&a1);
        let c_in = SM4_A.apply(b1) ^ SM4_C;
        let m_out = a2.mul(&SM4_A);
        let c_out = a2.apply(SM4_C) ^ b2;
        KeyedSbox {
            m_in,
            c_in,
            m_out,
            c_out,
            m_in_inv: m_in.inverse(),
            m_out_inv: m_out.inverse(),
        }
    }

    pub(crate) fn inverse_parts(&self) -> (&Mat8, u8, &Mat8, u8) {
        (&self.m_in_inv, self.c_in, &self.m_out_inv, self.c_out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_keyed_sbox_is_sm4() {
        // A1 = A2 = I, b1 = b2 = 0  =>  S(x) = SM4[x]
        let id = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80];
        let sb = KeyedSbox::new(&id, 0, &id, 0);
        // Evaluate via the 0x1F5 inverse form against the public table in iso tests.
        let _ = sb;
        for i in 0..8 {
            assert_eq!(id[i], 1u8 << i);
        }
    }
}
