//! Field isomorphism between GF(2)[x]/0x1F5 and the AES field GF(2)[x]/0x11B,
//! plus helpers to express keyed S-boxes as AES-field affine·inverse·affine maps
//! for GF2P8AFFINEQB / GF2P8AFFINEINVQB. The data-path field stays 0x1F5;
//! this iso is only used to drive the AES-field inversion inside GFNI.

use crate::affine::Mat8;
use crate::sbox_aff::KeyedSbox;

const fn gmul_poly(mut a: u8, mut b: u8, low: u8) -> u8 {
    let mut r = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            r ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= low;
        }
        b >>= 1;
    }
    r
}
pub(crate) const fn aes_mul(a: u8, b: u8) -> u8 {
    gmul_poly(a, b, 0x1B)
}

/// Smallest root of the SM4 field polynomial inside the AES field.
pub const ROOT: u8 = {
    let mut g = 2u16;
    let mut found = 0u8;
    while g < 256 {
        let gg = g as u8;
        let mut pw = [0u8; 9];
        pw[0] = 1;
        let mut j = 1;
        while j < 9 {
            pw[j] = aes_mul(pw[j - 1], gg);
            j += 1;
        }
        let v = pw[8] ^ pw[7] ^ pw[6] ^ pw[5] ^ pw[4] ^ pw[2] ^ pw[0];
        if v == 0 {
            found = gg;
            break;
        }
        g += 1;
    }
    found
};

/// phi as a column matrix: column j = ROOT^j in G.
pub const PHI: Mat8 = {
    let mut cols = [0u8; 8];
    let mut p = 1u8;
    let mut j = 0;
    while j < 8 {
        cols[j] = p;
        p = aes_mul(p, ROOT);
        j += 1;
    }
    Mat8 { cols }
};

/// One S-box direction as  y = Q·inv_G(P·x ⊕ p) ⊕ q  over the AES field.
#[derive(Clone, Copy, Debug)]
pub struct AesForm {
    pub p_mat: Mat8,
    pub p: u8,
    pub q_mat: Mat8,
    pub q: u8,
}

impl AesForm {
    fn phi_inv() -> Mat8 {
        static P: std::sync::OnceLock<Mat8> = std::sync::OnceLock::new();
        *P.get_or_init(|| PHI.inverse())
    }

    pub fn forward(sb: &KeyedSbox) -> AesForm {
        let phi_inv = Self::phi_inv();
        AesForm {
            p_mat: PHI.mul(&sb.m_in),
            p: PHI.apply(sb.c_in),
            q_mat: sb.m_out.mul(&phi_inv),
            q: sb.c_out,
        }
    }
    pub fn inverse(sb: &KeyedSbox) -> AesForm {
        let phi_inv = Self::phi_inv();
        let (mi, ci, mo, co) = sb.inverse_parts();
        AesForm {
            p_mat: PHI.mul(mo),
            p: PHI.apply(mo.apply(co)),
            q_mat: mi.mul(&phi_inv),
            q: mi.apply(ci),
        }
    }
}

/// GFNI matrix operand: qword byte (7-i) holds the row for output bit i.
pub fn gfni_qword(m: &Mat8) -> u64 {
    let mut q = 0u64;
    for i in 0..8 {
        let mut row = 0u8;
        for j in 0..8 {
            row |= ((m.cols[j] >> i) & 1) << j;
        }
        q |= (row as u64) << (8 * (7 - i));
    }
    q
}

pub fn mulc_qword(c: u8) -> u64 {
    let mut cols = [0u8; 8];
    for j in 0..8 {
        cols[j] = crate::gf::const_mul(c, 1 << j);
    }
    gfni_qword(&Mat8 { cols })
}

pub fn rotl_qword(k: usize) -> u64 {
    let mut cols = [0u8; 8];
    for j in 0..8 {
        cols[j] = 1u8 << ((j + k) % 8);
    }
    gfni_qword(&Mat8 { cols })
}
