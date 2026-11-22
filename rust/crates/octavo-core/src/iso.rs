//! Field isomorphism between the SM4 field GF(2)[x]/0x1F5 and the AES field GF(2)[x]/0x11B,
//! plus helpers to express keyed S-boxes as AES-field affine·inverse·affine maps.
//!
//! phi: F(0x1F5) -> G(0x11B) is the GF(2)-linear map x^j -> g^j, where g = 0x23 is a root of
//! x^8+x^7+x^6+x^5+x^4+x^2+1 in G (the first such root; any of the 8 roots works). Then
//!     inv_F = phi^-1 · inv_G · phi,
//! so  S(x) = Mout·inv_F(Min·x ⊕ cin) ⊕ cout
//!          = (Mout·phi^-1) · inv_G( (phi·Min)·x ⊕ phi(cin) ) ⊕ cout,
//! which is exactly GF2P8AFFINEQB followed by GF2P8AFFINEINVQB.

use crate::affine::Mat8;
use crate::sbox::KeyedSbox;

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
        // evaluate x^8+x^7+x^6+x^5+x^4+x^2+1 at gg in G
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

/// AES S-box affine part: SubBytes(x) = A_AES·inv_G(x) ⊕ 0x63.
pub const A_AES: Mat8 = {
    let mut rows = [0u8; 8];
    let mut i = 0;
    while i < 8 {
        rows[i] = (1u8 << i) | (1u8 << ((i + 4) % 8)) | (1u8 << ((i + 5) % 8)) | (1u8 << ((i + 6) % 8)) | (1u8 << ((i + 7) % 8));
        i += 1;
    }
    Mat8::from_rows(rows)
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
    pub fn forward(sb: &KeyedSbox) -> AesForm {
        let phi_inv = PHI.inverse();
        AesForm { p_mat: PHI.mul(&sb.m_in), p: PHI.apply(sb.c_in), q_mat: sb.m_out.mul(&phi_inv), q: sb.c_out }
    }
    /// SI(y) = Min^-1·inv_F(Mout^-1·y ⊕ Mout^-1·cout) ⊕ Min^-1·cin
    pub fn inverse(sb: &KeyedSbox) -> AesForm {
        let phi_inv = PHI.inverse();
        let (mi, ci, mo, co) = sb.inverse_parts();
        AesForm {
            p_mat: PHI.mul(mo),
            p: PHI.apply(mo.apply(co)),
            q_mat: mi.mul(&phi_inv),
            q: mi.apply(ci),
        }
    }
    /// Scalar reference evaluation (tests only; uses a variable-time AES-field inverse).
    pub fn eval_ref(&self, x: u8) -> u8 {
        self.q_mat.apply(aes_inv_ref(self.p_mat.apply(x) ^ self.p)) ^ self.q
    }
}

pub(crate) fn aes_inv_ref(x: u8) -> u8 {
    // x^254 in G
    let mut r = 1u8;
    let mut b = x;
    let mut e = 254u32;
    while e > 0 {
        if e & 1 == 1 {
            r = aes_mul(r, b);
        }
        b = aes_mul(b, b);
        e >>= 1;
    }
    r
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gf;
    #[test]
    fn phi_is_field_isomorphism() {
        assert_eq!(ROOT, 0x23);
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(PHI.apply(gf::mul(a, b)), aes_mul(PHI.apply(a), PHI.apply(b)));
            }
            assert_eq!(PHI.apply(gf::inv(a)), aes_inv_ref(PHI.apply(a)));
        }
        // bijective
        let mut seen = [false; 256];
        for a in 0..=255u8 {
            seen[PHI.apply(a) as usize] = true;
        }
        assert!(seen.iter().all(|&s| s));
    }
    #[test]
    fn aes_affine_matches_known_sbox_points() {
        let sb = |x: u8| A_AES.apply(aes_inv_ref(x)) ^ 0x63;
        assert_eq!(sb(0x00), 0x63);
        assert_eq!(sb(0x01), 0x7c);
        assert_eq!(sb(0x53), 0xed);
        assert_eq!(sb(0xff), 0x16);
    }
    #[test]
    fn aes_form_exhaustive_on_many_sboxes() {
        let sch = crate::Schedule::new(&[0x5cu8; 128], &[9u8; 16]);
        for rk in sch.rounds.iter() {
            for sb in [&rk.s, &rk.s2] {
                let (f, i) = (AesForm::forward(sb), AesForm::inverse(sb));
                for x in 0..=255u8 {
                    assert_eq!(f.eval_ref(x), sb.fwd(x));
                    assert_eq!(i.eval_ref(x), sb.inv(x));
                }
            }
        }
    }
}
