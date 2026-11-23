#![allow(dead_code)]
//! 8x8 bit matrices over GF(2), stored by COLUMNS so that application is a
//! branch-free masked XOR. Python convention: a matrix is 8 row masks and
//! output bit i = parity(row_i & x).

use crate::gf::mask;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mat8 {
    pub cols: [u8; 8],
}

impl Mat8 {
    pub const IDENTITY: Mat8 = Mat8 {
        cols: [1, 2, 4, 8, 16, 32, 64, 128],
    };

    /// Build from Python-style row masks.
    pub const fn from_rows(rows: [u8; 8]) -> Mat8 {
        let mut cols = [0u8; 8];
        let mut i = 0;
        while i < 8 {
            let mut j = 0;
            while j < 8 {
                cols[j] |= ((rows[i] >> j) & 1) << i;
                j += 1;
            }
            i += 1;
        }
        Mat8 { cols }
    }

    #[inline(always)]
    pub fn apply(&self, x: u8) -> u8 {
        let mut r = 0u8;
        let mut j = 0;
        while j < 8 {
            r ^= self.cols[j] & mask(x >> j);
            j += 1;
        }
        r
    }

    /// Matrix product self·other (apply `other` first).
    pub fn mul(&self, other: &Mat8) -> Mat8 {
        let mut cols = [0u8; 8];
        for j in 0..8 {
            cols[j] = self.apply(other.cols[j]);
        }
        Mat8 { cols }
    }

    /// Inverse by constant-time Gauss-Jordan. Schedule-time only. The
    /// caller must pass an invertible matrix; a singular input yields garbage
    /// rather than a data-dependent early exit.
    pub fn inverse(&self) -> Mat8 {
        let mut rows = [0u16; 8];
        for i in 0..8 {
            let mut r = 0u16;
            for j in 0..8 {
                r |= (((self.cols[j] >> i) & 1) as u16) << j;
            }
            rows[i] = r | (1u16 << (8 + i));
        }
        for col in 0..8 {
            for r in 0..8 {
                let missing = ((rows[col] >> col) & 1) ^ 1;
                let has = (rows[r] >> col) & 1;
                let in_range = if r > col { 1u16 } else { 0 };
                let do_swap = missing & has & in_range;
                let m = 0u16.wrapping_sub(do_swap);
                let t = (rows[col] ^ rows[r]) & m;
                rows[col] ^= t;
                rows[r] ^= t;
            }
            let pivot = rows[col];
            for k in 0..8 {
                let need = if k != col { (rows[k] >> col) & 1 } else { 0 };
                let m = 0u16.wrapping_sub(need);
                rows[k] ^= pivot & m;
            }
        }
        let mut out_rows = [0u8; 8];
        for i in 0..8 {
            out_rows[i] = (rows[i] >> 8) as u8;
        }
        Mat8::from_rows(out_rows)
    }
}
