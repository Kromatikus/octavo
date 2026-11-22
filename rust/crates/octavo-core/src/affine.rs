//! 8x8 bit matrices over GF(2), stored by COLUMNS so that application is a branch-free
//! masked XOR (constant time). Python convention: a matrix is 8 row masks and
//! output bit i = parity(row_i & x).

use crate::gf::mask;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mat8 {
    pub cols: [u8; 8],
}

impl Mat8 {
    pub const IDENTITY: Mat8 = Mat8 { cols: [1, 2, 4, 8, 16, 32, 64, 128] };

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

    /// Inverse by Gauss-Jordan on columns. Only called on matrices already known to be invertible
    /// (the schedule rejects singular ones, matching Python). Runs a fixed number of steps.
    pub fn inverse(&self) -> Mat8 {
        // Work on rows of [M | I]
        let mut rows = [0u16; 8];
        for i in 0..8 {
            let mut r = 0u16;
            for j in 0..8 {
                r |= (((self.cols[j] >> i) & 1) as u16) << j;
            }
            rows[i] = r | (1u16 << (8 + i));
        }
        for bit in 0..8 {
            // find pivot (key-derived data; schedule-time only)
            let mut piv = bit;
            while piv < 8 && (rows[piv] >> bit) & 1 == 0 {
                piv += 1;
            }
            assert!(piv < 8, "singular matrix");
            rows.swap(bit, piv);
            for k in 0..8 {
                if k != bit && (rows[k] >> bit) & 1 == 1 {
                    rows[k] ^= rows[bit];
                }
            }
        }
        let mut out_rows = [0u8; 8];
        for i in 0..8 {
            out_rows[i] = (rows[i] >> 8) as u8;
        }
        Mat8::from_rows(out_rows)
    }
}

/// GF(2) rank of 8 row masks — identical algorithm to sneak_n2.mat_invertible.
pub fn rank_rows(m: &[u8; 8]) -> u32 {
    let mut rows = *m;
    let mut rank = 0usize;
    for bit in 0..8 {
        let mut piv = None;
        for i in rank..8 {
            if (rows[i] >> bit) & 1 == 1 {
                piv = Some(i);
                break;
            }
        }
        let Some(p) = piv else { continue };
        rows.swap(rank, p);
        for i in 0..8 {
            if i != rank && (rows[i] >> bit) & 1 == 1 {
                rows[i] ^= rows[rank];
            }
        }
        rank += 1;
    }
    rank as u32
}
