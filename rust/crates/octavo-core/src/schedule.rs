//! Per-message schedule, derived from (seed, nonce) via StaffSponge(b"K", seed, nonce).
//! Squeeze order is identical to sneak_n2.Schedule.
//!
//! NOT constant time: the rejection sampling (invertible matrices, `below`, S2 != S) loops a
//! key-dependent number of times, exactly as the Python reference does. It runs once per
//! (seed, nonce), not per block.

use crate::affine::rank_rows;
use crate::sbox::KeyedSbox;
use crate::sponge::StaffSponge;
use crate::{BLOCK_LEN, NB, NF, NR};

#[derive(Clone)]
pub struct RoundKey {
    pub rk: [u8; BLOCK_LEN],
    pub s: KeyedSbox,
    pub s2: KeyedSbox,
    pub sh: [u8; NF],
    pub sv: [u8; NB],
    pub sigma: [[u8; NB]; NF],
    pub bridge: [u8; 64],
}

#[derive(Clone)]
pub struct Schedule {
    pub rounds: [RoundKey; NR],
    pub white: [u8; BLOCK_LEN],
}

fn invertible_mat(sp: &mut StaffSponge) -> [u8; 8] {
    loop {
        let m: [u8; 8] = sp.take();
        if rank_rows(&m) == 8 {
            return m;
        }
    }
}

impl Schedule {
    /// `seed`: key material (128 bytes for live Octavo / étude keys / app seeds).
    /// `nonce`: 16 bytes.
    pub fn new(seed: &[u8], nonce: &[u8]) -> Schedule {
        let mut sp = StaffSponge::new(b"K", seed, nonce);
        let rounds = core::array::from_fn(|_| {
            let rk: [u8; BLOCK_LEN] = sp.take();
            let a1 = invertible_mat(&mut sp);
            let a2 = invertible_mat(&mut sp);
            let [b1, b2]: [u8; 2] = sp.take();
            let s = KeyedSbox::new(&a1, b1, &a2, b2);
            let sh = core::array::from_fn(|_| sp.below(8));
            let sv = core::array::from_fn(|_| sp.below(16));
            let sigma = core::array::from_fn(|_| sp.perm::<NB>());
            let bridge = sp.perm::<64>();
            let s_tab = s.table();
            let s2 = loop {
                let a3 = invertible_mat(&mut sp);
                let a4 = invertible_mat(&mut sp);
                let [b3, b4]: [u8; 2] = sp.take();
                let cand = KeyedSbox::new(&a3, b3, &a4, b4);
                if cand.table() != s_tab {
                    break cand;
                }
            };
            RoundKey { rk, s, s2, sh, sv, sigma, bridge }
        });
        let white = sp.take();
        Schedule { rounds, white }
    }
}
