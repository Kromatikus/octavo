//! Best-effort wiping of secret key material on drop (feature `zeroize`).
//!
//! The schedule, the hardware/SIMD precompute tables and the format context are flat plain-data
//! values (byte and u64 arrays, no pointers) for which all-zero bytes are a valid value, so they
//! are overwritten with `zeroize::zeroize_flat_type` (volatile writes + a compiler fence).
//! Limits: copies the compiler made earlier (moves, registers, spilled stack) are not reachable.
#![allow(unsafe_code)]

/// Zero a flat plain-data value in place.
/// Only call this on types made of integers / integer arrays (no references, Box, Vec, enums
/// with niches); every caller below satisfies that.
#[inline(never)]
pub(crate) fn wipe_flat<T: Copy>(x: &mut T) {
    // SAFETY: T: Copy has no Drop glue and owns no heap memory; every caller passes integer-only
    // structs/arrays, for which the all-zero bit pattern is valid.
    unsafe { zeroize::zeroize_flat_type(x as *mut T) }
}

impl Drop for crate::schedule::Schedule {
    fn drop(&mut self) {
        for rk in self.rounds.iter_mut() {
            wipe_flat(&mut rk.rk);
            wipe_flat(&mut rk.s);
            wipe_flat(&mut rk.s2);
            wipe_flat(&mut rk.sh);
            wipe_flat(&mut rk.sv);
            wipe_flat(&mut rk.sigma);
            wipe_flat(&mut rk.bridge);
        }
        wipe_flat(&mut self.white);
    }
}
