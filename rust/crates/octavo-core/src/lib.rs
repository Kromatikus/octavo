//! # octavo-core — Rust port of Octavo (working name N2), phase 1
//!
//! **Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.**
//!
//! Byte-compatible with `sneak_n2.py` (SHA-256 19181bc1…e71eee): 128-byte block, 1024-bit seed,
//! 16 rounds, keyed SM4-affine S-boxes, SM4-field (0x1F5) mixes.
//!
//! Layers:
//! - [`Schedule`] / [`Cipher`]: raw block permutation (the `block_cipher` score vectors).
//! - [`formats`] (feature `formats`): v6 single-block AEAD, v7 movements, v9 rehearsal,
//!   étude block/movements, and the app HKDF key expansion.
#![cfg_attr(not(feature = "std"), no_std)]
// unsafe is confined to `hw` (CPU intrinsics behind runtime feature checks).
#![deny(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod affine;
pub mod backend;
pub mod bitslice;
pub mod gf;
#[cfg(all(target_arch = "x86_64", feature = "alloc"))]
pub mod hw;
#[cfg(all(target_arch = "x86_64", feature = "alloc"))]
pub mod simd;
pub mod iso;
pub mod round;
pub mod sbox;
pub mod schedule;
pub mod sponge;
#[cfg(feature = "zeroize")]
mod wipe;
#[cfg(feature = "alloc")]
pub mod sha_mb;

#[cfg(feature = "formats")]
pub mod formats;

pub use backend::{force_backend, selected_backend, Auto, BackendKind, CtScalar, CtSoft, SboxBackend};
#[cfg(feature = "table-backend")]
pub use backend::Table;
pub use schedule::Schedule;

pub const BLOCK_LEN: usize = 128;
pub const NF: usize = 16; // faces (staves)
pub const NB: usize = 8; // beats per face
pub const NR: usize = 16; // rounds
pub const NONCE_LEN: usize = 16;
pub const SEED_LEN: usize = 128;

/// SHA-256 of the Python reference this port follows.
pub const REFERENCE_SHA256: &str = "19181bc1623115c075dc5dee25edec388f5413466777d47b7f19fa66d1e71eee";

pub const HONEST_NOTE: &str =
    "Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.";

/// A keyed block cipher instance: schedule for (seed, nonce) plus an S-box backend.
pub struct Cipher<B: SboxBackend = Auto> {
    pub schedule: Schedule,
    backend: B,
    rounds: usize,
}

impl<B: SboxBackend> Cipher<B> {
    /// Full 16-round Octavo.
    pub fn new(seed: &[u8], nonce: &[u8; NONCE_LEN]) -> Self {
        Self::with_rounds(seed, nonce, NR)
    }
    /// Reduced rounds (études use 2, 4, 6; live Octavo is 16).
    pub fn with_rounds(seed: &[u8], nonce: &[u8], rounds: usize) -> Self {
        assert!(rounds >= 1 && rounds <= NR);
        let schedule = Schedule::new(seed, nonce);
        let backend = B::prepare(&schedule);
        Cipher { schedule, backend, rounds }
    }
    pub fn encrypt_block(&self, block: &mut [u8; BLOCK_LEN]) {
        self.backend.encrypt_blocks(&self.schedule, core::slice::from_mut(block), self.rounds)
    }
    pub fn decrypt_block(&self, block: &mut [u8; BLOCK_LEN]) {
        self.backend.decrypt_blocks(&self.schedule, core::slice::from_mut(block), self.rounds)
    }
    /// Encrypt many independent blocks (raw permutation, same schedule); engines may interleave them.
    pub fn encrypt_blocks(&self, blocks: &mut [[u8; BLOCK_LEN]]) {
        self.backend.encrypt_blocks(&self.schedule, blocks, self.rounds)
    }
    pub fn decrypt_blocks(&self, blocks: &mut [[u8; BLOCK_LEN]]) {
        self.backend.decrypt_blocks(&self.schedule, blocks, self.rounds)
    }
    pub fn rounds(&self) -> usize {
        self.rounds
    }
}
