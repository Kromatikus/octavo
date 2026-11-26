//! SN3C/ AEAD (fix2): a nonce-misuse-resistant, SIV-style mode over the 1024-bit
//! (128-byte) N3 block cipher, with a PMAC-style parallel tag. Homemade; for real secrets
//! use AES-GCM-SIV, age, or libsodium.
//!
//! Construction ("N3-PMAC-SIV", lab format 0x1C):
//! * The underlying block cipher is still fix1 (FORMAT_BYTE 0x1B). The authenticated
//!   mode uses format 0x1C so blobs cannot be confused with fix1's 0x1B CMAC-SIV.
//!   This tree does not implement the old CMAC-S2V mode; open 0x1B blobs with fix1.
//! * Key derivation: from the 128-byte master seed, two 128-byte subkeys
//!   `seed_mac`, `seed_enc` = SHA-256-expand("SN3C/" || 0x1C || "AEAD-KDF" || label || ctr || seed),
//!   label 'M' / 'E'. Each keys an N3 instance with a fixed, distinct cipher nonce
//!   ("SN3C/AEAD-MAC" / "SN3C/AEAD-ENC", zero padded). Key setup (~1.5 ms x 2) happens once
//!   per master key, not per message.
//! * Transcript (unique length-prefix encoding, streamed, never fully allocated):
//!     u64le(|H|) || H || u64le(|AD|) || AD || u64le(16) || nonce || u64le(|M|) || M
//!   where H = "SN3C/" || 0x1C. This is the only string that is MACed. Minimum length is
//!   54 bytes, so the PMAC always has at least one (usually partial) block.
//! * MAC: PMAC over 128-byte blocks with E_mac, using Gray-code offsets in GF(2^1024)
//!   mod x^1024 + x^19 + x^6 + x + 1 (same irreducible as fix1 CMAC).
//!     L = E_mac(0);  L[j] = x^j L  (dbl applied j times);  L[0] = L.
//!     Δ_0 = L[1] = 2L;
//!     for k >= 1, Δ_k = Δ_{k-1} ⊕ L[ntz(k+1)+1]
//!       (closed form: Δ_k = XOR_{i=1}^{k+1} L[ntz(i)+1]).
//!     Final masks: K_full = 3L = L ⊕ 2L,  K_part = 5L = L ⊕ 4L.
//!     Middle full blocks 0..n-2 are encrypted through the batch-64 path:
//!       Σ ^= E_mac(M_i ⊕ Δ_i).
//!     Last full:   Σ ^= last ⊕ Δ_{n-1} ⊕ K_full.
//!     Last partial: Σ ^= pad10*(last) ⊕ Δ_{n-1} ⊕ K_part.
//!     tag_block = E_mac(Σ);  tag = tag_block[0..32].
//! * Encryption: CTR with E_enc, already on the batch-64 path; counter block i =
//!   tag(32) || "SN3C/CTR" || zeros || u64le(i) at bytes 120..128. Keystream XOR
//!   message; no padding.
//! * Blob: "SN3C/" (5) || 0x1C (1) || nonce (16) || tag (32) || ciphertext (len = msg len).
//!   Overhead is 54 bytes, same as fix1. Open: strict parse (0x1B is rejected as BadFormat),
//!   CTR-decrypt, recompute the tag, constant-time compare of the 32-byte tag; on failure
//!   the plaintext buffer is wiped and only `AuthFailed` is returned.
//!
//! 3L/5L (rather than 2L/4L) are used as final masks so a single full-block transcript
//! does not cancel Δ_0 = 2L down to the raw message block.

use crate::{Backend, Cipher, BLOCK_LEN, NONCE_LEN, SEED_LEN, SPONGE_PREFIX};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// AEAD format byte for this working copy. Distinct from the block-cipher FORMAT_BYTE (0x1B).
pub const AEAD_FORMAT: u8 = 0x1C;
pub const TAG_LEN: usize = 32;
pub const AEAD_NONCE_LEN: usize = 16;
pub const HEADER_LEN: usize = 6; // "SN3C/" || format byte
pub const OVERHEAD: usize = HEADER_LEN + AEAD_NONCE_LEN + TAG_LEN; // 54
/// Largest accepted message / ciphertext (1 GiB). Longer blobs are rejected as `TooLong`.
pub const MAX_MSG_LEN: usize = 1 << 30;
const CTR_DOMAIN: &[u8; 8] = b"SN3C/CTR";
const MAC_CIPHER_NONCE: [u8; NONCE_LEN] = *b"SN3C/AEAD-MAC\0\0\0";
const ENC_CIPHER_NONCE: [u8; NONCE_LEN] = *b"SN3C/AEAD-ENC\0\0\0";
const BATCH: usize = 64;
/// L[0..=64] covers ntz(i)+1 for every 1-based block index that 1 GiB can produce.
const LPOW: usize = 65;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadError {
    /// Blob shorter than the 54-byte header + nonce + tag.
    TooShort,
    /// Ciphertext longer than MAX_MSG_LEN.
    TooLong,
    /// First five bytes are not "SN3C/".
    BadPrefix,
    /// Format byte is not 0x1C.
    BadFormat,
    /// Tag mismatch (tampering, wrong key, wrong AD, truncation inside the ciphertext).
    AuthFailed,
}

impl core::fmt::Display for AeadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            AeadError::TooShort => "blob too short",
            AeadError::TooLong => "blob too long",
            AeadError::BadPrefix => "bad prefix (expected SN3C/)",
            AeadError::BadFormat => "unsupported format byte",
            AeadError::AuthFailed => "authentication failed",
        };
        f.write_str(s)
    }
}
impl std::error::Error for AeadError {}

/// Parsed view of a blob (no authentication yet).
#[derive(Debug, Clone, Copy)]
pub struct Parsed<'a> {
    pub nonce: &'a [u8; AEAD_NONCE_LEN],
    pub tag: &'a [u8; TAG_LEN],
    pub ciphertext: &'a [u8],
}

/// Strict, panic-free parser.
pub fn parse_blob(blob: &[u8]) -> Result<Parsed<'_>, AeadError> {
    if blob.len() < OVERHEAD {
        return Err(AeadError::TooShort);
    }
    if blob.len() - OVERHEAD > MAX_MSG_LEN {
        return Err(AeadError::TooLong);
    }
    let (hdr, rest) = blob.split_at(HEADER_LEN);
    if &hdr[..5] != SPONGE_PREFIX {
        return Err(AeadError::BadPrefix);
    }
    if hdr[5] != AEAD_FORMAT {
        return Err(AeadError::BadFormat);
    }
    let (nonce, rest) = rest.split_at(AEAD_NONCE_LEN);
    let (tag, ciphertext) = rest.split_at(TAG_LEN);
    let nonce: &[u8; AEAD_NONCE_LEN] = nonce.try_into().map_err(|_| AeadError::TooShort)?;
    let tag: &[u8; TAG_LEN] = tag.try_into().map_err(|_| AeadError::TooShort)?;
    Ok(Parsed { nonce, tag, ciphertext })
}

type Block = [u8; BLOCK_LEN];

/// Doubling in GF(2^1024), big-endian bit order (CMAC convention), constant time.
#[inline]
pub(crate) fn dbl(b: &Block) -> Block {
    let mut out = [0u8; BLOCK_LEN];
    let msb = b[0] >> 7;
    for i in 0..BLOCK_LEN {
        let next = if i + 1 < BLOCK_LEN { b[i + 1] >> 7 } else { 0 };
        out[i] = (b[i] << 1) | next;
    }
    let mask = 0u8.wrapping_sub(msb);
    // x^19 + x^6 + x + 1 = 0x08_00_43 in the last three bytes
    out[BLOCK_LEN - 1] ^= 0x43 & mask;
    out[BLOCK_LEN - 3] ^= 0x08 & mask;
    out
}

#[inline]
fn xor_into(a: &mut Block, b: &Block) {
    for (x, y) in a.iter_mut().zip(b.iter()) {
        *x ^= *y;
    }
}

fn xor_blocks(a: &Block, b: &Block) -> Block {
    let mut o = *a;
    xor_into(&mut o, b);
    o
}

fn kdf(seed: &[u8; SEED_LEN], label: u8) -> [u8; SEED_LEN] {
    let mut out = [0u8; SEED_LEN];
    for (ctr, chunk) in out.chunks_mut(32).enumerate() {
        let mut h = Sha256::new();
        h.update(SPONGE_PREFIX);
        h.update([AEAD_FORMAT]);
        h.update(b"AEAD-KDF");
        h.update([label]);
        h.update((ctr as u32).to_be_bytes());
        h.update(seed);
        chunk.copy_from_slice(&h.finalize());
    }
    out
}

pub struct Aead {
    mac: Cipher,
    enc: Cipher,
    lpow: [Block; LPOW],
    k_full: Block,
    k_part: Block,
    /// Worker threads for the independent PMAC / CTR block batches (1 = single-threaded).
    threads: usize,
    /// Messages shorter than this stay single-threaded.
    par_min: usize,
}

/// Messages below this size stay single-threaded (thread start-up would cost more than it saves).
const PAR_MIN_DEFAULT: usize = 256 * 1024;
/// Default and maximum worker count when `N3_THREADS` is unset.
const MAX_DEFAULT_THREADS: usize = 8;

/// Thread count: `N3_THREADS` (a positive integer) if set, else the number of CPUs, at most 8.
/// The count never changes the output bytes.
pub fn default_threads() -> usize {
    if let Ok(v) = std::env::var("N3_THREADS") {
        if let Ok(n) = v.trim().parse::<usize>() {
            if n >= 1 {
                return n.min(256);
            }
        }
    }
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1).min(MAX_DEFAULT_THREADS)
}

impl Aead {
    pub fn new(seed: &[u8; SEED_LEN]) -> Self {
        Self::with_backend(seed, Backend::detect()).expect("detected backend is supported")
    }

    pub fn with_backend(seed: &[u8; SEED_LEN], backend: Backend) -> Result<Self, String> {
        let mut sm = kdf(seed, b'M');
        let mut se = kdf(seed, b'E');
        let mac = Cipher::with_backend(&sm, &MAC_CIPHER_NONCE, backend)?;
        let enc = Cipher::with_backend(&se, &ENC_CIPHER_NONCE, backend)?;
        wipe(&mut sm);
        wipe(&mut se);
        let l = mac.encrypt_block(&[0u8; BLOCK_LEN]);
        let mut lpow = [[0u8; BLOCK_LEN]; LPOW];
        lpow[0] = l;
        for j in 1..LPOW {
            lpow[j] = dbl(&lpow[j - 1]);
        }
        let k_full = xor_blocks(&lpow[0], &lpow[1]); // 3L
        let k_part = xor_blocks(&lpow[0], &lpow[2]); // 5L
        Ok(Aead { mac, enc, lpow, k_full, k_part, threads: default_threads(), par_min: PAR_MIN_DEFAULT })
    }

    pub fn backend(&self) -> Backend {
        self.mac.backend()
    }

    /// Set the worker-thread count (1 = single-threaded). Output bytes do not depend on it.
    pub fn with_threads(mut self, n: usize) -> Self {
        self.threads = n.max(1);
        self
    }

    pub fn threads(&self) -> usize {
        self.threads
    }

    /// Override the small-message cutoff (tests and benches only).
    #[doc(hidden)]
    pub fn with_par_min(mut self, bytes: usize) -> Self {
        self.par_min = bytes;
        self
    }

    /// Threads actually used for `len` bytes: 1 for small inputs, never more than one per batch.
    fn eff_threads(&self, len: usize) -> usize {
        if self.threads <= 1 || len < self.par_min {
            return 1;
        }
        self.threads.min(len / (BATCH * BLOCK_LEN)).max(1)
    }

    /// PMAC over the length-prefixed transcript of (header, AD, nonce, message).
    fn pmac_transcript(&self, ad: &[u8], nonce: &[u8; AEAD_NONCE_LEN], msg: &[u8]) -> Block {
        let t = self.eff_threads(msg.len());
        if t > 1 {
            return self.pmac_transcript_par(ad, nonce, msg, t);
        }
        let total = 8 + HEADER_LEN + 8 + ad.len() + 8 + AEAD_NONCE_LEN + 8 + msg.len();
        let mut acc = PmacAcc::new(self, total);
        acc.feed(&(HEADER_LEN as u64).to_le_bytes());
        acc.feed(SPONGE_PREFIX);
        acc.feed(&[AEAD_FORMAT]);
        acc.feed(&(ad.len() as u64).to_le_bytes());
        acc.feed(ad);
        acc.feed(&(AEAD_NONCE_LEN as u64).to_le_bytes());
        acc.feed(nonce);
        acc.feed(&(msg.len() as u64).to_le_bytes());
        acc.feed(msg);
        acc.finish()
    }

    fn ctr_xor(&self, tag: &[u8; TAG_LEN], data: &mut [u8]) {
        let t = self.eff_threads(data.len());
        if t <= 1 {
            return self.ctr_xor_from(tag, data, 0);
        }
        // Each worker gets whole batches, so its first counter is (offset / 128).
        let nbatches = (data.len() + BATCH * BLOCK_LEN - 1) / (BATCH * BLOCK_LEN);
        let chunk_len = ((nbatches + t - 1) / t) * (BATCH * BLOCK_LEN);
        std::thread::scope(|s| {
            for (k, ch) in data.chunks_mut(chunk_len).enumerate() {
                let first = ((k * chunk_len) / BLOCK_LEN) as u64;
                s.spawn(move || self.ctr_xor_from(tag, ch, first));
            }
        });
    }

    /// CTR keystream XOR where `data[0]` is counter block `first`.
    fn ctr_xor_from(&self, tag: &[u8; TAG_LEN], data: &mut [u8], first: u64) {
        let mut base = [0u8; BLOCK_LEN];
        base[..TAG_LEN].copy_from_slice(tag);
        base[TAG_LEN..TAG_LEN + 8].copy_from_slice(CTR_DOMAIN);
        let mut ks = vec![[0u8; BLOCK_LEN]; BATCH];
        let mut ctr: u64 = first;
        for chunk in data.chunks_mut(BATCH * BLOCK_LEN) {
            let nb = (chunk.len() + BLOCK_LEN - 1) / BLOCK_LEN;
            for b in ks.iter_mut().take(nb) {
                *b = base;
                b[BLOCK_LEN - 8..].copy_from_slice(&ctr.to_le_bytes());
                ctr = ctr.wrapping_add(1);
            }
            self.enc.encrypt_blocks(&mut ks[..nb]);
            for (i, byte) in chunk.iter_mut().enumerate() {
                *byte ^= ks[i / BLOCK_LEN][i % BLOCK_LEN];
            }
        }
        for b in ks.iter_mut() {
            wipe(b);
        }
    }

    /// Gray-code offset Δ_i = XOR over set bits b of gray(i+1) of L[b+1] (closed form).
    fn delta_at(&self, i: u64) -> Block {
        let n = i + 1;
        let mut g = n ^ (n >> 1);
        let mut d = [0u8; BLOCK_LEN];
        while g != 0 {
            let b = g.trailing_zeros() as usize;
            xor_into(&mut d, &self.lpow[b + 1]);
            g &= g - 1;
        }
        d
    }

    /// Multithreaded PMAC. Same transcript and same math as `PmacAcc`: the middle blocks are
    /// independent (Σ ^= E(M_i ⊕ Δ_i)), so each worker takes a run of whole 64-block batches and
    /// the partial sums are XORed (order does not matter). The final block is done once, here.
    fn pmac_transcript_par(&self, ad: &[u8], nonce: &[u8; AEAD_NONCE_LEN], msg: &[u8], t: usize) -> Block {
        let mut prefix = Vec::with_capacity(8 + HEADER_LEN + 8 + ad.len() + 8 + AEAD_NONCE_LEN + 8);
        prefix.extend_from_slice(&(HEADER_LEN as u64).to_le_bytes());
        prefix.extend_from_slice(SPONGE_PREFIX);
        prefix.push(AEAD_FORMAT);
        prefix.extend_from_slice(&(ad.len() as u64).to_le_bytes());
        prefix.extend_from_slice(ad);
        prefix.extend_from_slice(&(AEAD_NONCE_LEN as u64).to_le_bytes());
        prefix.extend_from_slice(nonce);
        prefix.extend_from_slice(&(msg.len() as u64).to_le_bytes());
        let total = prefix.len() + msg.len();
        let nblocks = (total + BLOCK_LEN - 1) / BLOCK_LEN; // >= 1
        let n_mid = (nblocks - 1) as u64;
        let nbatches = (n_mid + BATCH as u64 - 1) / BATCH as u64;
        let t = (t as u64).min(nbatches.max(1));
        let per = (nbatches + t - 1) / t.max(1);

        let prefix_ref = &prefix[..];
        let work = |lo_batch: u64, hi_batch: u64| -> Block {
            let mut sigma = [0u8; BLOCK_LEN];
            let mut batch = [[0u8; BLOCK_LEN]; BATCH];
            let lo = lo_batch * BATCH as u64;
            let hi = (hi_batch * BATCH as u64).min(n_mid);
            if lo >= hi {
                return sigma;
            }
            let mut delta = self.delta_at(lo);
            let mut i = lo;
            while i < hi {
                let n = ((hi - i) as usize).min(BATCH);
                for k in 0..n {
                    let idx = i + k as u64;
                    let copied = fill_transcript(prefix_ref, msg, idx as usize * BLOCK_LEN, &mut batch[k]);
                    debug_assert_eq!(copied, BLOCK_LEN);
                    xor_into(&mut batch[k], &delta);
                    // Δ_{idx+1} = Δ_idx ⊕ L[ntz(idx+2)+1]
                    let tz = (idx + 2).trailing_zeros() as usize + 1;
                    xor_into(&mut delta, &self.lpow[tz]);
                }
                self.mac.encrypt_blocks(&mut batch[..n]);
                for b in batch.iter_mut().take(n) {
                    xor_into(&mut sigma, b);
                    wipe(b);
                }
                i += n as u64;
            }
            sigma
        };

        let mut sigma = [0u8; BLOCK_LEN];
        std::thread::scope(|s| {
            let work = &work;
            let handles: Vec<_> = (1..t)
                .map(|k| s.spawn(move || work(k * per, (k + 1) * per)))
                .collect();
            let first = work(0, per);
            xor_into(&mut sigma, &first);
            for h in handles {
                let part = h.join().expect("pmac worker panicked");
                xor_into(&mut sigma, &part);
            }
        });

        // Final block, identical to PmacAcc::finish.
        let last_idx = (nblocks - 1) as u64;
        let mut last = [0u8; BLOCK_LEN];
        let filled = fill_transcript(&prefix, msg, last_idx as usize * BLOCK_LEN, &mut last);
        debug_assert!(filled > 0);
        let delta = self.delta_at(last_idx);
        if filled == BLOCK_LEN {
            xor_into(&mut last, &delta);
            xor_into(&mut last, &self.k_full);
        } else {
            last[filled] = 0x80;
            xor_into(&mut last, &delta);
            xor_into(&mut last, &self.k_part);
        }
        xor_into(&mut sigma, &last);
        let out = self.mac.encrypt_block(&sigma);
        wipe(&mut sigma);
        wipe(&mut last);
        out
    }

    /// Encrypt and authenticate. Nonce reuse is tolerated (only equality of identical
    /// (AD, nonce, message) triples leaks), but unique nonces are still recommended.
    pub fn seal(&self, nonce: &[u8; AEAD_NONCE_LEN], ad: &[u8], msg: &[u8]) -> Result<Vec<u8>, AeadError> {
        if msg.len() > MAX_MSG_LEN {
            return Err(AeadError::TooLong);
        }
        let v = self.pmac_transcript(ad, nonce, msg);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&v[..TAG_LEN]);
        let mut out = Vec::with_capacity(OVERHEAD + msg.len());
        out.extend_from_slice(SPONGE_PREFIX);
        out.push(AEAD_FORMAT);
        out.extend_from_slice(nonce);
        out.extend_from_slice(&tag);
        out.extend_from_slice(msg);
        self.ctr_xor(&tag, &mut out[OVERHEAD..]);
        Ok(out)
    }

    /// Verify and decrypt. Returns the plaintext only if the tag verifies.
    pub fn open(&self, ad: &[u8], blob: &[u8]) -> Result<Vec<u8>, AeadError> {
        let p = parse_blob(blob)?;
        let mut pt = p.ciphertext.to_vec();
        self.ctr_xor(p.tag, &mut pt);
        let v = self.pmac_transcript(ad, p.nonce, &pt);
        if ct_eq(&v[..TAG_LEN], p.tag) {
            Ok(pt)
        } else {
            wipe(&mut pt);
            Err(AeadError::AuthFailed)
        }
    }

    /// Tag check only (used by the dudect harness): recompute the tag for `pt` and compare.
    #[doc(hidden)]
    pub fn verify_tag(&self, ad: &[u8], nonce: &[u8; AEAD_NONCE_LEN], pt: &[u8], tag: &[u8; TAG_LEN]) -> bool {
        let v = self.pmac_transcript(ad, nonce, pt);
        ct_eq(&v[..TAG_LEN], tag)
    }
}

/// Copy transcript bytes [start, start+out.len()) of `prefix || msg` into `out`; returns how many
/// bytes existed (the rest of `out` is left untouched). Public lengths only.
fn fill_transcript(prefix: &[u8], msg: &[u8], start: usize, out: &mut [u8]) -> usize {
    let total = prefix.len() + msg.len();
    let mut pos = start;
    let mut o = 0;
    while o < out.len() && pos < total {
        let n;
        if pos < prefix.len() {
            n = (prefix.len() - pos).min(out.len() - o);
            out[o..o + n].copy_from_slice(&prefix[pos..pos + n]);
        } else {
            let m = pos - prefix.len();
            n = (msg.len() - m).min(out.len() - o);
            out[o..o + n].copy_from_slice(&msg[m..m + n]);
        }
        pos += n;
        o += n;
    }
    o
}

/// Streaming PMAC accumulator. Encrypts every completed non-final block through
/// the batch-64 path; the last block is mixed with a distinct 3L/5L mask.
struct PmacAcc<'a> {
    aead: &'a Aead,
    sigma: Block,
    delta: Block,
    next_idx: u64,
    batch: [Block; BATCH],
    batch_n: usize,
    buf: Block,
    filled: usize,
    remaining: usize,
}

impl<'a> PmacAcc<'a> {
    fn new(aead: &'a Aead, total: usize) -> Self {
        PmacAcc {
            aead,
            sigma: [0u8; BLOCK_LEN],
            delta: aead.lpow[1],
            next_idx: 0,
            batch: [[0u8; BLOCK_LEN]; BATCH],
            batch_n: 0,
            buf: [0u8; BLOCK_LEN],
            filled: 0,
            remaining: total,
        }
    }

    fn feed(&mut self, data: &[u8]) {
        debug_assert!(data.len() <= self.remaining);
        let mut d = data;
        while !d.is_empty() {
            let take = (BLOCK_LEN - self.filled).min(d.len());
            self.buf[self.filled..self.filled + take].copy_from_slice(&d[..take]);
            self.filled += take;
            self.remaining -= take;
            d = &d[take..];
            if self.filled == BLOCK_LEN && self.remaining > 0 {
                self.push_middle();
                self.filled = 0;
            }
        }
    }

    fn push_middle(&mut self) {
        let mut x = self.buf;
        xor_into(&mut x, &self.delta);
        self.batch[self.batch_n] = x;
        self.batch_n += 1;
        if self.batch_n == BATCH {
            self.flush_batch();
        }
        self.advance_delta();
    }

    fn advance_delta(&mut self) {
        self.next_idx += 1;
        // Arriving at 0-based index `next_idx` (1-based i = next_idx+1):
        // Δ_i = Δ_{i-1} ⊕ L[ntz(i)+1].
        let i = self.next_idx + 1;
        let tz = i.trailing_zeros() as usize + 1;
        debug_assert!(tz < LPOW);
        xor_into(&mut self.delta, &self.aead.lpow[tz]);
    }

    fn flush_batch(&mut self) {
        if self.batch_n == 0 {
            return;
        }
        self.aead.mac.encrypt_blocks(&mut self.batch[..self.batch_n]);
        for i in 0..self.batch_n {
            xor_into(&mut self.sigma, &self.batch[i]);
            wipe(&mut self.batch[i]);
        }
        self.batch_n = 0;
    }

    fn finish(mut self) -> Block {
        debug_assert_eq!(self.remaining, 0);
        self.flush_batch();
        // Minimum transcript is 54 bytes, so there is always a last block.
        debug_assert!(self.filled > 0);
        let mut last = [0u8; BLOCK_LEN];
        last[..self.filled].copy_from_slice(&self.buf[..self.filled]);
        if self.filled == BLOCK_LEN {
            xor_into(&mut last, &self.delta);
            xor_into(&mut last, &self.aead.k_full);
        } else {
            last[self.filled] = 0x80;
            xor_into(&mut last, &self.delta);
            xor_into(&mut last, &self.aead.k_part);
        }
        xor_into(&mut self.sigma, &last);
        let out = self.aead.mac.encrypt_block(&self.sigma);
        wipe(&mut self.sigma);
        wipe(&mut self.buf);
        wipe(&mut last);
        out
    }
}

impl Zeroize for Aead {
    fn zeroize(&mut self) {
        for b in &mut self.lpow {
            crate::wipe_bytes(b);
        }
        crate::wipe_bytes(&mut self.k_full);
        crate::wipe_bytes(&mut self.k_part);
        self.mac.zeroize();
        self.enc.zeroize();
    }
}

impl Drop for Aead {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Constant-time equality for equal-length slices (length is public).
#[inline(never)]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= core::hint::black_box(x ^ y);
    }
    let acc = core::hint::black_box(acc) as u32;
    // 1 iff acc == 0, without a data-dependent branch before this point
    ((acc.wrapping_sub(1) >> 8) & 1) == 1
}

fn wipe(b: &mut [u8]) {
    for x in b.iter_mut() {
        unsafe { core::ptr::write_volatile(x, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
pub(crate) fn dbl_pub(b: &Block) -> Block {
    dbl(b)
}

#[cfg(test)]
pub(crate) fn gray_delta_pub(lpow: &[Block; LPOW], k: u64) -> Block {
    // Closed form: Δ_k = XOR_{i=1}^{k+1} L[ntz(i)+1]
    let mut d = [0u8; BLOCK_LEN];
    for i in 1..=k + 1 {
        let tz = i.trailing_zeros() as usize + 1;
        xor_into(&mut d, &lpow[tz]);
    }
    d
}

#[cfg(test)]
impl Aead {
    pub(crate) fn lpow_ref(&self) -> &[Block; LPOW] {
        &self.lpow
    }
    pub(crate) fn delta_at_pub(&self, i: u64) -> Block {
        self.delta_at(i)
    }
    pub(crate) fn k_full_ref(&self) -> &Block {
        &self.k_full
    }
    pub(crate) fn k_part_ref(&self) -> &Block {
        &self.k_part
    }
}
