//! EXPERIMENTAL SN3C/ AEAD, lab format 0x1D: "N3-POLYVAL-SIV". A nonce-misuse-resistant
//! SIV mode over the 1024-bit N3 block cipher whose tag comes from POLYVAL (RFC 8452) instead
//! of a full-cipher PMAC pass. Homemade composition, NOT reviewed, not attacked yet. For real
//! secrets use AES-GCM-SIV, age, or libsodium.
//!
//! The 0x1C AEAD (`crate::aead`) and SN3F are unchanged; this is a separate lab mode.
//!
//! Construction (mirrors RFC 8452 AES-GCM-SIV, adapted to a 128-byte block):
//! * Master keys: from the 128-byte seed, three 128-byte subkeys via the same SHA-256-expand
//!   KDF as 0x1C but with format byte 0x1D and labels 'A' (auth-key derivation cipher),
//!   'T' (tag cipher), 'E' (CTR cipher). Each keys an N3 instance with a fixed distinct cipher
//!   nonce ("SN3C/PV-AK", "SN3C/PV-TG", "SN3C/PV-EN"). Three key setups per master key, once.
//! * Per-nonce auth key (RFC 8452 §4 analogue): one N3 block
//!     A = E_ak( "SN3V/AK\0" || 0^8 || nonce(16) || 0^96 );   polyval_key = A[0..16].
//!   (Deviation: RFC also derives a per-nonce encryption key. Here the CTR key stays per master
//!   key, because an N3 key schedule costs ~1.5 ms per message; the SIV tag sits inside every
//!   counter block, so keystreams are still per-(nonce, AD, message).)
//! * Hash (RFC 8452 §4): S = POLYVAL(polyval_key, pad16(AD) || pad16(M) || LEN) with
//!   LEN = u64le(8*|AD|) || u64le(8*|M|). Then S ^= nonce (all 16 bytes).
//! * Tag/SIV: T_blk = E_tag( S(16) || "SN3V/TAG" || 0^104 );  tag = T_blk[0..32] (32 bytes, same
//!   API as 0x1C). Security is ~128-bit (the hash output is 128 bits), the 32-byte tag is an
//!   IV/tag expansion, not 256 bits of forgery resistance.
//! * Encryption: CTR with E_enc; counter block i = tag(32) || "SN3V/CTR" || 0^80 || u64le(i)
//!   (bytes 120..128). Keystream XOR message, no padding. Threaded like 0x1C (whole batches).
//! * Blob: "SN3C/" || 0x1D || nonce(16) || tag(32) || ciphertext. Overhead 54 bytes.
//! * Open: strict parse (0x1C and everything else gives BadFormat), CTR-decrypt, recompute POLYVAL
//!   and the tag, constant-time compare, wipe plaintext and return only `AuthFailed` on mismatch.
//!
//! Security shape (GCM-SIV-like, not proven here): forging a ciphertext for a fixed (key, nonce)
//! needs a POLYVAL collision/forgery, probability about (blocks)/2^128 per attempt. Nonce reuse
//! reveals only whether two (AD, M) pairs under that nonce are identical. Because the tag is the
//! CTR IV, two different messages with colliding POLYVAL output would share a keystream (~2^-128
//! per pair under a repeated nonce). POLYVAL is ~2 GB/s here (RustCrypto `polyval`), far cheaper
//! than the cipher pass. Both layers are threaded for messages >= 256 KiB: CTR by whole batches,
//! POLYVAL by splitting the message into segments recombined with powers of the key (the result
//! is bit-identical to the sequential hash, see `polyval`).

use crate::aead::{ct_eq, default_threads, AeadError, AEAD_NONCE_LEN, HEADER_LEN, MAX_MSG_LEN, OVERHEAD, TAG_LEN};
use crate::{Backend, Cipher, BLOCK_LEN, NONCE_LEN, SEED_LEN, SPONGE_PREFIX};
use polyval::universal_hash::{KeyInit, UniversalHash};
use polyval::Polyval;
use sha2::{Digest, Sha256};

/// Experimental format byte, distinct from the 0x1B cipher and the 0x1C PMAC-SIV AEAD.
pub const PV_FORMAT: u8 = 0x1D;
const CTR_DOMAIN: &[u8; 8] = b"SN3V/CTR";
const AK_DOMAIN: &[u8; 8] = b"SN3V/AK\0";
const TAG_DOMAIN: &[u8; 8] = b"SN3V/TAG";
const AK_CIPHER_NONCE: [u8; NONCE_LEN] = *b"SN3C/PV-AK\0\0\0\0\0\0";
const TG_CIPHER_NONCE: [u8; NONCE_LEN] = *b"SN3C/PV-TG\0\0\0\0\0\0";
const EN_CIPHER_NONCE: [u8; NONCE_LEN] = *b"SN3C/PV-EN\0\0\0\0\0\0";
const BATCH: usize = 64;
const PAR_MIN_DEFAULT: usize = 256 * 1024;

type Block = [u8; BLOCK_LEN];

fn kdf(seed: &[u8; SEED_LEN], label: u8) -> [u8; SEED_LEN] {
    let mut out = [0u8; SEED_LEN];
    for (ctr, chunk) in out.chunks_mut(32).enumerate() {
        let mut h = Sha256::new();
        h.update(SPONGE_PREFIX);
        h.update([PV_FORMAT]);
        h.update(b"AEAD-KDF");
        h.update([label]);
        h.update((ctr as u32).to_be_bytes());
        h.update(seed);
        chunk.copy_from_slice(&h.finalize());
    }
    out
}

fn wipe(b: &mut [u8]) {
    for x in b.iter_mut() {
        unsafe { core::ptr::write_volatile(x, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Parsed view of a 0x1D blob (no authentication yet).
pub fn parse_blob(blob: &[u8]) -> Result<([u8; AEAD_NONCE_LEN], [u8; TAG_LEN], &[u8]), AeadError> {
    if blob.len() < OVERHEAD {
        return Err(AeadError::TooShort);
    }
    if blob.len() - OVERHEAD > MAX_MSG_LEN {
        return Err(AeadError::TooLong);
    }
    if &blob[..5] != SPONGE_PREFIX {
        return Err(AeadError::BadPrefix);
    }
    if blob[5] != PV_FORMAT {
        return Err(AeadError::BadFormat);
    }
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    nonce.copy_from_slice(&blob[HEADER_LEN..HEADER_LEN + AEAD_NONCE_LEN]);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&blob[HEADER_LEN + AEAD_NONCE_LEN..OVERHEAD]);
    Ok((nonce, tag, &blob[OVERHEAD..]))
}

/// POLYVAL "dot": a . b = a*b*x^-128 in GF(2^128), via the vetted crate (one block, state 0).
fn dot(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut p = Polyval::new(a.into());
    p.update_padded(b);
    p.finalize().into()
}

/// D_k = H.H...H (k factors, k >= 1): the factor a state picks up when k more blocks follow it.
fn dot_pow(h: &[u8; 16], mut k: u64) -> [u8; 16] {
    debug_assert!(k >= 1);
    let mut base = *h;
    let mut acc: Option<[u8; 16]> = None;
    while k > 0 {
        if k & 1 == 1 {
            acc = Some(match acc {
                Some(x) => dot(&x, &base),
                None => base,
            });
        }
        k >>= 1;
        if k > 0 {
            base = dot(&base, &base);
        }
    }
    acc.unwrap()
}

fn polyval_seg(key: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let mut p = Polyval::new(key.into());
    p.update_padded(data);
    p.finalize().into()
}

fn len_block(ad: usize, msg: usize) -> [u8; 16] {
    let mut len = [0u8; 16];
    len[..8].copy_from_slice(&((ad as u64) * 8).to_le_bytes());
    len[8..].copy_from_slice(&((msg as u64) * 8).to_le_bytes());
    len
}

/// EXPERIMENTAL POLYVAL-SIV AEAD over N3 (format 0x1D).
pub struct AeadPv {
    ak: Cipher,
    tg: Cipher,
    enc: Cipher,
    threads: usize,
    par_min: usize,
}

impl AeadPv {
    pub fn new(seed: &[u8; SEED_LEN]) -> Self {
        Self::with_backend(seed, Backend::detect()).expect("detected backend is supported")
    }

    pub fn with_backend(seed: &[u8; SEED_LEN], backend: Backend) -> Result<Self, String> {
        let mut sa = kdf(seed, b'A');
        let mut st = kdf(seed, b'T');
        let mut se = kdf(seed, b'E');
        let ak = Cipher::with_backend(&sa, &AK_CIPHER_NONCE, backend)?;
        let tg = Cipher::with_backend(&st, &TG_CIPHER_NONCE, backend)?;
        let enc = Cipher::with_backend(&se, &EN_CIPHER_NONCE, backend)?;
        wipe(&mut sa);
        wipe(&mut st);
        wipe(&mut se);
        Ok(AeadPv { ak, tg, enc, threads: default_threads(), par_min: PAR_MIN_DEFAULT })
    }

    pub fn backend(&self) -> Backend {
        self.enc.backend()
    }

    /// Worker threads for the CTR layer (1 = single-threaded). Output bytes do not depend on it.
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

    fn eff_threads(&self, len: usize) -> usize {
        if self.threads <= 1 || len < self.par_min {
            return 1;
        }
        self.threads.min(len / (BATCH * BLOCK_LEN)).max(1)
    }

    /// RFC 8452 POLYVAL(key, pad16(AD) || pad16(M) || LEN). For large messages the full-block part
    /// of M is split across threads: each segment is hashed from state 0 and multiplied by
    /// D_(blocks after it) (POLYVAL is linear in the running state), so the result equals the
    /// sequential hash bit for bit.
    fn polyval(&self, key: &[u8; 16], ad: &[u8], msg: &[u8]) -> [u8; 16] {
        let t = self.eff_threads(msg.len());
        if t <= 1 {
            let mut p = Polyval::new(key.into());
            p.update_padded(ad);
            p.update_padded(msg);
            p.update_padded(&len_block(ad.len(), msg.len()));
            return p.finalize().into();
        }
        let nf = msg.len() / 16;
        let per = (nf + t - 1) / t;
        let mut tail = msg[nf * 16..].to_vec();
        tail.resize((tail.len() + 15) / 16 * 16, 0);
        tail.extend_from_slice(&len_block(ad.len(), msg.len()));
        // (data, blocks): AD, then M chunks, then padded tail + length block.
        let mut segs: Vec<(&[u8], u64)> = vec![(ad, ((ad.len() + 15) / 16) as u64)];
        for c in msg[..nf * 16].chunks(per * 16) {
            segs.push((c, (c.len() / 16) as u64));
        }
        segs.push((&tail[..], (tail.len() / 16) as u64));
        let mut sums = vec![[0u8; 16]; segs.len()];
        std::thread::scope(|s| {
            let (first, rest) = sums.split_first_mut().expect("at least two segments");
            for (sum, (d, _)) in rest.iter_mut().zip(segs.iter().skip(1)) {
                s.spawn(move || *sum = polyval_seg(key, d));
            }
            *first = polyval_seg(key, segs[0].0);
        });
        let mut after = 0u64;
        let mut out = [0u8; 16];
        for (sum, (_, nb)) in sums.iter().zip(segs.iter()).rev() {
            let term = if after == 0 { *sum } else { dot(sum, &dot_pow(key, after)) };
            for (o, x) in out.iter_mut().zip(term.iter()) {
                *o ^= *x;
            }
            after += *nb;
        }
        wipe(&mut tail);
        out
    }

    /// Tag = E_tag(POLYVAL(per-nonce key, AD, M, lengths) ^ nonce, domain)[0..32].
    fn tag_of(&self, ad: &[u8], nonce: &[u8; AEAD_NONCE_LEN], msg: &[u8]) -> [u8; TAG_LEN] {
        let mut blk: Block = [0u8; BLOCK_LEN];
        blk[..8].copy_from_slice(AK_DOMAIN);
        blk[16..16 + AEAD_NONCE_LEN].copy_from_slice(nonce);
        let mut a = self.ak.encrypt_block(&blk);
        let mut key = [0u8; 16];
        key.copy_from_slice(&a[..16]);
        wipe(&mut a);
        let mut s = self.polyval(&key, ad, msg);
        wipe(&mut key);
        for (x, n) in s.iter_mut().zip(nonce.iter()) {
            *x ^= *n;
        }
        let mut tb: Block = [0u8; BLOCK_LEN];
        tb[..16].copy_from_slice(&s);
        tb[16..24].copy_from_slice(TAG_DOMAIN);
        wipe(&mut s);
        let out = self.tg.encrypt_block(&tb);
        wipe(&mut tb);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&out[..TAG_LEN]);
        tag
    }

    fn ctr_xor(&self, tag: &[u8; TAG_LEN], data: &mut [u8]) {
        let t = self.eff_threads(data.len());
        if t <= 1 {
            return self.ctr_xor_from(tag, data, 0);
        }
        let nbatches = (data.len() + BATCH * BLOCK_LEN - 1) / (BATCH * BLOCK_LEN);
        let chunk_len = ((nbatches + t - 1) / t) * (BATCH * BLOCK_LEN);
        std::thread::scope(|s| {
            for (k, ch) in data.chunks_mut(chunk_len).enumerate() {
                let first = ((k * chunk_len) / BLOCK_LEN) as u64;
                s.spawn(move || self.ctr_xor_from(tag, ch, first));
            }
        });
    }

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

    /// Encrypt and authenticate. Nonce reuse is tolerated (only equality of identical
    /// (AD, nonce, message) triples leaks).
    pub fn seal(&self, nonce: &[u8; AEAD_NONCE_LEN], ad: &[u8], msg: &[u8]) -> Result<Vec<u8>, AeadError> {
        if msg.len() > MAX_MSG_LEN {
            return Err(AeadError::TooLong);
        }
        let tag = self.tag_of(ad, nonce, msg);
        let mut out = Vec::with_capacity(OVERHEAD + msg.len());
        out.extend_from_slice(SPONGE_PREFIX);
        out.push(PV_FORMAT);
        out.extend_from_slice(nonce);
        out.extend_from_slice(&tag);
        out.extend_from_slice(msg);
        self.ctr_xor(&tag, &mut out[OVERHEAD..]);
        Ok(out)
    }

    /// Verify and decrypt. Returns the plaintext only if the tag verifies.
    pub fn open(&self, ad: &[u8], blob: &[u8]) -> Result<Vec<u8>, AeadError> {
        let (nonce, tag, ct) = parse_blob(blob)?;
        let mut pt = ct.to_vec();
        self.ctr_xor(&tag, &mut pt);
        let v = self.tag_of(ad, &nonce, &pt);
        if ct_eq(&v, &tag) {
            Ok(pt)
        } else {
            wipe(&mut pt);
            Err(AeadError::AuthFailed)
        }
    }
}
