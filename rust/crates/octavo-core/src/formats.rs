//! Wire formats on top of the block cipher, byte-compatible with sneak_n2.py:
//! v6 single-block AEAD, v7 movements, v9 rehearsal stream, étude block/movements (lab only),
//! and the app-layer HKDF-SHA512 key expansion.
//!
//! Pickups/nonces are passed in explicitly (deterministic, so the published score can be rebuilt).
//! Generating a fresh random pickup is the caller's job (phase 2 CLI/app).
//!
//! **Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.**

use alloc::vec::Vec;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;

use crate::backend::SboxBackend;
use crate::schedule::Schedule;
use crate::sponge::sponge;
use crate::{Auto, BLOCK_LEN, NR};

pub const MAGIC: &[u8; 3] = b"SN2";
pub const MAX_MSG: usize = 127;
pub const MAX_AD_LEN: usize = 65536;
pub const MAX_MOVEMENTS: usize = 8192;
pub const MAX_REHEARSAL_CHUNKS: usize = 1 << 24;
pub const REHEARSAL_CHUNK_MIN: usize = 128;
pub const REHEARSAL_CHUNK_MAX: usize = 1 << 20;
pub const FMT_V6: u8 = 6;
pub const FMT_V7: u8 = 7;
pub const FMT_V9: u8 = 9;
pub const BLOB_LEN_V6: usize = 228;

/// key_signature sponge nonce = KEY_SIG_PIN[1] in sneak_n2.py (the pinned mix digest). The Python
/// import-time source attestation has no Rust equivalent; the port pins the resulting nonces.
pub const KEY_SIG_NONCE: [u8; 32] = hex32("fe93996970ecd92693b5f8f43ffb2cad5e96867f258a38b12637f1014b12b4c6");
/// Rehearsal signature sponge nonce = REHEARSAL_SIG_PIN[1] in sneak_n2.py.
pub const REH_SIG_NONCE: [u8; 32] = hex32("a21cf6e768a88cc21b4698b54426cf2d1527936f101f783862a609efa8bbad45");

const fn hex32(s: &str) -> [u8; 32] {
    const fn nib(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("bad hex"),
        }
    }
    let b = s.as_bytes();
    let mut o = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        o[i] = (nib(b[2 * i]) << 4) | nib(b[2 * i + 1]);
        i += 1;
    }
    o
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Wrong version byte, magic, or length.
    Format,
    /// Commitment / tag / cadence / SIV check failed.
    Auth,
    /// Tag valid but decrypted block malformed.
    Decode,
    /// Bad padding in a rehearsal final chunk.
    Pad,
    /// Caller input out of range (message/AD too long, bad chunk size, ...).
    Input,
}

type HmacSha256 = Hmac<Sha256>;

fn mac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac key");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}
fn h(parts: &[&[u8]]) -> [u8; 32] {
    let mut d = Sha256::new();
    for p in parts {
        d.update(p);
    }
    d.finalize().into()
}
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}
fn enc_ad(ad: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + ad.len());
    v.extend_from_slice(&(ad.len() as u64).to_be_bytes());
    v.extend_from_slice(ad);
    v
}
fn enc_block(m: &[u8]) -> [u8; BLOCK_LEN] {
    let mut b = [0u8; BLOCK_LEN];
    b[0] = m.len() as u8;
    b[1..1 + m.len()].copy_from_slice(m);
    b
}
/// Fixed-pattern inverse of enc_block: scans all 127 payload bytes regardless of L.
fn dec_block(b: &[u8; BLOCK_LEN]) -> Result<Vec<u8>, Error> {
    let l = b[0];
    let bad_len = ((MAX_MSG as u16).wrapping_sub(l as u16) >> 8) as u8 & 1;
    let lm = (l & 0x7f) as usize;
    let mut acc = 0u8;
    for (i, &x) in b[1..].iter().enumerate() {
        // in pad region iff i >= lm ; mask without branching on secret data
        let in_pad = (((i as isize) - (lm as isize)) >> (isize::BITS - 1)) as u8 ^ 0xff; // 0xff if i >= lm
        acc |= x & in_pad;
    }
    if (bad_len | (acc != 0) as u8) != 0 {
        return Err(Error::Decode);
    }
    Ok(b[1..1 + lm].to_vec())
}
fn xor_into(a: &mut [u8], b: &[u8]) {
    for (x, y) in a.iter_mut().zip(b) {
        *x ^= *y;
    }
}

// ---- seed-only derived values ----
pub fn key_sig(k: &[u8]) -> [u8; 16] {
    let mut o = [0u8; 16];
    sponge(b"G", k, &KEY_SIG_NONCE, &mut o);
    o
}
pub fn rehearsal_sig(k: &[u8]) -> [u8; 16] {
    let mut o = [0u8; 16];
    sponge(b"H", k, &REH_SIG_NONCE, &mut o);
    o
}
pub fn clef(k: &[u8]) -> [u8; 16] {
    let mut o = [0u8; 16];
    sponge(b"C", k, &[0u8; 16], &mut o);
    o
}
fn k_commit(k: &[u8]) -> [u8; 32] {
    let mut o = [0u8; 32];
    sponge(b"U", k, &[0u8; 16], &mut o);
    o
}
/// Étude key K_e = StaffSponge(b"E", seed, [rounds] || 15 zero bytes).take(128).
pub fn etude_key(seed: &[u8], rounds: u8) -> [u8; 128] {
    let mut n = [0u8; 16];
    n[0] = rounds;
    let mut o = [0u8; 128];
    sponge(b"E", seed, &n, &mut o);
    o
}

/// Key context for live Octavo (16 rounds, v6/v7) or an étude (reduced rounds, lab version bytes).
pub struct Ctx {
    pub k: [u8; 128],
    pub rounds: usize,
    pub etude: bool,
    pub v_block: u8,
    pub v_mov: u8,
    clef: [u8; 16],
    kc: [u8; 32],
    ks: [u8; 16],
}

impl Ctx {
    /// Live Octavo with a 128-byte seed.
    pub fn live(seed: &[u8; 128]) -> Ctx {
        Self::build(*seed, NR, false, FMT_V6, FMT_V7)
    }
    /// Étude (weakened, reduced-round, lab only) with rounds in {2, 4, 6, 16}.
    pub fn etude(seed: &[u8; 128], rounds: u8) -> Result<Ctx, Error> {
        let (vb, vm) = match rounds {
            2 => (0x82, 0x83),
            4 => (0x84, 0x85),
            6 => (0x86, 0x87),
            16 => (0x90, 0x91),
            _ => return Err(Error::Input),
        };
        Ok(Self::build(etude_key(seed, rounds), rounds as usize, true, vb, vm))
    }
    fn build(k: [u8; 128], rounds: usize, etude: bool, v_block: u8, v_mov: u8) -> Ctx {
        Ctx { clef: clef(&k), kc: k_commit(&k), ks: key_sig(&k), k, rounds, etude, v_block, v_mov }
    }
    fn vb(&self, v: u8) -> Vec<u8> {
        if self.etude { alloc::vec![v] } else { Vec::new() }
    }
    fn cipher(&self, nonce: &[u8]) -> (Schedule, Auto) {
        let s = Schedule::new(&self.k, nonce);
        let b = Auto::prepare(&s);
        (s, b)
    }
    fn mac_key(&self, nonce: &[u8]) -> [u8; 32] {
        let mut o = [0u8; 32];
        sponge(b"M", &self.k, nonce, &mut o);
        o
    }
}

fn check_ad(ad: &[u8]) -> Result<(), Error> {
    if ad.len() > MAX_AD_LEN { Err(Error::Input) } else { Ok(()) }
}

// ================= v6 / étude single block =================
pub fn seal_block(ctx: &Ctx, msg: &[u8], pickup: &[u8; 16], ad: &[u8]) -> Result<Vec<u8>, Error> {
    if msg.len() > MAX_MSG {
        return Err(Error::Input);
    }
    check_ad(ad)?;
    let ver = [ctx.v_block];
    let eb = enc_block(msg);
    let ead = enc_ad(ad);
    let nonce: [u8; 16] = h(&[&ctx.clef, &ctx.vb(ctx.v_block), pickup, &eb, &ead])[..16].try_into().unwrap();
    let commit = mac(&ctx.kc, &[b"U", &ver, MAGIC, pickup, &nonce, &ead]);
    let (sch, be) = ctx.cipher(&nonce);
    let mut ct = eb;
    be.encrypt_blocks(&sch, core::slice::from_mut(&mut ct), ctx.rounds);
    let tag = mac(&ctx.mac_key(&nonce), &[&ctx.clef, &ctx.ks, &ver, MAGIC, pickup, &nonce, &commit, &ct, &ead]);
    let mut out = Vec::with_capacity(BLOB_LEN_V6);
    for p in [&ver[..], MAGIC, pickup, &nonce, &commit, &ct, &tag] {
        out.extend_from_slice(p);
    }
    Ok(out)
}

pub fn open_block(ctx: &Ctx, blob: &[u8], ad: &[u8]) -> Result<Vec<u8>, Error> {
    check_ad(ad)?;
    if blob.len() != BLOB_LEN_V6 || blob[0] != ctx.v_block || &blob[1..4] != MAGIC {
        return Err(Error::Format);
    }
    let (ver, pickup, nonce, commit, ct, tag) =
        (&blob[..1], &blob[4..20], &blob[20..36], &blob[36..68], &blob[68..196], &blob[196..]);
    let ead = enc_ad(ad);
    let ok1 = ct_eq(commit, &mac(&ctx.kc, &[b"U", ver, MAGIC, pickup, nonce, &ead]));
    let ok2 = ct_eq(tag, &mac(&ctx.mac_key(nonce), &[&ctx.clef, &ctx.ks, ver, MAGIC, pickup, nonce, commit, ct, &ead]));
    if !(ok1 & ok2) {
        return Err(Error::Auth);
    }
    let (sch, be) = ctx.cipher(nonce);
    let mut b: [u8; BLOCK_LEN] = ct.try_into().unwrap();
    be.decrypt_blocks(&sch, core::slice::from_mut(&mut b), ctx.rounds);
    let msg = dec_block(&b)?;
    let syn = h(&[&ctx.clef, &ctx.vb(ctx.v_block), pickup, &enc_block(&msg), &ead]);
    if !ct_eq(&syn[..16], nonce) {
        return Err(Error::Auth);
    }
    Ok(msg)
}

// ================= v7 / étude movements =================
struct MovRow {
    theme: [u8; 128],
    idx: [u8; 8],
    fin: [u8; 1],
    ct: [u8; 128],
    pt: Vec<u8>,
}

fn sponge128(dom: &[u8], k: &[u8], n: &[u8]) -> [u8; 128] {
    let mut o = [0u8; 128];
    sponge(dom, k, n, &mut o);
    o
}

fn mov_core(ctx: &Ctx, nonce: &[u8], items: &[&[u8]], decrypt: bool) -> Result<Vec<MovRow>, Error> {
    let (sch, be) = ctx.cipher(nonce);
    let mut theme = sponge128(b"T", &ctx.k, nonce);
    let n = items.len();
    let mut out = Vec::with_capacity(n);
    let tweak = |i: usize| -> ([u8; 8], [u8; 1], [u8; 128]) {
        let idx = (i as u64).to_be_bytes();
        let fin = [(i == n - 1) as u8];
        (idx, fin, sponge128(b"W", &ctx.k, &h(&[b"SN2/I", nonce, &idx, &fin])[..16]))
    };
    if decrypt {
        // The theme chain only needs ciphertexts, so every block can be decrypted at once.
        let mut blocks: Vec<[u8; 128]> = items.iter().map(|c| (*c).try_into().unwrap()).collect();
        be.decrypt_blocks(&sch, &mut blocks, ctx.rounds);
        for (i, item) in items.iter().enumerate() {
            let (idx, fin, tw) = tweak(i);
            let ct: [u8; 128] = (*item).try_into().unwrap();
            let mut b = blocks[i];
            xor_into(&mut b, &theme);
            xor_into(&mut b, &tw);
            let pt = dec_block(&b)?;
            let next = sponge128(b"T", &ctx.k, &h(&[b"SN2/T", &theme, &ct, &idx, &fin])[..16]);
            out.push(MovRow { theme, idx, fin, ct, pt });
            theme = next;
        }
    } else {
        // Encryption is sequential: each theme depends on the previous ciphertext.
        for (i, item) in items.iter().enumerate() {
            let (idx, fin, tw) = tweak(i);
            let mut b = enc_block(item);
            xor_into(&mut b, &theme);
            xor_into(&mut b, &tw);
            be.encrypt_blocks(&sch, core::slice::from_mut(&mut b), ctx.rounds);
            let next = sponge128(b"T", &ctx.k, &h(&[b"SN2/T", &theme, &b, &idx, &fin])[..16]);
            out.push(MovRow { theme, idx, fin, ct: b, pt: item.to_vec() });
            theme = next;
        }
    }
    Ok(out)
}

pub fn seal_movements(ctx: &Ctx, msg: &[u8], pickup: &[u8; 16], ad: &[u8]) -> Result<Vec<u8>, Error> {
    check_ad(ad)?;
    let mut chunks: Vec<&[u8]> = msg.chunks(MAX_MSG).collect();
    if chunks.is_empty() {
        chunks.push(&[]);
    }
    if chunks.len() > MAX_MOVEMENTS {
        return Err(Error::Input);
    }
    let ver = [ctx.v_mov];
    let nm = (chunks.len() as u32).to_be_bytes();
    let ead = enc_ad(ad);
    let nonce: [u8; 16] =
        h(&[&ctx.clef, &ctx.vb(ctx.v_mov), pickup, &(msg.len() as u64).to_be_bytes(), msg, &ead])[..16].try_into().unwrap();
    let commit = mac(&ctx.kc, &[b"U", &ver, MAGIC, pickup, &nonce, &ead, &nm]);
    let hdr = [&ctx.clef[..], &ctx.ks, &ver, MAGIC, pickup, &nonce, &commit].concat();
    let ck = sponge32(b"D", &ctx.k, &nonce);
    let ok = sponge32(b"O", &ctx.k, &nonce);
    let rows = mov_core(ctx, &nonce, &chunks, false)?;
    let cads: Vec<[u8; 32]> =
        rows.iter().map(|r| mac(&ck, &[&hdr, &r.idx, &r.fin, &r.theme, &r.ct, &ead])).collect();
    let mut parts: Vec<&[u8]> = alloc::vec![&hdr, &nm];
    parts.extend(rows.iter().map(|r| &r.ct[..]));
    parts.extend(cads.iter().map(|c| &c[..]));
    parts.push(&ead);
    let coda = mac(&ok, &parts);
    let mut out = Vec::with_capacity(72 + 160 * rows.len() + 32);
    for p in [&ver[..], MAGIC, pickup, &nonce, &commit, &nm] {
        out.extend_from_slice(p);
    }
    for (r, c) in rows.iter().zip(&cads) {
        out.extend_from_slice(&r.ct);
        out.extend_from_slice(c);
    }
    out.extend_from_slice(&coda);
    Ok(out)
}

fn sponge32(dom: &[u8], k: &[u8], n: &[u8]) -> [u8; 32] {
    let mut o = [0u8; 32];
    sponge(dom, k, n, &mut o);
    o
}

pub fn open_movements(ctx: &Ctx, blob: &[u8], ad: &[u8]) -> Result<Vec<u8>, Error> {
    check_ad(ad)?;
    if blob.len() < 72 + 160 + 32 || blob[0] != ctx.v_mov || &blob[1..4] != MAGIC {
        return Err(Error::Format);
    }
    let (ver, pickup, nonce, commit, nm) = (&blob[..1], &blob[4..20], &blob[20..36], &blob[36..68], &blob[68..72]);
    let n = u32::from_be_bytes(nm.try_into().unwrap()) as usize;
    if n < 1 || n > MAX_MOVEMENTS || blob.len() != 72 + 160 * n + 32 {
        return Err(Error::Format);
    }
    let cts: Vec<&[u8]> = (0..n).map(|i| &blob[72 + 160 * i..200 + 160 * i]).collect();
    let cads: Vec<&[u8]> = (0..n).map(|i| &blob[200 + 160 * i..232 + 160 * i]).collect();
    let hdr = [&ctx.clef[..], &ctx.ks, ver, MAGIC, pickup, nonce, commit].concat();
    let ead = enc_ad(ad);
    let ok1 = ct_eq(commit, &mac(&ctx.kc, &[b"U", ver, MAGIC, pickup, nonce, &ead, nm]));
    let mut parts: Vec<&[u8]> = alloc::vec![&hdr, nm];
    parts.extend(cts.iter().copied());
    parts.extend(cads.iter().copied());
    parts.push(&ead);
    let ok2 = ct_eq(&blob[blob.len() - 32..], &mac(&sponge32(b"O", &ctx.k, nonce), &parts));
    if !(ok1 & ok2) {
        return Err(Error::Auth);
    }
    let rows = mov_core(ctx, nonce, &cts, true)?;
    let ck = sponge32(b"D", &ctx.k, nonce);
    for (r, cad) in rows.iter().zip(&cads) {
        if !ct_eq(cad, &mac(&ck, &[&hdr, &r.idx, &r.fin, &r.theme, &r.ct, &ead])) {
            return Err(Error::Auth);
        }
    }
    let msg: Vec<u8> = rows.into_iter().flat_map(|r| r.pt).collect();
    let syn = h(&[&ctx.clef, &ctx.vb(ctx.v_mov), pickup, &(msg.len() as u64).to_be_bytes(), &msg, &ead]);
    if !ct_eq(&syn[..16], nonce) {
        return Err(Error::Auth);
    }
    Ok(msg)
}

// ================= v9 rehearsal stream =================
fn reh_keys(seed: &[u8], pickup: &[u8], nonce: &[u8], cs32: &[u8], i: u64, fin: u8, add: &[u8], nb: usize) -> Vec<u8> {
    let info = [b"chunk\x09" as &[u8], pickup, nonce, cs32, &i.to_be_bytes(), &[fin], add].concat();
    let mut out = alloc::vec![0u8; 32 + 128 * nb];
    sponge(b"R", seed, &info, &mut out);
    out
}
fn reh_schedule(seed: &[u8], pickup: &[u8], nonce: &[u8], cs32: &[u8], add: &[u8]) -> Schedule {
    let info = [b"sched\x09" as &[u8], pickup, nonce, cs32, add].concat();
    let mut n = [0u8; 16];
    sponge(b"R", seed, &info, &mut n);
    Schedule::new(seed, &n)
}

/// Per-stream parameters shared by every chunk.
struct RehStream<'a> {
    seed: &'a [u8],
    pickup: &'a [u8],
    nonce: &'a [u8],
    cs32: &'a [u8],
    add: &'a [u8],
    sch: Schedule,
    be: Auto,
}

impl RehStream<'_> {
    /// XEX-style crypt of one chunk in place (all its blocks at once); returns the chunk MAC key.
    fn crypt_chunk(&self, i: usize, fin: u8, data: &mut [u8], decrypt: bool) -> [u8; 32] {
        let nb = data.len() / 128;
        let keys = reh_keys(self.seed, self.pickup, self.nonce, self.cs32, i as u64, fin, self.add, nb);
        let (blocks, _) = data.as_chunks_mut::<128>();
        for (b, tw) in blocks.iter_mut().zip(keys[32..].chunks_exact(128)) {
            xor_into(b, tw);
        }
        if decrypt {
            self.be.decrypt_blocks(&self.sch, blocks, NR);
        } else {
            self.be.encrypt_blocks(&self.sch, blocks, NR);
        }
        for (b, tw) in blocks.iter_mut().zip(keys[32..].chunks_exact(128)) {
            xor_into(b, tw);
        }
        keys[..32].try_into().unwrap()
    }
    /// Run crypt_chunk over chunk ranges, optionally on several threads. Returns MAC keys in order.
    /// `chunks[i]` = (offset, len) into `buf`; the last one is final.
    fn crypt_all(&self, buf: &mut [u8], chunks: &[(usize, usize)], decrypt: bool, threads: usize) -> Vec<[u8; 32]> {
        let n = chunks.len();
        #[cfg(feature = "parallel")]
        if threads > 1 && n > 1 {
            // split buf into disjoint per-chunk slices, then hand contiguous groups to threads
            let mut slices: Vec<&mut [u8]> = Vec::with_capacity(n);
            let mut rest = buf;
            let mut pos = 0;
            for &(off, len) in chunks {
                let (_, r) = rest.split_at_mut(off - pos);
                let (c, r2) = r.split_at_mut(len);
                slices.push(c);
                rest = r2;
                pos = off + len;
            }
            let per = n.div_ceil(threads);
            let mut keys = alloc::vec![[0u8; 32]; n];
            std::thread::scope(|sc| {
                let mut handles = Vec::new();
                let mut base = 0;
                let mut it = slices.into_iter();
                while base < n {
                    let group: Vec<&mut [u8]> = it.by_ref().take(per).collect();
                    let start = base;
                    base += group.len();
                    handles.push(sc.spawn(move || {
                        group
                            .into_iter()
                            .enumerate()
                            .map(|(j, d)| {
                                let i = start + j;
                                self.crypt_chunk(i, (i == n - 1) as u8, d, decrypt)
                            })
                            .collect::<Vec<_>>()
                    }));
                }
                let mut i = 0;
                for hd in handles {
                    for k in hd.join().expect("rehearsal worker panicked") {
                        keys[i] = k;
                        i += 1;
                    }
                }
            });
            return keys;
        }
        let _ = threads;
        chunks
            .iter()
            .enumerate()
            .map(|(i, &(off, len))| self.crypt_chunk(i, (i == n - 1) as u8, &mut buf[off..off + len], decrypt))
            .collect()
    }

    /// Encrypt chunks (optionally on `threads` worker threads) and hand each finished chunk to
    /// `consume(i, ciphertext, mac_key)` strictly in chunk order, as soon as it and all earlier
    /// chunks are done. Lets the sequential tag chain run while later chunks are still being
    /// encrypted. Chunks are dealt round-robin so they finish roughly in order.
    fn crypt_stream(&self, buf: &mut [u8], chunks: &[(usize, usize)], threads: usize, mut consume: impl FnMut(usize, &[u8], &[u8; 32])) {
        let n = chunks.len();
        #[cfg(feature = "parallel")]
        if threads > 1 && n > 1 {
            let threads = threads.min(n);
            let mut lists: Vec<Vec<(usize, &mut [u8])>> = (0..threads).map(|_| Vec::new()).collect();
            let mut rest = buf;
            let mut pos = 0;
            for (i, &(off, len)) in chunks.iter().enumerate() {
                let (_, r) = rest.split_at_mut(off - pos);
                let (c, r2) = r.split_at_mut(len);
                lists[i % threads].push((i, c));
                rest = r2;
                pos = off + len;
            }
            std::thread::scope(|sc| {
                let (tx, rx) = std::sync::mpsc::channel::<(usize, &mut [u8], [u8; 32])>();
                for list in lists {
                    let tx = tx.clone();
                    sc.spawn(move || {
                        for (i, d) in list {
                            let k = self.crypt_chunk(i, (i == n - 1) as u8, d, false);
                            if tx.send((i, d, k)).is_err() {
                                return;
                            }
                        }
                    });
                }
                drop(tx);
                let mut pending: Vec<Option<(&mut [u8], [u8; 32])>> = (0..n).map(|_| None).collect();
                let mut next = 0;
                for (i, d, k) in rx {
                    pending[i] = Some((d, k));
                    while next < n {
                        match pending[next].take() {
                            Some((d, k)) => {
                                consume(next, d, &k);
                                next += 1;
                            }
                            None => break,
                        }
                    }
                }
                assert_eq!(next, n, "rehearsal worker stopped early");
            });
            return;
        }
        let _ = threads;
        for (i, &(off, len)) in chunks.iter().enumerate() {
            let d = &mut buf[off..off + len];
            let k = self.crypt_chunk(i, (i == n - 1) as u8, d, false);
            consume(i, d, &k);
        }
    }
}

/// Seal a whole message as a v9 rehearsal stream. Returns (blob, final_tag).
pub fn seal_rehearsal(
    seed: &[u8; 128],
    msg: &[u8],
    pickup: &[u8; 16],
    nonce: &[u8; 16],
    chunk_size: usize,
    ad: &[u8],
) -> Result<(Vec<u8>, [u8; 32]), Error> {
    seal_rehearsal_threads(seed, msg, pickup, nonce, chunk_size, ad, 1)
}

/// Same as [`seal_rehearsal`] (identical bytes) but encrypts chunks on up to `threads` threads
/// (feature `parallel`; otherwise `threads` is ignored).
pub fn seal_rehearsal_threads(
    seed: &[u8; 128],
    msg: &[u8],
    pickup: &[u8; 16],
    nonce: &[u8; 16],
    chunk_size: usize,
    ad: &[u8],
    threads: usize,
) -> Result<(Vec<u8>, [u8; 32]), Error> {
    check_ad(ad)?;
    if chunk_size % 128 != 0 || !(REHEARSAL_CHUNK_MIN..=REHEARSAL_CHUNK_MAX).contains(&chunk_size) {
        return Err(Error::Input);
    }
    let nfull = msg.len() / chunk_size;
    if nfull + 1 > MAX_REHEARSAL_CHUNKS {
        return Err(Error::Input);
    }
    let cs32 = (chunk_size as u32).to_be_bytes();
    let ead = enc_ad(ad);
    let add = h(&[b"SN2/A", &ead]);
    let commit = mac(&k_commit(seed), &[b"U", b"\x09", MAGIC, pickup, nonce, &ead, &cs32]);
    let sch = reh_schedule(seed, pickup, nonce, &cs32, &add);
    let be = Auto::prepare(&sch);
    let st = RehStream { seed, pickup, nonce, cs32: &cs32, add: &add, sch, be };
    let (cl, rs) = (clef(seed), rehearsal_sig(seed));
    // padded plaintext: full chunks, then final = rest || 0x80 || zeros to a 128 multiple
    let mut buf = msg.to_vec();
    buf.push(0x80);
    let pad = (128 - (buf.len() - nfull * chunk_size) % 128) % 128;
    buf.resize(buf.len() + pad, 0);
    let mut chunks: Vec<(usize, usize)> = (0..nfull).map(|i| (i * chunk_size, chunk_size)).collect();
    chunks.push((nfull * chunk_size, buf.len() - nfull * chunk_size));
    let mut out = Vec::with_capacity(72 + buf.len() + 32 * chunks.len());
    for p in [b"\x09" as &[u8], MAGIC, pickup, nonce, &commit, &cs32] {
        out.extend_from_slice(p);
    }
    let mut prev = [0u8; 32];
    let nch = chunks.len();
    st.crypt_stream(&mut buf, &chunks, threads, |i, ct, key| {
        let fin = (i == nch - 1) as u8;
        let tag = mac(key, &[&cl, &rs, b"\x09", MAGIC, pickup, nonce, &commit, &cs32, &(i as u64).to_be_bytes(), &[fin], &add, &prev, ct]);
        out.extend_from_slice(ct);
        out.extend_from_slice(&tag);
        prev = tag;
    });
    Ok((out, prev))
}

pub fn open_rehearsal(seed: &[u8; 128], blob: &[u8], ad: &[u8]) -> Result<Vec<u8>, Error> {
    open_rehearsal_threads(seed, blob, ad, 1)
}

/// Same as [`open_rehearsal`] with chunk decryption on up to `threads` threads (feature
/// `parallel`). Every chunk tag (the whole chain) is verified before any plaintext is produced.
pub fn open_rehearsal_threads(seed: &[u8; 128], blob: &[u8], ad: &[u8], threads: usize) -> Result<Vec<u8>, Error> {
    check_ad(ad)?;
    if blob.len() < 72 + 160 || blob[0] != 9 || &blob[1..4] != MAGIC {
        return Err(Error::Format);
    }
    let (pickup, nonce, commit, cs32) = (&blob[4..20], &blob[20..36], &blob[36..68], &blob[68..72]);
    let cs = u32::from_be_bytes(cs32.try_into().unwrap()) as usize;
    if cs % 128 != 0 || !(REHEARSAL_CHUNK_MIN..=REHEARSAL_CHUNK_MAX).contains(&cs) {
        return Err(Error::Format);
    }
    let ead = enc_ad(ad);
    let add = h(&[b"SN2/A", &ead]);
    if !ct_eq(commit, &mac(&k_commit(seed), &[b"U", b"\x09", MAGIC, pickup, nonce, &ead, cs32])) {
        return Err(Error::Auth);
    }
    // chunk boundaries within the body: (ct offset, ct len) relative to body
    let body = &blob[72..];
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut pos = 0;
    while body.len() - pos > cs + 32 {
        if spans.len() + 1 >= MAX_REHEARSAL_CHUNKS {
            return Err(Error::Format);
        }
        spans.push((pos, cs));
        pos += cs + 32;
    }
    let last = body.len() - pos;
    if last < 160 || (last - 32) % 128 != 0 {
        return Err(Error::Format);
    }
    spans.push((pos, last - 32));
    let n = spans.len();
    let (cl, rs) = (clef(seed), rehearsal_sig(seed));
    // MAC keys (first 32 bytes of each chunk sponge) and the whole tag chain. Sequential by design
    // (each tag covers the previous one ahead of the ciphertext). No plaintext leaves this function
    // unless every tag matches.
    let verify = || -> bool {
        let mut prev = [0u8; 32];
        for (i, &(off, len)) in spans.iter().enumerate() {
            let fin = (i == n - 1) as u8;
            let mut mk = [0u8; 32];
            let info = [b"chunk\x09" as &[u8], pickup, nonce, cs32, &(i as u64).to_be_bytes(), &[fin], &add].concat();
            sponge(b"R", seed, &info, &mut mk);
            let (ct, tag) = (&body[off..off + len], &body[off + len..off + len + 32]);
            let want = mac(&mk, &[&cl, &rs, b"\x09", MAGIC, pickup, nonce, commit, cs32, &(i as u64).to_be_bytes(), &[fin], &add, &prev, ct]);
            if !ct_eq(tag, &want) {
                return false;
            }
            prev = want;
        }
        true
    };
    // gather ciphertexts contiguously (decrypted in place below)
    let mut pt: Vec<u8> = Vec::with_capacity(body.len());
    let mut chunks = Vec::with_capacity(n);
    for &(off, len) in &spans {
        chunks.push((pt.len(), len));
        pt.extend_from_slice(&body[off..off + len]);
    }
    #[cfg(feature = "parallel")]
    let overlap = threads > 1 && n > 1;
    #[cfg(not(feature = "parallel"))]
    let overlap = false;
    if !overlap {
        // one thread: check the whole chain first, then decrypt
        if !verify() {
            return Err(Error::Auth);
        }
        let sch = reh_schedule(seed, pickup, nonce, cs32, &add);
        let be = Auto::prepare(&sch);
        let st = RehStream { seed, pickup, nonce, cs32, add: &add, sch, be };
        st.crypt_all(&mut pt, &chunks, true, threads);
    } else {
        #[cfg(feature = "parallel")]
        {
            // threads > 1: this thread walks the tag chain while `threads - 1` workers decrypt into
            // the private buffer; on any mismatch the buffer is wiped and nothing is returned.
            let sch = reh_schedule(seed, pickup, nonce, cs32, &add);
            let be = Auto::prepare(&sch);
            let st = RehStream { seed, pickup, nonce, cs32, add: &add, sch, be };
            let ok = std::thread::scope(|sc| {
                let pt_ref = &mut pt;
                let chunks_ref = &chunks;
                let st_ref = &st;
                let h = sc.spawn(move || {
                    st_ref.crypt_all(pt_ref, chunks_ref, true, threads - 1);
                });
                let ok = verify();
                h.join().expect("rehearsal decrypt panicked");
                ok
            });
            if !ok {
                pt.iter_mut().for_each(|b| *b = 0);
                core::hint::black_box(&pt);
                return Err(Error::Auth);
            }
        }
    }
    let start = chunks[n - 1].0;
    let mut end = pt.len();
    while end > start && pt[end - 1] == 0 {
        end -= 1;
    }
    if end == start || pt[end - 1] != 0x80 {
        return Err(Error::Pad);
    }
    end -= 1;
    if end - start >= cs {
        return Err(Error::Pad);
    }
    pt.truncate(end);
    Ok(pt)
}

// ================= app layer: HKDF-SHA512 key expansion =================
/// seed = HKDF-SHA512(salt = 64 zero bytes, ikm = key, info = "Octavo app key v1", L = 128).
/// Rejects an empty key or an all-zero key (the Python app also rejects those).
pub fn app_seed(key: &[u8]) -> Result<[u8; 128], Error> {
    if key.is_empty() || key.iter().all(|&b| b == 0) {
        return Err(Error::Input);
    }
    type HmacSha512 = Hmac<Sha512>;
    let mut m = <HmacSha512 as Mac>::new_from_slice(&[0u8; 64]).unwrap();
    m.update(key);
    let prk = m.finalize().into_bytes();
    let mut okm = [0u8; 128];
    let mut t: Vec<u8> = Vec::new();
    for (i, chunk) in okm.chunks_mut(64).enumerate() {
        let mut m = <HmacSha512 as Mac>::new_from_slice(&prk).unwrap();
        m.update(&t);
        m.update(b"Octavo app key v1");
        m.update(&[(i + 1) as u8]);
        t = m.finalize().into_bytes().to_vec();
        chunk.copy_from_slice(&t[..chunk.len()]);
    }
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dec_block_rules() {
        let b = enc_block(b"hi");
        assert_eq!(dec_block(&b).unwrap(), b"hi");
        let mut bad = b;
        bad[127] = 1;
        assert_eq!(dec_block(&bad), Err(Error::Decode));
        let mut bad = b;
        bad[0] = 200;
        assert_eq!(dec_block(&bad), Err(Error::Decode));
        let full = enc_block(&[7u8; 127]);
        assert_eq!(dec_block(&full).unwrap(), [7u8; 127].to_vec());
    }
}

// wipe the context keys on drop (feature `zeroize`).
#[cfg(feature = "zeroize")]
impl Drop for Ctx {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.k.zeroize();
        self.clef.zeroize();
        self.kc.zeroize();
        self.ks.zeroize();
    }
}

#[cfg(feature = "stream")]
#[path = "stream.rs"]
pub mod stream;
