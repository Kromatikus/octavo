//! Constant-memory streaming v9 rehearsal seal/open over `std::io`.
//!
//! Byte-identical to [`super::seal_rehearsal`] / [`super::open_rehearsal`] (and to Python
//! `sneak_n2.encrypt_rehearsal_file` / `decrypt_rehearsal_file`): the blob layout is
//! `09 'SN2' pickup(16) nonce(16) commit(32) chunk_size(4, BE)` then, per chunk, `ct ‖ tag(32)`.
//!
//! Memory is O(threads × batch × chunk_size) regardless of the input length.
//!
//! **Open is streaming, like Python's `decrypt_rehearsal_file`:** every chunk's tag (and the tag
//! chain up to it) is verified before that chunk is written (with `threads > 1` the batch is
//! decrypted into a private buffer by `threads - 1` workers WHILE the calling thread walks the tag
//! chain; the buffer is wiped and nothing is written if any tag fails), but truncation or a
//! forged final chunk is only detected at the END of the stream, after earlier verified chunks
//! have been written to `out`. Callers that must not release anything from a rejected stream
//! (the CLI does this) write into a temporary file and publish it only after `Ok`.
//!
//! **Seal overlaps the tag chain with encryption:** workers encrypt the batch's chunks round-robin
//! and hand each finished chunk back in order, so the (inherently sequential) HMAC chain and the
//! write run on the calling thread while later chunks are still being encrypted.
//! The chunk keystream uses the multi-buffer sponge (`sha_mb`) via `reh_keys`/`sponge`.
//!
//! Secrets (chunk keys, MAC keys, plaintext batch buffers, the commitment key) are wiped
//! with `zeroize` after use; the schedule and backend tables are wiped on drop (feature `zeroize`).

use super::*;
use std::io::{self, Read, Write};
use zeroize::{Zeroize, Zeroizing};

/// Error from a streaming operation: an Octavo format/auth error, or an I/O error.
#[derive(Debug)]
pub enum StreamError {
    Crypto(Error),
    Io(io::Error),
}
impl From<Error> for StreamError {
    fn from(e: Error) -> Self {
        StreamError::Crypto(e)
    }
}
impl From<io::Error> for StreamError {
    fn from(e: io::Error) -> Self {
        StreamError::Io(e)
    }
}
impl core::fmt::Display for StreamError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StreamError::Crypto(Error::Format) => f.write_str("not a valid Octavo v9 stream (bad version, magic, chunk size or length)"),
            StreamError::Crypto(Error::Auth) => f.write_str("authentication failed (wrong key, wrong --ad, or the data was changed or truncated)"),
            StreamError::Crypto(Error::Decode) => f.write_str("decode error"),
            StreamError::Crypto(Error::Pad) => f.write_str("bad padding in the final chunk"),
            StreamError::Crypto(Error::Input) => f.write_str("input out of range (associated data too long, bad chunk size, or too many chunks)"),
            StreamError::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}
impl std::error::Error for StreamError {}

/// Tuning knobs. Output bytes never depend on `threads` or `batch_chunks`.
#[derive(Clone, Copy, Debug)]
pub struct StreamOptions {
    /// Plaintext bytes per non-final chunk (seal only): a multiple of 128 in 128..=1 MiB.
    pub chunk_size: usize,
    /// Worker threads (feature `parallel`; otherwise 1 is used).
    pub threads: usize,
    /// Chunks buffered per thread per batch.
    pub batch_chunks: usize,
}
impl Default for StreamOptions {
    fn default() -> Self {
        StreamOptions { chunk_size: 65536, threads: 1, batch_chunks: 4 }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub chunks: u64,
}

/// Read until `buf` is full or EOF; returns bytes read.
pub fn read_full<R: Read + ?Sized>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

struct Keys<'a> {
    seed: &'a [u8; 128],
    pickup: [u8; 16],
    nonce: [u8; 16],
    commit: [u8; 32],
    cs32: [u8; 4],
    add: [u8; 32],
    cl: [u8; 16],
    rs: [u8; 16],
    sch: Schedule,
    be: Auto,
}
impl Drop for Keys<'_> {
    fn drop(&mut self) {
        self.cl.zeroize();
        self.rs.zeroize();
    }
}

impl<'a> Keys<'a> {
    fn new(seed: &'a [u8; 128], pickup: [u8; 16], nonce: [u8; 16], commit: [u8; 32], cs32: [u8; 4], add: [u8; 32]) -> Self {
        let sch = reh_schedule(seed, &pickup, &nonce, &cs32, &add);
        let be = Auto::prepare(&sch);
        Keys { seed, pickup, nonce, commit, cs32, add, cl: clef(seed), rs: rehearsal_sig(seed), sch, be }
    }
    fn mac_key(&self, i: u64, fin: u8) -> Zeroizing<[u8; 32]> {
        let info = [b"chunk\x09" as &[u8], &self.pickup, &self.nonce, &self.cs32, &i.to_be_bytes(), &[fin], &self.add].concat();
        let mut mk = Zeroizing::new([0u8; 32]);
        sponge(b"R", self.seed, &info, &mut *mk);
        mk
    }
    fn tag(&self, mk: &[u8; 32], i: u64, fin: u8, prev: &[u8; 32], ct: &[u8]) -> [u8; 32] {
        mac(mk, &[&self.cl, &self.rs, b"\x09", MAGIC, &self.pickup, &self.nonce, &self.commit, &self.cs32, &i.to_be_bytes(), &[fin], &self.add, prev, ct])
    }
    /// XEX crypt of one chunk in place; returns its MAC key.
    fn crypt_one(&self, i: u64, fin: u8, data: &mut [u8], decrypt: bool) -> Zeroizing<[u8; 32]> {
        let nb = data.len() / 128;
        let mut keys = reh_keys(self.seed, &self.pickup, &self.nonce, &self.cs32, i, fin, &self.add, nb);
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
        let mut mk = Zeroizing::new([0u8; 32]);
        mk.copy_from_slice(&keys[..32]);
        keys.zeroize();
        mk
    }
    /// Crypt the contiguous chunks `buf[..len]` (each `cs` bytes, the last possibly shorter),
    /// global indices starting at `base`; the last one is final iff `last_final`. MAC keys are
    /// not needed by the caller (open derives them while verifying), so they are dropped (wiped).
    fn crypt_batch(&self, buf: &mut [u8], cs: usize, base: u64, last_final: bool, decrypt: bool, threads: usize) {
        let n = buf.len().div_ceil(cs);
        let fin = |j: usize| (last_final && j == n - 1) as u8;
        #[cfg(feature = "parallel")]
        if threads > 1 && n > 1 {
            let threads = threads.min(n);
            std::thread::scope(|sc| {
                let mut lists: Vec<Vec<(usize, &mut [u8])>> = (0..threads).map(|_| Vec::new()).collect();
                for (j, d) in buf.chunks_mut(cs).enumerate() {
                    lists[j % threads].push((j, d));
                }
                for list in lists {
                    sc.spawn(move || {
                        for (j, d) in list {
                            drop(self.crypt_one(base + j as u64, fin(j), d, decrypt));
                        }
                    });
                }
            });
            return;
        }
        let _ = threads;
        for (j, d) in buf.chunks_mut(cs).enumerate() {
            drop(self.crypt_one(base + j as u64, fin(j), d, decrypt));
        }
    }

    /// Encrypt the chunks of `buf` (as in `crypt_batch`) on `threads` workers, dealt round-robin,
    /// and call `consume(j, ciphertext, mac_key)` on the calling thread strictly in chunk order as
    /// soon as chunk j and all earlier ones are done, so the tag chain overlaps with encryption.
    fn seal_batch_ordered(&self, buf: &mut [u8], cs: usize, base: u64, last_final: bool, threads: usize, mut consume: impl FnMut(usize, &[u8], &[u8; 32])) {
        let n = buf.len().div_ceil(cs);
        let fin = |j: usize| (last_final && j == n - 1) as u8;
        #[cfg(feature = "parallel")]
        if threads > 1 && n > 1 {
            let threads = threads.min(n);
            std::thread::scope(|sc| {
                let (tx, rx) = std::sync::mpsc::channel::<(usize, &mut [u8], Zeroizing<[u8; 32]>)>();
                let mut lists: Vec<Vec<(usize, &mut [u8])>> = (0..threads).map(|_| Vec::new()).collect();
                for (j, d) in buf.chunks_mut(cs).enumerate() {
                    lists[j % threads].push((j, d));
                }
                for list in lists {
                    let tx = tx.clone();
                    sc.spawn(move || {
                        for (j, d) in list {
                            let k = self.crypt_one(base + j as u64, fin(j), d, false);
                            if tx.send((j, d, k)).is_err() {
                                return;
                            }
                        }
                    });
                }
                drop(tx);
                let mut pending: Vec<Option<(&mut [u8], Zeroizing<[u8; 32]>)>> = (0..n).map(|_| None).collect();
                let mut next = 0;
                for (j, d, k) in rx {
                    pending[j] = Some((d, k));
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
                assert_eq!(next, n, "octavo stream worker stopped early");
            });
            return;
        }
        let _ = threads;
        for (j, d) in buf.chunks_mut(cs).enumerate() {
            let k = self.crypt_one(base + j as u64, fin(j), d, false);
            consume(j, d, &k);
        }
    }
}

fn check_cs(cs: usize) -> bool {
    cs % 128 == 0 && (REHEARSAL_CHUNK_MIN..=REHEARSAL_CHUNK_MAX).contains(&cs)
}

/// Chunks per batch: threads x batch_chunks, but at most ~16 MiB of chunk data (never below one
/// chunk per thread), so memory stays bounded for any chunk size.
fn batch_len(o: &StreamOptions, cs: usize) -> usize {
    let t = if cfg!(feature = "parallel") { o.threads.max(1) } else { 1 };
    (t * o.batch_chunks.max(1)).min(((16usize << 20) / cs).max(t)).min(4096)
}

/// Seal everything readable from `input` as one v9 stream into `out`. Returns the summary and
/// the final tag. Identical bytes to `seal_rehearsal(seed, whole_input, pickup, nonce, cs, ad)`.
pub fn seal_stream<R: Read + ?Sized, W: Write + ?Sized>(
    seed: &[u8; 128],
    input: &mut R,
    out: &mut W,
    pickup: &[u8; 16],
    nonce: &[u8; 16],
    ad: &[u8],
    opts: &StreamOptions,
) -> Result<(Summary, [u8; 32]), StreamError> {
    check_ad(ad)?;
    let cs = opts.chunk_size;
    if !check_cs(cs) {
        return Err(Error::Input.into());
    }
    let cs32 = (cs as u32).to_be_bytes();
    let ead = enc_ad(ad);
    let add = h(&[b"SN2/A", &ead]);
    let mut kc = k_commit(seed);
    let commit = mac(&kc, &[b"U", b"\x09", MAGIC, pickup, nonce, &ead, &cs32]);
    kc.zeroize();
    let keys = Keys::new(seed, *pickup, *nonce, commit, cs32, add);
    let mut sum = Summary::default();
    let mut hdr = Vec::with_capacity(72);
    for p in [b"\x09" as &[u8], MAGIC, pickup, nonce, &commit, &cs32] {
        hdr.extend_from_slice(p);
    }
    out.write_all(&hdr)?;
    sum.bytes_out += 72;
    let bn = batch_len(opts, cs);
    let mut buf = Zeroizing::new(alloc::vec![0u8; bn * cs]);
    let mut index: u64 = 0;
    let mut prev = [0u8; 32];
    loop {
        let mut used = 0usize;
        let mut nchunks = 0usize;
        let mut final_seen = false;
        while nchunks < bn {
            let got = read_full(input, &mut buf[used..used + cs])?;
            sum.bytes_in += got as u64;
            nchunks += 1;
            if got == cs {
                used += cs;
            } else {
                buf[used + got] = 0x80;
                let len = (got + 1).div_ceil(128) * 128;
                buf[used + got + 1..used + len].fill(0);
                used += len;
                final_seen = true;
                break;
            }
        }
        if index + nchunks as u64 > MAX_REHEARSAL_CHUNKS as u64 {
            return Err(Error::Input.into());
        }
        // tags + writes on this thread, in order, while workers are still encrypting later chunks
        let mut werr: Option<io::Error> = None;
        let base = index;
        keys.seal_batch_ordered(&mut buf[..used], cs, base, final_seen, opts.threads, |j, ct, mk| {
            if werr.is_some() {
                return;
            }
            let fin = (final_seen && j == nchunks - 1) as u8;
            let tag = keys.tag(mk, base + j as u64, fin, &prev, ct);
            if let Err(e) = out.write_all(ct).and_then(|_| out.write_all(&tag)) {
                werr = Some(e);
                return;
            }
            sum.bytes_out += (ct.len() + 32) as u64;
            prev = tag;
        });
        if let Some(e) = werr {
            return Err(e.into());
        }
        index += nchunks as u64;
        sum.chunks = index;
        if final_seen {
            break;
        }
    }
    out.flush()?;
    Ok((sum, prev))
}

/// Open a v9 stream from `input`, writing plaintext to `out` chunk by chunk (each chunk only after
/// its tag verified). See the module docs: on `Err`, `out` may already hold a verified prefix.
pub fn open_stream<R: Read + ?Sized, W: Write + ?Sized>(
    seed: &[u8; 128],
    input: &mut R,
    out: &mut W,
    ad: &[u8],
    opts: &StreamOptions,
) -> Result<Summary, StreamError> {
    check_ad(ad)?;
    let mut hdr = [0u8; 72];
    let got = read_full(input, &mut hdr)?;
    if got < 72 || hdr[0] != 9 || &hdr[1..4] != MAGIC {
        return Err(Error::Format.into());
    }
    let mut sum = Summary { bytes_in: 72, ..Summary::default() };
    let pickup: [u8; 16] = hdr[4..20].try_into().unwrap();
    let nonce: [u8; 16] = hdr[20..36].try_into().unwrap();
    let commit: [u8; 32] = hdr[36..68].try_into().unwrap();
    let cs32: [u8; 4] = hdr[68..72].try_into().unwrap();
    let cs = u32::from_be_bytes(cs32) as usize;
    if !check_cs(cs) {
        return Err(Error::Format.into());
    }
    let ead = enc_ad(ad);
    let add = h(&[b"SN2/A", &ead]);
    let mut kc = k_commit(seed);
    let want = mac(&kc, &[b"U", b"\x09", MAGIC, &pickup, &nonce, &ead, &cs32]);
    kc.zeroize();
    if !ct_eq(&commit, &want) {
        return Err(Error::Auth.into());
    }
    let keys = Keys::new(seed, pickup, nonce, commit, cs32, add);
    let unit = cs + 32;
    let bn = batch_len(opts, cs);
    // raw batch (ct ‖ tag per chunk, + 1 look-ahead byte) and a separate private plaintext buffer,
    // so the tag chain can be checked over the raw bytes while workers decrypt the copy.
    let mut arena = alloc::vec![0u8; bn * unit + 1];
    let mut buf = Zeroizing::new(alloc::vec![0u8; bn * cs]);
    let mut spans: Vec<(usize, usize, u8)> = Vec::with_capacity(bn);
    let mut carry: Option<u8> = None;
    let mut index: u64 = 0;
    let mut prev = [0u8; 32];
    loop {
        let mut used = 0usize;
        let mut nchunks = 0usize;
        let mut final_seen = false;
        let mut pos = 0usize;
        let mut have = 0usize;
        if let Some(b) = carry.take() {
            arena[0] = b;
            have = 1;
        }
        spans.clear();
        while nchunks < bn {
            let got = read_full(input, &mut arena[pos + have..pos + unit + 1])?;
            sum.bytes_in += got as u64;
            have += got;
            let (ctlen, fin) = if have == unit + 1 {
                if index + nchunks as u64 + 1 >= MAX_REHEARSAL_CHUNKS as u64 {
                    return Err(Error::Format.into());
                }
                (cs, 0u8)
            } else {
                if have < 160 || (have - 32) % 128 != 0 {
                    return Err(Error::Format.into());
                }
                (have - 32, 1u8)
            };
            spans.push((pos, ctlen, fin));
            buf[used..used + ctlen].copy_from_slice(&arena[pos..pos + ctlen]);
            used += ctlen;
            nchunks += 1;
            if fin == 1 {
                final_seen = true;
                break;
            }
            // the look-ahead byte is already the first byte of the next unit
            pos += unit;
            have = 1;
        }
        if !final_seen {
            carry = Some(arena[pos]);
        }
        // the tag chain for this batch (sequential by design); Some(last tag) iff every tag matches
        let verify = |mut prev: [u8; 32]| -> Option<[u8; 32]> {
            for (j, &(off, ctlen, fin)) in spans.iter().enumerate() {
                let i = index + j as u64;
                let (ct, tag) = (&arena[off..off + ctlen], &arena[off + ctlen..off + ctlen + 32]);
                let mk = keys.mac_key(i, fin);
                let want = keys.tag(&mk, i, fin, &prev, ct);
                if !ct_eq(tag, &want) {
                    return None;
                }
                prev = want;
            }
            Some(prev)
        };
        #[cfg(feature = "parallel")]
        let overlap = opts.threads > 1 && nchunks > 1;
        #[cfg(not(feature = "parallel"))]
        let overlap = false;
        let verified = if overlap {
            // workers decrypt into the private buffer while this thread walks the tag chain
            let (pt, keys_ref, threads) = (&mut buf[..used], &keys, opts.threads - 1);
            let base = index;
            std::thread::scope(|sc| {
                let h = sc.spawn(move || keys_ref.crypt_batch(pt, cs, base, final_seen, true, threads));
                let v = verify(prev);
                h.join().expect("octavo stream worker panicked");
                v
            })
        } else {
            let v = verify(prev);
            if v.is_some() {
                keys.crypt_batch(&mut buf[..used], cs, index, final_seen, true, opts.threads);
            }
            v
        };
        match verified {
            Some(p) => prev = p,
            None => {
                buf[..used].zeroize();
                return Err(Error::Auth.into());
            }
        }
        let mut end = used;
        if final_seen {
            let start = (nchunks - 1) * cs;
            while end > start && buf[end - 1] == 0 {
                end -= 1;
            }
            if end == start || buf[end - 1] != 0x80 {
                return Err(Error::Pad.into());
            }
            end -= 1;
            if end - start >= cs {
                return Err(Error::Pad.into());
            }
        }
        out.write_all(&buf[..end])?;
        sum.bytes_out += end as u64;
        buf[..used].zeroize();
        index += nchunks as u64;
        sum.chunks = index;
        if final_seen {
            break;
        }
    }
    out.flush()?;
    Ok(sum)
}
