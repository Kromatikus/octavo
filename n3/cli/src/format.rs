//! SN3F v1: a chunked, online (STREAM-style) file container over the N3 0x1C AEAD. See FORMAT.md.
//!
//! The AEAD itself (and its 0x1C single-blob format) is used unchanged as a primitive; this file
//! only decides how a stream is cut into chunks and what nonce/AD each chunk is sealed under.

use octavo_n3_draft3::aead::{Aead, AEAD_FORMAT, AEAD_NONCE_LEN, HEADER_LEN as BLOB_HEADER_LEN, TAG_LEN};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};

pub const MAGIC: &[u8; 5] = b"SN3F/";
pub const VERSION: u8 = 0x01;
/// magic(5) || version(1) || chunk_size u32le(4) || file_nonce(16)
pub const FILE_HEADER_LEN: usize = 26;
pub const FILE_NONCE_LEN: usize = 16;
pub const MIN_CHUNK: usize = 128;
pub const MAX_CHUNK: usize = 1 << 20;
pub const DEFAULT_CHUNK: usize = 65536;
/// Chunks buffered per worker thread per batch (memory ~ 2 x threads x this x chunk size).
pub const BATCH_PER_THREAD: usize = 4;

#[derive(Debug)]
pub enum FileError {
    Io(io::Error),
    /// Not an SN3F v1 file, or a damaged header/length.
    Format(String),
    /// Chunk `n` (0-based) did not verify: wrong key/AD, tampering, reordering, truncation, appending.
    Auth(u64),
}
impl std::fmt::Display for FileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileError::Io(e) => write!(f, "I/O error: {e}"),
            FileError::Format(s) => write!(f, "not a valid SN3F v1 file: {s}"),
            FileError::Auth(i) => write!(
                f,
                "authentication failed at chunk {i} (wrong key or AD, or the file was modified, reordered, truncated or extended)"
            ),
        }
    }
}
impl From<io::Error> for FileError {
    fn from(e: io::Error) -> Self {
        FileError::Io(e)
    }
}

pub fn check_chunk_size(n: usize) -> Result<(), String> {
    if !(MIN_CHUNK..=MAX_CHUNK).contains(&n) || n % 128 != 0 {
        return Err(format!("chunk size must be a multiple of 128 in {MIN_CHUNK}..={MAX_CHUNK}, got {n}"));
    }
    Ok(())
}

pub fn header_bytes(chunk_size: usize, file_nonce: &[u8; FILE_NONCE_LEN]) -> [u8; FILE_HEADER_LEN] {
    let mut h = [0u8; FILE_HEADER_LEN];
    h[..5].copy_from_slice(MAGIC);
    h[5] = VERSION;
    h[6..10].copy_from_slice(&(chunk_size as u32).to_le_bytes());
    h[10..].copy_from_slice(file_nonce);
    h
}

/// Parse and validate a header; returns the chunk size.
pub fn parse_header(h: &[u8; FILE_HEADER_LEN]) -> Result<usize, FileError> {
    if &h[..5] != MAGIC {
        return Err(FileError::Format("bad magic (expected \"SN3F/\")".into()));
    }
    if h[5] != VERSION {
        return Err(FileError::Format(format!("unsupported version 0x{:02x}", h[5])));
    }
    let cs = u32::from_le_bytes(h[6..10].try_into().unwrap()) as usize;
    check_chunk_size(cs).map_err(FileError::Format)?;
    Ok(cs)
}

/// Per-file context: header + SHA-256(user AD), from which each chunk's nonce and AD derive.
pub struct Ctx {
    header: [u8; FILE_HEADER_LEN],
    ad_hash: [u8; 32],
}
impl Ctx {
    pub fn new(header: [u8; FILE_HEADER_LEN], user_ad: &[u8]) -> Ctx {
        Ctx { header, ad_hash: Sha256::digest(user_ad).into() }
    }
    /// nonce_i = SHA-256("SN3F/nonce" || header || u64le(i) || final)[..16]
    pub fn nonce(&self, i: u64, fin: bool) -> [u8; AEAD_NONCE_LEN] {
        let mut h = Sha256::new();
        h.update(b"SN3F/nonce");
        h.update(self.header);
        h.update(i.to_le_bytes());
        h.update([fin as u8]);
        h.finalize()[..AEAD_NONCE_LEN].try_into().unwrap()
    }
    /// ad_i = "SN3F/ad" || header || SHA-256(user AD) || u64le(i) || final   (74 bytes)
    pub fn ad(&self, i: u64, fin: bool) -> [u8; 74] {
        let mut a = [0u8; 74];
        a[..7].copy_from_slice(b"SN3F/ad");
        a[7..33].copy_from_slice(&self.header);
        a[33..65].copy_from_slice(&self.ad_hash);
        a[65..73].copy_from_slice(&i.to_le_bytes());
        a[73] = fin as u8;
        a
    }
}

/// Read until `buf` holds `n` bytes or EOF; returns the bytes read (<= n).
fn read_up_to<R: Read>(r: &mut R, n: usize) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(n);
    r.take(n as u64).read_to_end(&mut buf)?;
    Ok(buf)
}

/// Deterministic parallel map: contiguous slices per thread, results in input order.
fn par_map<T: Sync, U: Send>(items: &[T], threads: usize, f: impl Fn(&T) -> U + Sync) -> Vec<U> {
    let t = threads.max(1).min(items.len().max(1));
    if t <= 1 {
        return items.iter().map(&f).collect();
    }
    let per = items.len().div_ceil(t);
    let f = &f;
    std::thread::scope(|s| {
        let hs: Vec<_> = items.chunks(per).map(|c| s.spawn(move || c.iter().map(f).collect::<Vec<U>>())).collect();
        hs.into_iter().flat_map(|h| h.join().expect("worker panicked")).collect()
    })
}

/// A chunk (or record) with its index and final flag.
struct Item {
    idx: u64,
    fin: bool,
    data: Vec<u8>,
}

/// Cuts a reader into items of exactly `unit` bytes, the last one marked final (it may be short;
/// it is empty only when the whole input is empty). One item of lookahead.
struct Cutter<R> {
    r: R,
    unit: usize,
    next: Option<Vec<u8>>,
    idx: u64,
    done: bool,
}
impl<R: Read> Cutter<R> {
    fn new(r: R, unit: usize) -> Cutter<R> {
        Cutter { r, unit, next: None, idx: 0, done: false }
    }
    fn batch(&mut self, max: usize) -> io::Result<Vec<Item>> {
        let mut out = Vec::new();
        while !self.done && out.len() < max {
            let cur = match self.next.take() {
                Some(c) => c,
                None => read_up_to(&mut self.r, self.unit)?,
            };
            let fin = if cur.len() < self.unit {
                true
            } else {
                let nx = read_up_to(&mut self.r, self.unit)?;
                if nx.is_empty() {
                    true
                } else {
                    self.next = Some(nx);
                    false
                }
            };
            out.push(Item { idx: self.idx, fin, data: cur });
            self.idx += 1;
            self.done = fin;
        }
        Ok(out)
    }
}

pub struct Summary {
    pub chunks: u64,
    pub bytes: u64,
}

/// Seal `r` into an SN3F v1 stream on `w`. `aead` should be single-threaded (`with_threads(1)`);
/// parallelism is across chunks. Output bytes do not depend on `threads`.
pub fn seal_stream<R: Read, W: Write + ?Sized>(
    aead: &Aead,
    r: R,
    w: &mut W,
    chunk_size: usize,
    user_ad: &[u8],
    file_nonce: &[u8; FILE_NONCE_LEN],
    threads: usize,
) -> Result<Summary, FileError> {
    check_chunk_size(chunk_size).map_err(FileError::Format)?;
    let header = header_bytes(chunk_size, file_nonce);
    let ctx = Ctx::new(header, user_ad);
    w.write_all(&header)?;
    let mut cut = Cutter::new(r, chunk_size);
    let mut sum = Summary { chunks: 0, bytes: 0 };
    loop {
        let items = cut.batch(threads.max(1) * BATCH_PER_THREAD)?;
        if items.is_empty() {
            break;
        }
        let sealed = par_map(&items, threads, |it| {
            let blob = aead.seal(&ctx.nonce(it.idx, it.fin), &ctx.ad(it.idx, it.fin), &it.data).expect("chunk within AEAD limits");
            debug_assert_eq!(blob[BLOB_HEADER_LEN - 1], AEAD_FORMAT);
            blob
        });
        for (it, blob) in items.iter().zip(&sealed) {
            // record = tag || ct (the blob's "SN3C/"||0x1C||nonce prefix is implied)
            w.write_all(&blob[BLOB_HEADER_LEN + AEAD_NONCE_LEN..])?;
            sum.chunks += 1;
            sum.bytes += it.data.len() as u64;
        }
    }
    Ok(sum)
}

/// Open an SN3F v1 stream. Plaintext is written to `w` batch by batch, each chunk only after it
/// verified; on any error the caller must discard what was written (the CLI uses a private
/// temporary file that is published only when this returns Ok).
pub fn open_stream<R: Read, W: Write + ?Sized>(aead: &Aead, mut r: R, w: &mut W, user_ad: &[u8], threads: usize) -> Result<Summary, FileError> {
    let mut header = [0u8; FILE_HEADER_LEN];
    let got = read_up_to(&mut r, FILE_HEADER_LEN)?;
    if got.len() < FILE_HEADER_LEN {
        return Err(FileError::Format("shorter than the 26-byte header".into()));
    }
    header.copy_from_slice(&got);
    let chunk_size = parse_header(&header)?;
    let ctx = Ctx::new(header, user_ad);
    let mut cut = Cutter::new(r, TAG_LEN + chunk_size);
    let mut sum = Summary { chunks: 0, bytes: 0 };
    loop {
        let items = cut.batch(threads.max(1) * BATCH_PER_THREAD)?;
        if items.is_empty() {
            break;
        }
        let opened = par_map(&items, threads, |it| {
            if it.data.len() < TAG_LEN {
                return Err(FileError::Format(format!("chunk {} is shorter than its 32-byte tag (truncated)", it.idx)));
            }
            let mut blob = Vec::with_capacity(BLOB_HEADER_LEN + AEAD_NONCE_LEN + it.data.len());
            blob.extend_from_slice(b"SN3C/");
            blob.push(AEAD_FORMAT);
            blob.extend_from_slice(&ctx.nonce(it.idx, it.fin));
            blob.extend_from_slice(&it.data);
            aead.open(&ctx.ad(it.idx, it.fin), &blob).map_err(|_| FileError::Auth(it.idx))
        });
        for pt in opened {
            let pt = pt?;
            w.write_all(&pt)?;
            sum.chunks += 1;
            sum.bytes += pt.len() as u64;
        }
    }
    Ok(sum)
}
