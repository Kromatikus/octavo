//! Library side of the `octavo` command-line tool (homemade Octavo cipher, v9 rehearsal files).
//!
//! **Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.**

pub mod earworm;
pub mod fsio;
pub mod policy;
pub mod sid;

use sha2::{Digest, Sha256};
use std::path::Path;
use zeroize::Zeroizing;

pub use octavo_core::formats::stream::{open_stream, seal_stream, StreamError, StreamOptions, Summary};

pub const HONEST: &str = "Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.";

pub fn hex(b: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(2 * b.len());
    for &x in b {
        s.push(D[(x >> 4) as usize] as char);
        s.push(D[(x & 15) as usize] as char);
    }
    s
}

/// Seed (key) held in memory; wiped on drop.
pub type Seed = Zeroizing<[u8; 128]>;

#[derive(Debug)]
pub enum KeyError {
    Io(std::io::Error),
    Parse(String),
    Weak(String),
}
impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyError::Io(e) => write!(f, "{e}"),
            KeyError::Parse(s) => write!(f, "{s}"),
            KeyError::Weak(s) => write!(f, "weak seed refused: {s} (see `octavo policy`; make a key with `octavo keygen`)"),
        }
    }
}

/// Parse a key file's text: UTF-8, only hex digits and whitespace, exactly 256 hex digits.
pub fn parse_seed_text(data: &[u8]) -> Result<Seed, KeyError> {
    let text = std::str::from_utf8(data).map_err(|_| KeyError::Parse("key file is not UTF-8 text".into()))?;
    let mut seed: Seed = Zeroizing::new([0u8; 128]);
    let mut n = 0usize;
    let mut half = 0u8;
    for c in text.chars() {
        if c.is_whitespace() {
            continue;
        }
        let v = c.to_digit(16).ok_or_else(|| KeyError::Parse("key file has characters other than hex digits and whitespace".into()))? as u8;
        if n >= 256 {
            n += 1;
            continue;
        }
        if n % 2 == 0 {
            half = v << 4;
        } else {
            seed[n / 2] = half | v;
        }
        n += 1;
    }
    if n != 256 {
        return Err(KeyError::Parse(format!("seed must be 256 hex digits, got {n}")));
    }
    Ok(seed)
}

/// Check a seed against the weak-seed rule.
pub fn check_seed(seed: &[u8; 128]) -> Result<(), KeyError> {
    match policy::weak_seed_reason(seed) {
        None => Ok(()),
        Some(r) => Err(KeyError::Weak(r)),
    }
}

/// Load + parse + policy-check a key file. Returns (seed, warnings).
pub fn load_key(p: &Path) -> Result<(Seed, Vec<String>), KeyError> {
    let (data, warn) = fsio::read_key_file(p).map_err(KeyError::Io)?;
    let seed = parse_seed_text(&data)?;
    check_seed(&seed)?;
    Ok((seed, warn))
}

/// One fresh draw from the OS CSPRNG, checked once, never redrawn (as Python keygen()).
pub fn keygen_seed() -> Result<Seed, String> {
    let mut seed: Seed = Zeroizing::new([0u8; 128]);
    getrandom::getrandom(&mut *seed).map_err(|e| format!("OS RNG failed: {e}"))?;
    if let Some(r) = policy::weak_seed_reason(&*seed) {
        return Err(format!(
            "the OS RNG output failed the weak-seed rule ({r}); expected far less than once in 10^9 draws, so the RNG or the policy is broken. keygen does not redraw."
        ));
    }
    Ok(seed)
}

/// Key file text in the Python load_seed/save_seed format: 256 hex digits and a newline.
pub fn seed_file_text(seed: &[u8; 128]) -> Zeroizing<Vec<u8>> {
    let mut v = Zeroizing::new(Vec::with_capacity(257));
    const D: &[u8; 16] = b"0123456789abcdef";
    for &x in seed.iter() {
        v.push(D[(x >> 4) as usize]);
        v.push(D[(x & 15) as usize]);
    }
    v.push(b'\n');
    v
}

/// Fresh 16-byte value shaped like Python's `_fresh_pickup` / `_fresh_stream_nonce`:
/// SHA-256(prefix ‖ urandom(16) ‖ time_ns(8) ‖ counter(8) ‖ pid(4))[:16].
pub fn fresh16(prefix: &[u8]) -> [u8; 16] {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    let mut r = [0u8; 16];
    getrandom::getrandom(&mut r).expect("OS RNG");
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0);
    let c = CTR.fetch_add(1, Ordering::Relaxed) + 1;
    let d = Sha256::new()
        .chain_update(prefix)
        .chain_update(r)
        .chain_update(t.to_be_bytes())
        .chain_update(c.to_be_bytes())
        .chain_update(std::process::id().to_be_bytes())
        .finalize();
    d[..16].try_into().unwrap()
}
