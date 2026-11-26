//! Library side of `n3file`: a streaming file container (SN3F v1) built on the experimental
//! N3 0x1C AEAD (PMAC-SIV over the 1024-bit N3 block cipher). See FORMAT.md.
//!
//! **Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.**

pub mod format;
pub mod fsio;
pub mod policy;

use std::path::Path;
use zeroize::Zeroizing;

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

/// Parse an even-length hex string (whitespace not allowed).
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return None;
    }
    let v = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    b.chunks(2).map(|p| Some((v(p[0])? << 4) | v(p[1])?)).collect()
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
            KeyError::Weak(s) => write!(f, "weak seed refused: {s} (see `n3file policy`; make a key with `n3file keygen`)"),
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

/// Check a seed against the weak-seed rule (port of N2's policy).
pub fn check_seed(seed: &[u8; 128]) -> Result<(), KeyError> {
    match policy::weak_seed_reason(&seed[..]) {
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

/// One fresh draw from the OS CSPRNG, checked once, never redrawn.
pub fn keygen_seed() -> Result<Seed, String> {
    let mut seed: Seed = Zeroizing::new([0u8; 128]);
    getrandom::getrandom(&mut seed[..]).map_err(|e| format!("OS RNG failed: {e}"))?;
    if let Some(r) = policy::weak_seed_reason(&seed[..]) {
        return Err(format!("the fresh OS-RNG seed failed the weak-seed rule ({r}); not redrawing: the RNG or the policy is broken"));
    }
    Ok(seed)
}

/// Key file text: 256 lowercase hex digits and a newline.
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
