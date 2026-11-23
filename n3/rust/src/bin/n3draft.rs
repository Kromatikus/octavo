//! Tiny stdin tool: each line is `e|d <seed_hex> <nonce_hex> <block_hex>`.
//! Prints the resulting 128-byte block as hex. Used by tools/verify_draft.py.
//! fix1: malformed input (bad hex, odd length, non-ASCII, invalid UTF-8, wrong
//! lengths, bad op) is reported as `line N: ...` on stderr with exit code 2.
//! No panics on any input.

use octavo_n3_draft3::{Cipher, BLOCK_LEN, NONCE_LEN, SEED_LEN};
use std::io::{self, BufRead, Write};

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return Err("odd hex length".into());
    }
    b.chunks_exact(2)
        .map(|p| match (hex_val(p[0]), hex_val(p[1])) {
            (Some(h), Some(l)) => Ok(h << 4 | l),
            _ => Err("invalid hex digit".to_string()),
        })
        .collect()
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn arr<const N: usize>(v: &[u8], what: &str) -> Result<[u8; N], String> {
    v.try_into().map_err(|_| format!("{what} must be {N} bytes, got {}", v.len()))
}

fn parse_line(line: &str) -> Result<(bool, [u8; SEED_LEN], [u8; NONCE_LEN], [u8; BLOCK_LEN]), String> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() != 4 {
        return Err("expected `e|d seed nonce block`".into());
    }
    let enc = match parts[0] {
        "e" => true,
        "d" => false,
        _ => return Err("op must be e or d".into()),
    };
    let seed = arr::<SEED_LEN>(&hex_decode(parts[1]).map_err(|e| format!("seed: {e}"))?, "seed")?;
    let nonce = arr::<NONCE_LEN>(&hex_decode(parts[2]).map_err(|e| format!("nonce: {e}"))?, "nonce")?;
    let block = arr::<BLOCK_LEN>(&hex_decode(parts[3]).map_err(|e| format!("block: {e}"))?, "block")?;
    Ok((enc, seed, nonce, block))
}

fn fail(lineno: usize, msg: &str) -> ! {
    eprintln!("line {lineno}: {msg}");
    std::process::exit(2);
}

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut cached: Option<([u8; SEED_LEN], [u8; NONCE_LEN], Cipher)> = None;
    for (i, raw) in stdin.lock().split(b'\n').enumerate() {
        let lineno = i + 1;
        let raw = match raw {
            Ok(r) => r,
            Err(e) => fail(lineno, &format!("read error: {e}")),
        };
        let line = match std::str::from_utf8(&raw) {
            Ok(s) => s.trim(),
            Err(_) => fail(lineno, "not valid UTF-8"),
        };
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (enc, seed, nonce, block) = match parse_line(line) {
            Ok(v) => v,
            Err(e) => fail(lineno, &e),
        };
        let hit = matches!(&cached, Some((s, n, _)) if *s == seed && *n == nonce);
        if !hit {
            cached = Some((seed, nonce, Cipher::new(&seed, &nonce)));
        }
        let cipher = match &cached {
            Some((_, _, c)) => c,
            None => fail(lineno, "internal: no cipher"),
        };
        let out = if enc { cipher.encrypt_block(&block) } else { cipher.decrypt_block(&block) };
        if writeln!(stdout, "{}", hex_encode(&out)).is_err() {
            std::process::exit(3);
        }
    }
}
