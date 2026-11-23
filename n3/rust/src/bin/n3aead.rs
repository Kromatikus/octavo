//! Lab CLI for the SN3C/ 0x1C AEAD (fix2 PMAC-SIV). The block cipher is still
//! format 0x1B. This tool seals and opens 0x1C blobs only; 0x1B CMAC-SIV blobs
//! from fix1 are rejected (open them with the fix1 `n3aead`). Homemade; for real
//! secrets use AES-GCM-SIV, age, or libsodium.
//!
//! usage: n3aead seal <seed_hex(256)> <nonce_hex(32)> <ad_hex|-> < plaintext > blob
//!        n3aead open <seed_hex(256)> <ad_hex|-> < blob > plaintext
//! Errors go to stderr with exit code 2 (bad args) or 1 (rejected blob). No panics on input.
use octavo_n3_draft3::aead::Aead;
use std::io::{Read, Write};

fn hex(s: &str) -> Result<Vec<u8>, String> {
    if s == "-" { return Ok(vec![]); }
    let b = s.as_bytes();
    if b.len() % 2 != 0 { return Err("odd hex length".into()); }
    let v = |c: u8| match c { b'0'..=b'9' => Some(c - b'0'), b'a'..=b'f' => Some(c - b'a' + 10), b'A'..=b'F' => Some(c - b'A' + 10), _ => None };
    b.chunks_exact(2).map(|p| match (v(p[0]), v(p[1])) { (Some(h), Some(l)) => Ok(h << 4 | l), _ => Err("invalid hex".to_string()) }).collect()
}
fn die(code: i32, m: &str) -> ! { eprintln!("n3aead: {m}"); std::process::exit(code) }
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let mut input = Vec::new();
    if std::io::stdin().read_to_end(&mut input).is_err() { die(2, "read error"); }
    let seed_of = |s: &str| -> [u8; 128] { hex(s).ok().and_then(|v| v.try_into().ok()).unwrap_or_else(|| die(2, "seed must be 128 bytes of hex")) };
    let out = match (a.get(1).map(|s| s.as_str()), a.len()) {
        (Some("seal"), 5) => {
            let nonce: [u8; 16] = hex(&a[3]).ok().and_then(|v| v.try_into().ok()).unwrap_or_else(|| die(2, "nonce must be 16 bytes of hex"));
            let ad = hex(&a[4]).unwrap_or_else(|e| die(2, &e));
            Aead::new(&seed_of(&a[2])).seal(&nonce, &ad, &input).unwrap_or_else(|e| die(1, &e.to_string()))
        }
        (Some("open"), 4) => {
            let ad = hex(&a[3]).unwrap_or_else(|e| die(2, &e));
            Aead::new(&seed_of(&a[2])).open(&ad, &input).unwrap_or_else(|e| die(1, &e.to_string()))
        }
        _ => die(2, "usage: n3aead seal <seed_hex(256)> <nonce_hex(32)> <ad_hex|-> | n3aead open <seed_hex(256)> <ad_hex|->  (SN3C/ 0x1C PMAC-SIV; 0x1B blobs are not supported)"),
    };
    if std::io::stdout().write_all(&out).is_err() { std::process::exit(3); }
}
