//! Weak-seed policy: a line-by-line port of Python `sneak_n2._weak_seed_reason` (same thresholds,
//! same order, same reason strings), plus the CLI's own input rules (see SEED_POLICY.md).
//!
//! It is a SANITY CHECK against guessable STRUCTURE (zero padding, text, counters, repeats, a few
//! listed constants), not an entropy test: passing it does NOT make a seed secret. `keygen` (128
//! bytes from the OS CSPRNG) is the real protection.

use sha2::{Digest, Sha256};

pub const SEED_MIN_DISTINCT_NONZERO: usize = 32;
pub const SEED_MAX_BYTE_COUNT: usize = 11;
pub const SEED_WEIGHT_RANGE: (u32, u32) = (384, 640);
pub const SEED_MAX_LAG_EQUAL: usize = 13;
pub const SEED_MAX_LAG_DIFF: usize = 13;
pub const SEED_DIFF_LAGS: [usize; 8] = [1, 2, 3, 4, 8, 16, 32, 64];
pub const SEED_MAX_MONOTONE_RUN: usize = 15;

/// SHA-256 of the PUBLIC demo seed (sneak1024-seed.txt, published in score/vectors.json).
pub const DEMO_SEED_SHA256: &str = "8d1f7c16876c149c2d445c2817a230ffaaec9d8a2fc9769e2f3aae155e3b8e24";

/// SHA-256 of 128-byte public constants (pi, e, sqrt2, sqrt3, sqrt5, golden ratio, ln2, SHA-256 K
/// halves, SHA-512 K[0:16], SHA-512 H x2, SHA-256 H x4, SM4 and AES S-box halves), copied from
/// sneak_n2.py `KNOWN_CONSTANT_SEEDS_SHA256`.
pub const KNOWN_CONSTANT_SEEDS_SHA256: [&str; 16] = [
    "03c50285b60e6a6dbadb58aaf888d50c1600651f7d1efbc85babf115955a9d82",
    "0ce7c215e60878a317417033e689573e817b94fa7ff54f17dc67451c86192cf2",
    "34be65dcec3623805ccd321f2334b175695f0baac6e68686c1282accdfda7066",
    "466b9a4c5f07776366b1b8344bcecfb535d3f625f39d4aee789321b40b9997bd",
    "55744ff6cd524c2f7c027e7d3135124c9ebe735528f5089701be4a7d8f8bcac4",
    "59f02e0b558821a9e0754a16238042dae0a8e160f399d0433891ee5f3206d3d8",
    "66c7cb6724de8cdb002eab74a963da538a43f82981614568842a188ac30c5cac",
    "6bc97b996e75d9740ce3a50f3c98f0a5d7c4e6a7d19f8247e6527f1e54b81743",
    "7869fb9100d9b0d0d92bf2bbcfb52265c57f47737d8244af09bec87a35214752",
    "9b218780eb7e2b53d8bff225e502fae6292f53fa494fa4008e97094e81f3f23f",
    "9f8873c9039f794c5b67cee5de3694ee5b0424230d8d40b42ca4fa7ba1a51ee4",
    "ac8042d65d6f9dca088981a6e585ce8b8b2ca4b690a5979a2440b5296f0e51c8",
    "d2c917c55c86db7769a169d0ee5b8bf63428307d11168effdb4ddb27a0fa1cd3",
    "d47ef496a677ab86f1766c679017b62da575fc4fc945ebbeb8eb185f1225392c",
    "e0f509b5d111471aecae1f40c18db29d1e1c5d05f42db79db4bae260706e856d",
    "f9922e9a37f3a9ac7ee1c689396035b9460d2d89f03e950692be336959dcc08c",
];

pub fn sha256_hex(b: &[u8]) -> String {
    crate::hex(&Sha256::digest(b))
}

pub fn is_demo_seed(seed: &[u8]) -> bool {
    sha256_hex(seed) == DEMO_SEED_SHA256
}

/// None if `seed` (128 bytes) passes, else the same reason text Python gives.
pub fn weak_seed_reason(seed: &[u8]) -> Option<String> {
    if seed.len() != 128 {
        return Some("seed must be 128 bytes (1024 bits)".into());
    }
    let mut seen = [false; 256];
    for &b in seed {
        seen[b as usize] = true;
    }
    if seen[1..].iter().filter(|&&x| x).count() < SEED_MIN_DISTINCT_NONZERO {
        return Some("need at least 32 distinct nonzero bytes".into());
    }
    let mut counts = [0usize; 256];
    for &b in seed {
        counts[b as usize] += 1;
    }
    if *counts.iter().max().unwrap() > SEED_MAX_BYTE_COUNT {
        return Some("one byte value repeats too often (zero padding or low entropy)".into());
    }
    let weight: u32 = seed.iter().map(|b| b.count_ones()).sum();
    if !(SEED_WEIGHT_RANGE.0..=SEED_WEIGHT_RANGE.1).contains(&weight) {
        return Some(format!("Hamming weight {weight} of 1024 is far from 512"));
    }
    if seed.iter().all(|&b| (0x20..=0x7e).contains(&b)) {
        return Some("all printable ASCII (a password or hex text, not 1024 random bits)".into());
    }
    if *seed.iter().max().unwrap() < 0x80 {
        return Some("every byte is below 0x80".into());
    }
    for k in 1..=64 {
        let eq = seed.iter().zip(&seed[k..]).filter(|(a, b)| a == b).count();
        if eq > SEED_MAX_LAG_EQUAL {
            return Some(format!("repeated pattern (period {k})"));
        }
    }
    for k in SEED_DIFF_LAGS {
        for op in 0..2 {
            let mut c = [0usize; 256];
            for (a, b) in seed[k..].iter().zip(seed) {
                let d = if op == 0 { a.wrapping_sub(*b) } else { a ^ b };
                c[d as usize] += 1;
            }
            if *c.iter().max().unwrap() > SEED_MAX_LAG_DIFF {
                return Some(format!("counter or arithmetic sequence (stride {k})"));
            }
        }
    }
    let (mut up, mut down) = (1usize, 1usize);
    for w in seed.windows(2) {
        up = if w[1] > w[0] { up + 1 } else { 1 };
        down = if w[1] < w[0] { down + 1 } else { 1 };
        if up > SEED_MAX_MONOTONE_RUN || down > SEED_MAX_MONOTONE_RUN {
            return Some("long monotone run".into());
        }
    }
    let hh = sha256_hex(seed);
    if KNOWN_CONSTANT_SEEDS_SHA256.contains(&hh.as_str()) {
        return Some("a published constant".into());
    }
    None
}

pub const POLICY_TEXT: &str = "\
Octavo seed policy (n3file CLI, same rule as the N2 `octavo` CLI)

A key is a 1024-bit seed: 128 bytes, stored as 256 hex digits in a 0600 file
(the same file format as Python sneak_n2.save_seed / load_seed).

1. `n3file keygen` draws the seed once from the OS CSPRNG (getrandom). It never
   redraws: if the draw fails the weak-seed rule, keygen stops with an error
   (the RNG or the policy is broken). This is the real protection.
2. Every seed the CLI reads (keygen output or a user-supplied key file) must
   pass the weak-seed rule, a port of Python _weak_seed_reason. It refuses:
   fewer than 32 distinct nonzero bytes (all-same or few-valued seeds); any byte
   value more than 11 times (zero padding, text); Hamming weight outside
   384..640 of 1024; all printable ASCII (a password or hex text); all bytes
   below 0x80; more than 13 equal bytes at any distance 1..64 (repeats); more
   than 13 equal differences (mod 256 or XOR) at distance 1,2,3,4,8,16,32,64
   (counters, arithmetic sequences); a rising or falling run of 16; and 16
   listed public constants (pi, e, SHA/AES/SM4 tables ...).
3. No passphrases. There is no option to turn a password into a key: a
   passphrase-derived seed would need a slow, memory-hard KDF (e.g. Argon2id),
   which this tool does not have, and a passphrase typed as the seed itself is
   printable text, which rule 2 refuses.
4. Key files: at most 16384 bytes, UTF-8, only hex digits and whitespace,
   exactly 256 hex digits; a symlink or a non-regular file is refused; a file
   readable or writable by group/others gets a warning (chmod 600).
5. The PUBLIC demo seed (sneak1024-seed.txt) passes rule 2 but is public:
   `seal` refuses it unless --allow-demo-seed; `open` warns.

The rule is a sanity check against guessable STRUCTURE, not an entropy test.
Many guessable seeds still pass it (hashed passwords, seeded PRNG output, a
flipped byte of a public seed). Never derive a key from anything someone else
could guess. Octavo is still homemade; for real secrets use AES-GCM-SIV, age,
or libsodium.
";
