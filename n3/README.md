# N3 (experimental)

**This folder is experimental.** Live Octavo in this repository is still **N2**
(`sneak_n2.py`, `octavo.py`, and the [Rust port and CLI](../rust/)). N2 remains
the default until N3 has an outside review. Do not treat N3 as a replacement
for N2 in production, and do not use either for real secrets.

**Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.**

N3 is the frozen lab snapshot `octavo_n3_004` (23 November 2026). It is a
separate cipher and a separate blob format. N2 and N3 cannot open each
other's files.

## Formats

- Block cipher domain: `SN3C/` + format byte `0x1B` (128-byte block, 1024-bit
  seed, 16 rounds, 8-stroke bow, constant-time key setup).
- Authenticated mode: N3-PMAC-SIV, `SN3C/` + `0x1C`, 54 bytes of overhead
  (header 6 + nonce 16 + tag 32). Lab CLI: `n3aead`.
- N2 blobs start with a version byte and `SN2` (v6, v7, or v9). A `0x1C` blob
  starts with `SN3C/` then `0x1C`.

## Build and test

Needs [rustup](https://rustup.rs) **rustc 1.100** (the system 1.85 compiler
cannot build the AVX-512 path). From this folder:

```bash
cd rust
~/.cargo/bin/cargo test --release --lib
~/.cargo/bin/cargo build --release --bin n3aead
```

Override the backend with `OCTAVO_N3_BACKEND=avx512gfni|avx2gfni|avx2|portable`
(`table` is a non-constant-time test path and is never auto-selected).

```bash
# seal / open (seed is 256 hex digits, nonce 32 hex digits; empty AD is -)
./target/release/n3aead seal <seed_hex> <nonce_hex> - < message > message.n3
./target/release/n3aead open <seed_hex> - < message.n3 > message.out
```

`n3aead` takes the seed on the command line, which can show up in process
lists. That is a limitation of this lab tool.

## Migrating from N2

See [MIGRATION.md](MIGRATION.md). Short version: decrypt with N2, check the
plaintext, seal with `n3aead` under a **fresh** N3 seed and nonce, check the
round-trip, then delete intermediates carefully. `migrate.py` in this folder
does those steps for one v6, v7, or v9 file.

Do not reuse the public N2 demo seed or an N2 32/64-byte app key.

## What is here

| Path | What |
|---|---|
| `rust/` | N3 Rust crate, tests, and `n3aead` |
| `python/` | Slow independent Python block-function reference |
| `spec/N3_SPEC.md` | N3 specification |
| `vectors/` | Known-answer tests (including 0x1C AEAD) |
| `tools/` | Python AEAD reference and lab helpers |
| `SNAPSHOT.md` | Freeze record for `octavo_n3_004` |
| `SHA256SUMS`, `SHA256SUMS.NOTE` | Checksums of the full freeze; this copy omits some lab trees |
| `REPORT.md` | Working-copy notes for the 004 line (fix3 key setup) |
| `MIGRATION.md`, `migrate.py` | N2 → N3 migration |

N3 004 has no score, earworm, or MIDI tool.

## Status

In-house attacks on 004 found no full 16-round break. The best practical
distinguisher stopped after 5 of 9 layers in round 1. Proven trail bounds
are 18 S-boxes in one standalone round and 35 over two. There is **no
external review** of N3, and no related-key trail proof. Details:
`/workspace/attacks_octavo_n3_004` on the lab machine (not in this folder).

Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.
