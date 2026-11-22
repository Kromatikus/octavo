# Octavo Rust port

This `rust/` folder is a byte-compatible Rust implementation of the Python cipher in this repository (`../sneak_n2.py`), plus the `octavo` CLI with earworm MIDI and C64 SID output.

**Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.**

Octavo (working name N2) is a homemade, experimental, music-themed 1024-bit block cipher. This tree is a
byte-compatible Rust implementation of `../sneak_n2.py`
(SHA-256 `19181bc1623115c075dc5dee25edec388f5413466777d47b7f19fa66d1e71eee`), which it only reads. No cipher or
format change versus that file.

Toolchain: Rust >= 1.89 (`export PATH=$HOME/.cargo/bin:$PATH` on this box).

| Path | What |
|---|---|
| `crates/octavo-core` | Core cipher, formats (v6/v7/v9), hardware backends (gfni-simd, gfni-512/256/128, aes-ni, ct-soft), fast decrypt (straight-line triplets `src/trip_gen.rs` from `tools/gen_trip.py`, VPSLLVW bow rotation, 4/8-block packed batches, AVX-512 16-lane SHA-256 keystream `src/sha_mb.rs`, v9 tag chain overlapped with crypto), `zeroize` wipe-on-drop, `stream` constant-memory v9 seal/open |
| `crates/octavo-cli` | `octavo` binary: keygen, check-key, seal, open, hear, policy. See `CLI.md`, `SEED_POLICY.md` |
| `dudect/` | Dudect-style timing harness (own crate, uses core feature `dudect-hooks`), suite script, results, `REPORT.md` |
| `tools/` | `run_all.sh` (all vectors + Python cross-tests on all six backends + bench), `bench_cli.sh`, Python helpers (run with `python3 -B`) |
| `docs/` | Progress logs and READMEs of the two source folders (`octavo_decrypt_speed`, `octavo_cli`) |
| `PROGRESS.md` | What was done in this merge, with test counts |

Quick start:

```
cargo test --offline --release --workspace --all-features
tools/run_all.sh
cargo build --release -p octavo-cli && target/release/octavo --help
```

Feature notes (core): `formats`, `parallel` (threads), `zeroize`, `stream` (= std + formats + zeroize),
`dudect-hooks` (timing hooks only), `table-backend` (NOT constant time; reference only).
`no_std` builds with no features.

Limits: homemade design with in-house analysis only; key setup is not constant time (rejection sampling);
wiping is best effort; streaming open releases verified batches as it goes (the CLI writes to a temp file
and publishes only after the whole stream verified). Octavo is still homemade; for real secrets use
AES-GCM-SIV, age, or libsodium.
