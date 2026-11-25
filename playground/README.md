# Local Octavo playground

A localhost-only web app for trying **Octavo N2** (the default live cipher), experimental **N3**, and a vetted AES-256-GCM-SIV path side by side: text, files (up to 8 MiB), and published test vectors. N2 Hear plays a short earworm from the key; N3 Hear plays a 3-voice earworm (melody, bass, and harmony) from a sealed 0x1C blob, with an optional original Ultima-style chiptune texture (display only; not a copy of any Ultima tune).

**Octavo is homemade and experimental — for real secrets use AES-GCM-SIV, age, or libsodium.**

The playground binds to `127.0.0.1` only. Keys are generated in memory and are not written to disk automatically (temporary 0600 files used to call the official CLIs are deleted before the request returns). N2 remains the default in this repository; N3 is experimental and not interchangeable with N2.

## Build the CLIs

From the repository root (Rust 1.89 or newer; N3's AVX-512 code needs rustup's cargo, typically `~/.cargo/bin/cargo`):

```bash
cargo build --release -p octavo-cli --manifest-path rust/Cargo.toml
cargo build --release --bin n3aead --manifest-path n3/rust/Cargo.toml
```

The playground looks for `rust/target/release/octavo` and `n3/rust/target/release/n3aead`, then for `octavo` / `n3aead` on `PATH`. You can override those with `OCTAVO_BIN` and `OCTAVO_N3AEAD_BIN`. The server still starts if a CLI is missing; `/api/info` and the endpoints that need it will say exactly which `cargo build --release` command to run.

## Run

From the repository root:

```bash
python3 playground/server.py          # http://127.0.0.1:8780/
python3 -B playground/test_app.py     # 28 automated checks
```

The Python cipher (`sneak_n2.py`, `octavo.py`) and the published vectors in `score/`, `independent_check/`, and `n3/vectors/` are used from this repository. The page also serves the existing `logo.png` and `sneak-staff-n2.png` (not redrawn).

Vetted mode uses the real Python `cryptography` AES-GCM-SIV library when it is installed. `age` is not faked if it is missing.

Octavo is homemade and experimental — for real secrets use AES-GCM-SIV, age, or libsodium.
