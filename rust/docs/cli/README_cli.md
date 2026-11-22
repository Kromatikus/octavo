# octavo_rust_port: Octavo in Rust (phase 1 core cipher + phase 2 hardware S-boxes)

**Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.**

This is a byte-compatible Rust port of Octavo (working name N2), a homemade, experimental,
music-themed 1024-bit block cipher. The source of truth is this repository's `sneak_n2.py`
(SHA-256 `19181bc1623115c075dc5dee25edec388f5413466777d47b7f19fa66d1e71eee`). The port only reads
that file, as a reference. This tree now lives in `rust/` on GitHub.

Octavo has had in-house analysis (about 9–10 of its 16 rounds of margin at 2^-256) and one
non-expert outside review. That is not a security proof. Treat this crate as a playground and a
conformance target, not as protection.

## What is in phase 1

Toolchain: Rust 1.89 or newer, for the stable AVX-512/GFNI intrinsics. Install with
[rustup](https://rustup.rs) (`rustup default stable` is fine once it is 1.89+).

`crates/octavo-core` (library, `#![deny(unsafe_code)]` except the `hw` module, `no_std` + `alloc` capable):

| Module | Contents |
|---|---|
| `sponge` | StaffSponge `SHA-256("SN2/"‖domain‖ctr32‖seed‖nonce)`, rejection `below`, Fisher–Yates `perm` |
| `schedule` | Per-(seed, nonce) schedule in the exact Python squeeze order: round keys, invertible A1/A2 (and A3/A4), keyed S and S2 (S2 ≠ S rule), weave shifts, butterfly orders, bridge permutation, whitening |
| `sbox`, `affine`, `gf` | Keyed S-box `S(x) = A2·SM4[A1·x ⊕ b1] ⊕ b2`, collapsed to `Mout·inv(Min·x ⊕ cin) ⊕ cout` using SM4[x] = A·inv(A·x ⊕ 0xD3) ⊕ 0xD3 over GF(2^8)/0x1F5 |
| `bitslice` | Constant-time 64-lane bitsliced S-box: u64 bit-planes, affine maps and x^254 in AND/XOR |
| `round` | Every layer and its inverse: add key, S, weave, staff butterfly, shell bridges, bar mix (latin pair + 6 bars), triplets, bow pressure, odd restack, cross-staff mix, S2 encore. Also all 16 rounds, whitening, and reduced rounds for études |
| `backend` | `SboxBackend` trait. `Auto` is the default: it picks GFNI-512, then GFNI-256, GFNI-128, AES-NI, then `CtSoft` at runtime. You can force a backend with `force_backend(Some(BackendKind::…))` or env `OCTAVO_BACKEND=gfni-512\|gfni-256\|gfni-128\|aes-ni\|ct-soft`. The other backends are `CtSoft` (bitsliced), `CtScalar` (per byte), and `Table` (feature `table-backend`, **not** constant time) |
| `iso` | Field isomorphism φ: GF(2^8)/0x1F5 → GF(2^8)/0x11B (x^j ↦ 0x23^j), checked exhaustively. It folds each keyed S-box and its inverse into `Q·inv_AES(P·x ⊕ p) ⊕ q` |
| `hw` (x86-64) | GFNI: `GF2P8AFFINEQB` (P, then XOR p) followed by `GF2P8AFFINEINVQB` (Q, then XOR q), on zmm, ymm or xmm registers. AES-NI: PSHUFB nibble-table affine, then `AESENCLAST` with a zero key and a PSHUFB that undoes ShiftRows, then a PSHUFB affine that folds in A_AES⁻¹ and 0x63. Runtime feature checks guard every path |
| `formats` (feature) | v6 single-block AEAD, v7 movements, v9 rehearsal stream (whole buffer), étude block and movements (lab version bytes), app HKDF-SHA512 key expansion (`Octavo app key v1`) |

## Results

`cargo test --all-features` exercises the published vectors as exported by
`tools/export_vectors.py`. That script reads `score/vectors.json`, `score/app_vectors.json` and the
three sample files, and changes none of them.

| Category | Pass |
|---|---|
| block_cipher (raw permutation, 2/4/6/16 rounds) | 16/16 |
| aead (v6 + étude block) | 24/24 |
| movements (v7 + étude movements) | 24/24 |
| rehearsal (v9, including the 70,000-byte vector) | 8/8 |
| nondemo | 7/7 |
| **score v11 total** | **79/79** |
| app (3 HKDF keys + open 3 v6 blobs) | 6/6 |
| live samples (hello-world v6, movements-demo v7, rehearsal-demo v9, each with 6 single-bit tampers rejected) | 3/3 |

The tests also check `key_sig` and `rehearsal_sig` for both seeds, the four étude keys, and the
SHAKE-256 definition of the non-demo seed. Every format vector is round-tripped (opened again) and
must reject a single-bit tamper.

Differential tests run against the real `sneak_n2.py` with random inputs:
- `tools/diff_python.py` covers 40 random blocks (including reduced rounds), 20 v6, 8 v7 and 6 v9
  blobs. All 74 match in Rust, and Rust re-seals each blob byte for byte. The `CtSoft`, `CtScalar`
  and `Table` backends give identical results.
- `tools/check_rust_blobs.py` opens 19 Rust-sealed v6/v7/v9 blobs with `sneak_n2.py`: 19/19.

## Phase 2: hardware S-box backends (2026-11-21)

The box CPU is an Intel Xeon (Sapphire Rapids class) with GFNI, AES-NI, VAES, VPCLMULQDQ, AVX2 and
AVX-512 (F/BW/VL/DQ/VBMI/VBMI2…). Every backend ran natively, so Intel SDE wasn't needed.

| Backend | Exhaustive S-box test | Score v11 | App | Samples | Python cross-test | Random-block agreement |
|---|---|---|---|---|---|---|
| gfni-512 | 384 tables × 256 ✔ | 79/79 | 6/6 | 3/3 | 74/74, Rust→Py 19/19 | ✔ |
| gfni-256 | 384 × 256 ✔ | 79/79 | 6/6 | 3/3 | 74/74 | ✔ |
| gfni-128 | 384 × 256 ✔ | 79/79 | 6/6 | 3/3 | 74/74, Rust→Py 19/19 | ✔ |
| aes-ni | 384 × 256 ✔ | 79/79 | 6/6 | 3/3 | 74/74, Rust→Py 19/19 | ✔ |
| ct-soft | (reference) | 79/79 | 6/6 | 3/3 | 74/74 | ✔ |

The exhaustive test covers 6 random schedules × 16 rounds × (S, S2, S⁻¹, S2⁻¹), all 256 inputs plus
short tail batches. The agreement test runs 60 random (seed, nonce, block, rounds) cases; every
backend matches `CtSoft` exactly for encryption and round-trips on decryption.

## Constant-time status

- **S-boxes (default `CtSoft`): constant time and table-free.** They use bitsliced affine maps plus
  field inversion, with no data-dependent branches or memory addresses. `CtScalar` uses the same
  math one byte at a time.
- **Mixes:** field multiplies by public constants are masked linear maps, and the triplets are
  mod-256 integer multiplies. The bow uses data-dependent rotation amounts through `rotate_left`,
  which is a single constant-time rotate instruction on x86-64 and AArch64.
- **Not constant time with respect to the key:**
  - The schedule is built once per (seed, nonce). Its rejection sampling and its matrix and `S2 ≠ S`
    checks loop a key-dependent number of times, exactly as in Python.
  - The weave, butterfly and bridge index patterns are key-dependent (but data-independent) shuffles
    of a 128-byte state.
- **Hardware backends:** `GF2P8AFFINEQB`, `GF2P8AFFINEINVQB`, `AESENCLAST` and `PSHUFB` have
  data-independent timing and make no memory lookups. Their per-round matrices and nibble tables
  are key-derived constants held in registers.
- `Table` is opt-in and **not** constant time. It exists for speed comparisons only.
- Constant-time behaviour has not been checked with a tool such as dudect or ctgrind yet (phase 2).

## Speed

Measured on the box (Xeon, release + LTO, one thread, portable build; `cargo run --release
--all-features --example bench`, `python3 tools/bench_python.py`). Key setup is the schedule plus
the backend's precompute.

| Backend | Encrypt / block | Decrypt / block | Key setup | Encrypt vs Python |
|---|---|---|---|---|
| Python `sneak_n2.py` | 6,769 µs (0.019 MB/s) | 8,654 µs | 17.8 ms | 1× |
| gfni-512 (**auto default**) | 46.9 µs (2.73 MB/s) | 67.2 µs | 193 µs | ~144× |
| gfni-256 | 45.8 µs | 65.9 µs | 194 µs | ~148× |
| gfni-128 | 42.8 µs (2.99 MB/s) | 66.9 µs | 181 µs | ~158× |
| aes-ni | 44.7 µs | 65.6 µs | 189 µs | ~151× |
| ct-soft (bitsliced) | 85.5 µs (1.50 MB/s) | 104.9 µs | 172 µs | ~79× |
| ct-scalar | 86.3 µs | 109.8 µs | 183 µs | ~78× |
| table (**not CT**) | 45.8 µs | 65.6 µs | 224 µs | — |

v9 sealing (8 MiB, one thread) runs at 2.80 MB/s on gfni-512 and 1.54 MB/s on ct-soft.

**Why it's only ~1.9× over ct-soft:** with GFNI or AES-NI the S-boxes are close to free, so the
time now goes to the byte-at-a-time linear layers (bar mixes, butterfly, bow, triplets, weave).
All hardware backends and even the non-CT table land on the same ~45 µs. The next speedup has to
come from vectorising those layers. One example: multiplying by a constant in 0x1F5 is a linear
map, so `GF2P8AFFINEQB` can do the bar and mix multiplies for 64 cells at once with no field
switch. Multi-block parallelism in v9 is another option. Neither is done yet (out of this phase's
scope).

## Layout and how to re-run

```
Cargo.toml                    workspace
crates/octavo-core/src/       library
crates/octavo-core/tests/     vectors.rs (published vectors, every backend), diff_python.rs (random vs sneak_n2.py, every backend), backends.rs (exhaustive HW S-box + agreement)
crates/octavo-core/examples/  bench.rs, emit_blobs.rs
tools/export_vectors.py       score/app/sample files -> vectors/octavo_vectors.json
tools/diff_python.py          random cases from sneak_n2.py -> vectors/diff_random.json
tools/check_rust_blobs.py     Rust -> Python direction
tools/bench_python.py         Python side of the benchmark
tools/run_all.sh              everything above
```

## Phase 2 (not done yet)

- ~~GFNI and AES-NI S-box backends~~ (done, phase 2).
- Vectorised linear layers (GFNI affine for constant field multiplies, SIMD across faces) and
  multi-block/multithreaded v9. This is where the remaining speed is.
- AArch64 hardware path (NEON/PMULL or the ARMv8 AES instructions). Non-x86 targets use ct-soft today.
- CLI: keygen, v6 seal/open with fresh OS-random pickups, v9 file encrypt/decrypt, vector check, the
  honest banner, vetted mode as the default for real secrets, and an optional "hear this".
- The Python seed policy (`_weak_seed_reason`, known-constant list), `load_seed`/`save_seed` (0600
  files) and keygen. The Rust core currently accepts any 128-byte seed. `app_seed` rejects an empty
  or all-zero key.
- A streaming, constant-memory v9 file API and parallel workers. The current API works on whole
  buffers.
- Finer error kinds (Python's `UnsupportedVersion`, `AuthError`, `DecodeError`), zeroizing secrets,
  fuzzing, and constant-time verification (dudect).
- Legacy readers (v2, v3, v8, non-committing études) are deliberately not ported, per the sketch.
- The key-signature nonces are pinned constants (`KEY_SIG_PIN`/`REHEARSAL_SIG_PIN` from
  `sneak_n2.py`). Python's import-time source attestation has no Rust equivalent.
- Tauri desktop app, music, and the game (sketched during the original lab work; not in this tree).

**Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.**

## Phase 3: performance (2026-11-21, no cipher or format change)

**Profile (before, gfni-512 path, ns per round):** encrypt 3172 (bar_mix 2×955 ≈ 60%, butterfly 197, bow 2×133,
triplets 2×77, odd 2×72, weave 73, bridges 49, cross 2×28, S-boxes ~15 each). Decrypt 4729 (bar_unmix 2×907,
uncross 2×515, unbutterfly 487, unbow 2×138). The S-box was never the bottleneck; scalar byte-wise mixes were.

**What changed**
- `src/simd.rs`: full-round GFNI + AVX-512 (VBMI) engine, backend `gfni-simd` (auto default when the CPU has it).
  Constant multiplies in latin/bars/cross are GF2P8AFFINEQB matrices; weave/butterfly/bridges are fused into
  key-setup-precomputed `vpermt2b` gathers; bow uses GFNI rotation matrices and mask blends (no data-dependent
  branches or indices). 4 blocks are interleaved per call.
- `encrypt_blocks`/`decrypt_blocks` multi-block API; v6 uses it; v7 decrypt batched (encrypt is inherently sequential).
- v9 rewritten around per-chunk batching; `seal_rehearsal_threads`/`open_rehearsal_threads` behind feature
  `parallel` (std::thread::scope); open verifies the whole tag chain before decrypting. Bytes identical for any thread count.
- `force_backend` is thread-local under std.

**Results:** every backend (gfni-simd, gfni-512, gfni-256, gfni-128, aes-ni, ct-soft) passes 79/79 score vectors,
6/6 app vectors, 3/3 samples, Python→Rust 74/74, Rust→Python 19/19; backends agree on random inputs; multi-block
== single-block; threaded v9 byte-identical; no_std builds.

**Speed (lab machine, 8 vCPU Sapphire Rapids class; v9 = 4 MiB, 64 KiB chunks)**

| backend | enc 1 blk | dec 1 blk | enc batched | dec batched | key setup | v9 seal 1T | v9 seal 8T | v9 open 8T |
|---|---|---|---|---|---|---|---|---|
| Python (sneak_n2) | 6769 µs | 8654 µs | – | – | 17.8 ms | – | – | – |
| phase 2 gfni-512 (before) | 46.9 µs | 67.2 µs | – | – | 193 µs | 2.8 MB/s | – | – |
| **gfni-simd** | **3.2 µs** | **6.4 µs** | **2.5 µs** | **5.3 µs** | 208 µs | **37 MB/s** | **188 MB/s** | **116 MB/s** |
| gfni-512 | 43.7 µs | 64.1 µs | 43.2 µs | 68.6 µs | 178 µs | 2.9 MB/s | 14.6 MB/s | 12.9 MB/s |
| gfni-256 | 45.4 µs | 66.3 µs | 43.5 µs | 65.9 µs | 179 µs | 2.9 MB/s | 16.5 MB/s | 13.5 MB/s |
| gfni-128 | 41.5 µs | 63.1 µs | 41.8 µs | 64.9 µs | 180 µs | 3.0 MB/s | 16.1 MB/s | 11.0 MB/s |
| aes-ni | 43.7 µs | 67.1 µs | 44.8 µs | 63.5 µs | 218 µs | 2.9 MB/s | 16.8 MB/s | 10.4 MB/s |
| ct-soft | 80.8 µs | 104.1 µs | 80.1 µs | 102.0 µs | 179 µs | 1.6 MB/s | 8.7 MB/s | 8.7 MB/s |
| AES-256-GCM (aes-gcm 0.10, 1T) | – | – | – | – | – | 1613 MB/s | – | – |

Re-run: `cargo run --release --all-features --example bench`.

**Remaining bottlenecks:** decrypt ≈2× encrypt (inverse triplet constants need many adds; uncross/unbow);
v9 1T at 37 MB/s vs ~50 MB/s raw block rate (SHA-256 sponge tweaks + HMAC per chunk); v9 open/seal tag chain and
HMAC are sequential, capping threads; key setup ~0.2 ms (SHA-256 sponge + S2 resampling; not constant time,
same as Python); v7 encrypt sequential; no ARM/NEON path; no dudect timing test yet. AES-256-GCM is still ~43×
faster single-threaded.

Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.
