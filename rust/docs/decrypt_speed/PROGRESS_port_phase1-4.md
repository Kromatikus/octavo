# Octavo Rust port — PROGRESS

Phase 1: core cipher, byte-compatible with `/workspace/sneak_n2/sneak_n2.py`
(SHA-256 19181bc1623115c075dc5dee25edec388f5413466777d47b7f19fa66d1e71eee, READ-ONLY).
Local only: no git push, no GitHub, no CloudAgent.

## Milestones
- [x] M0 toolchain: system rustc/cargo 1.85.1 already present (no rustup needed); crates.io reachable.
- [x] M0 baseline: independent checker `--quick` passes 78/78 (+6/6 app).
- [x] M0 SM4 S-box decomposition found: SM4[x] = A·inv(A·x ⊕ 0xD3) ⊕ 0xD3, A rows a7 4f 9e 3d 7a f4 e9 d3, field 0x1F5.
- [x] M1 cargo workspace + octavo-core skeleton
- [x] M2 GF / affine / CT keyed S-box (+ test vs SM4 table)
- [x] M3 sponge + schedule
- [x] M4 round layers + block encrypt/decrypt
- [x] M5 vector export script + block_cipher tests
- [x] M6 v6 / étude block AEAD, app HKDF
- [x] M7 v7 / étude movements, v9 rehearsal
- [x] M8 differential test vs sneak_n2.py (random inputs)
- [x] M9 benchmark Rust vs Python
- [x] M10 README

## Status log
- 2026-11-21 ~11:00 PM ET: M1–M7 done. `cargo test --all-features` -> unit 5/5; vectors: block_cipher 16/16,
  aead 24/24, movements 24/24, rehearsal 8/8 (incl. 70,000-byte), nondemo 7/7, app 6/6, samples 3/3.
  Vectors exported by `tools/export_vectors.py` -> `vectors/octavo_vectors.json` (sources untouched).
- M8: `tools/diff_python.py` (40 random blocks incl. reduced rounds, 20 v6, 8 v7, 6 v9 from real sneak_n2.py)
  -> `tests/diff_python.rs` 74/74 OK (also re-seals byte-identically); `tools/check_rust_blobs.py`
  (Rust-sealed v6/v7/v9 opened by sneak_n2.py) 19/19 OK. no_std builds (core, core+formats) compile.
- M9 first numbers (Xeon w/ GFNI, release, LTO): ct-soft per-byte 371 us/block (0.34 MB/s), table
  59 us/block (2.17 MB/s, NOT CT), schedule 178 us; Python 6713 us/block (0.019 MB/s), schedule 17 ms.
- Bitsliced 64-lane CT S-box + batch hook in SboxBackend; constant multiplies as masked linear maps.
  Final bench: CtSoft 73 us/block enc (1.76 MB/s), 96 us dec; CtScalar 80; Table 36 (not CT);
  Python 6713 us enc / 8710 dec, schedule 17.1 ms vs 0.17 ms. => ~92x.
- Added MAX_REHEARSAL_CHUNKS cap. README.md written. tools/run_all.sh re-runs everything.
- Housekeeping: my baseline checker run at 10:53 PM ET had created
  /workspace/sneak_n2/independent_check/__pycache__ (bytecode only). Removed it; sneak_n2.py SHA unchanged.
  All later Python runs use sys.dont_write_bytecode.

## PHASE 1 DONE (2026-11-21 ~11:08 PM ET). Phase 2 list: see README.md.

# Phase 2 — hardware S-box backends only (approved 11:10 PM ET; no CLI)
- [x] P2-M0 CPU: Intel Xeon (Sapphire-Rapids-class), 8 vCPU. Has GFNI, AES-NI, VAES, VPCLMULQDQ, AVX2,
  AVX-512 F/BW/VL/DQ/VBMI/VBMI2/BITALG/VPOPCNTDQ/FP16. Every backend runs natively, so no Intel SDE needed.
- [x] P2-M0 toolchain: system rustc 1.85 lacks stable AVX-512/GFNI intrinsics -> installed user-local
  rustup stable (rustc 1.100.0) in ~/.cargo. Use `export PATH=$HOME/.cargo/bin:$PATH`.
- [x] P2-M1 field isomorphism 0x1F5 -> 0x11B + GFNI matrix folding (exhaustive tests)
- [x] P2-M2 GFNI backends (512 / 256 / 128-bit)
- [x] P2-M3 AES-NI backend (AESENCLAST + PSHUFB nibble affines)
- [x] P2-M4 runtime detection + forcing (Auto backend, OCTAVO_BACKEND env)
- [x] P2-M5 all vectors + Python cross-tests on every backend; backends agree on random inputs
- [x] P2-M6 benchmarks
- P2 status (~11:12 PM ET): iso.rs (phi: x^j -> 0x23^j, exhaustively a field isomorphism), hw.rs (GFNI 512/256/128,
  AES-NI), Auto backend + force_backend()/OCTAVO_BACKEND. All 5 backends: 79/79 + 6/6 + 3 samples, 74/74 Python
  cross-tests; 384 keyed S-box tables x 256 inputs exhaustive per HW backend; 60 random blocks agree across backends.
- P2-M6 bench: gfni-512 46.9/67.2 us enc/dec, gfni-128 42.8, aes-ni 44.7, ct-soft 85.5/104.9, table 45.8;
  key setup ~170-225 us; Python 6769/8654 us, 17.8 ms. Bottleneck is now the linear layers, not the S-boxes.
- hmac/subtle are now optional (formats feature). no_std builds still compile. README updated.

## PHASE 2 (hardware S-boxes) DONE (2026-11-21 ~11:16 PM ET). CLI not started (as instructed).

# Phase 3: performance only (approved 11:21 PM ET; no cipher/format change, no CLI)
- [x] P3-M1 profile per layer (current GFNI path, one round, ns): enc round 3172 = weave 73, butterfly 197,
  bridges 49, 2x[bar_mix 955, trip 77, bow 133, odd 72, cross 28], S/S2 ~15 each. Bars (scalar masked
  constant-multiplies) ~60% of encrypt. Decrypt round 4729: bar_unmix 907 x2, uncross 515 x2,
  unbutterfly 487 (scalar INV3 multiplies), unbow 138 x2.
- [x] P3-M2 full-SIMD engine (GFNI + AVX-512 VBMI): column-major per-row layers, vpermi2b gathers for weave/butterfly/bridges
- [x] P3-M3 multi-block interleave + threaded v9 (flag)
- [x] P3-M4 all vectors / cross-tests / agreement on every backend
- [x] P3-M5 benchmarks before/after + aes-gcm reference (11:46 PM ET; table in README "Phase 3")
- P3 status (~11:40 PM ET): simd.rs full-round engine (backend "gfni-simd", auto default on this box),
  4-block interleave via encrypt_blocks/decrypt_blocks, batched v7 decrypt, v9 per-chunk batching +
  seal/open_rehearsal_threads (feature `parallel`, verify whole tag chain before decrypt). force_backend is
  now thread-local (std). All 6 backends: 79/79 + 6/6 + 3 samples, 74/74 Py cross, Rust->Py 19/19,
  multi-block (1..33 blocks) == single-block soft, threaded v9 byte-identical for 1/2/3/8 threads.

# Phase 4: decrypt speed (folder /workspace/octavo_decrypt_speed, cp -a of octavo_rust_port, 2026-11-22)
No cipher or format change. Port folder, older folders and frozen snapshots untouched.
- 08:44 AM ET baseline (this folder, unchanged code): gfni-simd enc 3.40 / dec 6.71 µs per block,
  batched 2.43 / 5.57, v9 seal 1T 27.7 MB/s, seal 8T 172 MB/s, open 8T 98 MB/s (box shared with other workers,
  so numbers wobble ±10-20%). bench_before.txt.
- Layer profile (new examples/profile.rs + simd::profile_layers): the compiler had turned the triplet add-chains
  and the 7 bow strokes into loops with branches on the (public) constant tables, and the inverse triplet
  constants (254, 253, 251, 236, ...) cost up to 7 adds each. unbow was 108 ns vs bow 66 ns.
- [x] D1 triplets: tools/gen_trip.py emits straight-line code (src/trip_gen.rs) with minimal signed-digit
  forms (254 = -2 -> 1 sub; inverse total 212 adds -> about 100 add/sub), balanced add trees. Test
  generated_triplets_match_tables checks against the tables + inverse round trip.
- [x] D2 bow: strokes unrolled with macros (test bow_tables_match keeps them in sync with BOW_STROKES/BOW_ROT);
  per-byte rotate is now PSHUFB byte-dup + VPSLLVW + blend (depth ~4) instead of a 3-stage GFNI barrel;
  mod 7 via min_u8(x, x-7) (no compares). bow 66 -> 25 ns, unbow 108 -> 35 ns.
- After D1+D2: gfni-simd enc 2.68 / dec 2.88 µs, batched 1.95 / 2.18 µs.
- [x] D3 4/8-block batches: the per-row layers are written once (src/simd_layers.rs) over small op shims
  (src/ops128.rs, src/ops512.rs). Batches of 4 blocks are packed one block per 128-bit lane of a zmm
  (4x4 lane transpose, _mm512_shuffle_i64x2), so every per-row instruction covers 4 blocks; batches of 8
  run two such chains side by side. Batched enc 2.43 -> ~0.8 µs, dec 5.57 -> ~0.85-0.9 µs per block.
- [x] D4 cross-staff layers fused: PSHUFB with zeroing index + masked GF2P8AFFINEQB (+ AND with an a-lane
  mask for the inverse) instead of shuffle/affine/2 blends. Small gain (cross 16 -> 12.5 ns, uncross 17 -> 15).
- [x] D5 v9 keystream sponge (the real v9 bottleneck after D3: 153 MB/s, 4 SHA-256 compressions per 32 bytes):
  src/sha_mb.rs pads the sponge message once and hashes 16 counters at a time with a 16-lane AVX-512
  SHA-256 (blocks after the counter block are lane-invariant, so their schedule+K is computed once).
  Fallback: template + sha2::compress256 (feature "compress" of the existing sha2 dep, no new crate).
  530 MB/s. Test squeeze_matches_staff_sponge: both paths == StaffSponge for many domains/nonces/lengths.
- [x] D6 v9 tag chain: still sequential (it must be: each HMAC input has the previous tag BEFORE the
  ciphertext, so no SHA-256 midstate can be shared or computed early). What changed: seal now hands each
  finished chunk to the chain in order while later chunks are still encrypting (round-robin chunk
  assignment, mpsc channel); open with threads > 1 walks the chain on the calling thread while
  threads-1 workers decrypt into a private buffer, which is wiped and Err(Auth) returned on any mismatch.
  1-thread open is unchanged (verify all, then decrypt). Bytes identical for every thread count.
- [x] D7 portable path (round.rs, used by gfni-512/256/128, aes-ni, ct-soft): inverse field mixes
  (INV3 multiplies in unbutterfly, inverse bridges, uncross, bar_unmix/unodd) now run 8 cells per u64
  (masked SWAR, no lookups); cross layers too. Test swar_mixes_match_scalar. Decrypt ~65 -> ~52 µs.
- emit_blobs now also seals two multi-threaded v9 streams (8 and 3 threads, multi-chunk), so
  check_rust_blobs.py opens 21 blobs (was 19); it builds emit_blobs with --features parallel.
  run_all.sh in this folder uses python3 -B and cargo --offline.
- Note: /workspace/sneak_n2/__pycache__ and score/__pycache__ already existed (files dated Nov 15-18),
  not created by this job; left alone.
- 09:08 AM ET full suite (tools/run_all.sh, run_all.log): all six backends 79/79 (block 16 + formats 63) + app 6/6
  + samples 3/3; Python->Rust 74/74 each; Rust->Python 21/21 each (+ default run 21/21); lib unit 15 passed
  (1 ignored = old round::layer_timings), backends 4/4, all tests ok. Builds: no_std (no features), alloc,
  formats, default, parallel - all clean. sneak_n2.py SHA unchanged; no new __pycache__ anywhere in /workspace.
- 09:11 AM ET A/B (baseline/ = copy of the untouched port + the new bench.rs; ab_gfni_simd.txt):
  before enc 3.24 / dec 6.66 µs, batched 2.40 / 5.34; v9 seal 1T 37.9, open 1T 20.4, seal 8T 208, open 8T 122 MB/s.
  after  enc 2.52 / dec 2.91 µs, batched 0.75 / 0.80; v9 seal 1T 121, open 1T 116, seal 8T 599, open 8T 555 MB/s.
## PHASE 4 DONE (2026-11-22 ~09:13 AM ET). Nothing committed or pushed.
