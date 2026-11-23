# octavo_n3_004 — frozen N3 lab snapshot

Frozen 2026-11-23, 4:47 PM ET, from /workspace/octavo_n3_fix3. Rust and lab build output (`target/`) excluded (rebuildable). Do not modify. New work goes in a new folder.

Lineage: octavo_n3_003 (format 0x1A, block function only) → fix1 (8-stroke bow, corrected trail bound, no 1-round impossible differential) → fix2 (N3-PMAC-SIV authenticated mode) → fix3 (faster constant-time key setup) → this freeze.

Round: `rk ; S ; chord ; bridges ; triplets ; bow ; S_mid ; cross ; S2`, then a final whitening XOR. 16 rounds, 128-byte block, field GF(2^8)/0x1F5. Prefix SN3C/.

Formats: block cipher SN3C/ **0x1B**; authenticated blobs SN3C/ **0x1C** (N3-PMAC-SIV, 54-byte overhead). The old fix1 0x1B CMAC-S2V mode is not in this tree; open those with /workspace/octavo_n3_fix1.

What changed since octavo_n3_003:
- **fix1:** 8-stroke bow with full two-way diffusion; the 1-round impossible differential is gone. Trail bound corrected to 18 S-boxes in one standalone round, 35 over two rounds, 17 per round in a long chain (~2^-100 per round in that model).
- **fix2:** parallel PMAC-style tag (N3-PMAC-SIV) is the only authenticated mode here.
- **fix3:** key setup fills the same keyed SM4-affine S-box tables from the closed form instead of a 256×256 constant-time scan, and caches a few key-independent tables. Setup is still constant-time. Ciphertexts are bit-identical to fix2.

Not interchangeable with octavo_n3_003: 003 used block format 0x1A and had no 0x1C AEAD. A 004 block ciphertext or 0x1C blob will not open as 003, and a 003 blob will not open here. Also not interchangeable with octavo_n3_001 (SN3/, 0x16/0x17/0x19) or with fix1's 0x1B authenticated blobs.

Backends: auto-selects the fastest supported path — avx512gfni, then avx2gfni, then avx2, then portable. Override with OCTAVO_N3_BACKEND=avx512gfni|avx2gfni|avx2|portable|table (`table` is a non-constant-time reference and is never auto-selected). `Cipher::with_backend` / `Cipher::backend` also available.

Evidence: a clean `~/.cargo/bin/cargo test --offline --release --lib` (rustc 1.100; system cargo 1.85 cannot build AVX-512) from a scratch copy at /workspace/octavo_n3_004_verify: **39 passed**. Includes known-answer vectors, all five backends, the AEAD suite, and a check that the fix3 S-box tables match the old scan. Log: `results/freeze004/cargo_test.txt`.

Speeds from fix3 on this box (America/New_York, 4:44 PM ET, taskset core 2): key setup about 0.59 ms on AVX-512 (about 0.90 ms on AVX2 and portable). `n3aead` 1 KiB seal about 2.6 ms; 1 MiB seal about 63 MiB/s (key setup included in each CLI run). Earlier in-process AVX-512 figures for this design were about 0.60 µs/block in a batch of 64.

Caveats: AVX2 paths were only forced on this AVX-512 box, not run on real AVX2-only chips. ARM portable build compiled, not run. No SSSE3 / pre-AVX2 path (those CPUs get portable). The trail bound is a simplified model; there is no proof against related-key attacks, and nobody outside has reviewed this. Not in the repo.

File hashes: SHA256SUMS.

Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.
