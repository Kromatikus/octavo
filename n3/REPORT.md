# fix3: faster constant-time key setup (working copy)

Working copy at `/workspace/octavo_n3_fix3`. This is `/workspace/octavo_n3_fix2` plus the faster key setup from `/workspace/octavo_n3_keysetup1`. The block cipher (format 0x1B) and the authenticated mode (N3-PMAC-SIV, format 0x1C) are unchanged. Ciphertexts are bit-identical to fix2. fix2, the keysetup1 lab, and the frozen snapshots were not modified. This is not a freeze and nothing was pushed.

The old fix2 report is kept as `REPORT_fix2.md`.

## What changed

Setup still builds the same keyed SM4-affine S-boxes, but it fills the 256-byte tables from the closed form `S(x) = Mout·inv(Min·x ⊕ cin) ⊕ cout` with a table-free Fermat inverse, instead of a 256×256 constant-time scan of SM4. A process-lifetime cache holds `PHI^{-1}` and the key-independent fallback tables. A HashSet bijectivity check that was not constant-time is gone. See `spec/N3_SPEC.md` §5.4.

Lab-only profiling code (`setup_prof.rs` and the widened `pub(crate)` visibility it needed) was not brought over. `n3setupprof` is a simple all-backend timer, and `n3dudect_setup` is kept as a check, like `n3dudect_tag`.

## Speed (America/New_York, 4:44 PM, `taskset` core 2)

`Cipher::with_backend`, µs, min of 3×80:

```
backend      fix2 (keysetup1 baseline)    fix3
avx512gfni                 1437.4   585.1
avx2gfni                   1883.8   902.9
avx2                       1800.0   903.8
portable                   1782.1   893.2
table                      1348.5   529.7
```

About 2.5× faster on AVX-512, about 2× on AVX2 and portable. The leftover on those slower backends is still the per-round Beneš masks and backend S-box forms.

`n3aead` CLI, key setup included in every run:

```
size    op      ms     MiB/s
1 KiB   seal    2.61    0.374
1 KiB   open    2.73    0.358
1 MiB   seal   15.87   63.007
1 MiB   open   15.28   65.432
```

A 1 KiB seal was about 4.7 ms on fix2 in the same-day keysetup1 baseline; a 1 MiB seal was about 16.7 ms / 60 MiB/s.

## Tests and timing checks

`cargo test --offline --release --lib`: 39 passed, including the original 38 (known-answer vectors and all five backends) plus a check that the new tables match the old scan and the public SM4 table. A live 4 KiB `n3aead` seal matched the untouched fix2 binary byte-for-byte.

Short dudect on key setup (10 s each, 17,200 measurements, 4:44–4:45 PM ET): two fixed seeds, max |t| = 2.13; a fixed seed versus a random seed, max |t| = 2.55. No evidence of a leak. This is not a proof. Logs: `results/fix3/`.

Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.
