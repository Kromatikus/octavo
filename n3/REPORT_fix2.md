# octavo_n3_fix2 — working copy

Working copy at `/workspace/octavo_n3_fix2`. This is `/workspace/octavo_n3_fix1` plus the parallel PMAC-style authenticated mode from `/workspace/octavo_n3_aead2`, now the default. The block cipher is unchanged. fix1, the aead2 lab, and the frozen snapshots were not modified. This is not a freeze and nothing was pushed.

The previous fix1 report is kept as `REPORT_fix1.md`.

## What changed

- The default (and only) authenticated mode is N3-PMAC-SIV, format byte `0x1C`. `n3aead` seals and opens these blobs. Overhead is still 54 bytes. The tag is a PMAC over a length-prefixed transcript (header, AD, nonce, message), middle blocks use the batch-64 path, the last block uses 10* padding and a 3L/5L mask, and counter-mode encryption — already on the batch path — is keyed by the 32-byte tag. Compare is constant-time.
- The block cipher is still fix1, format `0x1B` (8-stroke bow, corrected 18/35 bound). Encrypting a block has not changed.
- The old `0x1B` CMAC-S2V mode is **not** kept here. Carrying both MAC stacks is not cheap, and fix1 remains as a backup. A `0x1B` blob is rejected as `BadFormat`. Open those with the untouched fix1 tree.
- Spec: `spec/N3_SPEC.md` §5 and §5.3. Vectors: `vectors/aead_fix2_vectors.txt` (Python reference `tools/aead_ref.py`). CLI help states 0x1C only.

## Tests

`~/.cargo/bin/cargo test --offline --release --lib`: 38 passed in 1.68 s, including the block-cipher tests (format 0x1B) and the AEAD suite. All five backends (avx512gfni, avx2gfni, avx2, portable, table) agree bit-for-bit. Known-answer vectors match the independent Python reference. Bit flips, truncation, block reordering, and a `0x1B` header are rejected. The `n3aead` CLI round-trips a 0x1C blob and rejects a real fix1 0x1B blob (`unsupported format byte`).

## Timing and speed

Short dudect on `open` (15 s, 886,000 measurements, tag wrong in byte 0 vs byte 31): max |t| = 0.64, no evidence of a leak. Log: `results/fix2/dudect.txt` (America/New_York, 3:57–3:58 PM).

Quick same-session CLI throughput, `taskset` core 2, key setup included in every invocation (so short messages look slow on both sides):

```
tool   size     op      ms_min    MiB/s
fix2   1 KiB    seal      4.78    0.204
fix2   1 KiB    open      5.12    0.191
fix1   1 KiB    seal      4.69    0.208
fix1   1 KiB    open      4.74    0.206
fix2   64 KiB   seal      5.22   11.983
fix2   64 KiB   open      5.65   11.055
fix1   64 KiB   seal      6.68    9.363
fix1   64 KiB   open      6.60    9.463
fix2   1 MiB    seal     17.18   58.215
fix2   1 MiB    open     16.86   59.322
fix1   1 MiB    seal     33.09   30.217
fix1   1 MiB    open     32.87   30.422
```

On a 1 MiB message the CLI is about twice as fast as fix1 (58–59 MiB/s vs about 30). That is a bit below the in-process 75–77 vs 34–36 MiB/s from the aead2 lab, because each CLI run pays the ~3 ms key setup. At 1 KiB the setup dominates and the two tools are the same.

## Security

Same claim as the aead2 lab, not a stronger one. If the tag is a PRF and N3 is a strong PRP, nonce reuse still leaks only whether two (AD, nonce, message) triples were identical. That is not a proof for N3, the mode is not key-committing, and there has been no external review. 0x1C and 0x1B blobs are not interchangeable.

Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.
