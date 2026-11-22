# Dudect timing tests: merged Octavo tree (`rust/` on GitHub)

Absolute paths such as `/workspace/octavo_merged` in this report and in `results/` are from the lab machine; the result files were not rewritten.

**Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.**

Date: Sunday 22 Nov 2026, 10:04-10:34 AM ET. Machine: Intel Xeon (Sapphire-Rapids class), 8 vCPU, constant TSC
2.400 GHz, hypervisor guest. Harness ported from `/workspace/octavo_dudect` (left untouched) to
`dudect/harness`, linked against this tree's core with feature `dudect-hooks`.

Method (dudect, Reparaz-Balasch-Verbauwhede): two input classes randomly interleaved, lfence+rdtsc cycle counts,
Welch t on raw times and on times cropped at the pooled 99th percentile; |t| > 4.5 "likely", > 10 "definite".
Each case: 35 s budget (at least 20,000 samples, at most 20 M), `taskset` pinned (lane A CPU 2, lane B CPU 6, the
two `-mt` cases on 2 CPUs), GNU `timeout` hard limit 80 s. No case hit the timeout. Flagged cases were rerun,
plus A/A controls (`OCTAVO_DUDECT_AA=1`) and 4x-work scaling (`OCTAVO_DUDECT_ITERS`/`OCTAVO_DUDECT_REPS`).
Dudect can find a leak; it can never prove there is none. Full table: `results/summary.txt`; raw JSON/logs in `results/`.
Scripts: `run_suite.sh` (main), `followup.sh` (reruns), `micro_v2.sh` (VPSLLVW/bow micro tests, final design).

## Summary

| Area | Backends | Cases | Verdict |
|---|---|---|---|
| Block encrypt/decrypt, fixed vs random plaintext (`enc-pt`, `dec-pt`) | all 6 | 12 | no evidence (max abs t_crop 2.5) |
| Block encrypt/decrypt, fixed vs 16 random keys (`enc-key`, `dec-key`) | all 6 | 12 | no evidence, except `enc-key` gfni-simd (see below) |
| 8-block batches, fixed vs random (`enc-batch-pt`, `dec-batch-pt`; gfni-simd = packed 4-block zmm path used by v9) | all 6 | 12 | no evidence (max 1.95) |
| v9 tag compare, first vs last tag byte wrong (`v9-tag-pos`) | all 6 | 6 | no evidence (max 4.42, below 4.5) |
| Streaming open, valid stream, fixed vs random message (`stream-open-pt`), 1 thread | all 6 | 6 | no evidence |
| Streaming open, 2 threads (decrypt overlapped with tag chain) | gfni-simd | 1 | no evidence (-3.43) |
| Streaming tag compare, chunk-0 tag wrong first vs last byte (`stream-tag-pos`) | all 6 (+ 2-thread on gfni-simd) | 7 | no evidence |
| **VPSLLVW rotation directly** (`vrot128/512`: amounts all-1 vs random 1..7, all-1 vs all-7; plus A/A and 4x) | gfni-simd | 7 | **no evidence** (max 1.57) |
| **Bow / unbow layers on chosen state** (zero state = all amounts 1 vs random state; xmm and zmm; plus A/A and 4x) | gfni-simd | 7 | **no evidence** (max 1.24) |
| Expected, documented: key schedule (`schedule-key`) | gfni-simd | 1 | definite (-276): rejection sampling, as before |
| Expected, documented: valid vs tampered v9 open (`v9-valid-tamper`) | gfni-simd | 1 | definite: fail-closed early exit, as before |

## The VPSLLVW rotation (the new code)

The bow rotation is now PSHUFB byte-dup + VPSLLVW (per-word variable shift) + blend, with amounts computed
branch-free from the state. Final results (both classes read their inputs from equal-size rings at the same index):

| Case | samples | median cycles 0 / 1 | t_raw | t_crop | Verdict |
|---|---:|---|---:|---:|---|
| vrot128-amt (xmm, 512 rotations, amounts 1 vs random) | 20 M | 1560 / 1560 | 0.24 | -0.10 | no evidence |
| vrot128-1v7 (xmm, amounts 1 vs 7) | 20 M | 1602 / 1602 | 0.02 | 0.33 | no evidence |
| vrot512-amt (zmm, as in 4/8-block batches) | 20 M | 1628 / 1628 | -0.53 | -0.45 | no evidence |
| vrot512-1v7 | 20 M | 1650 / 1650 | 0.19 | 0.48 | no evidence |
| vrot128-amt A/A control | 20 M | 1646 / 1646 | -1.77 | -1.57 | no evidence |
| vrot128-amt 4x (2048 rotations) | 13.5 M | 5984 / 5984 | 0.31 | -1.17 | no evidence |
| vrot512-amt 4x | 12.8 M | 6236 / 6236 | 0.41 | 1.40 | no evidence |
| bow128-state (32 layers, zero vs random state) | 20 M | 2036 / 2036 | 1.35 | 0.71 | no evidence |
| unbow128-state | 20 M | 2748 / 2748 | -0.94 | 1.24 | no evidence |
| bow512-state | 20 M | 2818 / 2818 | -1.07 | -0.77 | no evidence |
| unbow512-state | 20 M | 3454 / 3454 | 0.04 | -0.60 | no evidence |
| unbow128 A/A / 4x (128 layers) | 20 M / 7.9 M | 2742 / 2742, 10414 / 10414 | 1.35 / 1.05 | -0.16 / 0.44 | no evidence |
| bow128 4x | 10.7 M | 7578 / 7578 | 0.98 | 0.15 | no evidence |

The full-round tests that go through the same code (enc/dec-pt and the batch tests on gfni-simd, 5-12 M samples
each) were also clean.

**First-design flags (kept as `results/v1design_*`, not used for the verdict).** In the first version of the
micro tests class 0 read its input from one fixed buffer and class 1 from a 4096-entry ring. Those runs flagged
vrot128 (|t| 17-32), vrot512-amt (7.6, 9.1) and unbow128 (16-66) with mean gaps of 0.3-6 cycles out of
1,600-3,000. They are not a VPSLLVW leak: the vrot128 sign flipped between two runs with identical seeds, none of
them grew with 4x the rotations (a count-dependent latency would scale with the number of shifts), the unbow128
A/A control (identical data in both classes) flagged too, and every flag disappeared once both classes used
the same memory path. The harness was fixed (matched rings) and all micro tests were rerun.

## Key-dependent cache effect on gfni-simd (known)

`enc-key` gfni-simd flagged again (t_crop 45.6, rerun 35.5; medians 6344 vs 6332 cycles). The follow-ups match the
earlier report: `enc-key-twokey` (one fixed vs one random key, both hot) shows nothing (2.51), while
`enc-key-interleaved` (16 key pairs) flags with the opposite sign (-14.1). This is a cache-residency effect of
16 distinct sets of key-derived tables, a few cycles, not a dependence on plaintext and not a single-key effect.
The design does not claim constant time across many cached keys. `dec-key` gfni-simd and all other backends
were clean. No code change.

## Expected (documented, not new)

- `schedule-key` (random vs fixed seed): ~15% slower medians for random seeds. Key setup uses rejection
  sampling and is documented as not constant time. Fix (not applied): a rejection-free schedule.
- `v9-valid-tamper`: a valid open costs ~502k cycles, a tampered one ~4k, because the tag chain is checked
  before decrypting (fail closed). Not a compare leak (see `v9-tag-pos`, `stream-tag-pos`).

## Limits

- Timing tests cannot prove absence of leaks; this is one CPU model in a VM. VPSLLVW and PSHUFB have fixed
  latency on current Intel cores per Intel's tables, but other CPUs (or future microcode) were not tested.
- `stream-open-pt` on the five slow backends ran only ~20,000 samples (each open ~1.7 ms), so it has low power.
- Streaming open timings include per-stream key setup (identical in both classes by design: same key, pickup and
  nonce), so they do not test key setup.
- The padding strip after a valid final chunk scans trailing zeros (data dependent, after authentication); the
  stream tests forced a non-zero last byte in both classes, so they do not cover that scan.
- Data-dependent power/frequency effects (Hertzbleed-style) were not studied.

Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.
