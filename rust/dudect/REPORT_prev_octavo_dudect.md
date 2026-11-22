# Dudect-style constant-time timing tests — Octavo Rust port

**Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.**

Date: Sunday, 22 November 2026, America/New_York (UTC−5).
Machine: Intel Xeon, 8 CPUs, constant TSC at 2.400 GHz, pinned to CPU 2 with `taskset`.
Source: a *copy* of `/workspace/octavo_rust_port` at `/workspace/octavo_dudect/octavo_rust_port`. The original port, `/workspace/octavo_cli`, `/workspace/octavo_decrypt_speed`, and every frozen snapshot were left untouched. Nothing was pushed or sent off the box.

Harness: `/workspace/octavo_dudect/harness` (`octavo-dudect`). Results JSON: `/workspace/octavo_dudect/results/`.

## Method

Welch’s t-test on two classes, randomly interleaved in a balanced list (dudect / Oreparaz, Balasch, Faust). Cycle counts from `lfence; rdtsc; lfence` on a `constant_tsc` CPU. Outliers cropped at the pooled 99th percentile; both raw and cropped *t* are reported. Verdicts use the usual thresholds on cropped |*t*|:

- |*t*| > 4.5 — likely leak
- |*t*| > 10 — definite leak

**Dudect can detect a leak. It cannot prove the absence of one.** A small, stable mean gap becomes a huge |*t*| once *n* is in the millions; medians, *t*_raw, and a rerun all have to agree before a flag is treated as real.

Each block-cipher run timed *only* `encrypt_block` / `decrypt_block`. Key schedules were built beforehand. Key tests used an equal-footprint pool (16 cached copies of one seed vs 16 distinct seeds) so a “one hot object vs many cold objects” artifact is less likely. Follow-ups for a flagged key test: a paired (interleaved) layout, and a two-key test with two equally hot ciphers.

The v9 tag test used a one-chunk rehearsal blob. `v9-tag-pos` flips the first tag byte vs the last (both fail `Auth` and return *before* schedule or decrypt) — that is the MAC-compare test. `v9-valid-tamper` compares a valid open (schedule + decrypt) to a tampered tag (early `Auth`); a large |*t*| is expected and is *not* a `ct_eq` leak. `schedule-key` times `Cipher::new` itself and is documented as not constant-time in the key.

Budget: 40 s per block test, 25 s per `v9-tag-pos`, 20 s per expected-difference test, each wrapped in `timeout`. Main suite 8:49:16–9:09:22 AM ET (~20 min). Reruns 9:12:17–9:16:15 AM ET (~4 min). Compile was a few seconds on top.

## Per-backend summary (primary suite)

|*t*_crop| is the largest cropped |*t*| among `enc-pt`, `enc-key`, `dec-pt`, `dec-key`, and `v9-tag-pos` in the first pass. Sample counts are the sum of *n*₀+*n*₁ over those five tests. The last two columns record what happened after a rerun of anything that first-pass flagged.

| Backend | Total samples | Max \|*t*_crop\| (first pass) | On | After rerun |
|---|---:|---:|---|---|
| gfni-simd | 57,052,811 | 10.206 | enc-key | **Did not reproduce** (rerun \|*t*_crop\|=1.613). Two-key follow-up 1.296. See “Key tests on gfni-simd” below. |
| gfni-512 | 19,371,717 | 1.066 | v9-tag-pos | No flag. All five tests NO_EVIDENCE. |
| gfni-256 | 19,439,471 | 2.664 | dec-pt | No flag. All five tests NO_EVIDENCE. |
| gfni-128 | 18,169,435 | 1.293 | v9-tag-pos | No flag. All five tests NO_EVIDENCE. |
| aes-ni | 19,492,101 | 4.926 | v9-tag-pos | **Did not reproduce** (rerun \|*t*_crop\|=1.127, identical medians). Noise. |
| ct-soft | 17,653,764 | 6.115 | v9-tag-pos | **Did not reproduce** (rerun \|*t*_crop\|=0.876, identical medians). Noise. |

Settled verdict for the data path (fixed key, fixed vs random block) and for the v9 MAC compare: **no reproducible leak on any backend.**

## Block encrypt / decrypt — first-pass table

Times are CPU cycles at 2.400 GHz. Medians are class 0 / class 1.

| Backend | Test | *n* | *t*_raw | *t*_crop | Verdict | Median cycles |
|---|---|---:|---:|---:|---|---:|
| gfni-simd | enc-pt | 11,845,341 | +0.482 | −1.739 | NO_EVIDENCE | 7524 / 7524 |
| gfni-simd | enc-key | 11,625,019 | +0.985 | +10.206 | DEFINITE_LEAK | 7744 / 7740 |
| gfni-simd | dec-pt | 8,593,529 | +0.022 | −0.496 | NO_EVIDENCE | 10778 / 10778 |
| gfni-simd | dec-key | 8,657,317 | +1.323 | +2.863 | NO_EVIDENCE | 10322 / 10320 |
| gfni-512 | enc-pt | 872,065 | −0.080 | +0.586 | NO_EVIDENCE | 106996 / 106996 |
| gfni-512 | enc-key | 896,047 | +1.250 | +0.189 | NO_EVIDENCE | 102276 / 102262 |
| gfni-512 | dec-pt | 576,744 | +0.773 | −0.023 | NO_EVIDENCE | 152148 / 152170 |
| gfni-512 | dec-key | 591,974 | −0.757 | +0.279 | NO_EVIDENCE | 152522 / 152512 |
| gfni-256 | enc-pt | 870,212 | −0.829 | +0.722 | NO_EVIDENCE | 109696 / 109692 |
| gfni-256 | enc-key | 882,063 | +0.886 | −0.002 | NO_EVIDENCE | 102276 / 102258 |
| gfni-256 | dec-pt | 578,394 | −0.990 | −2.664 | NO_EVIDENCE | 164488 / 164494 |
| gfni-256 | dec-key | 587,231 | −1.029 | −0.861 | NO_EVIDENCE | 160750 / 160778 |
| gfni-128 | enc-pt | 875,850 | +0.775 | +0.809 | NO_EVIDENCE | 106582 / 106410 |
| gfni-128 | enc-key | 892,156 | +0.687 | −0.400 | NO_EVIDENCE | 105848 / 105852 |
| gfni-128 | dec-pt | 574,833 | +0.834 | +0.571 | NO_EVIDENCE | 164244 / 164232 |
| gfni-128 | dec-key | 574,738 | −0.400 | +0.377 | NO_EVIDENCE | 164734 / 164710 |
| aes-ni | enc-pt | 727,476 | −0.362 | +0.419 | NO_EVIDENCE | 109512 / 109512 |
| aes-ni | enc-key | 858,222 | +1.284 | +0.556 | NO_EVIDENCE | 106852 / 106840 |
| aes-ni | dec-pt | 598,773 | −2.981 | +0.394 | NO_EVIDENCE | 159786 / 159674 |
| aes-ni | dec-key | 611,454 | +0.243 | −0.619 | NO_EVIDENCE | 149198 / 149186 |
| ct-soft | enc-pt | 483,854 | +1.206 | +2.481 | NO_EVIDENCE | 188358 / 188230 |
| ct-soft | enc-key | 468,241 | +1.048 | +1.032 | NO_EVIDENCE | 201134 / 201086 |
| ct-soft | dec-pt | 361,638 | +1.269 | −0.464 | NO_EVIDENCE | 258878 / 258888 |
| ct-soft | dec-key | 371,888 | +0.167 | −0.435 | NO_EVIDENCE | 255870 / 256104 |

Plaintext tests (fixed key, fixed vs random block) were clean on every backend, including gfni-simd with ~12 million encrypts. Medians often match to the cycle. That is the main “constant time with respect to the data” claim, and dudect did not contradict it.

gfni-simd is much faster than the S-box-only hardware backends (~7.5k cycles / 3.1 µs to encrypt, vs ~107k cycles / 45 µs), so it collected an order of magnitude more samples in the same 40 s and is more sensitive to a few-cycle gap.

## Key tests on gfni-simd (the one first-pass definite flag)

The first `enc-key` run on gfni-simd had |*t*_crop| = 10.206, but *t*_raw was only 0.985 and the median gap was 4 cycles (~1.7 ns, about 0.05% of the operation). That is a crop-inflated *t* from a huge *n*, not a large timing hole. Follow-ups:

| Run | *n* | *t*_raw | *t*_crop | Verdict | Median cycles | Cropped means |
|---|---:|---:|---:|---|---:|---:|
| enc-key (first pass, two pools) | 11,625,019 | +0.985 | +10.206 | DEFINITE_LEAK | 7744 / 7740 | (not recorded) |
| enc-key rerun (same setup) | 11,933,501 | −1.112 | −1.613 | NO_EVIDENCE | 7544 / 7546 | 7816.97 / 7817.44 |
| enc-key-twokey (key A vs key B, both hot) | 11,932,987 | +0.792 | +1.296 | NO_EVIDENCE | 7522 / 7522 | 7818.90 / 7818.51 |
| enc-key-interleaved (16 fixed + 16 random, paired) | 11,860,115 | −1.176 | −7.693 | LIKELY_LEAK | 7566 / 7568 | 7854.76 / 7857.09 |
| enc-key-interleaved, second run | 11,699,082 | −4.150 | −14.965 | DEFINITE_LEAK | 7718 / 7736 | 7979.48 / 7983.97 |

Reading:

- A single cached key vs another single cached key (two-key) shows **no evidence** of a value-dependent leak. Medians match exactly.
- Repeating the original 16+16 pool test **did not reproduce** the first-pass flag.
- Cycling through *many distinct* key schedules vs *many copies of one* schedule (interleaved layout) did show a small, same-direction gap on both runs (a few cycles; random-key side slightly slower). Cropped |*t*| was large because *n* ≈ 12 million and the cropped stdev is only ~510 cycles, so a 2–4 cycle mean gap is “significant.”

That many-key gap is consistent with a **cache effect of key-derived tables**, not a data-dependent branch. The gfni-simd engine (`simd.rs`) precomputes 128-byte gather index maps for the weave, staff butterfly and shell bridges and applies them with `VPERMI2B`. The instruction is fixed-latency; the *contents* of those maps are key-scheduled. Sixteen different maps are a more diverse working set than sixteen copies of one map. The port already documents this class of behaviour: the weave / butterfly / bridge patterns are “key-dependent (but data-independent)” and the cipher is **not claimed constant-time with respect to the key**.

This is not a confirmed bit-leaking short-circuit in the encrypt path, and it was **not** fixed in the port. If someone wanted to harden it: keep the existing “CT in the data, not in the key” claim; there is no cheap way to make “one key vs many keys” cache-identical. A heavier design change would be to drop key-dependent permutations, or to always touch a key-independent set of tables (for example a fixed permutation plus a key-dependent correction applied with a constant-time blend). Neither was applied.

The slower backends never reached this sensitivity: a 4-cycle gap on a 100 k-cycle encrypt with *n* ≈ 0.5–0.9 million is well under the threshold.

## v9 MAC compare (`v9-tag-pos`)

Both classes fail the chunk tag and return before any decrypt. This is the test of whether `ct_eq` (and the HMAC around it) short-circuits on the first differing byte.

| Backend | *n* (first) | *t*_crop first | Median first | Rerun *n* | *t*_crop rerun | Median rerun | Settled |
|---|---:|---:|---:|---:|---:|---:|---|
| gfni-simd | 16,331,605 | +0.415 | 3324 / 3324 | — | — | — | NO_EVIDENCE |
| gfni-512 | 16,434,887 | +1.066 | 3296 / 3296 | — | — | — | NO_EVIDENCE |
| gfni-256 | 16,521,571 | −1.070 | 3294 / 3294 | — | — | — | NO_EVIDENCE |
| gfni-128 | 15,251,858 | −1.293 | 3652 / 3652 | — | — | — | NO_EVIDENCE |
| aes-ni | 16,696,176 | +4.926 | 3288 / 3288 | 19,891,159 | −1.127 | 3298 / 3298 | NO_EVIDENCE (noise) |
| ct-soft | 15,968,143 | +6.115 | 3630 / 3630 | 19,168,629 | +0.876 | 3616 / 3616 | NO_EVIDENCE (noise) |

The two first-pass “likely leak” flags had **identical medians** and a sub-cycle or sign-flipping mean gap, on a path that does not even use the S-box backend. They did not reproduce. `open_rehearsal` compares tags with `subtle::ConstantTimeEq` (`formats.rs` `ct_eq`). No leak found in the MAC compare.

## Expected, documented non-CT results (not surprises)

### Key schedule (`schedule-key`) — definite, expected

| Backend | *n* | *t*_raw | *t*_crop | Median cycles (fixed / random seed) |
|---|---:|---:|---:|---:|
| gfni-simd | 100,339 | −285.298 | −320.515 | 439,068 / 509,680 |
| ct-soft | 125,688 | −369.618 | −390.148 | 342,585 / 409,212 |

Random seeds take ~16–19% longer. Source: `Schedule::new` is explicitly **not** constant-time. It uses rejection sampling (`StaffSponge::below`) for invertible matrices, weave shifts, and the `S2 ≠ S` retry loop, then `Auto::prepare`. The number of loop iterations depends on the seed.

A fix, not applied: make the schedule a fixed-iteration procedure — for example always draw a fixed maximum number of candidates and pick with a constant-time select, or use a rejection-free sampler for invertible 8-bit matrices, and derive S2 so that it is guaranteed different from S without a retry. Dummy work up to a cap also hides the retry count, at a speed cost.

### Valid vs tampered v9 open (`v9-valid-tamper`) — definite, expected

| Backend | *n* | *t*_crop | Median cycles (valid / tampered) |
|---|---:|---:|---:|
| gfni-simd | 204,239 | +3780.666 | 458,080 / 3,656 |
| ct-soft | 148,144 | +4159.359 | 632,101 / 3,832 |

Valid opens are ~125–165× slower. Source: `open_rehearsal` verifies the whole tag chain first and **only then** builds the schedule and decrypts. A bad tag returns `Error::Auth` immediately. That is standard fail-closed AEAD, not a leak in `ct_eq` (see `v9-tag-pos` above).

A fix, not applied and not really recommended for the compare: if the *total* open time must be independent of validity, one could always decrypt after a failed tag and still return `Auth` without revealing plaintext. That hides this gap at a large speed cost. Separately, the success path then strips padding with a data-dependent zero-run scan (`while end > start && pt[end-1] == 0`); that is a different issue, only reached after a valid tag, and was not the subject of this test.

## Caveats

- Dudect never proves constant time. A leak that is rare, input-specific, or smaller than this setup can see will be missed. The slower backends had fewer samples (~0.4–0.9 million per block test vs ~6–12 million on gfni-simd).
- This is a shared VM. Other work was running on the machine (other Octavo workers use different folders). Context switches show up as a long right tail; cropping at p99 is meant to reduce that, but it can also inflate |*t*| when *n* is huge and a 2-cycle mean gap remains. That is exactly what happened on the first-pass flags that did not reproduce.
- *t*_crop with *n* in the 10⁷ range will call a 0.05% gap “definite.” Always look at medians, *t*_raw, and a second run.
- rdtsc measures this CPU’s cycles, not wall-clock on another machine. Frequency scaling is less of a worry here (`constant_tsc`, `nonstop_tsc`), but the box is still a hypervisor guest.
- Block tests do not include key setup. Mixing `Cipher::new` into the timed region would light up `schedule-key` on every key test.
- The optional `Table` backend was not tested; it is documented as not constant-time.
- Bow-pressure rotations are data-dependent amounts, implemented with `rotate_left`, which is a single constant-time rotate on this x86-64 CPU. A different architecture could differ. These tests did not flag the data path.
- `v9-tag-pos` does not use the block backend on the failing path, so a per-backend difference there is almost certainly machine noise.

## Bottom line

- **Data path (fixed key, fixed vs random block):** no dudect evidence of a leak on any of the six backends, encrypt or decrypt.
- **MAC compare (first vs last tag byte, both failing):** no reproducible leak. The two first-pass flags were noise; `subtle::ConstantTimeEq` looks fine here.
- **Key schedule:** large, expected leak from rejection sampling. Already documented. A rejection-free or fixed-iteration schedule would be the fix; it was not applied.
- **Valid vs tampered v9 open:** large, expected gap because decrypt runs only after a good tag. Not a compare leak.
- **gfni-simd, many distinct cached keys vs many copies of one key:** a small, sometimes statistically large few-cycle gap, consistent with cache behaviour of key-derived gather tables, already out of the “CT with respect to the key” claim. Two hot keys did not separate. No code change was made.

Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.
