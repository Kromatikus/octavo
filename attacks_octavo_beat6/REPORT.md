# Octavo (files: `sneak_n2`): fresh attack after the beat-6 bow fix

**Date:** Monday 2026-11-09, about 9:27–9:45 AM EST (America/New_York).
**Target:** `/workspace/sneak_n2/sneak_n2.py`, SHA-256 `922a29d89be68b29a2be08873ff5a99a7cf264afebe1ece0387aa0f4fe56fe10`. Every script asserts this before importing. The live `BOW_STROKES` is `(0,1,2),(2,3,4),(4,5,0),(6,7,0),(1,2,3),(3,4,5),(5,6,0)`. "Previous" below means the beat-7-fix layout with `(4,5,6)`.
**Mode:** attack and report only. Nothing was changed in the cipher, tests, docs, renderer, pictures, seed, snapshots or older `attacks_*` folders, and no fix was applied (see `protected_verification.txt`). Lab experiments use the NumPy copy from the previous attack, revalidated against the live `round_enc`/`encrypt_grid` (16 rounds plus whitening). Candidate fixes were tried only on that lab copy.

> **Still homemade.** Finding no break doesn't prove it's secure. For real data, use AES-GCM-SIV (RFC 8452), age, or libsodium.

---

## Plain-language summary

* **No break found.** I found no way to read or forge a message without the seed. Every tampered, spliced, truncated, random or older blob was rejected, including the previous hello-world (pickup `ee95ddb2…`). Statistics after 1, 2, 3, 4 and 16 rounds look random.
* **The single-byte leak is gone on every beat, and 3 of the 4 even beats now have a written proof.** I scanned **2.69 billion** one-beat changes (random, rotation-symmetric, and low-weight bases, plus 401 M additive changes). None left a single changed byte after bow+rehair. On the even beats, no change ever ended up confined to one rehair pair.
  * **Beat 0:** proof. A beat-0 change always changes bow outputs 0, 1 and 2. That is two pairs, so at least 2 bytes change after rehair.
  * **Beat 4:** proof. Outputs 5 and 6 always change.
  * **Beat 6:** proof (same as last report). Outputs 5 and 7 always change.
  * **Beat 2:** only partly proven. When the bow's beat-0 output stays the same (about 15% of cases), outputs 3 and 4 always change. Otherwise it is measured only: in all 14.1 M measured cases, at least 3 pairs were active.
  * You asked about beat 0 especially. Changing it does shift three rotations at once, but it also always changes outputs 0, 1 and 2, so it can't leak a single byte.
* **The fix strengthened the beat-0 shared-rotation structure, but it stays inside one half-round.** Three strokes now share beat 0's rotations, so whenever beat 0 is constant, the back half of the bow is fixed-rotation ARX.
  * The best bow-alone beat-6 differential rose from 2^-7.5 to **2^-5.6**. Beat 7 stays about 2^-4.9.
  * A new integral appeared: a beat-6 "all 256 values" set now gives zero sums on rehair pair (4,5) in 128/128 cases (previously 0/128). One older integral (beat 0 → pair (2,3)) disappeared.
  * Bow+rehair cubes on beats 5–7 give 0.66 zero bits at d=12, against 0.50 before.
  * All of this dies by the next half-round (0.50). Starting from the round input, the integral dies at the cross layer (0.50), the same as before. The best bow+rehair differential is ≤ 2^-13 on every beat, which is at the sample floor. Nothing reaches round level.
* **Bow linear relations didn't get worse.** The 2-bit relation is still 0.145 in magnitude (−0.145 in the old report's sign convention) and the single-bit one is still 0.039, identical to the previous layout. I searched exhaustively for the best output mask on each rehair pair (Walsh transform, 2^22 samples). The best correlation that survives the rehair is **0.0038**, the same as before.
* **The key-signature blind spots are unchanged.** All three in-process tricks still change the cipher without changing the signature, and they still need code already running in your Python process. The identity-`staff_mix` case stays closed.

**Most pressing issue:** the three-way shared rotation (issue 1). **Proposed fix (not applied):** give each beat-0 reader its own view of beat 0 (details in §6). It reduces the bow-local differentials, but it can't remove the integral or cube structure, so it is optional hardening, not a security repair.

---

## Severity-ranked open issues

**Counts: 0 Critical, 0 High, 0 Medium, 4 Low, 4 Info.** None is a practical break.

| # | Sev. | Issue | Evidence | New? |
|---|---|---|---|---|
| 1 | **Low (most pressing)** | **Three-way shared rotation from beat 0.** Strokes `(4,5,0)`, `(6,7,0)` and `(5,6,0)` all read beat 0, which nothing writes after stroke 1, so they always use the same (r1, r2). | Bow-alone best differential, beat 6: 2^-7.54 → **2^-5.56** (`0x80 → (…,08,00,08)`). Beat 7: 2^-4.75 → 2^-4.89. Beat 4: 2^-13 → 2^-12. Half-round integral: beat 6 → rehair (4,5) zero-sum 128/128 (previous 0/128); beat 0 → (2,3) went 128/128 → 0/128. Bow+rehair cube d=12: 0.66 vs 0.50. Next half-round: 0.50. Round-input integral at cross: 0.50. Bow+rehair best differential ≤ 2^-13. | **Yes** (made stronger by the fix) |
| 2 | Low | **Beat 2 is the only beat without a complete written no-singleton argument.** | 0 / 534.8 M random + 66.8 M rotation-symmetric + 1.56 M low-weight + 133.7 M additive. Proven in the 15% case where the beat-0 output is unchanged. In the other 85%, ≥ 3 active pairs in all 14.1 M measured. | **Yes** |
| 3 | Low | **Key-signature in-process blind spots** (foreign globals, in-memory `__code__` edit, patched `builtins.divmod`). | 3/3 still show `key_sig_changed = False`, behaviour changed, and the live decrypt gives *DecodeError*. The other 7 tamper cases change key_sig or fail closed. | No (status confirmed) |
| 4 | Low | **Layer-level linearity** (known class). Triplet bit 0 exactly GF(2)-linear, bow 2-bit 0.145, bow single-bit 0.039. | All unchanged by the layout. Best rehair-pair output mask 0.0038 (2^22, Walsh). Bow+rehair single-bit max 0.0039. | No |
| 5 | Info | Guessable seeds accepted (`seed=1`, all-zero, all-FF). | `attack_keysched_misc`. | No |
| 6 | Info | RNG-failure equality leak (fixed pickup gives equal messages identical blobs). | Different messages still get different nonces. SIV-normal. | No |
| 7 | Info | Not constant-time (table lookups, data-dependent rotations). | Design note. | No |
| 8 | Info | Format limits: one 127-byte block, no associated data, 68-byte overhead. | Spec. | No |

---

## 1. Even beats: single-byte leak hunt (`attack_even_beats.py`)

A rehair singleton happens only if the bow output delta sits in exactly one pair (i, i+1), both cells change, and du = dv or du = 2·dv. That condition doesn't depend on the tables, so the scan checks it on the bow alone. A fast bow was validated against the live `bow_pressure` on 2,000 staffs, and the scan ran on 6 cores.

| scan | cases | beat 0 | beat 2 | beat 4 | other beats |
|---|---|---|---|---|---|
| A: 2^21 random bases × 255 XOR deltas (even beats) | 534.8 M each | **0** | **0** | **0** | — |
| B: 2^18 random bases, all 8 beats | 66.8 M each | 0 | 0 | 0 | 0 (1, 3, 5, 6, 7) |
| C: 2^18 bases with every byte rotation-symmetric (`rotl(x,4)=x`, so rotation changes often don't show) | 66.8 M each | 0 | 0 | 0 | 0 |
| D: 6,128 low-weight / repeated / one-hot bases | 1.56 M each | 0 | 0 | 0 | 0 |
| E: 2^19 bases × 255 **additive** deltas (+k mod 256) | 133.7 M each | 0 | 0 | 0 | — |

Across scans A–D, no even-beat change ever left exactly one active pair, the necessary first step (`one_pair_both = 0`). The minimum was always 2 active pairs. Odd beats sometimes have one active pair, but never in the field kernel, which matches the SPEC argument. Beat 6 always has exactly 2 active pairs, (4,5) and (6,7). No witnesses were found, so there was nothing to confirm on the live 16 round tables.

**Written arguments** (any base, any delta, any tables). Each uses only "pressure byte unchanged ⇒ rotations fixed" and "x ↦ x + c, x ↦ x ⊕ c are bijections":
* **Beat 0.** Stroke `(0,1,2)` has fixed rotations (beat 2 is unchanged), so u = s0 + rotl(s1) changes. Beat 0's final value is u, and s1 changes. Stroke `(2,3,4)` is untouched, so `(1,2,3)` has fixed rotations: beat 1 (= u5) changes, then beat 2 = s2 ⊕ rotl(u5) changes. Neither is written again. Outputs 0, 1 and 2 change: two pairs.
* **Beat 4.** Stroke `(4,5,0)` reads beat 0, which beat 4 can't reach before stroke 3, so its rotations are fixed. u3 changes and beat 5 changes. `(6,7,0)` is untouched. `(5,6,0)` has fixed rotations: beat 5 (= u7) changes, then beat 6 changes. Outputs 5 and 6 change: two pairs.
* **Beat 6.** Same as last report: outputs 5 and 7 change.
* **Beat 2 (partial).** If the bow's beat-0 output is unchanged, strokes `(4,5,0)`, `(6,7,0)` and `(5,6,0)` are untouched. s3 changed at stroke 2, so `(3,4,5)` (fixed rotations, beat 5 unchanged) changes beats 3 and 4: two pairs. Measured: 2,579,488 / 2,579,488. If beat 0 does change, I found no complete argument. Measured: ≥ 3 active pairs in all 14,132,192 cases.
* Empirically, the outputs that always change are: beat 0 → {0,1,2}, beat 4 → {5,6}, beat 6 → {5,7}. Beats 1, 2, 3, 5 and 7 have no single always-changed set. The odd beats rely on the SPEC's argument.

## 2. Beat-0 shared-rotation structure (`attack_shared_rotation.py`, `attack_bow.py`, `attack_bow_cube.py`, `attack_cube_survival.py`)

* **Facts.** Three strokes read beat 0 after its last write. r1 is near-uniform (37/37/37/37/36/36/36), and r2 is skewed (40×4, 32×3). P(r1 + r2 = 8) = 0.145.
* **Related-rotation on beat 0.** Only **1.87%** of beat-0 XOR deltas keep the three shared rotations. Even within those cases the best bow differential is 2^-8.1, and through bow+rehair it is 2^-15 (sample floor 2^-16).
* **Bow-alone best single-beat differentials** (log2, 2^14 bases, all deltas):

  | beat | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
  |---|---|---|---|---|---|---|---|---|
  | live | −8.1 | −6.5 | −12.4 | −8.3 | −12.0 | −8.3 | **−5.6** | −4.9 |
  | previous | −8.0 | −6.8 | −13.0 | −8.2 | −13.0 | −8.2 | −7.5 | −4.8 |
  | bow+rehair, live | −14 | −14 | −14 | −13 | −14 | −13 | −13 | −13 |

  The bow+rehair row is at the sample floor.
* **Bow reach** (which bow outputs an input beat can affect). Live: beat 0, 1, 2 → all 8; beat 3 → 1–4; beat 4 → 1–6; beat 5 → 3–6; beat 6 → 5–7; beat 7 → 5–7. Previous: beats 0 and 1 didn't reach 3–4, and beat 6 reached 3–7. Total reach is 44 vs 42.
* **Integrals.** Constant outputs are excluded, because they sum to zero trivially.
  * Bow only: as before, the beat-6/7 sets give balanced, zero-sum outputs on beats 5–7.
  * After the rehair S-boxes (non-constant cells, 128 sets): live gives beat 4 → (6,7), beat 6 → (4,5) and beat 7 → (4,5), each at 1.0. Previous gave beat 0 → (2,3), beat 4 → (6,7) and beat 7 → (4,5) at 1.0. So one integral was gained and one lost.
  * Two-beat 2^16 sets have the same character in both layouts.
* **Cubes on beats 5–7** (zero fraction; random 0.5):

  | one staff, d=12 | bow | rehair | cross | S2 | next half-round |
  |---|---|---|---|---|---|
  | live | 0.999 | **0.852** | 0.887 | 0.886 | **0.503** |
  | previous | 0.949 | 0.736 | 0.808 | 0.806 | 0.503 |

  The cross layer is linear and S2 acts cell by cell, so a one-staff property carries through them. Everything is random again after the next bars/trips/bow/rehair. Starting from the **round input** (an attacker-reachable set), one-cell integrals are 0.50 zero cells after the cross layer in both layouts (`attack_algebraic`).
* **Rotational pairs** (`rotl_k` on every byte): 0 commuting staffs for k = 1–4. Mean equal cells were 0.10 (live) vs 0.10 (previous). One round gives 0.49–0.51 (random 0.5).

## 3. Bow linear relations (`attack_bow.py`, `attack_shared_rotation.py`, `attack_linear.py`)

* **Bow alone, 64×64 single-bit, 2^22 samples:** max 0.0389, from c6.b0 → c7.b4. That is the same relation as before, with 13 relations ≥ 0.01 against 9 before and none ≥ 0.1.
* **Bow alone, 2-bit inputs:** (c0.b0 ⊕ c1.b7) → c0.b0 has magnitude **0.1447** in both layouts. It comes from stroke 1, which this layout change didn't touch.
* **Survival through the rehair:**
  * Best 2-bit-input to single-output-bit correlation over 2^21 samples: 0.0030 live vs 0.0031 previous, both at noise level.
  * Exhaustive best output mask over each rehair pair (Walsh on 2^16 masks, 2^22 samples):
    * c0b0⊕c1b7: **0.0038**, about 7.7σ, the same in both layouts (mask `0xdbf6` on pair (0,1))
    * c6b0: 0.0025 (null max ≈ 0.0021)

  The relations stay real but tiny, and the cross and next S-box layer dilute them further.
* **Round level:** 1 round, max |c| 5.27σ over 2^20 pairs; 2 rounds, 5.24σ (null max 5.27σ). Both argmaxes re-measured on fresh data at about 1.1σ. LSB-plane parity was 1.4σ and −0.1σ.
* **LAT:** all 64 tables max 2^-3, the same as SM4. The trail bound gives correlation ≤ 2^-564 over 16 rounds.

## 4. Regression (`attack_regression.py`, `attack_differential.py`, `attack_algebraic.py`, `attack_keysched_misc.py`, `attack_bias_followup.py`)

* **Integrity.** The hello-world blob (pickup `d450337d…`) decrypts. All 1,560 bit flips were rejected (1,536 tag mismatch + 24 bad version). Older samples `ee95ddb2…`, `76908595…`, `24d554eb…`, `a287436b…` and `724da1f4…` all gave **tag mismatch**. Also rejected:
  * 14 field splices: tag mismatch
  * 198 wrong lengths: bad blob length
  * 200 random blobs, 500 ciphertext corruptions and 200 tag corruptions: all tag mismatch

  Nothing was accepted, and no DecodeError occurred without the seed. Seed-holder checks (expected-access only): a valid tag with a wrong nonce gives `SIV nonce mismatch`, and a valid tag with random ciphertext gives `DecodeError`.
* **Nonces.** Caller-supplied nonces raise `ValueError`. 1,000 encryptions gave 1,000 unique pickups and nonces.
* **Related nonce** (48 one-bit flips; ideal values in brackets): rk HD 511.2 [512], S agreement 0.96 [1], MAC HD 128.0 [128], whitening HD 510.6 [512].
* **Related seed** (32 flips): rk 512.1, MAC 127.3, key_sig 64.5, ciphertext 511.2.
* **Slide:** 100 schedules × 120 round pairs, 0 equal components.
* **Sparse output** (≥ 8 unchanged bytes = hit): 0 hits at 1, 2, 3, 4 and 16 rounds. Max unchanged 7, 6, 5, 6 and 5. Mean 0.50 (random 0.5).
* **Avalanche:** 511.9 / 512.1 / 512.0 bits, with std about 16. SAC max z was 5.25 / 5.00 (null 5.27).
* **One-round (cell, Δ-value) bias:** first-pass max 108, null max about 100. A fresh pass gave max 103, and the top 5 re-measured on 2^16 new pairs at −1.75σ to +0.81σ. That is noise.
* **Truncated differentials, round 0** (this schedule): min/mean active cells after the bow 29/47.8, the same in both layouts. After the cross, 114 vs 116 minimum and 127.5 mean, with all 16 staffs active.
* **Trail bounds** (relaxed, single-trail): 1 / 2 / 3 / 4 / 16 rounds need ≥ 8 / 20 / 32 / 44 / 188 active S-boxes, so probability ≤ 2^-48 / 2^-120 / 2^-192 / 2^-264 / 2^-1128. This bound doesn't depend on the bow.
* **Cube/integral, 1–2 rounds:**
  * Cubes d = 4–16 give 51–80 always-zero bits (random 64).
  * One-cell integrals give 0–3 zero-sum cells (random 0.5).
  * Additive sums: 0.34% / 0.44% (random 0.39%).
* **Boomerang** (1–3 rounds): 0 returns.
* **Weak keys** (300 schedules): normal. The named weak seeds are still accepted (issue 5).

## 5. Key-signature in-process blind spots (`attack_regression.py`)

| change | key_sig changed? | live decrypt of tampered blob |
|---|---|---|
| revert `BOW_STROKES` to previous `(4,5,6)` | yes | tag mismatch |
| identity `staff_mix`, identity `odd_restack`, drop B0, MIX2 change, `encrypt_grid` default 16→4 | yes | tag mismatch |
| `NR` 16→8 | yes | IndexError |
| module global `sum = max` | fails closed (TypeError) | — |
| **`bow_stroke` rebuilt with foreign globals** | **no** | DecodeError |
| **`bow_stroke.__code__` edited in memory** | **no** | DecodeError |
| **`builtins.divmod` patched** | **no** | DecodeError |

Status: **unchanged, 3 open.** All three need attacker code already inside the Python process. The suggestion from last time still applies: add a behavioural known-answer digest to `key_signature`.

## 6. Most pressing issue and proposed fix (NOT applied)

**Issue 1.** Beat 0 now drives three strokes' rotations. Whenever beat 0 is constant, which is true for any change confined to beats 3–7, the back half of the bow is fixed-rotation ARX with identical rotations. That raises bow-local differentials, cubes and integrals. All of them are absorbed within the next half-round, so this is hardening, not a break.

**Proposed change:** keep `BOW_STROKES` as it is, but give each beat-0 reader a different view of the pressure byte before the r1/r2 formulas:
`(4,5,0)` uses p, `(6,7,0)` uses rotl(p,3), and `(5,6,0)` uses rotl(p,5).
Each rotation is still a fixed function of beat 0, so every singleton argument above, and the SPEC's odd-beat argument, carries over unchanged. Those arguments only use "pressure unchanged ⇒ rotations fixed". It also stays invertible, because beat 0 isn't written after stroke 1.

**Lab result** (`attack_fix_screen.py`):

| | live | proposed (bit slices) |
|---|---|---|
| singletons, all beats | 0 / 4.18 M | 0 / 4.18 M |
| forced-change proofs (beats 0, 4, 6) | hold | hold |
| bow-alone best differential, beat 7 / 6 / 0 | 2^-4.7 / 2^-5.6 / 2^-8.1 | **2^-7.4 / 2^-7.1 / 2^-10.2** |
| rehair integral beat 6/7 → (4,5) | 32/32 | 32/32 (unchanged) |
| bow+rehair cube d=12 | 0.656 | 0.705 (not improved) |
| c6.b0 → c7.b4 | 0.039 | 0.038 |

I also tried XOR constants (`00/5A/C3`) and mod-7 offsets. They helped less (beat 7: 2^-6.8 and 2^-5.6).

**Honest limits.**
* The integral and cube structure is inherent to fixed-rotation ARX whenever beat 0 is constant. Removing it would mean letting late strokes read bytes that change, and that would break the singleton proofs. I recommend keeping the proofs.
* The candidate was screened on only 4.18 M cases. Before applying it, run the full 2^21-base even-beat scan and the test suite.
* Applying it changes the code, so key_sig, every tag and the hello sample would change, and older blobs would fail on the tag.

**Also recommended (doc only):** add the beat-0 and beat-4 arguments to the SPEC, and mark beat 2 as "measured only" (issue 2).

## Not covered / limits

* No MILP/SAT best-trail search, and no clustering or linear-hull bounds. The bounds are single-trail and relaxed.
* Beat 2 is not fully proven, and the scans are random or structured rather than exhaustive over 2^64 bases.
* Cubes go up to d ≤ 16 and integrals up to 2-cell sets. There was no Gröbner or XL solving, and boomerangs covered at most 3 rounds.
* All round-level tests use a known fixed schedule (white-box lab). The real API derives a fresh SHA-256 schedule per message.
* Timing and side channels were not measured.
* The proposed fix was screened only lightly, on the lab copy.

## Replay

`python3 /workspace/sneak_n2/attacks_octavo_beat6/attack_replay.py` runs **16 checks in about 3.7 s** and prints **REPLAY PASS** (`replay_output.txt`). It is pinned to SHA `922a29d8…`.

## Compute and files

The scripts' wall times add up to about 20 min (the even-beat scan ran on 6 cores).

* `common.py`: SHA guard, lab batch, previous and pre-beat-7 layouts and samples.
* `attack_even_beats.py`, `attack_shared_rotation.py`, `attack_cube_survival.py`, `attack_bias_followup.py`, `attack_fix_screen.py` (new)
* `attack_bow.py`, `attack_regression.py`, `attack_differential.py`, `attack_linear.py`, `attack_algebraic.py`, `attack_bow_cube.py`, `attack_keysched_misc.py` (copied from `attacks_octavo_beat7` and adapted)

Each writes `*_results.json` and `*_output.txt`, with run logs in `*_run_output.txt`.

* `summary.json`, `attack_replay.py`, `replay_output.txt`
* `hash_protected.sh`, `protected_hashes_before.txt`, `protected_hashes_after.txt`, `protected_verification.txt`
