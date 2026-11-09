# Octavo (files: `sneak_n2`) — fresh attack after the beat-7 bow fix

**Date:** Monday 2026-11-09, about 08:15–08:35 AM EST (America/New_York).
**Target:** `/workspace/sneak_n2/sneak_n2.py`, SHA-256 `aa975c951dce9200f6dc2812b59bde90b47b7bd28f13acef6bbbbd65da2aab6d` (every script asserts it before it imports). Live `BOW_STROKES = (0,1,2),(2,3,4),(4,5,6),(6,7,0),(1,2,3),(3,4,5),(5,6,0)`.
**Mode:** attack and report only. Nothing in the cipher, tests, docs, renderer, pictures, seed, snapshots or older `attacks_*` folders was changed, and no fix was applied (see `protected_verification.txt`). Lab experiments run on an independent NumPy copy of the round, which was checked against the live `round_enc`/`encrypt_grid` before each run. Candidate fixes were tried only on that lab copy.

> **Still homemade.** Finding no break is not a proof of security. For real data, use AES-GCM-SIV (RFC 8452), age, or libsodium.

---

## Plain-language summary

* **No break found.** As before, I found no way to read messages or forge blobs without the seed. Every tampered, spliced, truncated, random or older blob was rejected. Statistical tests after 1, 2, 3, 4 and 16 rounds look random.
* **The beat-7 fix did what it claimed, but only for odd beats.** The exact test protocol reproduces *1,083 bow-alone singletons → 0 after the rehair*. A larger scan over **all eight beats** still finds rare **single-byte leaks from beat 6**: about **1 in a million beat-6 changes** (45 in 42.8 M across four independent scans; 19 in 16.7 M in the cleanest run). They don't depend on the tables, and 3 witnesses stay single-byte under all 16 round tables. It is the same mechanism as the old beat-7 problem, one stroke earlier. The SPEC's argument only covers beats 1, 3, 5 and 7, and the strict test only scans odd beats, so neither caught it. (The old layout had these too: 28 beat-6 plus 406 beat-7 per 16.7 M. So the fix was a big improvement, just not complete.)
* **The fix created a new local structure in the bow.** The last two strokes now always use the **same rotation amounts**, both read from beat 0. When beat 0 is unchanged, those rotations are fixed. That makes some bow-only patterns much more predictable:
  * The best beat-7 differential through the bow alone rose from about 2^-8 to **2^-4.8**.
  * A beat-7 "all 256 values" set now gives **zero XOR-sums on beats 5–7 every time** (64/64 bases, against 1/64 with the old layout).
  * The rehair S-boxes and the cross-staff layer wipe all of this out within the same half-round. Bow+rehair best differential is ≤ 2^-13, and integral sums are random after the cross layer. Nothing reaches round level.
* **One older, stronger bow-only linear relation turned up.** It is not caused by this change: (cell 0 bit 0 ⊕ cell 1 bit 7) → out cell 0 bit 0 has correlation **−0.145 (≈2^-2.8)**. That is stronger than the 0.039 relation reported before. It is the carry-free low bit of the first stroke's addition, and it fires whenever that stroke's rotation is 1 (37/256). The rehair caps it at **0.0037**.
* **The key-signature check has three in-process blind spots.** They use code the source hash can't see: a function rebuilt from its own bytecode with different globals, an in-memory bytecode edit, and a patched built-in (`divmod`). In each case the cipher changed but the signature didn't. All three need an attacker who is already running code inside your Python process, which is outside what a source hash can promise. The earlier identity-`staff_mix` blind spot is now **closed**.

**Most pressing issue:** the beat-6 single-byte leaks. **Proposed fix (not applied):** change the third bow stroke from `(4,5,6)` to `(4,5,0)`. Lab result: **0 / 133.7 M** cases on all beats, against 19 for the live layout on the same bases. Details are in §7.

---

## Severity-ranked open issues

Scale: Critical / High / Medium / Low / Info. **Counts: 0 Critical, 0 High, 0 Medium, 4 Low, 4 Info.** Nothing here is a practical break.

| # | Sev. | Issue | Evidence | New? |
|---|---|---|---|---|
| 1 | **Low (most pressing)** | **Beat-6 bow+rehair singletons.** A beat-6-only change can leave exactly 1 changed byte after bow+rehair. Table-independent. Bow delta lands in pair (6,7) with du = 2·dv. | 19/16.7 M (live, `attack_fix_confirm`), 14/16.7 M (`attack_even_beats`), 10/8.4 M (`attack_fix_screen`), 2/1.04 M (`attack_bow`); 0 on every other beat. 3 witnesses are single-byte under all 16 round tables. The cross layer then spreads a single cell to 12 cells. | **Yes** (pre-existing, newly found; the old layout had 28) |
| 2 | Low | **Shared-rotation structure from beat 0 feeding two strokes.** The last two strokes always share (r1, r2). | Bow-alone best differentials: beat 7 2^-8.1 → **2^-4.8**, beat 6 2^-11.0 → 2^-7.7. beat7^0x80 most-common output difference 0.0016 → 0.020. Beat-7 256-set gives zero XOR-sums on beats 5–7 in 64/64 bases (old 1/64). Bow+rehair best differential ≤ 2^-13 on every beat. Integral dies at cross. | **Yes** (caused by the fix) |
| 3 | Low | **Key-signature in-process blind spots.** Same source text with different behaviour. | 3 demos, all `key_sig_changed = False`, behaviour changed, and the live decrypt of the tampered blob gives *DecodeError* (the tag validated). | **Yes** (new concrete variants of a documented limit) |
| 4 | Low | **Layer-level linearity** (known class): triplet bit 0 exactly GF(2)-linear, cross branch number 6, bow single-bit 0.039, and a **new stronger bow 2-bit relation −0.145**. | `attack_linear`, `attack_bow`. Bow+rehair max single-bit correlation 0.0037. | Partly new (the 2-bit relation) |
| 5 | Info | **Guessable seeds are accepted.** `seed=1`, all-zero or all-FF bytes work silently. | `attack_keysched_misc`: the schedules look random, but the seed is trivially guessable. Key-management issue, not a cipher issue. | Not reported before |
| 6 | Info | **RNG-failure equality leak.** If `os.urandom` were broken (fixed pickup), equal messages would give identical blobs. | Different messages still get different SIV nonces (0 equal ciphertext bytes). This is normal for SIV. | Known by design |
| 7 | Info | **No constant-time implementation.** Python table lookups and data-dependent rotations leak timing in principle. | Design note; not measured. | Known class |
| 8 | Info | **Format limits.** Single 127-byte block, no associated data, and a blob carries a 68-byte overhead. | Spec. | Known |

---

## 1. Regression of prior findings (`attack_regression.py`, `attack_regression_results.json`)

**Integrity.** The recorded hello-world blob (pickup `ee95ddb2…`, nonce `3102e10a…`) decrypts. Nothing else was accepted, and no DecodeError occurred without the seed:

| probe | result |
|---|---|
| all 1,560 single-bit flips | 1,536 tag mismatch + 24 bad version |
| 4 older samples (`76908595…` pre-beat-7, `24d554eb…`, `a287436b…`, `724da1f4…`) | all **tag mismatch** |
| 14 field splices with the previous sample | 14 tag mismatch |
| 198 wrong lengths | 198 bad blob length |
| 200 random SN2 blobs | 200 tag mismatch |
| 500 ciphertext-byte corruptions | 500 tag mismatch |
| 200 tag-byte corruptions | 200 tag mismatch |
| seed-holder: valid tag + wrong SIV nonce | `AuthError: SIV nonce mismatch` |
| seed-holder: valid tag + random ct | `DecodeError` (seed holders only) |

**SIV and nonce misuse.**
* A caller-supplied nonce (a replayed one, or all zeros) raises `ValueError`.
* 1,000 encryptions of the same message gave 1,000 unique pickups and 1,000 unique nonces.
* With a forced fixed pickup, equal messages give identical blobs (issue 6). Different messages still get different nonces.

**Related nonce** (48 one-bit flips; ideal values in brackets):
* round-key HD 511.2 ± 3.7 [512]
* S-table agreement 0.96 [1]
* MAC-key HD 128.0 [128]
* whitening HD 510.6 [512]

**Slide.** 100 schedules × 120 round pairs gave 0 equal rk, S, S2, σ, bridge, SH or SV, and S = S2 never occurred within a round.

**Key-signature tamper** (closure: 57 code names, 35 data names; 62 listed):

| change | key_sig changed? | live decrypt of tampered blob |
|---|---|---|
| revert `BOW_STROKES` to old `(5,6,7)` | yes | tag mismatch |
| identity `staff_mix` (prior blind spot) | **yes (closed)** | tag mismatch |
| identity `odd_restack`; drop B0; MIX2 → ((1,1),(1,3)); `encrypt_grid` default rounds 16→4 | yes | tag mismatch |
| `NR` 16→8 | yes | encrypt raises IndexError |
| module global `sum = max` (built-in object) | fails closed (TypeError) | — |
| **`bow_stroke` rebuilt from its own `__code__` with foreign globals** (`BOW_ROT_MOD=5`) | **no** | **DecodeError** (tag valid) |
| **`bow_stroke.__code__` edited in memory** (`BOW_R2_SHIFT`→`BOW_ROT_BASE`) | **no** | **DecodeError** |
| **`builtins.divmod` patched** (used by `shell_mix`) | **no** | **DecodeError** |

All three blind spots need code already running in the process. They are concrete variants of limits the code comment already lists ("code whose `__code__` differs from the file", "C-level/interpreter changes").

## 2. Differential (`attack_bow.py`, `attack_even_beats.py`, `attack_differential.py`, `attack_fix_*.py`)

**Singleton scans** (one input beat changed, all 255 deltas):

| scan | live `(5,6,0)` | old `(5,6,7)` |
|---|---|---|
| test protocol (512 bases, odd beats, 522,240 cases): bow alone | **1,083** (7→5: 776, 3→1: 120, 5→3: 94, 1→0: 93) | 555 |
| same, bow+rehair | **0** | 5 |
| 4,096 random bases, **all beats** (8.36 M): bow alone / bow+rehair | 6,637 / **2 (beat 6)** | 3,294 / 20 |
| 65,536 random bases, all beats (133.7 M), bow+rehair by beat | **[0,0,0,0,0,0,14,0]** | [0,0,0,0,0,0,28,406] |
| two-beat input deltas (28 beat pairs × 65,536) → singleton | 0 | 0 |
| whole round (sparse-output scan below) | no output with ≥ 8 unchanged bytes | — |

The bow-alone singletons rose because a beat-7 change now often ends up only in beat 5. The rehair always spreads those, because pair (4,5) sees a one-cell change. **Beat-6 mechanism**, from witness `[90,8,17,194,106,100,92,5]`, beat 6 ^ 28:
1. Stroke `(4,5,6)` reads beat 6, so its r2 changes (5→2) and beat 5 changes by 144.
2. `(3,4,5)` reads beat 5, but its rotations happen to stay (7,4).
3. `(5,6,0)` then adds the changed beat 6 into beat 5 and cancels the 144.
4. The final bow delta is `(…,0,36,18)` on pair (6,7), with 36 = 2·18 in GF(2^8)/0x1F5, the Latin pair's y-kernel. So S2 sees no change, and exactly one byte changes.

**Truncated differentials, round 0** (128 cells × 4,096 single-byte deltas; minimum / mean active cells):

| after | S | linear | bars | trips | bow | rehair | cross (S2 inputs) | round out |
|---|---|---|---|---|---|---|---|---|
| live | 1/1 | 16/16 | 22/41.6 | 31/49.3 | 41/53.0 | 43/53.8 | **118**/127.5 | 121/127.5 |
| old | 1/1 | 16/16 | 22/41.6 | 32/49.3 | 41/53.0 | 44/53.8 | 116/127.5 | 121/127.5 |

All 16 staffs are active after the first cross layer.

**Best-trail bounds** (sound but relaxed: triplets+bow are treated as an arbitrary staff-local bijection, so the bow change cannot weaken them; DDT max 4/256 in every table; cross branch number 6):

| rounds | active S-boxes ≥ | trail probability ≤ |
|---|---|---|
| 1 | 8 | 2^-48 |
| 2 | 20 | 2^-120 |
| 3 | 32 | 2^-192 |
| 4 | 44 | 2^-264 |
| 16 | 188 | 2^-1128 |

This is a single-trail bound; clustering was not bounded.

**Best measured differentials, one staff, 2^14 bases** (log2 probability by input beat):

| beat | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
|---|---|---|---|---|---|---|---|---|
| bow alone, live | −8.1 | −6.5 | −12.4 | −8.3 | −13 | −8.3 | **−7.6** | **−4.9** |
| bow alone, old | −8.0 | −6.8 | −13 | −8.2 | −13 | −8.2 | −11.2 | −8.2 |
| bow+rehair, live (≤ sample floor) | −14 | −14 | −14 | −13 | −14 | −14 | −14 | −13 |

**Sparse-output search** (single-cell random delta; a hit is ≥ 8 unchanged output bytes):

| rounds | pairs | hits | max unchanged | mean |
|---|---|---|---|---|
| 1 | 262,144 | 0 | 6 | 0.500 |
| 2 | 262,144 | 0 | 6 | 0.499 |
| 3 | 131,072 | 0 | 6 | 0.500 |
| 4 | 65,536 | 0 | 5 | 0.501 |
| 16 | 16,384 | 0 | 5 | 0.501 |

The random mean is 0.5.

**Avalanche and SAC.**
* Avalanche: 512.09 / 511.98 / 511.85 bits after 1 / 2 / 16 rounds, with std about 16 (ideal 512 ± 16).
* SAC (1,024 × 1,024, 256 samples per input bit): max z 4.75 after 1 round and 5.12 after 2 rounds, against an expected null max of 5.27. Mean |deviation| matches the null exactly.
* One-round (cell, value) output-difference bias: max count 102, against a null max of about 100.

## 3. Linear (`attack_linear.py`, `attack_bow.py`)

* **LAT:** all 64 keyed S/S2 tables (2 schedules) have max |LAT| 16, so correlation is **2^-3**. The spectrum is identical to SM4's.
* **Trail bound** (same relaxed model): correlation ≤ 2^-24 / 2^-60 / 2^-96 / 2^-132 for 1 / 2 / 3 / 4 rounds, and ≤ 2^-564 for 16 rounds.
* **Measured single-bit correlations, all 2^20 in→out pairs:**
  * 1 round, N = 2^18: max |c| = 0.00926 (4.74σ; null max 5.27σ), 0 entries over 5σ. The argmax re-measured on fresh data was −0.9σ.
  * 2 rounds, N = 2^17: max 0.0136 (4.93σ), 0 over 5σ. Fresh re-measurement −0.8σ.
  * Mean |c| equals the null to 4 digits.
* **LSB-plane parity:** 0.8σ after 1 round, 1.96σ after 2.
* **Triplet bit 0 is exactly GF(2)-linear.** It still holds (20,000 grids; matrix in the JSON).
* **Bow cell6.bit0 → cell7.bit4:** 0.0389 live, 0.0389 old (2^22 samples, σ = 0.0005). **Unchanged.** Through bow+rehair, the max single-bit correlation is 0.0037.
* **Beat 0 feeding two rotations:** no new single-bit relation appeared. The 64 × 64 bow table has max 0.0389 (live) vs 0.0398 (old), with 8 vs 9 relations ≥ 0.01 and none ≥ 0.1.
* **New 2-bit-input search on the bow alone** (2,016 input pairs × 64 outputs, 2^20 samples): **(c0.b0 ⊕ c1.b7) → c0.b0, correlation −0.145**. The old layout has the same relation at −0.145 via (c0.b0 ⊕ c1.b4); each r1 value gives one such relation. It is pre-existing. Cause: beat 0 is written once, by u = s0 + rotl(s1, r1), whose low bit is carry-free, and r1 = 1 has probability 37/256 ≈ 0.145. It is local; the rehair S-box caps it.
* **Rotation statistics:** r1 is near-uniform (37/37/37/37/36/36/36). r2 is skewed (40,40,40,40,32,32,32 per 256). The shared pair is complementary (r1 + r2 = 8) with probability 0.145. In the old layout the two strokes had equal rotations only 2.3% of the time; now it is 100%.

## 4. Algebraic (`attack_algebraic.py`, `attack_bow_cube.py`)

* **Degree:** all 64 S/S2/SI/SI2 tables have degree 7. Each S-box has 23 bi-affine and 39 full-quadratic equations (SM4 base and keyed tables alike).
* **Integral by sub-layer, round 0** (one cell over all 256 values, 256 sets; mean zero-sum cells, random 0.5):
  * linear: 128
  * bars: 128
  * trips: 92.8
  * bow: 75.1
  * rehair: 74.3
  * **cross: 0.41** (old layout 0.57)
  
  The integral dies at the first cross layer, the same as with the old layout.
* **Integral by rounds:**
  * One cell: 0–2 zero-sum cells after 1, 2 and 3 rounds (random 0.5).
  * Two cells (65,536 texts): 0–3 zero-sum cells.
  * Additive mod-256 sums: 0.32% / 0.29% (random 0.39%).
* **Cube sums** (d = 4, 8, 12, 16 random bits, 4 bases, 1–2 rounds): 47–84 always-zero output bits, against a random expectation of 64. Nothing stands out.
* **New bow-only structure** (fraction of zero cube sums on output beats 5–7; random 0.5, degree < d gives 1.0):

  | cube vars | d | live | old |
  |---|---|---|---|
  | beats 5–7 | 16 | 0.93 | 0.73 |
  | beats 6–7 | 16 | **1.00** | 0.69 |
  | beat 7 | 8 (full cell) | **1.00** | 0.69 |

  Cause: with beat 0 constant, the last two strokes are fixed-rotation ARX, so s6′ = s6 + rotl(s7, r) runs over all 256 values. Through bow+rehair, the same cubes give 0.50–0.51 (random). This is a local, half-round property.
* **System size** (unchanged by this constant): 9,216 S-box evaluations over 16 rounds, about 359k quadratic equations, plus ARX carries and data-dependent rotations. Per-message schedules sit behind SHA-256.

## 5. Key schedule, related-key, weak-key (`attack_keysched_misc.py`)

* **Related seeds** (32 one-bit seed flips, same nonce; ideal values in brackets):
  * round-key HD 512.1 [512]
  * S agreement 0.94 [1]
  * MAC-key HD 127.3 [128]
  * clef HD 63.8 [64]
  * key_sig HD 65.3 [64]
  * ciphertext HD 513.6 [512]
* **Seed-bit influence** on the round-0 key: mean 0.5008, range 0.47–0.54.
* **Structure over 300 schedules (4,800 rounds):**
  * S fixed points: mean 0.98 (max 8)
  * bridge fixed points: 1.03
  * SH/SV all-zero: 0
  * identity σ faces: 3 (1.9 expected)
  * identity bridge: 0
  * S2 = S ⊕ const: 0
  * zero round-key bytes: 2,425 (2,400 expected)
* **Named weak seeds** (all-zero, all-FF, 0x01 repeated, int 1, 55AA): schedules look random and all round-trip. The API accepts them without complaint (issue 5).

## 6. Other ideas tried

* **Boomerang** (lab, fixed schedule, single-cell α and δ; 8,192 / 4,096 / 2,048 quartets over 1 / 2 / 3 rounds): 0 exact returns. The mean number of zero cells in P3⊕P4 was 0.496 / 0.497 / 0.481 (random 0.5), with 0 returns confined to one staff.
* **Rotational** (rotate every byte by k):
  * bow alone: 0 commuting staffs for k = 1–4
  * 1 round: 0.50 equal cells (random 0.5)
  * the unkeyed triplet and cross layers partly commute for k = 1 (5.2 and 26.5 equal cells), but the S-boxes erase this
  * related keys would need SHA-256 control
* **Staff symmetry:** the cross layer does not commute with the inner↔outer, rotate-4 or swap-pairs permutations.

## 7. Most pressing issue and proposed fix (NOT applied)

**Issue 1: beat-6 singletons.** The SPEC argues the no-singleton property for odd beats only. A beat-6 change alters the rotations of `(4,5,6)`, the shifted beat 5 can be cancelled again in `(5,6,0)`, and the leftover delta can land in pair (6,7)'s field kernel.

**Proposed change:** third stroke `(4,5,6)` → **`(4,5,0)`**, so its pressure is read from beat 0, which nothing writes after stroke 1.

**Argument for beat 6** (any base, any delta, any tables):
1. Beat 6 is now read by no stroke before `(6,7,0)`.
2. `(6,7,0)` has fixed rotations, so u = s6 + rotl(s7) changes, and s7′ = s7 ⊕ rotl(u, r2) changes. Beat 7 is never written again.
3. `(5,6,0)` has fixed rotations and adds the changed s6′ into an unchanged s5, so beat 5 changes.
4. Beats 5 and 7 therefore both change, in two different pairs, so the change can't stay confined to one pair and shrink to a single byte.

The odd-beat arguments in the SPEC carry over unchanged, because stroke `(4,5,·)` still always changes beat 4 for a beat-5 input when its pressure is fixed. Even beats 0, 2 and 4 are covered by measurement only (0 hits), not by proof.

**Lab evidence:**
* 65,536 random bases × 8 beats × 255 deltas = 133.7 M cases: **0** kernel hits, against **19** (all beat 6) for the live layout on the same bases.
* An exact inverse was checked on 65,536 staffs.
* The 3 witnesses change 4 bytes.
* Screening of all 35 single-pressure changes is in `attack_fix_screen_results.json`. `(1,2,6)` also reached 0 / 66.8 M, but it has no proof, so it is less suitable.

**Honest side effects** (`attack_fix_sidefx_results.json`):
* Beat 0 would feed 3 rotations.
* The bow-alone best beat-6 differential goes from 2^-7.75 to **2^-5.68** (beat 7 stays about 2^-4.8).
* Bow-alone singletons go from 6,721 to 7,835 per 8.36 M (all absorbed by the rehair).
* Max single-bit correlation is unchanged at 0.039.

All of these are bow-local and absorbed by the rehair S-boxes. The change would alter `BOW_STROKES`, so key_sig, every tag and the hello-world sample would change. Older blobs would fail on the tag.

**Also recommended:**
* Extend the strict test to all 8 beats (even beats are not scanned today).
* Correct the SPEC line "random 400,000-case scan … 0 on every beat". The beat-6 rate (about 1e-6) is too low for that scan size to detect.
* Optionally, for issue 3: add a behavioural known-answer digest to `key_signature` (encrypt fixed blocks under a fixed internal schedule and hash the output). That catches same-source and different-behaviour patches on the tested path.

## Not covered / limits

* No MILP/SAT search for concrete best multi-round trails, and no differential-clustering or linear-hull bound. The bounds are single-trail and relaxed.
* Cubes stop at d ≤ 16, integrals use 8- and 16-bit sets, and there was no Gröbner/XL solving.
* Boomerang tests used single-cell differences and at most 3 rounds. Rotational tests covered unkeyed layers and 1 round only.
* Weak-key checks were statistical over 300 schedules plus 5 named seeds. They were not exhaustive.
* Timing and side channels were not measured.
* All round-level tests use a fixed known schedule (white-box lab model). The real API derives a fresh SHA-256 schedule per message, so an outsider gets one block per schedule.
* Still homemade: use AES-GCM-SIV, age, or libsodium for anything real.

## Replay

`python3 /workspace/sneak_n2/attacks_octavo_beat7/attack_replay.py` runs 15 checks in about 3 s and prints **REPLAY PASS** (output in `replay_output.txt`).

## Files

* `common.py`: SHA guard and NumPy lab batch.
* `attack_regression.py`, `attack_bow.py`, `attack_even_beats.py`, `attack_differential.py`, `attack_linear.py`, `attack_algebraic.py`, `attack_bow_cube.py`, `attack_keysched_misc.py`, `attack_fix_screen.py`, `attack_fix_confirm.py`, `attack_fix_sidefx.py`: each writes `*_results.json` and `*_output.txt` (run logs in `*_run_output.txt`).
* `summary.json`, `attack_replay.py`, `replay_output.txt`.
* `protected_hashes_before.txt`, `protected_hashes_after.txt`, `protected_verification.txt`.
