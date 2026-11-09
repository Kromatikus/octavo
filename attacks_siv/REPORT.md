# Attack report: CURRENT 8-bit N2 with clef, bar-line encore, and SIV nonce

> **This is a homemade, unreviewed cipher. Do not use it for real secrets. For anything real, use AES-GCM-SIV, age, or libsodium.** This report is cryptanalysis only. It does not modify the cipher and does not certify it as secure.

- **Date:** Sunday 2026-11-08, about 10:41–10:50 AM EST (America/New_York).
- **Target:** `/workspace/sneak_n2/sneak_n2.py`, imported live, SHA-256 `3c61ec2c…bf86`. Cells are 128 bytes, with 16 rounds plus whitening. One round is: XOR rk → S → weave → staff butterfly → shell bridges → bars B0–B4 → S2 → **bar_mix encore**. The blob is `SN2 || nonce(16) || ct(128) || tag(32)`, 179 bytes. `tag = HMAC-SHA256(mac_key, clef || SN2 || nonce || ct)`, and the clef is `StaffSponge(C, seed, 0^16)`, which is never stored. `nonce = SHA-256(clef || encode_block(msg))[:16]`. Decryption checks the tag first, then decodes, then rechecks the SIV nonce. These steps were verified by reading the source; the demo blob matches `hello-world.txt`, and the demo nonce is `b98b9c38…0eb3`.
- **Scope:** Black-box tests of the public API, plus white-box and reduced-round tests that use the known seed and schedule. The raw chosen-plaintext blocks in the reduced-round tests do not need to be encodable messages, so they are not an outsider's oracle.
- **Untouched (checksummed):** the cipher, tests, SPEC, README, render, hello-world and demo-nonce files, PNGs, seed, `attacks/` (the 4-bit snapshot), `attacks_8bit/` (the pre-fix report), `baselines/`, `/workspace/test1`, `test3`, `test13`, `testn1`, `sneak_t1n`, `sneak_v2`–`sneak_v13`, and both `/tmp` legacy snapshots, which were imported read-only with bytecode writing turned off. **309 files were byte-identical before and after** (`protected_verification.txt`). All new work is in `attacks_siv/`. No pictures were drawn, and no fixes or N3 were attempted.

## Verdict

**The full 16-round cipher was not broken.** No plaintext, seed, or clef was recovered, and no fresh MAC forgery was found. This is a negative experimental result, not a proof of security.

How each claimed fix held up:

| Claimed fix | Holds? | Evidence |
|---|---|---|
| Clef in the HMAC closes legacy replay | **Yes** | 2 archived and 5,120 valid old blobs from both earlier versions, plus the 7 earlier wrong-plaintext witnesses, **all failed with `AuthError: tag mismatch`**. There were 0 `DecodeError`s and 0 plaintexts. |
| Encore stops the S2→S per-cell fusion | **Yes for per-cell tables, partly in general** | No next-round S input depends on only one S2 output (minimum is 2). The old fused table disagrees with the live boundary on 1,914 of 1,920 cells. **However,** the encore only mixes within the blocks {0,1,2}, {3,4}, and {5,6,7} of each staff. The fusion therefore moves up to 16-bit and 24-bit super-boxes, and some high-bit differences still cross the encore as a single cell with probability 1 (§4). |
| SIV nonce binds the nonce to the message | **Yes, for the stated goal** | Caller nonces that do not match are always rejected. 200,000 distinct messages gave 200,000 distinct nonces. A key-holder blob that is valid except for a non-SIV nonce gets `AuthError: SIV nonce mismatch` (256 of 256). |
| (Not claimed) dictionary attacks | **Still works, as expected** | With an encryption oracle, `encrypt(guess) == target` recovered **PIN=731 in 732 guesses**. Identical messages produce identical blobs. Without the clef, an offline check is not possible. |

**Diffusion and distinguishers:** the tested signals still appear at **round 2** and were **not detected from round 3**, the same death round as the pre-fix version, though the round-2 signals are weaker (§3). Full byte dependence arrives at **round 3**, not universally at round 2: on the demo schedule, 56 input/output pairs still have no path after two rounds. Only 6 of 17 schedules have full structural coverage at two rounds. All 17 are fully covered at three.

## Scripts

| Script | Output | Coverage |
|---|---|---|
| `attack_integrity_siv.py` | `attack_integrity_output.txt` | Random, `SN2`-prefixed, and real-nonce blobs; all 1,432 bit flips; byte changes; splices; truncation and extension; seedless tags; the tag is checked before `decrypt_grid` |
| `attack_legacy_clef_siv.py` | `attack_legacy_clef_output.txt` | Old blobs from both `/tmp` snapshots, the 7 earlier witnesses, and current blobs fed to old decoders |
| `attack_schedule_siv.py` | `attack_schedule_output.txt` | GF(2) affineness including the clef, the N1 basis predictor, M/K/C separation, and avalanche into keys, S, S2, mac_key, clef, and SIV |
| `attack_rounds_siv.py` | `attack_rounds_output.txt` | DDT and LAT of all 32 boxes; dependency; truncated-differential, integral, chi-bit, LSB, Δ128, and avalanche statistics against round count |
| `attack_dependency_siv.py` | `attack_dependency_output.txt` | Exact structural support with the encore over 17 schedules, empirical coverage at 1, 2, and 3 rounds, and an exhaustive witness for one missing pair |
| `attack_encore_fusion_siv.py` | `attack_encore_fusion_output.txt` | Encore matrix, fusion witnesses, single-cell differences that survive, and the {3,4} super-box DDT against a random baseline |
| `attack_siv_nonce.py` | `attack_siv_nonce_output.txt` | Determinism, nonce distinctness, caller-nonce rejection, PIN dictionary, XOR keystream check, and wrong-nonce stuffing |
| `snapshot_protected.py` | `protected_verification.txt` | Before and after SHA-256 of the 309 protected files |

Each script also saves a `*_results.json`. `common.py` contains a NumPy round accelerator that **includes the encore**. It was checked against live `N.round_enc` on 1,024 states (64 texts × 16 rounds) before any statistic was computed. Instrumentation (counting `decrypt_grid` calls and memoizing the demo-nonce schedule) is in-process monkeypatching only. To reproduce: `cd /workspace/sneak_n2/attacks_siv && python3 attack_<name>.py`.

## 1. Integrity: fresh garbage is rejected

| Test | Result |
|---|---|
| 200,000 random 179-byte blobs | all `AuthError` (nearly all fail at the prefix) |
| 1,000 `SN2` + random nonce, ct, and tag (real schedule each time) | all `AuthError` |
| 10,000 `SN2` + real nonce + random ct and tag | all `AuthError` |
| **All 1,432 single-bit flips** (version 24, nonce 128, ct 1,024, tag 256) | all `AuthError` |
| 3,000 random byte changes each in nonce, ct, and tag | 0 accepted of 9,000 |
| 6 splices between two valid blobs | all `AuthError` |
| Truncations to lengths 0–178; extensions by 1–32 bytes | 0 of 179 accepted; 0 of 32 accepted |
| 20,000 random tags on the real nonce and ct | all `AuthError` |
| 128 structured guesses (tags under a wrong seed, or with a zero clef) | all `AuthError` |
| **Total fresh invalid inputs** | **241,777 `AuthError`, 0 other outcomes, 0 `decrypt_grid` calls** |

The source order was confirmed: the tag `compare_digest` comes before `decrypt_grid`, and the SIV recheck comes after decoding. Only a blob built by the key holder with a valid MAC over a malformed block reaches `DecodeError`, as designed. Random-tag rejection is a sanity check, not a proof of HMAC security.

## 2. Legacy blobs and the clef: the earlier 7-wrong-plaintext flaw is closed

| Legacy input | Current result |
|---|---|
| Archived hello-world, `/tmp/sneak_n2_8bit_precolor2` (old lib decrypts it correctly) | `AuthError: tag mismatch` |
| Archived hello-world, `/tmp/sneak_n2_pre_clef_encore_siv` | `AuthError: tag mismatch` |
| 2,048 valid old blobs per snapshot under one fixed nonce (the same setup that gave 7 wrong plaintexts before); the old library round-tripped 64 of 64 | **2,048 of 2,048 `AuthError`**, for each snapshot |
| 512 valid old blobs per snapshot from the old public `encrypt()` with random nonces | 512 of 512 `AuthError`, for each snapshot |
| The 7 wrong-plaintext witnesses saved by the previous report | **7 of 7 `AuthError`** |
| 256 current blobs per old decoder (the stale-decoder direction) | 512 of 512 `AuthError` |

In total, 5,122 old blobs plus 7 witnesses gave 0 `DecodeError`s and 0 plaintexts. Old and current MAC keys are **still identical** (same `M` domain). The separation rests entirely on the 16-byte secret clef prefix in the HMAC message. Producing an old blob that verifies now would require a fresh HMAC forgery. **No fresh HMAC forgery was attempted or claimed beyond the random and structured guesses in §1.** As a second, independent backstop, the SIV recheck also catches wrong decodes: in §5, a key-holder splice that happened to decode cleanly was rejected as `SIV nonce mismatch`.

## 3. Schedule

- **Not affine.** GF(2) parallelogram tests over the full material (49,664 bits of schedule plus mac_key plus clef = 50,048 bits) had violation fractions of 0.3578–0.3633 for the seed and 0.3571–0.3606 for the nonce, against 0 for an affine map. The clef alone had 54–70 of 128 bits violating across 8 trials.
- **N1 inversion fails.** The affine basis predictor for a fresh seed got **17,963 of 50,048** bits wrong, including **58 of 128** clef bits wrong.
- **Avalanche from one seed-bit flip** (1,024 flips): keys and whitening 49.98%, S tables 49.99%, S2 tables 50.01%, mac_key 49.99%, clef 49.99%, and the hello-world SIV nonce 50.08% (the per-flip range for the 16-byte outputs is 33–66%, which is normal for 128-bit samples).
- **Avalanche from one nonce-bit flip:** keys about 50%, S and S2 about 50%, mac_key 49.83%, and **clef and SIV 0%**, because the clef is seed-only by design. There is one clef for every message.
- **M/K/C separation** at nonce 0^16, the only setting where C could collide: equal byte positions were K/M 14, K/C 13, and M/C 16 of 4,096 (16 expected). The clef does not appear in the K or M streams or in the schedule material, and the mac_key does not appear in the material. Preimages have fixed lengths.

No seed or clef was recovered. The failure of one structural model is not proof that every key-recovery approach fails, and the seed's actual entropy still matters.

## 4. S-boxes, the encore, and fusion

**The S-boxes:** all 32 measured on the demo schedule have DDT max 4/256 and LAT bias 16/256. All are affine-equivalent to SM4, the same family as before.

**The encore matrix** (bar_mix on one staff, mod 256; rows are outputs, columns are inputs):
```
[1 5 0 0 0 0 0 0]
[1 6 1 0 0 0 0 0]
[1 6 2 0 0 0 0 0]
[0 0 0 1 3 0 0 0]
[0 0 0 1 4 0 0 0]
[0 0 0 0 0 2 1 0]
[0 0 0 0 0 3 3 1]
[0 0 0 0 0 2 2 1]
```

- **No per-cell fused S-box remains.** Every row has 2 or 3 nonzero inputs. Across 15 boundaries × 32 contexts × 128 cells, a single S2-output change altered next-round S inputs as follows: 1 input in 169 cases, 2 in 30,633, and 3 in 30,638. Holding x_j fixed and varying one partner cell changed the next-S output for that cell 99.3–99.7% of the time. The old fused formula `S_{r+1}(S2_r(x)^k)` disagrees with the live boundary on **1,914 of 1,920** cells. **The 8-bit fusion and its DDT of 10–18 are gone.**
- **But the encore is block-diagonal.** Its connected blocks are **{0,1,2}, {3,4}, {5,6,7}**, and no bar line ever joins beats 2–3 or 4–5. (This also corrects the earlier description that the five lines "mix every adjacent pair".) So S2 → encore → XOR → S fuses into per-staff **super-boxes** of 24, 16, and 24 bits. The {3,4} 16-bit super-box was computed exhaustively for single-cell input differences (510 differences × 65,536 inputs), at 15 boundaries and 2 faces each. Its DDT max was **16–24 / 65,536**, against a matched random 16-bit permutation baseline of **16–18**. That is near random, and slightly elevated at some boundaries.
- **Single-cell differences can cross the encore.** Six single-cell XOR differences pass with probability 1 as exactly **one** active cell: beat 1 Δ0x80, beat 2 Δ0x80, beat 4 Δ0x40/0x80/0xC0, and beat 5 Δ0x80. The cause is even coefficients mod 256 (for example, 4·0x40 ≡ 0). As a result, the one-active-output fraction in the {3,4} super-box reached up to 0.031, against about 0.0078 for uniform. A differential trail can therefore stay one cell wide across a boundary, at the cost of passing through both S2 and S, each with DDT ≤ 4/256. The encore does **not** guarantee at least two active S-boxes after one active S2.
- **The 2-adic low-bit locality is still there.** The LSBs of output beats **2, 4, 5, and 7** each depend on the LSB of exactly one input cell. The low two bits of beat 4 ignore input 4. The global LSB parity statistics in §5 show no exploitable full-cipher bias.

## 5. Reduced rounds: signals last through round 2 and are not detected from round 3

The demo schedule was used, with 8,192 pairs per round (round 1 / 2 / 3 / 4 / 5 / 8 / 16):

| Metric | R1 | R2 | R3 | R4 | R5 | R8 | R16 |
|---|---|---|---|---|---|---|---|
| Unchanged bytes after a 1-byte Δ (random 0.5) | 100.52 | **1.024 ± 0.025** | 0.499 | 0.496 | 0.490 | 0.500 | 0.500 |
| Avalanche, 1-bit Δ (bits of 1,024) | 109.81 | 509.68 (min 173) | 512.02 | 511.93 | 512.26 | 511.93 | 512.01 |
| Best Δ128 differential / random multiple-search max | 1.0 (zero Δ) / .0068 | .0087 (zero Δ) / .0076 | .0068 / .0070 | .0073 / .0072 | .0072 / .0076 | .0073 / .0072 | .0068 / .0070 |
| 1-byte integral, zero-XOR bytes (64 sets) | 117.0 | **18.11** | 0.53 | 0.52 | 0.55 | 0.39 | 0.47 |
| Stuck bits (out of 65,536 set/bit combinations) | 51,327 | **178** | 0 | 0 | 0 | 0 | 0 |
| 2-byte integral, zero-XOR (8 × 65,536) | 127.75 | **42.38** | 0.625 | 0.75 | 0.125 | 0.625 | 0.375 |

- The chi-bit maximum deviation from round 3 on was 32–36, against 35 for a matched random baseline. The LSB best-of-384 bias was ≤ 0.0102 at every sampled round, under the about-1% familywise threshold of 0.012, and the global parity bias was ≤ 0.0042. No LSB signal was detected, including at round 1.
- **Exact structural dependency** (an upper bound computed with the encore): the demo schedule's minimum inputs per output were 16 / 120 / 128 at 1 / 2 / 3 rounds, with **56 missing pairs at 2 rounds**. Empirical runs with 128 bases match. Exhaustively varying input byte 33 over all 256 values left output byte 5 constant after 2 rounds. Across 17 schedules: 6 had full 2-round coverage, 11 did not (16–88 missing pairs), and **17 of 17 were full at round 3**.
- Compared with the pre-fix 8-bit version: the round-2 signals are **weaker** (unchanged bytes 1.27 → 1.02, 1-byte integral 32.8 → 18.1, 2-byte integral 57.5 → 42.4, stuck bits 216 → 178, sampled minimum avalanche 115 → 173, best round-2 Δ128 0.0233 → 0.0087, about the baseline of 0.0076). The **death round is unchanged at 3**.
- The last-round signals die: at rounds 3–16, none of these tests distinguished the cipher from random at these budgets. That does not mean every distinguisher dies at round 3, and it is not a quantified security margin. No MILP or SAT trail search, boomerang, or key-guessing attack was run.

## 6. SIV nonce, nonce reuse, and dictionary attacks

- **Determinism:** the same seed and message gave an identical blob in **200 of 200** cases. A passive observer can see repeated messages. This is inherent to deterministic authenticated encryption.
- **Distinct nonces:** 200,000 distinct messages gave 200,000 distinct nonces. A 1-bit change in the message changed 44–76 nonce bits (mean 64.46 of 128).
- **Caller nonce:** `encrypt(guess, nonce=target_nonce)` raised `ValueError` for **999 of 1,000** guesses and was accepted only for the true `PIN=731`. Random caller nonces for the true message were rejected 1,000 of 1,000 times. Note that the presence or absence of the `ValueError` is itself an equality oracle, with the same power as comparing blobs.
- **Leftover dictionary attack (demonstrated):** with an encryption oracle, `encrypt(b"PIN=%03d") == target_blob` **recovered PIN 731 in 732 guesses** (13 s). Comparing only the public 16-byte nonce field also works in 732 guesses. Without the seed-derived clef, an offline check is not possible: 2,003 guessed clefs gave 0 matches. **The attacker needs oracle or seed access. This is equality confirmation, not ciphertext-only recovery.**
- **Not keystream reuse:** `ct1⊕ct2 == pt1⊕pt2` held in 0 of 300 pairs, and the mean ciphertext XOR weight was 511.99 of 1,024.
- **Wrong nonce stuffed into a blob:** a wrong or random nonce with the original tag gave 202 of 202 `AuthError: tag mismatch`. As key-holder constructions (not attacks), a correctly encoded hello world under a random non-SIV nonce with a recomputed valid tag gave **256 of 256 `AuthError: SIV nonce mismatch`**. The hello-world ciphertext under a random nonce with a recomputed tag gave 255 `DecodeError` and 1 `SIV nonce mismatch`, so the decode that slipped through was still caught.

## 7. Comparison

| Attack class | N1 (historical) | 4-bit N2 | 8-bit N2 + S2, pre-fix | **Current (clef + encore + SIV)** |
|---|---|---|---|---|
| Fresh invalid ciphertext accepted | about 1/255, no MAC | 0 sampled | 0 / 241,647 | **0 / 241,777** |
| Legacy-blob replay | n/a | different format | **7 / 2,048 wrong plaintexts** | **0 / 5,122; all `AuthError`** |
| GF(2) seed recovery | demonstrated | fails | fails | fails (clef included) |
| Per-cell S2→S fusion | n/a | n/a | yes, DDT 10–18 | **gone**; 16- and 24-bit block super-boxes remain |
| Strongest reduced-round signal | about round 9 | through round 3 | through round 2 | **through round 2 (weaker); not detected from round 3** |
| Full byte dependency | slow | round 3 | round 3 (demo) | **round 3** (6 of 17 schedules at round 2) |
| Nonce reuse / dictionary | remains | remains | PIN in 732 with a fixed nonce | **PIN in 732 via a deterministic oracle**; arbitrary nonce reuse closed |

Historical N1 and 4-bit numbers are quoted from untouched reports and were not rerun.

## 8. Remaining issues (not fixed here, by instruction)

1. Deterministic encryption: identical messages are linkable, and anyone with an encryption oracle can confirm guesses (shown with the PIN).
2. The encore only mixes within the {0,1,2}, {3,4}, and {5,6,7} blocks. Beats 2–3 and 4–5 are never joined by any bar line. The probability-1 single-cell high-bit differences and the single-input LSB rows are leftover structure from the mod-256 linear layers.
3. All S-boxes are still affine-equivalent to SM4. There is no rigorous bound on active S-boxes or trails.
4. There is a white-box distinguisher at 2 rounds on most schedules. Full diffusion arrives only at round 3.
5. The MAC key is shared across versions, and version separation rests on the clef alone. There is still no explicit version or algorithm identifier in the transcript beyond `SN2`.
6. The full schedule (about 17 ms) is built before the tag is checked on any correctly framed blob, which leaves a CPU-cost asymmetry. Only the HMAC comparison is constant-time. No side-channel or DoS testing was done.
7. The SIV nonce is a truncated `SHA-256(clef || block)` rather than HMAC. With a fixed 144-byte input and a 16-byte truncation, no length-extension issue was found, but it is homemade.

**The full 16-round cipher was not broken by these scripts. That is not a claim of safety, a proof, or a full review. Do not use it for real secrets; use AES-GCM-SIV, age, or libsodium.**
