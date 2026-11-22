# OCT-4 — Extra checks on the Octavo trail search (follow-up to OCT-3)

Date: Sat Nov 21, 2026 (ET). Folder: `/workspace/trail_checks2_octavo`. Builds on `/workspace/trail_search_octavo` (OCT-3, read-only).
Target `/workspace/sneak_n2/sneak_n2.py`, read-only, SHA-256 `19181bc1623115c075dc5dee25edec388f5413466777d47b7f19fa66d1e71eee`, checked at start and end: unchanged.
`model.py` and `lincut.py` are byte-identical copies of OCT-3's; OCT-2's `octavo_np.py` (bit-exact against live) was imported read-only with
`PYTHONDONTWRITEBYTECODE=1`. No cipher change, no frozen snapshot or older folder touched, no picture, no push, no post.
Solver: OR-Tools 9.15 CP-SAT, per-op truncated model (the one behind OCT-3's proofs). Every run was capped, and timeouts are recorded as timeouts.

## 1. More key schedules (Stage 1): no round below 12
Eight new lab schedules (seed 20261122) at two round positions each, covering all 16 round indices, 1 round, differential and linear (32 runs, all OPTIMAL).

| Min active S-boxes in 1 round | 12 | 13 | 14 | 15 |
|---|---|---|---|---|
| New points (16) | 1 | 4 | 10 | 1 |
| With OCT-3's 4 points (20) | 3 | 5 | 10 | 2 |

Overall minimum **12** (median 14). **Nothing dipped below 12.** The linear and differential minima were equal at every point.
(A first try with 2 solver workers produced no bounds and was discarded: `runs/stage1_try1_2workers/`.)

## 2. Longer 2-round proof (Stage 2): did not close
Differential R=2 (`--lb 31`, `obj <= 38`) and linear R=2 (`--lb 28`, `obj <= 32`), 4 workers each, 2700 s cap. Both stopped together after 2083 s
(most likely an outside stop signal, since both runs ended in the same second) with status UNKNOWN. No trail was found and the bound didn't rise. **The proved values stay at diff ≥ 31 and lin ≥ 28**
(best known 38 / 32 from OCT-3). R=3 was not run because R=2 never finished OPTIMAL. The 3- and 4-round numbers are still sums of proved pieces.

## 3. Clustering (Stage 3)
- **Markov sum on the smallest two-S-layer piece** (S,S → Latin pair, real keyed S-boxes, 2 schedules; `markov2.c`, `runs/stage3_markov.txt`).
  Summing every characteristic: max EDP 2^-15.2 vs best single characteristic 2^-18, a gain of 2.6–3.6 bits. Linear ELP: 2^-15.1 vs 2^-18, a gain of 2.6–2.9 bits.
  Over the 3 active S-boxes that is **about 1–1.2 bits of erosion per active S-box** (partly a floor effect: 2^-16 is the floor for a 16-bit piece).
  For comparison, AES's proved 4-round MEDP (≈1.88·2^-114) vs its single-trail bound (2^-150) is about **1.4 bits per active S-box**.
- **Fixed-key exact on the same piece** (`superbox.c`, 4 schedule/round points): max DP 2^-11.7, max |corr| 2^-5.2, the random-16-bit-permutation level.
  It shows the piece behaves like a random permutation, but it's too small to measure erosion. There is no key between S-layers inside a round, so the
  Markov assumption behind every trail bound isn't literally true there.
- **Truncated-trail counts** (`stage3_count.py`, schedule 0 round 2, the 12-S-box optimum with its input/output patterns fixed, 150 s per level, incomplete).
  At least 183,726 / 213,295 / 180,883 truncated trails were found at 12 / 13 / 14 active S-boxes, but they use only **1 / 3 / 1 distinct sets of active S-boxes**.
  The huge counts come from free (non-S-box) intermediate bytes, while the S-box-set cluster factor is only ≈1.05. These are per-op patterns, many of them
  not realisable (OCT-3 Stage 5). The linear run at the same point: ≥ 121,940 / 261,720 / 272,345 trails, but 1 / 1 / 1 S-box sets (factor ≈1.02).
  So there is no sign of a large S-box-level cluster at the truncated level (counts incomplete; third point stopped to save time).
- **Cautious working figure:** count each active S-box as about **4.8 bits** instead of 6 (1.2 bits of erosion), or 4.6 bits if AES-like erosion applies.

## 4. Credit for the triplets and the bow (Stage 4)
- **Triplets (Z/256 3×3, det 1): no sound credit.** Exact: MSB differences {0,0x80}^3 pass with DP = 1, and LSB masks pass with |corr| = 1, on 7 of 49 support patterns
  (M mod 2 is invertible). At least 23 patterns have |corr| ≥ 1/2. Typical random behaviour is weak (row max DP ~2^-10.5, |corr| ~2^-8.5), but the worst case is what bounds count.
- **Bow ARX strokes: exact tables** (`bow_tables.c`, checked against octavo_np in `runs/stage4_bow_verify.json`, with the pressure byte uniform and its difference/mask zero).
  Differential: 1 to 4.25 bits per active stroke (best: uv→u' DP 2^-1; u→uv' 2^-2.68). Linear: v→u'v' has |corr| = 1 (parity is kept by rotation), so **linear gets nothing**.
  Strokes whose pressure byte is active get 0 credit (sound).
- **Probability-weighted 1-round minima** (`solve4.py`, S-box 6 bits, bow weights floored to 0.1 bit):

| Point | Diff weight (bits), bow credited | Diff, S-boxes only | Lin ELP weight (bits) |
|---|---|---|---|
| sched 0 round 0 | 94 (15 S + 4.0 bow) | 90 | ≥ 90 (timeout, 15 active) |
| sched 0 round 1 | 88 (13 S + 10.0) | 78 | 78 |
| sched 0 round 2 | 80 (12 S + 8.0) | 72 | 72 |
| sched 0 round 3 | 80 (12 S + 8.0) | 72 | 72 |
| new sched 2 round 11 (a 12-point) | 80 (12 S + 8.0) | 72 | 72 |

So the differential 1-round floor rises from 72–90 to **80–94 bits**. Linear stays at 72–90.

## 5. Updated bound table (schedule 0, rounds 0–3; per-op model; S-box DP ≤ 2^-6, |corr| ≤ 2^-3)

| Rounds | Diff active S-boxes, proved / best | Diff weight, proved (with bow) | Lin active, proved / best | Lin ELP weight, proved |
|---|---|---|---|---|
| 1 | 12–15 (20 points; ≥ 12 everywhere) | 80–94 | 12–15 | 72–90 |
| 2 | 31 / 38 (not closed) | 186 | 28 / 32 | 168 |
| 3 | 43 (sum) | 266 (186 + 80) | 40 (sum) | 240 |
| 4 | 55 (sum) | 346 | 52 (sum) | 312 |

The 3- and 4-round values are sums of proved pieces (each round of a nonzero trail costs at least that round's minimum). The 2-round weight uses the
larger of 31×6 and 94+88.

## 6. Margins vs 16 rounds (key recovery counted as +2 rounds)

| Level | Assumption | Diff passes at | Lin passes at | Attackable (+2) | Margin |
|---|---|---|---|---|---|
| 2^-256 | single trail (6 bits/S-box, bow credit) | 3 rounds (266) | 4 rounds (312) | 6 | **10** |
| 2^-256 | clustering haircut 1.2 bits/S-box | 4 rounds (~280) | 5 rounds (~307, round 5 extrapolated at 12 active) | 7 | **9** |
| 2^-1024 | single trail, extrapolated at 80 / 72 bits per extra round | 13 | 14 | 15–16 | **0–1** |
| 2^-1024 | with the 1.2-bit haircut (~66 / ~58 bits per extra round) | ~16 | ~18 | 18–20 | **none (falls short)** |

256 bits is the meaningful target, because the key schedule and tag are SHA-256-based. Against it Octavo keeps a **9–10 round margin** under these models.
At the strict 2^-1024 level, the cautious numbers **don't clear 16 rounds**. That stays a known thin spot and would need N3 (more rounds or a stronger mixing layer), which is on hold.

## 7. What improved vs OCT-3
- The per-round floor of 12 now holds across 20 schedule/round points instead of 4.
- The bow is credited soundly: the differential 1-round floor goes from 72 to 80 bits, and the 4-round single-trail bound from 330 to 346 bits.
- Clustering now has a number (≈1–1.2 bits per S-box on a measurable piece, with no large S-box-level truncated cluster seen) instead of an open caveat.
- The triplets are settled: they deserve no credit.
- Not improved: the 2-round proof (still 31 / 28).

## 8. Caveats
1. These are **model bounds** (truncated, Markov/independent-key, worst-case S-box), not proofs of security. There is no key between S-layers inside a round.
2. The 2-round search did not close, so 3 and 4 rounds are sums, and beyond 4 rounds is extrapolation.
3. The clustering figure comes from a 16-bit piece near its floor plus incomplete truncated counts. Real erosion over many rounds could differ.
4. Schedules are sampled (21 schedules × a few rounds in total, not all keys). The weighted bounds were computed on 5 points.
5. The bow credit assumes a uniform, independent pressure byte. Strokes with an active pressure byte get no credit.
6. Not covered: boomerang, impossible / truncated differential distinguishers, division property, related-key, side channels.

## Files
`PROGRESS.md`; Stage 1 `solve2.py`, `stage1_run.sh`, `stage1b_run.sh`, `runs/*_R1_seed20261122_*.json`; Stage 2 `stage2_run.sh`, `runs/*_R2_*.json`;
Stage 3 `superbox.c`, `stage3_superbox.py`, `markov2.c`, `stage3_markov.sh`, `stage3_count.py`, `stage3a_run.sh`, `runs/stage3_*`, `runs/count_*`;
Stage 4 `bow_tables.c`, `stage4_bow_verify.py`, `stage4_triplets.py`, `model4.py`, `solve4.py`, `runs/stage4_*`, `runs/w_*.json`; `logs/`.

## Honest verdict
Octavo is still homemade. These are model bounds from our own solver runs, not proofs of security, and no outside cryptanalyst has reviewed them.
For real secrets use AES-GCM-SIV, age, or libsodium.
