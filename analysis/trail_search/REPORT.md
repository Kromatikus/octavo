# OCT-3 — Automated trail search on live Octavo (NR = 16)

Date: Sat Nov 21, 2026 (ET). Target: `/workspace/sneak_n2/sneak_n2.py`, SHA-256 `19181bc1623115c075dc5dee25edec388f5413466777d47b7f19fa66d1e71eee`
(read-only; asserted on every import through OCT-2's `harness.py`; re-checked at the end: unchanged). OCT-2 files reused read-only with
`PYTHONDONTWRITEBYTECODE=1`. No live, frozen or older-folder file was modified; nothing pushed or posted; no picture; no N3 work.
Solver: OR-Tools 9.15 CP-SAT (already installed). Every run was time-capped; timeouts are recorded as best-found, not proofs.

## Model (Stage 0–1)
- Byte-level truncated model of one live round (SPEC R3/R4 + `octavo_np.py`, which is bit-exact vs live): 6 S-box layers per round
  (S 128, B0 Latin 32, odd restack 128, S2 128, encore B0 32, encore odd 128 = 576 S-boxes) and the linear/ARX layers between them.
- Exact byte branch numbers, matrices extracted from `octavo_np` and checked GF(2^8)-linear: mix2 = 3, all six bars = 3 (exhaustive),
  face butterfly = 6, bar chain B1..B4 = 3, cross_staff_mix per beat = 6 (matches the earlier report).
- Truncated rules are all **sound**: every real trail satisfies them, so solver minima are valid **lower bounds**. Triplets (Z/256) and the bow
  (ARX) are treated as structure-only bijections and get no probability credit. Keyed wiring (weave, σ, bridge) comes from one sampled lab
  schedule (schedule 0, rounds 0–3).
- Stage 1b/2b: exact truncated transition tables for the face butterfly and bar chain (validated on 16,000 random vectors and 136 witnesses)
  plus exact GF(2^8) cuts on the first linear stretch. Valid, but CP-SAT solved them more slowly, so the proved numbers below come from the per-op model.

## Results — minimum active S-boxes (schedule 0)

| Rounds | Differential: proved / best found | Linear: proved / best found | How proved |
|---|---|---|---|
| 1 (round 0) | **15** / 15 per-op; 20 exactly-realisable on stretch 1 | **15** / 15 per-op; 18 realisable on stretch 1 | CP-SAT OPTIMAL |
| 1 (rounds 1, 2, 3) | 13, 12, 12 | 13, 12, 12 | CP-SAT OPTIMAL |
| 2 (rounds 0–1) | **31** / 38 | **28** / 32 | diff: CP-SAT bound (900 s timeout); lin: sum of proved 1-round minima (solver lb 22 in 600 s) |
| 3 (rounds 0–2) | **43** | **40** | additive: 2-round bound + 1-round minimum (no solver run) |
| 4 (rounds 0–3) | **55** | **52** | additive (no solver run) |

The additive split is a proof under the model: every round of a nonzero trail has a nonzero input, so it costs at least that round's minimum.
"Best found" values are per-op trails; the spot check (Stage 5) shows such trails can be unrealisable, so the true minima are likely higher.

## Probability / correlation bounds (keyed S-box: DP ≤ 2^-6, |corr| ≤ 2^-3)

| Rounds | Diff trail EDP ≤ | Linear trail \|corr\| ≤ (ELP) |
|---|---|---|
| 1 | 2^-90 (2^-72 for the weakest round seen) | 2^-45 (2^-90) |
| 2 | 2^-186 | 2^-84 (2^-168) |
| 3 | 2^-258 | 2^-120 (2^-240) |
| 4 | 2^-330 | 2^-156 (2^-312) |

- **2^-256 level** (the relevant one: the schedule and tag are SHA-256-based, so 256-bit security is the ceiling): proved passed at
  **3 rounds (diff) and 4 rounds (linear)**. Adding the usual +2 rounds for key recovery gives about 6 attackable rounds, so a **margin of ~10 of 16 rounds**.
- **2^-1024 level** (full codebook of the 1024-bit block, a very strict target): **extrapolation only**. Assuming ≥ 12 active per extra round
  (the weakest proved single round; not proved for rounds 4–15 or other schedules), the bound passes 2^-1024 at **about 14 rounds**
  (2-round × floor(R/2) gives 12–14). At 16 rounds the extrapolated count is about 196–199 active (≈ 2^-1176). That is a thin margin (~2 rounds, ~0 after key recovery) at this strict level.

## Single-shell trails (Stage 4)
- Fully confined to one shell at every step: **impossible** (INFEASIBLE, diff and linear, 1 round). The weave and the shell bridges force the other shell.
- Input confined to one shell: R=1 minimum 15 (diff and lin, both shells), the same as unrestricted. R=2: no lower than the unrestricted bounds
  (best found 38 diff / 32 lin). **No single-shell weakness found.**

## Stage 5 spot check
The optimal 1-round per-op trail (4 → 4 active through S-out → weave → butterfly → bridges) has an **empty** GF(2^8) solution space.
So it is not a real trail, and the per-op model is loose (conservative). With exact tables, the best trail found that is realisable on that stretch had 20 (diff) / 18 (lin) active S-boxes.

## Comparison with OCT-2
- OCT-2 estimate: ≥ 4 active per round, so 2^-24 per round. **Solver-backed now: 12–15 per round** (2^-72 to 2^-90), and 31/43/55 for 2/3/4 rounds.
- The earlier relaxed bound was (2R−1)·6+2 = 20/32/44 for R = 2/3/4. The new proved values are higher: 31/43/55 diff and 28/40/52 linear.
- OCT-2 empirical: nothing past ~0.5 round. This is consistent.

## Caveats
1. **Truncated, key-independent S-boxes:** assumes any nonzero transition at worst-case DP/|corr|. It ignores keyed-S-box specifics, and gives the triplets and bow no credit (both conservative).
2. **Trails, not differentials or linear hulls:** clustering and hull effects can make real probabilities larger than a single-trail bound.
3. **Per-schedule wiring:** one sampled schedule, rounds 0–3. Other schedules and rounds have different weave and bridge wiring (the per-round minimum already varied from 12 to 15).
4. **Timeouts:** R=2 was not solved to optimality. R=3/4 come from additive decomposition, and 5–16 rounds are an explicit extrapolation.
5. **Per-schedule key model:** in the real API each message gets a fresh schedule, so an attacker sees far fewer texts per schedule than these bounds allow.
6. Not covered: boomerang, impossible/truncated-differential distinguishers, division property, related-key, side channels.

## Files
`PROGRESS.md`, `model.py`, `lincut.py`, `solve.py`, `solve_cuts.py`, `stage1_branch.py` (+output/json), `stage1b_table_check.py` (+output),
`stage5_spotcheck.py` (+output/json), `queue_stage34.sh`, `runs/*.json`, `logs/*.log`.

## Honest verdict
Octavo is still homemade. A solver-backed lower bound on truncated trails is good news, but it is not a full proof of security, and no outside cryptanalyst has reviewed it.
For real secrets use AES-GCM-SIV, age, or libsodium.
