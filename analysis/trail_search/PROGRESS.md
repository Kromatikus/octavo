# OCT-3: automated trail search on live Octavo — PROGRESS

Target: /workspace/sneak_n2/sneak_n2.py, read-only, SHA-256 19181bc1…1eee (asserted on import via OCT-2 harness.py; checked at start: unchanged).
Reuses /workspace/reduced_round_octavo (harness.py, octavo_np.py) read-only, with PYTHONDONTWRITEBYTECODE=1 so nothing is written there.
Solver: OR-Tools 9.15 CP-SAT (already installed; no pip needed). 8 cores, ~3 GB free RAM -> 4 workers per run, caps 5–15 min.

## Stage 0 — truncated model (model.py) — DONE
Source of truth: SPEC.md R3/R4 + octavo_np.py (bit-exact vs live on 96 cases). One round, byte level (128 bytes, byte 8f+t):
  S (128 S-boxes) -> weave (keyed byte permutation) -> butterfly (3 layers of field mix2 per face, keyed sigma) -> 64 shell bridges (mix2)
  -> per face: B0 Latin pair (mix2 + S, S2: 2 S-boxes) , B1..B4/M2/M3 field 2x2 MDS mixes, T0..T5 Z/256 3x3 (det 1), 7 bow ARX strokes,
     odd restack (4 Latin pairs = 8 S-boxes) -> cross_staff_mix (4 layers of mix2 per beat column)
  -> S2 (128) -> same pass again (encore).  S-box layers per round: 128+32+128+128+32+128 = 576.
Truncated rules (all sound, i.e. every real trail satisfies them -> min is a valid LOWER bound):
  - 2x2 MDS field mix (mix2 and the 6 bars): active count of {u,v,u',v'} is 0 or >=3.
  - butterfly per face: in+out active >= 6 or 0 (exact branch, Stage 1); cross per beat column: >= 6 or 0 (exact, Stage 1).
  - Latin pair: mix2 rule, and both outputs count as S-boxes.
  - Triplets (Z/256, not XOR-linear): bijection (some in active <=> some out active); diff only: a single active input with
    an odd coefficient forces that row's output active (and the same with the inverse matrix); inverse-zero-coefficient rule.
  - Bow stroke: diff: pressure byte unchanged; with p inactive, u'=u+rot(v), v'=v^rot(u') (one active => result active);
    with p active anything. Linear: (u,v) mask zero <=> (u',v') mask zero; p mask may change only if (u,v) active.
Assumptions: (1) keyed S-boxes are bijective and only counted (DP<=2^-6, |corr|<=2^-3 per box, measured in OCT-2);
 (2) keyed permutations (weave SH/SV, sigma, bridge) are taken from sampled lab schedules -> bounds are per sampled schedule;
     sigma does not change butterfly branch numbers; weave/bridge do change wiring, so several schedules are checked;
 (3) bow/triplets treated as structure-only nonlinear maps (no probability credit) -> conservative;
 (4) per-op truncated rules allow cancellations that may not be realisable -> bound may be loose (low), never too high.

## Stage 1 — branch numbers (stage1_branch.py) — DONE
Matrices extracted from octavo_np functions and GF-linearity verified on random vectors. Results (stage1_output.txt):
  mix2 = 3; all six bars = 3 (exhaustive 65,536 inputs); butterfly per face (8x8) = 6 exact; bar chain B1..B4 (7x7) = 3 exact;
  cross_staff_mix per beat (16x16) = 6 exact (per-op lower bound 6 = witness upper bound 6; matches the earlier report's 6).

## Stage 2 — differential
- R=1, schedule 0: OPTIMAL 15 active S-boxes (107 s). Input 6 active bytes; per layer [S,B0,odd,S2,B0',odd'] = [6,1,4,2,0,2].
- Per-op model (OCT_EXACT=0; mixes per op + exact branch numbers 6 for butterfly/cross) — all OPTIMAL unless noted:
  R=1 rounds 0/1/2/3 of schedule 0: 15 / 13 / 12 / 12 active S-boxes.   R=2 (rounds 0-1): timeout 900 s, best found 55, PROVED >= 31.
- Stage 5 (done early): the optimal 1-round per-op trail is NOT realisable: its first linear stretch (S out -> weave -> butterfly -> bridges,
  4 active -> 4 active) has an empty GF(2^8) solution space. So per-op numbers are valid but loose lower bounds.
- Tightening (Stage 2b): exact truncated transition tables for each face butterfly (13,300 allowed support pairs) and the B1..B4 bar chain
  (1,873), computed by GF(2^8) kernels and validated against octavo_np (stage1b_output.txt: 0/16,000 violations; 136/136 witnesses),
  plus lazy exact cuts on stretch 1 (solve_cuts.py). Harder for the solver: first try reached lb 13 / best 43 in 300 s.
- 6:13 PM ET interruption. Exact-table runs so far (900 s caps, no proof): diff R=1 best 42, lb 13 (interrupted in iteration 2);
  lin R=1 best 18 with a stretch-1-realisable trail, lb 13. (lb below the per-op 15 only because the table model is harder to solve;
  the exact model is a restriction of the per-op one, so >= 15 still holds and is now passed in as --lb.)
- 6:20 PM ET: final Stage 2b capped runs (600 s): exact diff R=1 (--lb 15) and exact diff R=2 (--lb 31).
- Stage 2b result (600 s caps, timeouts): exact diff R=1: proved >= 15, best found 20 (stretch 1 exactly realisable, input 2 bytes,
  round output 76 active). Exact diff R=2: proved >= 31 (no improvement over per-op), best found 141 (stretch-1 pattern not realisable,
  2 cuts added). Exact tables make CP-SAT slower, so the proved numbers still come from the per-op model. Stage 2b DONE.
- Stage 3/4 queue started (queue_stage34.sh, per-op model): lin R=2 600 s; single-shell R=1 diff/lin inner/outer; fully confined R=1; single-shell R=2.
## Stage 3 — linear (per-op) — DONE
  R=1 rounds 0/1/2/3: 15 / 13 / 12 / 12 (all OPTIMAL). R=2: timeout (785 s incl. presolve), solver lb 22, best 38;
  additive bound from proved per-round minima gives >= 15+13 = 28 (sound: every round of a trail has a nonzero input).
  Exact-table lin R=1 (900 s): best 18 with a stretch-1-realisable trail, lb 13 (< per-op 15, solver weakness).
## Stage 4 — single shell (per-op) — DONE
  Input confined to inner or outer shell, R=1: diff 15/15, lin 15/15 (OPTIMAL) = same as unrestricted round 0, no weakness.
  Fully confined (other shell inactive after every step), R=1, diff and lin: INFEASIBLE (proved instantly; weave and bridges force the other shell).
  Input in inner shell, R=2 (300 s): diff lb 23 best 38; lin lb 27 best 32. Proved bounds fall back to the unrestricted ones (>=31 / >=28),
  since single-shell-input trails are a subset. Their best-found trails also cap the unrestricted R=2 optimum: diff <= 38, lin <= 32 (per-op model).
## Decision: no R=3/R=4 solver runs (R=2 did not solve in 10 min). Multi-round numbers use additive decomposition (proved) + extrapolation (labelled).
## Stage 6 — REPORT.md written (proved: diff 15/31/43/55, lin 15/28/40/52 for R=1..4 of schedule 0; 2^-256 passed at 3–4 rounds;
   2^-1024 ≈ 14 rounds by labelled extrapolation). ALL STAGES DONE.
