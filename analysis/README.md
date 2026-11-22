# In-house analysis of live Octavo (2026-11-21)

This folder holds two lab reports on the current 16-round cipher. The cipher itself was not changed: `sneak_n2.py` is still SHA-256 `19181bc1623115c075dc5dee25edec388f5413466777d47b7f19fa66d1e71eee`. Nothing here was a proof of security, and no outside cryptanalyst has reviewed this work.

## Results

| Study | What it did | Headline |
|---|---|---|
| [Reduced-round tests (OCT-2)](reduced_round/REPORT.md) | Empirical distinguishers at whole-round and mid-round checkpoints: diffusion, differential, linear, integral/square, algebraic/cube, and single-shell mixing | **No distinguisher past about 0.5 of 16 rounds.** Full diffusion in 1 round. Differential, integral and cube tests reached 0.5 round (often only after peeling the last unkeyed mix); linear tests were already at noise by 0.5 round. A difference confined to one shell mixed fully after the first cross-staff mix (~0.4 round). |
| [Automated trail search (OCT-3)](trail_search/REPORT.md) | Byte-level truncated CP-SAT model (OR-Tools) of differential and linear trails, one sampled key schedule | **Proved active S-box lower bounds: 12–15 per round** (depending on the round), **31 differential / 28 linear for 2 rounds**, and (by adding those bounds) **43/40 for 3 rounds and 55/52 for 4 rounds**. A path cannot stay in one shell, even for one round. |

The 2-round trail-search runs hit a time cap, so the 2-round figures are proved lower bounds (not necessarily tight), and the 3- and 4-round figures are those bounds added together. The cheapest realisable 1-round paths found were costlier still (20 differential / 18 linear active S-boxes).

Using the usual +1–2 rounds for key recovery, the reduced-round tests leave a margin of at least 13.5 of 16 rounds empirically, or at least 11 from earlier trail math. The solver-backed 256-bit trail bound is crossed after 3 rounds (differential) or 4 (linear), which leaves a margin of about 10 of 16 after +2 rounds for key recovery. A much stricter 2^-1024 target would be an extrapolation only, and would leave only a thin margin.

## Caveats

- Tests and the solver used **one (or a few) key schedules** and modest sample sizes. Weak biases could hide. Other schedules have different weave and bridge wiring; the 1-round minimum already varied from 12 to 15.
- The trail bounds are for **single truncated trails**, not differentials or linear hulls. Many paths adding up together could make the real odds better for an attacker. The model is conservative in other ways (worst-case S-box transitions; no credit for the triplets or the bow).
- **Timeouts and sums:** 2-round searches were not solved to optimality. 3- and 4-round numbers are additive; 5–16 rounds are an explicit extrapolation.
- **Not tested:** boomerang, impossible or truncated-differential distinguishers, division property, related-key, side channels, and (in the reduced-round work) automated trail search — that last item is OCT-3.
- In the real API each message gets a fresh schedule, so an attacker sees far fewer texts per schedule than these lab tests allow.

## Honest verdict

Octavo is still homemade. A negative result or a truncated-trail bound is not a proof of security. For real secrets use AES-GCM-SIV, age, or libsodium.

## How to run

From the repository root:

    python3 analysis/reduced_round/harness.py

That is a short sanity check: it loads `sneak_n2.py` (and refuses to proceed if the SHA pin does not match), then round-trips 1, 2, 4 and 16 rounds. The longer OCT-2 stage scripts and the OCT-3 solver live next to the reports. The trail-search solver needs OR-Tools and NumPy; re-running those searches can take many minutes per instance.

## Lab paths and packaging

These reports and progress logs were written in the lab folders `/workspace/reduced_round_octavo` and `/workspace/trail_search_octavo`, targeting `/workspace/sneak_n2/sneak_n2.py`. Paths in the reports, `PROGRESS.md`, and any recorded outputs are historical and were left as written. The scripts in this tree now find `sneak_n2.py` (and, for the trail search, `analysis/reduced_round`) relative to themselves, and still pin the SHA above.

`analysis/` is kept in the repository for the record. It is **not** listed in `MANIFEST.in`, so it is not part of the `octavo-demo` source distribution — the same choice as the in-house `attacks_*/` folders. The sdist stays a small install of the demo cipher, the spec, the score, and the independent checker.
