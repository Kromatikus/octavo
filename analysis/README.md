# In-house analysis of live Octavo (2026-11-21)

This folder holds three lab reports on the current 16-round cipher. The cipher itself was not changed: `sneak_n2.py` is still SHA-256 `19181bc1623115c075dc5dee25edec388f5413466777d47b7f19fa66d1e71eee`. Nothing here was a proof of security, and no outside cryptanalyst has reviewed this work.

## Results

| Study | What it did | Headline |
|---|---|---|
| [Reduced-round tests (OCT-2)](reduced_round/REPORT.md) | Empirical distinguishers at whole-round and mid-round checkpoints: diffusion, differential, linear, integral/square, algebraic/cube, and single-shell mixing | **No distinguisher past about 0.5 of 16 rounds.** Full diffusion in 1 round. Differential, integral and cube tests reached 0.5 round (often only after peeling the last unkeyed mix); linear tests were already at noise by 0.5 round. A difference confined to one shell mixed fully after the first cross-staff mix (~0.4 round). |
| [Automated trail search (OCT-3)](trail_search/REPORT.md) | Byte-level truncated CP-SAT model (OR-Tools) of differential and linear trails, one sampled key schedule | **Proved active S-box lower bounds: 12–15 per round** (depending on the round), **31 differential / 28 linear for 2 rounds**, and (by adding those bounds) **43/40 for 3 rounds and 55/52 for 4 rounds**. A path cannot stay in one shell, even for one round. |
| [Extra trail-search checks (OCT-4)](trail_checks2/REPORT.md) | More key schedules, a longer 2-round proof attempt, clustering, and credit for the bow and the triplets | **20 points still have a 1-round minimum of 12 (median 14).** The 2-round bounds stay at **31/28** (not closed). Clustering is about **1–1.2 bits per active S-box**. The bow gives differential credit (4-round bound **346 bits**; linear none). The triplets give no credit. The 2^-256 margin is about **9–10 of 16 rounds**; the strict 2^-1024 target still falls short. |

The 2-round trail-search runs hit a time cap, so the 2-round figures are proved lower bounds (not necessarily tight), and the 3- and 4-round figures are those bounds added together. The cheapest realisable 1-round paths found were costlier still (20 differential / 18 linear active S-boxes).

Using the usual +1–2 rounds for key recovery, the reduced-round tests leave a margin of at least 13.5 of 16 rounds empirically, or at least 11 from earlier trail math. After the extra checks, the solver-backed 256-bit margin is about 9–10 of 16 rounds (10 on a single trail with bow credit; 9 after a 1.2-bit clustering haircut). A much stricter 2^-1024 target is an extrapolation only, and under the cautious numbers it falls short of 16 rounds.

## Extra trail-search checks (OCT-4)

A follow-up, in [`trail_checks2/`](trail_checks2/REPORT.md), re-ran the OCT-3 trail model on more keys and measured clustering, the bow and the triplets. The cipher was not changed.

- **More key schedules:** 20 key-and-round points (16 new plus OCT-3's 4). The 1-round minimum was **12** everywhere (median 14). Nothing dipped below 12.
- **2-round proof:** still **31 differential / 28 linear**. The longer runs did not close, so the 3- and 4-round figures remain summed bounds (43/40 and 55/52).
- **Clustering:** summing paths on a small measurable piece costs about **1–1.2 bits per active S-box** (AES is about 1.4). There was no sign of a large S-box-level truncated cluster.
- **The bow:** sound differential credit (1 to 4.25 bits per active stroke). The 4-round single-trail differential bound rises from 330 to **346 bits**. Linear attacks get no credit (one pattern passes through free).
- **The triplets:** no sound credit (some differences and masks pass with certainty).
- **Margins:** against the meaningful 2^-256 target (the schedule and tag are SHA-256-based), the margin is about **9–10 of 16 rounds** after +2 rounds for key recovery. The strict 2^-1024 target still **falls short** under the cautious numbers. Fixing that would mean more rounds or stronger mixing, which is N3 and still on hold.

## Caveats

- Tests and the solver used **sampled key schedules** and modest sample sizes. Weak biases could hide. The 1-round minimum was checked at 20 points and stayed at 12–15 (median 14); other keys could still differ.
- The trail bounds are for **single truncated trails**, not differentials or linear hulls. Clustering was measured at about 1–1.2 bits per active S-box on a small piece; real erosion over many rounds could differ. The model is still conservative in other ways (worst-case S-box transitions; no credit for the triplets; linear attacks get no bow credit).
- **Timeouts and sums:** 2-round searches were not solved to optimality. 3- and 4-round numbers are additive; 5–16 rounds are an explicit extrapolation.
- **Not tested:** boomerang, impossible or truncated-differential distinguishers, division property, related-key, side channels, and (in the reduced-round work) automated trail search — that last item is OCT-3.
- In the real API each message gets a fresh schedule, so an attacker sees far fewer texts per schedule than these lab tests allow.

## Honest verdict

Octavo is still homemade. A negative result or a truncated-trail bound is not a proof of security. For real secrets use AES-GCM-SIV, age, or libsodium.

## How to run

From the repository root:

    python3 analysis/reduced_round/harness.py

That is a short sanity check: it loads `sneak_n2.py` (and refuses to proceed if the SHA pin does not match), then round-trips 1, 2, 4 and 16 rounds. The longer OCT-2 stage scripts, the OCT-3 solver and the OCT-4 extra-check scripts live next to the reports. The trail-search solver needs OR-Tools and NumPy; re-running those searches can take many minutes per instance. The OCT-4 C helpers (`bow_tables.c`, `markov2.c`, `superbox.c`) have to be compiled if you want to re-run those stages; the compiled binaries were not checked in.

## Lab paths and packaging

These reports and progress logs were written in the lab folders `/workspace/reduced_round_octavo`, `/workspace/trail_search_octavo` and `/workspace/trail_checks2_octavo`, targeting `/workspace/sneak_n2/sneak_n2.py`. Paths in the reports, `PROGRESS.md`, and any recorded outputs are historical and were left as written. The scripts in this tree now find `sneak_n2.py` and the sibling analysis folders (`reduced_round`, `trail_search`) relative to themselves, and still pin the SHA above.

`analysis/` is kept in the repository for the record. It is **not** listed in `MANIFEST.in`, so it is not part of the `octavo-demo` source distribution — the same choice as the in-house `attacks_*/` folders. The sdist stays a small install of the demo cipher, the spec, the score, and the independent checker.
