# OCT-4: extra checks on the OCT-3 trail search — PROGRESS

Started Sat Nov 21, 2026, ~7:10 PM ET. Builds on /workspace/trail_search_octavo (OCT-3, read-only).
Target /workspace/sneak_n2/sneak_n2.py read-only, SHA-256 19181bc1623115c075dc5dee25edec388f5413466777d47b7f19fa66d1e71eee — verified unchanged at start.
model.py and lincut.py are byte-identical copies of the OCT-3 files (same SHA-256); solve2.py is an adapted copy of solve.py (adds --seed, --lb).
Everything runs with PYTHONDONTWRITEBYTECODE=1 and OCT_EXACT=0 (per-op model, the one that produced OCT-3's proofs) unless noted.
Nothing outside this folder is written. No pushes, posts, picture or cipher changes.

## How to resume
Each stage has a *_run.sh that skips jobs whose runs/*.json already exist. Re-run the script of the first stage not marked DONE.

## Stage 1 — more key schedules (1 round, diff + lin) — DONE (retries of 2 linear timeouts in Stage 1b)
New schedules: model.schedules(8, seed=20261122) (independent of OCT-3's seed 20261121 schedule 0).
Round indices per schedule k: (2k)%16 and (2k+7)%16 -> covers all 16 round positions, both parities. 32 runs, 420 s cap, 2 workers, 4 in parallel.
Script: stage1_run.sh (jobs in stage1_jobs.txt), log logs/stage1.log.
- 7:20 PM ET: first try (4 parallel x 2 workers, 420 s) gave NO lower bounds (CP-SAT with 2 workers lacks its bounding workers; proved_lower 0,
  best found 14-18). Kept in runs/stage1_try1_2workers/ for the record, not used. Restarted: 2 parallel x 4 workers, 360 s cap (OCT-3 used 4-8 workers).
## Stage 4 prep (started early at nice 10, small CPU): bow_tables.c (exact bow-stroke DP/corr tables, running), stage4_triplets.py (written, not run),
   superbox.c (Stage 3 exact 2-S-layer clustering on the Latin pair; written, not run).
- 7:28 PM ET Stage 4a (bow) DONE: runs/stage4_bow_tables.json (exact, via DP/LAT of 8-bit addition and the stroke identities; pressure byte uniform,
  its difference/mask zero). Verified vs octavo_np (runs/stage4_bow_verify.json: single-stroke composition == _bow; all 36 sampled argmax checks match).
  Max DP per pattern (in->out): u->uv' 2^-2.68, v->u' / v->uv' 2^-4.25, uv->u' 2^-1, uv->v' 2^-2.79, uv->uv' 2^-3.68; u->u', u->v', v->v' impossible.
  Max |corr|: v->uv' = 1 (parity of all bits: rotation keeps parity), uv->u'/uv->uv' 2^-2.79, u->v'/u->uv' 2^-4, uv->v' 2^-4.25.
  So the bow earns 1–4.2 bits (diff) per active stroke with the pressure byte inactive; linear 0–8.5 bits of ELP, but one linear pattern is free.
- 7:45 PM ET Stage 1 results (per-op model, 16 new (schedule, round) points, all 16 round positions covered):
  diff: all 16 OPTIMAL: 12 x1 (sched 2 round 11), 13 x4, 14 x10, 15 x1.  lin: 14 OPTIMAL with the same value as diff at the same point;
  2 timeouts at 360 s: sched 0 round 0 proved 13 (best 14), sched 6 round 3 proved 14 (best 15). Overall minimum 12; NOTHING below 12.
  With OCT-3's 4 points (15/13/12/12): 20 points, min 12 (3 points), median 14. Diff and lin minima coincide everywhere solved.
- Stage 1b (stage1b_run.sh, jobs in stage1b_jobs.txt): retry the 2 linear timeouts, 8 workers, 600 s, --lb from the first try. Log logs/stage1b.log.
  (Note: its skip-if-done filename check uses the wrong argument positions, so on resume it simply re-runs both; harmless.)
- Stage 4a (triplets) DONE: runs/stage4_triplets.json, logs/stage4_triplets.log. Exact: for all six maps, MSB differences {0,0x80}^3 give DP = 1 and
  LSB masks give |corr| = 1 on 7 of the 49 support patterns (M mod 2 is invertible). Sampled: >=23 patterns with |corr| >= 1/2.
  Typical random-input row max DP ~2^-10.5, typical random-mask |corr| ~2^-8.5 — but the worst cases are 1, so the triplets earn NO sound credit.
## Stage 2 — longer 2-round proof — QUEUED/RUNNING (stage2_run.sh; waits for Stage 1b; log logs/stage2.log)
  diff R=2 (--lb 31 --hint 38) and lin R=2 (--lb 28 --hint 32), schedule 0 rounds 0-1, 2700 s cap, 4 workers each in parallel;
  then R=3 (1800 s, 8 workers, --lb = 2-round optimum + 12) only for a mode whose R=2 run finished OPTIMAL. Resumable (skips existing runs/*.json).
- Stage 1b DONE (~7:50 PM ET): sched 0 round 0 lin OPTIMAL 14 (103 s); sched 6 round 3 lin OPTIMAL 15 (539 s). All 32 Stage-1 runs now OPTIMAL;
  lin == diff at every point. Distribution (16 new points): 12 x1, 13 x4, 14 x10, 15 x1. STAGE 1 DONE.
- ~7:50 PM ET Stage 2 runs started (both R=2, 2700 s caps -> expected end ~8:36 PM ET).
## Stage 3 work so far (light, nice 10, alongside Stage 2)
- stage3_superbox.py / superbox.c (exact, fixed key, real keyed S-boxes) on the 16-bit piece S,S -> Latin pair: max DP ~2^-11.7, max |corr| ~2^-5.2,
  best single characteristic 2^-18 / corr 2^-9. This is the random-16-bit-permutation floor (trail weight 18 > width 16), so it says the piece
  behaves like a random permutation; it is too small to measure erosion per S-box. Note: no key is added between S-layers inside a round,
  so the Markov (independent-key) assumption behind all trail bounds is not literally true inside a round.
- markov2.c (stage3_markov.sh -> runs/stage3_markov.txt): Markov EDP/ELP (all characteristics summed) vs best characteristic on the same piece.
- 7:55 PM ET: session interrupted and resumed; Stage 2 solvers (started 7:48 PM ET, end ~8:34 PM ET) kept running — not restarted.
- Stage 3b superbox DONE for 4 (schedule, round) points (runs/stage3_superbox.json): identical picture each time — max DP 2^-11.7..-11.8,
  max |corr| 2^-5.2..-5.3, best characteristic 2^-18 / 2^-9: random-16-bit-permutation floor.
- Stage 3c Markov DONE (runs/stage3_markov.txt, 2 S-box sets): summing all characteristics through S,S -> Latin pair (3 active S-boxes minimum)
  gives max EDP 2^-15.2 vs best characteristic 2^-18 (gain 2.8 bits; 2.6-3.6 bits for 2-byte inputs); ELP 2^-15.1 vs 2^-18 (gain 2.6-2.9 bits).
  ~0.9-1.2 bits per active S-box, partly a floor effect (2^-16 is the floor for a 16-bit piece). Reference: AES 4-round MEDP bound
  1.88*2^-114 vs single trail 2^-150 = ~1.4 bits per active S-box.
- Stage 3a (stage3_count.py, truncated-trail enumeration) — NOT RUN YET; runs after Stage 2 frees the CPU.
- Stage 2 RESULT (8:23 PM ET): both R=2 runs stopped after 2083 s of the 2700 s cap (both at the same second, so most likely an outside stop signal,
  not a solver finish) with status UNKNOWN: no trail found under the obj <= hint constraint and no bound above the passed-in --lb.
  Proved stays diff >= 31, lin >= 28 (no improvement over OCT-3); best known stays 38 / 32 from OCT-3. R=3 not run (R=2 not OPTIMAL). STAGE 2 DONE (no change).
## Stage 3a + Stage 4b — RUNNING (stage34b_run.sh; logs/stage3a.log, logs/stage4b.log; resumable, skips existing runs/*.json)
- 8:35 PM ET Stage 3a try 1 (one enumeration up to amin+4) only ever reached cost-16 trails (548,601 of them in 590 s, none at 12-15 listed yet):
  not useful, moved to runs/stage3a_try1/. Rewrote stage3_count.py to enumerate each exact cost level separately (150 s per level);
  now running as stage3a_run.sh (log logs/stage3a.log).
- Stage 4b first results (solve4.py, OPTIMAL, minutes each): 1-round min weight with bow credit, S-box 6 bits each:
  diff: s0 r0 94 bits (15 S + 4.0 bow; plain 90), s0 r2 80 (12 S + 8.0; plain 72), s0 r3 80, seed2 s2 r11 80.  lin (ELP): 72 = 12x6 + 0 everywhere
  (the bow's parity pattern v->uv' is free, so linear gets no gain).
- 8:42 PM ET Stage 3a try 2: level 12 alone had >= 147,348 truncated trails (incomplete at 150 s) for s0 r2 diff (logs/stage3a_try2.log).
  Most differ only in free (non-S-box) intermediate bytes. Try 3 (running): also counts DISTINCT active-S-box sets; levels amin..amin+2, 150 s each.
- Stage 4b: lin s0 r0 timed out at 600 s (proved 84, best 90; the active-count bound already gives >= 15 x 6 = 90). Running s0 r1 diff/lin for the 4-round sum.
- 8:55 PM ET Stage 3a try 3: schedule 0 round 2, levels 12/13/14 (150 s each, incomplete). Diff: >=183,726 / 213,295 / 180,883 truncated trails,
  1 / 3 / 1 distinct active-S-box sets (factor ~1.05). Lin: >=121,940 / 261,720 / 272,345, 1 / 1 / 1 sets (factor ~1.02). Third point
  (seed2 s2 r11) stopped deliberately to finish; not run. STAGE 3 DONE.
- Stage 4b DONE: diff weights s0 r0..r3 = 94 / 88 / 80 / 80, seed2 s2 r11 = 80; lin = >=90 / 78 / 72 / 72, 72. STAGE 4 DONE.
## Stage 5 — REPORT.md written (8:55 PM ET). SHA of sneak_n2.py re-checked at the end: unchanged. ALL STAGES DONE. No processes left running.
