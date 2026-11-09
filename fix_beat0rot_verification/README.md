# Beat-0 pressure-rotation fix verification

Post-apply checks for the live Octavo change described in
`attacks_octavo_beat6/REPORT.md` §6. This folder is **not** an attack report and does not
modify any `attacks_*` folder.

Target: `/workspace/sneak_n2/sneak_n2.py` after the beat-0 pressure-rotation fix
(`BOW_PRESSURE_ROT = (0,0,0,3,0,0,5)`). Scripts assert the live SHA and that
`BOW_PRESSURE_ROT` matches before importing the model.

Scripts:
- `verify_even_beats.py` — full 2^21-base even-beat singleton scan (A), 2^18 all-beat sanity (B),
  forced-change check (F). Multiprocessing.
- `verify_differentials.py` — bow-alone best single-beat differentials for beats 0/6/7 vs the
  pre-fix live numbers from the beat-6 report.
- `run_all.sh` — runs both and writes a short `SUMMARY.md`.

If any singleton is found, the apply step must revert to `/tmp/sneak_n2_pre_beat0rot`.
