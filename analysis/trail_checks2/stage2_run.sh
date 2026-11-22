#!/bin/bash
# Stage 2: longer 2-round proofs on OCT-3's schedule (seed 20261121, sched 0, rounds 0-1), per-op model.
# diff: --lb 31 (OCT-3 proved) --hint 38 (OCT-3 best real per-op trail); lin: --lb 28 (sum of proved 1-round minima) --hint 32 (OCT-3 best).
# Both in parallel, 4 workers each, 2700 s cap. Then 3 rounds (rounds 0-2) only for a mode whose 2-round run is OPTIMAL (1800 s, 8 workers).
cd "$(dirname "$0")"; export PYTHONDONTWRITEBYTECODE=1 OCT_EXACT=0
while pgrep -f stage1b_run.sh >/dev/null; do sleep 15; done
[ -f runs/diff_R2_seed20261121_s0_r0.json ] || python3 solve2.py diff 2 --start 0 --cap 2700 --workers 4 --lb 31 --hint 38 >> logs/stage2.log 2>&1 &
[ -f runs/lin_R2_seed20261121_s0_r0.json ]  || python3 solve2.py lin 2 --start 0 --cap 2700 --workers 4 --lb 28 --hint 32 >> logs/stage2.log 2>&1 &
wait
for mode in diff lin; do
  st=$(python3 -c "import json;d=json.load(open('runs/${mode}_R2_seed20261121_s0_r0.json'));print(d['status'], d['best_found'])")
  set -- $st
  if [ "$1" = "OPTIMAL" ] && [ ! -f runs/${mode}_R3_seed20261121_s0_r0.json ]; then
    python3 solve2.py $mode 3 --start 0 --cap 1800 --workers 8 --lb $(( $2 + 12 )) >> logs/stage2.log 2>&1
  fi
done
echo STAGE2_DONE >> logs/stage2.log
