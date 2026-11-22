#!/bin/bash
# Stage 3a v2: per-level truncated-trail enumeration (levels amin..amin+2, 150 s each), 1-round points. Skips existing outputs.
cd "$(dirname "$0")"; export PYTHONDONTWRITEBYTECODE=1 OCT_EXACT=0
for j in "diff 1 --seed 20261121 --sched 0 --start 2" "lin 1 --seed 20261121 --sched 0 --start 2" "diff 1 --seed 20261122 --sched 2 --start 11"; do
  set -- $j; f="runs/count_${1}_R1_seed${4}_s${6}_r${8}_K2.json"; [ -f "$f" ] || python3 stage3_count.py $j --K 2 --cap 450 --findcap 300 >> logs/stage3a.log 2>&1
done; echo STAGE3A_DONE >> logs/stage3a.log
