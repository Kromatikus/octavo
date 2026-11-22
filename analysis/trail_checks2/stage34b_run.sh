#!/bin/bash
# Stage 3a (truncated-trail enumeration, 1 worker each, 600 s) in parallel with Stage 4b (bow-weighted 1-round bounds, 4 workers, 600 s each).
cd "$(dirname "$0")"; export PYTHONDONTWRITEBYTECODE=1 OCT_EXACT=0
(
 for j in "diff 1 --seed 20261121 --sched 0 --start 2" "lin 1 --seed 20261121 --sched 0 --start 2" "diff 1 --seed 20261122 --sched 2 --start 11" "diff 1 --seed 20261121 --sched 0 --start 0"; do
   set -- $j; f="runs/count_${1}_R1_seed${4}_s${6}_r${8}_K4.json"; [ -f "$f" ] || python3 stage3_count.py $j --K 4 --cap 600 --findcap 300 >> logs/stage3a.log 2>&1
 done; echo STAGE3A_DONE >> logs/stage3a.log ) &
(
 for j in "--seed 20261121 --sched 0 --start 2" "--seed 20261122 --sched 2 --start 11" "--seed 20261121 --sched 0 --start 3" "--seed 20261121 --sched 0 --start 0"; do
   set -- $j
   for mode in diff lin; do f="runs/w_${mode}_R1_seed${2}_s${4}_r${6}.json"; [ -f "$f" ] || python3 solve4.py $mode 1 $j --cap 600 --workers 4 >> logs/stage4b.log 2>&1; done
 done; echo STAGE4B_DONE >> logs/stage4b.log ) &
wait
