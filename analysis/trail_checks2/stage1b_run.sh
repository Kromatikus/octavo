#!/bin/bash
# Stage 1b: retry Stage 1 timeouts with 8 workers, 600 s cap, passing the proved lb. Skips finished ones.
cd "$(dirname "$0")"; export PYTHONDONTWRITEBYTECODE=1 OCT_EXACT=0
while read -r line; do set -- $line; f="runs/${1}_R1_seed20261122_s${5}_r${7}_retry.json"; [ -f "$f" ] && continue; python3 solve2.py $line >> logs/stage1b.log 2>&1; done < stage1b_jobs.txt
echo STAGE1B_DONE >> logs/stage1b.log
