#!/bin/bash
# Stage 1: 1-round per-op min active S-boxes, 8 new lab schedules (seed 20261122, sched 0-7) x 2 round indices x diff/lin.
# Resumable: skips jobs whose runs/*.json already exists. 2 parallel x 4 workers, 360 s cap each.
cd "$(dirname "$0")"
export PYTHONDONTWRITEBYTECODE=1 OCT_EXACT=0
run() { set -- $1; f="runs/${1}_R${2}_seed${4}_s${6}_r${8}.json"; [ -f "$f" ] && exit 0; python3 solve2.py "$@" >> logs/stage1.log 2>&1; }
export -f run
xargs -P 2 -I{} bash -c 'run "{}"' < stage1_jobs.txt
echo STAGE1_DONE >> logs/stage1.log
