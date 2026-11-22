#!/bin/bash
# Stage 3/4 queue, per-op model (OCT_EXACT=0), run after the Stage 2b exact runs finish
export PYTHONDONTWRITEBYTECODE=1 OCT_EXACT=0
while pgrep -f solve_cuts.py >/dev/null; do sleep 10; done
python3 solve.py lin 2 --cap 600 --workers 8
for mode in diff lin; do for sh in inner outer; do python3 solve.py $mode 1 --shell $sh --cap 240 --workers 8; done; done
for mode in diff lin; do python3 solve.py $mode 1 --shell inner --confine --cap 120 --workers 8; done
for mode in diff lin; do python3 solve.py $mode 2 --shell inner --cap 300 --workers 8; done
echo QUEUE_DONE
