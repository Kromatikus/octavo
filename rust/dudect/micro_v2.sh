#!/usr/bin/env bash
# VPSLLVW / bow micro-tests, v2 design (both classes read inputs from equal-size rings at the same index),
# with A/A controls and 4x-work scaling checks. Hard timeouts as in run_suite.sh. Local only.
set -u
ROOT="$(cd "$(dirname "$0")" && pwd)"; source /dev/null
BIN="$ROOT/harness/target/release/octavo-dudect"; OUT="$ROOT/results"; SECS="${SECS:-35}"
one() { local name="$1" exp="$2" cpus="$3"; shift 3
  local json="$OUT/$name.json" log="$OUT/$name.log"
  if [[ -f "$json" ]] && grep -q '"verdict"' "$json"; then echo "skip $name"; return 0; fi
  echo "$(date '+%T') START $name $*"
  env "$@" timeout --signal=TERM --kill-after=8s "$((SECS + 45))s" taskset -c "$cpus" "$BIN" -e "$exp" -b gfni-simd \
      -s "$SECS" --max-samples 20000000 -o "$json" >/dev/null 2>"$log"
  echo "$(date '+%T') END $name rc=$? $(tail -1 "$log")"; }
lane_a() {
  for e in vrot128-amt vrot128-1v7 vrot512-amt vrot512-1v7; do one "${e}_gfni-simd" $e 2 X=1; done
  one vrot128-amt_gfni-simd_aa vrot128-amt 2 OCTAVO_DUDECT_AA=1
  one vrot128-amt_gfni-simd_x4 vrot128-amt 2 OCTAVO_DUDECT_ITERS=2048
  one vrot512-amt_gfni-simd_x4 vrot512-amt 2 OCTAVO_DUDECT_ITERS=2048
}
lane_b() {
  for e in bow128-state unbow128-state bow512-state unbow512-state; do one "${e}_gfni-simd" $e 6 X=1; done
  one unbow128-state_gfni-simd_aa unbow128-state 6 OCTAVO_DUDECT_AA=1
  one unbow128-state_gfni-simd_x4 unbow128-state 6 OCTAVO_DUDECT_REPS=128
  one bow128-state_gfni-simd_x4 bow128-state 6 OCTAVO_DUDECT_REPS=128
}
lane_a > "$OUT/micro_v2_a.log" 2>&1 &
lane_b > "$OUT/micro_v2_b.log" 2>&1 &
wait
