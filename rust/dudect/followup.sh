#!/usr/bin/env bash
# Follow-up runs for flagged cases: plain reruns, A/A controls (OCTAVO_DUDECT_AA=1) and 4x-work scaling
# (OCTAVO_DUDECT_ITERS / OCTAVO_DUDECT_REPS). Same hard timeouts as run_suite.sh.
set -u
ROOT="$(cd "$(dirname "$0")" && pwd)"; BIN="$ROOT/harness/target/release/octavo-dudect"; OUT="$ROOT/results"
SECS="${SECS:-35}"
one() { # name exp backend cpus [ENV=VAL ...]
  local name="$1" exp="$2" be="$3" cpus="$4"; shift 4
  local json="$OUT/$name.json" log="$OUT/$name.log"
  if [[ -f "$json" ]] && grep -q '"verdict"' "$json"; then echo "skip $name"; return 0; fi
  echo "$(date '+%T') START $name $*"
  env "$@" timeout --signal=TERM --kill-after=8s "$((SECS + 45))s" taskset -c "$cpus" "$BIN" -e "$exp" -b "$be" \
      -s "$SECS" --max-samples 20000000 -o "$json" >/dev/null 2>"$log"
  echo "$(date '+%T') END $name rc=$? $(tail -1 "$log")"
}
lane_a() {
  one vrot128-amt_gfni-simd_rerun vrot128-amt gfni-simd 2 X=1
  one vrot128-amt_gfni-simd_aa    vrot128-amt gfni-simd 2 OCTAVO_DUDECT_AA=1
  one vrot128-amt_gfni-simd_x4    vrot128-amt gfni-simd 2 OCTAVO_DUDECT_ITERS=2048
  one vrot128-1v7_gfni-simd_rerun vrot128-1v7 gfni-simd 2 X=1
  one vrot512-amt_gfni-simd_rerun vrot512-amt gfni-simd 2 X=1
  one vrot512-amt_gfni-simd_aa    vrot512-amt gfni-simd 2 OCTAVO_DUDECT_AA=1
}
lane_b() {
  one unbow128-state_gfni-simd_rerun unbow128-state gfni-simd 6 X=1
  one unbow128-state_gfni-simd_aa    unbow128-state gfni-simd 6 OCTAVO_DUDECT_AA=1
  one unbow128-state_gfni-simd_x4    unbow128-state gfni-simd 6 OCTAVO_DUDECT_REPS=128
  one vrot512-amt_gfni-simd_x4       vrot512-amt gfni-simd 6 OCTAVO_DUDECT_ITERS=2048
  one enc-key_gfni-simd_rerun        enc-key gfni-simd 6 X=1
  one enc-key-twokey_gfni-simd       enc-key-twokey gfni-simd 6 X=1
  one enc-key-interleaved_gfni-simd  enc-key-interleaved gfni-simd 6 X=1
}
lane_a > "$OUT/followup_a.log" 2>&1 &
lane_b > "$OUT/followup_b.log" 2>&1 &
wait
