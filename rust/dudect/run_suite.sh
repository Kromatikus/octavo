#!/usr/bin/env bash
# Dudect suite for this rust/ tree. Two pinned lanes run in parallel; every case is
# time-bounded by the harness (--seconds) and by GNU timeout (hard = seconds + 45 s).
# Usage: dudect/run_suite.sh [SECONDS]   (resumable: cases with a finished json are skipped)
set -u
export PATH="$HOME/.cargo/bin:$PATH"
ROOT="$(cd "$(dirname "$0")" && pwd)"
BIN="$ROOT/harness/target/release/octavo-dudect"
OUT="$ROOT/results"
SECS="${1:-35}"
mkdir -p "$OUT"
[[ -x "$BIN" ]] || { echo "build first: (cd $ROOT/harness && cargo build --offline --release)"; exit 1; }

run_one() { # exp backend cpus [suffix]
  local exp="$1" be="$2" cpus="$3" sfx="${4:-}"
  local name="${exp}_${be}${sfx}" hard=$((SECS + 45))
  local json="$OUT/$name.json" log="$OUT/$name.log"
  if [[ -f "$json" ]] && grep -q '"verdict"' "$json"; then echo "skip $name"; return 0; fi
  echo "$(date '+%T') START $name cpus=$cpus"
  timeout --signal=TERM --kill-after=8s "${hard}s" taskset -c "$cpus" "$BIN" -e "$exp" -b "$be" \
      -s "$SECS" --max-samples 20000000 -o "$json" >/dev/null 2>"$log"
  local rc=$?
  echo "$(date '+%T') END $name rc=$rc $(tail -1 "$log")"
}

BACKENDS=(gfni-simd gfni-512 gfni-256 gfni-128 aes-ni ct-soft)
COMMON=(enc-pt enc-key dec-pt dec-key enc-batch-pt dec-batch-pt v9-tag-pos stream-open-pt stream-tag-pos)
SIMD=(vrot512-amt vrot512-1v7 vrot128-amt vrot128-1v7 bow128-state unbow128-state bow512-state unbow512-state)

lane_a() {
  for be in gfni-simd gfni-512 gfni-256; do for e in "${COMMON[@]}"; do run_one "$e" "$be" 2; done; done
  for e in "${SIMD[@]:0:4}"; do run_one "$e" gfni-simd 2; done
  run_one stream-open-pt-mt gfni-simd 2,3
  run_one v9-valid-tamper gfni-simd 2
}
lane_b() {
  for be in gfni-128 aes-ni ct-soft; do for e in "${COMMON[@]}"; do run_one "$e" "$be" 6; done; done
  for e in "${SIMD[@]:4:4}"; do run_one "$e" gfni-simd 6; done
  run_one stream-tag-pos-mt gfni-simd 6,7
  run_one schedule-key gfni-simd 6
}
echo "suite start $(date '+%F %T %Z') secs=$SECS"
lane_a > "$OUT/lane_a.log" 2>&1 &
lane_b > "$OUT/lane_b.log" 2>&1 &
wait
echo "suite done $(date '+%F %T %Z')"
python3 -B "$ROOT/table.py" "$OUT"
