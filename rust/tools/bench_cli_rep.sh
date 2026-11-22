#!/usr/bin/env bash
# Repeated CLI throughput (file -> file) for given thread counts; prints each run.
# Usage: tools/bench_cli_rep.sh [MiB] [reps] [threads...]
set -euo pipefail
cd "$(dirname "$0")/.."
MB=${1:-256}; REPS=${2:-3}; shift 2 || true; TH=("${@:-1 8}")
B=target/release/octavo; D=target/bench_rep; rm -rf "$D"; mkdir -p "$D"
export OCTAVO_HOME="$D/home"
$B keygen -o "$D/k.key" 2>/dev/null
head -c $((MB*1048576)) /dev/urandom > "$D/p"
t() { local s=$(date +%s.%N); "$@"; local e=$(date +%s.%N); python3 -c "print('%.3f' % ($e-$s))"; }
for j in ${TH[@]}; do for r in $(seq $REPS); do
  ts=$(t $B seal -k "$D/k.key" -j $j "$D/p" -o "$D/c" --force)
  to=$(t $B open -k "$D/k.key" -j $j "$D/c" -o "$D/r" --force)
  cmp -s "$D/p" "$D/r" || { echo MISMATCH; exit 1; }
  python3 -c "m=$MB*1.048576; print('threads %d run %d: seal %6.1f MB/s  open %6.1f MB/s' % ($j,$r,m/$ts,m/$to))"
done; done
rm -rf "$D"
