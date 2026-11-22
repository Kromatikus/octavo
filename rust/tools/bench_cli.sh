#!/usr/bin/env bash
# Throughput of the octavo CLI (file -> file). Usage: tools/bench_cli.sh [MiB]
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
cd "$(dirname "$0")/.."
MB=${1:-256}
B=target/release/octavo
D=target/bench; rm -rf "$D"; mkdir -p "$D"
export OCTAVO_HOME="$D/home"
$B keygen -o "$D/k.key" 2>/dev/null
head -c $((MB*1048576)) /dev/urandom > "$D/p"
t() { local s=$(date +%s.%N); "$@"; local e=$(date +%s.%N); python3 -c "print('%.2f' % ($e-$s))"; }
for j in 1 2 4 8; do
  for bc in 4 16; do
    ts=$(t $B seal -k "$D/k.key" -j $j --batch-chunks $bc "$D/p" -o "$D/c" --force)
    to=$(t $B open -k "$D/k.key" -j $j --batch-chunks $bc "$D/c" -o "$D/r" --force)
    cmp -s "$D/p" "$D/r" || { echo MISMATCH; exit 1; }
    python3 -c "m=$MB*1.048576; print('threads %d batch %2d: seal %5.1f MB/s (%ss)  open %5.1f MB/s (%ss)' % ($j,$bc,m/$ts,'$ts',m/$to,'$to'))"
  done
done
# pipe path (stdin -> stdout spool)
ts=$(t sh -c "$B seal -k $D/k.key < $D/p > $D/c2")
to=$(t sh -c "$B open -k $D/k.key < $D/c2 > $D/r2")
cmp -s "$D/p" "$D/r2" || { echo MISMATCH; exit 1; }
python3 -c "m=$MB*1.048576; print('pipe (default threads): seal %5.1f MB/s  open (spooled) %5.1f MB/s' % (m/$ts, m/$to))"
rm -rf "$D"
