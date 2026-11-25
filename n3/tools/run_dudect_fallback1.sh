#!/bin/bash
# fallback1 dudect: 30 s each, sequential. Usage: run_dudect_fallback1.sh
# Build the probe with: cargo build --release --features lab --bin n3dudect
# (n3dudect is a lab-only binary; the default release build is just n3aead).
set -e
cd /workspace/octavo_n3_fallback1/rust
OUT=/workspace/octavo_n3_fallback1/results/fallback1
for be in avx2gfni avx2 portable; do
  for ex in enc-pt enc-key schedule-key; do
    if [ -f "$OUT/dudect_${be}_${ex}.json" ]; then continue; fi
    OCTAVO_N3_BACKEND=$be ./target/release/n3dudect -e $ex -s 30 -o "$OUT/dudect_${be}_${ex}.json" > "$OUT/dudect_${be}_${ex}.log" 2>&1
    echo "done $be $ex"
  done
done
echo ALLDONE
