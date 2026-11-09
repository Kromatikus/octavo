#!/bin/bash
# Hash protected trees (read-only). Usage: hash_protected.sh > out.txt
cd /workspace
for p in test1 test3 test13 testn1 testn3 testn4 testn5 sneak_t1n sneak_v* sneak1024-seed.txt sneak-staff-n2.png sneak_n2/sneak_n2.py sneak_n2/test_sneak_n2.py sneak_n2/render_n2.py sneak_n2/sneak-staff-n2.png sneak_n2/README.md sneak_n2/SPEC.md sneak_n2/hello-world.txt sneak_n2/test_results.txt sneak_n2/baselines sneak_n2/attacks sneak_n2/attacks_8bit sneak_n2/attacks_four_leftovers sneak_n2/attacks_join_pairs sneak_n2/attacks_linear_algebraic sneak_n2/attacks_octavo_beat7 sneak_n2/attacks_pickup sneak_n2/attacks_siv sneak_n2/attacks_three_fixes; do
  [ -e "$p" ] || { echo "MISSING $p"; continue; }
  if [ -d "$p" ]; then n=$(find "$p" -type f -not -path '*__pycache__*' | wc -l); t=$(find "$p" -type f -not -path '*__pycache__*' -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -c1-64); echo "$p dir files=$n tree=$t"
  else echo "$p file $(sha256sum "$p" | cut -c1-64)"; fi
done
