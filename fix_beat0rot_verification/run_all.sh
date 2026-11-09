#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
echo "=== verify_even_beats ==="
python3 -u verify_even_beats.py 2>&1 | tee verify_even_beats_output.txt
echo "=== verify_differentials ==="
python3 -u verify_differentials.py 2>&1 | tee verify_differentials_output.txt
python3 - <<'PY'
import json
from pathlib import Path
here = Path('.')
A = json.loads((here/'verify_even_beats_results.json').read_text())
D = json.loads((here/'verify_differentials_results.json').read_text())
lines = []
lines.append('# Beat-0 pressure-rotation fix — verification summary')
lines.append('')
lines.append(f"- Live SHA: `{A['live_sha']}`")
lines.append(f"- BOW_PRESSURE_ROT: `{A['pressure_rot']}`")
lines.append(f"- Even-beat scan PASS (0 hits): **{A['PASS']}** (total_hits={A['total_hits']})")
a = A['A_random_even_2^21']
lines.append(f"- Scan A (2^21 even): hits/cases per beat: " +
             ', '.join(f"{t}: {a[str(t)]['hits']}/{a[str(t)]['cases']}" for t in (0,2,4)))
b = A['B_random_all_beats_2^18']
lines.append(f"- Scan B (2^18 all beats) hits: " +
             ', '.join(f"{t}:{b[str(t)]['hits']}" for t in range(8)))
lines.append(f"- Forced changes F: `{A['F_forced_changes']}`")
lines.append(f"- Differentials (2^13 bases) log2 vs pre-fix report: " +
             ', '.join(f"beat{t}: {D['bow_best_diff'][str(t)]['log2']} (was {D['pre_fix_live_from_report'][str(t)]})"
                       for t in (0,6,7)))
lines.append(f"- Same-bases old-model log2: `{D['same_bases_old_model_log2']}`")
lines.append(f"- Improved vs report: `{D['improved']}`")
lines.append(f"- Wall: even {A['seconds']}s, diffs {D['seconds']}s")
lines.append('')
lines.append('Still homemade. For real secrets use AES-GCM-SIV, age, or libsodium.')
(here/'SUMMARY.md').write_text('\n'.join(lines)+'\n')
print((here/'SUMMARY.md').read_text())
PY
