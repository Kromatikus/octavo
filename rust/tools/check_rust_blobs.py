#!/usr/bin/env python3
"""Rust -> Python: open blobs sealed by the Rust port with this repo's sneak_n2.py (read-only import)."""
import hashlib, json, os, random, subprocess, sys
from pathlib import Path
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from octavo_ref import EXPECT_SHA256, py_dir
sys.path.insert(0, str(py_dir()))
import sneak_n2 as S
assert hashlib.sha256(open(S.__file__, 'rb').read()).hexdigest() == EXPECT_SHA256
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
rng = random.Random(7)
while True:
    seed = bytes(rng.getrandbits(8) for _ in range(128))
    if S._weak_seed_reason(seed) is None: break
out = subprocess.run(['cargo', 'run', '-q', '--release', '-p', 'octavo-core', '--features', 'parallel', '--example', 'emit_blobs', '--', seed.hex()],
                     cwd=ROOT, check=True, capture_output=True, text=True).stdout
ok = 0; cases = json.loads(out)
for c in cases:
    blob, ad, msg = (bytes.fromhex(c[k]) for k in ('blob', 'ad', 'msg'))
    f = {'v6': S.decrypt, 'v7': S.decrypt_movements, 'v9': S.decrypt_rehearsal}[c['mode']]
    got = f(blob, seed, ad=ad)
    assert got == msg, c['mode']; ok += 1
print('Rust-sealed blobs opened by sneak_n2.py: %d/%d OK' % (ok, len(cases)))
