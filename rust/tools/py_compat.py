#!/usr/bin/env python3
"""Python side of the octavo CLI cross-compat test. READ-ONLY use of this repo's sneak_n2.py
(or $OCTAVO_PY_DIR/sneak_n2.py). Run with python3 -B (and PYTHONDONTWRITEBYTECODE=1): no __pycache__ is written.
Usage: py_compat.py JOBS.json   -> prints a JSON result list.
Jobs: {"op":"enc","key":path,"src":path,"dst":path,"ad":hex,"cs":int}
      {"op":"dec","key":path,"src":path,"dst":path,"ad":hex}
      {"op":"policy","seeds":[hex,...]}            -> reasons (None = passes)
      {"op":"loadkey","key":path}                  -> sha256 of the seed load_seed() returns
"""
import hashlib, json, sys, warnings
from pathlib import Path
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from octavo_ref import EXPECT_SHA256, py_dir
sys.path.insert(0, str(py_dir()))
import sneak_n2 as S
assert hashlib.sha256(open(S.__file__, 'rb').read()).hexdigest() == EXPECT_SHA256
warnings.simplefilter('ignore')
out = []
for j in json.load(open(sys.argv[1])):
    try:
        if j['op'] == 'enc':
            n = S.encrypt_rehearsal_file(j['src'], j['dst'], S.load_seed(j['key']), ad=bytes.fromhex(j['ad']), chunk_size=j['cs'])
            out.append({'ok': True, 'n': n})
        elif j['op'] == 'dec':
            n = S.decrypt_rehearsal_file(j['src'], j['dst'], S.load_seed(j['key']), ad=bytes.fromhex(j['ad']))
            out.append({'ok': True, 'n': n})
        elif j['op'] == 'policy':
            out.append({'ok': True, 'reasons': [S._weak_seed_reason(bytes.fromhex(h)) for h in j['seeds']]})
        elif j['op'] == 'loadkey':
            out.append({'ok': True, 'sha': hashlib.sha256(S.load_seed(j['key'])).hexdigest()})
    except Exception as e:
        out.append({'ok': False, 'err': '%s: %s' % (type(e).__name__, e)})
print(json.dumps(out))
