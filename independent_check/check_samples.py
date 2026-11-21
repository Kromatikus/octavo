#!/usr/bin/env python3
"""Open the three live samples (v6 hello-world, v7 movements-demo, v9 rehearsal-demo) with the
independent implementation, and check that single-bit tampering is rejected."""
import re, json, ic_octavo as O
import os
D = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + os.sep
seed = bytes.fromhex(json.load(open(D + 'score/vectors.json'))['seed']['hex'])
def blob(f): return bytes.fromhex(re.search(r'^blob .*?: ([0-9a-f]{100,})$', open(D + f).read(), re.M).group(1))
ctx = O.Ctx(seed); ok = True
cases = [('hello-world.txt', lambda b: O.open_block(ctx, b)), ('movements-demo.txt', lambda b: O.open_movements(ctx, b)),
         ('rehearsal-demo.txt', lambda b: O.open_rehearsal(seed, b, b'rehearsal-demo'))]
for f, fn in cases:
    b = blob(f); m = fn(b); print('OPEN', f, len(b), 'bytes ->', m[:60])
    for pos in (0, 5, 25, 50, 100, len(b) - 1):
        t = bytearray(b); t[pos] ^= 1
        try: fn(bytes(t)); print('  TAMPER NOT REJECTED at', pos); ok = False
        except O.Reject: pass
    print('  6 single-bit tampers rejected' if ok else '')
assert O.open_block(ctx, blob('hello-world.txt')) == b'hello world'
print('ALL OK' if ok else 'PROBLEM')
