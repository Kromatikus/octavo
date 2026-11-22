#!/usr/bin/env python3
"""Differential cases from the REAL reference (sneak_n2.py, imported read-only, no bytecode written).
Random seeds / nonces / plaintexts / AD -> vectors/diff_random.json, checked by
crates/octavo-core/tests/diff_python.rs. Usage: python3 tools/diff_python.py [N_BLOCK] [SEED]"""
import hashlib, json, os, random, sys
sys.dont_write_bytecode = True
REF = '/workspace/sneak_n2'
sys.path.insert(0, REF)
import sneak_n2 as S
EXPECT = '19181bc1623115c075dc5dee25edec388f5413466777d47b7f19fa66d1e71eee'
assert hashlib.sha256(open(os.path.join(REF, 'sneak_n2.py'), 'rb').read()).hexdigest() == EXPECT

n_block = int(sys.argv[1]) if len(sys.argv) > 1 else 40
rng = random.Random(int(sys.argv[2]) if len(sys.argv) > 2 else 20261121)
rb = lambda n: bytes(rng.getrandbits(8) for _ in range(n))

def good_seed():
    while True:
        s = rb(128)
        if S._weak_seed_reason(s) is None: return s

out = dict(note='Generated from sneak_n2.py %s by tools/diff_python.py' % EXPECT, block=[], v6=[], v7=[], v9=[])
for i in range(n_block):
    seed, nonce, pt = good_seed(), rb(16), rb(128)
    rounds = [16, 16, 16, 2, 4, 6, rng.randint(1, 16)][i % 7]
    ct = S.grid_to_bytes(S.encrypt_grid(S.bytes_to_grid(pt), S.Schedule(seed, nonce), rounds))
    out['block'].append(dict(seed=seed.hex(), nonce=nonce.hex(), rounds=rounds, pt=pt.hex(), ct=ct.hex()))
for i in range(20):
    seed = good_seed(); msg = rb(rng.randint(0, 127)); ad = rb(rng.choice([0, 0, 5, 300]))
    out['v6'].append(dict(seed=seed.hex(), ad=ad.hex(), msg=msg.hex(), blob=S.encrypt(msg, seed, ad=ad).hex()))
for i in range(8):
    seed = good_seed(); msg = rb(rng.choice([0, 1, 127, 128, 254, 255, rng.randint(0, 900)])); ad = rb(rng.choice([0, 9]))
    out['v7'].append(dict(seed=seed.hex(), ad=ad.hex(), msg=msg.hex(), blob=S.encrypt_movements(msg, seed, ad=ad).hex()))
for cs, ln in [(128, 0), (128, 127), (128, 128), (256, 1000), (1024, 3000), (4096, 4095)]:
    seed = good_seed(); msg = rb(ln); ad = rb(rng.choice([0, 7]))
    out['v9'].append(dict(seed=seed.hex(), ad=ad.hex(), msg=msg.hex(), chunk_size=cs,
                          blob=S.encrypt_rehearsal(msg, seed, ad=ad, chunk_size=cs).hex()))
p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'vectors', 'diff_random.json')
json.dump(out, open(p, 'w'), indent=1)
print('wrote', p, {k: len(v) for k, v in out.items() if isinstance(v, list)})
