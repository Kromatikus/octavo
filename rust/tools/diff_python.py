#!/usr/bin/env python3
"""Differential cases from this repo's sneak_n2.py (imported read-only, no bytecode written).

The committed file vectors/diff_random.json is the fixture used by
crates/octavo-core/tests/diff_python.rs.

sneak_n2.encrypt / encrypt_movements / encrypt_rehearsal draw a fresh pickup
from the OS CSPRNG and have no public pickup argument, so regenerating the
v6/v7/v9 blobs is not deterministic. By default this script --check's the
committed fixture (recomputes the block ciphertexts; decrypts the format
blobs) and does not write. Use --write only to regenerate a new fixture.

Usage: python3 tools/diff_python.py [--check|--write] [N_BLOCK] [SEED]
"""
import hashlib, json, os, random, sys
from pathlib import Path
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from octavo_ref import EXPECT_SHA256, py_dir
REF = str(py_dir())
sys.path.insert(0, REF)
import sneak_n2 as S
assert hashlib.sha256(open(os.path.join(REF, 'sneak_n2.py'), 'rb').read()).hexdigest() == EXPECT_SHA256

args = [a for a in sys.argv[1:] if not a.startswith("-")]
flags = {a for a in sys.argv[1:] if a.startswith("-")}
if flags - {"--check", "--write"} or ({"--check", "--write"} <= flags):
    sys.exit("usage: python3 tools/diff_python.py [--check|--write] [N_BLOCK] [SEED]")
write = "--write" in flags
n_block = int(args[0]) if len(args) > 0 else 40
rng_seed = int(args[1]) if len(args) > 1 else 20261121
p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'vectors', 'diff_random.json')

if not write:
    v = json.load(open(p))
    ok = 0
    for c in v["block"]:
        seed, nonce, pt = bytes.fromhex(c["seed"]), bytes.fromhex(c["nonce"]), bytes.fromhex(c["pt"])
        ct = S.grid_to_bytes(S.encrypt_grid(S.bytes_to_grid(pt), S.Schedule(seed, nonce), c["rounds"]))
        assert ct.hex() == c["ct"], "block mismatch"
        ok += 1
    for c in v["v6"]:
        assert S.decrypt(bytes.fromhex(c["blob"]), bytes.fromhex(c["seed"]), ad=bytes.fromhex(c["ad"])) == bytes.fromhex(c["msg"])
        ok += 1
    for c in v["v7"]:
        assert S.decrypt_movements(bytes.fromhex(c["blob"]), bytes.fromhex(c["seed"]), ad=bytes.fromhex(c["ad"])) == bytes.fromhex(c["msg"])
        ok += 1
    for c in v["v9"]:
        assert S.decrypt_rehearsal(bytes.fromhex(c["blob"]), bytes.fromhex(c["seed"]), ad=bytes.fromhex(c["ad"])) == bytes.fromhex(c["msg"])
        ok += 1
    print("checked", p, "OK", ok, {k: len(v[k]) for k in ("block", "v6", "v7", "v9")})
    sys.exit(0)

rng = random.Random(rng_seed)
rb = lambda n: bytes(rng.getrandbits(8) for _ in range(n))

def good_seed():
    while True:
        s = rb(128)
        if S._weak_seed_reason(s) is None: return s

out = dict(note='Generated from sneak_n2.py %s by tools/diff_python.py' % EXPECT_SHA256, block=[], v6=[], v7=[], v9=[])
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
json.dump(out, open(p, 'w'), indent=1)
print('wrote', p, {k: len(v) for k, v in out.items() if isinstance(v, list)})
print('note: v6/v7/v9 blobs are not deterministic (fresh pickup); do not commit a rewrite unless intended')
