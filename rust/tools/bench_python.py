#!/usr/bin/env python3
"""Python side of the throughput comparison: sneak_n2.encrypt_grid per 128-byte block (read-only import)."""
import hashlib, sys, time
from pathlib import Path
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from octavo_ref import EXPECT_SHA256, py_dir
sys.path.insert(0, str(py_dir()))
import sneak_n2 as S
assert hashlib.sha256(open(S.__file__, 'rb').read()).hexdigest() == EXPECT_SHA256
import random; _r = random.Random(1)
while True:
    seed = bytes(_r.getrandbits(8) for _ in range(128))
    if S._weak_seed_reason(seed) is None: break
nonce = bytes([7] * 16)
t = time.perf_counter(); n = 30
for i in range(n): S.Schedule(seed, bytes([i]) + nonce[1:])
print('python schedule setup  %8.2f ms each' % ((time.perf_counter() - t) / n * 1e3))
sch = S.Schedule(seed, nonce); g = S.bytes_to_grid(bytes([0x5a] * 128))
n = 300; t = time.perf_counter()
for _ in range(n): g = S.encrypt_grid(g, sch)
e = time.perf_counter() - t
t = time.perf_counter()
for _ in range(n): g = S.decrypt_grid(g, sch)
d = time.perf_counter() - t
print('python encrypt %8.1f us/block %8.4f MB/s | decrypt %8.1f us/block %8.4f MB/s' % (e / n * 1e6, n * 128 / e / 1e6, d / n * 1e6, n * 128 / d / 1e6))
