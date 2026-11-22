"""Cube-set builder shared by stage 5b (same definition as in stage5_algebraic.py)."""
import numpy as np
rng = None
def cube_set(d, flavor):
    base = rng.integers(0, 256, 128, dtype=np.uint8)
    if flavor == "packed":
        start = int(rng.integers(0, 16)) * 64; bits = [(start + i) % 1024 for i in range(d)]
    else:
        bys = rng.choice(128, d, replace=False); bits = [int(b) * 8 + int(rng.integers(8)) for b in bys]
    n = 1 << d; idx = np.arange(n); P = np.tile(base, (n, 1))
    for i, b in enumerate(bits):
        P[:, b // 8] = (P[:, b // 8] & ~np.uint8(1 << (b % 8))) | (((idx >> i) & 1).astype(np.uint8) << (b % 8))
    return P
