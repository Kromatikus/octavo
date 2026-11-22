"""OCT-4 Stage 4a: XOR-differential and linear behaviour of the six Z/256 triplet maps (T0..T5), byte level.
Exact facts checked: (1) MSB differences: d in {0,0x80}^3 -> out 0x80*(M mod 2)d with DP 1 (x -> c*x mod 256 maps x^0x80 to cx^0x80 for odd c).
(2) LSB masks: bit0 of each output = GF(2) sum of bit0 of inputs with M mod 2 -> correlation +-1.
Since det M is odd, M mod 2 is invertible: 7 of the 49 (in,out) support patterns have DP 1 and 7 have |corr| 1.
Sampled: per-pattern best DP over structured + random input differences (2^14 samples each), per-pattern best |corr| over
masks with components in {0..3,0x80,0xc0} (2^16 samples). Sampled maxima are LOWER estimates of the true maxima."""
import sys, json, itertools
sys.dont_write_bytecode = True
import os
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "trail_search")))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "reduced_round")))
import numpy as np
import octavo_np as onp
m = onp.m
rng = np.random.default_rng(4)
def apply(M, X):
    u, v, w = (X[:, c].astype(np.int64) for c in range(3))
    return np.stack([((M[r][0]*u + M[r][1]*v + M[r][2]*w) & 255) for r in range(3)], 1).astype(np.uint8)
def pat(D): return (D[:, 0] != 0) * 1 + (D[:, 1] != 0) * 2 + (D[:, 2] != 0) * 4
out = {}
N = 1 << 14
for name, idx, M in m.TRIPLETS:
    M2 = np.array(M) % 2
    # (1) exact MSB check
    X = rng.integers(0, 256, (4096, 3), dtype=np.uint8); ok1 = True
    for d in itertools.product((0, 0x80), repeat=3):
        if not any(d): continue
        d = np.array(d, np.uint8); exp = (0x80 * ((M2 @ (d >> 7)) % 2)).astype(np.uint8)
        ok1 &= bool((apply(M, X ^ d) ^ apply(M, X) == exp).all())
    # (2) exact LSB mask check
    ok2 = True
    for b in itertools.product((0, 1), repeat=3):
        if not any(b): continue
        a = (np.array(b) @ M2) % 2
        Y = apply(M, X); lhs = (Y & np.array(b, np.uint8)).sum(1) % 2; rhs = (X & a.astype(np.uint8)).sum(1) % 2
        ok2 &= bool((lhs == rhs).all())
    # sampled per-pattern best DP
    best = np.zeros((8, 8)); typ = []
    cands = [np.array(d, np.uint8) for d in itertools.product((0, 0x40, 0x80, 0xc0), repeat=3) if any(d)]
    cands += [np.array([v if c == k else 0 for c in range(3)], np.uint8) for k in range(3) for v in range(1, 256)]
    cands += [rng.integers(0, 256, 3, dtype=np.uint8) for _ in range(600)]
    for t, d in enumerate(cands):
        if not d.any(): continue
        X = rng.integers(0, 256, (N, 3), dtype=np.uint8)
        D = apply(M, X ^ d) ^ apply(M, X)
        key = D[:, 0].astype(np.int64) << 16 | D[:, 1].astype(np.int64) << 8 | D[:, 2]
        vals, cnt = np.unique(key, return_counts=True)
        pin = int((d[0] != 0) + 2 * (d[1] != 0) + 4 * (d[2] != 0))
        po = ((vals >> 16) & 255 != 0) * 1 + ((vals >> 8) & 255 != 0) * 2 + (vals & 255 != 0) * 4
        for p_, c_ in zip(po, cnt): best[pin, p_] = max(best[pin, p_], c_ / N)
        if t >= len(cands) - 600: typ.append(cnt.max() / N)
    # sampled per-pattern best |corr|
    X = rng.integers(0, 256, (1 << 16, 3), dtype=np.uint8); Y = apply(M, X)
    comps = (0, 1, 2, 3, 0x80, 0xc0)
    def parity(Z, msk):
        z = (Z & np.array(msk, np.uint8)); z = z[:, 0] ^ z[:, 1] ^ z[:, 2]
        return np.unpackbits(z[:, None], axis=1).sum(1) & 1
    PX = {a: parity(X, a) for a in itertools.product(comps, repeat=3) if any(a)}
    PY = {b: parity(Y, b) for b in itertools.product(comps, repeat=3) if any(b)}
    cbest = np.zeros((8, 8))
    for a, pa in PX.items():
        pin = (a[0] != 0) + 2 * (a[1] != 0) + 4 * (a[2] != 0)
        for b, pb in PY.items():
            c = abs(1 - 2 * np.mean(pa ^ pb)); po = (b[0] != 0) + 2 * (b[1] != 0) + 4 * (b[2] != 0)
            cbest[pin, po] = max(cbest[pin, po], c)
    rt = [abs(1 - 2 * np.mean(parity(X, rng.integers(0, 256, 3, dtype=np.uint8)) ^ parity(Y, rng.integers(0, 256, 3, dtype=np.uint8)))) for _ in range(300)]
    out[name] = dict(M=M, msb_dp1_exact=ok1, lsb_corr1_exact=ok2,
        diff_patterns_dp_ge_half=int((best[1:, 1:] >= 0.5).sum()), diff_patterns_dp1=int((best[1:, 1:] >= 0.999).sum()),
        diff_min_over_patterns_of_best_dp_log2=float(np.log2(best[1:, 1:][best[1:, 1:] > 0].min())),
        diff_patterns_seen=int((best[1:, 1:] > 0).sum()),
        diff_typical_random_input_rowmax_dp_median_log2=float(np.log2(np.median(typ))),
        lin_patterns_corr_ge_half=int((cbest[1:, 1:] >= 0.5).sum()), lin_patterns_corr1=int((cbest[1:, 1:] >= 0.999).sum()),
        lin_min_over_patterns_of_best_corr_log2=float(np.log2(max(cbest[1:, 1:][cbest[1:, 1:] > 0].min(), 1e-9))),
        lin_patterns_seen_above_noise=int((cbest[1:, 1:] > 0.05).sum()),
        lin_typical_random_mask_abs_corr_median_log2=float(np.log2(max(np.median(rt), 1e-9))),
        best_dp_table_log2=np.round(np.log2(np.maximum(best[1:, 1:], 1e-9)), 2).tolist(),
        best_corr_table_log2=np.round(np.log2(np.maximum(cbest[1:, 1:], 1e-9)), 2).tolist())
    print(name, {k: v for k, v in out[name].items() if not k.endswith("table_log2")}, flush=True)
json.dump(out, open("runs/stage4_triplets.json", "w"), indent=1)
