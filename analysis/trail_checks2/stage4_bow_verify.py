"""Check the bow-stroke tables against octavo_np: (a) a single-stroke function, composed over the 7 strokes, equals octavo_np._bow;
(b) sampled DP / correlation of the table's argmax transitions match the exact table values."""
import sys, json
sys.dont_write_bytecode = True
import os
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "trail_search")))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "reduced_round")))
import numpy as np, octavo_np as onp
m = onp.m; R = onp.ROTL
def stroke(x, s):
    (i, j, p), k = m.BOW_STROKES[s], m.BOW_PRESSURE_ROT[s]
    pr = R[x[:, :, p], k].astype(np.int32)
    r1 = m.BOW_ROT_BASE + pr % m.BOW_ROT_MOD; r2 = m.BOW_ROT_BASE + (pr >> m.BOW_R2_SHIFT) % m.BOW_ROT_MOD
    u = ((x[:, :, i].astype(np.int32) + R[x[:, :, j], r1]) & 255).astype(np.uint8); v = x[:, :, j] ^ R[u, r2]
    x[:, :, i], x[:, :, j] = u, v
rng = np.random.default_rng(7)
X = rng.integers(0, 256, (20000, 16, 8), dtype=np.uint8); A = X.copy(); B = X.copy()
onp.NPRound._bow(A)
for s in range(7): stroke(B, s)
res = dict(single_stroke_composition_equals_octavo_np_bow=bool((A == B).all()))
T = json.load(open("runs/stage4_bow_tables.json"))
N = 1 << 20
for s in (0, 3, 6):      # strokes with pressure rotation k = 0, 3, 5
    (i, j, p) = m.BOW_STROKES[s]
    for pat, hx in T["diff_argmax_hex_du_dv_du2_dv2"].items():
        if hx == "00000000": continue
        du, dv, du2, dv2 = (int(hx[q:q+2], 16) for q in (0, 2, 4, 6))
        X = rng.integers(0, 256, (N, 1, 8), dtype=np.uint8); Y = X.copy(); Y[:, 0, i] ^= du; Y[:, 0, j] ^= dv
        stroke(X, s); stroke(Y, s)
        hit = ((X[:, 0, i] ^ Y[:, 0, i]) == du2) & ((X[:, 0, j] ^ Y[:, 0, j]) == dv2)
        res[f"stroke{s} diff {pat}"] = [T["diff_max_dp"][pat], round(float(hit.mean()), 5)]
    for pat, hx in T["lin_argmax_hex_au_av_bu_bv"].items():
        if hx == "00000000": continue
        au, av, bu, bv = (int(hx[q:q+2], 16) for q in (0, 2, 4, 6))
        X = rng.integers(0, 256, (N, 1, 8), dtype=np.uint8)
        par = lambda z: np.unpackbits(z[:, None], axis=1).sum(1) & 1
        lhs = par(X[:, 0, i] & au) ^ par(X[:, 0, j] & av); stroke(X, s); rhs = par(X[:, 0, i] & bu) ^ par(X[:, 0, j] & bv)
        res[f"stroke{s} lin {pat}"] = [T["lin_max_abs_corr"][pat], round(float(abs(1 - 2 * np.mean(lhs ^ rhs))), 5)]
print(json.dumps(res, indent=0)); json.dump(res, open("runs/stage4_bow_verify.json", "w"), indent=1)
