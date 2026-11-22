"""Stage 2b: differential tests with the free (unkeyed, XOR-linear) final cross_staff_mix peeled off,
positive controls to show the test has power, and a larger 2^20-pair test at r=1."""
import json, os, time, math, numpy as np
from octavo_np import lab_schedule, NPRound
rng = np.random.default_rng(int.from_bytes(os.urandom(8), "big"))
lines = []; out = {"tests": []}
def log(s): print(s, flush=True); lines.append(s)
t0 = time.time()
def wh_z(chi2, k): return ((chi2 / k) ** (1/3) - (1 - 2/(9*k))) / math.sqrt(2/(9*k))
from octavo_np import MUL
INV = np.zeros((256, 256), np.uint8)
import harness; m = harness.m
MI = m.MIX2_INV
def cross_unmix(D):
    x = D.reshape(-1, 16, 8).copy()
    for matching in reversed(m.CROSS_LAYERS):
        for f, h in matching:
            f, h = sorted((f, h)); a, b = x[:, f, :], x[:, h, :]
            x[:, f, :], x[:, h, :] = MUL[MI[0][0]][a] ^ MUL[MI[0][1]][b], MUL[MI[1][0]][a] ^ MUL[MI[1][1]][b]
    return x.reshape(-1, 128)
# sanity: cross_unmix(enc_upto cross) == enc_upto odd
ns = lab_schedule(rng); P = rng.integers(0, 256, (16, 128), dtype=np.uint8)
assert (cross_unmix(ns.enc_frac(P, 0, "cross")) == ns.enc_frac(P, 0, "odd")).all()
assert (cross_unmix(ns.enc_frac(P, 1, None)) == ns.enc_frac(P, 0, "odd2")).all()
log("cross_unmix verified: peeling the unkeyed cross_staff_mix maps 'cross'->'odd' and round output->'odd2' exactly")

def stats(D, N):
    chi = np.empty(128); zero = np.empty(128)
    for j in range(128):
        h = np.bincount(D[:, j], minlength=256); chi[j] = ((h - N/256)**2).sum() / (N/256); zero[j] = h[0]
    zc = max(wh_z(c, 255) for c in chi)
    cb = np.unpackbits(D, axis=1).sum(0, dtype=np.int64); zb = (np.abs(cb - N/2) / math.sqrt(N/4)).max()
    inactive = int((zero == N).sum())
    return zc, zb, inactive

N = 1 << 16; NS = 3; THRESH = 5.0
CASES = [("0.5 raw (control: before cross)", 0, "odd", False), ("0.5 peeled", 0, "cross", True),
         ("1 peeled", 1, None, True), ("1.5 peeled", 1, "cross", True), ("2 peeled", 2, None, True)]
best = None
for lname, full, stop, peel in CASES:
    hits = 0
    for kind in ("byte", "bit", "inner-shell"):
        v = np.zeros(128, np.uint8)
        if kind == "byte": v[int(rng.integers(128))] = int(rng.integers(1, 256))
        elif kind == "bit": b = int(rng.integers(1024)); v[b//8] = 1 << (b % 8)
        else: v[:64] = rng.integers(1, 256, 64, dtype=np.uint8)
        res = []
        for k in range(NS):
            ns = lab_schedule(rng); P = rng.integers(0, 256, (N, 128), dtype=np.uint8)
            D = ns.enc_frac(P, full, stop) ^ ns.enc_frac(P ^ v, full, stop)
            if peel: D = cross_unmix(D)
            res.append(stats(D, N))
        zc = max(r[0] for r in res); zb = max(r[1] for r in res); ina = min(r[2] for r in res)
        hit = zc > THRESH or zb > THRESH or ina > 0; hits += hit
        log(f"  r={lname:32s} {kind:11s}: max byte-chi z {zc:9.2f}  max bit z {zb:8.2f}  always-zero diff bytes {ina:3d}  {'DISTINGUISHED' if hit else '-'}")
        out["tests"].append({"case": lname, "diff": kind, "zc": float(zc), "zb": float(zb), "inactive_bytes": ina, "distinguished": bool(hit)})
    log(f"r={lname}: {hits}/3 distinguished  [{time.time()-t0:.0f}s]")
    if hits and peel: best = lname

# bigger sample at r=1 peeled: 2^20 pairs, one schedule per difference, chunked
NB = 1 << 20; CH = 1 << 17
for kind in ("byte", "bit"):
    v = np.zeros(128, np.uint8)
    if kind == "byte": v[int(rng.integers(128))] = int(rng.integers(1, 256))
    else: b = int(rng.integers(1024)); v[b//8] = 1 << (b % 8)
    ns = lab_schedule(rng); H = np.zeros((128, 256), np.int64); cb = np.zeros(1024, np.int64)
    for c in range(NB // CH):
        P = rng.integers(0, 256, (CH, 128), dtype=np.uint8)
        D = cross_unmix(ns.enc(P, 1, False) ^ ns.enc(P ^ v, 1, False))
        for j in range(128): H[j] += np.bincount(D[:, j], minlength=256)
        cb += np.unpackbits(D, axis=1).sum(0, dtype=np.int64)
    chi = ((H - NB/256)**2).sum(1) / (NB/256); zc = max(wh_z(c, 255) for c in chi); zb = (np.abs(cb - NB/2)/math.sqrt(NB/4)).max()
    hit = zc > THRESH or zb > THRESH
    log(f"  r=1 peeled, 2^20 pairs, {kind}: max byte-chi z {zc:.2f}  max bit z {zb:.2f}  {'DISTINGUISHED' if hit else '-'}  [{time.time()-t0:.0f}s]")
    out["tests"].append({"case": "1 peeled 2^20", "diff": kind, "zc": float(zc), "zb": float(zb), "distinguished": bool(hit)})
out["max_distinguished_peeled"] = best
log(f"max distinguished (with free peel of final cross_staff_mix): {best}")
open("stage2b_output.txt", "w").write("\n".join(lines) + "\n"); json.dump(out, open("stage2b_results.json", "w"), indent=1)
