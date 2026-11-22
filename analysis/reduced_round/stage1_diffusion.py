"""Stage 1: diffusion / avalanche per round (OCT-2). Uses octavo_np (checked vs harness.enc_r)."""
import json, os, time, numpy as np
from octavo_np import lab_schedule
rng = np.random.default_rng(int.from_bytes(os.urandom(8), "big"))
RMAX = 4; out = {}; lines = []
def log(s): print(s); lines.append(s)
t0 = time.time()
INNER = np.arange(64); OUTER = np.arange(64, 128)

# (a) byte dependency matrix and active bytes from a single-byte difference
NS, NBASE = 4, 64
dep = np.zeros((RMAX + 1, 128, 128), dtype=bool)
minact = np.full((RMAX + 1,), 999); meanact = np.zeros(RMAX + 1); cnt = 0
for k in range(NS):
    ns = lab_schedule(rng)
    P = rng.integers(0, 256, (128 * NBASE, 128), dtype=np.uint8)
    pos = np.repeat(np.arange(128), NBASE)
    d = rng.integers(1, 256, len(P), dtype=np.uint8)
    Q = P.copy(); Q[np.arange(len(P)), pos] ^= d
    for (r, a), (_, b) in zip(ns.enc_trace(P, RMAX), ns.enc_trace(Q, RMAX)):
        act = a != b
        for p in range(128): dep[r, p] |= act[pos == p].any(axis=0)
        na = act.sum(1); minact[r] = min(minact[r], na.min()); meanact[r] += na.mean() / NS
full_r = next((r for r in range(1, RMAX + 1) if dep[r].all()), None)
log("(a) single-byte input difference (4 schedules x 128 positions x 64 bases, random nonzero delta)")
for r in range(1, RMAX + 1):
    log(f"  r={r}: dependency matrix filled {dep[r].mean()*100:6.2f}%  min/mean active output bytes {minact[r]}/{meanact[r]:.2f} of 128")
log(f"  rounds to full byte dependency (every input byte reaches every output byte): {full_r}")
out["byte_dependency"] = {"filled_pct": {r: float(dep[r].mean()*100) for r in range(1, RMAX+1)},
                          "min_active": {r: int(minact[r]) for r in range(1, RMAX+1)},
                          "mean_active": {r: float(meanact[r]) for r in range(1, RMAX+1)}, "rounds_to_full": full_r}

# (b) bit avalanche / SAC matrix 1024 x 1024
NSB, NPB = 2, 512
log(f"(b) bit avalanche: {NSB} schedules x 1024 input bits x {NPB} bases; SAC matrix 1024x1024 per round")
sac = {}
for k in range(NSB):
    ns = lab_schedule(rng)
    flips = np.zeros((RMAX + 1, 1024, 1024), dtype=np.int32)
    for byte in range(128):
        P = rng.integers(0, 256, (8 * NPB, 128), dtype=np.uint8)
        bits = np.repeat(np.arange(8), NPB)
        Q = P.copy(); Q[:, byte] ^= (1 << bits).astype(np.uint8)
        for (r, a), (_, b) in zip(ns.enc_trace(P, RMAX), ns.enc_trace(Q, RMAX)):
            db = np.unpackbits(a ^ b, axis=1, bitorder="little")  # (8*NPB, 1024)
            for bit in range(8):
                flips[r, byte * 8 + bit] += db[bits == bit].sum(0, dtype=np.int32)
    for r in range(1, RMAX + 1):
        p = flips[r] / NPB
        sac.setdefault(r, []).append((float(p.mean()), float(np.abs(p - 0.5).max()), float((p == 0).mean()), float(np.abs(p-0.5).mean())))
null_max = 0.5 / np.sqrt(NPB) * np.sqrt(2 * np.log(2 * 1024 * 1024))
log(f"  null (ideal cipher) expected max |p-0.5| ~ {null_max:.3f} at {NPB} samples per cell")
sac_out = {}
for r in range(1, RMAX + 1):
    v = sac[r]; mean = np.mean([x[0] for x in v]); mx = max(x[1] for x in v); z = max(x[2] for x in v); md = np.mean([x[3] for x in v])
    passed = mx < 1.3 * null_max and z == 0
    log(f"  r={r}: mean flip prob {mean:.4f}  max|p-0.5| {mx:.3f}  mean|p-0.5| {md:.4f}  never-flipping cells {z*100:.2f}%  SAC {'PASS' if passed else 'FAIL'}")
    sac_out[r] = {"mean": mean, "max_dev": mx, "mean_dev": md, "zero_cells_frac": z, "pass": bool(passed)}
sac_r = next((r for r in range(1, RMAX + 1) if sac_out[r]["pass"]), None)
log(f"  rounds to bit-level SAC indistinguishable at this sample size: {sac_r}")
out["sac"] = sac_out; out["sac_null_max"] = float(null_max); out["rounds_to_sac"] = sac_r

# (c) single-shell confinement: difference only in inner (or outer) shell
log("(c) shell confinement: input difference confined to one shell")
NC = 4096; shell_out = {}
for label, src, dst, mode in (("inner 1 byte", INNER, OUTER, 1), ("inner all 64", INNER, OUTER, 64),
                              ("outer 1 byte", OUTER, INNER, 1), ("outer all 64", OUTER, INNER, 64)):
    res = {r: [] for r in range(1, RMAX + 1)}
    for k in range(4):
        ns = lab_schedule(rng)
        P = rng.integers(0, 256, (NC, 128), dtype=np.uint8); Q = P.copy()
        if mode == 1:
            pos = rng.choice(src, NC); Q[np.arange(NC), pos] ^= rng.integers(1, 256, NC, dtype=np.uint8)
        else:
            Q[:, src] ^= rng.integers(1, 256, (NC, 64), dtype=np.uint8)
        for (r, a), (_, b) in zip(ns.enc_trace(P, RMAX), ns.enc_trace(Q, RMAX)):
            act = a != b
            hw_dst = np.unpackbits((a ^ b)[:, dst], axis=1).sum(1); hw_src = np.unpackbits((a ^ b)[:, src], axis=1).sum(1)
            res[r].append((act[:, dst].sum(1).min(), act[:, dst].mean(), act[:, src].mean(), (hw_dst / np.maximum(hw_dst + hw_src, 1)).mean()))
    shell_out[label] = {}
    for r in range(1, RMAX + 1):
        mn = min(x[0] for x in res[r]); fd = np.mean([x[1] for x in res[r]]); fs = np.mean([x[2] for x in res[r]]); share = np.mean([x[3] for x in res[r]])
        log(f"  {label:13s} r={r}: other-shell active bytes min {mn:2d}/64, mean frac {fd:.3f}; own-shell frac {fs:.3f}; other-shell share of flipped bits {share:.3f} (ideal 0.5)")
        shell_out[label][r] = {"other_min_active": int(mn), "other_frac": float(fd), "own_frac": float(fs), "other_bit_share": float(share)}
out["shell_confinement"] = shell_out
log(f"elapsed {time.time()-t0:.0f} s")
open("stage1_output.txt", "w").write("\n".join(lines) + "\n")
json.dump(out, open("stage1_results.json", "w"), indent=1)
