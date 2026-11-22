"""Stage 3: empirical linear correlations: input masks (1024 single bits + 4 bytes x 255 byte masks) vs
1024 single output bits (raw and with the free unkeyed cross_staff_mix peeled), + LAT bound (OCT-2)."""
import json, os, time, math, numpy as np
from octavo_np import lab_schedule
from stage2b_peeled_lib import cross_unmix
rng = np.random.default_rng(int.from_bytes(os.urandom(8), "big"))
lines = []; out = {"tests": []}
def log(s): print(s, flush=True); lines.append(s)
t0 = time.time()
PAR = np.array([bin(x).count("1") & 1 for x in range(256)], np.uint8)
N = 1 << 18; CH = 1 << 14; NS = 2; THRESH = 6.0
LEVELS = [("0.5 raw", 0, "cross", False), ("0.5 peeled", 0, "cross", True), ("1 peeled", 1, None, True),
          ("1.5 peeled", 1, "cross", True), ("2 peeled", 2, None, True)]
null = math.sqrt(2 * math.log(2 * 2044 * 1024)) / math.sqrt(N)
log(f"N = 2^18 random plaintexts per schedule, {NS} schedules; 2044 input masks x 1024 output bits; null max |corr| ~ {null:.4f}; flag |corr|*sqrt(N) > {THRESH}")
best = None
for lname, full, stop, peel in LEVELS:
    hits = 0; worst = 0
    for k in range(NS):
        ns = lab_schedule(rng); bytes_sel = rng.choice(128, 4, replace=False)
        C = np.zeros((2044, 1024), np.float64)
        for c in range(N // CH):
            P = rng.integers(0, 256, (CH, 128), dtype=np.uint8)
            Y = ns.enc_frac(P, full, stop)
            if peel: Y = cross_unmix(Y)
            Yb = np.unpackbits(Y, axis=1, bitorder="little").astype(np.float32) * -2 + 1
            Xb = np.unpackbits(P, axis=1, bitorder="little").astype(np.float32) * -2 + 1
            Xm = np.empty((CH, 1020), np.float32)
            for i, b in enumerate(bytes_sel):
                Xm[:, i*255:(i+1)*255] = 1 - 2.0 * PAR[np.bitwise_and(P[:, b:b+1], np.arange(1, 256, dtype=np.uint8)[None, :])]
            X = np.concatenate([Xb, Xm], axis=1)
            C += X.T @ Yb
        C /= N
        z = np.abs(C).max() * math.sqrt(N); worst = max(worst, z)
        i, j = np.unravel_index(np.abs(C).argmax(), C.shape)
        hit = z > THRESH; hits += hit
        log(f"  r={lname:10s} sched {k}: max |corr| {np.abs(C).max():.4f} (z {z:.2f}) at input mask #{i} / output bit {j}; #|z|>{THRESH}: {(np.abs(C)*math.sqrt(N) > THRESH).sum()}  {'DISTINGUISHED' if hit else '-'}")
        out["tests"].append({"level": lname, "schedule": k, "max_abs_corr": float(np.abs(C).max()), "z": float(z),
                             "n_over": int((np.abs(C)*math.sqrt(N) > THRESH).sum()), "distinguished": bool(hit)})
    log(f"r={lname}: {hits}/{NS} schedules distinguished, max z {worst:.2f}  [{time.time()-t0:.0f}s]")
    if hits: best = lname
out["max_distinguished"] = best; out["N"] = N; out["null_max_corr"] = null
log(f"max linearly distinguished level: {best}")
log("LAT bound: keyed S-box max |corr| 2^-3; >=1 active S-box in each of 4 S-box layers per round -> trail |corr| <= 2^-12 per round (ELP 2^-24).")
open("stage3_output.txt", "w").write("\n".join(lines) + "\n"); json.dump(out, open("stage3_results.json", "w"), indent=1)
