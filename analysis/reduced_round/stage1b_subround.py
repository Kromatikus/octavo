"""Stage 1b: sub-round diffusion inside round 1 (and round 2 start), incl. single-shell confinement per layer."""
import json, os, time, numpy as np
from octavo_np import lab_schedule, NPRound
rng = np.random.default_rng(int.from_bytes(os.urandom(8), "big"))
lines = []; out = {}
def log(s): print(s); lines.append(s)
t0 = time.time()
INNER = np.arange(64); OUTER = np.arange(64, 128)
NS, NBASE = 4, 32
log("Round-1 checkpoints, single-byte input differences (4 schedules x 128 positions x 32 bases)")
log("checkpoint | dep.matrix filled | mean active bytes | inner-1-byte diff: outer active frac | outer-1-byte diff: inner active frac")
scheds = [lab_schedule(rng) for _ in range(NS)]
for stop in NPRound.CHECKPOINTS:
    dep = np.zeros((128, 128), bool); ma = []; io = []; oi = []
    for ns in scheds:
        P = rng.integers(0, 256, (128 * NBASE, 128), dtype=np.uint8)
        pos = np.repeat(np.arange(128), NBASE)
        Q = P.copy(); Q[np.arange(len(P)), pos] ^= rng.integers(1, 256, len(P), dtype=np.uint8)
        act = ns.enc_frac(P, 0, stop) != ns.enc_frac(Q, 0, stop)
        for p in range(128): dep[p] |= act[pos == p].any(0)
        ma.append(act.sum(1).mean())
        io.append(act[pos < 64][:, OUTER].mean()); oi.append(act[pos >= 64][:, INNER].mean())
    log(f"  {stop:9s} | {dep.mean()*100:6.2f}% | {np.mean(ma):6.2f} | {np.mean(io):.3f} | {np.mean(oi):.3f}")
    out[stop] = {"dep_filled_pct": float(dep.mean()*100), "mean_active": float(np.mean(ma)),
                 "inner_to_outer_frac": float(np.mean(io)), "outer_to_inner_frac": float(np.mean(oi))}
# SAC at half round (before S2) and right after S2
NPB = 256
for stop in ("cross", "S2", "cross2"):
    ns = scheds[0]; flips = np.zeros((1024, 1024), np.int32)
    for byte in range(128):
        P = rng.integers(0, 256, (8 * NPB, 128), dtype=np.uint8); bits = np.repeat(np.arange(8), NPB)
        Q = P.copy(); Q[:, byte] ^= (1 << bits).astype(np.uint8)
        db = np.unpackbits(ns.enc_frac(P, 0, stop) ^ ns.enc_frac(Q, 0, stop), axis=1, bitorder="little")
        for bit in range(8): flips[byte*8+bit] = db[bits == bit].sum(0, dtype=np.int32)
    p = flips / NPB; null = 0.5/np.sqrt(NPB)*np.sqrt(2*np.log(2*2**20))
    log(f"SAC at round-1 checkpoint '{stop}': mean {p.mean():.4f} max|p-0.5| {np.abs(p-0.5).max():.3f} (null ~{null:.3f}) never-flip cells {(p==0).mean()*100:.2f}%")
    out["sac_" + stop] = {"mean": float(p.mean()), "max_dev": float(np.abs(p-0.5).max()), "null_max": float(null), "zero_frac": float((p==0).mean())}
log(f"elapsed {time.time()-t0:.0f} s")
open("stage1b_output.txt", "w").write("\n".join(lines) + "\n"); json.dump(out, open("stage1b_results.json", "w"), indent=1)
