"""Stage 5: simple algebraic tests: cube / higher-order-differential zero-sums, degree bounds per checkpoint (OCT-2).
All-1024-bit zero-sum over a d-cube => degree < d in those variables; a nonzero sum => degree >= d."""
import json, os, time, numpy as np
from octavo_np import lab_schedule
from stage2b_peeled_lib import cross_unmix
rng = np.random.default_rng(int.from_bytes(os.urandom(8), "big"))
lines = []; out = {"tests": []}
def log(s): print(s, flush=True); lines.append(s)
t0 = time.time()
CHECK = [("0.25 shell", 0, "shell", False), ("0.45 bow", 0, "bow", False), ("0.5 = odd (peeled cross)", 0, "odd", False),
         ("0.6 S2", 0, "S2", False), ("0.9 bow2", 0, "bow2", False), ("1 peeled (odd2)", 1, None, True),
         ("1.5 peeled", 1, "cross", True), ("2 peeled", 2, None, True)]
DS = [2, 4, 6, 8, 10, 12, 14, 16, 18, 20]
T = 3
def cube_set(d, flavor):
    base = rng.integers(0, 256, 128, dtype=np.uint8)
    if flavor == "packed":    # d bits packed into consecutive bytes of one face (wrap to next face)
        start = int(rng.integers(0, 16)) * 64; bits = [(start + i) % 1024 for i in range(d)]
    else:                     # one bit in each of d distinct bytes
        bys = rng.choice(128, d, replace=False); bits = [int(b) * 8 + int(rng.integers(8)) for b in bys]
    n = 1 << d; idx = np.arange(n); P = np.tile(base, (n, 1))
    for i, b in enumerate(bits):
        P[:, b // 8] = (P[:, b // 8] & ~np.uint8(1 << (b % 8))) | (((idx >> i) & 1).astype(np.uint8) << (b % 8))
    return P
DS = [4, 8, 12, 16, 20]
THR = 0.55   # zero-bit fraction over 1024 bits x 3 trials; random 0.5, sigma ~0.009
summary = {}
for flavor in ("packed", "spread"):
    log(f"== {flavor} cubes, {T} trials per (checkpoint, d); distinguisher if zero-sum bit fraction > {THR} (random 0.5) ==")
    random_streak = 0
    for cname, full, stop, peel in CHECK:
        if random_streak >= 2:
            log(f"  {cname:26s}: skipped (two earlier checkpoints already random at every d)"); continue
        row = {}; zs = None
        for d in DS:
            fr = []
            for t in range(T):
                ns = lab_schedule(rng); Y = ns.enc_frac(cube_set(d, flavor), full, stop)
                if peel: Y = cross_unmix(Y)
                s_ = np.bitwise_xor.reduce(Y, axis=0); fr.append(1 - np.unpackbits(s_).mean())
            row[d] = float(np.mean(fr))
            if min(fr) == 1.0 and zs is None: zs = d
            out["tests"].append({"flavor": flavor, "checkpoint": cname, "d": d, "zero_bit_frac": row[d], "all_zero": bool(min(fr) == 1.0)})
        dist = max(row.values()) > THR
        random_streak = 0 if dist else random_streak + 1
        log(f"  {cname:26s}: zero-sum frac " + " ".join(f"d{d}:{v:.3f}" for d, v in row.items()) +
            (f" | full zero-sum from d={zs} (degree < {zs})" if zs else "") + (" DISTINGUISHED" if dist else " random") + f"  [{time.time()-t0:.0f}s]")
        summary[f"{flavor}|{cname}"] = {"fracs": row, "full_zero_sum_d": zs, "distinguished": bool(dist)}
out["summary"] = summary
open("stage5_output.txt", "w").write("\n".join(lines) + "\n"); json.dump(out, open("stage5_results.json", "w"), indent=1)
