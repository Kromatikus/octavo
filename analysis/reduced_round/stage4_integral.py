"""Stage 4: integral / square properties (OCT-2). XOR-sum balance per output byte (raw and peeled; the peel
is XOR-linear, so peeled balance = balance at the 'odd2' / 'odd' checkpoint), all-distinct (A) property."""
import json, os, time, numpy as np
from octavo_np import lab_schedule
from stage2b_peeled_lib import cross_unmix
rng = np.random.default_rng(int.from_bytes(os.urandom(8), "big"))
lines = []; out = {"tests": []}
def log(s): print(s, flush=True); lines.append(s)
t0 = time.time()
def make_set(nact, pos):
    n = 256 ** nact; base = rng.integers(0, 256, 128, dtype=np.uint8)
    P = np.tile(base, (n, 1)); idx = np.arange(n)
    for i, p in enumerate(pos): P[:, p] = (idx >> (8 * i)) & 255
    return P
def xsum(Y):
    return np.bitwise_xor.reduce(Y, axis=0)
CHECK = [("0.25 (after shell bridge)", 0, "shell"), ("0.4 (after bar)", 0, "bar"), ("0.45 (after bow)", 0, "bow"), ("0.5 (after odd_restack)", 0, "odd"), ("0.5 (after cross)", 0, "cross"),
         ("0.6 (after S2)", 0, "S2"), ("0.9 (after bow2)", 0, "bow2"), ("1 (peeled=odd2)", 1, None),
         ("1.5 (after cross, round 2)", 1, "cross"), ("2", 2, None)]
TR = 8
best = {}
for nact, label in ((1, "1 active byte (256 texts)"), (2, "2 active bytes, same face (2^16)"), (2, "2 active bytes, one per shell (2^16)")):
    log(f"== {label}, {TR} trials (fresh schedule + constants each) ==")
    for cname, full, stop in CHECK:
        cnt_raw, cnt_peel, cnt_perm, cnt_in, cnt_out = [], [], [], [], []
        for t in range(TR):
            ns = lab_schedule(rng)
            if nact == 1: pos = [int(rng.integers(128))]
            elif "same face" in label: f = int(rng.integers(16)); b = rng.choice(8, 2, replace=False); pos = [8*f+int(b[0]), 8*f+int(b[1])]
            else: pos = [int(rng.integers(64)), int(rng.integers(64, 128))]
            P = make_set(nact, pos); Y = ns.enc_frac(P, full, stop)
            b = xsum(Y) == 0; cnt_raw.append(int(b.sum())); cnt_in.append(int(b[:64].sum())); cnt_out.append(int(b[64:].sum()))
            cnt_peel.append(int((xsum(cross_unmix(Y)) == 0).sum()))
            if nact == 1: cnt_perm.append(sum(len(np.unique(Y[:, j])) == 256 for j in range(128)))
        nb, npl = min(cnt_raw), min(cnt_peel); npm = min(cnt_perm) if nact == 1 else None
        log(f"  {cname:28s}: balanced bytes per trial raw min {nb:3d} mean {np.mean(cnt_raw):6.1f} (inner/outer mean {np.mean(cnt_in):.1f}/{np.mean(cnt_out):.1f}), peeled min {npl:3d} mean {np.mean(cnt_peel):6.1f}" +
            (f", all-distinct min {npm}" if npm is not None else "") + f"  (random ~0.5)  [{time.time()-t0:.0f}s]")
        out["tests"].append({"set": label, "checkpoint": cname, "balanced_raw": nb, "balanced_peeled": npl, "all_distinct": npm})
        if nb >= 3 or npl >= 3: best[label] = cname
    log(f"  -> last checkpoint with a balanced byte: {best.get(label)}")
# 3 active bytes (2^24): one trial at r=1 (peeled), chunked XOR-sum
log("== 3 active bytes in one face (2^24 texts), r=1 peeled and r=0.9 (bow2), 2 trials ==")
for t in range(0):   # done once in run 1 (see stage4_run1_partial_output.txt); too slow to repeat
    ns = lab_schedule(rng); f = int(rng.integers(16)); pos = [8*f, 8*f+1, 8*f+2]; base = rng.integers(0, 256, 128, dtype=np.uint8)
    acc1 = np.zeros(128, np.uint8); acc2 = np.zeros(128, np.uint8)
    CH = 1 << 18
    for c in range((1 << 24) // CH):
        idx = np.arange(c*CH, (c+1)*CH); P = np.tile(base, (CH, 1))
        for i, p in enumerate(pos): P[:, p] = (idx >> (8*i)) & 255
        acc1 ^= xsum(cross_unmix(ns.enc_frac(P, 1, None))); acc2 ^= xsum(ns.enc_frac(P, 0, "bow2"))
    log(f"  trial {t}: r=1 peeled balanced bytes {(acc1==0).sum()}/128 (random ~0.5); r=0.9 bow2 balanced {(acc2==0).sum()}/128  [{time.time()-t0:.0f}s]")
    out["tests"].append({"set": "3 bytes 2^24", "trial": t, "r1_peeled_balanced": int((acc1==0).sum()), "bow2_balanced": int((acc2==0).sum())})
out["last_balanced"] = best
open("stage4_output.txt", "w").write("\n".join(lines) + "\n"); json.dump(out, open("stage4_results.json", "w"), indent=1)
