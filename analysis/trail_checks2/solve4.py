"""OCT-4 Stage 4: min trail WEIGHT (bits, -log2 of EDP / ELP bound) with S-boxes at 6 bits each (DP<=2^-6; corr^2<=2^-6)
and bow strokes weighted by the exact stroke tables (runs/stage4_bow_tables.json), floored to 0.1 bit. Triplets: 0 credit.
usage: solve4.py mode R [--seed S --sched i --start r --cap s --workers w --nobow]"""
import argparse, json, time, os, sys, math
sys.dont_write_bytecode = True
os.environ.setdefault("OCT_EXACT", "0")
import model4 as model
from ortools.sat.python import cp_model
ap = argparse.ArgumentParser()
ap.add_argument("mode"); ap.add_argument("R", type=int)
ap.add_argument("--seed", type=int, default=20261121); ap.add_argument("--sched", type=int, default=0)
ap.add_argument("--start", type=int, default=0); ap.add_argument("--cap", type=float, default=600)
ap.add_argument("--workers", type=int, default=4); ap.add_argument("--nobow", action="store_true"); ap.add_argument("--tag", default="")
a = ap.parse_args()
T = json.load(open("runs/stage4_bow_tables.json"))
key = "diff_max_dp" if a.mode == "diff" else "lin_max_abs_corr"
nm = {1: "u", 2: "v", 3: "uv"}
W = {}
for pin in (1, 2, 3):
    for pout in (1, 2, 3):
        x = T[key][f"{nm[pin]}->{nm[pout]}'"]
        if x <= 0: W[(pin, pout)] = None
        else:
            bits = -math.log2(x) * (1 if a.mode == "diff" else 2)
            W[(pin, pout)] = int(math.floor(bits * 10 + 1e-9))
model.BOW_W = None if a.nobow else W
ns = model.schedules(a.sched + 1, a.seed)[a.sched]
rops = [model.round_ops(ns.rounds[a.start + r]) for r in range(a.R)]
md, obj, xin, sb, states = model.build(rops, a.mode)
extra = model.build.extra
wobj = 60 * sum(sb) + sum(w * v for w, v in extra)
md.Minimize(wobj)
sv = cp_model.CpSolver(); sv.parameters.max_time_in_seconds = a.cap; sv.parameters.num_workers = a.workers
t = time.time(); st = sv.Solve(md); dt = time.time() - t
name = sv.StatusName(st)
out = dict(mode=a.mode, R=a.R, seed=a.seed, sched=a.sched, start=a.start, cap=a.cap, workers=a.workers, bow_weights_tenths=None if a.nobow else {f"{k[0]}->{k[1]}": v for k, v in W.items()},
           status=name, time_s=round(dt, 1))
if st in (cp_model.OPTIMAL, cp_model.FEASIBLE):
    out.update(best_weight_bits=sv.ObjectiveValue() / 10, proved_weight_bits=sv.BestObjectiveBound() / 10,
               sboxes_in_best=int(sum(sv.Value(v) for v in sb)), bow_bits_in_best=sum(w * sv.Value(v) for w, v in extra) / 10,
               bow_terms_active=int(sum(sv.Value(v) for w, v in extra)))
else:
    out.update(proved_weight_bits=sv.BestObjectiveBound() / 10)
print(json.dumps(out), flush=True)
os.makedirs("runs", exist_ok=True)
json.dump(out, open(f"runs/w_{a.mode}_R{a.R}_seed{a.seed}_s{a.sched}_r{a.start}{'_nobow' if a.nobow else ''}{a.tag}.json", "w"), indent=1)
