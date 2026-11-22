"""Stage 3a: truncated-trail clustering. For the optimal (per-op) trail of R rounds, fix its input and output activity patterns and
enumerate ALL truncated trails with the same patterns and <= a_min + K active S-boxes (CP-SAT, 1 worker, capped).
Cluster factor = sum_t 2^(-6 (a_t - a_min)): how much the summed (truncated-differential / hull) bound exceeds the single best trail
if every truncated trail reached the worst-case 2^-6 per S-box. Per-op model -> includes unrealisable trails -> over-counts (cautious).
usage: stage3_count.py mode R --seed S --sched i --start r --K k --cap s"""
import argparse, json, time, os, sys, collections
sys.dont_write_bytecode = True
os.environ.setdefault("OCT_EXACT", "0")
import model
from ortools.sat.python import cp_model
ap = argparse.ArgumentParser()
ap.add_argument("mode"); ap.add_argument("R", type=int)
ap.add_argument("--seed", type=int, default=20261121); ap.add_argument("--sched", type=int, default=0)
ap.add_argument("--start", type=int, default=0); ap.add_argument("--K", type=int, default=4)
ap.add_argument("--cap", type=float, default=300); ap.add_argument("--findcap", type=float, default=300)
a = ap.parse_args()
ns = model.schedules(a.sched + 1, a.seed)[a.sched]
rops = [model.round_ops(ns.rounds[a.start + r]) for r in range(a.R)]
md, obj, xin, sb, states = model.build(rops, a.mode); md.Minimize(obj)
sv = cp_model.CpSolver(); sv.parameters.max_time_in_seconds = a.findcap; sv.parameters.num_workers = 4
st = sv.Solve(md); amin = int(sv.ObjectiveValue()); opt = st == cp_model.OPTIMAL
pin = [sv.Value(v) for v in xin]; pout = [sv.Value(v) for v in states[-1]]
md2, obj2, xin2, sb2, states2 = model.build(rops, a.mode)
for v, b in zip(xin2, pin): md2.Add(v == b)
for v, b in zip(states2[-1], pout): md2.Add(v == b)
levels = {}
for lev in range(amin, amin + a.K + 1):     # enumerate each exact cost level separately, each with its own cap
    md2, obj2, xin2, sb2, states2 = model.build(rops, a.mode)
    for v, b in zip(xin2, pin): md2.Add(v == b)
    for v, b in zip(states2[-1], pout): md2.Add(v == b)
    md2.Add(obj2 == lev)
    cnt = [0]; sets = set()
    class CB(cp_model.CpSolverSolutionCallback):
        def __init__(s): super().__init__()
        def on_solution_callback(s):
            cnt[0] += 1; sets.add(tuple(q for q, v in enumerate(sb2) if s.Value(v)))
    sv2 = cp_model.CpSolver(); sv2.parameters.enumerate_all_solutions = True; sv2.parameters.num_workers = 1
    sv2.parameters.max_time_in_seconds = a.cap / (a.K + 1)
    t = time.time(); st2 = sv2.Solve(md2, CB())
    levels[lev] = dict(count=cnt[0], distinct_sbox_sets=len(sets), complete=sv2.StatusName(st2) in ("OPTIMAL", "INFEASIBLE"), status=sv2.StatusName(st2), time_s=round(time.time() - t, 1))
    print(lev, levels[lev], flush=True)
hist = {k: v["count"] for k, v in levels.items()}
fac = sum(c * 2.0 ** (-6 * (k - amin)) for k, c in hist.items())
fac_sets = sum(v["distinct_sbox_sets"] * 2.0 ** (-6 * (k - amin)) for k, v in levels.items())
done = "per-level"; dt = sum(v["time_s"] for v in levels.values())
out = dict(mode=a.mode, R=a.R, seed=a.seed, sched=a.sched, start=a.start, amin=amin, amin_optimal=opt, K=a.K,
           input_active=sum(pin), output_active=sum(pout), levels=levels, time_s=round(dt, 1),
           count_by_active=hist, total=sum(hist.values()), cluster_factor_6bit_lower=fac, cluster_factor_distinct_sbox_sets_lower=fac_sets,
           note="per level: complete=True means every truncated trail at that exact active count was enumerated; otherwise the count is a lower count, so the factor is a lower estimate")
print(json.dumps(out), flush=True)
json.dump(out, open(f"runs/count_{a.mode}_R{a.R}_seed{a.seed}_s{a.sched}_r{a.start}_K{a.K}.json", "w"), indent=1)
