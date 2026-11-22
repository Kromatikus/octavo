"""Run one CP-SAT min-active-S-box search. usage: solve.py mode R [--shell inner|outer] [--confine] [--sched i] [--cap s] [--per-op]"""
import argparse, json, time, sys
import model
from ortools.sat.python import cp_model
ap = argparse.ArgumentParser()
ap.add_argument("mode"); ap.add_argument("R", type=int)
ap.add_argument("--shell"); ap.add_argument("--confine", action="store_true")
ap.add_argument("--sched", type=int, default=0); ap.add_argument("--cap", type=float, default=600)
ap.add_argument("--workers", type=int, default=4); ap.add_argument("--tag", default="")
ap.add_argument("--start", type=int, default=0)
ap.add_argument("--hint", type=int, default=0, help="known upper bound to add as constraint (obj <= hint)")
a = ap.parse_args()
ns = model.schedules(a.sched + 1)[a.sched]
rops = [model.round_ops(ns.rounds[a.start + r]) for r in range(a.R)]
md, obj, xin, sb, states = model.build(rops, a.mode, shell=a.shell, confine=(a.shell if a.confine else None))
md.Minimize(obj)
if a.hint: md.Add(obj <= a.hint)
sv = cp_model.CpSolver(); sv.parameters.max_time_in_seconds = a.cap; sv.parameters.num_workers = a.workers
t = time.time(); st = sv.Solve(md); dt = time.time() - t
name = {cp_model.OPTIMAL: "OPTIMAL", cp_model.FEASIBLE: "FEASIBLE(timeout)", cp_model.INFEASIBLE: "INFEASIBLE", cp_model.UNKNOWN: "UNKNOWN(timeout)"}[st]
out = dict(mode=a.mode, R=a.R, start=a.start, shell=a.shell, confine=a.confine, sched=a.sched, cap=a.cap, status=name, time_s=round(dt, 1),
           best_found=(int(sv.ObjectiveValue()) if st in (cp_model.OPTIMAL, cp_model.FEASIBLE) else None),
           proved_lower=int(sv.BestObjectiveBound()) if st != cp_model.INFEASIBLE else None)
if st in (cp_model.OPTIMAL, cp_model.FEASIBLE):
    out["input_active"] = [i for i, v in enumerate(xin) if sv.Value(v)]
    per = len(sb) // a.R; layers = [128, 32, 128, 128, 32, 128]
    cnt = []
    for r in range(a.R):
        seg = sb[r * per:(r + 1) * per]; pos = 0; c = []
        for L in layers: c.append(sum(sv.Value(v) for v in seg[pos:pos + L])); pos += L
        cnt.append(c)
    out["active_per_round_layer[S,B0,odd,S2,B0',odd']"] = cnt
    out["round_output_active"] = [sum(sv.Value(v) for v in s) for s in states]
print(json.dumps(out))
fn = f"runs/{a.mode}_R{a.R}_{a.shell or 'full'}{'_confine' if a.confine else ''}_s{a.sched}{'_r%d' % a.start if a.start else ''}{a.tag}.json"
import os; os.makedirs("runs", exist_ok=True); json.dump(out, open(fn, "w"), indent=1)
