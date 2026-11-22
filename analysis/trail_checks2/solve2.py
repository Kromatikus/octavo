"""OCT-4 runner (copied/adapted from OCT-3 solve.py). One capped CP-SAT min-active-S-box run.
usage: solve2.py mode R --seed S --sched i --start r [--cap s] [--workers w] [--lb n] [--hint n] [--tag t]
Schedules: model.schedules(i+1, seed)[i]; OCT-3 used seed 20261121 schedule 0. Writes runs/<name>.json only."""
import argparse, json, time, os, sys
sys.dont_write_bytecode = True
import model
from ortools.sat.python import cp_model
ap = argparse.ArgumentParser()
ap.add_argument("mode"); ap.add_argument("R", type=int)
ap.add_argument("--seed", type=int, default=20261121); ap.add_argument("--sched", type=int, default=0)
ap.add_argument("--start", type=int, default=0); ap.add_argument("--cap", type=float, default=600)
ap.add_argument("--workers", type=int, default=4); ap.add_argument("--lb", type=int, default=0)
ap.add_argument("--hint", type=int, default=0); ap.add_argument("--tag", default="")
a = ap.parse_args()
ns = model.schedules(a.sched + 1, a.seed)[a.sched]
rops = [model.round_ops(ns.rounds[a.start + r]) for r in range(a.R)]
md, obj, xin, sb, states = model.build(rops, a.mode)
md.Minimize(obj)
if a.lb: md.Add(obj >= a.lb)
if a.hint: md.Add(obj <= a.hint)
sv = cp_model.CpSolver(); sv.parameters.max_time_in_seconds = a.cap; sv.parameters.num_workers = a.workers
t = time.time(); st = sv.Solve(md); dt = time.time() - t
name = {cp_model.OPTIMAL: "OPTIMAL", cp_model.FEASIBLE: "FEASIBLE(timeout)", cp_model.INFEASIBLE: "INFEASIBLE", cp_model.UNKNOWN: "UNKNOWN(timeout)"}[st]
out = dict(mode=a.mode, R=a.R, seed=a.seed, sched=a.sched, start=a.start, cap=a.cap, workers=a.workers, lb_in=a.lb, status=name,
           time_s=round(dt, 1), best_found=(int(sv.ObjectiveValue()) if st in (cp_model.OPTIMAL, cp_model.FEASIBLE) else None),
           proved_lower=max(a.lb, int(sv.BestObjectiveBound())) if st != cp_model.INFEASIBLE else None, exact=model.EXACT)
if st in (cp_model.OPTIMAL, cp_model.FEASIBLE):
    out["input_active"] = [i for i, v in enumerate(xin) if sv.Value(v)]
    per = len(sb) // a.R; layers = [128, 32, 128, 128, 32, 128]; cnt = []
    for r in range(a.R):
        seg = sb[r * per:(r + 1) * per]; pos = 0; c = []
        for L in layers: c.append(sum(sv.Value(v) for v in seg[pos:pos + L])); pos += L
        cnt.append(c)
    out["active_per_round_layer[S,B0,odd,S2,B0',odd']"] = cnt
    out["round_output_active"] = [sum(sv.Value(v) for v in s) for s in states]
    out["state_trace_active"] = [[k, [i for i, v in enumerate(s) if sv.Value(v)]] for k, s in getattr(model.build, "trace", [])][:0]
print(json.dumps({k: v for k, v in out.items() if k != "state_trace_active"}), flush=True)
fn = f"runs/{a.mode}_R{a.R}_seed{a.seed}_s{a.sched}_r{a.start}{a.tag}.json"
os.makedirs("runs", exist_ok=True); json.dump(out, open(fn, "w"), indent=1)
