"""CP-SAT min active S-boxes with lazy, provably-valid cuts from exact GF(2^8) checks of every round's stretch 1.
Cut for an unrealisable stretch pattern (Tin->Tout): any trail whose stretch-1 in-support is within Tin and out-support
within Tout must (empty case) be zero there, or (forced case) have that coordinate inactive.  Monotone, hence valid."""
import argparse, json, time, os
import model, lincut
from ortools.sat.python import cp_model
ap = argparse.ArgumentParser()
ap.add_argument("mode"); ap.add_argument("R", type=int)
ap.add_argument("--sched", type=int, default=0); ap.add_argument("--start", type=int, default=0)
ap.add_argument("--cap", type=float, default=600, help="total wall seconds"); ap.add_argument("--iter_cap", type=float, default=240)
ap.add_argument("--lb", type=int, default=0, help="valid lower bound proved by the looser per-op model");
ap.add_argument("--shell"); ap.add_argument("--workers", type=int, default=4)
a = ap.parse_args()
ns = model.schedules(a.sched + 1)[a.sched]
rounds = [ns.rounds[a.start + r] for r in range(a.R)]
md, obj, xin, sb, states = model.build([model.round_ops(r) for r in rounds], a.mode, shell=a.shell)
md.Minimize(obj)
if a.lb: md.Add(obj >= a.lb)
S1 = model.build.stretch1
Ms = [lincut.stretch1_matrix(r) for r in rounds]
if a.mode == "lin":   # masks propagate through the transpose-inverse; realisability of a mask pattern pair through L
    import numpy as np  # for masks: beta = (L^-1)^T alpha ; check with M' = inverse-transpose over GF(2^8)
    def ginv(M):
        n = 128; A = [list(map(int, M[r])) + [int(r == c) for c in range(n)] for r in range(n)]
        for c in range(n):
            p = next(r for r in range(c, n) if A[r][c]); A[c], A[p] = A[p], A[c]
            iv = int(lincut.INV[A[c][c]]); A[c] = [int(lincut.MUL[iv][v]) for v in A[c]]
            for r in range(n):
                if r != c and A[r][c]:
                    f = A[r][c]; A[r] = [x ^ int(lincut.MUL[f][y]) for x, y in zip(A[r], A[c])]
        return np.array([row[n:] for row in A], dtype=np.int64)
    Ms = [ginv(M).T for M in Ms]
t0 = time.time(); it = 0; ncuts = 0; hist = []
best = None
while time.time() - t0 < a.cap:
    it += 1
    sv = cp_model.CpSolver(); sv.parameters.num_workers = a.workers
    sv.parameters.max_time_in_seconds = min(a.iter_cap, a.cap - (time.time() - t0))
    st = sv.Solve(md)
    if st not in (cp_model.OPTIMAL, cp_model.FEASIBLE):
        hist.append(("no solution", sv.StatusName(st))); break
    val, lb = int(sv.ObjectiveValue()), int(sv.BestObjectiveBound())
    added = 0
    for r, ((vin, vout), M) in enumerate(zip(S1, Ms)):
        Tin = [i for i, v in enumerate(vin) if sv.Value(v)]; Tout = [j for j, v in enumerate(vout) if sv.Value(v)]
        if not Tin: continue
        res = lincut.check(M, Tin, Tout)
        if res is None: continue
        outside = [vin[i] for i in range(128) if i not in Tin] + [vout[j] for j in range(128) if j not in Tout]
        if res[0] == "empty":
            for i in Tin: md.Add(sum(outside) >= vin[i])      # any active in-byte needs something outside the box
        else:
            p = vin[res[2]] if res[1] == "in" else vout[res[2]]
            md.Add(sum(outside) >= p)
        added += 1
    ncuts += added
    hist.append(dict(it=it, status=sv.StatusName(st), val=val, lb=lb, cuts_added=added, t=round(time.time() - t0)))
    print(hist[-1], flush=True)
    if added == 0:
        best = dict(val=val, lb=lb, optimal=(st == cp_model.OPTIMAL), realisable_stretch1=True,
                    input_active=[i for i, v in enumerate(xin) if sv.Value(v)],
                    round_output_active=[sum(sv.Value(v) for v in s) for s in states]); break
    # lower bound remains valid after cuts only as the bound of the cut model; record it
out = dict(mode=a.mode, R=a.R, sched=a.sched, start=a.start, shell=a.shell, iterations=it, cuts=ncuts, history=hist, final=best,
           note="lb from the last iteration is a proved lower bound for the cut-strengthened model (cuts are valid), "
                "so it is a proved lower bound on active S-boxes for real trails under the model assumptions")
os.makedirs("runs", exist_ok=True)
json.dump(out, open(f"runs/cutsX_{a.mode}_R{a.R}_{a.shell or 'full'}_s{a.sched}_r{a.start}.json", "w"), indent=1)
print(json.dumps(dict((k, v) for k, v in out.items() if k != "history")))
