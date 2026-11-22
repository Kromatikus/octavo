"""Stage 5: is the minimum 1-round truncated differential trail (schedule 0) real?
(a) exact GF(2^8) check of the first linear stretch (S out -> weave -> butterfly -> bridges);
(b) empirical: inject differences from (a) after S on octavo_np and measure how often the truncated pattern survives
    to later checkpoints. Read-only use of octavo_np."""
import json, numpy as np, model
from ortools.sat.python import cp_model
onp = model.onp
MUL = onp.MUL.astype(np.int64)
INV = [0] + [next(b for b in range(1, 256) if MUL[a][b] == 1) for a in range(1, 256)]
ns = model.schedules(1)[0]; R0 = ns.rounds[0]
ops = model.round_ops(R0)
md, obj, xin, sb, states = model.build([ops], "diff")
md.Minimize(obj)
sv = cp_model.CpSolver(); sv.parameters.max_time_in_seconds = 300; sv.parameters.num_workers = 4
st = sv.Solve(md); A = int(sv.ObjectiveValue())
trace = model.build.trace
pat = lambda vs: [i for i, v in enumerate(vs) if sv.Value(v)]
T_in = pat(xin)
# index of op just after bridges = last 'mix' before first 'latin'
first_latin = next(k for k, (name, _) in enumerate(trace) if name == "latin")
T_br = pat(trace[first_latin - 1][1])
# checkpoints: end of first pass (before S2), end of round
s2_idx = [k for k, (name, _) in enumerate(trace) if name == "S"][1]
T_p1 = pat(trace[s2_idx - 1][1]); T_end = pat(trace[-1][1])
# cancellations: mix ops with 3 active (one zero output or input) are "forced cancellations"
canc = 0
print(f"status {sv.StatusName(st)} active={A} in={T_in} after-bridges={len(T_br)} after-pass1={len(T_p1)} end={len(T_end)}")
# (a) linear stretch L: S output -> weave -> butterfly -> bridges, as a 128x128 GF matrix from octavo_np
def L(x):
    s = x[None, :].copy()[:, R0.weave_src]
    for Aa, Bb in R0.butterfly: s[:, Aa], s[:, Bb] = onp.mix2_np(s[:, Aa], s[:, Bb])
    s[:, R0.inner], s[:, R0.outer] = onp.mix2_np(s[:, R0.inner], s[:, R0.outer])   # round 0: even
    return s[0]
cols = np.array([L(np.eye(128, dtype=np.uint8)[i]) for i in range(128)], dtype=np.int64).T  # 128x128
zero_rows = [j for j in range(128) if j not in T_br]
Msub = [[int(cols[j][i]) for i in T_in] for j in zero_rows]
# kernel of Msub over GF(2^8)
def kernel(Mx, n):
    Mx = [r[:] for r in Mx]; piv = []; rk = 0
    for c in range(n):
        p = next((r for r in range(rk, len(Mx)) if Mx[r][c]), None)
        if p is None: continue
        Mx[rk], Mx[p] = Mx[p], Mx[rk]; iv = INV[Mx[rk][c]]; Mx[rk] = [int(MUL[iv][v]) for v in Mx[rk]]
        for r in range(len(Mx)):
            if r != rk and Mx[r][c]:
                f = Mx[r][c]; Mx[r] = [a ^ int(MUL[f][b]) for a, b in zip(Mx[r], Mx[rk])]
        piv.append(c); rk += 1
    free = [c for c in range(n) if c not in piv]; basis = []
    for fc in free:
        v = [0] * n; v[fc] = 1
        for r, pc in enumerate(piv): v[pc] = Mx[r][fc]   # char 2: -x = x
        basis.append(v)
    return basis
B = kernel(Msub, len(T_in)) if Msub else [[1 if k == i else 0 for k in range(len(T_in))] for i in range(len(T_in))]
res = dict(active=A, T_in=T_in, n_after_bridges=len(T_br), n_after_pass1=len(T_p1), n_end=len(T_end), kernel_dim=len(B))
rng = np.random.default_rng(5)
def rand_in_V():
    v = np.zeros(len(T_in), np.int64)
    for b in B:
        c = int(rng.integers(1, 256)); v ^= np.array([int(MUL[c][x]) for x in b])
    x = np.zeros(128, np.uint8); x[T_in] = v; return x
if B:
    full = 0; exact = 0
    for _ in range(200):
        x = rand_in_V(); y = L(x)
        full += all(x[T_in] != 0); exact += set(np.nonzero(y)[0]) == set(T_br) and all(x[T_in] != 0)
    res["stretch1_realisable_fraction_exact_support"] = exact / 200
    # (b) empirical: inject delta after S on random states, run rest of round, check pattern containment
    N = 1 << 18
    P = rng.integers(0, 256, (N, 128), dtype=np.uint8)
    D = np.array([rand_in_V() for _ in range(64)])[rng.integers(0, 64, N)]
    def rest(s, upto):
        s = s[:, R0.weave_src]
        for Aa, Bb in R0.butterfly: s[:, Aa], s[:, Bb] = onp.mix2_np(s[:, Aa], s[:, Bb])
        s[:, R0.inner], s[:, R0.outer] = onp.mix2_np(s[:, R0.inner], s[:, R0.outer])
        x = s.reshape(-1, 16, 8)
        R0._bar(x); R0._trip(x); R0._bow(x); R0._odd(x); R0._cross(x)
        if upto == "pass1": return x.reshape(-1, 128)
        x = R0.S2[x]; R0._bar(x); R0._trip(x); R0._bow(x); R0._odd(x); R0._cross(x)
        return x.reshape(-1, 128)
    for name, T in (("pass1", T_p1), ("end", T_end)):
        dd = rest(P.copy(), name) ^ rest(P ^ D, name)
        outside = np.ones(128, bool); outside[T] = False
        ok = ~(dd[:, outside] != 0).any(axis=1)
        res[f"empirical_P(pattern within trail at {name})"] = f"{int(ok.sum())}/{N}"
print(json.dumps(res, indent=1)); json.dump(res, open("stage5_results.json", "w"), indent=1)
