"""Stage 1: byte-level branch numbers of Octavo's linear layers, with matrices extracted from octavo_np (bit-exact
vs live). Exact where small (T,Z rank enumeration over GF(2^8)), else CP-SAT per-op lower bound + explicit witness."""
import itertools, json, time, numpy as np
import model
onp, m = model.onp, model.m
MUL = onp.MUL.astype(np.int64)
INV = [0] + [next(b for b in range(1, 256) if MUL[a][b] == 1) for a in range(1, 256)]
def rank(A):
    A = [list(r) for r in A]; rk = 0; ncol = len(A[0]) if A else 0
    for c in range(ncol):
        p = next((r for r in range(rk, len(A)) if A[r][c]), None)
        if p is None: continue
        A[rk], A[p] = A[p], A[rk]; iv = INV[A[rk][c]]
        A[rk] = [MUL[iv][x] for x in A[rk]]
        for r in range(len(A)):
            if r != rk and A[r][c]:
                f = A[r][c]; A[r] = [x ^ MUL[f][y] for x, y in zip(A[r], A[rk])]
        rk += 1
    return rk
def apply(M, x):
    out = []
    for row in M:
        acc = 0
        for a, b in zip(row, x): acc ^= MUL[a][b]
        out.append(acc)
    return out
def exact_branch(M):
    n = len(M); best = 2 * n + 1; wit = None
    for a in range(1, n + 1):
        for T in itertools.combinations(range(n), a):
            for zs in range(n, -1, -1):
                if a + n - zs >= best: break
                found = False
                for Z in itertools.combinations(range(n), zs):
                    sub = [[M[z][t] for t in T] for z in Z] if Z else []
                    if (rank(sub) if sub else 0) < a:
                        best, wit, found = a + n - zs, (T, Z), True; break
                if found: break
    return best, wit
def matrix_of(fn, n):
    """columns from unit vectors; then verify GF-linearity on random vectors"""
    cols = [fn(np.eye(n, dtype=np.uint8)[i]) for i in range(n)]
    M = [[int(cols[c][r]) for c in range(n)] for r in range(n)]
    rng = np.random.default_rng(1)
    for _ in range(50):
        x = rng.integers(0, 256, n); assert list(fn(x.astype(np.uint8))) == apply(M, list(x)), "not GF-linear"
    return M
res = {}
ns = model.schedules(1)[0]; R0 = ns.rounds[0]
# 2x2 mixes: exhaustive over all 65536 inputs via octavo_np
uu, vv = np.meshgrid(np.arange(256, dtype=np.uint8), np.arange(256, dtype=np.uint8)); uu, vv = uu.ravel(), vv.ravel()
def bn2(f):
    a, b = f(uu, vv); w = (uu > 0).astype(int) + (vv > 0) + (a > 0) + (b > 0)
    return int(w[(uu > 0) | (vv > 0)].min())
res["mix2 (butterfly, bridges, cross, Latin-pair pre-mix)"] = bn2(onp.mix2_np)
for name, _, ij, M in m.BARS:
    if M: res[f"bar {name} {M}"] = bn2(lambda u, v, M=M: onp.bar_np(M, u, v))
# butterfly on one face (sigma keyed; it only relabels positions so branch number is key-independent)
def bfly(x):
    s = np.zeros((1, 128), np.uint8); s[0, :8] = x
    for A, B in R0.butterfly: s[:, A], s[:, B] = onp.mix2_np(s[:, A], s[:, B])
    return s[0, :8]
t = time.time(); Mb = matrix_of(bfly, 8); res["butterfly (one face, 8x8)"] = exact_branch(Mb)[0]
bf_t = time.time() - t
# bar chain B1..B4 (beats 1..7, after B0) as one 7x7 map
def bars(x):
    g = np.zeros((1, 16, 8), np.uint8); g[0, 0, 1:] = x
    for name, _, (i, j), M in m.BARS:
        if M: g[:, :, i], g[:, :, j] = onp.bar_np(M, g[:, :, i], g[:, :, j])
    return g[0, 0, 1:]
res["bar chain B1..B4 (beats 1-7, 7x7)"] = exact_branch(matrix_of(bars, 7))[0]
# cross_staff_mix on one beat column (16x16)
def cross(x):
    g = np.zeros((1, 16, 8), np.uint8); g[0, :, 0] = x; onp.NPRound._cross(g); return g[0, :, 0]
Mc = matrix_of(cross, 16)
# upper bound: information-set search (T of size a, a-1 zero outputs -> kernel vector), a<=3 exhaustive
best = (99, None)
for a in (1, 2, 3):
    for T in itertools.combinations(range(16), a):
        for Z in itertools.combinations(range(16), a - 1):
            sub = [[Mc[z][t] for t in T] for z in Z]
            # kernel vector of sub (a-1 x a): brute force coefficients for a<=2, else elimination
            if a == 1: xs = [[1]]
            else:
                xs = []
                if a == 2:
                    for c in range(1, 256):
                        if not (MUL[sub[0][0]][1] ^ MUL[sub[0][1]][c]): xs.append([1, c])
                else:
                    for c1 in range(256):
                        # solve for c2 from row 0, check row 1
                        r0 = sub[0]
                        if r0[2] == 0: continue
                        c2 = MUL[INV[r0[2]]][MUL[r0[0]][1] ^ MUL[r0[1]][c1]]
                        if (MUL[sub[1][0]][1] ^ MUL[sub[1][1]][c1] ^ MUL[sub[1][2]][c2]) == 0 and c1 and c2: xs.append([1, c1, c2])
            for xv in xs:
                x = [0] * 16
                for tt, c in zip(T, xv): x[tt] = c
                y = apply(Mc, x); w = sum(1 for v in x if v) + sum(1 for v in y if v)
                if w < best[0]: best = (w, x)
res["cross_staff_mix one beat (16x16) upper bound (witness search, input weight<=3)"] = best[0]
# lower bound: CP-SAT per-op model of the cross layer (4 mix2 layers)
from ortools.sat.python import cp_model
md = cp_model.CpModel(); st = [md.NewBoolVar(f"i{k}") for k in range(16)]; ins = list(st); n = [0]
for matching in m.CROSS_LAYERS:
    for a, b in matching:
        a, b = sorted((a, b)); x, y, z = md.NewBoolVar(""), md.NewBoolVar(""), md.NewBoolVar("")
        md.Add(st[a] + st[b] + x + y >= 3 * z)
        for v in (st[a], st[b], x, y): md.Add(v <= z)
        st[a], st[b] = x, y
md.Add(sum(ins) >= 1); md.Minimize(sum(ins) + sum(st))
sv = cp_model.CpSolver(); sv.parameters.max_time_in_seconds = 60; sv.Solve(md)
res["cross_staff_mix one beat: per-op truncated lower bound (CP-SAT)"] = int(sv.ObjectiveValue())
# exact check of cross branch: if upper==lower it's exact; else run exact enumeration up to the upper bound
if best[0] != res["cross_staff_mix one beat: per-op truncated lower bound (CP-SAT)"]:
    t = time.time(); eb = exact_branch(Mc); res["cross_staff_mix one beat (16x16) EXACT"] = eb[0]; res["cross exact time s"] = round(time.time() - t, 1)
res["witness cross"] = best[1]
res["butterfly exact time s"] = round(bf_t, 2)
for k, v in res.items(): print(f"{k}: {v}")
json.dump(res, open("stage1_results.json", "w"), indent=1, default=str)
