"""Exact GF(2^8) realisability check of a truncated pattern through stretch 1 (S out -> weave -> butterfly -> bridges)."""
import numpy as np, model
onp = model.onp
MUL = onp.MUL.astype(np.int64)
INV = np.array([0] + [next(b for b in range(1, 256) if MUL[a][b] == 1) for a in range(1, 256)])
def stretch1_matrix(npr):
    def L(x):
        s = x[None, :].copy()[:, npr.weave_src]
        for A, B in npr.butterfly: s[:, A], s[:, B] = onp.mix2_np(s[:, A], s[:, B])
        if npr.r % 2 == 0: s[:, npr.inner], s[:, npr.outer] = onp.mix2_np(s[:, npr.inner], s[:, npr.outer])
        else:              s[:, npr.outer], s[:, npr.inner] = onp.mix2_np(s[:, npr.outer], s[:, npr.inner])
        return s[0]
    M = np.array([L(np.eye(128, dtype=np.uint8)[i]) for i in range(128)], dtype=np.int64).T   # out x in
    rng = np.random.default_rng(3); x = rng.integers(0, 256, 128).astype(np.uint8)
    y = np.zeros(128, np.int64)
    for i in range(128): y ^= MUL[M[:, i], x[i]]
    assert (y == L(x)).all(), "stretch1 not GF-linear"
    return M
def kernel(A, n):
    A = [list(map(int, r)) for r in A]; piv = []; rk = 0
    for c in range(n):
        p = next((r for r in range(rk, len(A)) if A[r][c]), None)
        if p is None: continue
        A[rk], A[p] = A[p], A[rk]; iv = int(INV[A[rk][c]]); A[rk] = [int(MUL[iv][v]) for v in A[rk]]
        for r in range(len(A)):
            if r != rk and A[r][c]:
                f = A[r][c]; A[r] = [a ^ int(MUL[f][b]) for a, b in zip(A[r], A[rk])]
        piv.append(c); rk += 1
    basis = []
    for fc in [c for c in range(n) if c not in piv]:
        v = [0] * n; v[fc] = 1
        for r, pc in enumerate(piv): v[pc] = A[r][fc]
        basis.append(v)
    return basis
def check(M, Tin, Tout):
    """Return None if pattern (Tin -> Tout) is realisable with exact supports (generic vector of V), else
    ('empty',) or ('forced', kind, index) for a required-nonzero coordinate that is identically zero on V."""
    zero_rows = [j for j in range(128) if j not in Tout]
    A = [[M[j][i] for i in Tin] for j in zero_rows]
    B = kernel(A, len(Tin)) if A else [[int(k == i) for k in range(len(Tin))] for i in range(len(Tin))]
    if not B: return ("empty",)
    for c, i in enumerate(Tin):
        if all(b[c] == 0 for b in B): return ("forced", "in", i)
    for j in Tout:
        if all((np.bitwise_xor.reduce([MUL[M[j][i]][b[c]] for c, i in enumerate(Tin)]) if Tin else 0) == 0 for b in B):
            return ("forced", "out", j)
    return None
