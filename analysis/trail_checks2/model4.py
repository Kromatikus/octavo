"""OCT-4 copy of OCT-3 model.py with probability-weighted bow strokes (Stage 4). Original docstring: OCT-3 truncated (byte-level) model of one live Octavo round, built from octavo_np.py (OCT-2, read-only)
which is bit-exact vs live sneak_n2 (SHA asserted by harness.py). Never writes outside this folder."""
import os, sys
sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "trail_search")))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "reduced_round")))
import numpy as np
import octavo_np as onp   # imports harness -> asserts live SHA
m = onp.m
NF, NB = 16, 8
IDX = lambda f, t: 8 * f + t

def round_ops(npr):
    """Return list of ops on flat byte indices for one round. Op kinds:
       ('S', [i..])           S-box layer on bytes (each counted)
       ('perm', src)          new[k] = old[src[k]]
       ('mix', i, j)          GF(2^8) 2x2 MDS map in place (branch 3)
       ('latin', i, j)        mix2 then S on both outputs (2 S-boxes)
       ('trip', i, j, k, M)   Z/256 3x3 det-1 map
       ('bow', i, j, p)       ARX stroke, p is pressure byte (read only)
    """
    ops = [('S', list(range(128))), ('perm', list(npr.weave_src))]
    if EXACT:
        for f in range(NF):   # exact truncated transition table of the face butterfly (keyed sigma relabels positions)
            ops.append(('lin', [8 * f + t for t in range(8)], butterfly_matrix(npr, f)))
    else:
        ops.append(('mark',))
        for A, B in npr.butterfly:
            ops += [('mix', int(a), int(b)) for a, b in zip(A, B)]
        ops.append(('bnc', [list(range(8 * f, 8 * f + 8)) for f in range(NF)], 6))   # exact butterfly branch (Stage 1)
    ops += [('mix', int(a), int(b)) for a, b in zip(npr.inner, npr.outer)]
    ops.append(('stretch1_end',))   # S output -> weave -> butterfly -> bridges is one pure GF(2^8)-linear map
    def pass_():
        o = []
        for f in range(NF):
            if EXACT:
                o.append(('latin', IDX(f, 0), IDX(f, 1)))
                o.append(('lin', [IDX(f, t) for t in range(1, 8)], BARCHAIN))
            else:
                for name, _, (i, j), M in m.BARS:
                    o.append(('latin' if name == "B0 start" else 'mix', IDX(f, i), IDX(f, j)))
            for _, (i, j, k), M in m.TRIPLETS:
                o.append(('trip', IDX(f, i), IDX(f, j), IDX(f, k), M))
            for (i, j, p) in m.BOW_STROKES:
                o.append(('bow', IDX(f, i), IDX(f, j), IDX(f, p)))
            for t in (1, 3, 5, 7):
                o.append(('latin', IDX(f, t - 1), IDX(f, t)))
        o.append(('mark',))
        for matching in m.CROSS_LAYERS:
            for a, b in matching:
                a, b = sorted((a, b))
                o += [('mix', IDX(a, t), IDX(b, t)) for t in range(NB)]
        o.append(('bnc', [[IDX(f, t) for f in range(NF)] for t in range(NB)], 6))   # exact cross branch (Stage 1)
        return o
    ops += pass_() + [('S', list(range(128)))] + pass_()
    return ops

EXACT = os.environ.get("OCT_EXACT", "1") == "1"   # 0 = per-op model (Stage 2 first pass)
_TABLES = {}
def gf_matrix(fn, n):
    cols = [fn(np.eye(n, dtype=np.uint8)[i]) for i in range(n)]
    return tuple(tuple(int(cols[c][r]) for c in range(n)) for r in range(n))
def butterfly_matrix(npr, f):
    def bf(x):
        s = np.zeros((1, 128), np.uint8); s[0, 8 * f:8 * f + 8] = x
        for A, B in npr.butterfly: s[:, A], s[:, B] = onp.mix2_np(s[:, A], s[:, B])
        return s[0, 8 * f:8 * f + 8]
    return gf_matrix(bf, 8)
def _barchain(x):
    g = np.zeros((1, 16, 8), np.uint8); g[0, 0, 1:] = x
    for name, _, (i, j), M in m.BARS:
        if M: g[:, :, i], g[:, :, j] = onp.bar_np(M, g[:, :, i], g[:, :, j])
    return g[0, 0, 1:]
BARCHAIN = gf_matrix(_barchain, 7)
def exact_table(M, mode):
    """All (in-support, out-support) bit-pairs realisable with EXACT supports by y = M x (diff) or by masks
    beta = (M^-1)^T alpha (lin). Over GF(2^8) a support pair is realisable iff no required coordinate vanishes on
    V = {x: supp x within Tin, Mx zero outside Tout} (a union of <=16 proper subspaces cannot cover V)."""
    key = (M, mode)
    if key in _TABLES: return _TABLES[key]
    import lincut
    n = len(M); A = np.array(M, dtype=np.int64)
    if mode == "lin": A = ginv(A).T
    allowed = []
    for tin in range(1, 1 << n):
        Tin = [i for i in range(n) if tin >> i & 1]
        # enumerate out-supports by computing V for each candidate zero set is 2^n each; do it directly
        for tout in range(1, 1 << n):
            Tout = [j for j in range(n) if tout >> j & 1]
            zr = [j for j in range(n) if not tout >> j & 1]
            Bk = lincut.kernel([[A[j][i] for i in Tin] for j in zr], len(Tin)) if zr else [[int(k == c) for k in range(len(Tin))] for c in range(len(Tin))]
            if not Bk: continue
            if any(all(b[c] == 0 for b in Bk) for c in range(len(Tin))): continue
            ok = True
            for j in Tout:
                if all(int(np.bitwise_xor.reduce([lincut.MUL[A[j][i]][b[c]] for c, i in enumerate(Tin)])) == 0 for b in Bk):
                    ok = False; break
            if ok: allowed.append([tin >> i & 1 for i in range(n)] + [tout >> j & 1 for j in range(n)])
    allowed.append([0] * (2 * n))
    _TABLES[key] = allowed
    return allowed
def ginv(M):
    import lincut
    n = len(M); A = [list(map(int, M[r])) + [int(r == c) for c in range(n)] for r in range(n)]
    for c in range(n):
        p = next(r for r in range(c, n) if A[r][c]); A[c], A[p] = A[p], A[c]
        iv = int(lincut.INV[A[c][c]]); A[c] = [int(lincut.MUL[iv][v]) for v in A[c]]
        for r in range(n):
            if r != c and A[r][c]:
                f = A[r][c]; A[r] = [x ^ int(lincut.MUL[f][y]) for x, y in zip(A[r], A[c])]
    return np.array([row[n:] for row in A], dtype=np.int64)

def sbox_count_per_round():
    return 128 + 16 * 2 + 16 * 8 + 128 + 16 * 2 + 16 * 8

def build(rounds_ops, mode="diff", shell=None, confine=None, model=None):
    """CP-SAT model. mode 'diff' or 'lin'. shell in {None,'inner','outer'}: input confined to that shell.
    confine: if set, force EVERY intermediate byte of the other shell inactive (fully confined trail).
    Returns (model, objective expr, input vars, trace)."""
    from ortools.sat.python import cp_model
    md = model or cp_model.CpModel()
    nv = [0]
    def new():
        nv[0] += 1; return md.NewBoolVar(f"x{nv[0]}")
    st = [new() for _ in range(128)]
    x_in = list(st)
    md.Add(sum(st) >= 1)
    if shell:
        other = range(64, 128) if shell == "inner" else range(64)
        for i in other: md.Add(st[i] == 0)
    sb = []
    allstates = []
    trace = []
    extra = []   # (weight_tenths_of_bits, indicator) terms from bow strokes
    build.stretch1 = []
    def mix(a, b, c, d):
        z = new(); md.Add(a + b + c + d >= 3 * z)
        for v in (a, b, c, d): md.Add(v <= z)
    for ops in rounds_ops:
        for op in ops:
            k = op[0]
            if k == 'stretch1_end':
                build.stretch1.append((list(s_out), list(st)))
            elif k == 'mark':
                saved = list(st)
            elif k == 'bnc':
                for g in op[1]:
                    z = new(); vs = [saved[q] for q in g] + [st[q] for q in g]
                    md.Add(sum(vs) >= op[2] * z)
                    for v in vs: md.Add(v <= z)
            elif k == 'S':
                sb += [st[i] for i in op[1]]
                s_out = list(st)
            elif k == 'lin':
                idx, M = op[1], op[2]; outs = [new() for _ in idx]
                md.AddAllowedAssignments([st[q] for q in idx] + outs, exact_table(M, mode))
                # redundant linear form of the table (helps the LP relaxation): in+out is 0 or >= branch number
                br = min(sum(r) for r in exact_table(M, mode) if sum(r))
                z = new(); vs = [st[q] for q in idx] + outs; md.Add(sum(vs) >= br * z)
                for v in vs: md.Add(v <= z)
                # each active output needs an active input and vice versa (bijection)
                for o in outs: md.Add(o <= sum(st[q] for q in idx))
                for q, o in zip(idx, outs): st[q] = o
            elif k == 'perm':
                st = [st[s] for s in op[1]]
            elif k == 'mix' or k == 'latin':
                i, j = op[1], op[2]; a, b = new(), new()
                mix(st[i], st[j], a, b); st[i], st[j] = a, b
                if k == 'latin': sb += [a, b]
            elif k == 'trip':
                i, j, kk, M = op[1:]
                ins = [st[i], st[j], st[kk]]; outs = [new(), new(), new()]
                # bijection: some input active <=> some output active
                for o in outs: md.Add(o <= sum(ins))
                for v in ins: md.Add(v <= sum(outs))
                if mode == "diff":
                    # exactly one active input with odd coefficient in row r => output r active
                    for r in range(3):
                        for c in range(3):
                            if M[r][c] % 2 == 1:
                                others = [ins[q] for q in range(3) if q != c]
                                md.Add(outs[r] >= ins[c] - sum(others))
                    Minv = inv_mod256(M)
                    for c in range(3):
                        for r in range(3):
                            if Minv[c][r] % 2 == 1:
                                others = [outs[q] for q in range(3) if q != r]
                                md.Add(ins[c] >= outs[r] - sum(others))
                    for c in range(3):   # input c active => some output with nonzero inverse coeff active
                        md.Add(ins[c] <= sum(outs[r] for r in range(3) if Minv[c][r] % 256))
                st[i], st[j], st[kk] = outs
            elif k == 'bow':
                i, j, p = op[1:]
                u, v, pp = st[i], st[j], st[p]; u2, v2 = new(), new()
                if mode == "diff":   # p unchanged; given p, (u,v)->(u',v') via u'=u+rot(v), v'=v^rot(u')
                    md.Add(u2 >= u - v - pp); md.Add(u2 >= v - u - pp); md.Add(u2 <= u + v + pp)
                    md.Add(v2 >= v - u2 - pp); md.Add(v2 >= u2 - v - pp); md.Add(v2 <= v + u2 + pp)
                    st[i], st[j] = u2, v2
                    if BOW_W is not None: _bow_weight(md, [u, v], [u2, v2], [pp], BOW_W, extra)
                else:                # masks: (u,v) zero <=> (u',v') zero; then p mask passes unchanged
                    p2 = new(); z = new()
                    md.Add(u + v >= z); md.Add(u <= z); md.Add(v <= z)
                    md.Add(u2 + v2 >= z); md.Add(u2 <= z); md.Add(v2 <= z)
                    md.Add(p2 - pp <= z); md.Add(pp - p2 <= z)
                    st[i], st[j], st[p] = u2, v2, p2
                    if BOW_W is not None: _bow_weight(md, [u, v], [u2, v2], [pp, p2], BOW_W, extra)
            trace.append((op[0], list(st)))
            if confine:
                other = range(64, 128) if confine == "inner" else range(64)
                for q in other: md.Add(st[q] == 0)
        allstates.append(list(st))
    build.trace = trace
    build.extra = extra
    return md, sum(sb), x_in, sb, allstates

def inv_mod256(M):
    a = M
    cof = lambda r, c: (a[(r+1)%3][(c+1)%3]*a[(r+2)%3][(c+2)%3] - a[(r+1)%3][(c+2)%3]*a[(r+2)%3][(c+1)%3])
    det = sum(a[0][c] * cof(0, c) for c in range(3)) % 256
    di = pow(det, -1, 256)
    Mi = [[cof(c, r) * di % 256 for c in range(3)] for r in range(3)]   # adjugate^T
    for r in range(3):
        for c in range(3):
            assert sum(a[r][k] * Mi[k][c] for k in range(3)) % 256 == (r == c)
    return Mi

def schedules(n, seed=20261121):
    rng = np.random.default_rng(seed)
    return [onp.lab_schedule(rng) for _ in range(n)]


BOW_W = None   # dict {(in_pat, out_pat): weight in tenths of a bit (floored), or None = impossible}; pat 1=u,2=v,3=uv
def _bow_weight(md, ins, outs, ps, W, extra):
    """Add w * [pattern] for the stroke when all pressure-byte vars in ps are inactive (else weight 0: no credit)."""
    for pin in (1, 2, 3):
        for pout in (1, 2, 3):
            w = W[(pin, pout)]
            lits = [ins[0] if pin & 1 else ins[0].Not(), ins[1] if pin & 2 else ins[1].Not(),
                    outs[0] if pout & 1 else outs[0].Not(), outs[1] if pout & 2 else outs[1].Not()] + [p.Not() for p in ps]
            if w is None:       # impossible transition: forbid (sound: max DP / |corr| is exactly 0)
                md.AddBoolOr([l.Not() for l in lits]); continue
            if w <= 0: continue
            ind = md.NewBoolVar("")
            md.AddBoolOr([l.Not() for l in lits] + [ind])   # pattern holds => ind
            extra.append((w, ind))
