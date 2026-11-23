"""Byte-level truncated CP-SAT model of one N3 draft-1 round.

Reads /workspace/octavo_n3_draft1/python/octavo_n3.py (no edits). Field is
GF(2^8)/0x1F5. Constraints are sound: every real trail satisfies them, so
solver minima are lower bounds. The bow is modelled with the same stroke-level
rules as the N2 trail search (no S-box credit; pressure rotations do not
change activity). Triplets are GF(2^8)-linear MDS here, so they do get a
branch-number (and, optionally, exact-table) constraint.

Homemade; for real secrets use AES-GCM-SIV, age, or libsodium.
"""
from __future__ import annotations

import hashlib
import os
import sys

sys.dont_write_bytecode = True
DRAFT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "python"))
sys.path.insert(0, DRAFT)
import octavo_n3 as n3  # noqa: E402

NF, NB, NR = n3.NF, n3.NB, n3.NR
IDX = lambda f, t: 8 * f + t


def sha_bytes(label: bytes, n: int) -> bytes:
    out, c = b"", 0
    while len(out) < n:
        out += hashlib.sha256(b"octavo-n3-trail1/" + label + c.to_bytes(4, "big")).digest()
        c += 1
    return out[:n]


def sample_bridges(n_schedules=4, rounds=4, seed_label=b"sched"):
    """Return list of schedules, each a list of 16 bridge permutations (rounds)."""
    out = []
    for s in range(n_schedules):
        seed = sha_bytes(seed_label + f"-{s}".encode(), 128)
        nonce = sha_bytes(b"nonce-" + f"{s}".encode(), 16)
        sch = n3.Schedule(seed, nonce)
        out.append([list(r["bridge"]) for r in sch.rounds[:rounds]])
    return out


# --- exact truncated tables for small MDS maps ------------------------------
_TABLES = {}


def _kernel(rows, nvars):
    """Basis of the right kernel of a matrix over this field (rows are lists)."""
    m = [list(r) for r in rows]
    nr = len(m)
    if nr == 0:
        return [[int(i == j) for i in range(nvars)] for j in range(nvars)]
    nc = nvars
    piv_col = {}
    r = 0
    used = set()
    for c in range(nc):
        piv = next((i for i in range(r, nr) if m[i][c] != 0), None)
        if piv is None:
            continue
        m[r], m[piv] = m[piv], m[r]
        inv = n3.gf_inv(m[r][c])
        m[r] = [n3.gf_mul(inv, x) for x in m[r]]
        for i in range(nr):
            if i != r and m[i][c]:
                f = m[i][c]
                m[i] = [m[i][j] ^ n3.gf_mul(f, m[r][j]) for j in range(nc)]
        piv_col[c] = r
        used.add(c)
        r += 1
        if r == nr:
            break
    free = [c for c in range(nc) if c not in used]
    basis = []
    for fcol in free:
        vec = [0] * nc
        vec[fcol] = 1
        for c, pr in piv_col.items():
            vec[c] = n3.gf_mul(m[pr][fcol], n3.gf_inv(1) if False else 1)
            # m[pr] is monic at pivot c; the entry at fcol is the coeff to cancel
            vec[c] = m[pr][fcol]  # already the reduced row; x_c + m[pr][fcol] x_f = 0
            vec[c] = m[pr][fcol]  # wait: row says 1*x_c + ... + m[pr][fcol]*x_f = 0 so x_c = m[pr][fcol] (char 2)
        basis.append(vec)
    return basis


def _realisable_supports(M, mode: str):
    """Exact (in-support, out-support) pairs for y = M x (diff) or
    beta = (M^{-1})^T alpha (lin), including the zero pair."""
    key = (tuple(tuple(row) for row in M), mode)
    if key in _TABLES:
        return _TABLES[key]
    n = len(M)
    A = [list(row) for row in M]
    if mode == "lin":
        Minv = n3.mat_inv(M)
        # (M^{-1})^T
        A = [[Minv[j][i] for j in range(n)] for i in range(n)]
    allowed = []
    for tin in range(1, 1 << n):
        Tin = [i for i in range(n) if (tin >> i) & 1]
        for tout in range(1, 1 << n):
            zr = [j for j in range(n) if not ((tout >> j) & 1)]
            # V = {x : supp x ⊆ Tin, (A x)_j = 0 for j in zr}
            # Build the matrix of zero-output constraints on the Tin coordinates.
            rows = [[A[j][i] for i in Tin] for j in zr] if zr else []
            Bk = _kernel(rows, len(Tin)) if zr else [
                [int(k == c) for k in range(len(Tin))] for c in range(len(Tin))
            ]
            if not Bk:
                continue
            # every required input coordinate must be able to be nonzero
            if any(all(b[c] == 0 for b in Bk) for c in range(len(Tin))):
                continue
            ok = True
            for j in [j for j in range(n) if (tout >> j) & 1]:
                # (A x)_j must be able to be nonzero on V
                coeffs = [A[j][i] for i in Tin]
                if all(
                    _dot(coeffs, b) == 0 for b in Bk
                ):
                    ok = False
                    break
            if ok:
                allowed.append(
                    [(tin >> i) & 1 for i in range(n)] + [(tout >> j) & 1 for j in range(n)]
                )
    allowed.append([0] * (2 * n))
    _TABLES[key] = allowed
    return allowed


def _dot(a, b):
    acc = 0
    for x, y in zip(a, b):
        acc ^= n3.gf_mul(x, y)
    return acc


def mds_branch(n: int) -> int:
    return n + 1


# Precompute 8x8 and 3x3 tables lazily through helpers
def chord_staff_table(mode):
    return _realisable_supports(n3.CHORD_M, mode)


def trip_table(t, mode):
    return _realisable_supports(n3.TRIPLET_MS[t], mode)


def build(n_rounds, bridges, mode="diff", shell=None, confine=None, exact=True):
    """Build a CP-SAT model for `n_rounds` consecutive rounds starting at 0
    of one schedule (`bridges[r]` is the 64-entry permutation for round r).

    shell: 'inner'/'outer' confines the *input* of the first round.
    confine: 'inner'/'outer' forces the other shell inactive at every step.
    exact: use exact truncated tables for 8x8 chord and 3x3 triplets;
           16x16 cross and mix2 stay at the MDS branch-number rule.
    """
    from ortools.sat.python import cp_model

    md = cp_model.CpModel()
    nv = [0]

    def new():
        nv[0] += 1
        return md.NewBoolVar(f"v{nv[0]}")

    st = [new() for _ in range(128)]
    x_in = list(st)
    md.Add(sum(st) >= 1)
    if shell:
        other = range(64, 128) if shell == "inner" else range(64)
        for i in other:
            md.Add(st[i] == 0)

    sb = []

    def force_confine():
        if not confine:
            return
        other = range(64, 128) if confine == "inner" else range(64)
        for q in other:
            md.Add(st[q] == 0)

    def bn_rule(ins, outs, bn):
        z = new()
        vs = list(ins) + list(outs)
        md.Add(sum(vs) >= bn * z)
        for v in vs:
            md.Add(v <= z)
        # bijection: all-zero in <=> all-zero out is implied by BN + z
        # plus: some in => some out and vice versa (already if bn>=1)
        return z

    def apply_table(idx, table, bn):
        outs = [new() for _ in idx]
        md.AddAllowedAssignments([st[q] for q in idx] + outs, table)
        bn_rule([st[q] for q in idx], outs, bn)
        for q, o in zip(idx, outs):
            st[q] = o

    def mix2_pair(i, j):
        a, b = new(), new()
        bn_rule([st[i], st[j]], [a, b], 3)
        st[i], st[j] = a, b

    def chord():
        # Two shells independently: staff (8 beats) then faces (8 faces).
        tables = chord_staff_table(mode) if exact else None
        for lo in (0, 8):
            # staff MDS
            for f in range(lo, lo + 8):
                idx = [IDX(f, t) for t in range(8)]
                if exact:
                    apply_table(idx, tables, 9)
                else:
                    outs = [new() for _ in idx]
                    bn_rule([st[q] for q in idx], outs, 9)
                    for q, o in zip(idx, outs):
                        st[q] = o
            # face MDS
            for t in range(8):
                idx = [IDX(f, t) for f in range(lo, lo + 8)]
                if exact:
                    apply_table(idx, tables, 9)
                else:
                    outs = [new() for _ in idx]
                    bn_rule([st[q] for q in idx], outs, 9)
                    for q, o in zip(idx, outs):
                        st[q] = o

    def apply_bridges(bridge, r):
        for c in range(64):
            fi, ti = divmod(c, 8)
            fo, to = divmod(bridge[c], 8)
            fo += 8
            i, j = IDX(fi, ti), IDX(fo, to)
            # orientation does not change the 2x2 MDS branch number
            mix2_pair(i, j)

    def triplets():
        for f in range(16):
            for t, (i, j, k) in enumerate(n3.TRIPLET_WINDOWS):
                idx = [IDX(f, i), IDX(f, j), IDX(f, k)]
                if exact:
                    apply_table(idx, trip_table(t, mode), 4)
                else:
                    outs = [new() for _ in idx]
                    bn_rule([st[q] for q in idx], outs, 4)
                    for q, o in zip(idx, outs):
                        st[q] = o

    def bow():
        """N2-style stroke rules. Differential: with inactive pressure, an
        add/xor of a rotation forces activity through; an active pressure
        byte loosens the implication. Linear: (u,v) zero iff (u',v') zero,
        and the pressure mask may change only if the pair is active."""
        for f in range(16):
            for (i, j, p), _k in zip(n3.BOW_STROKES, n3.BOW_PRESSURE_ROT):
                u, v, pp = st[IDX(f, i)], st[IDX(f, j)], st[IDX(f, p)]
                u2, v2 = new(), new()
                if mode == "diff":
                    md.Add(u2 >= u - v - pp)
                    md.Add(u2 >= v - u - pp)
                    md.Add(u2 <= u + v + pp)
                    md.Add(v2 >= v - u2 - pp)
                    md.Add(v2 >= u2 - v - pp)
                    md.Add(v2 <= v + u2 + pp)
                    st[IDX(f, i)], st[IDX(f, j)] = u2, v2
                else:
                    p2 = new()
                    z = new()
                    md.Add(u + v >= z)
                    md.Add(u <= z)
                    md.Add(v <= z)
                    md.Add(u2 + v2 >= z)
                    md.Add(u2 <= z)
                    md.Add(v2 <= z)
                    md.Add(p2 - pp <= z)
                    md.Add(pp - p2 <= z)
                    st[IDX(f, i)], st[IDX(f, j)], st[IDX(f, p)] = u2, v2, p2
            # staff-level bijection (nonzero in <=> nonzero out)
            # already mostly implied stroke by stroke; keep a whole-staff cut
            # (no extra variables).

    def cross():
        for t in range(8):
            idx = [IDX(f, t) for f in range(16)]
            outs = [new() for _ in idx]
            bn_rule([st[q] for q in idx], outs, 17)
            for q, o in zip(idx, outs):
                st[q] = o

    def one_round(r):
        # S-box layer (counts activity of current state)
        sb.extend(list(st))
        force_confine()
        chord()
        force_confine()
        apply_bridges(bridges[r], r)
        force_confine()
        triplets()
        force_confine()
        bow()
        force_confine()
        cross()
        force_confine()
        # S2
        sb.extend(list(st))
        force_confine()

    # After S2 the state is the input to the next S (rk XOR does not change diffs/masks).
    for r in range(n_rounds):
        one_round(r)

    return md, sum(sb), x_in, sb


def solve(md, objective, time_limit_s=60, workers=8, dump_vars=None):
    from ortools.sat.python import cp_model

    slv = cp_model.CpSolver()
    slv.parameters.max_time_in_seconds = float(time_limit_s)
    slv.parameters.num_search_workers = workers
    md.Minimize(objective)
    st = slv.Solve(md)
    name = slv.StatusName(st)
    rec = {"status": name, "time_s": slv.WallTime(), "info": (slv.SolutionInfo() or "")[:400]}
    if st in (cp_model.OPTIMAL, cp_model.FEASIBLE):
        rec.update({
            "proved": st == cp_model.OPTIMAL,
            "objective": int(slv.ObjectiveValue()),
            "best_bound": int(slv.BestObjectiveBound()),
        })
        if dump_vars is not None:
            bits = [int(slv.Value(v)) for v in dump_vars]
            rec["activity"] = {
                "len": len(bits),
                "weights_per_layer": [sum(bits[i:i+128]) for i in range(0, len(bits), 128)],
                "S": bits[0:128],
                "S2": bits[128:256] if len(bits) >= 256 else None,
            }
        return rec
    if st == cp_model.INFEASIBLE:
        rec.update({"proved": True, "objective": None, "best_bound": None})
        return rec
    bound = slv.BestObjectiveBound()
    rec.update({
        "proved": False,
        "objective": None,
        "best_bound": int(bound) if bound is not None and bound >= 0 else None,
    })
    return rec
