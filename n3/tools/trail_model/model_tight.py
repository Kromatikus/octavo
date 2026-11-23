#!/usr/bin/env python3
"""Tightened CP-SAT model for N3 draft-1.

Wraps a local copy of the trail-1 model (not edited in its original folder).
Adds:
  - case-split constraints min_S / min_S2 (for the wt>=3 branch)
  - optional S_mid layer counted after the bow (restored-S-box variant,
    model only; the draft cipher is not changed)

Homemade; for real secrets use AES-GCM-SIV, age, or libsodium.
"""
from __future__ import annotations

import os
import sys

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
# Import the copied trail-1 builder under a stable name.
import model_base as base  # noqa: E402


def build(
    n_rounds,
    bridges,
    mode="diff",
    shell=None,
    confine=None,
    exact=False,
    min_S=0,
    min_S2=0,
    restore_smid=False,
):
    """Build a model. If restore_smid, each round counts an S-box layer
    on the bow output (before cross): S ; ... ; bow ; S_mid ; cross ; S2.
    """
    from ortools.sat.python import cp_model

    # Re-implement one_round with hooks rather than patching the original
    # file's closures. We duplicate the builder by calling a slightly
    # forked copy of base.build internals via a local rewrite.

    # Easiest reliable path: if not restore_smid, use base.build and add
    # min constraints on the returned sb list (first 128 = S, next 128 = S2,
    # repeating per round).
    if not restore_smid:
        md, obj, x_in, sb = base.build(
            n_rounds, bridges, mode=mode, shell=shell, confine=confine, exact=exact
        )
        for r in range(n_rounds):
            S = sb[2 * r * 128 : (2 * r + 1) * 128]
            S2 = sb[(2 * r + 1) * 128 : (2 * r + 2) * 128]
            if min_S:
                md.Add(sum(S) >= min_S)
            if min_S2:
                md.Add(sum(S2) >= min_S2)
        return md, obj, x_in, sb

    # restore_smid: fork the base builder's layer sequence.
    return _build_smid(
        n_rounds, bridges, mode, shell, confine, exact, min_S, min_S2
    )


def _build_smid(n_rounds, bridges, mode, shell, confine, exact, min_S, min_S2):
    """Same constraints as base.build, plus an S-box layer after the bow."""
    from ortools.sat.python import cp_model
    import octavo_n3 as n3

    # Ensure draft import (model_base already put it on path via trail1...
    # but model_base inserts DRAFT itself).
    NF, NB = 16, 8
    IDX = lambda f, t: 8 * f + t
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
        tables = base.chord_staff_table(mode) if exact else None
        for lo in (0, 8):
            for f in range(lo, lo + 8):
                idx = [IDX(f, t) for t in range(8)]
                if exact:
                    apply_table(idx, tables, 9)
                else:
                    outs = [new() for _ in idx]
                    bn_rule([st[q] for q in idx], outs, 9)
                    for q, o in zip(idx, outs):
                        st[q] = o
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
            mix2_pair(i, j)

    def triplets():
        for f in range(16):
            for t, (i, j, k) in enumerate(n3.TRIPLET_WINDOWS):
                idx = [IDX(f, i), IDX(f, j), IDX(f, k)]
                if exact:
                    apply_table(idx, base.trip_table(t, mode), 4)
                else:
                    outs = [new() for _ in idx]
                    bn_rule([st[q] for q in idx], outs, 4)
                    for q, o in zip(idx, outs):
                        st[q] = o

    def bow():
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

    def cross():
        for t in range(8):
            idx = [IDX(f, t) for f in range(16)]
            outs = [new() for _ in idx]
            bn_rule([st[q] for q in idx], outs, 17)
            for q, o in zip(idx, outs):
                st[q] = o

    def one_round(r):
        sb.extend(list(st))  # S
        if min_S:
            md.Add(sum(st) >= min_S)
        force_confine()
        chord()
        force_confine()
        apply_bridges(bridges[r], r)
        force_confine()
        triplets()
        force_confine()
        bow()
        force_confine()
        sb.extend(list(st))  # S_mid (restored after bow)
        force_confine()
        cross()
        force_confine()
        sb.extend(list(st))  # S2
        if min_S2:
            md.Add(sum(st) >= min_S2)
        force_confine()

    for r in range(n_rounds):
        one_round(r)

    return md, sum(sb), x_in, sb


solve = base.solve
sample_bridges = base.sample_bridges
