"""Shared helper: inverse of the unkeyed, XOR-linear cross_staff_mix (used to peel the last layer)."""
import numpy as np, harness
from octavo_np import MUL
m = harness.m; MI = m.MIX2_INV
def cross_unmix(D):
    x = D.reshape(-1, 16, 8).copy()
    for matching in reversed(m.CROSS_LAYERS):
        for f, h in matching:
            f, h = sorted((f, h)); a, b = x[:, f, :], x[:, h, :]
            x[:, f, :], x[:, h, :] = MUL[MI[0][0]][a] ^ MUL[MI[0][1]][b], MUL[MI[1][0]][a] ^ MUL[MI[1][1]][b]
    return x.reshape(-1, 128)
