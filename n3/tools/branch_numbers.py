"""Branch-number and invertibility checks for Octavo N3 draft-3 maps.

The block function is unchanged from draft-2. These checks exist so a
mutation that stays invertible and still looks fine under loose avalanche
tests is rejected if a public mix gets weaker.

Baselines (fail if any mix falls below):
  mix2     BN 3, and no zero entries
  chord    BN 9 (exact: every square minor is nonzero, i.e. MDS)
  triplets BN 4 each (exact: 3x3 MDS)
  cross    BN 17. Exact proof: the published map is the Cauchy matrix
           C[i][j] = 1/(x_i + y_j) over GF(2^8)/0x1F5 with
           x = 0..15, y = 16..31, which are 32 distinct field elements.
           A square Cauchy matrix with disjoint x and y is MDS, so BN = 17.
           Additionally, observed BN is checked on all input weights <= 2
           (exact for those weights).
  implied 1-round bound: BN_CROSS + 1, required to be >= 18, from the
           invertible-front + S_mid + cross argument in trail-2 / mutlab1.

Homemade; for real secrets use AES-GCM-SIV, age, or libsodium.
"""
from __future__ import annotations

import octavo_n3 as n3

MIX2_BN_MIN = 3
CHORD_BN_MIN = 9
TRIPLET_BN_MIN = 4
CROSS_BN_MIN = 17
IMPLIED_ONE_ROUND_MIN = 18

CROSS_CAUCHY_X = tuple(range(16))
CROSS_CAUCHY_Y = tuple(range(16, 32))
CHORD_CAUCHY_X = tuple(range(8))
CHORD_CAUCHY_Y = tuple(range(8, 16))


def mix2_matrix_from_fn():
    """Recover the 2x2 matrix actually implemented by mix2()."""
    c00, c10 = n3.mix2(1, 0)
    c01, c11 = n3.mix2(0, 1)
    return ((c00, c01), (c10, c11))


def observed_bn(M, max_in_wt=2) -> int:
    """Min wt(in)+wt(out) over nonzero inputs of weight <= max_in_wt.

    Weight-1 uses every scale. Weight-2 is scale-free (first entry 1).
    Exact for those input weights. A worse higher-weight pair would only
    lower the true branch number further.
    """
    n = len(M)
    best = 2 * n
    for i in range(n):
        for c in range(1, 256):
            x = [0] * n
            x[i] = c
            y = n3.mat_vec(M, x)
            best = min(best, 1 + sum(1 for v in y if v))
            if best <= 1:
                return best
    if max_in_wt >= 2:
        for i in range(n):
            for j in range(i + 1, n):
                for c in range(1, 256):
                    x = [0] * n
                    x[i] = 1
                    x[j] = c
                    y = n3.mat_vec(M, x)
                    w = 2 + sum(1 for v in y if v)
                    if w < best:
                        best = w
    return best


def invertible(M) -> bool:
    try:
        inv = n3.mat_inv([list(r) for r in M])
    except Exception:
        return False
    n = len(M)
    for j in range(n):
        e = [int(i == j) for i in range(n)]
        if n3.mat_vec(inv, n3.mat_vec(M, e)) != list(e):
            return False
    return True


def has_zero_entry(M) -> bool:
    return any(v == 0 for row in M for v in row)


def is_cauchy(M, xs, ys) -> bool:
    try:
        expected = n3.cauchy_matrix(list(xs), list(ys))
    except ValueError:
        return False
    if len(M) != len(expected) or len(M[0]) != len(expected[0]):
        return False
    return all(M[i][j] == expected[i][j] for i in range(len(M)) for j in range(len(M)))


def check_maps(mix2=None, chord=None, triplets=None, cross=None) -> list[str]:
    """Return a list of failure strings; empty means all checks passed."""
    failures = []
    if mix2 is None:
        mix2 = mix2_matrix_from_fn()
    if chord is None:
        chord = n3.CHORD_M
    if triplets is None:
        triplets = n3.TRIPLET_MS
    if cross is None:
        cross = n3.CROSS_M

    if has_zero_entry(mix2):
        failures.append("mix2 has a zero entry")
    if not invertible(mix2):
        failures.append("mix2 is not invertible")
    else:
        bn = observed_bn(mix2, 2)
        if bn < MIX2_BN_MIN:
            failures.append(f"mix2 BN {bn} < {MIX2_BN_MIN}")

    if not invertible(chord):
        failures.append("chord is not invertible")
    if not n3.is_mds(chord):
        failures.append("chord is not MDS (exact BN 9 failed)")
    else:
        # MDS already proves BN = 9; record observed wt<=2 as a cross-check
        bn = observed_bn(chord, 2)
        if bn < CHORD_BN_MIN:
            failures.append(f"chord observed BN {bn} < {CHORD_BN_MIN} (unexpected if MDS)")

    if len(triplets) != 6:
        failures.append(f"expected 6 triplet maps, got {len(triplets)}")
    for t, M in enumerate(triplets):
        if not invertible(M):
            failures.append(f"triplet[{t}] is not invertible")
        if not n3.is_mds(M):
            failures.append(f"triplet[{t}] is not MDS (exact BN 4 failed)")

    if not invertible(cross):
        failures.append("cross is not invertible")
    if not is_cauchy(cross, CROSS_CAUCHY_X, CROSS_CAUCHY_Y):
        failures.append(
            "cross is not the published Cauchy matrix "
            "(C[i][j] = 1/(x_i+y_j), x=0..15, y=16..31); "
            "this is the exact MDS / BN=17 proof"
        )
    bn_cross = observed_bn(cross, 2)
    if bn_cross < CROSS_BN_MIN:
        failures.append(
            f"cross observed BN (wt<=2) {bn_cross} < {CROSS_BN_MIN}"
        )
    implied = bn_cross + 1
    if implied < IMPLIED_ONE_ROUND_MIN:
        failures.append(
            f"implied 1-round bound BN_CROSS+1 = {implied} < {IMPLIED_ONE_ROUND_MIN}"
        )
    return failures


def as_mutable(M):
    return [list(row) for row in M]


def to_tuple(M):
    return tuple(tuple(row) for row in M)
