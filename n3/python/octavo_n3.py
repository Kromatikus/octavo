"""Octavo N3 block function with a constant-time key schedule (format 0x1B; fix1 8-stroke bow).

Same 16-round block function as draft-3 (S_mid after the bow). The key
schedule no longer uses rejection sampling, so ciphertexts differ from
draft-3. Independent Python reference; must match the Rust crate in this
folder. Not the live N2 cipher.

Homemade; for real secrets use AES-GCM-SIV, age, or libsodium.
"""

from __future__ import annotations

import hashlib

# --- sizes and identifiers -------------------------------------------------
NF, NB, NR = 16, 8, 16
BLOCK_LEN, NONCE_LEN, SEED_LEN = 128, 16, 128
FIELD_POLY = 0x1F5
SPONGE_PREFIX = b"SN3C/"
FORMAT_BYTE = 0x1B
DOMAIN_K = b"K"
GL2_LEN = 72
PERM64_LEN = 64 * 8

# Published SM4/SMS4 S-box, GB/T 32907-2016 (same public table N2 uses).
SM4_SBOX = bytes.fromhex(
    "d690e9fecce13db716b614c228fb2c05"
    "2b679a762abe04c3aa44132649860699"
    "9c4250f491ef987a33540b43edcfac62"
    "e4b31ca9c908e89580df94fa758f3fa6"
    "4707a7fcf37317ba83593c19e6854fa8"
    "686b81b27164da8bf8eb0f4b70569d35"
    "1e240e5e6358d1a225227c3b01217887"
    "d40046579fd327524c3602e7a0c4c89e"
    "eabf8ad240c738b5a3f7f2cef96115a1"
    "e0ae5da49b341a55ad933230f58cb1e3"
    "1df6e22e8266ca60c02923ab0d534e6f"
    "d5db3745defd8e2f03ff6a726d6c5b51"
    "8d1baf92bbddbc7f11d95c411f105ad8"
    "0ac13188a5cd7bbd2d74d012b8e5b4b0"
    "8969974a0c96777e65b9f109c56ec684"
    "18f07dec3adc4d2079ee5f3ed7cb3948"
)
assert len(SM4_SBOX) == 256 and len(set(SM4_SBOX)) == 256

# --- GF(2^8) with reduction polynomial 0x1F5 --------------------------------
def _mul_raw(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        b >>= 1
        a = ((a << 1) ^ (FIELD_POLY if a & 0x80 else 0)) & 255
    return p

_GF_MUL = [[_mul_raw(a, b) for b in range(256)] for a in range(256)]
_GF_INV = [0] * 256
for _a in range(1, 256):
    # a^254 = a^{-1} in a field of 255 nonzero elements
    x = _a
    for _ in range(253):
        x = _GF_MUL[x][_a]
    _GF_INV[_a] = x
    assert _GF_MUL[_a][_GF_INV[_a]] == 1


def gf_mul(a: int, b: int) -> int:
    return _GF_MUL[a][b]


def gf_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("no inverse for 0 in GF(2^8)")
    return _GF_INV[a]


def mat_vec(M, vec):
    n = len(M)
    out = [0] * n
    for i in range(n):
        acc = 0
        row = M[i]
        for j, x in enumerate(vec):
            acc ^= gf_mul(row[j], x)
        out[i] = acc
    return out


def mat_det(M) -> int:
    """Determinant over GF(2^8) by Gaussian elimination (char 2: no signs)."""
    n = len(M)
    a = [list(row) for row in M]
    det = 1
    for col in range(n):
        piv = next((i for i in range(col, n) if a[i][col] != 0), None)
        if piv is None:
            return 0
        if piv != col:
            a[col], a[piv] = a[piv], a[col]
            # char 2: row swap does not flip the sign
        scale = a[col][col]
        det = gf_mul(det, scale)
        inv = gf_inv(scale)
        a[col] = [gf_mul(x, inv) for x in a[col]]
        for i in range(col + 1, n):
            if a[i][col] == 0:
                continue
            f = a[i][col]
            a[i] = [a[i][j] ^ gf_mul(f, a[col][j]) for j in range(n)]
    return det


def mat_minor_det(M, rows, cols):
    sub = [[M[r][c] for c in cols] for r in rows]
    return mat_det(sub)


def mat_inv(M):
    n = len(M)
    a = [list(row) + [0] * n for row in M]
    for i in range(n):
        a[i][n + i] = 1
    for col in range(n):
        piv = next((i for i in range(col, n) if a[i][col] != 0), None)
        if piv is None:
            raise ValueError("singular matrix")
        a[col], a[piv] = a[piv], a[col]
        scale = gf_inv(a[col][col])
        a[col] = [gf_mul(x, scale) for x in a[col]]
        for i in range(n):
            if i == col or a[i][col] == 0:
                continue
            f = a[i][col]
            a[i] = [a[i][j] ^ gf_mul(f, a[col][j]) for j in range(2 * n)]
    return tuple(tuple(row[n:]) for row in a)


def cauchy_matrix(xs, ys):
    """C[i][j] = 1 / (x_i + y_j) over GF(2^8). MDS when the x's and y's are disjoint."""
    n = len(xs)
    if len(ys) != n:
        raise ValueError("Cauchy matrix must be square")
    if len(set(xs) | set(ys)) != 2 * n:
        raise ValueError("Cauchy x and y lists must be pairwise distinct")
    M = []
    for x in xs:
        row = []
        for y in ys:
            s = x ^ y
            if s == 0:
                raise ValueError("Cauchy pole: x_i = y_j")
            row.append(gf_inv(s))
        M.append(tuple(row))
    return tuple(M)


def is_mds(M) -> bool:
    """Every square submatrix has nonzero determinant."""
    n = len(M)
    from itertools import combinations

    for k in range(1, n + 1):
        for rows in combinations(range(n), k):
            for cols in combinations(range(n), k):
                if mat_minor_det(M, list(rows), list(cols)) == 0:
                    return False
    return True


# Public linear maps, derived from the Cauchy parameters in DESIGN_NOTES.md.
# chord: 8x8 on each staff (beats) then on each shell column (faces 0..7 / 8..15).
CHORD_M = cauchy_matrix(list(range(8)), list(range(8, 16)))
CHORD_INV = mat_inv(CHORD_M)

# Folded cross: one 16x16 map on the 16 faces, independently at each beat.
CROSS_M = cauchy_matrix(list(range(16)), list(range(16, 32)))
CROSS_INV = mat_inv(CROSS_M)

# Six overlapping 3-beat windows, same beats as N2; GF(2^8) MDS matrices.
# Window t uses x = (0,1,2) and y = (3+3t, 4+3t, 5+3t).
TRIPLET_WINDOWS = ((0, 1, 2), (1, 2, 3), (2, 3, 4), (3, 4, 5), (4, 5, 6), (5, 6, 7))
TRIPLET_MS = tuple(
    cauchy_matrix((0, 1, 2), (3 + 3 * t, 4 + 3 * t, 5 + 3 * t)) for t in range(6)
)
TRIPLET_INVS = tuple(mat_inv(M) for M in TRIPLET_MS)

# Two-cell mix used only by the shell bridges (same as N2).
# mix2(u, v) = (u + v, u + 2v) in the field.


def mix2(u: int, v: int):
    return u ^ v, u ^ gf_mul(2, v)


def mix2_inv(a: int, b: int):
    # Inverse of ((1,1),(1,2)): v = 3^{-1}(a+b), u = a+v.  3^{-1} in this field.
    inv3 = gf_inv(3)
    v = gf_mul(inv3, a ^ b)
    u = a ^ v
    return u, v


# --- GF(2)^8 affine maps for keyed S-boxes ---------------------------------
def mat_apply_bits(rows, x: int) -> int:
    """Output bit i (LSB = bit 0) is the parity of (row_i AND x)."""
    out = 0
    for i in range(8):
        if bin(rows[i] & x).count("1") & 1:
            out |= 1 << i
    return out


def bitmat_invertible(rows) -> bool:
    work, rank = list(rows), 0
    for bit in range(8):
        piv = next((i for i in range(rank, 8) if (work[i] >> bit) & 1), None)
        if piv is None:
            continue
        work[rank], work[piv] = work[piv], work[rank]
        for i in range(8):
            if i != rank and (work[i] >> bit) & 1:
                work[i] ^= work[rank]
        rank += 1
    return rank == 8


def make_keyed_sbox(A1, b1, A2, b2):
    fwd = [mat_apply_bits(A2, SM4_SBOX[mat_apply_bits(A1, x) ^ b1]) ^ b2 for x in range(256)]
    inv = [0] * 256
    for x, y in enumerate(fwd):
        inv[y] = x
    if len(set(fwd)) != 256:
        raise ValueError("keyed S-box is not bijective")
    return fwd, inv


# --- Constant-time key-schedule helpers (must match rust/src/key_ct.rs) ------
def _u64_gt(a: int, b: int) -> int:
    return 1 if a > b else 0


def _ct_gt_tag(a_tag, a_i, b_tag, b_i) -> int:
    tag_gt = _u64_gt(a_tag, b_tag)
    tag_lt = _u64_gt(b_tag, a_tag)
    tag_eq = 1 ^ tag_gt ^ tag_lt
    idx_gt = 1 if a_i > b_i else 0
    return tag_gt | (tag_eq & idx_gt)


def shuffle_from_tags(tags):
    """Bitonic sort of (tag, original index). out[i] is the original index
    that lands in position i. Same network as rust/src/key_ct.rs."""
    n = len(tags)
    tag = list(tags)
    idx = list(range(n))
    k = 2
    while k <= n:
        j = k // 2
        while j > 0:
            for i in range(n):
                l = i ^ j
                if l > i:
                    upward = (i & k) == 0
                    gt_al = _ct_gt_tag(tag[i], idx[i], tag[l], idx[l])
                    gt_la = _ct_gt_tag(tag[l], idx[l], tag[i], idx[i])
                    swap = gt_al if upward else gt_la
                    if swap:
                        tag[i], tag[l] = tag[l], tag[i]
                        idx[i], idx[l] = idx[l], idx[i]
            j //= 2
        k *= 2
    return idx


def tags_from_bytes(data: bytes):
    assert len(data) % 8 == 0
    n = len(data) // 8
    tags = []
    for i in range(n):
        t = 0
        for k in range(8):
            t = (t << 8) | data[8 * i + k]
        tags.append(t)
    return tags


def _load_u32_le(b: bytes) -> int:
    return int.from_bytes(b, "little")


def unit_lower(bits: int):
    rows = [0] * 8
    k = 0
    for i in range(8):
        row = 1 << i
        for j in range(i):
            row |= ((bits >> k) & 1) << j
            k += 1
        rows[i] = row
    return rows


def unit_upper(bits: int):
    rows = [0] * 8
    k = 0
    for i in range(8):
        row = 1 << i
        for j in range(i + 1, 8):
            row |= ((bits >> k) & 1) << j
            k += 1
        rows[i] = row
    return rows


def bitmat_mul(a, b):
    c = [0] * 8
    for i in range(8):
        acc = 0
        for k in range(8):
            if (a[i] >> k) & 1:
                acc ^= b[k]
        c[i] = acc
    return c


def gl2_from_bytes(data: bytes):
    assert len(data) == GL2_LEN
    l = unit_lower(_load_u32_le(data[0:4]))
    u = unit_upper(_load_u32_le(data[4:8]))
    lu = bitmat_mul(l, u)
    perm = shuffle_from_tags(tags_from_bytes(data[8:72]))
    return [lu[perm[i]] for i in range(8)]


def _tables_equal(a, b) -> int:
    return 1 if list(a) == list(b) else 0


def sbox_distinct_delta(s, s2, sm) -> int:
    chosen, have = 3, 0
    for d in range(4):
        cand = [(y ^ d) for y in sm]
        ok = int(cand != list(s) and cand != list(s2))
        if ok and not have:
            chosen = d
        have |= ok
    return chosen


# --- StaffSponge and Schedule (SN3C/ || 0x1B, fixed-length draws) ------------
class StaffSponge:
    """SHA-256(SN3C/ || FORMAT_BYTE || domain || ctr32be || seed || nonce)."""

    def __init__(self, domain: bytes, seed: bytes, nonce: bytes):
        if len(domain) != 1:
            raise ValueError("domain must be one byte")
        self.domain = domain
        self.seed = seed
        self.nonce = nonce
        self.ctr = 0
        self.buf = b""

    def _more(self):
        block = hashlib.sha256(
            SPONGE_PREFIX
            + bytes([FORMAT_BYTE])
            + self.domain
            + self.ctr.to_bytes(4, "big")
            + self.seed
            + self.nonce
        ).digest()
        self.buf += block
        self.ctr += 1

    def take(self, n: int) -> bytes:
        while len(self.buf) < n:
            self._more()
        out, self.buf = self.buf[:n], self.buf[n:]
        return out


def _as_grid(block: bytes):
    if len(block) != BLOCK_LEN:
        raise ValueError("block must be 128 bytes")
    return [list(block[8 * f : 8 * f + 8]) for f in range(NF)]


def _from_grid(g) -> bytes:
    return bytes(b for row in g for b in row)


class Schedule:
    """Per-message material from seed and nonce, format 0x1B.

    Fixed-length sponge draws: for each of 16 rounds, rk (128), six GL(8,2)
    matrices (72 bytes each as P·L·U), six S-box bias bytes, then a 64-byte
    bridge permutation from 512 tag bytes. S2 is tweaked by XOR of its output
    mask if it would equal S; S_mid by the smallest d in {0,1,2,3} that keeps
    it distinct from both. Then 128-byte `white`. Unused N2 SH/SV/sigma draws
    are dropped. Stream positions are not compatible with draft-3.
    """

    def __init__(self, seed: bytes, nonce: bytes):
        if not isinstance(seed, (bytes, bytearray)) or len(seed) != SEED_LEN:
            raise ValueError("seed must be 128 bytes")
        if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != NONCE_LEN:
            raise ValueError("nonce must be 16 bytes")
        seed = bytes(seed)
        nonce = bytes(nonce)
        sp = StaffSponge(DOMAIN_K, seed, nonce)
        self.rounds = []
        for _r in range(NR):
            rk = _as_grid(sp.take(BLOCK_LEN))
            A1 = gl2_from_bytes(sp.take(GL2_LEN))
            A2 = gl2_from_bytes(sp.take(GL2_LEN))
            b1, b2 = sp.take(2)
            S, SI = make_keyed_sbox(A1, b1, A2, b2)
            A3 = gl2_from_bytes(sp.take(GL2_LEN))
            A4 = gl2_from_bytes(sp.take(GL2_LEN))
            b3, b4 = sp.take(2)
            S2, _ = make_keyed_sbox(A3, b3, A4, b4)
            b4 ^= _tables_equal(S, S2)
            S2, SI2 = make_keyed_sbox(A3, b3, A4, b4)
            A5 = gl2_from_bytes(sp.take(GL2_LEN))
            A6 = gl2_from_bytes(sp.take(GL2_LEN))
            b5, b6 = sp.take(2)
            SM, _ = make_keyed_sbox(A5, b5, A6, b6)
            b6 ^= sbox_distinct_delta(S, S2, SM)
            SM, SIM = make_keyed_sbox(A5, b5, A6, b6)
            bridge = shuffle_from_tags(tags_from_bytes(sp.take(PERM64_LEN)))
            self.rounds.append(
                dict(
                    rk=rk,
                    S=S,
                    SI=SI,
                    S2=S2,
                    SI2=SI2,
                    SM=SM,
                    SIM=SIM,
                    bridge=bridge,
                )
            )
        self.white = _as_grid(sp.take(BLOCK_LEN))


# --- N3 layers -------------------------------------------------------------
def xor_grid(g, k):
    return [[g[f][t] ^ k[f][t] for t in range(NB)] for f in range(NF)]


def sub_bytes(g, box):
    return [[box[x] for x in row] for row in g]


def chord(g, inverse=False):
    """Per 64-byte shell: 8x8 MDS along each staff, then 8x8 MDS across the
    eight faces of each beat. Inverse undoes faces then staffs."""
    M = CHORD_INV if inverse else CHORD_M
    g = [row[:] for row in g]
    shells = ((0, 8), (8, 16))
    if not inverse:
        for lo, hi in shells:
            for f in range(lo, hi):
                g[f] = mat_vec(M, g[f])
            for t in range(NB):
                col = [g[f][t] for f in range(lo, hi)]
                mixed = mat_vec(M, col)
                for i, f in enumerate(range(lo, hi)):
                    g[f][t] = mixed[i]
    else:
        for lo, hi in shells:
            for t in range(NB):
                col = [g[f][t] for f in range(lo, hi)]
                mixed = mat_vec(M, col)
                for i, f in enumerate(range(lo, hi)):
                    g[f][t] = mixed[i]
            for f in range(lo, hi):
                g[f] = mat_vec(M, g[f])
    return g


def shell_bridges(g, bridge, round_index, inverse=False):
    """64 inner/outer pairs; orientation alternates with the round index.
    Pairs are disjoint, so mix2_inv can use the same loop order as mix2."""
    step = mix2_inv if inverse else mix2
    g = [row[:] for row in g]
    for c in range(64):
        fi, ti = divmod(c, NB)
        fo, to = divmod(bridge[c], NB)
        fo += 8
        if round_index % 2 == 0:
            g[fi][ti], g[fo][to] = step(g[fi][ti], g[fo][to])
        else:
            g[fo][to], g[fi][ti] = step(g[fo][to], g[fi][ti])
    return g


def triplets(g, inverse=False):
    """Six overlapping 3-beat GF(2^8) mixes on each staff, T0..T5 forward,
    T5..T0 on the inverse."""
    g = [row[:] for row in g]
    seq = list(range(6 - 1, -1, -1)) if inverse else list(range(6))
    mats = TRIPLET_INVS if inverse else TRIPLET_MS
    for row in g:
        for t in seq:
            i, j, k = TRIPLET_WINDOWS[t]
            row[i], row[j], row[k] = mat_vec(mats[t], (row[i], row[j], row[k]))
    return g


# Bow, unchanged from N2 (add-rotate-XOR with the beat-0/6/7 pressure fixes).
# fix1 (format 0x1B): 8-stroke bow, full diffusion forward and inverse (OHLO's choice;
# the 10-stroke sawtooth is kept in lab/sawtooth10).
BOW_STROKES = ((2, 3, 4), (5, 7, 1), (0, 7, 3), (4, 7, 6), (1, 6, 0), (1, 7, 2), (2, 5, 4), (0, 3, 1),)
BOW_PRESSURE_ROT = (0,) * 8
BOW_ROT_BASE, BOW_ROT_MOD, BOW_R2_SHIFT = 1, 7, 3


def rotl8(x: int, n: int) -> int:
    n &= 7
    return ((x << n) | (x >> (8 - n))) & 255 if n else x


def _bow_stroke(u, v, p):
    r1 = BOW_ROT_BASE + (p % BOW_ROT_MOD)
    r2 = BOW_ROT_BASE + ((p >> BOW_R2_SHIFT) % BOW_ROT_MOD)
    u = (u + rotl8(v, r1)) & 255
    v = v ^ rotl8(u, r2)
    return u, v


def _unbow_stroke(u, v, p):
    r1 = BOW_ROT_BASE + (p % BOW_ROT_MOD)
    r2 = BOW_ROT_BASE + ((p >> BOW_R2_SHIFT) % BOW_ROT_MOD)
    v = v ^ rotl8(u, r2)
    u = (u - rotl8(v, r1)) & 255
    return u, v


def bow(staff, inverse=False):
    s = list(staff)
    strokes = zip(reversed(BOW_STROKES), reversed(BOW_PRESSURE_ROT)) if inverse else zip(
        BOW_STROKES, BOW_PRESSURE_ROT
    )
    step = _unbow_stroke if inverse else _bow_stroke
    for (i, j, p), k in strokes:
        s[i], s[j] = step(s[i], s[j], rotl8(s[p], k))
    return s


def bow_grid(g, inverse=False):
    return [bow(row, inverse=inverse) for row in g]


def folded_cross(g, inverse=False):
    """One 16x16 MDS mix of the 16 faces, independently at each beat."""
    M = CROSS_INV if inverse else CROSS_M
    g = [row[:] for row in g]
    for t in range(NB):
        col = [g[f][t] for f in range(NF)]
        mixed = mat_vec(M, col)
        for f in range(NF):
            g[f][t] = mixed[f]
    return g


def _round_enc(g, material, r):
    g = xor_grid(g, material["rk"])
    g = sub_bytes(g, material["S"])
    g = chord(g)
    g = shell_bridges(g, material["bridge"], r)
    g = triplets(g)
    g = bow_grid(g)
    g = sub_bytes(g, material["SM"])
    g = folded_cross(g)
    g = sub_bytes(g, material["S2"])
    return g


def _round_dec(g, material, r):
    g = sub_bytes(g, material["SI2"])
    g = folded_cross(g, inverse=True)
    g = sub_bytes(g, material["SIM"])
    g = bow_grid(g, inverse=True)
    g = triplets(g, inverse=True)
    g = shell_bridges(g, material["bridge"], r, inverse=True)
    g = chord(g, inverse=True)
    g = sub_bytes(g, material["SI"])
    g = xor_grid(g, material["rk"])
    return g


class Cipher:
    def __init__(self, seed: bytes, nonce: bytes):
        self.schedule = Schedule(seed, nonce)

    def encrypt_block(self, pt: bytes) -> bytes:
        g = _as_grid(pt)
        for r in range(NR):
            g = _round_enc(g, self.schedule.rounds[r], r)
        g = xor_grid(g, self.schedule.white)
        return _from_grid(g)

    def decrypt_block(self, ct: bytes) -> bytes:
        g = _as_grid(ct)
        g = xor_grid(g, self.schedule.white)
        for r in range(NR - 1, -1, -1):
            g = _round_dec(g, self.schedule.rounds[r], r)
        return _from_grid(g)


def encrypt_block(seed: bytes, nonce: bytes, pt: bytes) -> bytes:
    return Cipher(seed, nonce).encrypt_block(pt)


def decrypt_block(seed: bytes, nonce: bytes, ct: bytes) -> bytes:
    return Cipher(seed, nonce).decrypt_block(ct)


def verify_linear_maps():
    """Invertibility and MDS checks for the public maps. Returns a dict."""
    out = {}
    out["chord_det_nonzero"] = mat_det(CHORD_M) != 0
    out["chord_inv_ok"] = all(
        mat_vec(CHORD_INV, mat_vec(CHORD_M, e)) == list(e)
        for e in ([int(i == j) for i in range(8)] for j in range(8))
    )
    out["chord_mds"] = is_mds(CHORD_M)
    out["cross_det_nonzero"] = mat_det(CROSS_M) != 0
    out["cross_inv_ok"] = all(
        mat_vec(CROSS_INV, mat_vec(CROSS_M, e)) == list(e)
        for e in ([int(i == j) for i in range(16)] for j in range(16))
    )
    # Full 16x16 MDS is implied by the Cauchy construction; checking every
    # minor is expensive. Confirm all entries nonzero and all 2x2 minors
    # nonzero, which are the first MDS conditions.
    from itertools import combinations

    out["cross_entries_nonzero"] = all(CROSS_M[i][j] for i in range(16) for j in range(16))
    two_by_two = True
    for rows in combinations(range(16), 2):
        for cols in combinations(range(16), 2):
            if mat_minor_det(CROSS_M, list(rows), list(cols)) == 0:
                two_by_two = False
                break
        if not two_by_two:
            break
    out["cross_2x2_nonzero"] = two_by_two
    out["triplet_mds"] = all(is_mds(M) for M in TRIPLET_MS)
    out["triplet_inv_ok"] = all(
        mat_vec(INV, mat_vec(M, e)) == list(e)
        for M, INV in zip(TRIPLET_MS, TRIPLET_INVS)
        for e in ([int(i == j) for i in range(3)] for j in range(3))
    )
    # mix2 inverse of the field pair used by bridges
    out["mix2_inv_ok"] = all(
        mix2_inv(*mix2(u, v)) == (u, v) for u in range(0, 256, 17) for v in range(0, 256, 19)
    )
    return out
