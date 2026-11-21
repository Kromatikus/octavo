"""Independent Octavo core, written from SPEC.md only. Parameterised (CFG) so spec ambiguities
can be tested; the defaults are the settings that matched the published vectors."""
import hashlib
from sm4_sbox import SM4_SBOX

CFG = dict(mat_out='lsb', mat_col='lsb', rand='rej', fy='down', face_rot='L', col_rot='-',
           bfly='field', bridge='field', cross='field', bridge_u0='inner')

def sponge(dom, seed, nonce, n):
    out = bytearray(); c = 0
    while len(out) < n:
        out += hashlib.sha256(b"SN2/" + dom + c.to_bytes(4, 'big') + seed + nonce).digest(); c += 1
    return bytes(out[:n])

class Stream:
    def __init__(self, dom, seed, nonce):
        self.dom, self.seed, self.nonce, self.c, self.buf = dom, seed, nonce, 0, b""
    def take(self, n):
        while len(self.buf) < n:
            self.buf += hashlib.sha256(b"SN2/" + self.dom + self.c.to_bytes(4, 'big') + self.seed + self.nonce).digest(); self.c += 1
        r, self.buf = self.buf[:n], self.buf[n:]
        return r

# GF(2^8), SM4 polynomial 0x1F5
def _gmul(a, b):
    r = 0
    while b:
        if b & 1: r ^= a
        a <<= 1
        if a & 0x100: a ^= 0x1F5
        b >>= 1
    return r
GMUL = [[_gmul(a, b) for b in range(256)] for a in range(256)]
GINV = [0] * 256
for a in range(1, 256):
    for b in range(1, 256):
        if GMUL[a][b] == 1: GINV[a] = b; break

def rotl8(x, r): r &= 7; return ((x << r) | (x >> (8 - r))) & 255 if r else x

def popc(x): return bin(x).count('1') & 1

def mat_apply(rows, x, cfg):
    out = 0
    for i in range(8):
        row = rows[i]
        if cfg['mat_col'] == 'msb':
            row = int('{:08b}'.format(row)[::-1], 2)
        p = popc(row & x)
        out |= p << (i if cfg['mat_out'] == 'lsb' else 7 - i)
    return out

def gf2_rank(rows):
    rows = list(rows); r = 0
    for bit in range(8):
        piv = None
        for k in range(r, 8):
            if rows[k] >> bit & 1: piv = k; break
        if piv is None: continue
        rows[r], rows[piv] = rows[piv], rows[r]
        for k in range(8):
            if k != r and rows[k] >> bit & 1: rows[k] ^= rows[r]
        r += 1
    return r

def keyed_sbox(A1, b1, A2, b2, cfg):
    S = bytes(mat_apply(A2, SM4_SBOX[mat_apply(A1, x, cfg) ^ b1], cfg) ^ b2 for x in range(256))
    SI = bytearray(256)
    for x in range(256): SI[S[x]] = x
    return S, bytes(SI)

class Schedule:
    def __init__(self, seed, nonce, cfg=CFG):
        st = Stream(b"K", seed, nonce); self.cfg = cfg
        def mat():
            while True:
                rows = list(st.take(8))
                if gf2_rank(rows) == 8: return rows
        def randint(n):  # uniform in [0, n)
            if cfg['rand'] == 'rej':
                lim = 256 - 256 % n
                while True:
                    b = st.take(1)[0]
                    if b < lim: return b % n
            elif cfg['rand'] == 'lt':
                while True:
                    b = st.take(1)[0]
                    if b < n: return b
            else:
                return st.take(1)[0] % n
        def perm(n):
            p = list(range(n))
            if cfg['fy'] == 'down':
                for i in range(n - 1, 0, -1):
                    j = randint(i + 1); p[i], p[j] = p[j], p[i]
            else:
                for i in range(n - 1):
                    j = i + randint(n - i); p[i], p[j] = p[j], p[i]
            return p
        self.rounds = []
        for r in range(16):
            rk = st.take(128)
            A1 = mat(); A2 = mat(); b1, b2 = st.take(2)
            S, SI = keyed_sbox(A1, b1, A2, b2, cfg)
            SH = [randint(8) for _ in range(16)]
            SV = [randint(16) for _ in range(8)]
            sig = [perm(8) for _ in range(16)]
            bridge = perm(64)
            while True:
                A3 = mat(); A4 = mat(); b3, b4 = st.take(2)
                S2, SI2 = keyed_sbox(A3, b3, A4, b4, cfg)
                if S2 != S: break
            self.rounds.append(dict(rk=rk, S=S, SI=SI, S2=S2, SI2=SI2, SH=SH, SV=SV, sig=sig, bridge=bridge))
        self.white = st.take(128)

# ---- two-cell mixes ----
def mix2(u, v, kind):
    if kind == 'field': return u ^ v, u ^ GMUL[2][v]
    return (u + v) & 255, (u + 2 * v) & 255
INV3 = GINV[3]
def mix2_inv(a, b, kind):
    if kind == 'field':
        v = GMUL[INV3][a ^ b]; return a ^ v, v
    return (2 * a - b) & 255, (b - a) & 255

BARS = [None, ((1, 1), (1, 2)), ((3, 5), (1, 2)), ((1, 3), (1, 4)), ((5, 2), (2, 1)), ((2, 1), (1, 1)), ((3, 1), (2, 1))]
def bar_inv(M):
    (a, b), (c, d) = M
    det = GMUL[a][d] ^ GMUL[b][c]; di = GINV[det]
    return ((GMUL[di][d], GMUL[di][b]), (GMUL[di][c], GMUL[di][a]))
BARS_INV = [None] + [bar_inv(M) for M in BARS[1:]]
def bar_apply(M, u, v):
    (a, b), (c, d) = M
    return GMUL[a][u] ^ GMUL[b][v], GMUL[c][u] ^ GMUL[d][v]

def latin(u, v, Sa, Sb):
    x = u ^ v; y = u ^ GMUL[2][v]; return Sa[x], Sb[y]
def unlatin(u, v, SIa, SIb):
    x = SIa[u]; y = SIb[v]; v0 = GMUL[INV3][x ^ y]; return x ^ v0, v0

TRIPLETS = [((5, 1, 1), (2, 3, 1), (5, 5, 2)), ((1, 3, 1), (3, 5, 2), (3, 2, 1)), ((2, 1, 1), (1, 3, 1), (3, 3, 2)),
            ((3, 3, 1), (2, 5, 3), (1, 3, 2)), ((1, 1, 1), (1, 3, 2), (3, 2, 3)), ((2, 1, 3), (3, 1, 3), (1, 2, 5))]
def _adj_inv(M):
    import itertools
    m = [list(r) for r in M]
    def minor(i, j): rr = [r[:j] + r[j + 1:] for k, r in enumerate(m) if k != i]; return rr[0][0] * rr[1][1] - rr[0][1] * rr[1][0]
    det = sum(((-1) ** j) * m[0][j] * minor(0, j) for j in range(3)); assert det == 1
    return tuple(tuple((((-1) ** (i + j)) * minor(j, i)) % 256 for j in range(3)) for i in range(3))
TRIPLETS_INV = [_adj_inv(M) for M in TRIPLETS]

BOW_STROKES = ((0, 1, 2), (2, 3, 4), (4, 5, 0), (6, 7, 0), (1, 2, 3), (3, 4, 5), (5, 6, 0))
BOW_ROT = (0, 0, 0, 3, 0, 0, 5)

CROSS = [[(0, 4), (1, 5), (2, 6), (3, 7), (8, 12), (9, 13), (10, 14), (11, 15)],
         [(0, 8), (1, 9), (2, 10), (3, 11), (4, 12), (5, 13), (6, 14), (7, 15)],
         [(0, 1), (2, 3), (4, 5), (6, 7), (8, 9), (10, 11), (12, 13), (14, 15)],
         [(1, 2), (5, 6), (9, 10), (13, 14)]]

# ---- layers on a grid g[f][t] (list of 16 lists of 8) ----
def weave(g, SH, SV, cfg):
    h = []
    for f in range(16):
        s = SH[f]
        h.append([g[f][(t + s) % 8] for t in range(8)] if cfg['face_rot'] == 'L' else [g[f][(t - s) % 8] for t in range(8)])
    o = [[0] * 8 for _ in range(16)]
    for t in range(8):
        for f in range(16):
            o[f][t] = h[(f + SV[t]) % 16][t] if cfg['col_rot'] == '+' else h[(f - SV[t]) % 16][t]
    return o
def unweave(g, SH, SV, cfg):
    h = [[0] * 8 for _ in range(16)]
    for t in range(8):
        for f in range(16):
            if cfg['col_rot'] == '+': h[(f + SV[t]) % 16][t] = g[f][t]
            else: h[(f - SV[t]) % 16][t] = g[f][t]
    o = []
    for f in range(16):
        s = SH[f]; row = [0] * 8
        for t in range(8):
            if cfg['face_rot'] == 'L': row[(t + s) % 8] = h[f][t]
            else: row[(t - s) % 8] = h[f][t]
        o.append(row)
    return o

def butterfly(g, sig, kind, inv=False):
    g = [r[:] for r in g]
    layers = (1, 2, 4) if not inv else (4, 2, 1)
    for f in range(16):
        s = sig[f]; row = g[f]
        for m in layers:
            for i in range(8):
                if i & m == 0:
                    a, b = s[i], s[i | m]
                    row[a], row[b] = (mix2_inv if inv else mix2)(row[a], row[b], kind)
    return g

def bridges(g, br, r, cfg, inv=False):
    g = [r_[:] for r_ in g]; kind = cfg['bridge']
    inner_u = (r % 2 == 0) == (cfg['bridge_u0'] == 'inner')
    for c in range(64):
        fi, ti = divmod(c, 8); fo, to = divmod(64 + br[c], 8)
        if inner_u:
            g[fi][ti], g[fo][to] = (mix2_inv if inv else mix2)(g[fi][ti], g[fo][to], kind)
        else:
            g[fo][to], g[fi][ti] = (mix2_inv if inv else mix2)(g[fo][to], g[fi][ti], kind)
    return g

def bar_mix(g, Sa, Sb):
    g = [r[:] for r in g]
    for row in g:
        row[0], row[1] = latin(row[0], row[1], Sa, Sb)
        for k in range(1, 7): row[k], row[k + 1] = bar_apply(BARS[k], row[k], row[k + 1])
    return g
def bar_unmix(g, SIa, SIb):
    g = [r[:] for r in g]
    for row in g:
        for k in range(6, 0, -1): row[k], row[k + 1] = bar_apply(BARS_INV[k], row[k], row[k + 1])
        row[0], row[1] = unlatin(row[0], row[1], SIa, SIb)
    return g

def trip(g, inv=False):
    g = [r[:] for r in g]
    seq = list(enumerate(TRIPLETS)) if not inv else [(k, TRIPLETS_INV[k]) for k in range(5, -1, -1)]
    for row in g:
        for k, M in seq:
            x = row[k:k + 3]
            row[k:k + 3] = [sum(M[i][j] * x[j] for j in range(3)) % 256 for i in range(3)]
    return g

def bow(g, inv=False):
    g = [r[:] for r in g]
    for row in g:
        seq = range(7) if not inv else range(6, -1, -1)
        for k in seq:
            i, j, p = BOW_STROKES[k]
            view = rotl8(row[p], BOW_ROT[k]); r1 = 1 + view % 7; r2 = 1 + (view >> 3) % 7
            u, v = row[i], row[j]
            if not inv:
                u = (u + rotl8(v, r1)) & 255; v ^= rotl8(u, r2)
            else:
                v ^= rotl8(u, r2); u = (u - rotl8(v, r1)) & 255
            row[i], row[j] = u, v
    return g

def odd(g, Sa, Sb):
    g = [r[:] for r in g]
    for row in g:
        for t in (0, 2, 4, 6): row[t], row[t + 1] = latin(row[t], row[t + 1], Sa, Sb)
    return g
def unodd(g, SIa, SIb):
    g = [r[:] for r in g]
    for row in g:
        for t in (6, 4, 2, 0): row[t], row[t + 1] = unlatin(row[t], row[t + 1], SIa, SIb)
    return g

def cross(g, kind, inv=False):
    g = [r[:] for r in g]
    layers = CROSS if not inv else CROSS[::-1]
    for L in layers:
        for a, b in L:
            for t in range(8):
                g[a][t], g[b][t] = (mix2_inv if inv else mix2)(g[a][t], g[b][t], kind)
    return g

def sub(g, S): return [[S[x] for x in r] for r in g]
def to_grid(b): return [list(b[8 * f:8 * f + 8]) for f in range(16)]
def from_grid(g): return bytes(x for r in g for x in r)

def round_enc(g, rk, r, cfg):
    g = [[x ^ rk['rk'][8 * f + t] for t, x in enumerate(row)] for f, row in enumerate(g)]
    g = sub(g, rk['S'])
    g = weave(g, rk['SH'], rk['SV'], cfg)
    g = butterfly(g, rk['sig'], cfg['bfly'])
    g = bridges(g, rk['bridge'], r, cfg)
    for enc in (0, 1):
        if enc: g = sub(g, rk['S2'])
        g = bar_mix(g, rk['S'], rk['S2'])
        g = trip(g)
        g = bow(g)
        g = odd(g, rk['S'], rk['S2'])
        g = cross(g, cfg['cross'])
    return g

def round_dec(g, rk, r, cfg):
    for enc in (1, 0):
        g = cross(g, cfg['cross'], inv=True)
        g = unodd(g, rk['SI'], rk['SI2'])
        g = bow(g, inv=True)
        g = trip(g, inv=True)
        g = bar_unmix(g, rk['SI'], rk['SI2'])
        if enc: g = sub(g, rk['SI2'])
    g = bridges(g, rk['bridge'], r, cfg, inv=True)
    g = butterfly(g, rk['sig'], cfg['bfly'], inv=True)
    g = unweave(g, rk['SH'], rk['SV'], cfg)
    g = sub(g, rk['SI'])
    return [[x ^ rk['rk'][8 * f + t] for t, x in enumerate(row)] for f, row in enumerate(g)]

def encrypt_grid(block, sch, rounds=16):
    g = to_grid(block)
    for r in range(rounds): g = round_enc(g, sch.rounds[r], r, sch.cfg)
    return bytes(a ^ b for a, b in zip(from_grid(g), sch.white))

def decrypt_grid(block, sch, rounds=16):
    g = to_grid(bytes(a ^ b for a, b in zip(block, sch.white)))
    for r in range(rounds - 1, -1, -1): g = round_dec(g, sch.rounds[r], r, sch.cfg)
    return from_grid(g)
