"""NumPy batch re-implementation of live Octavo rounds (OCT-2). Read-only use of harness/sneak_n2.
State: uint8 array (N, 128), byte index = 8*face + beat (same as bytes_to_grid). Checked vs harness.enc_r."""
import numpy as np
import harness
m = harness.m
NF, NB = m.NF, m.NB
MUL = np.array([[m.gf_mul(a, b) for b in range(256)] for a in range(256)], dtype=np.uint8)
ROTL = np.array([[m.rotl8(x, n % 8) for n in range(8)] for x in range(256)], dtype=np.uint8)  # ROTL[x, n]

def mix2_np(u, v):          # MIX2 = ((1,1),(1,2))
    return u ^ v, u ^ MUL[2][v]

def bar_np(M, u, v):
    return MUL[M[0][0]][u] ^ MUL[M[0][1]][v], MUL[M[1][0]][u] ^ MUL[M[1][1]][v]

def latin_np(u, v, Sa, Sb):
    return Sa[u ^ v], Sb[u ^ MUL[2][v]]

class NPRound:
    def __init__(self, rk, r):
        self.r = r
        self.rk = np.array([x for row in rk["rk"] for x in row], dtype=np.uint8)
        self.S = np.array(rk["S"], dtype=np.uint8); self.S2 = np.array(rk["S2"], dtype=np.uint8)
        SH, SV = rk["SH"], rk["SV"]
        # weave as gather: out[(f+SV[b])%16][b] = g[f][(b+SH[f])%8]
        src = np.zeros(128, dtype=np.int64)
        for f in range(NF):
            for b in range(NB):
                src[((f + SV[b]) % NF) * 8 + b] = f * 8 + (b + SH[f]) % 8
        self.weave_src = src
        # staff butterfly: 3 layers, each 64 disjoint pairs (flat indices)
        self.butterfly = []
        for mm in m.LAYERS:
            A, B = [], []
            for f in range(NF):
                s = rk["sigma"][f]
                for i in range(NB):
                    if i & mm: continue
                    A.append(f * 8 + s[i]); B.append(f * 8 + s[i | mm])
            self.butterfly.append((np.array(A), np.array(B)))
        inner, outer = [], []
        for c in range(64):
            fi, ti = divmod(c, NB); fo, to = divmod(rk["bridge"][c], NB); fo += 8
            inner.append(fi * 8 + ti); outer.append(fo * 8 + to)
        self.inner, self.outer = np.array(inner), np.array(outer)

    def _bar(self, x):
        for name, _, (i, j), M in m.BARS:
            if name == "B0 start": x[:, :, i], x[:, :, j] = latin_np(x[:, :, i], x[:, :, j], self.S, self.S2)
            else: x[:, :, i], x[:, :, j] = bar_np(M, x[:, :, i], x[:, :, j])

    @staticmethod
    def _trip(x):
        for _, (i, j, k), M in m.TRIPLETS:
            u = x[:, :, i].astype(np.int32); v = x[:, :, j].astype(np.int32); w = x[:, :, k].astype(np.int32)
            x[:, :, i] = ((M[0][0]*u + M[0][1]*v + M[0][2]*w) & 255).astype(np.uint8)
            x[:, :, j] = ((M[1][0]*u + M[1][1]*v + M[1][2]*w) & 255).astype(np.uint8)
            x[:, :, k] = ((M[2][0]*u + M[2][1]*v + M[2][2]*w) & 255).astype(np.uint8)

    @staticmethod
    def _bow(x):
        for (i, j, p), k in zip(m.BOW_STROKES, m.BOW_PRESSURE_ROT):
            pr = ROTL[x[:, :, p], k].astype(np.int32)
            r1 = m.BOW_ROT_BASE + (pr % m.BOW_ROT_MOD)
            r2 = m.BOW_ROT_BASE + ((pr >> m.BOW_R2_SHIFT) % m.BOW_ROT_MOD)
            u = x[:, :, i]; v = x[:, :, j]
            u = ((u.astype(np.int32) + ROTL[v, r1]) & 255).astype(np.uint8)
            v = v ^ ROTL[u, r2]
            x[:, :, i], x[:, :, j] = u, v

    def _odd(self, x):
        for t in (1, 3, 5, 7):
            x[:, :, t-1], x[:, :, t] = latin_np(x[:, :, t-1], x[:, :, t], self.S, self.S2)

    @staticmethod
    def _cross(x):
        for matching in m.CROSS_LAYERS:
            for f, h in matching:
                f, h = sorted((f, h))
                x[:, f, :], x[:, h, :] = mix2_np(x[:, f, :], x[:, h, :])

    def enc(self, s):
        s = self.S[s ^ self.rk]
        s = s[:, self.weave_src]
        for A, B in self.butterfly:
            s[:, A], s[:, B] = mix2_np(s[:, A], s[:, B])
        if self.r % 2 == 0: s[:, self.inner], s[:, self.outer] = mix2_np(s[:, self.inner], s[:, self.outer])
        else:               s[:, self.outer], s[:, self.inner] = mix2_np(s[:, self.outer], s[:, self.inner])
        x = s.reshape(-1, NF, NB)
        self._bar(x); self._trip(x); self._bow(x); self._odd(x); self._cross(x)
        x = self.S2[x]
        self._bar(x); self._trip(x); self._bow(x); self._odd(x); self._cross(x)
        return x.reshape(-1, 128)

    CHECKPOINTS = ("key+S", "weave", "butterfly", "shell", "bar", "trip", "bow", "odd", "cross", "S2",
                   "bar2", "trip2", "bow2", "odd2", "cross2")
    def enc_upto(self, s, stop):
        """Run this round only up to and including checkpoint `stop` (for sub-round tests)."""
        s = self.S[s ^ self.rk]
        if stop == "key+S": return s
        s = s[:, self.weave_src]
        if stop == "weave": return s
        for A, B in self.butterfly:
            s[:, A], s[:, B] = mix2_np(s[:, A], s[:, B])
        if stop == "butterfly": return s
        if self.r % 2 == 0: s[:, self.inner], s[:, self.outer] = mix2_np(s[:, self.inner], s[:, self.outer])
        else:               s[:, self.outer], s[:, self.inner] = mix2_np(s[:, self.outer], s[:, self.inner])
        if stop == "shell": return s
        x = s.reshape(-1, NF, NB)
        steps = [("bar", self._bar), ("trip", self._trip), ("bow", self._bow), ("odd", self._odd), ("cross", self._cross)]
        for name, fn in steps:
            fn(x)
            if stop == name: return x.reshape(-1, 128)
        x = self.S2[x]
        if stop == "S2": return x.reshape(-1, 128)
        for name, fn in steps:
            fn(x)
            if stop == name + "2": return x.reshape(-1, 128)
        raise ValueError(stop)

class NPSchedule:
    def __init__(self, seed, nonce):
        self.sch = harness.schedule(seed, nonce)
        self.rounds = [NPRound(rk, r) for r, rk in enumerate(self.sch.rounds)]
        self.white = np.array([x for row in self.sch.white for x in row], dtype=np.uint8)
    def enc(self, P, rounds, white=True):
        s = np.ascontiguousarray(P, dtype=np.uint8).copy()
        for r in range(rounds): s = self.rounds[r].enc(s)
        return s ^ self.white if white else s
    def enc_frac(self, P, full, stop=None):
        """`full` complete rounds, then round `full` up to checkpoint `stop` (None = nothing more). No whitening."""
        s = np.ascontiguousarray(P, dtype=np.uint8).copy()
        for r in range(full): s = self.rounds[r].enc(s)
        return self.rounds[full].enc_upto(s, stop) if stop else s
    def enc_trace(self, P, rounds):
        """yield state after each round (no whitening) for r=1..rounds"""
        s = np.ascontiguousarray(P, dtype=np.uint8).copy()
        for r in range(rounds):
            s = self.rounds[r].enc(s); yield r + 1, s

def lab_schedule(rng):
    return NPSchedule(rng.bytes(128), rng.bytes(16))

if __name__ == "__main__":
    import os, time
    rng = np.random.default_rng(int.from_bytes(os.urandom(8), "big"))
    ok = 0
    for k in range(4):
        ns = lab_schedule(rng)
        P = rng.integers(0, 256, (6, 128), dtype=np.uint8)
        for rounds in (1, 2, 3, 16):
            C = ns.enc(P, rounds)
            for i in range(len(P)):
                assert bytes(C[i]) == harness.enc_r(bytes(P[i]), ns.sch, rounds), (k, rounds, i)
                ok += 1
    for k in range(3):
        ns = lab_schedule(rng); P = rng.integers(0, 256, (8, 128), dtype=np.uint8)
        for full in (0, 1):
            assert (ns.enc_frac(P, full, "cross2") == ns.enc(P, full + 1, white=False)).all()
    print("enc_frac(..., 'cross2') == full round: OK")
    print(f"NumPy round matches harness.enc_r on {ok} (block, schedule, rounds) cases [4 schedules x 6 blocks x r in 1,2,3,16]")
    ns = lab_schedule(rng); P = rng.integers(0, 256, (1 << 16, 128), dtype=np.uint8)
    t = time.time(); ns.enc(P, 1); dt = time.time() - t
    print(f"NumPy: one round on 65536 blocks in {dt:.2f} s = {dt/65536*1e6:.1f} us/block/round")
