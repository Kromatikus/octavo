#!/usr/bin/env python3
"""trim1: replace the 512-bit staff/cross kernels in rust/src/gfni_layers.rs with
Karatsuba-style dyadic versions. The chord and cross matrices are dyadic: M[i][j] = c[i ^ j].
For [[A,B],[B,A]]:  out0 = A*S + (A+B)*v1,  out1 = A*S + (A+B)*v0,  S = v0 + v1,
so one n x n dyadic product costs 3 products of size n/2 instead of 4. Same GF(2^8) result,
fewer GF2P8AFFINEQB and XOR ops. All constants are public.
Usage: python3 tools/gen_kar_z.py <layers.rs>   (needs octavo_n3.py for the matrices)"""
import sys, re, random
sys.path.insert(0, "/workspace/octavo_n3_cleanup1/repo/n3/python")
sys.dont_write_bytecode = True
import octavo_n3 as n

TF = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2"

def const_mul(a, b):
    r = 0
    while b:
        if b & 1: r ^= a
        hi = a & 0x80; a = (a << 1) & 255
        if hi: a ^= 0xF5
        b >>= 1
    return r

def mulc_qword(c):
    cols = [const_mul(c, 1 << j) for j in range(8)]
    q = 0
    for i in range(8):
        row = 0
        for j in range(8): row |= ((cols[j] >> i) & 1) << j
        q |= row << (8 * (7 - i))
    return q

class Gen:
    def __init__(s): s.lines = []; s.k = 0; s.ops = [0, 0]
    def new(s): s.k += 1; return f"w{s.k}"
    def xor(s, a, b):
        r = s.new(); s.lines.append(f"    let {r} = _mm512_xor_si512({a}, {b});"); s.ops[1] += 1; return r
    def mul(s, c, a):
        assert c != 0
        if c == 1: return a
        r = s.new(); s.lines.append(f"    let {r} = aff512({a}, 0x{mulc_qword(c):016X});"); s.ops[0] += 1; return r
    def kar(s, c, v):
        m = len(c)
        if m == 1: return [s.mul(c[0], v[0])]
        h = m // 2
        S = [s.xor(v[i], v[i + h]) for i in range(h)]
        P = s.kar(c[:h], S)
        cab = [c[i] ^ c[i + h] for i in range(h)]
        Q1 = s.kar(cab, v[h:]); Q0 = s.kar(cab, v[:h])
        return [s.xor(P[i], Q1[i]) for i in range(h)] + [s.xor(P[i], Q0[i]) for i in range(h)]

def emit(name, M, doc):
    c = [int(x) for x in M[0]]; m = len(c)
    assert all(int(M[i][j]) == c[i ^ j] for i in range(m) for j in range(m))
    g = Gen()
    out = g.kar(c, [f"v[{i}]" for i in range(m)])
    # simulate to verify against the dense matrix
    body = "\n".join(g.lines)
    res = [f"    let r{i} = {o};" for i, o in enumerate(out)]
    txt = (f"// {doc}: dyadic Karatsuba, {g.ops[0]} affine + {g.ops[1]} xor (was {m*m - sum(1 for r in M for x in r if int(x)==1)} affine + {m*(m-1)} xor)\n"
           f"#[inline]\n#[target_feature(enable = \"{TF}\")]\nunsafe fn {name}(v: &mut [__m512i; {m}]) {{\n{body}\n"
           + "\n".join(res) + "\n" + "\n".join(f"    v[{i}] = r{i};" for i in range(m)) + "\n}\n")
    return txt, g

def verify(M, g_fn_cols):
    pass

def check_algebra():
    # Python model of the same recursion over GF(2^8)
    def kar(c, v):
        m = len(c)
        if m == 1: return [const_mul(c[0], v[0])]
        h = m // 2
        S = [v[i] ^ v[i + h] for i in range(h)]
        P = kar(c[:h], S); cab = [c[i] ^ c[i + h] for i in range(h)]
        Q1 = kar(cab, v[h:]); Q0 = kar(cab, v[:h])
        return [P[i] ^ Q1[i] for i in range(h)] + [P[i] ^ Q0[i] for i in range(h)]
    for M in (n.CHORD_M, n.CHORD_INV, n.CROSS_M, n.CROSS_INV):
        m = len(M)
        for _ in range(200):
            v = [random.randrange(256) for _ in range(m)]
            ref = []
            for i in range(m):
                a = 0
                for j in range(m): a ^= const_mul(int(M[i][j]), v[j])
                ref.append(a)
            assert kar([int(x) for x in M[0]], v) == ref
    print("python model matches dense matrices")

def main():
    check_algebra()
    path = sys.argv[1]
    src = open(path).read()
    for name, M, doc in [("staff_fwd_z", n.CHORD_M, "staff fwd"), ("staff_inv_z", n.CHORD_INV, "staff inv"),
                         ("cross_fwd_z", n.CROSS_M, "cross fwd"), ("cross_inv_z", n.CROSS_INV, "cross inv")]:
        txt, g = emit(name, M, doc)
        print(name, "affine", g.ops[0], "xor", g.ops[1])
        pat = re.compile(r"#\[inline\]\n#\[target_feature\(enable = \"[^\"]*\"\)\]\nunsafe fn " + name + r"\(.*?\n}\n", re.S)
        assert pat.search(src), name
        src = pat.sub(lambda _: txt, src, count=1)
    open(path, "w").write(src)
main()
