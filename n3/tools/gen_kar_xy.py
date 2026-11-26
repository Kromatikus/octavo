#!/usr/bin/env python3
"""trim2: replace the 128-bit (x) and 256-bit (y) staff/faces/cross kernels in rust/src/gfni_layers.rs with
Karatsuba-style dyadic versions. The chord and cross matrices are dyadic: M[i][j] = c[i ^ j].
For [[A,B],[B,A]]:  out0 = A*S + (A+B)*v1,  out1 = A*S + (A+B)*v0,  S = v0 + v1,
so one n x n dyadic product costs 3 products of size n/2 instead of 4. Same GF(2^8) result,
fewer GF2P8AFFINEQB and XOR ops. All constants are public.
Usage: python3 tools/gen_kar_xy.py <layers.rs>   (needs octavo_n3.py for the matrices)"""
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
    def __init__(s, xor_fn, aff_fn, ind="    "):
        s.lines = []; s.k = 0; s.ops = [0, 0]; s.xf = xor_fn; s.af = aff_fn; s.ind = ind
    def new(s): s.k += 1; return f"w{s.k}"
    def xor(s, a, b):
        r = s.new(); s.lines.append(f"{s.ind}let {r} = {s.xf}({a}, {b});"); s.ops[1] += 1; return r
    def mul(s, c, a):
        assert c != 0
        if c == 1: return a
        r = s.new(); s.lines.append(f"{s.ind}let {r} = {s.af}({a}, 0x{mulc_qword(c):016X});"); s.ops[0] += 1; return r
    def kar(s, c, v):
        m = len(c)
        if m == 1: return [s.mul(c[0], v[0])]
        h = m // 2
        S = [s.xor(v[i], v[i + h]) for i in range(h)]
        P = s.kar(c[:h], S)
        cab = [c[i] ^ c[i + h] for i in range(h)]
        Q1 = s.kar(cab, v[h:]); Q0 = s.kar(cab, v[:h])
        return [s.xor(P[i], Q1[i]) for i in range(h)] + [s.xor(P[i], Q0[i]) for i in range(h)]

TYPES = {"x": ("__m128i", "aff128", "_mm_xor_si128"), "y": ("__m256i", "aff256", "_mm256_xor_si256")}

def emit(name, M, kind, w, doc):
    typ, aff, xor = TYPES[w]
    c = [int(x) for x in M[0]]; m = len(c)
    assert all(int(M[i][j]) == c[i ^ j] for i in range(m) for j in range(m))
    nv = 16 if kind in ("faces", "cross") else 8
    groups = [0, 8] if kind == "faces" else [0]
    ind = "        " if kind == "faces" else "    "
    body = []; tot = [0, 0]
    for base in groups:
        g = Gen(xor, aff, ind)
        out = g.kar(c, [f"v[{base + i}]" for i in range(m)])
        if kind == "faces":
            body.append(f"    {{ // shell faces {base}..{base + 7}")
        body += g.lines
        body += [f"{ind}let r{i} = {o};" for i, o in enumerate(out)]
        body += [f"{ind}v[{base + i}] = r{i};" for i in range(m)]
        if kind == "faces":
            body.append("    }")
        tot[0] += g.ops[0]; tot[1] += g.ops[1]
    txt = (f"// {doc}: dyadic Karatsuba, {tot[0]} affine + {tot[1]} xor\n"
           f"#[inline]\n#[target_feature(enable = \"{TF}\")]\nunsafe fn {name}(v: &mut [{typ}; {nv}]) {{\n"
           + "\n".join(body) + "\n}\n")
    return txt, tot

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
    specs = []
    for w in ("x", "y"):
        for d, Mc, Mi in (("fwd", n.CHORD_M, None), ("inv", n.CHORD_INV, None)):
            specs.append((f"staff_{d}_{w}", Mc, "staff", w))
            specs.append((f"faces_{d}_{w}", Mc, "faces", w))
        specs.append((f"cross_fwd_{w}", n.CROSS_M, "cross", w))
        specs.append((f"cross_inv_{w}", n.CROSS_INV, "cross", w))
    for name, M, kind, w in specs:
        txt, tot = emit(name, M, kind, w, name)
        print(name, "affine", tot[0], "xor", tot[1])
        pat = re.compile(r"#\[inline\]\n#\[target_feature\(enable = \"[^\"]*\"\)\]\nunsafe fn " + name + r"\(.*?\n}\n", re.S)
        assert pat.search(src), name
        src = pat.sub(lambda _: txt, src, count=1)
    open(path, "w").write(src)
main()
