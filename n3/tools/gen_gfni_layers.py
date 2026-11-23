#!/usr/bin/env python3 -B
"""Generate straight-line GFNI layer code for N3 chord, triplets and cross.

Public Cauchy matrices over GF(2^8)/0x1F5 are baked in as GF2P8AFFINEQB
qwords (multiply-by-constant bit matrices). No loops or index tables on
the data path. Output: rust/src/gfni_layers.rs, include!-ed by gfni.rs.

Usage: python3 tools/gen_gfni_layers.py [out.rs]
"""
from __future__ import annotations
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
import octavo_n3 as n  # noqa: E402

TF = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2"


def const_mul(a: int, b: int) -> int:
    r = 0
    while b:
        if b & 1:
            r ^= a
        hi = a & 0x80
        a = (a << 1) & 255
        if hi:
            a ^= 0xF5
        b >>= 1
    return r


def mulc_qword(c: int) -> int:
    cols = [const_mul(c, 1 << j) for j in range(8)]
    q = 0
    for i in range(8):
        row = 0
        for j in range(8):
            row |= ((cols[j] >> i) & 1) << j
        q |= row << (8 * (7 - i))
    return q


def xor_tree(xor: str, terms: list[str]) -> str:
    if not terms:
        raise ValueError("empty xor tree")
    xs = list(terms)
    while len(xs) > 1:
        nxt = []
        for i in range(0, len(xs) - 1, 2):
            nxt.append(f"{xor}({xs[i]}, {xs[i + 1]})")
        if len(xs) % 2:
            nxt.append(xs[-1])
        xs = nxt
    return xs[0]


def emit_matvec(name: str, matrix, typ: str, aff: str, xor: str) -> str:
    """Unrolled y = M x on a &mut [T; n] named v."""
    n = len(matrix)
    lines = [
        f"#[inline]",
        f"#[target_feature(enable = \"{TF}\")]",
        f"unsafe fn {name}(v: &mut [{typ}; {n}]) {{",
    ]
    for j in range(n):
        lines.append(f"    let s{j} = v[{j}];")
    for i, row in enumerate(matrix):
        terms = []
        for j, c in enumerate(row):
            c = int(c)
            if c == 0:
                continue
            if c == 1:
                terms.append(f"s{j}")
            else:
                terms.append(f"{aff}(s{j}, 0x{mulc_qword(c):016X})")
        lines.append(f"    let t{i} = {xor_tree(xor, terms)};")
    for i in range(n):
        lines.append(f"    v[{i}] = t{i};")
    lines.append("}")
    return "\n".join(lines) + "\n"


def emit_matvec_axpy(name: str, matrix, typ: str, aff: str, xor: str) -> str:
    """Register-friendly y = M x: accumulate one input column at a time."""
    n = len(matrix)
    lines = [
        f"#[inline]",
        f"#[target_feature(enable = \"{TF}\")]",
        f"unsafe fn {name}(v: &mut [{typ}; {n}]) {{",
    ]
    lines.append("    let s = v[0];")
    for i, row in enumerate(matrix):
        c = int(row[0])
        if c == 0:
            raise ValueError(f"{name}: zero at [{i}][0], Cauchy should not have zeros")
        if c == 1:
            lines.append(f"    let mut t{i} = s;")
        else:
            lines.append(f"    let mut t{i} = {aff}(s, 0x{mulc_qword(c):016X});")
    for j in range(1, n):
        lines.append(f"    let s = v[{j}];")
        for i, row in enumerate(matrix):
            c = int(row[j])
            if c == 0:
                raise ValueError(f"{name}: zero at [{i}][{j}]")
            if c == 1:
                lines.append(f"    t{i} = {xor}(t{i}, s);")
            else:
                lines.append(f"    t{i} = {xor}(t{i}, {aff}(s, 0x{mulc_qword(c):016X}));")
    for i in range(n):
        lines.append(f"    v[{i}] = t{i};")
    lines.append("}")
    return "\n".join(lines) + "\n"


def emit_triplets(name: str, mats, typ: str, aff: str, xor: str, reverse: bool) -> str:
    order = list(range(6))
    if reverse:
        order = list(reversed(order))
    wins = n.TRIPLET_WINDOWS
    lines = [
        f"#[inline]",
        f"#[target_feature(enable = \"{TF}\")]",
        f"unsafe fn {name}(v: &mut [{typ}; 16]) {{",
        f"    // v[f] holds the 8 beats of face f (low 8 bytes, or 4x that in ymm).",
        f"    // Each window is a 3x3 MDS on beats i,j,k of every face; we apply it",
        f"    // after gathering those three beats, but here v is face-major so we",
        f"    // first require beat columns. See trip on 8 beat-columns below.",
        "}",
    ]
    # Triplets are naturally on beat columns (16 faces wide), not face vectors
    # of 8 beats. Emit a version that takes 8 beat-columns instead.
    _ = (name, mats, typ, aff, xor, reverse, wins, lines)
    return ""  # replaced below


def emit_trip_cols(name: str, mats, typ: str, aff: str, xor: str, reverse: bool) -> str:
    """3x3 MDS on overlapping beat windows. v is 8 beat-columns (16 or 64 wide)."""
    order = list(reversed(range(6))) if reverse else list(range(6))
    wins = n.TRIPLET_WINDOWS
    lines = [
        f"#[inline]",
        f"#[target_feature(enable = \"{TF}\")]",
        f"unsafe fn {name}(v: &mut [{typ}; 8]) {{",
    ]
    for t in order:
        i, j, k = wins[t]
        M = mats[t]
        lines.append(f"    {{ // window {t} beats ({i},{j},{k})")
        lines.append(f"        let s0 = v[{i}];")
        lines.append(f"        let s1 = v[{j}];")
        lines.append(f"        let s2 = v[{k}];")
        for r in range(3):
            terms = []
            for c, s in enumerate((0, 1, 2)):
                coeff = int(M[r][c])
                if coeff == 0:
                    continue
                if coeff == 1:
                    terms.append(f"s{s}")
                else:
                    terms.append(f"{aff}(s{s}, 0x{mulc_qword(coeff):016X})")
            lines.append(f"        let t{r} = {xor_tree(xor, terms)};")
        dest = (i, j, k)
        for r, d in enumerate(dest):
            lines.append(f"        v[{d}] = t{r};")
        lines.append("    }")
    lines.append("}")
    return "\n".join(lines) + "\n"


def emit_chord_faces(name: str, M, typ: str, aff: str, xor: str) -> str:
    """8x8 MDS on faces 0..7 and 8..15 independently. v is 16 face-vectors (all beats)."""
    lines = [
        f"#[inline]",
        f"#[target_feature(enable = \"{TF}\")]",
        f"unsafe fn {name}(v: &mut [{typ}; 16]) {{",
    ]
    for shell, base in enumerate((0, 8)):
        lines.append(f"    {{ // shell {shell} faces {base}..{base+7}")
        for j in range(8):
            lines.append(f"        let s{j} = v[{base + j}];")
        for i, row in enumerate(M):
            terms = []
            for j, c in enumerate(row):
                c = int(c)
                if c == 0:
                    continue
                if c == 1:
                    terms.append(f"s{j}")
                else:
                    terms.append(f"{aff}(s{j}, 0x{mulc_qword(c):016X})")
            lines.append(f"        let t{i} = {xor_tree(xor, terms)};")
        for i in range(8):
            lines.append(f"        v[{base + i}] = t{i};")
        lines.append("    }")
    lines.append("}")
    return "\n".join(lines) + "\n"


def main() -> None:
    out = sys.argv[1] if len(sys.argv) > 1 else str(ROOT / "rust/src/gfni_layers.rs")
    parts = [
        f"// @generated by tools/gen_gfni_layers.py -- do not edit.",
        f"// Straight-line chord, triplets and cross for the N3 GFNI backend.",
        f"// Coefficients are public GF(2^8)/0x1F5 Cauchy constants, encoded as",
        f"// GF2P8AFFINEQB multiply-by-constant qwords. No data-dependent lookups.",
        "",
    ]
    specs = [
        # staffs: 8 beat-columns
        ("staff_fwd_x", n.CHORD_M, "staff", "__m128i", "aff128", "_mm_xor_si128"),
        ("staff_inv_x", n.CHORD_INV, "staff", "__m128i", "aff128", "_mm_xor_si128"),
        ("staff_fwd_z", n.CHORD_M, "staff", "__m512i", "aff512", "_mm512_xor_si512"),
        ("staff_inv_z", n.CHORD_INV, "staff", "__m512i", "aff512", "_mm512_xor_si512"),
        ("staff_fwd_y", n.CHORD_M, "staff", "__m256i", "aff256", "_mm256_xor_si256"),
        ("staff_inv_y", n.CHORD_INV, "staff", "__m256i", "aff256", "_mm256_xor_si256"),
        # chord faces: 16 face-vectors
        ("faces_fwd_x", n.CHORD_M, "faces", "__m128i", "aff128", "_mm_xor_si128"),
        ("faces_inv_x", n.CHORD_INV, "faces", "__m128i", "aff128", "_mm_xor_si128"),
        ("faces_fwd_y", n.CHORD_M, "faces", "__m256i", "aff256", "_mm256_xor_si256"),
        ("faces_inv_y", n.CHORD_INV, "faces", "__m256i", "aff256", "_mm256_xor_si256"),
        # cross: 16 face-vectors
        ("cross_fwd_x", n.CROSS_M, "cross", "__m128i", "aff128", "_mm_xor_si128"),
        ("cross_inv_x", n.CROSS_INV, "cross", "__m128i", "aff128", "_mm_xor_si128"),
        ("cross_fwd_y", n.CROSS_M, "cross", "__m256i", "aff256", "_mm256_xor_si256"),
        ("cross_inv_y", n.CROSS_INV, "cross", "__m256i", "aff256", "_mm256_xor_si256"),
        ("cross_fwd_z", n.CROSS_M, "cross_axpy", "__m512i", "aff512", "_mm512_xor_si512"),
        ("cross_inv_z", n.CROSS_INV, "cross_axpy", "__m512i", "aff512", "_mm512_xor_si512"),
        # triplets: 8 beat-columns
        ("trip_fwd_x", n.TRIPLET_MS, "trip", "__m128i", "aff128", "_mm_xor_si128"),
        ("trip_inv_x", n.TRIPLET_INVS, "trip", "__m128i", "aff128", "_mm_xor_si128"),
        ("trip_fwd_z", n.TRIPLET_MS, "trip", "__m512i", "aff512", "_mm512_xor_si512"),
        ("trip_inv_z", n.TRIPLET_INVS, "trip", "__m512i", "aff512", "_mm512_xor_si512"),
        ("trip_fwd_y", n.TRIPLET_MS, "trip", "__m256i", "aff256", "_mm256_xor_si256"),
        ("trip_inv_y", n.TRIPLET_INVS, "trip", "__m256i", "aff256", "_mm256_xor_si256"),
    ]
    for name, M, kind, typ, aff, xor in specs:
        if kind == "staff":
            parts.append(emit_matvec(name, M, typ, aff, xor))
        elif kind == "faces":
            parts.append(emit_chord_faces(name, M, typ, aff, xor))
        elif kind == "cross":
            parts.append(emit_matvec(name, M, typ, aff, xor))
        elif kind == "cross_axpy":
            parts.append(emit_matvec_axpy(name, M, typ, aff, xor))
        elif kind == "trip":
            rev = name.startswith("trip_inv")
            parts.append(emit_trip_cols(name, M, typ, aff, xor, reverse=rev))
        parts.append("")
    Path(out).write_text("\n".join(parts))
    print(f"wrote {out} ({Path(out).stat().st_size} bytes)")


if __name__ == "__main__":
    main()
