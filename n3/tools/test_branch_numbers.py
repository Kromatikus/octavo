#!/usr/bin/env python3
"""Run branch-number tests on draft-3 maps; confirm draft-2 vectors still match.

Passes on the real constants. Must fail on the silent-weakness mutants
listed below, taken from /workspace/octavo_n3_mutlab1/results.csv.

Homemade; for real secrets use AES-GCM-SIV, age, or libsodium.
"""
from __future__ import annotations

import json
import sys
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DRAFT2_VECTORS = Path("/workspace/octavo_n3_draft2/vectors/draft2_vectors.json")
sys.path.insert(0, str(ROOT / "python"))
sys.path.insert(0, str(ROOT / "tools"))

import octavo_n3 as n3  # noqa: E402
import branch_numbers as bn  # noqa: E402

# Silent-weakness singles from mutlab1 (invertible, loose full-round
# avalanche would pass, but a mix BN dropped). Values are the exact
# recorded changes.
SILENT_SAMPLES = [
    {
        "id": "S003_0",
        "changes": "MIX2_MATRIX[1][1] 2->0",
        "kind": "mix2",
        "i": 1,
        "j": 1,
        "old": 2,
        "new": 0,
    },
    {
        "id": "S011_0",
        "changes": "CHORD_M[0][7] 143->145",
        "kind": "chord",
        "i": 0,
        "j": 7,
        "old": 143,
        "new": 145,
    },
    {
        "id": "S039_0",
        "changes": "CHORD_M[4][3] 143->144",
        "kind": "chord",
        "i": 4,
        "j": 3,
        "old": 143,
        "new": 144,
    },
    {
        "id": "S058_0",
        "changes": "CHORD_M[6][6] 196->192",
        "kind": "chord",
        "i": 6,
        "j": 6,
        "old": 196,
        "new": 192,
    },
    {
        "id": "S068_0",
        "changes": "CROSS_M[0][0] 98->96",
        "kind": "cross",
        "i": 0,
        "j": 0,
        "old": 98,
        "new": 96,
    },
    {
        "id": "S077_0",
        "changes": "CROSS_M[3][3] 98->92",
        "kind": "cross",
        "i": 3,
        "j": 3,
        "old": 98,
        "new": 92,
    },
    {
        "id": "S089_0",
        "changes": "CROSS_M[7][7] 98->104",
        "kind": "cross",
        "i": 7,
        "j": 7,
        "old": 98,
        "new": 104,
    },
]


def apply_sample(sample):
    mix2 = bn.as_mutable(bn.mix2_matrix_from_fn())
    chord = bn.as_mutable(n3.CHORD_M)
    trips = [bn.as_mutable(M) for M in n3.TRIPLET_MS]
    cross = bn.as_mutable(n3.CROSS_M)
    kind, i, j, old, new = sample["kind"], sample["i"], sample["j"], sample["old"], sample["new"]
    target = {"mix2": mix2, "chord": chord, "cross": cross}[kind]
    got = target[i][j]
    if got != old:
        raise SystemExit(
            f"{sample['id']}: expected baseline {kind}[{i}][{j}]={old}, found {got}"
        )
    target[i][j] = new
    return (
        bn.to_tuple(mix2),
        bn.to_tuple(chord),
        tuple(bn.to_tuple(M) for M in trips),
        bn.to_tuple(cross),
    )


def cipher_roundtrip(n_blocks=4) -> None:
    seed = bytes(range(128))
    nonce = bytes(range(16))
    c = n3.Cipher(seed, nonce)
    for k in range(n_blocks):
        pt = bytes((k * 17 + i) & 255 for i in range(128))
        ct = c.encrypt_block(pt)
        pt2 = c.decrypt_block(ct)
        if pt2 != pt:
            raise SystemExit(f"cipher invertibility failed on block {k}")
        if ct == pt:
            raise SystemExit(f"cipher produced a fixed point on block {k}")


def check_draft2_vectors() -> int:
    data = json.loads(DRAFT2_VECTORS.read_text())
    ok = 0
    for vec in data["vectors"]:
        seed = bytes.fromhex(vec["seed"])
        nonce = bytes.fromhex(vec["nonce"])
        pt = bytes.fromhex(vec["pt"])
        expect = bytes.fromhex(vec["ct"])
        got = n3.encrypt_block(seed, nonce, pt)
        if got != expect:
            raise SystemExit(
                f"draft-3 Python output differs from draft-2 vector {vec['name']}"
            )
        back = n3.decrypt_block(seed, nonce, got)
        if back != pt:
            raise SystemExit(f"draft-3 decrypt failed on vector {vec['name']}")
        ok += 1
    return ok


def main() -> int:
    print("== draft-2 vectors (cipher output must be unchanged) ==")
    nvec = check_draft2_vectors()
    print(f"  {nvec} vectors match /workspace/octavo_n3_draft2/vectors/draft2_vectors.json")

    print("== cipher invertibility (4 blocks) ==")
    cipher_roundtrip(4)
    print("  ok")

    print("== baseline maps (must pass) ==")
    mix2 = bn.mix2_matrix_from_fn()
    print(f"  mix2 matrix = {mix2}")
    fails = bn.check_maps()
    if fails:
        print("  FAIL on real constants:")
        for f in fails:
            print("   -", f)
        return 1
    print(
        f"  pass  mix2 BN>={bn.MIX2_BN_MIN} no zeros, "
        f"chord MDS/BN {bn.CHORD_BN_MIN}, "
        f"triplets MDS/BN {bn.TRIPLET_BN_MIN}, "
        f"cross Cauchy + observed BN>={bn.CROSS_BN_MIN}, "
        f"implied 1-round >={bn.IMPLIED_ONE_ROUND_MIN}"
    )

    print("== silent-weakness mutants from mutlab1 (must fail) ==")
    caught = 0
    details = []
    for sample in SILENT_SAMPLES:
        m2, ch, tr, cr = apply_sample(sample)
        fails = bn.check_maps(mix2=m2, chord=ch, triplets=tr, cross=cr)
        status = "caught" if fails else "MISSED"
        if fails:
            caught += 1
        details.append((sample["id"], status, fails, sample["changes"]))
        preview = "; ".join(fails) if fails else "no failures (test gap)"
        print(f"  {status} {sample['id']}  {sample['changes']}")
        for line in fails:
            print(f"      {line}")
        if not fails:
            print("      TEST GAP: this silent mutant was not rejected")

    n = len(SILENT_SAMPLES)
    print(f"== summary: caught {caught} of {n} sampled silent mutants ==")
    out = {
        "baseline_pass": True,
        "vectors_matched": nvec,
        "caught": caught,
        "sampled": n,
        "details": [
            {"id": i, "status": s, "failures": f, "changes": c}
            for i, s, f, c in details
        ],
    }
    dest = ROOT / "vectors" / "branch_tests.json"
    dest.write_text(json.dumps(out, indent=2) + "\n")
    print(f"  wrote {dest}")
    if caught != n:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
