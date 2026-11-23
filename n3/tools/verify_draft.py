#!/usr/bin/env python3
"""Generate ctkey1 (format 0x1A) test vectors, check Rust == Python, invertibility, avalanche.

Homemade; for real secrets use AES-GCM-SIV, age, or libsodium.
"""

from __future__ import annotations

import hashlib
import json
import random
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
import octavo_n3 as n3  # noqa: E402

CARGO_DIR = ROOT / "rust"
VECTORS = ROOT / "vectors"
TARGET = ROOT / "target"
BIN = TARGET / "release" / "n3draft"


def sha_bytes(label: bytes, n: int) -> bytes:
    out = b""
    c = 0
    while len(out) < n:
        out += hashlib.sha256(b"octavo-n3-ctkey1/" + label + c.to_bytes(4, "big")).digest()
        c += 1
    return out[:n]


def build_rust() -> Path:
    env = dict(**__import__("os").environ)
    env["CARGO_TARGET_DIR"] = str(TARGET)
    subprocess.check_call(
        ["cargo", "build", "--release", "--bin", "n3draft"],
        cwd=CARGO_DIR,
        env=env,
    )
    if not BIN.is_file():
        raise SystemExit(f"missing {BIN}")
    return BIN


def rust_batch(bin_path: Path, jobs: list[tuple[str, bytes, bytes, bytes]]) -> list[bytes]:
    """jobs are (op, seed, nonce, block). Returns output blocks, same order."""
    text = "\n".join(
        f"{op} {seed.hex()} {nonce.hex()} {block.hex()}" for op, seed, nonce, block in jobs
    ) + "\n"
    proc = subprocess.run(
        [str(bin_path)],
        input=text,
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise SystemExit(f"n3draft failed:\n{proc.stderr}")
    lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
    if len(lines) != len(jobs):
        raise SystemExit(f"expected {len(jobs)} rust lines, got {len(lines)}")
    return [bytes.fromhex(ln) for ln in lines]


def hamming(a: bytes, b: bytes) -> int:
    return sum((x ^ y).bit_count() for x, y in zip(a, b))


def main() -> int:
    t0 = time.perf_counter()
    print("== linear maps ==")
    maps = n3.verify_linear_maps()
    for k, v in maps.items():
        print(f"  {k}: {v}")
        if not v:
            raise SystemExit("linear-map check failed")

    print("== build rust ==")
    bin_path = build_rust()

    print("== deterministic vectors (Python vs Rust) ==")
    cases = [
        ("zero-pt", sha_bytes(b"seed-a", 128), sha_bytes(b"nonce-a", 16), bytes(128)),
        ("ff-pt", sha_bytes(b"seed-a", 128), sha_bytes(b"nonce-a", 16), bytes([0xFF] * 128)),
        ("seq-pt", sha_bytes(b"seed-b", 128), sha_bytes(b"nonce-b", 16), bytes(range(128))),
        (
            "pattern",
            sha_bytes(b"seed-c", 128),
            sha_bytes(b"nonce-c", 16),
            bytes((5 * i + 1) & 255 for i in range(128)),
        ),
        (
            "hello",
            sha_bytes(b"seed-d", 128),
            bytes(range(16)),
            (b"hello world" + bytes(128))[:128],
        ),
    ]
    vector_rows = []
    jobs = []
    py_cts = []
    for name, seed, nonce, pt in cases:
        ciph = n3.Cipher(seed, nonce)
        ct = ciph.encrypt_block(pt)
        pt2 = ciph.decrypt_block(ct)
        if pt2 != pt:
            raise SystemExit(f"Python invertibility failed on {name}")
        py_cts.append(ct)
        jobs.append(("e", seed, nonce, pt))
        vector_rows.append(
            {
                "name": name,
                "seed": seed.hex(),
                "nonce": nonce.hex(),
                "pt": pt.hex(),
                "ct": ct.hex(),
            }
        )
    rust_cts = rust_batch(bin_path, jobs)
    rust_jobs_d = [("d", s, n, ct) for (_, s, n, _), ct in zip(jobs, rust_cts)]
    rust_pts = rust_batch(bin_path, rust_jobs_d)
    for (name, seed, nonce, pt), py_ct, ru_ct, ru_pt in zip(cases, py_cts, rust_cts, rust_pts):
        if py_ct != ru_ct:
            raise SystemExit(f"Rust != Python encrypt on {name}")
        if ru_pt != pt:
            raise SystemExit(f"Rust decrypt failed on {name}")
        print(f"  {name}: agree  ct[0:8]={py_ct[:8].hex()}")

    VECTORS.mkdir(exist_ok=True)
    vec_path = VECTORS / "ctkey1_vectors.json"
    vec_path.write_text(json.dumps({"draft": "n3-ctkey1", "format_byte": 26, "prefix": "SN3C/", "vectors": vector_rows}, indent=2) + "\n")
    print(f"  wrote {vec_path}")

    print("== 1000 random blocks: decrypt(encrypt(x))==x and Rust==Python ==")
    rng = random.Random(20261122)
    seed = sha_bytes(b"rand-seed", 128)
    nonce = sha_bytes(b"rand-nonce", 16)
    ciph = n3.Cipher(seed, nonce)
    pts = [bytes(rng.randrange(256) for _ in range(128)) for _ in range(1000)]
    py_cts_r = [ciph.encrypt_block(pt) for pt in pts]
    for i, (pt, ct) in enumerate(zip(pts, py_cts_r)):
        if ciph.decrypt_block(ct) != pt:
            raise SystemExit(f"Python invertibility failed on random block {i}")
    rust_cts_r = rust_batch(bin_path, [("e", seed, nonce, pt) for pt in pts])
    rust_pts_r = rust_batch(bin_path, [("d", seed, nonce, ct) for ct in rust_cts_r])
    if rust_cts_r != py_cts_r:
        bad = next(i for i, (a, b) in enumerate(zip(py_cts_r, rust_cts_r)) if a != b)
        raise SystemExit(f"Rust != Python on random block {bad}")
    if rust_pts_r != pts:
        raise SystemExit("Rust invertibility failed on a random block")
    print("  1000/1000 invertibility and agreement")

    print("== avalanche (1-bit input flips, full 16 rounds) ==")
    # Fixed key; 4 deterministic plaintexts; every 1024 input bits flipped once.
    av_seed = sha_bytes(b"avalanche-seed", 128)
    av_nonce = sha_bytes(b"avalanche-nonce", 16)
    av = n3.Cipher(av_seed, av_nonce)
    bases = [
        bytes(128),
        bytes([0xFF] * 128),
        bytes(range(128)),
        sha_bytes(b"avalanche-pt", 128),
    ]
    distances = []
    for bi, base in enumerate(bases):
        ct0 = av.encrypt_block(base)
        buf = bytearray(base)
        for bit in range(1024):
            byte, off = divmod(bit, 8)
            buf[byte] ^= 1 << off
            ct1 = av.encrypt_block(bytes(buf))
            buf[byte] ^= 1 << off
            distances.append(hamming(ct0, ct1))
        print(f"  plaintext {bi}: mean so far {sum(distances)/len(distances)/1024:.6f}")
    mean_bits = sum(distances) / len(distances)
    mean_frac = mean_bits / 1024
    min_bits = min(distances)
    max_bits = max(distances)
    print(
        f"  n={len(distances)}  mean flipped bits={mean_bits:.4f}/1024  "
        f"fraction={mean_frac:.6f}  min={min_bits}  max={max_bits}"
    )
    result = {
        "maps": maps,
        "vectors": str(vec_path),
        "random_blocks": 1000,
        "rust_python_agree": True,
        "invertibility": True,
        "avalanche": {
            "plaintexts": 4,
            "bits_per_plaintext": 1024,
            "n": len(distances),
            "mean_flipped_bits": mean_bits,
            "mean_fraction": mean_frac,
            "min_flipped_bits": min_bits,
            "max_flipped_bits": max_bits,
        },
        "elapsed_s": time.perf_counter() - t0,
    }
    outp = VECTORS / "ctkey1_verify.json"
    outp.write_text(json.dumps(result, indent=2) + "\n")
    print(f"  wrote {outp}")
    print(f"done in {result['elapsed_s']:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
