#!/usr/bin/env python3
"""Decrypt one N2 blob (v6/v7/v9) and seal it as N3 0x1C, then verify the open.

Uses this repository's live N2 (`sneak_n2.py` at the repo root, or OCTAVO_N2_ROOT)
and n3aead built from n3/rust (or N3_AEAD). Homemade; for real secrets use
AES-GCM-SIV, age, or libsodium.
"""
from __future__ import annotations

import argparse
import os
import secrets
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
# Default N2 tree is this repository's root (live sneak_n2.py). Override with OCTAVO_N2_ROOT.
N2_ROOT = os.environ.get("OCTAVO_N2_ROOT", os.path.abspath(os.path.join(HERE, "..")))
# Default n3aead is the binary built from n3/rust. Override with N3_AEAD.
DEFAULT_N3_AEAD = os.environ.get(
    "N3_AEAD", os.path.join(HERE, "rust", "target", "release", "n3aead")
)


def die(msg: str, code: int = 1) -> None:
    print(f"migrate: {msg}", file=sys.stderr)
    raise SystemExit(code)


def load_hex_seed(path: str) -> bytes:
    raw = open(path, "r", encoding="utf-8").read()
    hexdigits = "".join(c for c in raw if c not in " \t\r\n")
    if any(c not in "0123456789abcdefABCDEF" for c in hexdigits):
        die(f"seed file {path} is not hex")
    if len(hexdigits) != 256:
        die(f"seed file {path} must be 256 hex digits (1024 bits), got {len(hexdigits)}")
    return bytes.fromhex(hexdigits)


def classify(blob: bytes) -> str:
    if blob[:5] == b"SN3C/":
        fmt = blob[5] if len(blob) > 5 else -1
        if fmt == 0x1C:
            return "n3-0x1C"
        if fmt == 0x1B:
            return "n3-0x1B"
        return f"n3-0x{fmt:02x}"
    if len(blob) >= 4 and blob[1:4] == b"SN2":
        return {2: "n2-v2", 4: "n2-v4", 6: "n2-v6", 7: "n2-v7", 8: "n2-v8", 9: "n2-v9"}.get(
            blob[0], f"n2-v{blob[0]}"
        )
    return "unknown"


def decrypt_n2(blob: bytes, seed: bytes, ad: bytes) -> bytes:
    sys.path.insert(0, N2_ROOT)
    import sneak_n2  # noqa: E402

    kind = classify(blob)
    if kind == "n2-v6":
        return sneak_n2.decrypt(blob, seed, ad=ad)
    if kind == "n2-v7":
        return sneak_n2.decrypt_movements(blob, seed, ad=ad)
    if kind == "n2-v9":
        return sneak_n2.decrypt_rehearsal(blob, seed, ad=ad)
    if kind == "n2-v2":
        die("legacy v2: open with sneak_n2.decrypt_legacy, then re-run on the plaintext")
    if kind == "n2-v8":
        die("legacy v8: open with sneak_n2.decrypt_rehearsal_legacy(..., allow_unchained=True), then re-run")
    if kind.startswith("n3-"):
        die(f"{kind} is already an N3 blob; this tool starts from N2")
    die(f"unrecognized blob ({kind})")


def ad_hex(ad: bytes) -> str:
    return "-" if ad == b"" else ad.hex()


def run_n3(n3aead: str, args: list[str], data: bytes) -> bytes:
    cmd = [n3aead, *args]
    p = subprocess.run(cmd, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode != 0:
        err = p.stderr.decode("latin1", "replace").strip()
        die(f"n3aead {' '.join(args[:1])} failed (exit {p.returncode}): {err}")
    return p.stdout


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--n2-seed", required=True, help="N2 seed file, 256 hex digits")
    ap.add_argument("--n3-seed", required=True, help="N3 seed file, 256 hex digits (use a fresh one)")
    ap.add_argument("--in", dest="src", required=True, help="N2 blob path")
    ap.add_argument("--out", required=True, help="N3 0x1C blob path (must not exist unless --force)")
    ap.add_argument("--ad", default="-", help="associated data as text, or - for empty")
    ap.add_argument("--ad-hex", default=None, help="associated data as hex (overrides --ad)")
    ap.add_argument("--n3-aead", default=os.environ.get("N3_AEAD", DEFAULT_N3_AEAD))
    ap.add_argument("--force", action="store_true")
    ap.add_argument(
        "--shred-plain",
        action="store_true",
        help="shred the temporary plaintext after a successful round-trip (not the N2 blob)",
    )
    args = ap.parse_args()

    if not os.path.isfile(args.src):
        die(f"missing input {args.src}")
    if os.path.exists(args.out) and not args.force:
        die(f"refusing to overwrite {args.out} (pass --force)")
    if not os.path.isfile(args.n3_aead) or not os.access(args.n3_aead, os.X_OK):
        die(f"n3aead not found or not executable: {args.n3_aead}")

    n2_seed = load_hex_seed(args.n2_seed)
    n3_seed = load_hex_seed(args.n3_seed)
    if n2_seed == n3_seed:
        print("migrate: warning: N2 and N3 seeds are identical; prefer a fresh N3 seed", file=sys.stderr)

    ad = bytes.fromhex(args.ad_hex) if args.ad_hex is not None else (b"" if args.ad == "-" else args.ad.encode("utf-8"))
    blob = open(args.src, "rb").read()
    kind = classify(blob)
    print(f"migrate: detected {kind} ({len(blob)} bytes)")
    plain = decrypt_n2(blob, n2_seed, ad)
    print(f"migrate: N2 open ok ({len(plain)} byte plaintext)")

    nonce = secrets.token_bytes(16)
    n3_blob = run_n3(args.n3_aead, ["seal", n3_seed.hex(), nonce.hex(), ad_hex(ad)], plain)
    if n3_blob[:6] != b"SN3C/\x1c":
        die("n3aead seal did not return an SN3C/ 0x1C blob")
    opened = run_n3(args.n3_aead, ["open", n3_seed.hex(), ad_hex(ad)], n3_blob)
    if opened != plain:
        die("N3 round-trip mismatch")
    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | (0 if args.force else os.O_EXCL), 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(n3_blob)
    print(f"migrate: wrote {args.out} ({len(n3_blob)} bytes, 0x1C, round-trip ok)")
    if args.shred_plain:
        # Plaintext lived only in memory here; nothing to shred unless we wrote a temp.
        print("migrate: plaintext was not written to disk; --shred-plain is a no-op")


if __name__ == "__main__":
    main()
