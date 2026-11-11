#!/usr/bin/env python3
"""Generate (or regenerate) the published Octavo score: score/vectors.json.

The score is a set of fixed, deterministic test vectors for the raw keyed
permutation and for both AEAD modes, at the published étude round counts
(2, 4, 6) and at the full 16 rounds. 16-round AEAD blobs use étude version
bytes, so they are not interchangeable with live encrypt / encrypt_movements
blobs, but their ciphertext matches the full-round cipher on the same input.

Run from anywhere:
    python3 /workspace/sneak_n2/score/generate_score.py

This overwrites score/vectors.json. The test suite regenerates the vectors
in memory and compares them to the committed file.
"""
import hashlib, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.dont_write_bytecode = True
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import sneak_n2 as N
from etudes import etude, ETUDE_WARNING, ETUDE_FMT_BLOCK, ETUDE_FMT_MOVEMENTS, ETUDE_ROUNDS

# ---------------------------------------------------------------------------
# Fixed inputs. These are part of the published score; do not change them
# without issuing a new score file (and a new revision note).
# ---------------------------------------------------------------------------
SEED_PATH = os.path.join(ROOT, "sneak1024-seed.txt")
# Schedule nonce for raw permutation vectors (not an SIV nonce).
PERMUTE_NONCE = bytes.fromhex("0123456789abcdef0123456789abcdef")
PT_ZERO = bytes(128)
PT_FF = bytes([0xFF] * 128)
PT_SEQ = bytes(range(128))
# Pickup A: empty or omitted AD. Pickup B: used with associated data.
PICKUP_A = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
PICKUP_B = bytes.fromhex("101112131415161718191a1b1c1d1e1f")
AD = b"from:alice"
MSG_0 = b""
MSG_1 = b"A"
MSG_127 = bytes(range(127))
# Movements plaintexts: 0, 128 (two movements), 1000, 4096 bytes.
MV_0 = b""
MV_128 = bytes(range(128))
MV_1000 = bytes((i * 3 + 1) % 256 for i in range(1000))
MV_4096 = bytes((i * 7 + 13) % 256 for i in range(4096))
# Above this blob size, the score records sha256+length instead of full hex.
BLOB_HEX_LIMIT = 2048

ROUNDS = list(ETUDE_ROUNDS)


def _hx(b: bytes) -> str:
    return b.hex()


def _blob_fields(blob: bytes, kind: str) -> dict:
    out = {
        "blob_len": len(blob),
        "blob_sha256": hashlib.sha256(blob).hexdigest(),
        "fmt_version": blob[0],
        "pickup": _hx(blob[4:20]),
        "nonce": _hx(blob[20:36]),
    }
    if len(blob) <= BLOB_HEX_LIMIT:
        out["blob"] = _hx(blob)
    out["commit"] = _hx(blob[36:68])
    if kind == "block":
        out["ciphertext"] = _hx(blob[68:196])
        out["tag"] = _hx(blob[196:228])
    else:
        nmov = int.from_bytes(blob[68:72], "big")
        out["nmov"] = nmov
        out["coda"] = _hx(blob[-32:])
    return out


def build_vectors() -> dict:
    """Return the published score as a JSON-serializable dict."""
    seed = N.load_seed(SEED_PATH)
    seed_hex = seed.hex()
    seed_sha = hashlib.sha256(seed).hexdigest()
    file_sha = hashlib.sha256(open(os.path.join(ROOT, "sneak_n2.py"), "rb").read()).hexdigest()
    key_sig = N.key_signature(seed).hex()

    block_cipher = []
    for rounds in ROUNDS:
        E = etude(rounds)
        for name, pt in (("zero", PT_ZERO), ("ff", PT_FF), ("seq", PT_SEQ),
                         ("hello-block", N.encode_block(b"hello world"))):
            ct = E.permute(pt, seed, PERMUTE_NONCE)
            rec = E.unpermute(ct, seed, PERMUTE_NONCE)
            if rec != pt:
                raise RuntimeError("permute/unpermute mismatch at %s r=%d" % (name, rounds))
            block_cipher.append({
                "id": "permute-r%d-%s" % (rounds, name),
                "rounds": rounds,
                "nonce": _hx(PERMUTE_NONCE),
                "plaintext": _hx(pt),
                "ciphertext": _hx(ct),
            })

    aead = []
    for rounds in ROUNDS:
        E = etude(rounds)
        cases = (
            ("empty", MSG_0, b"", PICKUP_A),
            ("empty-ad", MSG_0, AD, PICKUP_B),
            ("1", MSG_1, b"", PICKUP_A),
            ("1-ad", MSG_1, AD, PICKUP_B),
            ("127", MSG_127, b"", PICKUP_A),
            ("127-ad", MSG_127, AD, PICKUP_B),
        )
        for name, msg, ad, pickup in cases:
            blob = E.encrypt(msg, seed, ad=ad, pickup=pickup)
            if E.decrypt(blob, seed, ad=ad) != msg:
                raise RuntimeError("aead round-trip failed %s r=%d" % (name, rounds))
            rec = {
                "id": "aead-r%d-%s" % (rounds, name),
                "mode": "etude-block",
                "rounds": rounds,
                "ad": _hx(ad),
                "msg": _hx(msg),
            }
            rec.update(_blob_fields(blob, "block"))
            if rec["fmt_version"] != ETUDE_FMT_BLOCK[rounds]:
                raise RuntimeError("unexpected aead version")
            aead.append(rec)

    movements = []
    mv_cases = (
        ("0", MV_0, b"", PICKUP_A),
        ("128", MV_128, b"", PICKUP_A),
        ("1000", MV_1000, b"", PICKUP_A),
        ("4096", MV_4096, b"", PICKUP_A),
        ("128-ad", MV_128, AD, PICKUP_B),
        ("1000-ad", MV_1000, AD, PICKUP_B),
    )
    for rounds in ROUNDS:
        E = etude(rounds)
        for name, msg, ad, pickup in mv_cases:
            blob = E.encrypt_movements(msg, seed, ad=ad, pickup=pickup)
            if E.decrypt_movements(blob, seed, ad=ad) != msg:
                raise RuntimeError("movements round-trip failed %s r=%d" % (name, rounds))
            rec = {
                "id": "movements-r%d-%s" % (rounds, name),
                "mode": "etude-movements",
                "rounds": rounds,
                "ad": _hx(ad),
                "msg_len": len(msg),
                "msg_sha256": hashlib.sha256(msg).hexdigest(),
            }
            if len(msg) <= 128:
                rec["msg"] = _hx(msg)
            rec.update(_blob_fields(blob, "movements"))
            if rec["fmt_version"] != ETUDE_FMT_MOVEMENTS[rounds]:
                raise RuntimeError("unexpected movements version")
            movements.append(rec)

    return {
        "name": "Octavo published score",
        "warning": ETUDE_WARNING,
        "note": (
            "Étude blobs use distinct version bytes and cannot be opened by "
            "encrypt/decrypt or encrypt_movements/decrypt_movements. "
            "Current étude blobs carry a tuning commitment (like live v6/v7), "
            "binding encode_ad(ad) and, in movements, nmov. "
            "16-round permute and 16-round étude ciphertext match the live "
            "full-round cipher on the same seed, nonce and input; commitments and tags differ."
        ),
        "revision": N.REVISION,
        "revision_date": N.REVISION_DATE,
        "sneak_n2_sha256": file_sha,
        "EXPECTED_MIX_SHA256": N.EXPECTED_MIX_SHA256,
        "key_sig": key_sig,
        "seed": {
            "path": "sneak1024-seed.txt",
            "sha256": seed_sha,
            "hex": seed_hex,
        },
        "format": {
            "etude_rounds": list(ETUDE_ROUNDS),
            "etude_fmt_block": {str(r): v for r, v in ETUDE_FMT_BLOCK.items()},
            "etude_fmt_movements": {str(r): v for r, v in ETUDE_FMT_MOVEMENTS.items()},
            "pickup_a": _hx(PICKUP_A),
            "pickup_b": _hx(PICKUP_B),
            "permute_nonce": _hx(PERMUTE_NONCE),
            "associated_data": _hx(AD),
            "associated_data_utf8": AD.decode("ascii"),
            "blob_hex_limit": BLOB_HEX_LIMIT,
        },
        "counts": {
            "block_cipher": len(block_cipher),
            "aead": len(aead),
            "movements": len(movements),
            "total": len(block_cipher) + len(aead) + len(movements),
        },
        "block_cipher": block_cipher,
        "aead": aead,
        "movements": movements,
    }


def vectors_path(path=None) -> str:
    return path or os.path.join(HERE, "vectors.json")


def write_vectors(path=None) -> str:
    data = build_vectors()
    dest = vectors_path(path)
    with open(dest, "w") as f:
        json.dump(data, f, indent=2, sort_keys=False)
        f.write("\n")
    return dest


def load_committed(path=None) -> dict:
    with open(vectors_path(path)) as f:
        return json.load(f)


if __name__ == "__main__":
    dest = write_vectors()
    data = load_committed(dest)
    c = data["counts"]
    print("wrote", dest)
    print("revision", data["revision"], data["revision_date"])
    print("vectors: %d block-cipher, %d aead, %d movements (%d total)" % (
        c["block_cipher"], c["aead"], c["movements"], c["total"]))
    print("sneak_n2.py SHA", data["sneak_n2_sha256"])
    print("key_sig", data["key_sig"])
