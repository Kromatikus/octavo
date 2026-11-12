#!/usr/bin/env python3
"""Generate (or regenerate) the published Octavo score: score/vectors.json.

The score is a set of fixed, deterministic test vectors for the raw keyed
permutation and for both AEAD modes, at the published étude round counts
(2, 4, 6) and at the full 16 rounds. Since the conductor revision every
étude runs under its own derived key K_e = StaffSponge(b"E", seed,
rounds || 15 zero bytes).take(128) and hashes its version byte into the SIV
nonce, so no étude vector shares round material with a live blob. The
16-round permutation is still the live staff-core, keyed by K_e.
Score version 3 (conductor): étude bytes 0x82/0x84/0x86/0x90 and
0x83/0x85/0x87/0x91. Score version 4 (rehearsal) adds 8 live format-version-8
rehearsal stream vectors with a pinned pickup and stream nonce; the 64 étude
vectors are unchanged. Score version 5 (rehearsal-fix) regenerates those 8
rehearsal vectors, because the AD digest now enters the R-sponge chunk keys,
tweaks and schedule nonce (v8 was never published, so there is no legacy v8);
the 64 étude vectors are still unchanged. Score version 6 (rehearsal-polish)
regenerates the 8 rehearsal vectors once more: only their tags change (new rehearsal
digest, hence rehearsal_sig); headers and ciphertext blocks match score version 5.
Score version 7 (rehearsal-finale) regenerates them again for the same reason (the
rehearsal-polish attack fixes moved the rehearsal digest); headers and ciphertext
blocks match score version 6, only the tags differ.
The tuning-fix score (0xA*/0xB*, shared live keys) was
never published; the octavo009 score (0xE*/0xF*) is frozen in octavo009.

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
from etudes import etude, etude_key, ETUDE_WARNING, ETUDE_FMT_BLOCK, ETUDE_FMT_MOVEMENTS, ETUDE_ROUNDS, ETUDE_KEY_DOMAIN

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
# Rehearsal (live format version 8) vectors: fixed stream nonces paired with pickups A/B.
# Live encryptors draw a fresh pickup and nonce; the generator pins them only here.
STREAM_NONCE_A = bytes.fromhex("202122232425262728292a2b2c2d2e2f")
STREAM_NONCE_B = bytes.fromhex("303132333435363738393a3b3c3d3e3f")
RH_70000 = bytes((i * 11 + 5) % 256 for i in range(70000))
REHEARSAL_CASES = (
    # (id suffix, msg, ad, chunk_size)
    ("0-cs128", b"", b"", 128),
    ("1-cs128", MSG_1, b"", 128),
    ("127-cs128", MSG_127, b"", 128),
    ("128-cs128", MV_128, b"", 128),
    ("1000-cs256", MV_1000, b"", 256),
    ("1000-ad-cs256", MV_1000, AD, 256),
    ("4096-cs1024", MV_4096, b"", 1024),
    ("70000-cs65536", RH_70000, b"", 65536),
)
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


def _rehearsal_encrypt(msg, seed, ad, chunk_size):
    """Live encrypt_rehearsal with the pickup and stream nonce pinned (vectors only)."""
    pickup, nonce = (PICKUP_B, STREAM_NONCE_B) if ad else (PICKUP_A, STREAM_NONCE_A)
    saved = N._fresh_pickup, N._fresh_stream_nonce
    N._fresh_pickup, N._fresh_stream_nonce = (lambda: pickup), (lambda: nonce)
    try:
        return N.encrypt_rehearsal(msg, seed, ad, chunk_size)
    finally:
        N._fresh_pickup, N._fresh_stream_nonce = saved


_RH_CACHE = {}


def rehearsal_blob(vec_id: str) -> bytes:
    """Rebuild one published rehearsal blob by id (for blobs too long to store as hex)."""
    if vec_id not in _RH_CACHE:
        seed = N.load_seed(SEED_PATH)
        for name, msg, ad, cs in REHEARSAL_CASES:
            if "rehearsal-" + name == vec_id:
                _RH_CACHE[vec_id] = _rehearsal_encrypt(msg, seed, ad, cs)
                break
        else:
            raise KeyError(vec_id)
    return _RH_CACHE[vec_id]


def build_vectors() -> dict:
    """Return the published score as a JSON-serializable dict."""
    seed = N.load_seed(SEED_PATH)
    seed_hex = seed.hex()
    seed_sha = hashlib.sha256(seed).hexdigest()
    file_sha = hashlib.sha256(open(os.path.join(ROOT, "sneak_n2.py"), "rb").read()).hexdigest()
    key_sig = N.key_signature(seed).hex()

    block_cipher = []
    for rounds in ROUNDS:
        E = etude(rounds, lab_seed=True)   # the score is published on the public demo seed
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
        E = etude(rounds, lab_seed=True)   # the score is published on the public demo seed
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
        E = etude(rounds, lab_seed=True)   # the score is published on the public demo seed
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

    rehearsal = []
    for name, msg, ad, cs in REHEARSAL_CASES:
        vid = "rehearsal-" + name
        blob = rehearsal_blob(vid)
        if N.decrypt_rehearsal(blob, seed, ad) != msg:
            raise RuntimeError("rehearsal round-trip failed %s" % name)
        rec = {
            "id": vid,
            "mode": "rehearsal",
            "rounds": 16,
            "ad": _hx(ad),
            "chunk_size": cs,
            "msg_len": len(msg),
            "msg_sha256": hashlib.sha256(msg).hexdigest(),
        }
        if len(msg) <= 128:
            rec["msg"] = _hx(msg)
        rec.update({
            "blob_len": len(blob),
            "blob_sha256": hashlib.sha256(blob).hexdigest(),
            "fmt_version": blob[0],
            "pickup": _hx(blob[4:20]),
            "nonce": _hx(blob[20:36]),
            "commit": _hx(blob[36:68]),
        })
        if len(blob) <= BLOB_HEX_LIMIT:
            rec["blob"] = _hx(blob)
        rec["final_tag"] = _hx(blob[-32:])
        if rec["fmt_version"] != N.FMT_REHEARSAL:
            raise RuntimeError("unexpected rehearsal version")
        rehearsal.append(rec)

    return {
        "name": "Octavo published score",
        "warning": ETUDE_WARNING,
        "note": (
            "Étude blobs use distinct version bytes and cannot be opened by "
            "encrypt/decrypt or encrypt_movements/decrypt_movements. "
            "Current étude blobs carry a tuning commitment (like live v6/v7), "
            "binding encode_ad(ad) and, in movements, nmov. "
            "Every étude runs under its own derived key K_e (sponge domain E, "
            "round count in the tweak) and binds its version byte in the SIV "
            "nonce, so étude vectors never share round material with live blobs. "
            "16-round permute equals the live full-round staff-core keyed by K_e. "
            "Score version 4 (rehearsal) adds 8 LIVE format-version-8 rehearsal "
            "stream vectors (full 16 rounds, demo seed, pinned pickup and stream "
            "nonce); the 64 étude vectors are unchanged from score version 3. "
            "Score version 5 (rehearsal-fix) regenerates the 8 rehearsal vectors "
            "(AD digest now in the R-sponge chunk keys, tweaks and schedule nonce); "
            "the 64 étude vectors are unchanged. "
            "Score version 6 (rehearsal-polish) regenerates the 8 rehearsal vectors "
            "because the rehearsal digest (which attests the whole v8 API code, file "
            "helpers and workers included) moved, so rehearsal_sig and every chunk "
            "TAG changed; headers and ciphertext blocks are byte-identical to score "
            "version 5, and the 64 étude vectors are unchanged. "
            "Score version 7 (rehearsal-finale) regenerates the 8 rehearsal vectors "
            "once more for the same reason (the rehearsal-polish attack fixes moved "
            "the rehearsal digest, hence rehearsal_sig and every chunk TAG); headers "
            "and ciphertext blocks are byte-identical to score version 6, and the 64 "
            "étude vectors are unchanged."
        ),
        "score_version": 7,
        "revision": N.REVISION,
        "revision_date": N.REVISION_DATE,
        "sneak_n2_sha256": file_sha,
        "EXPECTED_MIX_SHA256": N.EXPECTED_MIX_SHA256,
        "key_sig": key_sig,
        "EXPECTED_REHEARSAL_SHA256": N.EXPECTED_REHEARSAL_SHA256,
        "rehearsal_sig": N.rehearsal_signature(seed).hex(),
        "seed": {
            "path": "sneak1024-seed.txt",
            "sha256": seed_sha,
            "hex": seed_hex,
        },
        "format": {
            "etude_rounds": list(ETUDE_ROUNDS),
            "etude_fmt_block": {str(r): v for r, v in ETUDE_FMT_BLOCK.items()},
            "etude_fmt_movements": {str(r): v for r, v in ETUDE_FMT_MOVEMENTS.items()},
            "etude_key": "K_e = StaffSponge(b'E', seed, bytes([rounds]) + 15 zero bytes).take(128)",
            "etude_key_sha256": {str(r): hashlib.sha256(etude_key(seed, r)).hexdigest() for r in ROUNDS},
            "etude_siv_nonce": "SHA-256(clef(K_e) || version || pickup || encode_block(msg) || encode_ad(ad))[:16]; movements: SHA-256(clef(K_e) || version || pickup || u64be(len) || msg || encode_ad(ad))[:16]",
            "pickup_a": _hx(PICKUP_A),
            "pickup_b": _hx(PICKUP_B),
            "permute_nonce": _hx(PERMUTE_NONCE),
            "associated_data": _hx(AD),
            "associated_data_utf8": AD.decode("ascii"),
            "blob_hex_limit": BLOB_HEX_LIMIT,
            "rehearsal_fmt": N.FMT_REHEARSAL,
            "rehearsal_header": "version(1)=8 || SN2(3) || pickup(16) || nonce(16) || commit(32) || chunk_size(4, uint32be)",
            "rehearsal_stream_nonce_a": _hx(STREAM_NONCE_A),
            "rehearsal_stream_nonce_b": _hx(STREAM_NONCE_B),
        },
        "counts": {
            "block_cipher": len(block_cipher),
            "aead": len(aead),
            "movements": len(movements),
            "rehearsal": len(rehearsal),
            "total": len(block_cipher) + len(aead) + len(movements) + len(rehearsal),
        },
        "block_cipher": block_cipher,
        "aead": aead,
        "movements": movements,
        "rehearsal": rehearsal,
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
    print("vectors: %d block-cipher, %d aead, %d movements, %d rehearsal (%d total)" % (
        c["block_cipher"], c["aead"], c["movements"], c["rehearsal"], c["total"]))
    print("sneak_n2.py SHA", data["sneak_n2_sha256"])
    print("key_sig", data["key_sig"])
