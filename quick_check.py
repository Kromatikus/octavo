"""Portable sanity check for a fresh clone: decrypts the published hello-world
and rehearsal-demo blobs, round-trips a message under a fresh random seed,
checks that a missing seed raises TypeError, and confirms score version 11.
Run: python3 quick_check.py"""
import hashlib
import json
import os
from sneak_n2 import (
    FMT_REHEARSAL,
    FMT_VERSION,
    AuthError,
    UnsupportedVersion,
    decrypt,
    decrypt_rehearsal,
    encrypt,
    load_seed,
)

HERE = os.path.dirname(os.path.abspath(__file__))


def blob_from(name):
    return bytes.fromhex(next(l for l in open(os.path.join(HERE, name)) if l.startswith("blob")).split()[-1])


assert FMT_VERSION == 6
assert FMT_REHEARSAL == 9
seed = load_seed(os.path.join(HERE, "sneak1024-seed.txt"))
blob = blob_from("hello-world.txt")
assert blob[0] == 6 and decrypt(blob, seed) == b"hello world"
rblob = blob_from("rehearsal-demo.txt")
assert rblob[0] == 9 and decrypt_rehearsal(rblob, seed, b"rehearsal-demo") == (
    b"Octavo rehearsal: the piece is played in fixed-length passages. "
    b"Each passage is sealed with its own tag, numbered, and the last one is marked final, "
    b"so a cut, a swap or a repeat is heard at once."
)
try:
    decrypt(rblob, seed); raise SystemExit("FAIL: v9 rehearsal blob accepted by decrypt()")
except UnsupportedVersion:
    pass
key = os.urandom(128)
msg = b"meet at noon"
b2 = encrypt(msg, key)
assert decrypt(b2, key) == msg
sealed = encrypt(msg, key, ad=b"from:alice")
assert decrypt(sealed, key, ad=b"from:alice") == msg
try:
    decrypt(sealed, key); raise SystemExit("FAIL: missing AD accepted")
except AuthError:
    pass
bad = bytearray(b2); bad[-1] ^= 1
try:
    decrypt(bytes(bad), key); raise SystemExit("FAIL: tampered blob accepted")
except AuthError:
    pass
for old in (1, 2, 4, 8):
    try:
        decrypt(bytes([old]) + blob[1:], seed); raise SystemExit(f"FAIL: version-{old} blob accepted")
    except UnsupportedVersion:
        pass
try:
    encrypt(msg); raise SystemExit("FAIL: missing seed accepted")
except TypeError as e:
    assert "seed is required" in str(e)
score = json.load(open(os.path.join(HERE, "score", "vectors.json")))
assert score["score_version"] == 11 and score["counts"]["total"] == 79
assert score["revision"] == "rehearsal-honest2"
src = open(os.path.join(HERE, "sneak_n2.py"), "rb").read()
assert hashlib.sha256(src).hexdigest() == score["sneak_n2_sha256"]
print("OK: hello-world (v6) and rehearsal-demo (v9) decrypt, random-key round trip works, AD binds, missing seed raises TypeError, tampering and versions 1, 2, 4 and 8 are rejected, score is version 11, sneak_n2.py SHA matches the published score")
