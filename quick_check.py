"""Portable sanity check for a fresh clone: decrypts the published hello-world blob
and round-trips a message under a fresh random seed, with and without associated data.
Run: python3 quick_check.py"""
import os
from sneak_n2 import encrypt, decrypt, load_seed, AuthError, UnsupportedVersion, FMT_VERSION

assert FMT_VERSION == 6
seed = load_seed(os.path.join(os.path.dirname(os.path.abspath(__file__)), "sneak1024-seed.txt"))
blob = bytes.fromhex(next(l for l in open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "hello-world.txt")) if l.startswith("blob")).split()[-1])
assert blob[0] == 6 and decrypt(blob, seed) == b"hello world"
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
for old in (1, 2, 4):
    try:
        decrypt(bytes([old]) + blob[1:], seed); raise SystemExit(f"FAIL: version-{old} blob accepted")
    except UnsupportedVersion:
        pass
print("OK: hello-world decrypts, random-key round trip works, AD binds, tampering and versions 1, 2 and 4 are rejected")
