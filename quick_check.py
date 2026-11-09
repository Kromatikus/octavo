"""Portable sanity check for a fresh clone: decrypts the published hello-world blob
and round-trips a message under a fresh random seed. Run: python3 quick_check.py"""
import os
from sneak_n2 import encrypt, decrypt, load_seed, AuthError

seed = load_seed(os.path.join(os.path.dirname(os.path.abspath(__file__)), "sneak1024-seed.txt"))
blob = bytes.fromhex(next(l for l in open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "hello-world.txt")) if l.startswith("blob")).split()[-1])
assert decrypt(blob, seed) == b"hello world"
key = os.urandom(128)
msg = b"meet at noon"
b2 = encrypt(msg, key)
assert decrypt(b2, key) == msg
bad = bytearray(b2); bad[-1] ^= 1
try:
    decrypt(bytes(bad), key); raise SystemExit("FAIL: tampered blob accepted")
except AuthError:
    pass
print("OK: hello-world decrypts, random-key round trip works, tampering is rejected")
