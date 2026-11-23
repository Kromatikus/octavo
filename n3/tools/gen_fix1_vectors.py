#!/usr/bin/env python3
"""fix1 (format 0x1B, 8-stroke bow) vectors from the Python reference.
Same names/seeds/nonces/pts as ctkey1_vectors.json; new ciphertexts.
Homemade; for real secrets use AES-GCM-SIV, age, or libsodium."""
import json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
import octavo_n3 as n3
assert n3.FORMAT_BYTE == 0x1B
old = json.load(open(ROOT / "vectors/ctkey1_vectors.json"))
out = {"draft": "n3-fix1", "format_byte": 0x1B, "prefix": "SN3C/", "vectors": []}
for v in old["vectors"]:
    seed, nonce, pt = (bytes.fromhex(v[k]) for k in ("seed", "nonce", "pt"))
    ct = n3.encrypt_block(seed, nonce, pt)
    assert n3.decrypt_block(seed, nonce, ct) == pt
    assert ct.hex() != v["ct"]
    out["vectors"].append({"name": v["name"], "seed": v["seed"], "nonce": v["nonce"], "pt": v["pt"], "ct": ct.hex()})
    print(v["name"], ct.hex()[:32], flush=True)
json.dump(out, open(ROOT / "vectors/fix1_vectors.json", "w"), indent=2)
