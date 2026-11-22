"""Stage 0 harness for the Octavo reduced-round analysis (OCT-2).
Imports the tree's sneak_n2.py READ-ONLY and asserts its SHA-256 first. Never writes there.

In the original lab this imported /workspace/sneak_n2. In the repo (and in a live
sneak_n2 checkout) this file lives at analysis/reduced_round/harness.py, so the
cipher module is two directories up.
"""
import hashlib, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
LIVE = os.path.abspath(os.path.join(HERE, "..", ".."))
EXPECTED_SHA = "19181bc1623115c075dc5dee25edec388f5413466777d47b7f19fa66d1e71eee"
_src = open(os.path.join(LIVE, "sneak_n2.py"), "rb").read()
assert hashlib.sha256(_src).hexdigest() == EXPECTED_SHA, "sneak_n2.py changed; stop"
sys.dont_write_bytecode = True
sys.path.insert(0, LIVE)
import sneak_n2 as m  # noqa: E402

NR = m.NR

def schedule(seed: bytes, nonce: bytes):
    return m.Schedule(seed, nonce)

def enc_r(block: bytes, sch, rounds: int, white: bool = True) -> bytes:
    """Reduced-round encryption: first `rounds` live rounds, optional final whitening."""
    return m.grid_to_bytes(m.encrypt_grid(m.bytes_to_grid(block), sch, rounds=rounds, white=white))

def dec_r(block: bytes, sch, rounds: int) -> bytes:
    return m.grid_to_bytes(m.decrypt_grid(m.bytes_to_grid(block), sch, rounds=rounds))

if __name__ == "__main__":
    import time
    seed = hashlib.sha512(b"OCT-2 lab seed (not a real key)").digest()[:128] if False else os.urandom(128)
    nonce = os.urandom(16)
    t = time.time(); sch = schedule(seed, nonce); ts = time.time() - t
    pt = os.urandom(128)
    for r in (1, 2, 4, 16):
        ct = enc_r(pt, sch, r)
        assert dec_r(ct, sch, r) == pt, r
    full = enc_r(pt, sch, 16)
    assert full == m.grid_to_bytes(m.encrypt_grid(m.bytes_to_grid(pt), sch)), "16-round harness != live encrypt_grid"
    t = time.time(); [enc_r(os.urandom(128), sch, 1) for _ in range(50)]; t1 = (time.time() - t) / 50
    print(f"OK: round-trips at 1,2,4,16 rounds; 16-round harness matches live encrypt_grid")
    print(f"Schedule build {ts*1000:.1f} ms; one round {t1*1000:.2f} ms per block (pure Python)")
