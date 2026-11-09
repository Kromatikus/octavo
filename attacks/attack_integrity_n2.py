"""N2 attack 1 — integrity / MAC (the hole N1 failed): random & SN2-prefixed blobs, every bit-flip class,
splicing, truncation/extension, chosen-message forgery without the seed, and whether a valid MAC leaks
anything through the decoder (N1's decode-success oracle)."""
import sys, os, random, time, statistics
sys.path.insert(0, "/workspace/sneak_n2"); import sneak_n2 as N
SEED = N.load_seed(); R = random.Random(11); out = []
def log(*a): s = " ".join(map(str, a)); print(s); out.append(s)
rb = lambda n: bytes(R.randrange(256) for _ in range(n))
def accepted(blob, seed=SEED):
    try: N.decrypt(blob, seed); return True
    except (N.AuthError, N.DecodeError, ValueError): return False
def err(blob, seed=SEED):
    try: N.decrypt(blob, seed); return "ACCEPTED"
    except Exception as e: return type(e).__name__

DEMO_NONCE = bytes.fromhex(open("/workspace/sneak_n2/demo-nonce.txt").read().strip())
demo = N.encrypt(b"hello world", SEED, DEMO_NONCE)
log("=== N2 integrity / authentication ===")
log(f"demo blob ({len(demo)} bytes): {demo.hex()}")
log(f"demo decrypts: {N.decrypt(demo, SEED)!r}")

# 1. random blobs (compare N1: ~1/255 = 0.39% silently accepted)
NN = 200000
acc = sum(accepted(rb(115)) for _ in range(NN))
log(f"[random blobs] {NN} random 115-byte blobs accepted: {acc}/{NN} ({100*acc/NN:.4f}%)  [N1 accepted ~0.39% of 64-byte cts]")
M = 10000  # SN2-prefixed blobs build a full schedule each, so a smaller (still decisive) sample
acc2 = sum(accepted(b"SN2" + rb(112)) for _ in range(M))
log(f"[random blobs] {M} random blobs WITH correct 'SN2' prefix accepted: {acc2}/{M}")
# random nonce fixed to the demo nonce, random ct+tag (attacker knows the public nonce)
acc3 = sum(accepted(b"SN2" + DEMO_NONCE + rb(96)) for _ in range(M))
log(f"[random blobs] {M} blobs with 'SN2'+real demo nonce, random ct+tag accepted: {acc3}/{M}")

# 2. every bit-flip class on the valid demo blob (N1: 2/512 ct flips decoded to wrong text)
def flip(b, k): return bytes(x ^ (1 << (k % 8)) if i == k // 8 else x for i, x in enumerate(b))
for name, lo, hi in (("version[0:3]", 0, 3), ("nonce[3:19]", 3, 19), ("ciphertext[19:83]", 19, 83), ("tag[83:115]", 83, 115)):
    bits = range(8 * lo, 8 * hi); a = sum(accepted(flip(demo, k)) for k in bits)
    kinds = {err(flip(demo, k)) for k in bits}
    log(f"[bit flips] {name}: {a}/{8*(hi-lo)} accepted; error types seen: {sorted(kinds)}")

# 3. multi-bit random corruption of each region
for name, lo, hi in (("nonce", 3, 19), ("ct", 19, 83), ("tag", 83, 115)):
    a = 0
    for _ in range(3000):
        b = bytearray(demo); k = R.randrange(lo, hi); b[k] ^= R.randrange(1, 256); a += accepted(bytes(b))
    log(f"[byte corruption] random single-byte change in {name}: {a}/3000 accepted")

# 4. splicing across two valid blobs (different nonces)
b1 = N.encrypt(b"attack at dawn", SEED); b2 = N.encrypt(b"retreat at dusk", SEED)
splices = {
    "b1 nonce + b2 ct + b1 tag": b1[:19] + b2[19:83] + b1[83:],
    "b2 nonce + b1 ct + b1 tag": b2[:19] + b1[19:83] + b1[83:],
    "b1 nonce+ct + b2 tag":      b1[:83] + b2[83:],
    "b1 version+nonce + b2 ct+tag": b1[:19] + b2[19:],
}
for name, blob in splices.items(): log(f"[splice] {name}: {err(blob)}")

# 5. truncation / extension
log(f"[truncate] lengths 0..114 accepted: {sum(accepted(demo[:L]) for L in range(115))}/115")
log(f"[extend]   demo + k random bytes (k=1..32) accepted: {sum(accepted(demo + rb(k)) for k in range(1,33))}/32")

# 6. chosen-message forgery without the seed: try to forge a tag for a chosen (nonce, ct)
#    HMAC-SHA256 with a 256-bit secret key => expected work ~2^256; we sample to confirm no shortcut.
target_nonce = rb(16); target_ct = N.grid_to_bytes(N.encrypt_grid(N.bytes_to_grid(N.encode_block(b"send $1000 to mallory")), N.Schedule(SEED, target_nonce)))
# attacker does NOT know SEED/mac_key; brute force the 32-byte tag over a budget
budget = 20000; forged = False
for _ in range(budget):
    if accepted(b"SN2" + target_nonce + target_ct + rb(32)): forged = True; break
log(f"[forgery] chosen (nonce, ct) for 'send $1000 to mallory', {budget} random tags, no seed: forged={forged}  (HMAC-SHA256: expected ~2^256)")

# 7. decode oracle after a VALID mac: does the length/padding check leak, like N1's decode-success oracle?
#    An attacker without the seed can never reach the decoder (tag fails first). With the seed, show the
#    error for a tag-valid-but-malformed block is DecodeError (distinct from AuthError) — only reachable WITH the key.
sch = N.Schedule(SEED, DEMO_NONCE)
bad_block = bytes([200]) + bytes(63)          # length byte 200 > 63: malformed but we will MAC it correctly
bad_ct = N.grid_to_bytes(N.encrypt_grid(N.bytes_to_grid(bad_block), sch))
bad_blob = b"SN2" + DEMO_NONCE + bad_ct + N._tag(sch.mac_key, DEMO_NONCE, bad_ct)
log(f"[decode oracle] tag-valid but malformed block (len=200) -> {err(bad_blob)} (DecodeError, reachable ONLY with the seed/mac_key)")
log(f"[decode oracle] for an attacker without the seed, every tamper above returns AuthError BEFORE decryption, so no padding/length oracle is exposed")
# confirm: tampering ct always yields AuthError, never DecodeError (tag checked first)
only_auth = all(err(flip(demo, k)) == "AuthError" for k in range(8*19, 8*83))
log(f"[decode oracle] all 512 ct-bit tampers yield AuthError, never DecodeError (tag is checked first): {only_auth}")

# 8. timing: is the tag compare constant-time-ish (compare_digest) vs the decode path?
src = open("/workspace/sneak_n2/sneak_n2.py").read()
log(f"[impl] hmac.compare_digest used for tag: {'hmac.compare_digest(tag' in src}; version compared with compare_digest: {'hmac.compare_digest(v' in src}")

open("/workspace/sneak_n2/attacks/attack_integrity_output.txt", "w").write("\n".join(out) + "\n")
