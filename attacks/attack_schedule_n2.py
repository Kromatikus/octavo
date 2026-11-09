"""N2 attack 2 — key schedule. N1's schedule was GF(2)-linear in the seed, so ONE round's 1024-bit
material + the public nonce recovered the whole seed by Gaussian elimination. Here: show the seed->material
map is NOT affine (so that attack cannot work), probe for implementation shortcuts (domain separation,
seed bytes copied into the stream, nonce-only derivation), and confirm the only remaining path is a
SHA-256 preimage (not attempted)."""
import sys, os, random, hashlib, statistics
sys.path.insert(0, "/workspace/sneak_n2"); import sneak_n2 as N
SEED = N.load_seed(); R = random.Random(13); out = []
def log(*a): s = " ".join(map(str, a)); print(s); out.append(s)
rb = lambda n: bytes(R.randrange(256) for _ in range(n))
hd = lambda a, b: sum(bin(x ^ y).count("1") for x, y in zip(a, b))
DEMO_NONCE = bytes.fromhex(open("/workspace/sneak_n2/demo-nonce.txt").read().strip())
mat = lambda seed, nonce: N.Schedule(seed, nonce).material()   # 1088 bytes of round keys + whitening

log("=== N2 key schedule ===")

# 1. GF(2)-affineness test: if material were affine in the seed (as in N1), then for any seeds a,b,c
#    M(a)^M(b)^M(c)^M(a^b^c) == 0. Sample this; N1 satisfies it exactly, a one-way schedule should not.
viol = []
for _ in range(40):
    a, b, c = rb(128), rb(128), rb(128)
    d = bytes(x ^ y ^ z for x, y, z in zip(a, b, c))
    comb = bytes(w ^ x ^ y ^ z for w, x, y, z in zip(mat(a, DEMO_NONCE), mat(b, DEMO_NONCE), mat(c, DEMO_NONCE), mat(d, DEMO_NONCE)))
    viol.append(sum(bin(v).count("1") for v in comb))
log(f"[linearity] affine test M(a)^M(b)^M(c)^M(a^b^c): mean nonzero bits {statistics.mean(viol):.0f}/{8*1088} (N1: exactly 0 = perfectly linear; N2 should be ~half)")
# linearity in the nonce too
viol2 = []
for _ in range(40):
    a, b, c = rb(16), rb(16), rb(16); d = bytes(x ^ y ^ z for x, y, z in zip(a, b, c))
    comb = bytes(w ^ x ^ y ^ z for w, x, y, z in zip(mat(SEED, a), mat(SEED, b), mat(SEED, c), mat(SEED, d)))
    viol2.append(sum(bin(v).count("1") for v in comb))
log(f"[linearity] affine test in the nonce: mean nonzero bits {statistics.mean(viol2):.0f}/{8*1088}")

# 2. try the N1 attack directly: treat seed->material as a 1024-bit-in linear map and solve.
#    Build the candidate linear system from basis vectors and check it reproduces a fresh seed's material.
base0 = mat(bytes(128), DEMO_NONCE)                      # M(0)
cols = [bytes(x ^ y for x, y in zip(mat(bytes([0]*k + [1 << (7 - (0))] if False else [0]*128), DEMO_NONCE), base0)) for k in range(0)]  # placeholder
# predict M(seed) under an affine hypothesis: M(seed) ?= M(0) ^ sum_{seed bit set} (M(e_i)^M(0))
def affine_predict(seed_bytes):
    acc = bytearray(base0)
    bits = int.from_bytes(seed_bytes, "big")
    for i in range(1024):
        if (bits >> i) & 1:
            ei = (1 << i).to_bytes(128, "big")
            delta = bytes(x ^ y for x, y in zip(mat(ei, DEMO_NONCE), base0))
            for j in range(len(acc)): acc[j] ^= delta[j]
    return bytes(acc)
test_seed = rb(128)
pred = affine_predict(test_seed); real = mat(test_seed, DEMO_NONCE)
log(f"[N1-style inversion] affine model vs true material for a random seed: {hd(pred, real)}/{8*1088} bits wrong "
    f"({'affine model FAILS -> no linear seed recovery' if hd(pred, real) > 100 else 'AFFINE (seed recoverable!)'})")

# 3. given full round keys + public nonce, is the seed recoverable? The only inversion is SHA-256 preimage.
log("[seed recovery] round keys are SHA-256(\"SN2/K\"||ctr||seed||nonce) blocks. Recovering the seed from them "
    "requires inverting SHA-256 on a 128-byte secret suffix: no known shortcut. NOT attempted (not a Python-scriptable break).")

# 4. implementation shortcuts / mistakes
sch = N.Schedule(SEED, DEMO_NONCE)
streamK = N.StaffSponge(b"K", SEED, DEMO_NONCE).take(2048)
streamM = N.StaffSponge(b"M", SEED, DEMO_NONCE).take(2048)
log(f"[impl] domain separation: K-stream and M-stream share 0 of 2048 bytes in order: {sum(a==b for a,b in zip(streamK,streamM))} equal positions (expect ~8 by chance)")
log(f"[impl] mac_key == SHA256('SN2/M'||ctr0||seed||nonce)[:32]: {sch.mac_key == hashlib.sha256(b'SN2/M'+(0).to_bytes(4,'big')+SEED+DEMO_NONCE).digest()}")
log(f"[impl] mac_key present verbatim in schedule material (seed copied into stream?): {sch.mac_key in sch.material()}")
# seed bytes leaking into the stream?
seed_hits = sum(1 for i in range(len(streamK)-8) if streamK[i:i+8] in SEED)
log(f"[impl] any 8-byte run of the seed appears verbatim in 2048 bytes of K-stream: {seed_hits} (expect 0)")
# nonce-only? zero out the seed and see if material still depends on the seed
log(f"[impl] seed actually used (material(seed) != material(0)): {mat(SEED, DEMO_NONCE) != mat(bytes(128), DEMO_NONCE)}")
log(f"[impl] nonce actually used (material(nonce) != material(other nonce)): {mat(SEED, DEMO_NONCE) != mat(SEED, rb(16))}")
# counter actually advances (no repeated SHA blocks)
blocks = [streamK[i:i+32] for i in range(0, 2048, 32)]
log(f"[impl] SHA-256 counter advances (all {len(blocks)} squeezed blocks distinct): {len(set(blocks))==len(blocks)}")
# int vs bytes seed consistency (loader cannot absorb hex from comments: it reads the file as-is)
log(f"[impl] int seed (N1 style) and bytes seed give identical material: {mat(int.from_bytes(SEED,'big'), DEMO_NONCE)==mat(SEED, DEMO_NONCE)}")

# 5. avalanche: 1-bit nonce / seed flip => ~half of schedule bits (unpredictable, unlike N1's known XOR diff)
nb = [hd(mat(SEED, DEMO_NONCE), mat(SEED, bytes(x ^ (1 << (k % 8)) if i == k//8 else x for i, x in enumerate(DEMO_NONCE)))) / (8*1088) for k in range(128)]
sb = [hd(mat(SEED, DEMO_NONCE), mat((int.from_bytes(SEED,'big') ^ (1 << k)).to_bytes(128,'big'), DEMO_NONCE)) / (8*1088) for k in range(0, 1024, 17)]
log(f"[avalanche] 1-bit nonce flip: schedule-bit change fraction mean {statistics.mean(nb):.4f} (min {min(nb):.3f}, max {max(nb):.3f})")
log(f"[avalanche] 1-bit seed flip:  schedule-bit change fraction mean {statistics.mean(sb):.4f} (min {min(sb):.3f}, max {max(sb):.3f})")
log("[avalanche] related nonces: unlike N1, the material difference is NOT predictable without the seed (it is a SHA-256 output).")

open("/workspace/sneak_n2/attacks/attack_schedule_output.txt", "w").write("\n".join(out) + "\n")
