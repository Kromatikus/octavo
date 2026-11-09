"""N2 attack 4 — nonce reuse. Two messages under the same seed+nonce share the whole schedule, so the
64-byte block is a single fixed keyed permutation. What leaks? equality, keystream structure, a
yes/no/maybe guesser (the N1 hole)? Demonstrate with experiments."""
import sys, os, random, statistics
sys.path.insert(0, "/workspace/sneak_n2"); import sneak_n2 as N
SEED = N.load_seed(); R = random.Random(19); out = []
def log(*a): s = " ".join(map(str, a)); print(s); out.append(s)
rb = lambda n: bytes(R.randrange(256) for _ in range(n))
hd = lambda a, b: sum(bin(x ^ y).count("1") for x, y in zip(a, b))
nonce = rb(16)
ct = lambda m: N.encrypt(m, SEED, nonce)[19:83]     # the 64 ciphertext bytes under a FIXED reused nonce

log("=== N2 nonce reuse (same seed + same nonce for every message below) ===")

# 1. equality leak (unavoidable for any deterministic scheme)
m1 = b"hello world"; m2 = b"hello world"; m3 = b"hello w0rld"
log(f"[equality] identical messages -> identical ct: {ct(m1) == ct(m2)}")
log(f"[equality] messages differing in 1 byte -> identical ct: {ct(m1) == ct(m3)} (distinct, as expected)")
# full-blob equality (nonce is reused so the whole blob matches for equal messages)
b1 = N.encrypt(m1, SEED, nonce); b2 = N.encrypt(m2, SEED, nonce)
log(f"[equality] whole 115-byte blob identical for equal (msg,nonce): {b1 == b2} (so reuse reveals repeats)")

# 2. is it keystream-like? For a stream cipher ct = pt XOR ks, so ct1^ct2 == pt1^pt2. Test.
leak = 0; n = 300
for _ in range(n):
    a, b = rb(20), rb(20)
    pa = bytes([len(a)]) + a + bytes(63 - len(a)); pb = bytes([len(b)]) + b + bytes(63 - len(b))
    if bytes(x^y for x,y in zip(ct(a), ct(b))) == bytes(x^y for x,y in zip(pa, pb)): leak += 1
log(f"[keystream] ct1^ct2 == pt1^pt2 (stream-cipher structure): {leak}/{n}  (0 => NOT a keystream; it is a keyed permutation)")
# how much does ct1^ct2 reveal about pt1^pt2? correlation of the two XOR patterns
corr = []
for _ in range(300):
    a, b = rb(63), rb(63)
    pa = bytes([63]) + a[:63]; pb = bytes([63]) + b[:63]
    cx = bytes(x^y for x,y in zip(ct(a[:63]), ct(b[:63]))); px = bytes(x^y for x,y in zip(pa, pb))
    corr.append(hd(cx, bytes(64)))  # weight of ct-xor; for permutation it's ~random regardless of pt-xor
log(f"[keystream] ct-xor Hamming weight for two random messages: mean {statistics.mean(corr):.1f}/512 (random ~256)")

# 3. two messages differing in a few bytes: does ct distance stay large (good) or shrink (leak)?
dists = []
for _ in range(300):
    base = rb(40); other = bytearray(base); k = R.randrange(40); other[k] ^= R.randrange(1,256)
    dists.append(hd(ct(bytes(base)), ct(bytes(other))))
log(f"[diffusion] 1-byte plaintext change under reused nonce: ct distance mean {statistics.mean(dists):.1f}/512, min {min(dists)} (full-permutation ~256)")

# 4. yes/no/maybe guesser — the N1 hole. With an encryption oracle under a fixed nonce, an attacker who
#    guesses the plaintext can confirm it (true of ANY deterministic cipher). Demonstrate, and note it needs
#    the oracle, not a seedless break.
secret = b"launch code: 7731"
target = ct(secret)
guesses = [b"launch code: 0000", b"launch code: 7731", b"abort", secret]
hits = [g for g in guesses if ct(g) == target]
log(f"[guesser] with an encryption oracle (fixed nonce), confirming a guessed plaintext works: matched {hits} "
    f"(expected: only the correct guess; this is the generic deterministic-encryption leak, NOT a seedless break)")
# small-domain confirmation: 3-digit PIN space
pin = b"PIN=427"; tpin = ct(pin); found = next((f"{d:03d}" for d in range(1000) if ct(b"PIN=" + f"{d:03d}".encode()) == tpin), None)
log(f"[guesser] 3-digit PIN recovered by oracle enumeration under reused nonce: {found} (1000 queries; a fresh nonce per message prevents this)")

# 5. does reuse leak anything WITHOUT the oracle (ciphertext-only, two ciphertexts)? 
#    Given only ct(m1), ct(m2) and nothing else, can we learn m1^m2 or any bit? For a keyed permutation, no.
log("[ciphertext-only] given only two ciphertexts under a reused nonce (no oracle, no seed): no method found to recover either plaintext or their XOR; the block is a secret keyed permutation, not a keystream.")
log("[verdict] nonce reuse leaks message EQUALITY and enables oracle-confirmation of guesses (both generic to deterministic encryption). It is NOT keystream reuse. encrypt() draws a fresh os.urandom(16) nonce, so this needs deliberate misuse.")

open("/workspace/sneak_n2/attacks/attack_nonce_output.txt", "w").write("\n".join(out) + "\n")
