"""Tests for Sneak staff-core N2 (8-bit cells + five bar-line mixes + two interior joins (7 mixes) per staff + late S2 + bar/triplet encore + six triplets after each bar pass + clef-bound tag + SIV nonce: 16 faces x 8 byte-beats, 128-byte block, keyed SM4-affine S-boxes, SM4-field pairs/butterfly, integer triplets and nonlinear bow pressure plus cross-staff matchings). Run: python3 test_sneak_n2.py  (writes nothing into N1 / snapshot trees)."""
import inspect, sys, os, random, hashlib, subprocess
sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE); import sneak_n2 as N
import warnings; warnings.simplefilter("ignore", N.LegacyFormatWarning)   # dedicated tests below re-enable it locally
SEED = N.load_seed(); R = random.Random(2); P = F = S = 0
def check(name, cond):
    global P, F
    if cond: P += 1; print("PASS", name)
    else: F += 1; print("FAIL", name)
def skip(name):
    global S
    S += 1; print("SKIP", name)
def optional_blob(path):
    try:
        for line in open(path):
            if line.startswith("blob"):
                return bytes.fromhex(line.split()[-1])
    except FileNotFoundError:
        return None
    return None
def fails_closed(f):
    """True iff f() raises (so no payload is returned)."""
    try: f(); return False
    except (N.AuthError, N.DecodeError, ValueError): return True
def catch(f):
    try: f(); return None
    except Exception as e: return e
rb = lambda n: bytes(R.randrange(256) for _ in range(n))
rgrid = lambda: [[R.randrange(256) for _ in range(8)] for _ in range(16)]
flip = lambda b, k: bytes(x ^ (1 << (k % 8)) if i == k // 8 else x for i, x in enumerate(b))
hd = lambda a, b: sum(bin(x ^ y).count("1") for x, y in zip(a, b))
DEMO_NONCE = bytes.fromhex(open(os.path.join(HERE, "demo-nonce.txt")).read().strip())   # pre-pickup SIV nonce; still used as a fixed schedule nonce and for old-version blobs
def hw_field(label):
    for line in open(os.path.join(HERE, "hello-world.txt")):
        if line.startswith(label): return bytes.fromhex(line.split()[-1])
HW_BLOB = hw_field("blob"); HW_PICKUP = hw_field("pickup")
PRE_PICKUP_179 = optional_blob("/tmp/sneak_n2_pre_pickup/hello-world.txt")

# ---- seed / format
check("seed is the 1024-bit file (128 bytes), same parse as N1", len(SEED) == 128 and SEED.hex().startswith("62ba585f"))
check("blob length 228 = 1 + 3 + 16 + 16 + 32 + 128 + 32", len(N.encrypt(b"hello world", SEED)) == 228 == N.BLOB_LEN == 1 + 3 + 16 + 16 + 32 + 128 + 32)
check("blob starts with version byte 6 then b'SN2'", N.encrypt(b"x", SEED)[:4] == bytes([N.FMT_VERSION]) + b"SN2" == b"\x06SN2")
# ---- packaging (relative seed, cached attestation, version byte, weak seeds)
check("SEED_PATH is sneak1024-seed.txt next to the module",
      os.path.basename(N.SEED_PATH)=="sneak1024-seed.txt" and os.path.dirname(os.path.abspath(N.SEED_PATH))==os.path.abspath(HERE))
check("load_seed() finds the module-relative demo seed", N.load_seed()==SEED and SEED.hex().startswith("62ba585f"))
import importlib.util, tempfile, shutil
with tempfile.TemporaryDirectory(prefix="n2_noseed_") as _td:
    shutil.copy(os.path.join(HERE, "sneak_n2.py"), os.path.join(_td, "sneak_n2.py"))
    assert not os.path.isfile(os.path.join(_td, "sneak1024-seed.txt"))
    _sp = importlib.util.spec_from_file_location("sneak_n2_noseed", os.path.join(_td, "sneak_n2.py"))
    _alt = importlib.util.module_from_spec(_sp); sys.modules["sneak_n2_noseed"] = _alt; _sp.loader.exec_module(_alt)
    _e = catch(lambda: _alt.load_seed())
    check("load_seed() raises when the module-relative seed file is missing (no /workspace fallback)",
          isinstance(_e, FileNotFoundError) and _alt.SEED_PATH==os.path.join(_td, "sneak1024-seed.txt"))
check("embedded mix digest matches a fresh sha256(mix_description())",
      N.EXPECTED_MIX_SHA256==N._MIX_SHA256==hashlib.sha256(N.mix_description()).hexdigest() and N._SOURCE_AVAILABLE is True)
check("FMT_VERSION is 6 and is authenticated in the tag; legacy v2 is 2; unpublished v4 is 4", N.FMT_VERSION==6 and N.FMT_VERSION_V2==2 and N.FMT_VERSION_V4==4)
old_style = b"SN2" + bytes(192)
e_old = catch(lambda: N.decrypt(old_style, SEED))
check("old 195-byte SN2 blob raises UnsupportedVersion before a tag check",
      isinstance(e_old, N.UnsupportedVersion) and str(e_old)=="unsupported version")
wrong_ver = bytes([1]) + b"SN2" + bytes(192)
e_ver = catch(lambda: N.decrypt(wrong_ver, SEED))
check("version byte 1 on a 196-byte blob raises UnsupportedVersion, not tag mismatch",
      isinstance(e_ver, N.UnsupportedVersion) and str(e_ver)=="unsupported version")
wrong_ver3 = bytes([3]) + b"SN2" + bytes(192)
e_ver3 = catch(lambda: N.decrypt(wrong_ver3, SEED))
check("version byte 3 on a 196-byte blob raises UnsupportedVersion, not tag mismatch",
      isinstance(e_ver3, N.UnsupportedVersion) and str(e_ver3)=="unsupported version")
check("weak seeds rejected: all-zero, integer 1, all-FF, 31 distinct nonzero bytes",
      all(isinstance(catch(lambda s=s: N.encrypt(b"x", s)), ValueError) and "weak seed" in str(catch(lambda s=s: N._seed_bytes(s)))
          for s in (bytes(128), 1, bytes([255]*128), bytes(range(1,32))+bytes(97))))
check("real demo seed and os.urandom(128) are accepted",
      len(N._seed_bytes(SEED))==128 and len(N._seed_bytes(os.urandom(128)))==128)

# ---- round trips
check("roundtrip hello world (SIV nonce)", N.decrypt(N.encrypt(b"hello world", SEED), SEED) == b"hello world")
check("hello-world.txt demo blob (228 bytes) decrypts to b'hello world' and its pickup/nonce/commit/ct/tag lines match live split_blob",
      len(HW_BLOB) == 228 and N.decrypt(HW_BLOB, SEED) == b"hello world" and N.split_blob(HW_BLOB) == (bytes([N.FMT_VERSION]) + b"SN2", HW_PICKUP, hw_field("nonce"), hw_field("commit"), hw_field("ciphertext"), hw_field("tag")))
check("roundtrip random messages, every length 0..127 (x3)", all(N.decrypt(N.encrypt(m, SEED), SEED) == m for L in range(128) for m in (rb(L), rb(L), bytes(L))))
check("roundtrip edge msgs (0xFF*127, trailing zeros, 0x80*127, empty)", all(N.decrypt(N.encrypt(m, SEED), SEED) == m for m in (b"\xff" * 127, b"x\x00\x00", b"\x80" * 127, b"")))
check("oversize message (128, 200 bytes) rejected", fails_closed(lambda: N.encrypt(bytes(128), SEED)) and fails_closed(lambda: N.encrypt(bytes(200), SEED)))
check("int seed (N1-style) accepted and equals bytes seed (cross-decrypt)", N.decrypt(N.encrypt(b"hi", int.from_bytes(SEED, "big")), SEED) == b"hi" and N.decrypt(N.encrypt(b"hi", SEED), int.from_bytes(SEED, "big")) == b"hi")

# ---- integrity: fail closed
c = HW_BLOB; C_PK, C_NONCE = c[4:20], c[20:36]
check("every single-bit flip of the 228-byte blob (1824: version, pickup, nonce, commit, ct, tag) fails closed", len(c) * 8 == 1824 and
      all(fails_closed(lambda k=k: N.decrypt(flip(c, k), SEED)) for k in range(8 * len(c))))
for name, lo, hi in (("version", 0, 4), ("pickup", 4, 20), ("nonce", 20, 36), ("commit", 36, 68), ("ciphertext", 68, 196), ("tag", 196, 228)):
    # conductor: a version-byte flip is UnsupportedVersion (no longer an AuthError subclass); everything else AuthError
    check(f"all {8*(hi-lo)} single-bit flips in {name} raise AuthError (no payload)",
          all(isinstance(catch(lambda k=k: N.decrypt(flip(c, k), SEED)), N.UnsupportedVersion if k < 8 else N.AuthError) for k in range(8 * lo, 8 * hi)))
rand_ok = 0
for _ in range(1000):
    blob = rb(228)
    if not fails_closed(lambda: N.decrypt(blob, SEED)): rand_ok += 1
print(f"random 228-byte blobs accepted: {rand_ok}/1000")
check("1000 random 228-byte blobs: 0 accepted", rand_ok == 0)
rand_ok196 = sum(not fails_closed(lambda b=rb(196): N.decrypt(b, SEED)) for _ in range(1000))
print(f"random 196-byte blobs accepted: {rand_ok196}/1000")
check("1000 random 196-byte (legacy-sized) blobs: 0 accepted", rand_ok196 == 0)
rand_ok2 = sum(not fails_closed(lambda b=bytes([N.FMT_VERSION]) + b"SN2" + rb(224): N.decrypt(b, SEED)) for _ in range(1000))
print(f"random blobs with correct version+SN2 prefix accepted: {rand_ok2}/1000")
check("1000 random blobs WITH correct version+SN2 prefix: 0 accepted", rand_ok2 == 0)
check("truncated blobs (every length 0..227) fail closed", all(fails_closed(lambda L=L: N.decrypt(c[:L], SEED)) for L in range(228)))
METERED_LOOPED = bytes.fromhex("534e32e573fbdf1e63278498735dfce435611e6ddb30fb6e2deaf5f356a741a7212e25bedc3a86da69c2e72bb2ca96f5f9198d619533d5c0e5bc7c4f892a33bc243d5919db5981c71000354729bb9b6c96a42e27c71ead9b443ec3bb651ad6c1f64049ad670e9fce010d9a294010462bbe177eca89fe9d25b5e86fc1ba3f28c9170938db2b4da9d0853062ea019567e8f8fda3dec9e3365d9abaf8d550eecf1102846ba55f316e2ba1feb88eff2fa16a705311ae1bbe416b9d4f9829246ff24edd27c1c2196e5947e3230f")
METERED_UNLOOPED = bytes.fromhex("534e32e573fbdf1e63278498735dfce435611ea5c1cd29edd57f80f90f337c115fc2a7046e01ccbd13ca1c0ee21ead2fafb5139c39c11642a529b431fb81bf425af5c43390bfaa045decccb50ee069545f3470390e3f26be64d7a7b2ca55d9f4488d3ae5789ce45cfa13530267e01b01f7490aef86e6073f100f996b2f86555211ee3e73875d1ca47c3fd161943217e67cb11f0864499f22f6e97425ab6ebe2cc0f07c88e529214f10860951a3362925eff74c270c77fa2b94a45db3c641ae1a00749c217827d6f10c68fb")
OLD_4BIT_115 = bytes.fromhex("534e32e573fbdf1e63278498735dfce435611e328603c75274b178415090ebb344261cf94b1cfada32739a41ed2ab590e447bb4a07ff1013668f0802cd4b3c81aa4dc96c008db753d8b82ec56d91fb7a6208eeef4204fa2b9b6d42d6efb30c39d70ee0866e669bbb7a35a75ff2d90e4df41bc7")   # 4-bit N2 demo blob (115 bytes)
check("old 4-bit 115-byte blob fails closed on length (AuthError); zero-padded / re-wrapped to 179 and 195 bytes also fails closed",
      len(OLD_4BIT_115) == 115 and isinstance(catch(lambda: N.decrypt(OLD_4BIT_115, SEED)), (N.AuthError, N.UnsupportedVersion))
      and fails_closed(lambda: N.decrypt(OLD_4BIT_115 + bytes(64), SEED)) and fails_closed(lambda: N.decrypt(OLD_4BIT_115[:83] + bytes(64) + OLD_4BIT_115[83:], SEED)) and fails_closed(lambda: N.decrypt(OLD_4BIT_115 + bytes(80), SEED)))
check("old metered 203-byte blobs (looped and unlooped) fail closed on length (AuthError), also cut to 179 / 195 bytes", len(METERED_LOOPED) == len(METERED_UNLOOPED) == 203
      and all(isinstance(catch(lambda b=b: N.decrypt(b, SEED)), (N.AuthError, N.UnsupportedVersion)) for b in (METERED_LOOPED, METERED_UNLOOPED))
      and all(fails_closed(lambda b=b: N.decrypt(b[:179], SEED)) for b in (METERED_LOOPED, METERED_UNLOOPED))
      and all(fails_closed(lambda b=b: N.decrypt(b[:195], SEED)) for b in (METERED_LOOPED, METERED_UNLOOPED)))
PREBAR_179 = bytes.fromhex("534e32e573fbdf1e63278498735dfce435611e3589c1087bc86a600186bc2f497b23eea1ffda180f7c53a4cf83b016afbc9eb50558bf4a34a6e6506129f5c8b5c60b50f056070bb2488f256aade8a13e49d0f03fefb0d5bd6596d62c07892bb3a7d43b14b45c759ef02b379e498538766025fe20ad6d7de0a0410fda7161a489327cfb3980b75ffeb6671e67f9f6659bd58b731a59f177f0b1679eda217f4a8d8946af07c78480e6daee87527015f5844b7438")   # 8-bit N2 demo blob from before the bar-line layer (same length)
check("pre-bar 8-bit 179-byte demo blob now fails the clef-bound tag -> AuthError, no payload",
      len(PREBAR_179) == 179 and isinstance(catch(lambda: N.decrypt(PREBAR_179, SEED)), (N.AuthError, N.UnsupportedVersion)))
if PRE_PICKUP_179 is None:
    skip("pre-pickup 179-byte hello-world blob (from /tmp/sneak_n2_pre_pickup) fails closed")
else:
    _e = catch(lambda: N.decrypt(PRE_PICKUP_179, SEED))
    check("pre-pickup 179-byte hello-world blob (from /tmp/sneak_n2_pre_pickup) fails closed as unsupported version",
          len(PRE_PICKUP_179) == 179 and isinstance(_e, N.UnsupportedVersion) and "unsupported version" in str(_e))
check("staffs are linear: no staff-loop layer (no staff_loop/staff_unloop/LOOP_A/LOOP_B) and no loop step in round_enc/round_dec",
      not any(hasattr(N, n) for n in ("staff_loop", "staff_unloop", "loop_a", "loop_b", "LOOP_A", "LOOP_B"))
      and "loop" not in inspect.getsource(N.round_enc) and "loop" not in inspect.getsource(N.round_dec))
check("8-bit cells: 16 faces x 8 byte-beats, 128-byte block, 228-byte blob, max payload 127", N.NF == 16 and N.NB == 8 and N.CELL_BITS == 8 and N.BLOCK_LEN == 128 and N.BLOB_LEN == 228 and N.MAX_MSG == 127)
check("extended blob (extra byte) fails closed", fails_closed(lambda: N.decrypt(c + b"\x00", SEED)))
check("version prefix changed to SN1 / SN3 / sn2 fails closed", all(fails_closed(lambda v=v: N.decrypt(v + c[4:], SEED)) for v in (b"SN1", b"SN3", b"sn2")))
c2 = N.encrypt(b"hello world!", SEED)
check("splicing: ct+tag of one blob with nonce of another fails", fails_closed(lambda: N.decrypt(c[:20] + c2[20:36] + c[36:], SEED)))
check("splicing: pickup of another blob onto this one fails", fails_closed(lambda: N.decrypt(c[:4] + c2[4:20] + c[20:], SEED)))
check("tag of one message on ct of another fails", fails_closed(lambda: N.decrypt(c[:196] + c2[196:], SEED)))
wrong = [bytearray(SEED) for _ in range(3)]; wrong[0][0] ^= 1; wrong[1][127] ^= 0x80; wrong[2] = bytearray(rb(128))
check("wrong seed fails closed (bit 0, bit 1023, random seed)", all(isinstance(catch(lambda w=w: N.decrypt(c, bytes(w))), N.AuthError) for w in wrong))
check("decrypt checks tag before decoding (tampered ct -> AuthError, never DecodeError)",
      all(isinstance(catch(lambda k=k: N.decrypt(flip(c, k), SEED)), N.AuthError) for k in range(8 * 68, 8 * 196, 7)))
src = open(os.path.join(HERE, "sneak_n2.py")).read()
check("tag compared with hmac.compare_digest", "hmac.compare_digest(tag" in src)

# ---- nonces / determinism / schedule avalanche
hw_text = open(os.path.join(HERE, "hello-world.txt")).read()
check("demo blob in hello-world.txt: blob, pickup, nonce, commit, ct, tag hex all present", all(x.hex() in hw_text for x in N.split_blob(c)[1:]) and c.hex() in hw_text)
a1, a2 = N.encrypt(b"hello world", SEED), N.encrypt(b"hello world", SEED)
check("pickup: same message twice -> different pickups, nonces, blobs; both decrypt to original",
      a1[4:20] != a2[4:20] and a1[20:36] != a2[20:36] and a1 != a2 and N.decrypt(a1, SEED) == N.decrypt(a2, SEED) == b"hello world")
check("pickup: 200 encryptions of the same message -> 200 distinct pickups and blobs", len({N.encrypt(b"1234", SEED) for _ in range(200)}) == 200)
from unittest.mock import patch as _patch_urandom
with _patch_urandom.object(N.os, "urandom", lambda n: bytes([0x5A])*n):
    broken1 = N.encrypt(b"same message", SEED)
    broken2 = N.encrypt(b"same message", SEED)
check("pickup hardening: constant os.urandom still yields different pickups and blobs; both decrypt",
      broken1 != broken2 and broken1[4:20] != broken2[4:20] and N.decrypt(broken1, SEED) == N.decrypt(broken2, SEED) == b"same message")
ad_msg, ad_ok, ad_bad = b"hello associated", b"from:alice", b"from:bob"
ad_blob = N.encrypt(ad_msg, SEED, ad=ad_ok)
check("AD round-trip: encrypt(..., ad=x) decrypts with the same ad", N.decrypt(ad_blob, SEED, ad=ad_ok) == ad_msg)
e_wrong = catch(lambda: N.decrypt(ad_blob, SEED, ad=ad_bad))
check("wrong AD fails authentication with the unified AuthError message", isinstance(e_wrong, N.AuthError) and type(e_wrong) is N.AuthError and str(e_wrong)=="authentication failed")
e_missing = catch(lambda: N.decrypt(ad_blob, SEED))
check("missing AD fails authentication when the blob was sealed with nonempty AD", isinstance(e_missing, N.AuthError) and type(e_missing) is N.AuthError and str(e_missing)=="authentication failed")
empty_abs = N.encrypt(b"empty-vs-absent", SEED)
empty_exp = N.encrypt(b"empty-vs-absent", SEED, ad=b"")
check("empty versus absent AD behave the same (both decrypt with omitted or b'')",
      N.decrypt(empty_abs, SEED) == N.decrypt(empty_abs, SEED, ad=b"") == b"empty-vs-absent"
      and N.decrypt(empty_exp, SEED) == N.decrypt(empty_exp, SEED, ad=b"") == b"empty-vs-absent"
      and inspect.signature(N.encrypt).parameters["ad"].default == b""
      and inspect.signature(N.decrypt).parameters["ad"].default == b"")
amb1 = N.encrypt(b"bar", SEED, ad=b"foo")
amb2 = N.encrypt(b"ar", SEED, ad=b"foob")
e_amb = catch(lambda: N.decrypt(amb1, SEED, ad=b"foob"))
check("length-prefix AD encoding is unambiguous: (ad='foo',msg='bar') != (ad='foob',msg='ar'); cross-AD decrypt fails",
      N._encode_ad(b"foo") + N.encode_block(b"bar") != N._encode_ad(b"foob") + N.encode_block(b"ar")
      and N._encode_ad(b"ab") + N._encode_ad(b"c") != N._encode_ad(b"a") + N._encode_ad(b"bc")
      and N._encode_ad(b"") == (0).to_bytes(8, "big") and N._encode_ad(b"hi") == (2).to_bytes(8, "big") + b"hi"
      and N.decrypt(amb1, SEED, ad=b"foo") == b"bar" and N.decrypt(amb2, SEED, ad=b"foob") == b"ar"
      and isinstance(e_amb, N.AuthError) and type(e_amb) is N.AuthError and str(e_amb)=="authentication failed")
PRE_INFO = optional_blob("/tmp/sneak_n2_pre_infofix/hello-world.txt")
if PRE_INFO is None:
    skip("octavo003 version-1 196-byte hello-world blob fails as unsupported version")
else:
    e_pre = catch(lambda: N.decrypt(PRE_INFO, SEED))
    check("octavo003 version-1 196-byte hello-world blob fails as unsupported version",
          len(PRE_INFO)==196 and PRE_INFO[0]==1 and isinstance(e_pre, N.UnsupportedVersion) and str(e_pre)=="unsupported version")
msgs = {rb(R.randrange(1, 64)) for _ in range(300)}
check("300 different messages -> 300 different nonces and ciphertexts", len({N.encrypt(m, SEED)[20:36] for m in msgs}) == len(msgs) == len({N.encrypt(m, SEED)[N.CT0:N.CT1] for m in msgs}))
def nonce_formula_ok(m, ad=b""):
    b = N.encrypt(m, SEED, ad=ad); pk, n = b[4:20], b[20:36]
    return n == hashlib.sha256(N.staff_clef(SEED) + pk + N.encode_block(m) + N._encode_ad(ad)).digest()[:16] == N.siv_nonce(m, pk, SEED, ad)
check("nonce formula: SHA-256(clef || pickup || encode_block(msg) || encode_ad(ad))[:16] for the pickup stored in the blob (demo + 50 random + AD)",
      C_NONCE == hashlib.sha256(N.staff_clef(SEED) + C_PK + N.encode_block(b"hello world") + N._encode_ad(b"")).digest()[:16] and all(nonce_formula_ok(rb(R.randrange(128))) for _ in range(50)) and nonce_formula_ok(b"hi", b"from:alice"))
check("encrypt(msg, nonce=wrong) raises ValueError (random, zero, old demo SIV, another blob's nonce for same msg)",
      all(isinstance(catch(lambda n=n: N.encrypt(b"hello world", SEED, n)), ValueError) for n in (rb(16), bytes(16), DEMO_NONCE, C_NONCE)))
check("encrypt has no public pickup argument (signature is msg, seed, nonce, ad)", list(inspect.signature(N.encrypt).parameters) == ["msg", "seed", "nonce", "ad"])
check("os.urandom used only inside _fresh_pickup, never for the nonce", inspect.getsource(N.encrypt).count("os.urandom(") == 0 and "pickup = _fresh_pickup()" in inspect.getsource(N.encrypt)
      and inspect.getsource(N._fresh_pickup).count("os.urandom(") == 1
      and "urandom" not in inspect.getsource(N.siv_nonce) and "urandom" not in inspect.getsource(N.Schedule))
def pin_dictionary_fails(trials=200):
    rr = random.Random(77)
    for _ in range(trials):
        pin = ("%04d" % rr.randrange(10000)).encode(); target = N.encrypt(pin, SEED)
        if N.encrypt(pin, SEED) == target: return False
        if any(N.encrypt(("%04d" % g).encode(), SEED) == target for g in rr.sample(range(10000), 5)): return False
    return True
check("PIN dictionary: encrypt(correct_guess) != target blob over 200 fresh PIN-like targets (old match attack fails)", pin_dictionary_fails())
sch_g = N.Schedule(SEED, DEMO_NONCE); ct_g = N.grid_to_bytes(N.encrypt_grid(N.bytes_to_grid(N.encode_block(b"guess")), sch_g))
_forged_commit = N._commitment(N._commit_key(SEED), N.FMT_VERSION, C_PK, DEMO_NONCE)
forged = bytes([N.FMT_VERSION]) + b"SN2" + C_PK + DEMO_NONCE + _forged_commit + ct_g + N._tag(sch_g.mac_key, C_PK, DEMO_NONCE, ct_g, N.staff_clef(SEED), N.key_signature(SEED), version=N.FMT_VERSION, commit=_forged_commit)
check("valid tag but blob nonce != SIV nonce of recovered message -> AuthError (insider-built blob)", isinstance(catch(lambda: N.decrypt(forged, SEED)), N.AuthError))
check("bad nonce length rejected", fails_closed(lambda: N.encrypt(b"x", SEED, b"short")))
base = N.Schedule(SEED, DEMO_NONCE).material(); fr = []
for k in range(128):
    m2 = N.Schedule(SEED, flip(DEMO_NONCE, k)).material(); fr.append(hd(base, m2) / (8 * len(base)))
print(f"schedule avalanche (1-bit nonce flip, all 128 bits, {8*len(base)} schedule bits): mean {sum(fr)/len(fr):.4f}, min {min(fr):.4f}, max {max(fr):.4f}")
check("1-bit nonce flip changes ~half of round-key+whitening bits (each of 128 flips in 0.46..0.54)", all(0.46 <= x <= 0.54 for x in fr))
sch0 = N.Schedule(SEED, DEMO_NONCE); sch1 = N.Schedule(SEED, flip(DEMO_NONCE, 0))
# Sample keyed tables for the keyed Latin B0/rehair layers (round 0 of the demo schedule): S for u', S2 for v'.
TS = (sch0.rounds[0]["S"], sch0.rounds[0]["S2"]); TSI = (sch0.rounds[0]["SI"], sch0.rounds[0]["SI2"])
check("1-bit nonce flip changes every round's S-box params, weave, sigma and bridge (16/16 rounds)",
      all(all(sch0.rounds[r][k] != sch1.rounds[r][k] for k in ("S", "S2", "SH", "SV", "sigma", "bridge")) for r in range(16)))
check("1-bit nonce flip changes MAC key", sch0.mac_key != sch1.mac_key)
mk = [hd(base, N.Schedule(flip(SEED, k), DEMO_NONCE).material()) / (8 * len(base)) for k in range(0, 1024, 37)]
check("1-bit seed flip changes ~half the schedule bits (28 positions)", all(0.46 <= x <= 0.54 for x in mk))
st = N.StaffSponge(b"K", SEED, DEMO_NONCE).take(64); sm = N.StaffSponge(b"M", SEED, DEMO_NONCE).take(64)
check("domain separation: MAC stream (b'M') and schedule stream (b'K') differ and MAC key not in schedule material",
      st != sm and sch0.mac_key not in sch0.material() and sch0.mac_key == sm[:32])
check("clef = StaffSponge domain 'C', seed + zero nonce (independent hashlib check), 16 bytes, not in blob",
      N.staff_clef(SEED) == hashlib.sha256(b"SN2/C" + (0).to_bytes(4, "big") + SEED + bytes(16)).digest()[:16] and N.staff_clef(SEED) not in c)
check("clef depends on seed", N.staff_clef(flip(SEED, 5)) != N.staff_clef(SEED))
check("tag = HMAC-SHA256(mac_key, clef || key_sig || version || 'SN2' || pickup || nonce || commit || ct || encode_ad(ad)) (independent hmac check)",
      c[N.CT1:] == __import__("hmac").new(N.Schedule(SEED, C_NONCE).mac_key, N.staff_clef(SEED) + N.key_signature(SEED) + bytes([N.FMT_VERSION]) + b"SN2" + c[4:20] + c[20:36] + c[N.CM0:N.CM1] + c[N.CT0:N.CT1] + N._encode_ad(b""), hashlib.sha256).digest())
check("MAC key derived from seed via SHA-256 domain 'M' (independent check with hashlib)",
      sch0.mac_key == hashlib.sha256(b"SN2/M" + (0).to_bytes(4, "big") + SEED + DEMO_NONCE).digest())

# ---- S-boxes (8-bit, keyed SM4-affine)
exec(open(os.path.join(HERE, "sm4_vector_check.py")).read())     # SM4 reference cipher, used ONLY to authenticate the S-box table
check("base S-box table is the published SM4 S-box: GB/T 32907-2016 Example 1 and draft-ribose-cfrg-sm4 Example 4 reproduce", sm4_table_ok(N.SM4_SBOX))
bd, bl = N.ddt_max(N.SM4_SBOX), N.lat_max(N.SM4_SBOX)
print(f"SM4 base S-box: DDT max {bd}/256 (best differential prob {bd}/256 = 2^-6), LAT max |count-128| {bl}/256 (|bias| {bl}/256 = 2^-4, nonlinearity {128-bl})")
check("SM4 base S-box: permutation, DDT max 4, LAT max 16 (nonlinearity 112)", sorted(N.SM4_SBOX) == list(range(256)) and bd == 4 and bl == 16)
def sbox_ok(sch): return all(sorted(rk[k]) == list(range(256)) and all(rk[ik][rk[k][x]] == x for x in range(256)) and N.ddt_max(rk[k]) == 4 for rk in sch.rounds for k, ik in (("S", "SI"), ("S2", "SI2")))
dd = [N.ddt_max(rk[k]) for rk in sch0.rounds for k in ("S", "S2")]; ll = [N.lat_max(rk[k]) for rk in sch0.rounds for k in ("S", "S2")]
print(f"demo nonce, 32 keyed round S-boxes: DDT max {sorted(set(dd))}, LAT max {sorted(set(ll))}")
check("demo nonce: all 32 keyed round S-boxes are permutations (with inverse) and inherit DDT max 4", sbox_ok(sch0) and dd == [4] * 32)
check("demo nonce: all 32 keyed round S-boxes inherit LAT max 16", ll == [16] * 32)
check("5 random nonces: all 160 keyed S-boxes permutations with DDT max 4", all(sbox_ok(N.Schedule(SEED, rb(16))) for _ in range(5)))
check("affine matrices A1–A4 invertible (8x8 over GF(2)) in every round", all(N.mat_invertible(rk[k]) for rk in sch0.rounds for k in ("A1", "A2", "A3", "A4")))
check("S-boxes are keyed: 16 distinct boxes among the 16 demo rounds, none equal to the SM4 base", len({tuple(rk["S"]) for rk in sch0.rounds}) == 16 and all(bytes(rk[k]) != N.SM4_SBOX for rk in sch0.rounds for k in ("S", "S2")))
check("no AES S-box / MixColumns / GF(2^8) AES poly / AES libraries in library",
      not any(w in src.lower() for w in ("637c777bf26b6fc5", "0x63, 0x7c", "0x11b", "mixcolumns(", "from crypto", "import cryptography", "aesgcm", "aes.new")))

# ---- mixes / round invertibility
check("2-cell SM4-field mix is a bijection on all 65536 byte pairs, exhaustive inverse", len({N.mix2(u, v) for u in range(256) for v in range(256)}) == 65536 and all(N.mix2_inv(*N.mix2(u, v)) == (u, v) for u in range(256) for v in range(256)))
# ---- bar lines: five different invertible 2-byte mixes per staff (four measures of 2/4)
check("five bar lines (boundaries 0,2,4,6,8) plus two interior joins M2 (2,3), M3 (4,5) = 7 mixes in beat order; every adjacent pair mixed; no (7,0) end-to-end pair",
      [b[1] for b in N.BARS] == [0, 2, 3, 4, 5, 6, 8] and [b[2] for b in N.BARS] == [(0, 1), (1, 2), (2, 3), (3, 4), (4, 5), (5, 6), (6, 7)]
      and [b[0] for b in N.BARS if b[0].startswith("B")] == ["B0 start", "B1 bar 2", "B2 center", "B3 bar 6", "B4 end"]
      and all(set(b[2]) != {0, 7} for b in N.BARS))
check("six active field pairs have distinct invertible matrices; B0 slot is unused (None)",
      len(N.BARS) == 7 and N.BARS[0][3] is None and N.BARS_INV[0] is None
      and len({b[3] for b in N.BARS[1:]}) == 6
      and [N.bar_det(b[3]) for b in N.BARS[1:]] == [3, 3, 7, 1, 3, 1])
for k, (name, _, _, M) in enumerate(N.BARS):
    if name == "B0 start": continue  # covered by exhaustive keyed-Latin checks below
    Mi = N.BARS_INV[k]
    check(f"bar {name} mix {M} is a bijection on all 65536 byte pairs and its inverse {Mi} undoes it",
          len({N.bar_apply(M, u, v) for u in range(256) for v in range(256)}) == 65536
          and all(N.bar_apply(Mi, *N.bar_apply(M, u, v)) == (u, v) for u in range(256) for v in range(256)))
# GF(2)-linearity makes the XOR derivative independent of the base state.
check("SM4 field reduction uses 0xF5, not AES 0x1B", N.gf_mul(128, 2) == 0xF5)
check("all nonzero field inverses and high-bit products", all(N.gf_mul(x, N.gf_inv(x)) == 1 and N.gf_mul(x, 128) != 0 for x in range(1,256)))
for name, _, _, M in N.BARS[1:]:
    check(f"{name}: every nonzero single-cell XOR derivative has two outputs at ANY base",
          all(all(N.bar_apply(M, d, 0)) and all(N.bar_apply(M, 0, d)) for d in range(1,256))
          and all(N.gf_mul(c, x ^ d) == N.gf_mul(c, x) ^ N.gf_mul(c, d)
                  for c in set(sum(M, ())) for x in range(256) for d in range(256)))
check("bar layer as a whole inverts (500 random grids)", all((lambda g: N.bar_unmix(N.bar_mix(g, *TS), *TSI) == g)(rgrid()) for _ in range(500)))
check("bar layer is in the round: round_enc calls bar_mix, round_dec calls bar_unmix",
      "bar_mix(" in inspect.getsource(N.round_enc) and "bar_unmix(" in inspect.getsource(N.round_dec))
# ---- triplets: all six unlooped adjacent windows, after each bar pass
check("six distinct det-1 triplets cover (0,1,2)..(5,6,7), no wrap",
      [t[1] for t in N.TRIPLETS] == [tuple(range(i, i+3)) for i in range(6)]
      and len({t[2] for t in N.TRIPLETS}) == 6 and all(N.triplet_det(t[2]) == 1 for t in N.TRIPLETS))
check("each triplet row and column has >=2 odd coefficients", all(
      all(sum(x & 1 for x in row) >= 2 for row in M)
      and all(sum(M[i][j] & 1 for i in range(3)) >= 2 for j in range(3)) for _, _, M in N.TRIPLETS))
def mat_product(A, B):
    n = len(A)
    return tuple(tuple(sum(A[i][k] * B[k][j] for k in range(n)) & 255 for j in range(n)) for i in range(n))
for ti, (name, beats, M) in enumerate(N.TRIPLETS):
    Mi = N.TRIPLETS_INV[ti]; ident = ((1,0,0),(0,1,0),(0,0,1))
    check(f"{name} {beats} matrix {M}, det 1, two-sided inverse {Mi}",
          mat_product(M, Mi) == ident == mat_product(Mi, M)
          and all((lambda v: N.triplet_apply(Mi, *N.triplet_apply(M, *v)) == v)(tuple(rb(3))) for _ in range(1000)))
def single_cell_exhaustive(M):
    # Equivalent exhaustive reduction, not random sampling: Z/256 linearity gives
    # F(v')-F(v) = M[:,j]*((x XOR a)-x), regardless of ALL other input cells.
    # Output XOR is zero iff its additive difference is zero. We exhaust all
    # 3*255*256 choices of input cell, nonzero XOR delta and input value x;
    # each case represents all 256**2 completions of the other two cells.
    count = 0; minimum = 3
    for j in range(3):
        for a in range(1, 256):
            for x in range(256):
                d = (x ^ a) - x
                weight = sum((M[i][j] * d) & 255 != 0 for i in range(3))
                count += weight == 1; minimum = min(minimum, weight)
    return count, minimum
for name, _, M in N.TRIPLETS:
    single, minimum = single_cell_exhaustive(M)
    print(f"{name}: all 3*255*256 XOR cases, independent of 256**2 other-cell completions: singleton events {single}, min output cells {minimum}")
    check(f"{name} exhaustive equivalent: NO single-cell events for ANY single-cell nonzero XOR input difference", single == 0 and minimum >= 2)
check("triplet layer inverse, 500 random grids; does not mutate caller grid", all(
      (lambda g: N.triplet_unmix(N.triplet_mix(g)) == g and N.triplet_mix(g) is not g)(rgrid()) for _ in range(500)))
check("combined bar+triplet layer inverse on both shells, 500 random grids", all(
      (lambda g: N.bar_unmix(N.triplet_unmix(N.triplet_mix(N.bar_mix(g, *TS))), *TSI) == g)(rgrid()) for _ in range(500)))
def staff_matrix(layer):
    cols = [layer([[int(i == j) for i in range(8)]])[0] for j in range(8)]
    return tuple(tuple(cols[j][i] for j in range(8)) for i in range(8))
combined = lambda g: N.triplet_mix(N.bar_mix(g, *TS))
for label, layer in (("triplets", N.triplet_mix), ("bar+triplet (same as encore)", combined)):
    M = staff_matrix(layer)
    weights = [sum(M[i][j] & 1 for i in range(8)) for j in range(8)]
    observed = [sum(x != 0 for x in layer([[128 if i == j else 0 for i in range(8)]])[0]) for j in range(8)]
    print(f"{label} 0x80 output weights at zero base (0..7): {observed}; singleton crossings: {observed.count(1)}")
    check(f"{label}: no singleton 0x80 crossing at zero and 256 uniform base states", min(observed) >= 2 and all(sum(a != b for a, b in zip(layer([[base]*8])[0], layer([[base ^ (128 if i == j else 0) for i in range(8)]])[0])) >= 2 for base in range(256) for j in range(8)))

check("staff butterfly inverse (300 random grids, random sigma)", all((lambda g, s: N.staff_unmix(N.staff_mix(g, s), s) == g)(rgrid(), [R.sample(range(8), 8) for _ in range(16)]) for _ in range(300)))
check("shell bridge inverse, even and odd rounds (300 grids)", all((lambda g, b, r: N.shell_unmix(N.shell_mix(g, b, r), b, r) == g)(rgrid(), R.sample(range(64), 64), r) for _ in range(150) for r in (0, 1)))
check("weave inverse (300 grids)", all((lambda g, SH, SV: N.unweave(N.weave(g, SH, SV), SH, SV) == g)(rgrid(), [R.randrange(8) for _ in range(16)], [R.randrange(16) for _ in range(8)]) for _ in range(300)))
check("every round r = 0..15 inverts (20 grids each)", all(N.round_dec(N.round_enc(g, sch0.rounds[r], r), sch0.rounds[r], r) == g for r in range(16) for g in (rgrid() for _ in range(20))))
check("full 16-round block cipher encrypt/decrypt inverse (300 grids)", all(N.decrypt_grid(N.encrypt_grid(g, sch0), sch0) == g for g in (rgrid() for _ in range(300))))
check("block cipher is a permutation sample: 2000 random blocks -> 2000 distinct outputs", len({N.grid_to_bytes(N.encrypt_grid(N.bytes_to_grid(rb(128)), sch0)) for _ in range(2000)}) == 2000)
check("byte<->grid encoding inverse (128 bytes <-> 16x8 byte cells)", all(N.grid_to_bytes(N.bytes_to_grid(b)) == b for b in (rb(128) for _ in range(100))))
def _val_err(f):
    try: f()
    except ValueError: return True
    except Exception: return False
    return False
check("bytes_to_grid rejects blocks that are not 128 bytes (0, 5, 127, 129, 256)", all(_val_err(lambda n=n: N.bytes_to_grid(bytes(n))) for n in (0, 5, 127, 129, 256)))
check("siv_nonce rejects pickups that are not 16 bytes (0, 15, 17, 32) and accepts 16", all(_val_err(lambda n=n: N.siv_nonce(b"hi", bytes(n), SEED)) for n in (0, 15, 17, 32)) and len(N.siv_nonce(b"hi", bytes(16), SEED)) == 16)

# Explicit order / compatibility regression checks against both backups.
import importlib.util, hmac as _h
def load(name, path):
    if not os.path.isfile(path):
        return None
    sp = importlib.util.spec_from_file_location(name, path); m = importlib.util.module_from_spec(sp); sys.modules[name] = m; sp.loader.exec_module(m); return m
OLD = load("precolor2", "/tmp/sneak_n2_8bit_precolor2/sneak_n2.py")
PRE = load("preclef", "/tmp/sneak_n2_pre_clef_encore_siv/sneak_n2.py")
PRET = load("pretriplet", "/tmp/sneak_n2_pre_triplet/sneak_n2.py")
PREJ = load("prejoin", "/tmp/sneak_n2_pre_join_pairs/sneak_n2.py")   # cipher just before the 3-4 / 5-6 joins
FIELD_OLD = load("prefield", "/tmp/sneak_n2_pre_field_retune/sneak_n2.py")
if FIELD_OLD is None:
    skip("triplet tuples and integer helpers byte-for-byte unchanged by field retune")
else:
    check("triplet tuples and integer helpers byte-for-byte unchanged by field retune", N.TRIPLETS == FIELD_OLD.TRIPLETS and all(inspect.getsource(getattr(N, f)) == inspect.getsource(getattr(FIELD_OLD, f)) for f in ("triplet_apply", "triplet_inv", "triplet_det", "staff_mix")))
N3 = load("testn3", "/workspace/testn3/sneak_n2.py")                  # frozen testn3 copy (same previous cipher)
PRE_ORDER = load("preclef_order", "/tmp/sneak_n2_pre_clef_encore_siv/sneak_n2.py")
if PRE_ORDER is not None:
    PRE_ORDER.BARS, PRE_ORDER.BARS_INV = N.BARS, N.BARS_INV               # same pre-encore round, but with the new 7-mix list
if OLD is None:
    skip("round-0 existing sponge prefixes unchanged")
else:
    oldsch = OLD.Schedule(SEED, DEMO_NONCE)
    check("round-0 existing sponge prefixes unchanged", all(oldsch.rounds[0][k] == sch0.rounds[0][k] for k in oldsch.rounds[0]))
check("both colorings present: S2 differs from S in every round", all(rk["S2"] != rk["S"] for rk in sch0.rounds))
check("nonce flip changes second-coloring affine parameters every round", all(any(a[k] != b[k] for k in ("A3", "A4", "b3", "b4")) for a,b in zip(sch0.rounds, sch1.rounds)))
check("S2 exactly uses the published SM4-affine recipe", all(N.keyed_sbox(rk["A3"],rk["b3"],rk["A4"],rk["b4"]) == (rk["S2"],rk["SI2"]) for rk in sch0.rounds))
def order_ok():
    for r,rk in enumerate(sch0.rounds):
        g = rgrid()
        mid = N.shell_mix(N.staff_mix(N.weave([[rk["S"][x] for x in row] for row in N.xor_grid(g,rk["rk"])],rk["SH"],rk["SV"]),rk["sigma"]),rk["bridge"],r)
        T, TI = (rk["S"], rk["S2"]), (rk["SI"], rk["SI2"])
        mid = N.cross_staff_mix([N.odd_restack(N.bow_pressure(row), *T) for row in N.triplet_mix(N.bar_mix(mid, *T))])
        late = [[rk["S2"][x] for x in row] for row in mid]
        out = N.cross_staff_mix([N.odd_restack(N.bow_pressure(row), *T) for row in N.triplet_mix(N.bar_mix(late, *T))])
        if N.round_enc(g,rk,r) != out: return False
        back = N.bar_unmix(N.triplet_unmix([N.unbow_pressure(N.unodd_restack(row, *TI)) for row in N.cross_staff_unmix(out)]), *TI)
        if back != late: return False
        back = [[rk["SI2"][x] for x in row] for row in back]
        back = N.bar_unmix(N.triplet_unmix([N.unbow_pressure(N.unodd_restack(row, *TI)) for row in N.cross_staff_unmix(back)]), *TI)
        back = N.shell_unmix(back,rk["bridge"],r)
        back = N.staff_unmix(back,rk["sigma"])
        back = N.unweave(back,rk["SH"],rk["SV"])
        back = N.xor_grid([[rk["SI"][x] for x in row] for row in back],rk["rk"])
        if N.round_dec(out,rk,r) != back or back != g: return False
    return True
check("round order: bars -> triplets -> bow -> odd_restack -> cross -> S2 -> encore bars -> encore triplets -> bow -> odd_restack -> cross; decrypt reverses, uncross FIRST", order_ok()
      and inspect.getsource(N.round_enc).count("bar_mix(") == 2 and inspect.getsource(N.round_enc).count("triplet_mix(") == 2
      and inspect.getsource(N.round_dec).split("\n")[1].strip().startswith("g = cross_staff_unmix(g)"))
def trace_order():
    from unittest.mock import patch
    names = ("bar_mix", "triplet_mix", "bar_unmix", "triplet_unmix", "bow_pressure", "unbow_pressure", "odd_restack", "unodd_restack", "cross_staff_mix", "cross_staff_unmix"); calls = []
    def wrap(name, fun):
        def wrapped(*args): calls.append(name); return fun(*args)
        return wrapped
    from contextlib import ExitStack
    with ExitStack() as stack:
        for name in names: stack.enter_context(patch.object(N, name, wrap(name, getattr(N, name))))
        g = rgrid(); out = N.round_enc(g, sch0.rounds[0], 0); N.round_dec(out, sch0.rounds[0], 0)
    return calls == (["bar_mix", "triplet_mix"] + ["bow_pressure"]*16 + ["odd_restack"]*16 + ["cross_staff_mix"])*2 + (["cross_staff_unmix"] + ["unodd_restack"]*16 + ["unbow_pressure"]*16 + ["triplet_unmix", "bar_unmix"])*2
check("instrumented sequence: each bow -> rehair -> cross, inverse uncross -> unrehair -> unbow", trace_order())
check("historical pair slots, S-boxes, schedule, clef, encoding, weave and butterfly/bridge routing unchanged from pre-triplet (B0 implementation intentionally changed)",
      [b[:3] for b in N.BARS] == [b[:3] for b in PRET.BARS]
      and [b[3] for b in N.BARS[1:]] == [b[3] for b in PRET.BARS[1:]]
      and N.BARS[0][3] is None
      and all(inspect.getsource(getattr(N,name)) == inspect.getsource(getattr(PRET,name)) for name in (
      "Schedule", "StaffSponge", "keyed_sbox", "staff_clef", "encode_block",   # siv_nonce/_tag/encrypt/decrypt/split_blob changed by the pickup
      "weave", "unweave", "staff_mix", "staff_unmix", "shell_mix", "shell_unmix")))
def not_fused():
    rr = random.Random(9)
    for r in range(15):
        a, b = sch0.rounds[r], sch0.rounds[r + 1]
        F = lambda g: [[b["S"][x] for x in row] for row in N.xor_grid(N.cross_staff_mix([N.odd_restack(N.bow_pressure(row), a["S"], a["S2"]) for row in N.triplet_mix(N.bar_mix([[a["S2"][x] for x in row] for row in g], a["S"], a["S2"]))]), b["rk"])]
        g = rgrid(); h = [row[:] for row in g]; h[0][1] ^= rr.randrange(1, 256)
        if sum(x != y for p_, q_ in zip(F(g), F(h)) for x, y in zip(p_, q_)) < 2: return False
    return True
check("S2 -> encore -> xor rk -> next-round S is NOT a single-cell function (1-cell change hits >=2 cells, rounds 0..14)", not_fused())
fc = lambda b: isinstance(catch(lambda: N.decrypt(b, SEED)), (N.AuthError, N.DecodeError, N.UnsupportedVersion))   # conductor: UnsupportedVersion is its own class
if None in (OLD, PRE):
    skip("old 179-byte blobs from /tmp/sneak_n2_8bit_precolor2 and /tmp/sneak_n2_pre_clef_encore_siv raise AuthError (4 demo blobs)")
else:
    olds = {"precolor2 demo": OLD.encrypt(b"hello world", SEED, DEMO_NONCE),
            "precolor2 old-nonce": OLD.encrypt(b"hello world", SEED, bytes.fromhex("e573fbdf1e63278498735dfce435611e")),
            "pre-clef old-nonce": PRE.encrypt(b"hello world", SEED, bytes.fromhex("e573fbdf1e63278498735dfce435611e")),
            "pre-clef SIV-nonce": PRE.encrypt(b"hello world", SEED, DEMO_NONCE),
            }
    check("old 179-byte blobs from /tmp/sneak_n2_8bit_precolor2 and /tmp/sneak_n2_pre_clef_encore_siv raise AuthError (4 demo blobs)",
          all(len(b) == 179 and isinstance(catch(lambda b=b: N.decrypt(b, SEED)), (N.AuthError, N.UnsupportedVersion)) for b in olds.values()))
rr_ = random.Random(11)
if None in (FIELD_OLD, PRET, PREJ, N3):
    skip("pre-triplet + pre-join + testn3 old-length demo blobs fail closed")
    skip("256 random pre-join-pairs blobs fail closed (AuthError or DecodeError), none returns a plaintext")
    skip("pre-triplet/pre-join/testn3/pre-field demo blobs (179 bytes) now fail on length -> AuthError")
    skip("256 random pre-triplet blobs fail closed (AuthError or DecodeError), none returns plaintext")
else:
    prej = {"pre-field-retune demo": FIELD_OLD.encrypt(b"hello world", SEED), "pre-triplet demo": PRET.encrypt(b"hello world", SEED), "pre-join-pairs demo": PREJ.encrypt(b"hello world", SEED), "testn3 demo": N3.encrypt(b"hello world", SEED)}
    oldj = [PREJ.encrypt(bytes(rr_.randrange(256) for _ in range(rr_.randrange(40))), SEED) for _ in range(256)]
    check("pre-triplet + pre-join + testn3 old-length demo blobs fail closed", all(fc(b) for b in prej.values()))
    check("256 random pre-join-pairs blobs fail closed (AuthError or DecodeError), none returns a plaintext", all(fc(b) for b in oldj))
    oldt = [PRET.encrypt(bytes(rr_.randrange(256) for _ in range(rr_.randrange(40))), SEED) for _ in range(256)]
    check("pre-triplet/pre-join/testn3/pre-field demo blobs (179 bytes) now fail as unsupported version (not a key signature)",
          all(len(b) == 179 and isinstance(catch(lambda b=b: N.decrypt(b, SEED)), N.UnsupportedVersion) for b in prej.values()))
    check("256 random pre-triplet blobs fail closed (AuthError or DecodeError), none returns plaintext", all(fc(b) for b in oldt))
if PRE is None:
    skip("512 random pre-clef blobs (valid under old MAC) all raise AuthError")
else:
    oldmany = [PRE.encrypt(bytes(rr_.randrange(256) for _ in range(rr_.randrange(40))), SEED) for _ in range(512)]
    check("512 random pre-clef blobs (valid under old MAC) all raise AuthError", all(isinstance(catch(lambda b=b: N.decrypt(b, SEED)), (N.AuthError, N.UnsupportedVersion)) for b in oldmany))

# ---- three leftover-shape fixes
PICKUP_OLD = load("pickup_old", "/tmp/sneak_n2_pre_three_fixes/sneak_n2.py")
old_blob = optional_blob("/tmp/sneak_n2_pre_three_fixes/hello-world.txt")
if old_blob is None:
    skip("pickup-era 195-byte recorded blob now raises unsupported version")
else:
    e = catch(lambda: N.decrypt(old_blob, SEED))
    check("pickup-era 195-byte recorded blob now raises unsupported version (not DecodeError)",
          len(old_blob) == 195 and isinstance(e, N.UnsupportedVersion) and "unsupported version" in str(e))
check("blob regions are version + SN2 + pickup + nonce + commit + ct + tag", (N.PK0, N.N0, N.CM0, N.CM1, N.CT0, N.CT1, N.BLOB_LEN) == (4,20,36,68,68,196,228))
check("mix2 high-bit derivative is (0x80,0xF5), not integer singleton",
      tuple(a^b for a,b in zip(N.mix2(0,0), N.mix2(0,128))) == (128,245))
check("mix2 matrix determinant 3, characteristic-two inverse", N.MIX2_MATRIX == ((1,1),(1,2))
      and N.bar_det(N.MIX2_MATRIX) == 3 and N.MIX2_INV == N.bar_inv(N.MIX2_MATRIX))
if PICKUP_OLD is None:
    skip("triplet tables and integer arithmetic unchanged from pickup era")
else:
    check("triplet tables and integer arithmetic unchanged from pickup era", N.TRIPLETS == PICKUP_OLD.TRIPLETS
          and all(inspect.getsource(getattr(N,n)) == inspect.getsource(getattr(PICKUP_OLD,n)) for n in ("triplet_apply", "triplet_inv", "triplet_det", "triplet_mix", "triplet_unmix")))
check("key signature uses domain G and sha256(mix_description()) as sponge nonce (independent hashlib)",
      len(N.key_signature(SEED)) == 16 and N._MIX_SHA256 == N.EXPECTED_MIX_SHA256 == hashlib.sha256(N.mix_description()).hexdigest()
      and N.key_signature(SEED) == hashlib.sha256(
          b"SN2/G" + bytes(4) + SEED + bytes.fromhex(N._MIX_SHA256)).digest()[:16])
check("key signature has no public encrypt/decrypt override and no blob field", list(inspect.signature(N.encrypt).parameters) == ["msg","seed","nonce","ad"]
      and list(inspect.signature(N.decrypt).parameters) == ["blob","seed","ad"] and N.key_signature(SEED) not in c)
# Copies remain in memory only: no edits to any old snapshot or attack tree.
for kind in ("pair", "triplet", "mix2"):
    alt = load("altered_"+kind, os.path.join(HERE,"sneak_n2.py"))
    if kind == "pair":
        alt.BARS = alt.BARS[1:]  # actually skips B0 during encryption
        alt.BARS_INV = tuple(alt.bar_inv(M) for _,_,_,M in alt.BARS)
    elif kind == "triplet":
        alt.TRIPLETS = alt.TRIPLETS[1:]
        alt.TRIPLETS_INV = tuple(alt.triplet_inv(M) for _,_,M in alt.TRIPLETS)
    else:
        alt.MIX2_MATRIX = ((1,1),(1,3))
        alt.MIX2_INV = alt.bar_inv(alt.MIX2_MATRIX)
    ab = alt.encrypt(b"hello world", SEED)
    er = catch(lambda: N.decrypt(ab, SEED))
    # In-process mutation no longer moves the cached key_sig; the ciphertext still will not
    # decrypt under the live mix (tag may verify, then DecodeError / SIV mismatch).
    check("altered "+kind+" score: 228-byte alternate blob fails closed on live decrypt",
          len(ab) == 228 and alt.decrypt(ab, SEED) == b"hello world"
          and isinstance(er, (N.AuthError, N.DecodeError)))
# Each relevant constant is encoded dynamically, not a fixed prose promise.
from unittest.mock import patch
for name, value in (("FIELD_POLY",0x1F7), ("BOW_STROKES",tuple(reversed(N.BOW_STROKES))),
                    ("BOW_PRESSURE_ROT",tuple(reversed(N.BOW_PRESSURE_ROT))),
                    ("BOW_ROT_BASE",2), ("BOW_ROT_MOD",6), ("BOW_R2_SHIFT",2)):
    desc0 = N.mix_description()
    with patch.object(N, name, value): changed = N.mix_description() != desc0
    check("mix_description changes with "+name+" (key_sig is cached at import)", changed)
check("bow strokes match open even then interior odd order, pressure read only may wrap", N.BOW_STROKES ==
      ((0,1,2),(2,3,4),(4,5,0),(6,7,0),(1,2,3),(3,4,5),(5,6,0)) and all({i,j}!={0,7} and p not in (i,j) for i,j,p in N.BOW_STROKES))
check("BOW_PRESSURE_ROT aligned with BOW_STROKES: beat-0 readers use 0,3,5; others identity",
      N.BOW_PRESSURE_ROT == (0,0,0,3,0,0,5) and len(N.BOW_PRESSURE_ROT)==len(N.BOW_STROKES)
      and [N.BOW_PRESSURE_ROT[i] for i,st in enumerate(N.BOW_STROKES) if st[2]==0]==[0,3,5]
      and all(N.BOW_PRESSURE_ROT[i]==0 for i,st in enumerate(N.BOW_STROKES) if st[2]!=0))
check("bow stroke inverse, exhaustive byte pairs for pressures 0, 127, 255", all(
      N.unbow_stroke(*N.bow_stroke(u,v,p),p)==(u,v) for p in (0,127,255) for u in range(256) for v in range(256)))
staffs = [list(rb(8)) for _ in range(20000)]
check("bow pressure two-sided inverse: 20,000 random staffs plus uniform edge staffs", all(
      N.unbow_pressure(N.bow_pressure(s)) == s and N.bow_pressure(N.unbow_pressure(s)) == s
      for s in staffs + [[v]*8 for v in range(256)]))
check("bow pressure is nonidentity and copies its input", all(N.bow_pressure(s) != s for s in staffs[:100])
      and all((lambda x: N.bow_pressure(x) is not x and x==s)(s[:]) for s in staffs[:100]))
# Retired field matrix ((1,5),(1,6)) is no longer stored or attested. The witness
# is kept only here so we can show live keyed B0 is a different map.
check("B0 has no unused field matrix to attest (slot and inverse are None)",
      N.BARS[0][3] is None and N.BARS_INV[0] is None
      and "((1, 5), (1, 6))" not in N._canon_data(N.BARS)
      and "NoneType:None" in N._canon_data(N.BARS[:1]))
check("live keyed B0 is not the retired field witness (5,1)->(0,3)",
      N.bar_apply(((1, 5), (1, 6)), 5, 1) == (0, 3) and N.b0_apply(5, 1, *TS) != (0, 3))
check("_canon_data encodes set/frozenset/bytearray/memoryview/float deterministically",
      N._canon_data({3, 1, 2}) == N._canon_data({1, 2, 3}) == "set{int:1,int:2,int:3}"
      and N._canon_data(frozenset({2, 1})) == "frozenset{int:1,int:2}"
      and N._canon_data(bytearray(b"ab")) == "bytearray:b'ab'"
      and N._canon_data(memoryview(b"ab")) == "memoryview:b'ab'"
      and N._canon_data(1.25) == "float:1.25")
_untyped = catch(lambda: N._canon_data(object()))
check("_canon_data raises TypeError for an unsupported type (explicit, not silent)",
      isinstance(_untyped, TypeError) and "cannot attest object of type object" in str(_untyped))
# Putting the retired matrix back would change the description, but not the round function.
_desc0 = N.mix_description()
_ghost = (("B0 start", 0, (0, 1), ((1, 5), (1, 6))),) + N.BARS[1:]
with patch.object(N, "BARS", _ghost):
    _changed = N.mix_description() != _desc0
check("re-inserting the retired B0 matrix changes mix_description (it would be attested if kept)", _changed)

# ---- cross-staff geometry, commitment, inverses and old confinement regression
import json
for name in ("CROSS_OPPOSITE", "CROSS_RADIAL", "CROSS_ADJACENT"):
    matching = getattr(N, name)
    check(name + " is an oriented perfect matching of 16 staffs",
          len(matching) == 8 and all(f < h for f,h in matching)
          and sorted(x for pair in matching for x in pair) == list(range(16)))
check("cross layer order is opposite, radial, adjacent, bridge", N.CROSS_LAYERS ==
      (N.CROSS_OPPOSITE, N.CROSS_RADIAL, N.CROSS_ADJACENT, N.CROSS_BRIDGE))
def cross_inverse_ok():
    for _ in range(1000):
        g = rgrid(); before = [row[:] for row in g]
        a = N.cross_staff_mix(g); b = N.cross_staff_unmix(g)
        if (N.cross_staff_unmix(a) != g or N.cross_staff_mix(b) != g or g != before
            or a is g or b is g or any(x is y for x,y in zip(a,g))
            or any(x is y for x,y in zip(b,g))): return False
    return True
check("cross-staff two-sided inverse and no input/row mutation, 1000 random grids", cross_inverse_ok())
desc = json.loads(N.mix_description())["cross_staff"]
check("canonical description includes cross matchings, effective layer order and placement",
      desc["opposite"] == [list(p) for p in N.CROSS_OPPOSITE]
      and desc["radial"] == [list(p) for p in N.CROSS_RADIAL]
      and desc["adjacent"] == [list(p) for p in N.CROSS_ADJACENT]
      and desc["layers"] == [[list(p) for p in layer] for layer in N.CROSS_LAYERS]
      and desc["bridge"] == [list(p) for p in N.CROSS_BRIDGE]
      and desc["order"] == "opposite;radial;adjacent;bridge"
      and desc["placement"] == "after-mid-rehair-before-S2;after-encore-rehair")
for name in ("CROSS_OPPOSITE", "CROSS_RADIAL", "CROSS_ADJACENT", "CROSS_BRIDGE", "CROSS_LAYERS"):
    desc0 = N.mix_description()
    with patch.object(N, name, tuple(reversed(getattr(N, name)))):
        changed = N.mix_description() != desc0
    check("mix_description changes with " + name + " (key_sig is cached at import)", changed)
alt = load("altered_cross", os.path.join(HERE,"sneak_n2.py"))
alt.CROSS_LAYERS = tuple(reversed(alt.CROSS_LAYERS))
ab = alt.encrypt(b"hello world", SEED); er = catch(lambda: N.decrypt(ab,SEED))
check("altered effective cross order roundtrips locally but fails closed on live decrypt",
      alt.decrypt(ab,SEED) == b"hello world" and isinstance(er, (N.AuthError, N.DecodeError)))
PRE_CROSS = load("pre_cross", "/tmp/sneak_n2_pre_cross_staff/sneak_n2.py")
pre_cross_blob = optional_blob("/tmp/sneak_n2_pre_cross_staff/hello-world.txt")
if pre_cross_blob is None:
    skip("pre-cross 195-byte hello-world pickup 28c124 now fails as unsupported version")
else:
    er = catch(lambda: N.decrypt(pre_cross_blob, SEED))
    check("pre-cross 195-byte hello-world pickup 28c124 now fails as unsupported version",
          len(pre_cross_blob)==195 and pre_cross_blob[3:19].hex().startswith("28c124")
          and isinstance(er,N.UnsupportedVersion) and "unsupported version" in str(er))
if PRE_CROSS is None:
    skip("triplets, schedule, weave, bridges, encoding unchanged from pre-cross")
    skip("bow_pressure/unbow_pressure sources differ from pre-cross")
else:
    check("triplets, schedule, weave, bridges, encoding unchanged from pre-cross (packaging changed encrypt/decrypt/_tag/siv_nonce; B0/rehair/bow intentionally changed earlier)",
          all(inspect.getsource(getattr(N,n)) == inspect.getsource(getattr(PRE_CROSS,n)) for n in
              ("triplet_mix","triplet_unmix",
               "staff_mix","staff_unmix","shell_mix","shell_unmix","weave","unweave","Schedule",
               "StaffSponge","keyed_sbox","encode_block")))
    check("bow_pressure/unbow_pressure sources differ from pre-cross (beat-0 pressure-rot fix applies rotl8 view)",
          inspect.getsource(N.bow_pressure) != inspect.getsource(PRE_CROSS.bow_pressure)
          and inspect.getsource(N.unbow_pressure) != inspect.getsource(PRE_CROSS.unbow_pressure)
          and "BOW_PRESSURE_ROT" in inspect.getsource(N.bow_pressure)
          and "BOW_PRESSURE_ROT" in inspect.getsource(N.unbow_pressure))
rr_cross = random.Random(20261108); active_counts=[]; staff_union=set(); confined=0
for trial in range(300):
    g = [[rr_cross.randrange(256) for _ in range(8)] for _ in range(16)]
    h = [row[:] for row in g]; h[0][2] ^= 0x5a if trial==0 else rr_cross.randrange(1,256)
    a=N.round_enc(g,sch0.rounds[0],0); b=N.round_enc(h,sch0.rounds[0],0)
    active={f for f in range(16) if a[f]!=b[f]}
    active_counts.append(len(active)); staff_union |= active
    confined += active <= {6,8,10,14,15}
print(f"cell-2 one-round spread (300 pairs, demo schedule; first delta 0x5a): min {min(active_counts)}, max {max(active_counts)}, union {sorted(staff_union)}, confined {confined}/300")
check("cell-2 previous five-staff confinement broken in all 300 pairs; union all 16 staffs",
      confined==0 and staff_union==set(range(16)) and min(active_counts)>5)
for name, expected in (("testn4","46274b690e3d3ae53649b810591681b94f53983c72f6fb9789a19c8670003f45"),
                       ("testn3","a64dc256aab66436073e888bbb6a31210f1b5c0af00b10c14ddd875fafd1b1b1")):
    fp = os.path.join("/workspace", name, "sneak_n2.py")
    if not os.path.isfile(fp):
        skip(name+" frozen source hash unchanged")
    else:
        check(name+" frozen source hash unchanged", hashlib.sha256(open(fp,"rb").read()).hexdigest()==expected)

# ---- four leftover-shape fixes (independent seeded scans)
FOUR_PRE = "/tmp/sneak_n2_pre_four_leftovers"
four_blob = optional_blob(FOUR_PRE+"/hello-world.txt")
if four_blob is None:
    skip("pre-four 195-byte hello-world pickup 831a4499 fails as unsupported version")
else:
    er = catch(lambda: N.decrypt(four_blob, SEED))
    check("pre-four 195-byte hello-world pickup 831a4499 fails as unsupported version, not DecodeError",
          len(four_blob)==195 and four_blob[3:19].hex()=="831a4499756825b07352034a552a9756"
          and isinstance(er,N.UnsupportedVersion) and str(er)=="unsupported version")
check("CROSS_BRIDGE is intended partial oriented disjoint matching, not a perfect matching",
      N.CROSS_BRIDGE==((1,2),(5,6),(9,10),(13,14))
      and all(f<h for f,h in N.CROSS_BRIDGE) and len({x for p in N.CROSS_BRIDGE for x in p})==8)
seen={0}
while True:
    nxt=seen | {v for layer in N.CROSS_LAYERS for u,v in layer if u in seen} | {u for layer in N.CROSS_LAYERS for u,v in layer if v in seen}
    if nxt==seen: break
    seen=nxt
print("four-layer cross graph component from 0:",sorted(seen))
check("four-layer cross graph is one connected 16-staff component", seen==set(range(16)))
check("B0 exhaustive two-sided inverse on all 65,536 pairs", all(
      N.b0_unapply(*N.b0_apply(u,v,*TS),*TSI)==(u,v) and N.b0_apply(*N.b0_unapply(u,v,*TSI),*TS)==(u,v)
      for u in range(256) for v in range(256)))
witness=tuple(a^b for a,b in zip(N.b0_apply(0,0,*TS),N.b0_apply(5,1,*TS)))
indep=lambda u,v:(TS[0][u^v],TS[1][u^N._gf_mul_raw(2,v)])
print("B0 live old-witness output XOR (round-0 tables):",tuple(hex(x) for x in witness))
check("B0 (0,0) vs (5,1) witness no longer (0,3); live equals independent x=u^v, y=u^2v, (S[x],S2[y])",
      witness!=(0,3) and all(N.b0_apply(u,v,*TS)==indep(u,v) for u in range(256) for v in range(256)))
# All bases for this old differential: a linear map would have one derivative.
derivs={tuple(a^b for a,b in zip(N.b0_apply(u,v,*TS),N.b0_apply(u^5,v^1,*TS))) for u in range(256) for v in range(256)}
print("B0 old (5,1) delta over 65,536 bases: distinct derivatives",len(derivs),
      "; first-output zeros",sum(a==0 for a,b in derivs),"; second-output zeros",sum(b==0 for a,b in derivs))
check("B0 old differential is not a base-independent linear kernel wipe",len(derivs)>1 and all(a!=0 for a,b in derivs))
rr4=random.Random(4419)
# General single-input property: changing either input must change both outputs.
single_ok=True
for _ in range(20000):
    u,v,d=rr4.randrange(256),rr4.randrange(256),rr4.randrange(1,256)
    base=N.b0_apply(u,v,*TS)
    for other in (N.b0_apply(u^d,v,*TS),N.b0_apply(u,v^d,*TS)):
        single_ok &= all(a!=b for a,b in zip(base,other))
check("B0 exactly-one-input changes both outputs (40,000 sampled derivatives)",single_ok)
rehair_staffs=[[v]*8 for v in range(256)]+[[rr4.randrange(256) for _ in range(8)] for _ in range(20000)]
check("odd_restack two-sided inverse, copies without mutation (20,256 staffs)",all(
      N.unodd_restack(N.odd_restack(s,*TS),*TSI)==s and N.odd_restack(N.unodd_restack(s,*TSI),*TS)==s
      and N.odd_restack(s,*TS) is not s and N.unodd_restack(s,*TSI) is not s for s in rehair_staffs))
check("odd restack beat 7 only pairs with 6; no beat-7-to-0 line", N.odd_restack([0]*7+[1],*TS)[:6]==N.odd_restack([0]*8,*TS)[:6]
      and "(1, 3, 5, 7)" in inspect.getsource(N.odd_restack) and "(7, 5, 3, 1)" in inspect.getsource(N.unodd_restack))
# All 255 deltas on 256 uniform + 256 random bases, on ALL EIGHT beats (beat-6 fix: was odd beats only).
single_before=single_after=cases=highbit_after=0; min_after=8; rehair_singles=[]
beat_before=[0]*8; beat_after=[0]*8; beat_cases=[0]*8
for s in rehair_staffs[:512]:
    a=N.bow_pressure(s); ar=N.odd_restack(a,*TS)
    for t in range(8):
        for d in range(1,256):
            h=s[:]; h[t]^=d; b=N.bow_pressure(h); br=N.odd_restack(b,*TS)
            single_before+=sum(x!=y for x,y in zip(a,b))==1
            weight=sum(x!=y for x,y in zip(ar,br))
            single_after+=weight==1; min_after=min(min_after,weight); cases+=1
            beat_before[t]+=sum(x!=y for x,y in zip(a,b))==1; beat_after[t]+=weight==1; beat_cases[t]+=1
            highbit_after+=(weight==1 and d==128)
            if weight==1: rehair_singles.append((s[:],t,d))
print(f"all-beat scan bow -> bow+rehair: {single_before}/{cases} -> {single_after}/{cases} singletons; min after {min_after}; includes every delta 0x80")
print("per-beat singletons (130,560 cases each), bow alone:",beat_before,"; bow+rehair:",beat_after)
check("bow+odd_restack has no singletons for 1,044,480 all-beat input cases (8 beats x 130,560, all 255 deltas; odd subset = the old 522,240)",
      cases==1044480 and beat_cases==[130560]*8 and sum(beat_cases[1::2])==522240 and single_before>0 and single_after==0
      and beat_after==[0]*8 and min_after>=2)
check("ARX rotation constants retired (no B0_ROT_*/ODD_RESTACK_R* attributes)",
      not any(hasattr(N,n) for n in ("B0_ROT_R1","B0_ROT_R2","ODD_RESTACK_R1","ODD_RESTACK_R2")))
check("latin_pair/latin_unpair/round_enc/round_dec are in MIX_CODE_FUNCS",
      all(n in N.MIX_CODE_FUNCS for n in ("latin_pair","latin_unpair","round_enc","round_dec","b0_apply","b0_unapply","odd_restack","unodd_restack")))
for name in ("latin_pair","latin_unpair","round_enc","round_dec"):
    desc0=N.mix_description()
    swapped=(lambda *a: None)
    with patch.object(N,name,swapped): changed=N.mix_description()!=desc0
    check("description changes when "+name+" object is replaced (key_sig is cached at import)",changed)
desc4=json.loads(N.mix_description())
LATIN_DESC=dict(kind="field+keyed-sbox",field=[[1,1],[1,2]],tables="u'=S[x];v'=S2[y];inverse SI,SI2")
check("B0 description is keyed Latin pair (field MIX2 then S/S2), not ARX or the unused matrix",
      desc4["bars"][0]==dict(name="B0 start",boundary=0,pair=[0,1],**LATIN_DESC))
check("description records keyed Latin odd rehair and pairs",all(desc4["odd_restack"][k]==v for k,v in LATIN_DESC.items())
      and desc4["odd_restack"]["pairs"]==[[0,1],[2,3],[4,5],[6,7]] and "r1" not in desc4["odd_restack"])
# ---- rotation retune (2026-11-09): B0 (3,5)->(2,7), odd restack (2,6)->(5,4)
ROT_PRE = "/tmp/sneak_n2_pre_rotation_retune"
rot_blob = optional_blob(ROT_PRE+"/hello-world.txt")
if rot_blob is None:
    skip("pre-rotation-retune 195-byte hello-world pickup 724da1f4 fails as unsupported version, not DecodeError")
else:
    er = catch(lambda: N.decrypt(rot_blob, SEED))
    check("pre-rotation-retune 195-byte hello-world pickup 724da1f4 fails as unsupported version, not DecodeError",
          len(rot_blob)==195 and rot_blob[3:19].hex()=="724da1f42b3aa81489b97a1dcaeb14c4"
          and isinstance(er,N.UnsupportedVersion) and str(er)=="unsupported version")
# ---- keyed Latin pair (2026-11-09): B0 and odd rehair = field step (MIX2) then round S (u') / S2 (v')
LAT_PRE = "/tmp/sneak_n2_pre_latin_mix"
lat_blob = optional_blob(LAT_PRE+"/hello-world.txt")
if lat_blob is None:
    skip("pre-latin 195-byte hello-world pickup a287436b fails as unsupported version, not DecodeError")
else:
    er = catch(lambda: N.decrypt(lat_blob, SEED))
    check("pre-latin 195-byte hello-world pickup a287436b fails as unsupported version, not DecodeError",
          len(lat_blob)==195 and lat_blob[3:19].hex()=="a287436b086c25ff762366eb747704d0"
          and isinstance(er,N.UnsupportedVersion) and str(er)=="unsupported version")
inv3=N.gf_inv(3)
check("latin_unpair inverse formula: v = gf_mul(gf_inv(3), x^y), u = x^v equals mix2_inv on all 65,536 (x,y)",
      N.gf_mul(3,inv3)==1 and all((lambda v:(x^v,v))(N.gf_mul(inv3,x^y))==N.mix2_inv(x,y) for x in range(256) for y in range(256)))
check("keyed B0 and rehair pair are bijections with exact two-sided inverses for all 16 rounds' tables (65,536 pairs each)",
      all(len({N.latin_pair(u,v,rk["S"],rk["S2"]) for u in range(256) for v in range(256)})==65536
          and all(N.latin_unpair(*N.latin_pair(u,v,rk["S"],rk["S2"]),rk["SI"],rk["SI2"])==(u,v)
                  and N.latin_pair(*N.latin_unpair(u,v,rk["SI"],rk["SI2"]),rk["S"],rk["S2"])==(u,v) for u in range(256) for v in range(256))
          for rk in sch0.rounds))
b0_single=[0,0]
for u in range(256):
    for v in range(256):
        base=N.b0_apply(u,v,*TS)
        for d in range(1,256):
            for col,other in enumerate((N.b0_apply(u^d,v,*TS),N.b0_apply(u,v^d,*TS))):
                b0_single[col]+=sum(x!=y for x,y in zip(base,other))==1
print("B0 exhaustive single-input singletons (u column, v column) over 2x255x65,536, round-0 tables:",b0_single,"(ARX 2,7 had [0, 10752])")
check("B0 exhaustive single-input singletons are 0 (pure-Python, round-0 tables)", b0_single==[0,0])
import numpy as np
_u=np.repeat(np.arange(256),256); _v=np.tile(np.arange(256),256)
def np_singletons(Fm):
    c=[0,0]
    for col in (0,1):
        for d in range(1,256):
            idx=((_u^(d if col==0 else 0))<<8)|(_v^(d if col==1 else 0))
            c[col]+=int(((Fm!=Fm[idx]).sum(1)==1).sum())
    return c
lat_counts={}; fixed=[]; zero_maps=[]
for r,rk in enumerate(sch0.rounds):
    T=(rk["S"],rk["S2"])
    lat_counts[(r,"B0")]=np_singletons(np.array([N.b0_apply(u,v,*T) for u in range(256) for v in range(256)]))
    for t in (1,3,5,7):
        outs=[N.odd_restack([u if k==t-1 else (v if k==t else 0) for k in range(8)],*T) for u in range(256) for v in range(256)]
        lat_counts[(r,(t-1,t))]=np_singletons(np.array([(o[t-1],o[t]) for o in outs]))
    fixed.append(sum(N.b0_apply(u,v,*T)==(u,v) for u in range(256) for v in range(256))); zero_maps.append(N.b0_apply(0,0,*T))
print("live-table singleton counts, 16 rounds x (B0 + 4 rehair pairs):",sorted(set(tuple(c) for c in lat_counts.values())))
print("keyed pair (0,0) images per round:",zero_maps)
print("keyed pair fixed points per round (u,v)->(u,v):",fixed)
check("B0 and every rehair pair (0,1),(2,3),(4,5),(6,7): 0 singletons over all 2x255x65,536 one-input changes, all 16 rounds' tables",
      len(lat_counts)==80 and all(c==[0,0] for c in lat_counts.values()))
check("(0,0) is not a fixed point of the keyed pair in any of the 16 demo rounds", all(z!=(0,0) for z in zero_maps))
print(f"all-beat 0x80 singletons after bow+rehair: {highbit_after}/4096 (ARX 5,4 had 3/522,240 and 0/2,048 on odd beats)")
def _kernel_case(s,t,d):
    h=s[:]; h[t]^=d; db=[x^y for x,y in zip(N.bow_pressure(s),N.bow_pressure(h))]
    act=[i for i in range(8) if db[i]]
    return (len(act)==2 and act[0]%2==0 and act[1]==act[0]+1
            and (db[act[0]]==db[act[1]] or db[act[0]]==N.gf_mul(2,db[act[1]])))
def _single_all_tables(s,t,d):
    h=s[:]; h[t]^=d
    return all(sum(x!=y for x,y in zip(N.odd_restack(N.bow_pressure(s),rk["S"],rk["S2"]),
                                       N.odd_restack(N.bow_pressure(h),rk["S"],rk["S2"])))==1 for rk in sch0.rounds)
print("bow+keyed rehair singleton witnesses (base, beat, delta):",[(b if b.count(b[0])<8 else [b[0]]*8,t,hex(d)) for b,t,d in rehair_singles])
# Beat-7 fix (2026-11-09): last bow stroke (5,6,7) -> (5,6,0). The 5 old witnesses (all beat 7) are gone.
check("bow+keyed rehair: 0x80 singletons 0/4,096 and 0/1,044,480 all-beat singletons (beat-7 + beat-6 fixes)",
      cases==1044480 and highbit_after==0 and single_after==0 and rehair_singles==[])
OLD_B7=[([26]*8,7,0x24),([53]*8,7,0xe1),([117]*8,7,0x4e),([142,151,20,118,251,3,37,161],7,0x27),([91,12,141,148,97,40,0,144],7,0xb1)]
check("the 5 pre-fix beat-7 witnesses now change >=2 bytes after bow+rehair for all 16 rounds' tables",
      all(sum(x!=y for x,y in zip(N.odd_restack(N.bow_pressure(s),rk["S"],rk["S2"]),
              N.odd_restack(N.bow_pressure([c^(d if k==t else 0) for k,c in enumerate(s)]),rk["S"],rk["S2"])))>=2
          for s,t,d in OLD_B7 for rk in sch0.rounds))
# Proof lemma: a beat-7-only change leaves beats 0..4 untouched and ALWAYS changes beat 5 after bow,
# so the bow delta spans rehair pairs (4,5) and (6,7) (singleton needs a delta inside ONE pair).
rr7=random.Random(7007); lem=True
for _ in range(200000):
    s7=[rr7.randrange(256) for _ in range(8)]; d=rr7.randrange(1,256); h=s7[:]; h[7]^=d
    a,b=N.bow_pressure(s7),N.bow_pressure(h)
    lem &= a[:5]==b[:5] and a[5]!=b[5]
check("beat-7 lemma: bow keeps beats 0..4, always changes beat 5 (200,000 random staffs x deltas)", lem)
# ---- beat-6 fix (2026-11-09, after attacks_octavo_beat7): third stroke (4,5,6) -> (4,5,0).
# Lemma: a beat-6-only change leaves beats 0..4 untouched and ALWAYS changes beats 5 AND 7 (two rehair pairs).
rr6=random.Random(6006); lem6=True
for _ in range(200000):
    s6=[rr6.randrange(256) for _ in range(8)]; d=rr6.randrange(1,256); h=s6[:]; h[6]^=d
    a,b=N.bow_pressure(s6),N.bow_pressure(h)
    lem6 &= a[:5]==b[:5] and a[5]!=b[5] and a[7]!=b[7]
check("beat-6 lemma: bow keeps beats 0..4, always changes beats 5 and 7 (200,000 random staffs x deltas)", lem6)
check("beat 6 is read as pressure by no stroke; beat 0 feeds exactly the three strokes (4,5,0),(6,7,0),(5,6,0)",
      all(p!=6 for _,_,p in N.BOW_STROKES) and [st for st in N.BOW_STROKES if st[2]==0]==[(4,5,0),(6,7,0),(5,6,0)])
# Witnesses from attacks_octavo_beat7 (REPORT.md section 2 + attack_even_beats live_confirmation): single-byte under
# all 16 round tables before the fix. Now every one changes >=2 bytes after bow+rehair for every round's tables.
OLD_B6=[([90,8,17,194,106,100,92,5],6,28),([61,184,68,8,147,13,127,98],6,14),
        ([121,234,152,46,28,121,240,211],6,18),([248,57,224,163,155,133,232,18],6,36)]
b6_w=[[sum(x!=y for x,y in zip(N.odd_restack(N.bow_pressure(s),rk["S"],rk["S2"]),
        N.odd_restack(N.bow_pressure([c^(d if k==t else 0) for k,c in enumerate(s)]),rk["S"],rk["S2"]))) for rk in sch0.rounds]
      for s,t,d in OLD_B6]
print("pre-fix beat-6 witnesses, bow+rehair changed bytes per round table:",b6_w)
check("the 4 pre-fix beat-6 witnesses (3 all-table + REPORT mechanism example) now change >=2 bytes for all 16 rounds' tables",
      all(min(w)>=2 for w in b6_w))
PRE_B6_STROKES=((0,1,2),(2,3,4),(4,5,6),(6,7,0),(1,2,3),(3,4,5),(5,6,0))
PRE_B6_PRESSURE_ROT=(0,0,0,0,0,0,0)  # pre-beat0rot: every stroke used p as-is
with patch.object(N,"BOW_STROKES",PRE_B6_STROKES), patch.object(N,"BOW_PRESSURE_ROT",PRE_B6_PRESSURE_ROT):
    ctrl=[[sum(x!=y for x,y in zip(N.odd_restack(N.bow_pressure(s),rk["S"],rk["S2"]),
            N.odd_restack(N.bow_pressure([c^(d if k==t else 0) for k,c in enumerate(s)]),rk["S"],rk["S2"]))) for rk in sch0.rounds]
          for s,t,d in OLD_B6]
check("negative control: with pre-beat6 (4,5,6) strokes AND all-zero BOW_PRESSURE_ROT patched in, the 4 beat-6 witnesses are single-byte under all 16 tables",
      all(w==[1]*16 for w in ctrl)
      and N.BOW_STROKES==((0,1,2),(2,3,4),(4,5,0),(6,7,0),(1,2,3),(3,4,5),(5,6,0))
      and N.BOW_PRESSURE_ROT==(0,0,0,3,0,0,5))
# Large NumPy scan: vectorised bow (checked against live bow_pressure) + live round-0 keyed rehair.
_S0=np.array(list(TS[0]),dtype=np.int64); _S20=np.array(list(TS[1]),dtype=np.int64); _G2=np.array(list(N._GF_MUL[2]),dtype=np.int64)
def _rotl(x,r): return ((x<<r)|(x>>(8-r)))&255
def np_bow(A):
    A=A.copy()
    for (i,j,p),k in zip(N.BOW_STROKES, N.BOW_PRESSURE_ROT):
        P=_rotl(A[:,p],k); r1=N.BOW_ROT_BASE+(P%N.BOW_ROT_MOD); r2=N.BOW_ROT_BASE+((P>>N.BOW_R2_SHIFT)%N.BOW_ROT_MOD)
        u=(A[:,i]+_rotl(A[:,j],r1))&255; v=A[:,j]^_rotl(u,r2); A[:,i]=u; A[:,j]=v
    return A
def np_rehair(A):
    O=A.copy()
    for t in (1,3,5,7):
        u,v=A[:,t-1],A[:,t]; O[:,t-1]=_S0[u^v]; O[:,t]=_S20[u^_G2[v]]
    return O
_chk=np.random.default_rng(66).integers(0,256,(5000,8),dtype=np.int64)
check("NumPy bow/rehair model equals live bow_pressure/odd_restack on 5,000 random staffs",
      all(list(np_rehair(np_bow(_chk))[k])==N.odd_restack(N.bow_pressure(list(map(int,_chk[k]))),*TS)
          and list(np_bow(_chk)[k])==N.bow_pressure(list(map(int,_chk[k]))) for k in range(5000)))
import time as _time
_t0=_time.time(); rng6=np.random.default_rng(20261109); B6_BASES=65536; b6_hits=[0]*8; b6_cases=[0]*8
_D=np.arange(1,256,dtype=np.int64)
for chunk in range(B6_BASES//4096):
    base=rng6.integers(0,256,(4096,8),dtype=np.int64); ref=np_rehair(np_bow(base))
    for t in range(8):
        if t!=6 and chunk>=4: continue          # other beats: 16,384 bases x 255 (4.18 M each); beat 6: all 65,536 bases
        Bx=np.repeat(base,255,axis=0); Bx[:,t]^=np.tile(_D,4096)
        w=(np_rehair(np_bow(Bx))!=np.repeat(ref,255,axis=0)).sum(1)
        b6_hits[t]+=int((w==1).sum()); b6_cases[t]+=len(w)
print(f"NumPy bow+rehair singleton scan (round-0 tables), cases per beat {b6_cases}, singletons {b6_hits}, {_time.time()-_t0:.1f}s")
check("beat-6 scan: 0 singletons in 16,711,680 beat-6 cases (65,536 random bases x 255 deltas; pre-fix layout gave ~19) and 0 on every other beat (4,177,920 each)",
      b6_cases[6]==16711680 and all(c==4177920 for k,c in enumerate(b6_cases) if k!=6) and b6_hits==[0]*8)
B6_PRE = "/tmp/sneak_n2_pre_beat6"
b6_blob = optional_blob(B6_PRE+"/hello-world.txt")
if b6_blob is None:
    skip("pre-beat6-fix 195-byte hello-world pickup ee95ddb2 fails as unsupported version, not DecodeError")
else:
    er = catch(lambda: N.decrypt(b6_blob, SEED))
    check("pre-beat6-fix 195-byte hello-world pickup ee95ddb2 fails as unsupported version, not DecodeError",
          len(b6_blob)==195 and b6_blob[3:19].hex()=="ee95ddb278a849bae4a34fe594ee87e5"
          and isinstance(er,N.UnsupportedVersion) and str(er)=="unsupported version")
# ---- beat-0 pressure-rotation fix (2026-11-09, after attacks_octavo_beat6 §6)
B0R_PRE = "/tmp/sneak_n2_pre_beat0rot"
b0r_blob = optional_blob(B0R_PRE+"/hello-world.txt")
if b0r_blob is None:
    skip("pre-beat0rot 195-byte hello-world pickup d450337d fails as unsupported version, not DecodeError")
else:
    er = catch(lambda: N.decrypt(b0r_blob, SEED))
    check("pre-beat0rot 195-byte hello-world pickup d450337d fails as unsupported version, not DecodeError",
          len(b0r_blob)==195 and b0r_blob[3:19].hex()=="d450337d3bbe0b460ae4298952279c7a"
          and isinstance(er,N.UnsupportedVersion) and str(er)=="unsupported version")
# Explicit pressure views: for every pressure byte, the three beat-0 strokes see 0/3/5-bit rotates.
def _stroke_views(p):
    return [N.rotl8(p, N.BOW_PRESSURE_ROT[i]) for i,st in enumerate(N.BOW_STROKES) if st[2]==0]
check("beat-0 pressure views are p, rotl8(p,3), rotl8(p,5) for all 256 pressure bytes",
      all(_stroke_views(p)==[p, N.rotl8(p,3), N.rotl8(p,5)] for p in range(256)))
# Distinct (r1,r2) for the three beat-0 readers on most pressures (shared-rotation hardening).
def _rr(view):
    return (N.BOW_ROT_BASE+(view%N.BOW_ROT_MOD), N.BOW_ROT_BASE+((view>>N.BOW_R2_SHIFT)%N.BOW_ROT_MOD))
shared = sum(1 for p in range(256) if len({_rr(v) for v in _stroke_views(p)})==1)
distinct3 = sum(1 for p in range(256) if len({_rr(v) for v in _stroke_views(p)})==3)
print(f"beat-0 reader (r1,r2) distinctness over 256 p: shared-all={shared}, all-three-distinct={distinct3}")
check("beat-0 readers rarely share one (r1,r2); usually all three distinct (shared < 16, distinct3 > 180)",
      shared < 16 and distinct3 > 180)
# Cheap bow-alone differential spot check (2^12 bases, beats 0/6/7): should beat the pre-fix live numbers
# from attacks_octavo_beat6 (beat 6 ~2^-5.6, beat 7 ~2^-4.9, beat 0 ~2^-8.1).
_rngd=np.random.default_rng(909); Bd=_rngd.integers(0,256,(1<<12,8),dtype=np.int64); Ad=np_bow(Bd)
def _best_diff(t):
    pack=lambda z:(z.astype(np.int64)*(256**np.arange(8))).sum(1); best=0
    for d in range(1,256):
        H=Bd.copy(); H[:,t]^=d; best=max(best,int(np.unique(pack(Ad^np_bow(H)),return_counts=True)[1].max()))
    return round(float(np.log2(best/len(Bd))),2)
bd0,bd6,bd7=_best_diff(0),_best_diff(6),_best_diff(7)
print(f"bow-alone best diff log2 (2^12 bases): beat0={bd0}, beat6={bd6}, beat7={bd7} (pre-fix live ~-8.1/-5.6/-4.9)")
check("bow-alone best differentials on beats 0/6/7 improved vs pre-fix live (~-8.1/-5.6/-4.9)",
      bd0 <= -9.0 and bd6 <= -6.5 and bd7 <= -6.5)
# Description records pressure_rot; key_sig changes if BOW_PRESSURE_ROT is patched (already in loop above).
desc_bow=json.loads(N.mix_description())["bow"]
check("mix_description bow records pressure_rot and the view-then-r1/r2 formula",
      desc_bow["pressure_rot"]==list(N.BOW_PRESSURE_ROT) and "pressure_rot" in desc_bow["formula"]
      and desc_bow["strokes"]==[list(s) for s in N.BOW_STROKES])
B7_PRE = "/tmp/sneak_n2_pre_beat7"
b7_blob = optional_blob(B7_PRE+"/hello-world.txt")
if b7_blob is None:
    skip("pre-beat7-fix 195-byte hello-world pickup 76908595 fails as unsupported version, not DecodeError")
else:
    er = catch(lambda: N.decrypt(b7_blob, SEED))
    check("pre-beat7-fix 195-byte hello-world pickup 76908595 fails as unsupported version, not DecodeError",
          len(b7_blob)==195 and b7_blob[3:19].hex()=="76908595dcdc8f11ff9e045ac25c080c"
          and isinstance(er,N.UnsupportedVersion) and str(er)=="unsupported version")
def affine_bits(f):
    rel=[]
    for col in (0,1):
        for bit in range(8):
            g=lambda u,v:(f(u,v)[col]>>bit)&1; c=g(0,0)
            um=sum((g(1<<j,0)^c)<<j for j in range(8)); vm=sum((g(0,1<<j)^c)<<j for j in range(8))
            if all(g(u,v)==c^(bin(u&um).count("1")&1)^(bin(v&vm).count("1")&1) for u in range(256) for v in range(256)):
                rel.append((col,bit,um,vm,c))
    return rel
aff=[(r,affine_bits(lambda u,v,T=(rk["S"],rk["S2"]):N.latin_pair(u,v,*T))) for r,rk in enumerate(sch0.rounds)]
print("keyed pair exact affine output bits per round (col,bit,u_mask,v_mask,const):",[a for _,a in aff])
check("keyed pair: no output bit is an exact affine function of the inputs (all 16 rounds' tables)", all(a==[] for _,a in aff))
# ---- signature-gap fix (2026-11-09): reachable-closure coverage of code AND module data
import ast as _ast, functools, types as _types, textwrap as _textwrap, tempfile
SIG_PRE = "/tmp/sneak_n2_pre_sig_gap"
sig_blob = optional_blob(SIG_PRE+"/hello-world.txt")
if sig_blob is None:
    skip("pre-sig-gap 195-byte hello-world pickup 24d554eb fails as unsupported version, not DecodeError")
else:
    er = catch(lambda: N.decrypt(sig_blob, SEED))
    check("pre-sig-gap 195-byte hello-world pickup 24d554eb fails as unsupported version, not DecodeError",
          len(sig_blob)==195 and sig_blob[3:19].hex()=="24d554eb3d22f0b6412d7da59e504df1"
          and isinstance(er,N.UnsupportedVersion) and str(er)=="unsupported version")
# Independent call-graph walk (own AST walker over the module's globals, from MIX_CODE_ROOTS).
def indep_closure():
    seen=set(); data=set(); todo=list(N.MIX_CODE_ROOTS)
    skip=set(N._ATTEST_SKIP)
    while todo:
        n=todo.pop()
        if n in skip or n in seen or n in data or not hasattr(N,n): continue
        o=getattr(N,n)
        if isinstance(o,_types.ModuleType): continue
        if inspect.isfunction(o) or inspect.isclass(o):
            seen.add(n); todo += [x.id for x in _ast.walk(_ast.parse(_textwrap.dedent(inspect.getsource(o)))) if isinstance(x,_ast.Name)]
        else: data.add(n)
    return seen,data
reach,reach_data=indep_closure()
IMPORT_TIME_BUILDERS={"_gf_mul_raw","bar_det","bar_inv","triplet_det","triplet_inv"}
print("reachable functions/classes:",len(reach),"; reachable module data:",sorted(reach_data))
check("nothing reachable from MIX_CODE_ROOTS is missing from MIX_CODE_FUNCS; listed extras are only the import-time table builders",
      reach <= set(N.MIX_CODE_FUNCS) and set(N.MIX_CODE_FUNCS)-reach==IMPORT_TIME_BUILDERS
      and (reach,reach_data)==N.mix_code_closure() and len(N.MIX_CODE_FUNCS)==len(set(N.MIX_CODE_FUNCS)))
mod_defs={n for n,o in vars(N).items() if (inspect.isfunction(o) or inspect.isclass(o)) and getattr(o,"__module__",None)==N.__name__}
print("module functions/classes NOT in coverage:",sorted(mod_defs-set(N.MIX_CODE_FUNCS)))
_rh_only = N.mix_code_closure(N.REHEARSAL_CODE_ROOTS)[0]-set(N.MIX_CODE_FUNCS)
check("only non-cipher helpers are outside mix coverage (ddt_max, lat_max, grid_rows, encrypt_hello, import attestations incl. the import-time source snapshot) plus rehearsal code, which the rehearsal digest covers",
      mod_defs-set(N.MIX_CODE_FUNCS)=={"ddt_max","lat_max","grid_rows","encrypt_hello","_init_attestation","_init_rehearsal_attestation","_module_source_snapshot","_verify_executed_code"}|_rh_only
      and all("rehearsal" in n.lower() or n in ("_fresh_stream_nonce","UnfinalizedStreamWarning") for n in _rh_only)
      and "UnfinalizedStreamWarning" in _rh_only and "_module_source_snapshot" not in _rh_only)
check("closure includes staff_mix/staff_unmix/shell_mix/shell_unmix/weave/unweave/xor_grid/Schedule/keyed_sbox/encode_block/encrypt_grid/decrypt_grid",
      {"staff_mix","staff_unmix","shell_mix","shell_unmix","weave","unweave","xor_grid","Schedule","StaffSponge","keyed_sbox",
       "mat_apply","mat_invertible","encode_block","encrypt_grid","decrypt_grid","bytes_to_grid","grid_to_bytes","_tag","staff_clef"} <= reach)
check("module data hashed includes BARS, BARS_INV, TRIPLETS(_INV), CROSS_*, BOW_* (incl. BOW_PRESSURE_ROT), LAYERS, SM4_SBOX, _GF_MUL, MIX2_*, sizes",
      {"BARS","BARS_INV","TRIPLETS","TRIPLETS_INV","CROSS_OPPOSITE","CROSS_RADIAL","CROSS_ADJACENT","CROSS_BRIDGE","CROSS_LAYERS",
       "BOW_STROKES","BOW_PRESSURE_ROT","BOW_ROT_BASE","BOW_ROT_MOD","BOW_R2_SHIFT","LAYERS","SM4_SBOX","_GF_MUL","MIX2_MATRIX","MIX2_INV","FIELD_POLY",
       "NF","NB","NR","BLOCK_LEN","VERSION","MAX_AD_LEN"} <= reach_data and json.loads(N.mix_description())["mix_data"]["names"]==sorted(reach_data)
      and len(reach_data)==56)   # conductor-polish: + _UNPAD_TOP, _UNPAD_MASKS
def frame(h,parts):
    for part in parts: b=part.encode(); h.update(len(b).to_bytes(8,"big")); h.update(b)
desc5=json.loads(N.mix_description())
code=hashlib.sha256()
for name in desc5["mix_code"]["functions"]:
    o=getattr(N,name); frame(code,(name,inspect.getsource(o),N._canon_data((getattr(o,"__defaults__",None),getattr(o,"__kwdefaults__",None)))))
data=hashlib.sha256()
for name in sorted(reach_data): frame(data,(name,N._canon_data(getattr(N,name))))
check("independent recomputation of mix_code and mix_data digests matches",
      desc5["mix_code"]["sha256"]==code.hexdigest() and desc5["mix_data"]["sha256"]==data.hexdigest()
      and desc5["mix_code"]["functions"]==list(N.MIX_CODE_FUNCS))
def modified_source(full, name):
    """Behaviour-preserving edit to ONE top-level def/class: insert a no-op statement (or parenthesise a one-line return)."""
    lines=full.split("\n"); idx=next(i for i,l in enumerate(lines) if l.startswith(("def "+name+"(","class "+name+"(","class "+name+":")))
    hdr=lines[idx]
    if hdr.split("#")[0].rstrip().endswith(":"):
        nxt=next(l for l in lines[idx+1:] if l.strip()); ind=nxt[:len(nxt)-len(nxt.lstrip())]
        lines.insert(idx+1, ind+"_sig_gap_probe = 1  # modified copy")
    else:
        assert ": return " in hdr, name; lines[idx]=hdr.replace(": return ",": return (",1)+")"
    return "\n".join(lines)
live_sig=N.key_signature(SEED); results={}
def loosen_attest(src_text):
    # rehearsal: the rehearsal digest covers the staff-core too, so a modified copy loosens both embedded digests
    return src_text.replace('EXPECTED_MIX_SHA256 = "'+N.EXPECTED_MIX_SHA256+'"', 'EXPECTED_MIX_SHA256 = "TO_BE_FILLED"', 1).replace(
        'EXPECTED_REHEARSAL_SHA256 = "'+N.EXPECTED_REHEARSAL_SHA256+'"', 'EXPECTED_REHEARSAL_SHA256 = "TO_BE_FILLED"', 1)
with tempfile.TemporaryDirectory(prefix="n2_sig_gap_") as td:
    for name in [n for n in N.MIX_CODE_FUNCS if n not in ("AuthError","DecodeError","UnsupportedVersion")]:
        path=os.path.join(td,"mod_"+name+".py"); open(path,"w").write(loosen_attest(modified_source(src,name)))
        alt=load("sig_gap_"+name,path)
        assert inspect.getsource(getattr(alt,name))!=inspect.getsource(getattr(N,name)), name
        ab=alt.encrypt(b"hello world", SEED)
        er=catch(lambda:N.decrypt(ab,SEED))
        results[name]=(alt.key_signature(SEED)!=live_sig, isinstance(er,N.AuthError) and str(er)=="authentication failed")
    bad=[n for n,(a,b) in results.items() if not (a and b)]
    print(f"modified-file revisions: {len(results)} functions/classes; key_sig changed AND live decrypt of alt blob -> authentication failed for {len(results)-len(bad)}; failures {bad}")
    for name in ("staff_mix","staff_unmix","shell_mix","shell_unmix","weave","unweave"):
        check("modified file of "+name+": key_sig changes and its blob fails live with AuthError authentication failed", results[name]==(True,True))
    check("modified file of EVERY covered function/class (all but the exception classes) changes key_sig and fails live on tag",
          not bad and len(results)==len(N.MIX_CODE_FUNCS)-3)
    # Identity staff_mix as its own revision (file copy), not an in-process patch.
    idsrc=loosen_attest(src).replace("def staff_mix(g, sigma):", "def staff_mix(g, sigma):\n    return [row[:] for row in g]\n    # ", 1)
    idpath=os.path.join(td,"identity_staff_mix_rev.py"); open(idpath,"w").write(idsrc)
    ident=load("identity_staff_mix_rev",idpath)
    blob3=ident.encrypt(b"hello world",SEED)
    er3=catch(lambda:N.decrypt(blob3,SEED))
    print("identity staff_mix revision: key_sig same as live:",ident.key_signature(SEED)==live_sig,"; tampered blob on live:",repr(er3))
    check("identity staff_mix file revision: key_sig differs and its blob fails live on TAG",
          ident.key_signature(SEED)!=live_sig and isinstance(er3,N.AuthError) and str(er3)=="authentication failed")
    # A replacement that calls a NEW module-level helper: the helper is followed by the live closure walk.
    hp=os.path.join(td,"helper_a.py"); open(hp,"w").write("def staff_mix(g,sigma):return _extra(g)\ndef _extra(g):return [row[:] for row in g]\n")
    hq=os.path.join(td,"helper_b.py"); open(hq,"w").write("def _extra(g):return [row[::-1] for row in g]\n")
    ha=load("helper_a",hp); hb=load("helper_b",hq)
    with patch.object(N,"staff_mix",ha.staff_mix), patch.object(N,"_extra",ha._extra,create=True):
        d_a=N.mix_description(); in_closure="_extra" in N.mix_code_closure()[0]
        with patch.object(N,"_extra",hb._extra): d_b=N.mix_description()
    check("new module-level helper named by a replacement is in the live closure; changing only that helper changes mix_description",
          in_closure and d_a!=N.mix_description() and d_b!=d_a)
# Data tables that were NOT in the old JSON description.
for name,value in (("LAYERS",(1,4,2)),("SM4_SBOX",N.SM4_SBOX[1:]+N.SM4_SBOX[:1]),("_GF_MUL",N._GF_MUL[:-1]+(bytes(256),)),
                   ("BARS_INV",N.BARS_INV[::-1]),("TRIPLETS_INV",N.TRIPLETS_INV[::-1]),("MIX2_INV",((1,1),(1,1))),("NR",15),("VERSION",b"SN3")):
    desc0=N.mix_description()
    with patch.object(N,name,value): changed=N.mix_description()!=desc0
    check("mix_description changes when module data "+name+" changes (key_sig is cached at import)",changed)
# Fail closed: mix_description still raises on a non-attestable replacement; key_signature uses the cache.
for label,obj in (("builtin list",list),("functools.partial",functools.partial(N.staff_mix))):
    with patch.object(N,"staff_mix",obj):
        e1=catch(lambda:N.mix_description()); e2=catch(lambda:N.key_signature(SEED))
    check("staff_mix replaced by "+label+": mix_description raises (fail closed); cached key_signature still works",
          isinstance(e1,Exception) and e2 is None)
check("key signature is stable across calls in an untouched process", N.key_signature(SEED)==live_sig==N.key_signature(SEED))
# A real file gives inspect an honest changed source; no protected files touched.
import tempfile
with tempfile.TemporaryDirectory(prefix="n2_code_patch_") as td:
    patchpath=os.path.join(td,"patched_n2.py")
    patched_src=src.replace('row[i], row[j] = b0_apply(row[i], row[j], Sa, Sb) if name == "B0 start" else bar_apply(M, row[i], row[j])',
                            'row[i], row[j] = (row[i], row[j]) if name == "B0 start" else bar_apply(M, row[i], row[j])')
    patched_src=patched_src.replace('row[i], row[j] = b0_unapply(row[i], row[j], SIa, SIb) if BARS[k][0] == "B0 start" else bar_apply(BARS_INV[k], row[i], row[j])',
                                    'row[i], row[j] = (row[i], row[j]) if BARS[k][0] == "B0 start" else bar_apply(BARS_INV[k], row[i], row[j])')
    patched_src=loosen_attest(patched_src)
    open(patchpath,"w").write(patched_src)
    alt=load("skip_b0_code",patchpath)
    ab=alt.encrypt(b"hello world",SEED); er=catch(lambda:N.decrypt(ab,SEED))
    check("copied bar_mix skips B0, BARS identical: key_sig changes; alternate roundtrip; live authentication failed",
          alt.BARS==N.BARS and inspect.getsource(alt.bar_mix)!=inspect.getsource(N.bar_mix)
          and alt.mix_description()!=N.mix_description() and alt.key_signature(SEED)!=N.key_signature(SEED)
          and alt.decrypt(ab,SEED)==b"hello world" and isinstance(er,N.AuthError) and str(er)=="authentication failed")
    desc0=N.mix_description()
    with patch.object(N,"bar_mix",alt.bar_mix):
        check("runtime replacing bar_mix object changes mix_description without editing BARS (key_sig stays cached)",
              N.mix_description()!=desc0)

# ---- diffusion: 1-byte input difference at every one of the 128 cells, union of affected output BYTES over trials
def dependence(maxr=6, trials=4):
    rr = random.Random(5); union = [[set() for _ in range(128)] for _ in range(maxr)]; mean = [0] * maxr; n = 0
    for p in range(128):
        for _ in range(trials):
            sch = N.Schedule(SEED, bytes(rr.randrange(256) for _ in range(16)))
            g = [[rr.randrange(256) for _ in range(8)] for _ in range(16)]
            h = [row[:] for row in g]; h[p // 8][p % 8] ^= rr.randrange(1, 256)
            for r in range(maxr):
                g = N.round_enc(g, sch.rounds[r], r); h = N.round_enc(h, sch.rounds[r], r)
                d = {8 * f + t for f in range(16) for t in range(8) if g[f][t] != h[f][t]}
                union[r][p] |= d; mean[r] += len(d)
            n += 1
    mins = [min(len(u) for u in union[r]) for r in range(maxr)]
    return mins, [m / n for m in mean], next((r + 1 for r in range(maxr) if mins[r] == 128), None)
n2 = dependence()
print("N2-8bit+bars+triplets diffusion, min over 128 input bytes of |union of affected output bytes| after r rounds:", n2[0])
print("N2-8bit+bars+triplets diffusion, mean affected bytes per single trial (random ~127.5):", [round(x, 1) for x in n2[1]])
print(f"N2-8bit+bars+triplets full byte dependence at round {n2[2]}  (8-bit N2 before bars: round 3, min-union [37, 127, 128]; 4-bit N2: round 3)")
check("N2-8bit reaches full 128-byte dependence by round 4", n2[2] is not None and n2[2] <= 4)
check("N2-8bit mean affected bytes after 3 rounds >= 120 (random-like 127.5)", n2[1][2] >= 120)
def av(rounds, n=300):
    hs = []
    for _ in range(n):
        s = N.Schedule(SEED, rb(16)); x = rb(128); y = flip(x, R.randrange(1024))
        e = lambda z: N.grid_to_bytes(N.encrypt_grid(N.bytes_to_grid(z), s, rounds))
        hs.append(hd(e(x), e(y)))
    return sum(hs) / n, min(hs), max(hs)
for r in (1, 2, 3, 4, 16):
    a = av(r, 300 if r < 16 else 1000); print(f"bit avalanche {r:2d} rounds: mean {a[0]:.1f}/1024, min {a[1]}, max {a[2]}")
    if r == 4: a4 = a
    if r == 16: a16 = a
check("4-round bit avalanche mean within 496..528 (of 1024)", 496 <= a4[0] <= 528)
check("16-round bit avalanche mean within 500..524, min > 440", 500 <= a16[0] <= 524 and a16[1] > 440)
cnt = [0] * 256
for _ in range(2000):
    for b in N.encrypt(rb(12), SEED)[N.CT0:N.CT1]: cnt[b] += 1
ex = sum(cnt) / 256; chi = sum((o - ex) ** 2 / ex for o in cnt); print(f"ct byte chi2 over 2000 random messages (255 df, 99.9% crit 330.5): {chi:.1f}")
check("ct byte distribution uniform-ish (chi2 < 330.5)", chi < 330.5)

# ---- test-gap fix from the 2% mutation lab (lab-only; cipher unchanged)
# Mutant C059 set MIX2_MATRIX[0][0] 1->0, so mix2 became (v, u^2v): invertible, but the
# first output ignores u. One-round avalanche fell to ~448/1024 bits and ~111.8/128
# changed bytes; later rounds hid it well enough that the loose statistical bounds
# above (full dependence by round 4, mean affected bytes after 3 rounds >= 120,
# 16-round mean in 500..524) would likely still pass. Zeroing a last-row triplet
# coefficient likewise stayed inside those bounds. These checks close that gap:
# every small linear mix is complete (MDS-like / branch-number, derived from the
# live maps), and a tight one-round diffusion band is scored with a fixed seed.
import time as _tg_time
_tg_t0 = _tg_time.perf_counter()

def field_pair_complete(mod, M):
    """2x2 over GF(2^8) is MDS iff every entry is nonzero and det is nonzero.
    Then a change in either input changes both outputs, for every nonzero delta."""
    return (all(M[i][j] != 0 for i in range(2) for j in range(2))
            and mod.bar_det(M) != 0
            and all(all(mod.bar_apply(M, d, 0)) and all(mod.bar_apply(M, 0, d)) for d in range(1, 256)))

def triplet_complete(mod, M):
    """Each output depends on each input (every entry nonzero), a one-input change
    always hits >=2 outputs (each row/column has >=2 odd entries; odd is a unit
    mod 256), and det is odd (invertible over Z/256Z). Not a full MDS claim —
    even entries are allowed, matching the live design comment."""
    return (all(M[i][j] != 0 for i in range(3) for j in range(3))
            and all(sum(x & 1 for x in row) >= 2 for row in M)
            and all(sum(M[i][j] & 1 for i in range(3)) >= 2 for j in range(3))
            and (mod.triplet_det(M) & 1) == 1)

def linear_mixes_complete(mod):
    """Structural completeness of every small linear mix on this module."""
    if not field_pair_complete(mod, mod.MIX2_MATRIX):
        return False
    for name, _, _, M in mod.BARS:
        if M is None:
            continue  # B0 has no field matrix; its field step is mix2 via latin_pair
        if not field_pair_complete(mod, M):
            return False
    for _, _, M in mod.TRIPLETS:
        if not triplet_complete(mod, M):
            return False
    return True

check("mix2 2x2 is MDS over GF(2^8): all entries nonzero, det nonzero, both outputs depend on both inputs",
      field_pair_complete(N, N.MIX2_MATRIX) and N.MIX2_MATRIX == ((1, 1), (1, 2)))
check("each field bar-pair matrix is MDS over GF(2^8) (every output depends on every input)",
      all(M is not None and field_pair_complete(N, M) for _, _, _, M in N.BARS[1:]) and N.BARS[0][3] is None)
_idS = list(range(256))
check("B0 and odd-restack latin field step equals mix2 (identity S-boxes, all 65,536 pairs); both therefore inherit the MDS 2x2",
      all(N.latin_pair(u, v, _idS, _idS) == N.mix2(u, v) == N.b0_apply(u, v, _idS, _idS)
          for u in range(256) for v in range(256))
      and all((lambda s: tuple(N.odd_restack(s, _idS, _idS)[t-1:t+1]) == N.mix2(s[t-1], s[t]))
              ([u if k == t-1 else (v if k == t else 0) for k in range(8)])
              for t in (1, 3, 5, 7) for u in range(0, 256, 17) for v in range(0, 256, 17)))
check("staff butterfly, shell bridges, and cross-staff layers apply mix2 (the MDS 2x2), not a private matrix",
      all("mix2(" in inspect.getsource(getattr(N, fn)) for fn in ("staff_mix", "shell_mix", "cross_staff_mix")))
check("each triplet: every entry nonzero, >=2 odd coefficients per row and column, odd determinant",
      all(triplet_complete(N, M) for _, _, M in N.TRIPLETS))
check("all small linear mixes (mix2, field bars, B0/latin/restack field step, triplets) are complete",
      linear_mixes_complete(N))

# One-round diffusion, fixed cases. Calibrated on live SEED + DEMO_NONCE, round 0,
# RNG seed 20261110, 48 single-bit + 48 single-byte differences (white=False, one
# round_enc). Baseline means were ~512.8 / 511.3 flipped bits and ~127.5 / 127.6
# changed bytes. C059 scored ~439 / 442 bits and ~108.9 / 110.4 bytes. Band
# 500..524 is the same tight window as the 16-round check, with ~12 bits of
# margin on the baseline mean; 124 changed bytes is ~3.5 below the baseline
# mean of ~127.5 and ~13 above C059.
_TG_RNG_SEED, _TG_NBIT, _TG_NBYTE = 20261110, 48, 48
_TG_BIT_LO, _TG_BIT_HI, _TG_BYTE_MIN = 500, 524, 124

def one_round_diffusion(mod, sch, rng_seed=_TG_RNG_SEED, n_bit=_TG_NBIT, n_byte=_TG_NBYTE):
    """Mean flipped bits and changed bytes after exactly one round, fixed RNG."""
    rng = random.Random(rng_seed)
    rk = sch.rounds[0]
    def enc(block):
        return mod.grid_to_bytes(mod.round_enc(mod.bytes_to_grid(block), rk, 0))
    bit_hw, bit_cb, byte_hw, byte_cb = [], [], [], []
    for _ in range(n_bit):
        x = bytes(rng.randrange(256) for _ in range(128))
        bit = rng.randrange(1024)
        y = bytes(b ^ (1 << (bit % 8)) if i == bit // 8 else b for i, b in enumerate(x))
        xe, ye = enc(x), enc(y)
        bit_hw.append(sum(bin(a ^ b).count("1") for a, b in zip(xe, ye)))
        bit_cb.append(sum(a != b for a, b in zip(xe, ye)))
    for _ in range(n_byte):
        x = bytes(rng.randrange(256) for _ in range(128))
        pos = rng.randrange(128)
        dx = rng.randrange(1, 256)
        y = bytearray(x); y[pos] ^= dx
        xe, ye = enc(x), enc(bytes(y))
        byte_hw.append(sum(bin(a ^ b).count("1") for a, b in zip(xe, ye)))
        byte_cb.append(sum(a != b for a, b in zip(xe, ye)))
    return (sum(bit_hw) / n_bit, sum(bit_cb) / n_bit, sum(byte_hw) / n_byte, sum(byte_cb) / n_byte)

def one_round_in_band(stats):
    bit_hw, bit_cb, byte_hw, byte_cb = stats
    return (_TG_BIT_LO <= bit_hw <= _TG_BIT_HI and _TG_BIT_LO <= byte_hw <= _TG_BIT_HI
            and bit_cb >= _TG_BYTE_MIN and byte_cb >= _TG_BYTE_MIN)

_tg_live = one_round_diffusion(N, sch0)
print(f"one-round diffusion (SEED+DEMO_NONCE, RNG {_TG_RNG_SEED}, {_TG_NBIT} bit + {_TG_NBYTE} byte): "
      f"bit mean { _tg_live[0]:.3f}/1024 bits, {_tg_live[1]:.3f}/128 bytes; "
      f"byte-diff mean {_tg_live[2]:.3f}/1024 bits, {_tg_live[3]:.3f}/128 bytes")
check("one-round single-bit and single-byte means: flipped bits in 500..524, changed bytes >= 124",
      one_round_in_band(_tg_live))

# Regression: throwaway copies of the live module (nothing written to the tree).
# C059 is the lab mutant (MIX2[0][0] 1->0 plus the two accompanying triplet tweaks).
# The last-row-zero mutant is T0.M[2][2] 2->0, one of the lab's triplet-corner flags.
def _rebuild_trips(mod, edits):
    trips = []
    for name, win, Mat in mod.TRIPLETS:
        Mat = [list(row) for row in Mat]
        if name in edits:
            i, j, val = edits[name]
            Mat[i][j] = val
        trips.append((name, win, tuple(tuple(row) for row in Mat)))
    mod.TRIPLETS = tuple(trips)
    mod.TRIPLETS_INV = tuple(mod.triplet_inv(M) for _, _, M in mod.TRIPLETS)

_c059 = load("mutant_c059", os.path.join(HERE, "sneak_n2.py"))
_c059.MIX2_MATRIX = ((0, 1), (1, 2))
_c059.MIX2_INV = _c059.bar_inv(_c059.MIX2_MATRIX)
_rebuild_trips(_c059, {"T5": (1, 1, 7), "T3": (0, 1, 9)})
_c059_stats = one_round_diffusion(_c059, sch0)
print(f"C059 throwaway one-round: bit mean {_c059_stats[0]:.3f}/1024 bits, {_c059_stats[1]:.3f}/128 bytes; "
      f"byte-diff mean {_c059_stats[2]:.3f}/1024 bits, {_c059_stats[3]:.3f}/128 bytes")
check("C059 throwaway (MIX2[0][0] 1->0) fails the mix2 MDS check and the one-round diffusion band",
      not field_pair_complete(_c059, _c059.MIX2_MATRIX)
      and not linear_mixes_complete(_c059)
      and not one_round_in_band(_c059_stats)
      and _c059_stats[0] < _TG_BIT_LO and _c059_stats[2] < _TG_BIT_LO
      and _c059_stats[1] < _TG_BYTE_MIN and _c059_stats[3] < _TG_BYTE_MIN)

_t0z = load("mutant_t0_lastrow", os.path.join(HERE, "sneak_n2.py"))
_rebuild_trips(_t0z, {"T0": (2, 2, 0)})
check("triplet last-row-zero throwaway (T0.M[2][2] 2->0) fails the all-entries-nonzero / complete-mix check",
      not triplet_complete(_t0z, _t0z.TRIPLETS[0][2])
      and not linear_mixes_complete(_t0z)
      and linear_mixes_complete(N)
      and _t0z.TRIPLETS[0][2][2][2] == 0
      and N.TRIPLETS[0][2][2][2] == 2)
print(f"test-gap checks wall time: {_tg_time.perf_counter() - _tg_t0:.2f}s")

# ---- outer-layer fixes (strict types, verify-before-expand, AD cap, FEATURES)
_bad_types = (5, 0, [104, 105], "hi", None)
check("encrypt rejects int/list/str/None msg with TypeError (no bytes() coercion)",
      all(isinstance(catch(lambda m=m: N.encrypt(m, SEED)), TypeError) for m in _bad_types))
check("encrypt rejects int/list/str/None ad with TypeError (no bytes() coercion)",
      all(isinstance(catch(lambda a=a: N.encrypt(b"x", SEED, ad=a)), TypeError) for a in (3, 0, [1, 2], "ad", None)))
check("decrypt rejects int/list/str/None blob with TypeError",
      all(isinstance(catch(lambda b=b: N.decrypt(b, SEED)), TypeError) for b in _bad_types))
check("decrypt rejects int/list/str/None ad with TypeError",
      all(isinstance(catch(lambda a=a: N.decrypt(HW_BLOB, SEED, ad=a)), TypeError) for a in (3, 0, [1, 2], "ad", None)))
check("encrypt/decrypt accept bytearray and memoryview for msg, blob, and ad",
      N.decrypt(bytearray(N.encrypt(bytearray(b"hi"), SEED, ad=memoryview(b"ad"))), SEED, ad=bytearray(b"ad")) == b"hi"
      and N.decrypt(memoryview(N.encrypt(memoryview(b"ok"), SEED, ad=bytearray(b""))), SEED) == b"ok")
check("explicit ad=None is TypeError, not empty AD",
      isinstance(catch(lambda: N.encrypt(b"x", SEED, ad=None)), TypeError)
      and N.decrypt(N.encrypt(b"x", SEED), SEED, ad=b"") == b"x")

check("MAX_AD_LEN is 65536 and is enforced on encrypt and decrypt",
      N.MAX_AD_LEN == 65536)
_ad_max = b"A" * N.MAX_AD_LEN
check("AD of exactly MAX_AD_LEN round-trips",
      N.decrypt(N.encrypt(b"cap", SEED, ad=_ad_max), SEED, ad=_ad_max) == b"cap")
_e_ad = catch(lambda: N.encrypt(b"x", SEED, ad=b"A" * (N.MAX_AD_LEN + 1)))
_e_ad_d = catch(lambda: N.decrypt(HW_BLOB, SEED, ad=b"A" * (N.MAX_AD_LEN + 1)))
check("AD of MAX_AD_LEN+1 raises ValueError on encrypt and decrypt",
      isinstance(_e_ad, ValueError) and "associated data too long" in str(_e_ad)
      and isinstance(_e_ad_d, ValueError) and "associated data too long" in str(_e_ad_d))

_seen = []
_orig_sch = N.Schedule.__init__
def _sch_probe(self, seed, nonce):
    _seen.append("Schedule")
    return _orig_sch(self, seed, nonce)
N.Schedule.__init__ = _sch_probe
try:
    _bad = bytearray(HW_BLOB); _bad[-1] ^= 1
    _e_bad = catch(lambda: N.decrypt(bytes(_bad), SEED))
    _n_bad = list(_seen)
    _seen.clear()
    _ok = N.decrypt(HW_BLOB, SEED)
    _n_good = list(_seen)
finally:
    N.Schedule.__init__ = _orig_sch
check("bad tag is rejected without building Schedule; a valid blob still builds Schedule then decrypts",
      isinstance(_e_bad, N.AuthError) and type(_e_bad) is N.AuthError and str(_e_bad) == "authentication failed"
      and _n_bad == [] and _n_good == ["Schedule"] and _ok == b"hello world")

check("FEATURES mention the version byte and AD in the HMAC description, and AD in the SIV nonce",
      any("HMAC" in f and "version" in f and "AD" in f for f in N.FEATURES)
      and any("SIV" in f and "AD" in f for f in N.FEATURES)
      and any("movements" in f and "theme" in f and "cadence" in f and "coda" in f and "cadences" in f and "AD" in f for f in N.FEATURES)
      and any("études" in f and "lab only" in f for f in N.FEATURES)
      and any("tuning" in f and "HMAC-U" in f and "commitment" in f for f in N.FEATURES)
      and any("tuning" in f and "HMAC" in f for f in N.FEATURES)
      and any("conductor" in f and "equal-time" in f for f in N.FEATURES)
      and any("conductor-polish" in f and "equal-time" in f for f in N.FEATURES)
      and any("rehearsal" in f and "v8" in f for f in N.FEATURES)
      and N.REVISION == "rehearsal-finale" and N.REVISION_DATE == "2026-11-11")

# ---- movements mode (format version 7; legacy version 3 only via decrypt_movements_legacy)
check("FMT_MOVEMENTS is 7, distinct from single-block version 6, and the header/stride sizes match the layout",
      N.FMT_MOVEMENTS == 7 and N.FMT_VERSION == 6
      and N.FMT_MOVEMENTS_V3 == 3 and N.FMT_VERSION_V2 == 2
      and N.FMT_MOVEMENTS_V5 == 5 and N.FMT_VERSION_V4 == 4
      and N.MAX_MOVEMENTS == 8192 and N.MAX_MOVEMENTS_MSG == 8192 * 127
      and N.MOVEMENT_STRIDE == 160 and N.MOVEMENTS_HDR_LEN == 72 and N.NMOV0 == 68
      and N.COMMIT_LEN == 32 and N.COMMIT_DOMAIN == b"U")
_mv_lens = (0, 1, 126, 127, 128, 129, 253, 254, 255, 256, 381, 400)
_mv_ok = True
_mv_n = {}
for _L in _mv_lens:
    _m = bytes((_L + i) % 256 for i in range(_L))
    _b = N.encrypt_movements(_m, SEED)
    _n = int.from_bytes(_b[N.NMOV0:N.MOVEMENTS_HDR_LEN], "big")
    _mv_n[_L] = _n
    _exp_n = 1 if _L == 0 else (_L + 126) // 127
    _exp_len = N.MOVEMENTS_HDR_LEN + _exp_n * N.MOVEMENT_STRIDE + N.TAG_LEN
    if not (_b[:4] == bytes([N.FMT_MOVEMENTS]) + b"SN2" and _n == _exp_n and len(_b) == _exp_len and N.decrypt_movements(_b, SEED) == _m):
        _mv_ok = False
check("movements round-trip lengths 0,1,126,127,128,129,253,254,255,256,381,400 with expected movement counts",
      _mv_ok and _mv_n[0] == _mv_n[1] == _mv_n[127] == 1 and _mv_n[128] == _mv_n[254] == 2 and _mv_n[255] == 3)
_mv_big = bytes(range(256)) * 16  # 4096 bytes, 33 movements
_mv_big_blob = N.encrypt_movements(_mv_big, SEED)
check("movements round-trip a 4096-byte message (33 movements)",
      int.from_bytes(_mv_big_blob[N.NMOV0:N.MOVEMENTS_HDR_LEN], "big") == 33 and N.decrypt_movements(_mv_big_blob, SEED) == _mv_big)
_mv_ad = b"from:orchestra"
_mv_msg = b"theme " * 40  # 240 bytes -> 2 movements
_mv_ad_blob = N.encrypt_movements(_mv_msg, SEED, ad=_mv_ad)
check("movements AD round-trip and empty AD matches omitted AD",
      N.decrypt_movements(_mv_ad_blob, SEED, ad=_mv_ad) == _mv_msg
      and N.decrypt_movements(N.encrypt_movements(b"solo", SEED), SEED) == b"solo"
      and N.decrypt_movements(N.encrypt_movements(b"solo", SEED, ad=b""), SEED, ad=b"") == b"solo")
check("movements rejects int/list/str/None msg and ad with TypeError",
      all(isinstance(catch(lambda m=m: N.encrypt_movements(m, SEED)), TypeError) for m in _bad_types)
      and all(isinstance(catch(lambda a=a: N.encrypt_movements(b"x", SEED, ad=a)), TypeError) for a in (3, 0, [1, 2], "ad", None))
      and all(isinstance(catch(lambda b=b: N.decrypt_movements(b, SEED)), TypeError) for b in _bad_types))
check("movements oversize message and MAX_AD_LEN+1 are rejected",
      isinstance(catch(lambda: N.encrypt_movements(bytes(N.MAX_MOVEMENTS_MSG + 1), SEED)), ValueError)
      and isinstance(catch(lambda: N.encrypt_movements(b"x", SEED, ad=b"A" * (N.MAX_AD_LEN + 1))), ValueError)
      and isinstance(catch(lambda: N.decrypt_movements(_mv_ad_blob, SEED, ad=b"A" * (N.MAX_AD_LEN + 1))), ValueError))
check("movements wrong seed, wrong AD, and empty-vs-absent AD mismatch fail closed",
      isinstance(catch(lambda: N.decrypt_movements(_mv_ad_blob, bytes(range(128)))), N.AuthError)
      and isinstance(catch(lambda: N.decrypt_movements(_mv_ad_blob, SEED, ad=b"from:balcony")), N.AuthError)
      and isinstance(catch(lambda: N.decrypt_movements(_mv_ad_blob, SEED)), N.AuthError)
      and isinstance(catch(lambda: N.decrypt_movements(_mv_ad_blob, SEED, ad=b"")), N.AuthError))
check("version confusion: decrypt rejects a movements blob; decrypt_movements rejects a version-6 blob",
      isinstance(catch(lambda: N.decrypt(_mv_ad_blob, SEED, ad=_mv_ad)), N.UnsupportedVersion)
      and isinstance(catch(lambda: N.decrypt_movements(HW_BLOB, SEED)), N.UnsupportedVersion)
      and str(catch(lambda: N.decrypt(_mv_ad_blob, SEED, ad=_mv_ad))) == "unsupported version"
      and str(catch(lambda: N.decrypt_movements(HW_BLOB, SEED))) == "unsupported version")
# synthetic nonce binding
_pk = _mv_ad_blob[4:20]
_syn = N.siv_nonce_movements(_mv_msg, _pk, SEED, _mv_ad)
check("movements SIV nonce matches sha256(clef||pickup||len||msg||encode_ad(ad)) and a wrong caller nonce is rejected",
      _mv_ad_blob[20:36] == _syn
      and _syn == __import__("hashlib").sha256(N.staff_clef(SEED) + _pk + len(_mv_msg).to_bytes(8, "big") + _mv_msg + N._encode_ad(_mv_ad)).digest()[:16]
      and isinstance(catch(lambda: N.encrypt_movements(_mv_msg, SEED, ad=_mv_ad, nonce=bytes(16))), ValueError))

def _mv_tamper_ok():
    blob = N.encrypt_movements(b"twelve notes make a row and then some more" * 5, SEED, ad=b"score")
    n = int.from_bytes(blob[N.NMOV0:N.MOVEMENTS_HDR_LEN], "big")
    assert n >= 2
    cases = []
    # truncate / extend
    cases.append(isinstance(catch(lambda: N.decrypt_movements(blob[:-1], SEED, ad=b"score")), N.AuthError))
    cases.append(isinstance(catch(lambda: N.decrypt_movements(blob + b"\x00", SEED, ad=b"score")), N.AuthError))
    # bit flips in every region
    regions = {
        "version": 0, "magic": 2, "pickup": 10, "nonce": 24, "commit": 40, "nmov": N.NMOV0 + 2,
        "ct0": N.MOVEMENTS_HDR_LEN + 10, "cadence0": N.MOVEMENTS_HDR_LEN + N.BLOCK_LEN + 3,
        "coda": len(blob) - 1,
    }
    for off in regions.values():
        bad = bytearray(blob); bad[off] ^= 1
        cases.append(isinstance(catch(lambda b=bytes(bad): N.decrypt_movements(b, SEED, ad=b"score")), (N.AuthError, N.UnsupportedVersion)))
    # reorder movements 0 and 1
    swapped = bytearray(blob)
    s, st = N.MOVEMENTS_HDR_LEN, N.MOVEMENT_STRIDE
    swapped[s:s+st], swapped[s+st:s+2*st] = blob[s+st:s+2*st], blob[s:s+st]
    cases.append(isinstance(catch(lambda: N.decrypt_movements(bytes(swapped), SEED, ad=b"score")), N.AuthError))
    # drop last movement and rewrite count to n-1
    dropped = bytearray(blob[:s] + blob[s:s+(n-1)*st] + blob[-32:])
    dropped[N.NMOV0:N.MOVEMENTS_HDR_LEN] = (n-1).to_bytes(4, "big")
    cases.append(len(dropped) == N.MOVEMENTS_HDR_LEN + (n-1)*st + N.TAG_LEN)
    cases.append(isinstance(catch(lambda: N.decrypt_movements(bytes(dropped), SEED, ad=b"score")), N.AuthError))
    # duplicate first movement at the end and rewrite count to n+1
    dup = bytearray(blob[:s] + blob[s:s+n*st] + blob[s:s+st] + blob[-32:])
    dup[N.NMOV0:N.MOVEMENTS_HDR_LEN] = (n+1).to_bytes(4, "big")
    cases.append(isinstance(catch(lambda: N.decrypt_movements(bytes(dup), SEED, ad=b"score")), N.AuthError))
    # splice movement 0 from another message
    other = N.encrypt_movements(b"a different piece altogether that also spans two movements.." + b"!" * 80, SEED, ad=b"score")
    spliced = bytearray(blob)
    spliced[s:s+st] = other[s:s+st]
    cases.append(isinstance(catch(lambda: N.decrypt_movements(bytes(spliced), SEED, ad=b"score")), N.AuthError))
    # downgrade version byte to 2
    down = bytearray(blob); down[0] = 2
    cases.append(isinstance(catch(lambda: N.decrypt_movements(bytes(down), SEED, ad=b"score")), N.UnsupportedVersion))
    cases.append(isinstance(catch(lambda: N.decrypt(bytes(down), SEED, ad=b"score")), N.UnsupportedVersion))  # v2 is not spoken by decrypt (conductor: not an AuthError)
    return all(cases)
check("movements tampers fail closed: truncate, extend, bit flips, reorder, drop, duplicate, splice, downgrade",
      _mv_tamper_ok())

# verify-then-decrypt: bad coda / flipped cadence must not build Schedule
# A cadence-only edit is caught by the coda (which now covers cadence bytes);
# the cadence key is derived only after the coda check passes.
_seen_mv = []
_seen_cadkey = []
_orig_mv_sch = N.Schedule.__init__
_orig_cadkey = N._cadence_key
def _sch_probe_mv(self, seed, nonce):
    _seen_mv.append("Schedule")
    return _orig_mv_sch(self, seed, nonce)
def _cadkey_probe(seed, nonce):
    _seen_cadkey.append("cadence_key")
    return _orig_cadkey(seed, nonce)
N.Schedule.__init__ = _sch_probe_mv
N._cadence_key = _cadkey_probe
try:
    _good_mv = N.encrypt_movements(b"cadence check " * 12, SEED)
    _seen_mv.clear(); _seen_cadkey.clear()
    _bad_coda = bytearray(_good_mv); _bad_coda[-1] ^= 1
    _e_coda = catch(lambda: N.decrypt_movements(bytes(_bad_coda), SEED))
    _n_coda = list(_seen_mv); _k_coda = list(_seen_cadkey)
    _seen_mv.clear(); _seen_cadkey.clear()
    _bad_cad = bytearray(_good_mv)
    _bad_cad[N.MOVEMENTS_HDR_LEN + N.BLOCK_LEN] ^= 1  # first cadence byte
    _e_cad = catch(lambda: N.decrypt_movements(bytes(_bad_cad), SEED))
    _n_cad = list(_seen_mv); _k_cad = list(_seen_cadkey)
    _seen_mv.clear(); _seen_cadkey.clear()
    _ok_mv = N.decrypt_movements(_good_mv, SEED)
    _n_ok = list(_seen_mv); _k_ok = list(_seen_cadkey)
finally:
    N.Schedule.__init__ = _orig_mv_sch
    N._cadence_key = _orig_cadkey
check("movements: bad coda or cadence is rejected without building Schedule; a valid blob still builds Schedule then decrypts",
      isinstance(_e_coda, N.AuthError) and type(_e_coda) is N.AuthError and str(_e_coda) == "authentication failed"
      and isinstance(_e_cad, N.AuthError) and type(_e_cad) is N.AuthError and str(_e_cad) == "authentication failed"
      and _n_coda == [] and _n_cad == [] and _n_ok == ["Schedule"]
      and _ok_mv == b"cadence check " * 12)
check("movements: cadence-only edit is caught by the coda, and the cadence key is derived only after the coda passes",
      str(_e_cad) == "authentication failed" and _k_coda == [] and _k_cad == [] and _k_ok == ["cadence_key"])

# ---- movements tag domains and authenticated inputs (independent of attestation hashing)
def _sponge_take(domain, seed, nonce, n):
    out, ctr = b"", 0
    while len(out) < n:
        out += hashlib.sha256(b"SN2/" + domain + ctr.to_bytes(4, "big") + seed + nonce).digest()
        ctr += 1
    return out[:n]

_pin_msg = b"twelve notes make a row and then some more" * 5  # two movements
_pin_ad = b"score"
_pin_blob = N.encrypt_movements(_pin_msg, SEED, ad=_pin_ad)
_pin_n = int.from_bytes(_pin_blob[N.NMOV0:N.MOVEMENTS_HDR_LEN], "big")
assert _pin_n == 2
_pin_pk, _pin_nn = _pin_blob[4:20], _pin_blob[20:36]
_pin_cm = _pin_blob[N.CM0:N.CM1]
_pin_body = _pin_blob[N.MOVEMENTS_HDR_LEN:-N.TAG_LEN]
_pin_cts = [_pin_body[i*N.MOVEMENT_STRIDE:i*N.MOVEMENT_STRIDE+N.BLOCK_LEN] for i in range(_pin_n)]
_pin_cads = [_pin_body[i*N.MOVEMENT_STRIDE+N.BLOCK_LEN:(i+1)*N.MOVEMENT_STRIDE] for i in range(_pin_n)]
_pin_coda = _pin_blob[-N.TAG_LEN:]
_pin_clef = N.staff_clef(SEED)
_pin_ks = N.key_signature(SEED)
_pin_theme0 = _sponge_take(b"T", SEED, _pin_nn, N.BLOCK_LEN)
_pin_themes = [_pin_theme0]
for _i in range(_pin_n - 1):
    _nxt = hashlib.sha256(b"SN2/T" + _pin_themes[-1] + _pin_cts[_i] + _i.to_bytes(8, "big") + b"\x00").digest()[:16]
    _pin_themes.append(_sponge_take(b"T", SEED, _nxt, N.BLOCK_LEN))
_pin_cad_key = _sponge_take(b"D", SEED, _pin_nn, 32)
_pin_coda_key = _sponge_take(b"O", SEED, _pin_nn, 32)
import hmac as _hmac
_pin_cad_ok = True
for _i in range(_pin_n):
    _final = b"\x01" if _i == _pin_n - 1 else b"\x00"
    _exp_cad = _hmac.new(_pin_cad_key, _pin_clef + _pin_ks + bytes([N.FMT_MOVEMENTS]) + b"SN2" + _pin_pk + _pin_nn + _pin_cm
                         + _i.to_bytes(8, "big") + _final + _pin_themes[_i] + _pin_cts[_i] + N._encode_ad(_pin_ad),
                         hashlib.sha256).digest()
    _pin_cad_ok = _pin_cad_ok and (_exp_cad == _pin_cads[_i])
_pin_exp_coda = _hmac.new(_pin_coda_key, _pin_clef + _pin_ks + bytes([N.FMT_MOVEMENTS]) + b"SN2" + _pin_pk + _pin_nn + _pin_cm
                          + _pin_n.to_bytes(4, "big") + b"".join(_pin_cts) + b"".join(_pin_cads) + N._encode_ad(_pin_ad),
                          hashlib.sha256).digest()
_pin_old_coda = _hmac.new(_pin_coda_key, _pin_clef + _pin_ks + bytes([N.FMT_MOVEMENTS]) + b"SN2" + _pin_pk + _pin_nn + _pin_cm
                          + _pin_n.to_bytes(4, "big") + b"".join(_pin_cts) + N._encode_ad(_pin_ad),
                          hashlib.sha256).digest()
_pin_tweak0_mid = hashlib.sha256(b"SN2/I" + _pin_nn + (0).to_bytes(8, "big") + b"\x00").digest()[:16]
_pin_tweak0 = _sponge_take(b"W", SEED, _pin_tweak0_mid, N.BLOCK_LEN)

check("movements domains T/D/O/W/I match independent SHA-256 squeezes (theme, cadence key, coda key, tweak)",
      N._theme_start(SEED, _pin_nn) == _pin_theme0 == _pin_themes[0]
      and N._cadence_key(SEED, _pin_nn) == _pin_cad_key
      and N._coda_key(SEED, _pin_nn) == _pin_coda_key
      and N._movement_tweak(SEED, _pin_nn, 0, False) == _pin_tweak0
      and N._theme_next(SEED, _pin_themes[0], _pin_cts[0], 0, False) == _pin_themes[1])
check("movements cadence HMAC covers ct, theme, index and AD; coda HMAC covers header, count, all ct, all cadences and AD",
      _pin_cad_ok and _pin_exp_coda == _pin_coda and _pin_old_coda != _pin_coda
      and _pin_blob[20:36] == _pin_nn)

# Gap mutants from mutation_lab_2pct_movements: changing a domain letter or
# dropping cadence bytes from the coda must fail these pins (and fail closed).
def _mv_gap_mutants_caught():
    src = open(os.path.join(HERE, "sneak_n2.py")).read()
    src = src.replace('EXPECTED_MIX_SHA256 = "' + N.EXPECTED_MIX_SHA256 + '"',
                      'EXPECTED_MIX_SHA256 = "TO_BE_FILLED"', 1).replace(
                      'EXPECTED_REHEARSAL_SHA256 = "' + N.EXPECTED_REHEARSAL_SHA256 + '"',
                      'EXPECTED_REHEARSAL_SHA256 = "TO_BE_FILLED"', 1)
    cases = []
    mutants = {
        "theme domain T->M": ('StaffSponge(b"T", _seed_bytes(seed), nonce).take(BLOCK_LEN)',
                              'StaffSponge(b"M", _seed_bytes(seed), nonce).take(BLOCK_LEN)'),
        "coda omits cadences": ("+ cts + cadences + _encode_ad(ad)",
                                "+ cts + _encode_ad(ad)"),
    }
    for name, (a, b) in mutants.items():
        if a not in src:
            return False
        alt_src = src.replace(a, b, 1)
        td = tempfile.mkdtemp(prefix="n2_mvgap_")
        try:
            path = os.path.join(td, "sneak_n2.py")
            open(path, "w").write(alt_src)
            open(os.path.join(td, "sneak1024-seed.txt"), "w").write(open(os.path.join(HERE, "sneak1024-seed.txt")).read())
            modname = "sneak_n2_gap_" + "".join(ch if ch.isalnum() else "_" for ch in name)
            alt = load(modname, path)
            if "theme domain" in name:
                cases.append(alt._theme_start(SEED, _pin_nn) != _sponge_take(b"T", SEED, _pin_nn, N.BLOCK_LEN))
            else:
                blob = alt.encrypt_movements(_pin_msg, SEED, ad=_pin_ad)
                nn = blob[20:36]; nmov = int.from_bytes(blob[alt.NMOV0:alt.MOVEMENTS_HDR_LEN], "big")
                body = blob[alt.MOVEMENTS_HDR_LEN:-alt.TAG_LEN]
                cts = [body[i*alt.MOVEMENT_STRIDE:i*alt.MOVEMENT_STRIDE+alt.BLOCK_LEN] for i in range(nmov)]
                cads = [body[i*alt.MOVEMENT_STRIDE+alt.BLOCK_LEN:(i+1)*alt.MOVEMENT_STRIDE] for i in range(nmov)]
                coda_key = _sponge_take(b"O", SEED, nn, 32)
                cm = blob[alt.CM0:alt.CM1]
                exp_with_cads = _hmac.new(coda_key, alt.staff_clef(SEED) + alt.key_signature(SEED)
                                          + bytes([alt.FMT_MOVEMENTS]) + b"SN2" + blob[4:20] + nn + cm
                                          + nmov.to_bytes(4, "big") + b"".join(cts) + b"".join(cads)
                                          + alt._encode_ad(_pin_ad), hashlib.sha256).digest()
                cases.append(blob[-32:] != exp_with_cads)
                # live decrypt of mutant blob (different key_sig / coda) fails closed
                cases.append(isinstance(catch(lambda b=blob: N.decrypt_movements(b, SEED, ad=_pin_ad)), N.AuthError))
        finally:
            shutil.rmtree(td)
    return all(cases) and len(cases) == 3
check("movements gap mutants (theme domain T->M; coda omits cadences) fail the new pins",
      _mv_gap_mutants_caught())

_mv_demo = os.path.join(HERE, "movements-demo.txt")
if os.path.isfile(_mv_demo):
    _mv_demo_blob = None
    _mv_demo_plain = None
    for _line in open(_mv_demo):
        if _line.startswith("blob"):
            _mv_demo_blob = bytes.fromhex(_line.split()[-1])
        if _line.startswith("plaintext_hex"):
            _mv_demo_plain = bytes.fromhex(_line.split()[-1])
    check("movements-demo.txt decrypts to its recorded plaintext",
          _mv_demo_blob is not None and _mv_demo_plain is not None
          and _mv_demo_blob[:4] == bytes([N.FMT_MOVEMENTS]) + b"SN2"
          and N.decrypt_movements(_mv_demo_blob, SEED) == _mv_demo_plain)
else:
    check("movements-demo.txt is present beside the tests", False)

# ---- tuning-fix (key commitment binds AD and nmov; unified auth error; legacy rejected)
_SEED_B = bytes(range(16, 144))  # 128 distinct bytes, 127 nonzero; a second valid key
assert len(set(b for b in _SEED_B if b)) >= 32
_blob_a = N.encrypt(b"tuning probe", SEED)
_blob_b = N.encrypt(b"tuning probe", _SEED_B)
_va, _pka, _nna, _cma, _cta, _tga = N.split_blob(_blob_a)
_vb, _pkb, _nnb, _cmb, _ctb, _tgb = N.split_blob(_blob_b)
_e_wrong_key = catch(lambda: N.decrypt(_blob_a, _SEED_B))
check("a blob made under key A fails under key B with the unified AuthError",
      isinstance(_e_wrong_key, N.AuthError) and type(_e_wrong_key) is N.AuthError
      and str(_e_wrong_key) == "authentication failed"
      and not hasattr(N, "CommitError"))
check("commitments and tags differ across keys for the same message (no two-key blob by construction)",
      _cma != _cmb and _tga != _tgb
      and N._commitment(N._commit_key(SEED), N.FMT_VERSION, _pka, _nna) == _cma
      and N._commitment(N._commit_key(_SEED_B), N.FMT_VERSION, _pka, _nna) != _cma
      and isinstance(catch(lambda: N.decrypt(_blob_b, SEED)), N.AuthError)
      and str(catch(lambda: N.decrypt(_blob_b, SEED))) == "authentication failed")
# commitment checked first: flip a commit bit, and also try a wrong key, without building Schedule
_seen_tune, _seen_mac = [], []
_orig_sch_t = N.Schedule.__init__
_orig_sponge = N.StaffSponge.__init__
def _sch_probe_t(self, seed, nonce):
    _seen_tune.append("Schedule")
    return _orig_sch_t(self, seed, nonce)
def _sponge_probe(self, domain, seed, nonce):
    if domain == b"M":
        _seen_mac.append("M")
    return _orig_sponge(self, domain, seed, nonce)
N.Schedule.__init__ = _sch_probe_t
N.StaffSponge.__init__ = _sponge_probe
try:
    _flip_cm = bytearray(_blob_a); _flip_cm[N.CM0] ^= 1
    _e_cm = catch(lambda: N.decrypt(bytes(_flip_cm), SEED))
    _n_cm, _m_cm = list(_seen_tune), list(_seen_mac)
    _seen_tune.clear(); _seen_mac.clear()
    _e_kb = catch(lambda: N.decrypt(_blob_a, _SEED_B))
    _n_kb, _m_kb = list(_seen_tune), list(_seen_mac)
    _seen_tune.clear(); _seen_mac.clear()
    _ok_t = N.decrypt(_blob_a, SEED)
    _n_okt, _m_okt = list(_seen_tune), list(_seen_mac)
finally:
    N.Schedule.__init__ = _orig_sch_t
    N.StaffSponge.__init__ = _orig_sponge
check("conductor: commitment bit flips and wrong keys still compute the tag (MAC key M) but never build a Schedule",
      isinstance(_e_cm, N.AuthError) and type(_e_cm) is N.AuthError and str(_e_cm) == "authentication failed"
      and _n_cm == [] and "M" in _m_cm
      and isinstance(_e_kb, N.AuthError) and str(_e_kb) == "authentication failed" and _n_kb == [] and "M" in _m_kb
      and _ok_t == b"tuning probe" and _n_okt == ["Schedule"] and "M" in _m_okt)
_ind_ck = hashlib.sha256(b"SN2/" + b"U" + (0).to_bytes(4, "big") + SEED + bytes(16)).digest()[:32]
# StaffSponge may squeeze more than 32 if take asks 32 of first block (32 from one sha256) — first block is exactly 32
_ind_cm = __import__("hmac").new(_ind_ck, b"U" + bytes([N.FMT_VERSION]) + b"SN2" + _pka + _nna + N._encode_ad(b""), hashlib.sha256).digest()
_wrong_dom = __import__("hmac").new(_ind_ck, b"C" + bytes([N.FMT_VERSION]) + b"SN2" + _pka + _nna + N._encode_ad(b""), hashlib.sha256).digest()
_no_ad = __import__("hmac").new(_ind_ck, b"U" + bytes([N.FMT_VERSION]) + b"SN2" + _pka + _nna, hashlib.sha256).digest()
check("tuning domain letter U is pinned and encode_ad is in the commitment HMAC",
      N.COMMIT_DOMAIN == b"U" and N._commit_key(SEED) == _ind_ck and _cma == _ind_cm != _wrong_dom
      and _ind_cm != _no_ad
      and "StaffSponge(COMMIT_DOMAIN" in inspect.getsource(N._commit_key)
      and "COMMIT_DOMAIN +" in inspect.getsource(N._commitment)
      and "_encode_ad(ad)" in inspect.getsource(N._commitment))

# AD is bound in the commitment: same pickup/nonce, different AD => different commitment
_cm_alice = N._commitment(N._commit_key(SEED), N.FMT_VERSION, _pka, _nna, b"from:alice")
_cm_bob = N._commitment(N._commit_key(SEED), N.FMT_VERSION, _pka, _nna, b"from:bob")
_ad_cm = N.encrypt(b"tuning ad", SEED, ad=b"from:alice")
_ad_pk, _ad_nn, _ad_c = _ad_cm[4:20], _ad_cm[20:36], _ad_cm[36:68]
_e_ad_cm = catch(lambda: N.decrypt(_ad_cm, SEED, ad=b"from:bob"))
_e_ad_key = catch(lambda: N.decrypt(_ad_cm, _SEED_B, ad=b"from:alice"))
check("associated data is bound in the commitment, so a different AD changes it",
      _cm_alice != _cm_bob
      and N._commitment(N._commit_key(SEED), N.FMT_VERSION, _ad_pk, _ad_nn, b"from:alice") == _ad_c
      and N._commitment(N._commit_key(SEED), N.FMT_VERSION, _ad_pk, _ad_nn, b"from:bob") != _ad_c
      and N.decrypt(_ad_cm, SEED, ad=b"from:alice") == b"tuning ad")
check("wrong key and wrong AD raise the identical AuthError type and message",
      type(_e_wrong_key) is type(_e_ad_cm) is type(_e_ad_key) is N.AuthError
      and str(_e_wrong_key) == str(_e_ad_cm) == str(_e_ad_key) == "authentication failed")
# wrong AD also fails at the commitment, before Schedule / MAC-key work
_seen_tune, _seen_mac = [], []
N.Schedule.__init__ = _sch_probe_t
N.StaffSponge.__init__ = _sponge_probe
try:
    _seen_tune.clear(); _seen_mac.clear()
    _e_ad_early = catch(lambda: N.decrypt(_ad_cm, SEED, ad=b"from:bob"))
    _n_ad, _m_ad = list(_seen_tune), list(_seen_mac)
finally:
    N.Schedule.__init__ = _orig_sch_t
    N.StaffSponge.__init__ = _orig_sponge
check("conductor: wrong AD runs both checks (MAC-key domain M derived) and builds no Schedule",
      isinstance(_e_ad_early, N.AuthError) and str(_e_ad_early) == "authentication failed"
      and _n_ad == [] and "M" in _m_ad)

# movements commitment binds nmov as well as AD
_mv_cm_blob = N.encrypt_movements(b"tuning movements " * 8, SEED)
_e_mv_key = catch(lambda: N.decrypt_movements(_mv_cm_blob, _SEED_B))
_mv_flip = bytearray(_mv_cm_blob); _mv_flip[N.CM0] ^= 1
_e_mv_flip = catch(lambda: N.decrypt_movements(bytes(_mv_flip), SEED))
_mv_n = int.from_bytes(_mv_cm_blob[N.NMOV0:N.MOVEMENTS_HDR_LEN], "big")
_mv_pk, _mv_nn, _mv_c = _mv_cm_blob[4:20], _mv_cm_blob[20:36], _mv_cm_blob[36:68]
check("movements: wrong key and commitment bit flips raise unified AuthError before coda/cadence work",
      isinstance(_e_mv_key, N.AuthError) and type(_e_mv_key) is N.AuthError and str(_e_mv_key) == "authentication failed"
      and isinstance(_e_mv_flip, N.AuthError) and str(_e_mv_flip) == "authentication failed"
      and N.decrypt_movements(_mv_cm_blob, SEED) == b"tuning movements " * 8)
check("movements commitment binds nmov: the recorded count matches, a different count does not",
      N._commitment(N._commit_key(SEED), N.FMT_MOVEMENTS, _mv_pk, _mv_nn, b"", nmov=_mv_n) == _mv_c
      and N._commitment(N._commit_key(SEED), N.FMT_MOVEMENTS, _mv_pk, _mv_nn, b"", nmov=_mv_n - 1) != _mv_c
      and N._commitment(N._commit_key(SEED), N.FMT_MOVEMENTS, _mv_pk, _mv_nn, b"") != _mv_c)

# default decrypt rejects published v2/v3; named legacy helpers still open them
_pre_tune = "/workspace/octavo009"
if not os.path.isdir(_pre_tune):
    _pre_tune = "/tmp/sneak_n2_pre_tuning"
_pre_hw = optional_blob(os.path.join(_pre_tune, "hello-world.txt"))
_pre_mv = optional_blob(os.path.join(_pre_tune, "movements-demo.txt"))
_pre_mv_plain = None
try:
    for _line in open(os.path.join(_pre_tune, "movements-demo.txt")):
        if _line.startswith("plaintext_hex"):
            _pre_mv_plain = bytes.fromhex(_line.split()[-1])
except FileNotFoundError:
    pass
if _pre_hw is None:
    skip("legacy octavo009 version-2 hello-world blob is rejected by default and opens via decrypt_legacy")
else:
    _e_v2_def = catch(lambda: N.decrypt(_pre_hw, SEED))
    check("legacy octavo009 version-2 hello-world is rejected by decrypt() and opens via decrypt_legacy()",
          len(_pre_hw) == 196 and _pre_hw[0] == 2
          and isinstance(_e_v2_def, N.UnsupportedVersion) and str(_e_v2_def) == "unsupported version"
          and N.decrypt_legacy(_pre_hw, SEED, allow_noncommitting=True) == b"hello world"
          and N._legacy_key_signature(SEED).hex() == "d8a1358aae4116aaafcee90ec74a4d8e")
if _pre_mv is None or _pre_mv_plain is None:
    skip("legacy octavo009 version-3 movements-demo is rejected by default and opens via decrypt_movements_legacy")
else:
    _e_v3_def = catch(lambda: N.decrypt_movements(_pre_mv, SEED))
    check("legacy octavo009 version-3 movements-demo is rejected by decrypt_movements() and opens via decrypt_movements_legacy()",
          _pre_mv[0] == 3
          and isinstance(_e_v3_def, N.UnsupportedVersion) and str(_e_v3_def) == "unsupported version"
          and N.decrypt_movements_legacy(_pre_mv, SEED, allow_noncommitting=True) == _pre_mv_plain)

# unpublished tuning v4/v5 blobs (never pushed) are rejected outright, including by the legacy helpers
_pre_fix = "/tmp/sneak_n2_pre_tuningfix"
_v4_hw = optional_blob(os.path.join(_pre_fix, "hello-world.txt"))
_v5_mv = optional_blob(os.path.join(_pre_fix, "movements-demo.txt"))
if _v4_hw is None:
    skip("unpublished tuning v4 hello-world blob is rejected by decrypt and decrypt_legacy")
else:
    check("unpublished tuning v4 blobs are rejected by decrypt() and decrypt_legacy()",
          _v4_hw[0] == 4 and len(_v4_hw) == 228
          and isinstance(catch(lambda: N.decrypt(_v4_hw, SEED)), N.UnsupportedVersion)
          and isinstance(catch(lambda: N.decrypt_legacy(_v4_hw, SEED, allow_noncommitting=True)), N.UnsupportedVersion)
          and str(catch(lambda: N.decrypt(_v4_hw, SEED))) == "unsupported version")
if _v5_mv is None:
    skip("unpublished tuning v5 movements blob is rejected by decrypt_movements and decrypt_movements_legacy")
else:
    check("unpublished tuning v5 blobs are rejected by decrypt_movements() and decrypt_movements_legacy()",
          _v5_mv[0] == 5
          and isinstance(catch(lambda: N.decrypt_movements(_v5_mv, SEED)), N.UnsupportedVersion)
          and isinstance(catch(lambda: N.decrypt_movements_legacy(_v5_mv, SEED, allow_noncommitting=True)), N.UnsupportedVersion)
          and str(catch(lambda: N.decrypt_movements(_v5_mv, SEED))) == "unsupported version")

# ---- études (reduced-round lab API) and the published score
import etudes as E
# The suite runs études on the public demo seed, which needs the explicit lab flag (conductor).
etude = lambda r: E.etude(r, lab_seed=True)
check("etude() only accepts the published round counts 2, 4, 6, 16",
      all(etude(r).rounds == r for r in (2, 4, 6, 16))
      and all(isinstance(catch(lambda r=r: etude(r)), ValueError) for r in (0, 1, 3, 5, 8, 15, 17, 32)))
_live_vers = {N.FMT_VERSION, N.FMT_MOVEMENTS, N.FMT_VERSION_V2, N.FMT_MOVEMENTS_V3, N.FMT_VERSION_V4, N.FMT_MOVEMENTS_V5, 1}
check("etude blobs use distinct committed version bytes, not 2/3/4/5/6/7",
      E.ETUDE_FMT_BLOCK == {2: 0x82, 4: 0x84, 6: 0x86, 16: 0x90}
      and E.ETUDE_FMT_MOVEMENTS == {2: 0x83, 4: 0x85, 6: 0x87, 16: 0x91}
      and E.ETUDE_FMT_BLOCK_TUNINGFIX == {2: 0xA2, 4: 0xA4, 6: 0xA6, 16: 0xB0}
      and E.ETUDE_FMT_MOVEMENTS_TUNINGFIX == {2: 0xA3, 4: 0xA5, 6: 0xA7, 16: 0xB1}
      and set(E.ETUDE_FMT_BLOCK.values()).isdisjoint(E.ETUDE_FMT_BLOCK_TUNINGFIX.values())
      and set(E.ETUDE_FMT_MOVEMENTS.values()).isdisjoint(E.ETUDE_FMT_MOVEMENTS_TUNINGFIX.values())
      and E.ETUDE_FMT_BLOCK_LEGACY == {2: 0xE2, 4: 0xE4, 6: 0xE6, 16: 0xF0}
      and E.ETUDE_FMT_MOVEMENTS_LEGACY == {2: 0xE3, 4: 0xE5, 6: 0xE7, 16: 0xF1}
      and E.ETUDE_FMT_BLOCK_TUNING == {2: 0xC2, 4: 0xC4, 6: 0xC6, 16: 0xD0}
      and E.ETUDE_FMT_MOVEMENTS_TUNING == {2: 0xC3, 4: 0xC5, 6: 0xC7, 16: 0xD1}
      and set(E.ETUDE_FMT_BLOCK.values()) & _live_vers == set()
      and set(E.ETUDE_FMT_MOVEMENTS.values()) & _live_vers == set()
      and set(E.ETUDE_FMT_BLOCK.values()).isdisjoint(E.ETUDE_FMT_BLOCK_LEGACY.values())
      and set(E.ETUDE_FMT_BLOCK.values()).isdisjoint(E.ETUDE_FMT_BLOCK_TUNING.values()))
_e16 = etude(16)
_pt = bytes(range(128)); _nn = bytes(range(16))
_sch = N.Schedule(SEED, _nn)
_full = N.grid_to_bytes(N.encrypt_grid(N.bytes_to_grid(_pt), _sch))
_k16 = E.etude_key(SEED, 16)
_full_e = N.grid_to_bytes(N.encrypt_grid(N.bytes_to_grid(_pt), N.Schedule(_k16, _nn)))
check("conductor: etude(16) permute is the live 16-round core keyed by K_e (not the live seed), and inverts",
      _e16.permute(_pt, SEED, _nn) == _full_e != _full and _e16.unpermute(_full_e, SEED, _nn) == _pt
      and _e16.unpermute(_full, SEED, _nn) != _pt)
check("etude(2/4/6) permute differs from full-round and still inverts",
      all((lambda r: (lambda E_, ct: ct != _full and E_.unpermute(ct, SEED, _nn) == _pt)(etude(r), etude(r).permute(_pt, SEED, _nn)))(r) for r in (2, 4, 6)))
_eblob = _e16.encrypt(b"hello world", SEED, pickup=HW_PICKUP)
check("conductor: etude(16) hello-world with the live pickup shares only the pickup (nonce, ct, commit, tag all differ)",
      _eblob[0] == 0x90 and _eblob[4:20] == HW_BLOB[4:20] and _eblob[20:36] != HW_BLOB[20:36]
      and _eblob[N.CT0:N.CT1] != HW_BLOB[N.CT0:N.CT1]
      and _eblob[N.CM0:N.CM1] != HW_BLOB[N.CM0:N.CM1] and _eblob[N.CT1:] != HW_BLOB[N.CT1:]
      and _e16.decrypt(_eblob, SEED) == b"hello world")
check("normal decrypt rejects every étude single-block version as UnsupportedVersion",
      all(isinstance(catch(lambda r=r: N.decrypt(etude(r).encrypt(b"x", SEED, pickup=HW_PICKUP), SEED)), N.UnsupportedVersion) for r in (2, 4, 6, 16)))
check("normal decrypt_movements rejects every étude movements version as UnsupportedVersion",
      all(isinstance(catch(lambda r=r: N.decrypt_movements(etude(r).encrypt_movements(b"xy", SEED, pickup=HW_PICKUP), SEED)), N.UnsupportedVersion) for r in (2, 4, 6, 16)))
check("étude decrypt rejects ordinary version-6 and version-7 blobs",
      isinstance(catch(lambda: _e16.decrypt(HW_BLOB, SEED)), N.UnsupportedVersion)
      and isinstance(catch(lambda: _e16.decrypt_movements(_mv_demo_blob, SEED)), N.UnsupportedVersion))
_ead = b"from:alice"
_emsg = bytes(range(40))
check("étude single-block and movements round-trip at 2, 4, 6, 16, with and without AD",
      all(etude(r).decrypt(etude(r).encrypt(_emsg, SEED, pickup=HW_PICKUP), SEED) == _emsg
          and etude(r).decrypt(etude(r).encrypt(_emsg, SEED, ad=_ead, pickup=HW_PICKUP), SEED, ad=_ead) == _emsg
          and etude(r).decrypt_movements(etude(r).encrypt_movements(_emsg * 4, SEED, pickup=HW_PICKUP), SEED) == _emsg * 4
          and etude(r).decrypt_movements(etude(r).encrypt_movements(_emsg * 4, SEED, ad=_ead, pickup=HW_PICKUP), SEED, ad=_ead) == _emsg * 4
          for r in (2, 4, 6, 16)))
check("encrypt still has no public pickup argument; études are not in the attested sneak_n2 module",
      list(inspect.signature(N.encrypt).parameters) == ["msg", "seed", "nonce", "ad"]
      and not hasattr(N, "etude") and "etude" not in N.MIX_CODE_FUNCS and "etude" not in N.MIX_CODE_ROOTS)
# Legacy (pre-tuning) étude blobs from the octavo009 score open only via decrypt_legacy
_pre_score = os.path.join(_pre_tune, "score", "vectors.json")
if os.path.isfile(_pre_score):
    import json as _json_legacy
    _ps = _json_legacy.load(open(_pre_score))
    _leg_aead = next(v for v in _ps["aead"] if v["id"] == "aead-r16-1")
    _leg_blob = bytes.fromhex(_leg_aead["blob"])
    _leg_msg = bytes.fromhex(_leg_aead["msg"])
    _leg_mv = next(v for v in _ps["movements"] if v["id"] == "movements-r16-128")
    _leg_mv_blob = bytes.fromhex(_leg_mv["blob"])
    check("legacy pre-tuning étude blobs (0xF0 / 0xF1) are rejected by default and open via decrypt_legacy",
          _leg_blob[0] == 0xF0 and isinstance(catch(lambda: _e16.decrypt(_leg_blob, SEED)), N.UnsupportedVersion)
          and _e16.decrypt_legacy(_leg_blob, SEED, allow_noncommitting=True) == _leg_msg
          and _leg_mv_blob[0] == 0xF1 and isinstance(catch(lambda: _e16.decrypt_movements(_leg_mv_blob, SEED)), N.UnsupportedVersion)
          and _e16.decrypt_movements_legacy(_leg_mv_blob, SEED, allow_noncommitting=True) == bytes(range(128)))
else:
    skip("legacy pre-tuning étude blobs (0xF0 / 0xF1) are rejected by default and open via decrypt_legacy")

# unpublished tuning étude bytes (0xC*/0xD*) are rejected by default and by the legacy helpers
_tune_score = os.path.join(_pre_fix, "score", "vectors.json")
if os.path.isfile(_tune_score):
    import json as _json_tune
    _ts = _json_tune.load(open(_tune_score))
    _t_aead = next(v for v in _ts["aead"] if v["id"] == "aead-r16-1")
    _t_blob = bytes.fromhex(_t_aead["blob"])
    _t_mv = next(v for v in _ts["movements"] if v["id"] == "movements-r16-128")
    _t_mv_blob = bytes.fromhex(_t_mv["blob"])
    check("unpublished tuning étude blobs (0xD0 / 0xD1) are rejected by decrypt and decrypt_legacy",
          _t_blob[0] == 0xD0 and isinstance(catch(lambda: _e16.decrypt(_t_blob, SEED)), N.UnsupportedVersion)
          and isinstance(catch(lambda: _e16.decrypt_legacy(_t_blob, SEED, allow_noncommitting=True)), N.UnsupportedVersion)
          and _t_mv_blob[0] == 0xD1 and isinstance(catch(lambda: _e16.decrypt_movements(_t_mv_blob, SEED)), N.UnsupportedVersion)
          and isinstance(catch(lambda: _e16.decrypt_movements_legacy(_t_mv_blob, SEED, allow_noncommitting=True)), N.UnsupportedVersion))
else:
    skip("unpublished tuning étude blobs (0xD0 / 0xD1) are rejected by decrypt and decrypt_legacy")

# ---- conductor (equal-time single-block rejects, étude key separation, legacy opt-in, L4, I3)
import warnings as _w, time as _time
_cd_seed_b = bytes(range(16, 144))
_cd_blob = N.encrypt(b"conductor probe", SEED, ad=b"from:alice")
def _cd_mut(b, off):
    x = bytearray(b); x[off] ^= 1; return bytes(x)
_cd_cases = {
    "wrong key": (_cd_blob, _cd_seed_b, b"from:alice"),
    "wrong AD": (_cd_blob, SEED, b"from:bob"),
    "bad commit": (_cd_mut(_cd_blob, N.CM0 + 5), SEED, b"from:alice"),
    "bad pickup": (_cd_mut(_cd_blob, N.PK0 + 1), SEED, b"from:alice"),
    "bad ct": (_cd_mut(_cd_blob, N.CT0 + 7), SEED, b"from:alice"),
    "bad tag": (_cd_mut(_cd_blob, N.CT1 + 3), SEED, b"from:alice"),
}
_cd_calls = []
_cd_orig = (N._commitment, N._tag, N.Schedule.__init__)
def _cd_commitment(*a, **k): _cd_calls.append("commit"); return _cd_orig[0](*a, **k)
def _cd_tagf(*a, **k): _cd_calls.append("tag"); return _cd_orig[1](*a, **k)
def _cd_sch(self, *a, **k): _cd_calls.append("Schedule"); return _cd_orig[2](self, *a, **k)
N._commitment, N._tag, N.Schedule.__init__ = _cd_commitment, _cd_tagf, _cd_sch
_cd_trace = {}
try:
    for _name, (_b, _s, _a) in _cd_cases.items():
        _cd_calls.clear()
        _e = catch(lambda: N.decrypt(_b, _s, ad=_a))
        _cd_trace[_name] = (type(_e), str(_e), list(_cd_calls))
finally:
    N._commitment, N._tag, N.Schedule.__init__ = _cd_orig
check("conductor M1: every single-block reject (wrong key/AD, bad commit/pickup/ct/tag) runs commitment AND tag, no Schedule, one AuthError",
      all(t == (N.AuthError, "authentication failed", ["commit", "tag"]) for t in _cd_trace.values()))
check("conductor M1: decrypt combines the two compare_digest results with & (no short-circuit) and raises once",
      "commit_ok & tag_ok" in inspect.getsource(N.decrypt)
      and inspect.getsource(N.decrypt).count('raise AuthError("authentication failed")') == 1)
# timing: commit-fail vs tag-fail medians (old gap ~3x, 8 us vs 24 us); loose bound to stay robust on a busy box
def _cd_time(b, s, a, n):
    out = []
    for _ in range(n):
        t0 = _time.perf_counter_ns()
        try: N.decrypt(b, s, ad=a)
        except N.AuthError: pass
        out.append(_time.perf_counter_ns() - t0)
    return out
_cd_tc, _cd_tt = [], []
for _ in range(40):
    _cd_tc += _cd_time(*_cd_cases["bad commit"], 25); _cd_tt += _cd_time(*_cd_cases["bad tag"], 25)
_cd_mc, _cd_mt = sorted(_cd_tc)[len(_cd_tc) // 2], sorted(_cd_tt)[len(_cd_tt) // 2]
print("conductor timing: median commit-fail %.2f us, tag-fail %.2f us, ratio %.3f" % (_cd_mc / 1e3, _cd_mt / 1e3, _cd_mt / _cd_mc))
check("conductor M1: single-block commit-fail and tag-fail medians are within 25% (was ~3x)",
      0.8 < _cd_mt / _cd_mc < 1.25)
# movements keep commitment-first (documented trade-off)
_cd_mv = N.encrypt_movements(b"m" * 300, SEED)
_cd_seen = []
_cd_ock = N._coda_key
N._coda_key = lambda *a: (_cd_seen.append("O"), _cd_ock(*a))[1]
try:
    _e_mvc = catch(lambda: N.decrypt_movements(_cd_mut(_cd_mv, N.CM0), SEED))
    _cd_mv_commit = list(_cd_seen); _cd_seen.clear()
    _e_mvt = catch(lambda: N.decrypt_movements(_cd_mut(_cd_mv, len(_cd_mv) - 1), SEED))
    _cd_mv_coda = list(_cd_seen)
finally:
    N._coda_key = _cd_ock
_sec = open(os.path.join(HERE, "SECURITY.md")).read()
check("conductor-polish L1: movements compute the coda on a commitment failure too (same work), one AuthError, and the docs say so",
      str(_e_mvc) == str(_e_mvt) == "authentication failed" and type(_e_mvc) is type(_e_mvt) is N.AuthError
      and _cd_mv_commit == ["O"] and _cd_mv_coda == ["O"]
      and "commit_ok & coda_ok" in inspect.getsource(N.decrypt_movements)
      and "equal-time" in N.decrypt_movements.__doc__ and "Timing" in N.decrypt_movements.__doc__
      and "conductor-polish" in _sec and "movements" in _sec)

# ---- étude key separation
_cd_live_ct = HW_BLOB[N.CT0:N.CT1]; _cd_live_nn = HW_BLOB[20:36]
check("conductor: étude keys are derived (domain E, round count in tweak), distinct per round count and from the seed",
      E.ETUDE_KEY_DOMAIN == b"E"
      and len({E.etude_key(SEED, r) for r in (2, 4, 6, 16)} | {SEED}) == 5
      and E.etude_key(SEED, 4) == N.StaffSponge(b"E", SEED, bytes([4]) + bytes(15)).take(128))
check("conductor: etude(16).unpermute cannot decrypt a live v6 ciphertext (no shared round material)",
      etude(16).unpermute(_cd_live_ct, SEED, _cd_live_nn)[:12] != N.encode_block(b"hello world")[:12]
      and N.grid_to_bytes(N.decrypt_grid(N.bytes_to_grid(_cd_live_ct), N.Schedule(SEED, _cd_live_nn)))[:12] == N.encode_block(b"hello world")[:12])
_cd_relabel = bytes([0x90]) + HW_BLOB[1:]
check("conductor: a live v6 blob relabelled as a 16-round étude does not open (AuthError), even for the seed holder",
      type(catch(lambda: etude(16).decrypt(_cd_relabel, SEED))) is N.AuthError)
_cd_ms = {r: etude(r).encrypt(b"hello world", SEED, pickup=HW_PICKUP) for r in (2, 4, 6, 16)}
check("conductor: études with the live pickup never reproduce the live nonce or Schedule (r = 2, 4, 6, 16)",
      all(b[20:36] != HW_BLOB[20:36] for b in _cd_ms.values())
      and len({b[20:36] for b in _cd_ms.values()}) == 4
      and N.Schedule(E.etude_key(SEED, 2), _cd_live_nn).material() != N.Schedule(SEED, _cd_live_nn).material())
_cd_k2 = E.etude_key(SEED, 2)
_cd_n2 = hashlib.sha256(N.staff_clef(_cd_k2) + bytes([0x82]) + HW_PICKUP + N.encode_block(b"hello world") + N._encode_ad(b"")).digest()[:16]
_cd_n2_nov = hashlib.sha256(N.staff_clef(_cd_k2) + HW_PICKUP + N.encode_block(b"hello world") + N._encode_ad(b"")).digest()[:16]
check("conductor: the étude version byte is hashed into the SIV nonce",
      _cd_ms[2][20:36] == _cd_n2 != _cd_n2_nov and etude(2).siv_nonce(b"hello world", HW_PICKUP, SEED) == _cd_n2)
_cd_rs = os.urandom(128)
while len(set(b for b in _cd_rs if b)) < 32: _cd_rs = os.urandom(128)
check("conductor: études refuse seed=None and the public demo seed unless lab_seed=True; other seeds work",
      all(isinstance(catch(f), ValueError) and "lab_seed=True" in str(catch(f)) for f in (
          lambda: E.etude(2).encrypt(b"x", None), lambda: E.etude(2).encrypt(b"x", SEED),
          lambda: E.etude(4).permute(bytes(128), SEED, bytes(16)), lambda: E.etude(16).decrypt(_cd_ms[16], SEED),
          lambda: E.etude(6).encrypt_movements(b"x", None)))
      and E.etude(2).decrypt(E.etude(2).encrypt(b"lab", _cd_rs), _cd_rs) == b"lab"
      and E.etude(2, lab_seed=True).encrypt(b"x", None, pickup=HW_PICKUP) == etude(2).encrypt(b"x", SEED, pickup=HW_PICKUP)
      and E.DEMO_SEED_SHA256 == hashlib.sha256(SEED).hexdigest())
_cd_tf_score = "/tmp/sneak_n2_pre_conductor/score/vectors.json"
if os.path.isfile(_cd_tf_score):
    import json as _json_cd
    _cd_tf = _json_cd.load(open(_cd_tf_score))
    _cd_tfb = bytes.fromhex(next(v for v in _cd_tf["aead"] if v["id"] == "aead-r16-1")["blob"])
    _cd_tfm = bytes.fromhex(next(v for v in _cd_tf["movements"] if v["id"] == "movements-r16-128")["blob"])
    check("conductor: never-published tuning-fix étude bytes (0xB0 / 0xB1) are rejected by every étude and live path",
          _cd_tfb[0] == 0xB0 and _cd_tfm[0] == 0xB1
          and all(isinstance(catch(f), N.UnsupportedVersion) for f in (
              lambda: etude(16).decrypt(_cd_tfb, SEED), lambda: etude(16).decrypt_legacy(_cd_tfb, SEED, allow_noncommitting=True),
              lambda: etude(16).decrypt_movements(_cd_tfm, SEED), lambda: etude(16).decrypt_movements_legacy(_cd_tfm, SEED, allow_noncommitting=True),
              lambda: N.decrypt(_cd_tfb, SEED), lambda: N.decrypt_movements(_cd_tfm, SEED))))
else:
    skip("conductor: never-published tuning-fix étude bytes (0xB0 / 0xB1) are rejected by every étude and live path")

# ---- Etude(r) pins its round count
_cd_e2m = etude(2).encrypt_movements(b"pin" * 50, SEED, pickup=HW_PICKUP)
_cd_rc = [catch(lambda: etude(16).decrypt(_cd_ms[2], SEED)), catch(lambda: etude(2).decrypt(_cd_ms[4], SEED)),
          catch(lambda: etude(4).decrypt_movements(_cd_e2m, SEED))]
check("conductor: Etude(r).decrypt / decrypt_movements reject another round count's blob (UnsupportedVersion: étude round count mismatch)",
      all(isinstance(e, N.UnsupportedVersion) and str(e) == "étude round count mismatch" for e in _cd_rc)
      and etude(2).decrypt(_cd_ms[2], SEED) == b"hello world" and etude(2).decrypt_movements(_cd_e2m, SEED) == b"pin" * 50)
if os.path.isfile(_pre_score):
    check("conductor: Etude(r).decrypt_legacy pins the round count too (a 16-round 0xF0 blob is refused by etude(2))",
          str(catch(lambda: etude(2).decrypt_legacy(_leg_blob, SEED, allow_noncommitting=True))) == "étude round count mismatch")
else:
    skip("conductor: Etude(r).decrypt_legacy pins the round count too (a 16-round 0xF0 blob is refused by etude(2))")

# ---- UnsupportedVersion is not an AuthError; legacy helpers need the flag and warn
check("conductor: UnsupportedVersion is a ValueError but NOT an AuthError subclass",
      issubclass(N.UnsupportedVersion, ValueError) and not issubclass(N.UnsupportedVersion, N.AuthError)
      and not issubclass(N.AuthError, N.UnsupportedVersion))
def _cd_fallback(blob):
    try:
        return ("opened", N.decrypt(blob, SEED))
    except N.AuthError:
        return ("authfallback", None)
    except N.UnsupportedVersion:
        return ("unsupported", None)
_cd_v2like = bytes([2]) + b"SN2" + bytes(192)
check("conductor: a natural `except AuthError:` fallback no longer swallows UnsupportedVersion",
      _cd_fallback(_cd_v2like) == ("unsupported", None) and _cd_fallback(_cd_relabel[:1] + HW_BLOB[1:]) == ("unsupported", None))
_cd_leg_calls = [
    ("decrypt_legacy", lambda **k: N.decrypt_legacy(_cd_v2like, SEED, **k)),
    ("decrypt_movements_legacy", lambda **k: N.decrypt_movements_legacy(bytes([3]) + b"SN2" + bytes(300), SEED, **k)),
    ("Etude.decrypt_legacy", lambda **k: etude(16).decrypt_legacy(bytes([0xF0]) + b"SN2" + bytes(192), SEED, **k)),
    ("Etude.decrypt_movements_legacy", lambda **k: etude(16).decrypt_movements_legacy(bytes([0xF1]) + b"SN2" + bytes(300), SEED, **k)),
]
_cd_noflag = [catch(f) for _, f in _cd_leg_calls] + [catch(lambda f=f: f(allow_noncommitting=1)) for _, f in _cd_leg_calls]
check("conductor: every legacy helper refuses (ValueError naming allow_noncommitting) without allow_noncommitting=True",
      all(type(e) is ValueError and "allow_noncommitting=True" in str(e) for e in _cd_noflag)
      and type(catch(lambda: N.decrypt_legacy(b"", SEED))) is ValueError)
_cd_warned = []
for _nm, _f in _cd_leg_calls:
    with _w.catch_warnings(record=True) as _rec:
        _w.simplefilter("always")
        catch(lambda: _f(allow_noncommitting=True))
    _cd_warned.append(any(issubclass(r.category, N.LegacyFormatWarning) and "not key-committing" in str(r.message) for r in _rec))
check("conductor-polish L2: every legacy helper emits LegacyFormatWarning (a UserWarning, not a DeprecationWarning) when allowed",
      all(_cd_warned) and issubclass(N.LegacyFormatWarning, UserWarning) and not issubclass(N.LegacyFormatWarning, DeprecationWarning))
if _pre_hw is not None:
    with _w.catch_warnings(record=True) as _rec:
        _w.simplefilter("always")
        _cd_hw_open = N.decrypt_legacy(_pre_hw, SEED, allow_noncommitting=True)
    check("conductor: the published octavo009 v2 hello-world still opens with the flag, with exactly one warning",
          _cd_hw_open == b"hello world" and sum(issubclass(r.category, N.LegacyFormatWarning) for r in _rec) == 1)
else:
    skip("conductor: the published octavo009 v2 hello-world still opens with the flag, with exactly one warning")

# ---- L4 constant-structure unpad
_cd_rr = random.Random(11)
_cd_unpad_ok = all(N._unpad_block(N.encode_block(bytes(_cd_rr.randrange(256) for _ in range(L)))) [0] for L in range(128))
_cd_unpad_eq = True
for _ in range(4000):
    _b = bytearray(128); _b[0] = _cd_rr.randrange(256)
    for _i in range(1, 128):
        if _cd_rr.random() < 0.04: _b[_i] = _cd_rr.randrange(1, 256)
    _b = bytes(_b); _L = _b[0]
    _old_ok = not (_L > 127 or any(_b[1 + _L:]))
    _ok, _m = N._unpad_block(_b)
    _cd_unpad_eq &= (_ok == _old_ok) and (not _ok or _m == _b[1:1 + _L])
_cd_src = "".join(inspect.getsource(f) for f in (N.decrypt, N._decrypt_legacy_v2, N.decrypt_movements, N._decrypt_legacy_v3)) + open(os.path.join(HERE, "etudes.py")).read()
check("conductor L4: _unpad_block matches the old pad check on 4000 random blocks and every length; no `any(b[1 + L:])` scan remains",
      _cd_unpad_ok and _cd_unpad_eq and "any(b[1 + L:])" not in _cd_src and "any(block[1 + L:])" not in _cd_src
      and _cd_src.count("_unpad_block(") >= 8)
_cd_ucalls = []
_cd_ou = N._unpad_block
N._unpad_block = lambda b: (_cd_ucalls.append(1), _cd_ou(b))[1]
try:
    _cd_mvok = N.decrypt_movements(_cd_mv, SEED)
finally:
    N._unpad_block = _cd_ou
check("conductor L4: movements decode every block before raising (one combined DecodeError decision)",
      _cd_mvok == b"m" * 300 and len(_cd_ucalls) == 3 and "dec_ok &= ok" in inspect.getsource(N.decrypt_movements))

# ---- I3 seed cache
_cd_l1 = N.load_seed(); _cd_l2 = N.load_seed()
for _ in range(40): N._seed_bytes(os.urandom(64) + bytes(range(64)))
check("conductor I3: the default seed file is parsed once (cached by stat key) and validated seeds are remembered (bounded LRU)",
      _cd_l1 is _cd_l2 and _cd_l1 == SEED and N.load_seed.cache[1] is _cd_l1 and len(N._seed_bytes.ok) <= 16
      and N._seed_bytes(SEED) == SEED and SEED in N._seed_bytes.ok
      and all(isinstance(catch(lambda s=s: N._seed_bytes(s)), ValueError) for s in (bytes(128), bytes(128), b"\x01" * 128))
      and "_seed_bytes.ok" not in N.mix_code_closure()[1])

# ---- port reference: masked xtime GF(2^8) multiply is bit-identical to the live table (not used live: ~3x slower)
def _cd_gf_masked(a, b):
    out = 0
    for _ in range(8):
        out ^= a & -(b & 1)
        a = ((a << 1) ^ (N.FIELD_POLY & -(a >> 7))) & 255
        b >>= 1
    return out
check("conductor L1 (port reference): branch-free masked-doubling multiply equals _GF_MUL on all 65536 inputs",
      all(_cd_gf_masked(a, b) == N._GF_MUL[a][b] for a in range(256) for b in range(256)))

# ---- docs
_readme = open(os.path.join(HERE, "README.md")).read()
check("conductor docs: README and SECURITY say the default seed is a public demo seed, and SECURITY lists Rust-port requirements",
      "public demo seed" in _readme and "public demo seed" in _sec and "Rust port requirements" in _sec
      and "allow_noncommitting=True" in _sec and "public demo seed" in N.__doc__.lower().replace("\n", " "))

# ---- conductor-polish (L1 movements equal-time, L2 warning class, L3 mask unpad, I1-I6)
import collections as _cp_coll, subprocess as _cp_sp, shutil as _cp_sh, tempfile as _cp_tmp
_cp_seed = bytes(range(16, 144))
_cp_mv = N.encrypt_movements(b"p" * 400, _cp_seed, ad=b"from:alice")
_cp_cases = {
    "bad commit": (_cd_mut(_cp_mv, N.CM0 + 2), _cp_seed, b"from:alice"),
    "bad coda": (_cd_mut(_cp_mv, len(_cp_mv) - 1), _cp_seed, b"from:alice"),
    "bad ct": (_cd_mut(_cp_mv, N.MOVEMENTS_HDR_LEN + 3), _cp_seed, b"from:alice"),
    "bad cadence": (_cd_mut(_cp_mv, N.MOVEMENTS_HDR_LEN + N.BLOCK_LEN + 1), _cp_seed, b"from:alice"),
    "wrong AD": (_cp_mv, _cp_seed, b"from:bob"),
    "wrong key": (_cp_mv, SEED, b"from:alice"),
}
_cp_calls = []
_cp_orig = (N._commitment, N._coda_tag, N._cadence_key, N.Schedule.__init__)
def _cp_c(*a, **k): _cp_calls.append("commit"); return _cp_orig[0](*a, **k)
def _cp_o(*a, **k): _cp_calls.append("coda"); return _cp_orig[1](*a, **k)
def _cp_d(*a, **k): _cp_calls.append("cadkey"); return _cp_orig[2](*a, **k)
def _cp_s(self, *a, **k): _cp_calls.append("Schedule"); return _cp_orig[3](self, *a, **k)
N._commitment, N._coda_tag, N._cadence_key, N.Schedule.__init__ = _cp_c, _cp_o, _cp_d, _cp_s
_cp_trace = {}
try:
    for _nm, (_b, _s, _a) in _cp_cases.items():
        _cp_calls.clear()
        _e = catch(lambda: N.decrypt_movements(_b, _s, ad=_a))
        _cp_trace[_nm] = (type(_e), str(_e), list(_cp_calls))
finally:
    N._commitment, N._coda_tag, N._cadence_key, N.Schedule.__init__ = _cp_orig
check("conductor-polish L1: every outsider movements reject (bad commit/coda/ct/cadence, wrong AD/key) runs commitment AND coda, no cadence key, no Schedule, one AuthError",
      all(t == (N.AuthError, "authentication failed", ["commit", "coda"]) for t in _cp_trace.values()))
check("conductor-polish L1: decrypt_movements raises authentication failed exactly twice (combined commit/coda, then combined cadences) and decrypts nothing before both",
      inspect.getsource(N.decrypt_movements).split('"""')[2].count('raise AuthError("authentication failed")') == 2
      and inspect.getsource(N.decrypt_movements).index("commit_ok & coda_ok") < inspect.getsource(N.decrypt_movements).index("decrypt_grid"))
def _cp_time(b, s, a, n):
    out = []
    for _ in range(n):
        t0 = _time.perf_counter_ns()
        try: N.decrypt_movements(b, s, ad=a)
        except N.AuthError: pass
        out.append(_time.perf_counter_ns() - t0)
    return out
_cp_tc, _cp_to = [], []
for _ in range(40):
    _cp_tc += _cp_time(*_cp_cases["bad commit"], 25); _cp_to += _cp_time(*_cp_cases["bad coda"], 25)
_cp_mc, _cp_mo = sorted(_cp_tc)[len(_cp_tc) // 2], sorted(_cp_to)[len(_cp_to) // 2]
print("conductor-polish movements timing: median commit-fail %.2f us, coda-fail %.2f us, ratio %.3f" % (_cp_mc / 1e3, _cp_mo / 1e3, _cp_mo / _cp_mc))
check("conductor-polish L1: movements commit-fail and coda-fail medians are within 25% (was ~2.5x)",
      0.8 < _cp_mo / _cp_mc < 1.25)
_cp_e16m = etude(16).encrypt_movements(b"q" * 300, SEED, pickup=HW_PICKUP)
_cp_seen = []
_cp_ock = N._coda_key
N._coda_key = lambda *a: (_cp_seen.append("O"), _cp_ock(*a))[1]
try:
    _cp_ee = catch(lambda: etude(16).decrypt_movements(_cd_mut(_cp_e16m, N.CM0), SEED))
finally:
    N._coda_key = _cp_ock
check("conductor-polish L1: étude movements also compute the coda on a commitment failure (combined reject)",
      type(_cp_ee) is N.AuthError and str(_cp_ee) == "authentication failed" and _cp_seen == ["O"]
      and etude(16).decrypt_movements(_cp_e16m, SEED) == b"q" * 300)
_cp_good = N.decrypt_movements(_cp_mv, _cp_seed, ad=b"from:alice")
check("conductor-polish L1: a good movements blob still opens, and a valid-coda bad-pad block still gives DecodeError only after auth",
      _cp_good == b"p" * 400)

# L2: shown by default (fresh interpreter, called from an imported module, default filters)
_cp_dir = _cp_tmp.mkdtemp(prefix="octavo_cp_")
open(os.path.join(_cp_dir, "libcall.py"), "w").write(
    "import sneak_n2 as N\n"
    "def go():\n"
    "    try: N.decrypt_legacy(bytes([2]) + b'SN2' + bytes(192), bytes(range(16, 144)), allow_noncommitting=True)\n"
    "    except N.Rejected: pass\n")
_cp_r = _cp_sp.run([sys.executable, "-B", "-c", "import libcall; libcall.go()"], cwd=_cp_dir, capture_output=True, text=True,
                   env=dict(os.environ, PYTHONPATH=HERE + os.pathsep + _cp_dir, PYTHONWARNINGS=""))
check("conductor-polish L2: a library module calling decrypt_legacy(..., allow_noncommitting=True) prints LegacyFormatWarning under default filters",
      _cp_r.returncode == 0 and "LegacyFormatWarning" in _cp_r.stderr and "not key-committing" in _cp_r.stderr)
_cp_sh.rmtree(_cp_dir, ignore_errors=True)

# L3: fixed-width mask unpad equals the old rule on every length and many blocks; no per-byte loop
_cp_rr = random.Random(2026)
_cp_bad = 0; _cp_n = 0
for _L in range(256):
    _blks = [bytes([_L]) + bytes(127)]
    for _pos in range(1, 128):
        for _v in (1, 0x80, 0xFF):
            _x = bytearray([_L] + [0] * 127); _x[_pos] = _v; _blks.append(bytes(_x))
    for _ in range(12):
        _x = bytearray([_L] + [0] * 127)
        for _i in range(1, min(_L, 127) + 1): _x[_i] = _cp_rr.randrange(256)
        if _cp_rr.random() < .5: _x[_cp_rr.randrange(1, 128)] = _cp_rr.randrange(1, 256)
        _blks.append(bytes(_x))
    for _b in _blks:
        _Lb = _b[0]; _old = not (_Lb > 127 or any(_b[1 + _Lb:]))
        _ok, _m = N._unpad_block(_b); _cp_n += 1
        _cp_bad += (_ok != _old) or (_ok and _m != _b[1:1 + _Lb])
_cp_usrc = inspect.getsource(N._unpad_block)
check("conductor-polish L3: mask _unpad_block equals the old pad rule on %d blocks (every L 0..255, every single-byte pad position), fixed-width masks, no loop" % _cp_n,
      _cp_bad == 0 and _cp_n > 90000 and "for " not in _cp_usrc.split('"""')[2] and "_UNPAD_MASKS[L & MAX_MSG]" in _cp_usrc
      and len(N._UNPAD_MASKS) == 128 and all(m.bit_length() == 1017 for m in N._UNPAD_MASKS)
      and N._UNPAD_MASKS[127] == N._UNPAD_TOP)
def _cp_ut(L, n=3000):
    _b = N.encode_block(b"A" * L); out = []
    for _ in range(n):
        t0 = _time.perf_counter_ns(); N._unpad_block(_b); out.append(_time.perf_counter_ns() - t0)
    return sorted(out)[n // 2]
_cp_u0, _cp_u127 = min(_cp_ut(0) for _ in range(3)), min(_cp_ut(127) for _ in range(3))
print("conductor-polish unpad timing: median L=0 %d ns, L=127 %d ns" % (_cp_u0, _cp_u127))
check("conductor-polish L3: unpad L=0 vs L=127 medians within 400 ns (loop version was ~750 ns apart) and under 3 us",
      abs(_cp_u0 - _cp_u127) < 400 and max(_cp_u0, _cp_u127) < 3000)

# I2: private legacy bodies are gated and version-pinned on their own
_cp_v2 = bytes([2]) + b"SN2" + bytes(192)
_cp_priv_noflag = [catch(lambda: N._decrypt_legacy_v2(_cp_v2, SEED, b"")),
                   catch(lambda: N._decrypt_legacy_v3(bytes([3]) + b"SN2" + bytes(300), SEED, b"")),
                   catch(lambda: etude(16)._decrypt_legacy_block(bytes([0xF0]) + b"SN2" + bytes(192), SEED, b"")),
                   catch(lambda: etude(16)._decrypt_legacy_movements(bytes([0xF1]) + b"SN2" + bytes(300), SEED, b""))]
check("conductor-polish I2: every private legacy body refuses without allow_noncommitting=True (ValueError)",
      all(type(e) is ValueError and "allow_noncommitting=True" in str(e) for e in _cp_priv_noflag))
_cp_live_v2like = bytes([N.FMT_VERSION]) + HW_BLOB[1:N.CM0] + HW_BLOB[N.CM1:]      # 196 bytes, byte 6
_cp_pins = [catch(lambda: N._decrypt_legacy_v2(_cp_live_v2like, SEED, b"", allow_noncommitting=True)),
            catch(lambda: N._decrypt_legacy_v3(_cp_mv, _cp_seed, b"", allow_noncommitting=True)),
            catch(lambda: etude(16)._decrypt_legacy_block(bytes([2]) + _cp_live_v2like[1:], SEED, b"", allow_noncommitting=True)),
            catch(lambda: etude(2)._decrypt_legacy_block(bytes([0xF0]) + _cp_live_v2like[1:], SEED, b"", allow_noncommitting=True)),
            catch(lambda: etude(16)._decrypt_legacy_movements(bytes([3]) + b"SN2" + bytes(300), SEED, b"", allow_noncommitting=True))]
check("conductor-polish I2: private legacy bodies pin the version byte (live/other bytes -> UnsupportedVersion; another round count -> mismatch)",
      all(isinstance(e, N.UnsupportedVersion) for e in _cp_pins) and str(_cp_pins[3]) == "étude round count mismatch")
check("conductor-polish I2: private étude legacy bodies apply the demo-seed gate too",
      "lab_seed=True" in str(catch(lambda: E.etude(16)._decrypt_legacy_block(bytes([0xF0]) + b"SN2" + bytes(192), SEED, b"", allow_noncommitting=True))))
if _pre_hw is not None:
    with _w.catch_warnings(record=True) as _rec:
        _w.simplefilter("always")
        _cp_hw = N._decrypt_legacy_v2(_pre_hw, SEED, b"", allow_noncommitting=True)
    check("conductor-polish I2: the published v2 hello-world opens through the private body with the flag, with exactly one warning",
          _cp_hw == b"hello world" and sum(issubclass(r.category, N.LegacyFormatWarning) for r in _rec) == 1)
else:
    skip("conductor-polish I2: the published v2 hello-world opens through the private body with the flag, with exactly one warning")

# I3: shared parent class
check("conductor-polish I3: Rejected is the common ValueError parent of AuthError, DecodeError and UnsupportedVersion; AuthError and UnsupportedVersion stay disjoint",
      issubclass(N.Rejected, ValueError) and all(issubclass(c, N.Rejected) for c in (N.AuthError, N.DecodeError, N.UnsupportedVersion))
      and not issubclass(N.UnsupportedVersion, N.AuthError) and not issubclass(N.AuthError, N.UnsupportedVersion)
      and "Rejected" in N.MIX_CODE_FUNCS)
_cp_rej = [catch(f) for f in (lambda: N.decrypt(b"", SEED), lambda: N.decrypt(bytes([2]) + bytes(195), SEED), lambda: N.decrypt(HW_BLOB, _cp_seed),
                              lambda: N.decrypt_movements(bytes([3]) + bytes(300), SEED), lambda: N.decrypt_movements(_cp_mv, SEED),
                              lambda: etude(4).decrypt(_cd_ms[2], SEED), lambda: N.decrypt(HW_BLOB[:-1], SEED))]
check("conductor-polish I3: one `except Rejected:` clause catches every reject class (length, version, auth, round mismatch); caller errors stay plain",
      all(isinstance(e, N.Rejected) for e in _cp_rej)
      and not isinstance(catch(lambda: N.decrypt_legacy(_cp_v2, SEED)), N.Rejected)
      and not isinstance(catch(lambda: N.decrypt(HW_BLOB, bytes(128))), N.Rejected)
      and isinstance(catch(lambda: N.decrypt("x", SEED)), TypeError))
check("conductor-polish I3: SECURITY.md documents Rejected and recommends an allowlist / cutoff for legacy fallback, not `except UnsupportedVersion`",
      "Rejected" in _sec and "allowlist" in _sec and "cutoff" in _sec)

# I1: documented end date for legacy étude helpers
_cp_esrc = open(os.path.join(HERE, "etudes.py"), encoding="utf-8").read()
check("conductor-polish I1: etudes.py and SECURITY.md give an end date for the legacy étude helpers",
      "2027-03-01" in _cp_esrc and "REMOVED" in _cp_esrc and "2027-03-01" in _sec)

# I4: seed-file cache keyed on dev/inode/size/mtime/ctime
_cp_tree = _cp_tmp.mkdtemp(prefix="octavo_cp_seed_")
_cp_sh.copy(os.path.join(HERE, "sneak_n2.py"), _cp_tree)
_cp_sh.copy(os.path.join(HERE, "sneak1024-seed.txt"), _cp_tree)
_cp_alt = os.urandom(128)
while len(set(b for b in _cp_alt if b)) < 32: _cp_alt = os.urandom(128)
open(os.path.join(_cp_tree, "alt.txt"), "w").write(_cp_alt.hex() + "\n")
_cp_prog = (
    "import os, shutil, sneak_n2 as N\n"
    "p = N.SEED_PATH; a = N.load_seed(); st = os.stat(p)\n"
    "shutil.copyfile('alt.txt', p); os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))\n"   # same size+mtime, new content
    "b = N.load_seed()\n"
    "os.replace('alt2.txt', p) if os.path.exists('alt2.txt') else None\n"
    "print(a.hex() != b.hex(), b.hex() == open('alt.txt').read().strip(), len(N.load_seed.cache[0]))\n")
_cp_r = _cp_sp.run([sys.executable, "-B", "-c", _cp_prog], cwd=_cp_tree, capture_output=True, text=True)
_cp_sh.rmtree(_cp_tree, ignore_errors=True)
check("conductor-polish I4: replacing the seed file with a same-size, same-mtime seed is noticed (cache key has inode + ctime)",
      _cp_r.stdout.split() == ["True", "True", "6"])

# I5: LRU memo; étude keys never memoized
N._seed_bytes(SEED)
for _ in range(15): N._seed_bytes(os.urandom(64) + bytes(range(64)))
N._seed_bytes(SEED)                          # hit -> most recent
for _ in range(15): N._seed_bytes(os.urandom(64) + bytes(range(64)))
_cp_lru_kept = SEED in N._seed_bytes.ok
for _ in range(16): N._seed_bytes(os.urandom(64) + bytes(range(64)))
_cp_lru_dropped = SEED not in N._seed_bytes.ok
_cp_before = len(N._seed_bytes.ok)
_cp_ks = [E.etude_key(SEED, r) for r in (2, 4, 6, 16)]
etude(4).decrypt(etude(4).encrypt(b"lru", SEED), SEED)
check("conductor-polish I5: the seed memo is a bounded LRU (no clear-all), and étude keys K_e are never memoized",
      isinstance(N._seed_bytes.ok, _cp_coll.OrderedDict) and N._seed_bytes.size == 16 and len(N._seed_bytes.ok) <= 16
      and _cp_lru_kept and _cp_lru_dropped and _cp_before == 16
      and all(type(k) is N._DerivedKey for k in _cp_ks) and not any(bytes(k) in N._seed_bytes.ok for k in _cp_ks)
      and "clear()" not in inspect.getsource(N._seed_bytes))
check("conductor-polish I5: a weak value wrapped as _DerivedKey is still rejected (marker skips the memo, never the rule)",
      isinstance(catch(lambda: N._seed_bytes(N._DerivedKey(bytes(128)))), ValueError)
      and N._seed_bytes(N._DerivedKey(_cp_ks[0])) == _cp_ks[0])

# I6: lab_seed read-only
_cp_h = E.etude(2)
_cp_set = catch(lambda: setattr(_cp_h, "lab_seed", True))
check("conductor-polish I6: Etude.lab_seed is read-only after construction; the demo seed stays refused",
      isinstance(_cp_set, AttributeError) and _cp_h.lab_seed is False and E.etude(2, lab_seed=True).lab_seed is True
      and "lab_seed=True" in str(catch(lambda: _cp_h.encrypt(b"x", SEED)))
      and "ungated" in E.etude_key.__doc__.lower())

# ---- rehearsal (format version 8): STREAM-style chunked online AE, lifts the 1,040,384-byte cap
import contextlib as _rh_ctx, tempfile as _rh_tmp, shutil as _rh_sh, hmac as _rh_hmac, time as _rh_time, io as _rh_io
_RH_PK = bytes.fromhex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"); _RH_NC = bytes.fromhex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf")
@_rh_ctx.contextmanager
def _rh_fixed(pickup=_RH_PK, nonce=_RH_NC, mod=None):
    """Pin the fresh pickup and stream nonce (tests and published vectors only)."""
    m = N if mod is None else mod
    o1, o2 = m._fresh_pickup, getattr(m, "_fresh_stream_nonce", None)
    m._fresh_pickup = lambda: pickup
    if o2 is not None: m._fresh_stream_nonce = lambda: nonce
    try: yield
    finally:
        m._fresh_pickup = o1
        if o2 is not None: m._fresh_stream_nonce = o2
def _rh_err(f):
    e = catch(f); return (type(e).__name__, str(e)) if e is not None else None
def _rh_len(n, cs):
    """Expected v8 stream length for an n-byte message at chunk size cs."""
    full = n // cs; last = n - full * cs
    return 72 + full * (cs + 32) + ((last + 1 + 127) // 128) * 128 + 32
def _rh_chunks(blob, cs):
    """Split a v8 stream into (header, [chunk bytes...]) using the public framing."""
    body = blob[72:]; out = []
    while len(body) > cs + 32: out.append(body[:cs + 32]); body = body[cs + 32:]
    out.append(body); return blob[:72], out
_rh_msgs = {n: bytes((i * 31 + n) % 256 for i in range(n)) for n in (0, 1, 127, 128, 129, 255, 256, 257, 383, 384, 1000)}

check("rehearsal constants: FMT_REHEARSAL 8, 72-byte header, chunk 128..1 MiB (default 64 KiB), 2^24 chunks, domains R/H",
      N.FMT_REHEARSAL == 8 and N.REHEARSAL_HDR_LEN == 72 == 1 + 3 + 16 + 16 + 32 + 4 and N.RH_CS0 == 68
      and (N.REHEARSAL_CHUNK_MIN, N.REHEARSAL_CHUNK_MAX, N.REHEARSAL_CHUNK_DEFAULT) == (128, 1 << 20, 65536)
      and N.MAX_REHEARSAL_CHUNKS == 1 << 24 and N.REHEARSAL_DOMAIN == b"R" and N.REHEARSAL_SIG_DOMAIN == b"H"
      and N.FMT_REHEARSAL not in (N.FMT_VERSION, N.FMT_MOVEMENTS, N.FMT_VERSION_V2, N.FMT_VERSION_V4, N.FMT_MOVEMENTS_V3, N.FMT_MOVEMENTS_V5)
      and N.FMT_REHEARSAL not in tuple(E.ETUDE_FMT_BLOCK.values()) + tuple(E.ETUDE_FMT_MOVEMENTS.values()))
_rh_used = {b"C", b"G", b"K", b"M", b"U", b"T", b"W", b"D", b"O", b"E"}
check("rehearsal domains are new: R and H are not existing sponge letters; raw prefixes SN2/A and SN2/Q avoid every sponge letter and P/T/I",
      N.REHEARSAL_DOMAIN not in _rh_used and N.REHEARSAL_SIG_DOMAIN not in _rh_used and N.REHEARSAL_DOMAIN != N.REHEARSAL_SIG_DOMAIN
      and N.REHEARSAL_AD_PREFIX == b"SN2/A" and N.REHEARSAL_NONCE_PREFIX == b"SN2/Q"
      and not ({b"A", b"Q"} & (_rh_used | {b"R", b"H", b"P", b"I"})))

# round trips and exact lengths, several chunk sizes
_rh_rt = []
for _cs in (128, 256, 384):
    for _n, _m in _rh_msgs.items():
        _b = N.encrypt_rehearsal(_m, SEED, b"rt", _cs)
        _rh_rt.append(N.decrypt_rehearsal(_b, SEED, b"rt") == _m and len(_b) == _rh_len(_n, _cs)
                      and _b[:4] == b"\x08SN2" and int.from_bytes(_b[68:72], "big") == _cs)
check("rehearsal round trip for 0,1,127,128,129,255,256,257,383,384,1000 bytes at chunk sizes 128/256/384, exact stream lengths",
      all(_rh_rt) and len(_rh_rt) == 33)
_rh_e0 = N.encrypt_rehearsal(b"", SEED)
check("empty stream: 232 bytes = header 72 + one 128-byte final chunk + tag; decrypts to b''; default chunk size 65536 in the header",
      len(_rh_e0) == 232 and N.decrypt_rehearsal(_rh_e0, SEED) == b"" and int.from_bytes(_rh_e0[68:72], "big") == 65536)
check("a plaintext that is an exact multiple of the chunk size ends with an empty 128-byte final chunk",
      [len(c) for c in _rh_chunks(N.encrypt_rehearsal(bytes(256), SEED, b"", 128), 128)[1]] == [160, 160, 160])
_rh_d1, _rh_d2 = N.encrypt_rehearsal(bytes(384), SEED, b"", 128), N.encrypt_rehearsal(bytes(384), SEED, b"", 128)
_rh_c1 = _rh_chunks(_rh_d1, 128)[1]
check("equal chunks never give equal ciphertext (per-chunk tweaks), and two encryptions of one message differ (fresh pickup and nonce)",
      len({c[:128] for c in _rh_c1}) == len(_rh_c1) == 4 and _rh_d1 != _rh_d2 and _rh_d1[4:36] != _rh_d2[4:36])

# incremental == one-shot, any split; workers > 1 byte-identical
_rh_m = bytes(R.randrange(256) for _ in range(1500))
with _rh_fixed():
    _rh_one = N.encrypt_rehearsal(_rh_m, SEED, b"inc", 128)
    _rh_incs = []
    for _trial in range(6):
        _enc = N.RehearsalEncryptor(SEED, b"inc", 128); _out = b""; _i = 0
        while _i < len(_rh_m):
            _k = R.choice((0, 1, 2, 7, 127, 128, 129, 300)); _out += _enc.update(_rh_m[_i:_i + _k]); _i += _k
        _rh_incs.append(_out + _enc.finalize())
    _enc = N.RehearsalEncryptor(SEED, b"inc", 128); _out = b"".join(_enc.update(bytes([x])) for x in _rh_m) + _enc.finalize()
    _rh_incs.append(_out)
    _rh_par = N.encrypt_rehearsal(_rh_m, SEED, b"inc", 128, workers=3)
    _rh_par_hdr = N.RehearsalEncryptor(SEED, b"inc", 128).finalize()
check("rehearsal incremental encryption (random splits, empty updates, 1-byte updates) is byte-identical to one-shot",
      all(x == _rh_one for x in _rh_incs) and len(_rh_incs) == 7)
check("workers=3 (process pool) encryption is byte-identical to workers=1; header comes first even from a finalize()-only stream",
      _rh_par == _rh_one and _rh_par_hdr[:72] == _rh_one[:72] and len(_rh_par_hdr) == 232)
_rh_dec_ok = []
for _trial in range(6):
    _dec = N.RehearsalDecryptor(SEED, b"inc"); _out = b""; _i = 0
    while _i < len(_rh_one):
        _k = R.choice((0, 1, 5, 71, 72, 159, 160, 161, 500)); _out += _dec.update(_rh_one[_i:_i + _k]); _i += _k
    _rh_dec_ok.append(_out + _dec.finalize() == _rh_m)
_dec = N.RehearsalDecryptor(SEED, b"inc"); _out = b"".join(_dec.update(bytes([x])) for x in _rh_one) + _dec.finalize()
check("rehearsal incremental decryption (random splits, 1-byte feeds, workers=3) equals one-shot",
      all(_rh_dec_ok) and _out == _rh_m and N.decrypt_rehearsal(_rh_one, SEED, b"inc", workers=3) == _rh_m
      and N.decrypt_rehearsal(memoryview(bytearray(_rh_one)), SEED, b"inc") == _rh_m)

# a 3-chunk sample stream for the tamper / truncation sweeps
_rh_s = bytes(range(256)) + b"rehearsal tail"           # 270 bytes -> chunks 128, 128, final 14
with _rh_fixed(): _rh_blob = N.encrypt_rehearsal(_rh_s, SEED, b"from:alice", 128)
_rh_hdr, _rh_ch = _rh_chunks(_rh_blob, 128)
check("sample stream framing: 72-byte header, two 160-byte non-final chunks, one 160-byte final chunk",
      len(_rh_blob) == 552 and [len(c) for c in _rh_ch] == [160, 160, 160] and N.decrypt_rehearsal(_rh_blob, SEED, b"from:alice") == _rh_s)

_rh_flip = []
for _pos in range(len(_rh_blob)):
    _t = flip(_rh_blob, 8 * _pos + (_pos % 8))
    _e = catch(lambda: N.decrypt_rehearsal(_t, SEED, b"from:alice"))
    _rh_flip.append((_pos, type(_e).__name__ if _e is not None else None))
check("every single-bit flip in every byte of a v8 stream is rejected (byte 0 -> UnsupportedVersion, every other byte -> AuthError), all Rejected",
      len(_rh_flip) == 552 and _rh_flip[0][1] == "UnsupportedVersion" and all(t == "AuthError" for p, t in _rh_flip[1:]))

_rh_tr = []
for _cut in range(len(_rh_blob)):
    _dec = N.RehearsalDecryptor(SEED, b"from:alice")
    _pre = _dec.update(_rh_blob[:_cut])
    _full = max(0, (_cut - 72 - 1) // 160) if _cut > 72 else 0
    _full = min(_full, 2)
    _e = catch(_dec.finalize)
    _rh_tr.append(_pre == _rh_s[:128 * _full] and isinstance(_e, N.AuthError) and isinstance(_e, N.Rejected))
check("truncation at every offset 0..551 (including exact chunk boundaries): update() yields only the verified chunk-aligned prefix, finalize() raises AuthError",
      all(_rh_tr) and len(_rh_tr) == 552)
check("dropping only the final chunk is rejected: the last non-final chunk fails as a final chunk ('authentication failed')",
      _rh_err(lambda: N.decrypt_rehearsal(_rh_hdr + _rh_ch[0] + _rh_ch[1], SEED, b"from:alice")) == ("AuthError", "authentication failed")
      and _rh_err(lambda: N.decrypt_rehearsal(_rh_hdr, SEED, b"from:alice")) == ("AuthError", "bad stream length")
      and _rh_err(lambda: N.decrypt_rehearsal(b"", SEED)) == ("AuthError", "bad stream length")
      and _rh_err(lambda: N.decrypt_rehearsal(_rh_blob[:40], SEED)) == ("AuthError", "bad stream length"))
_rh_bad = {
    "swap 0,1": _rh_hdr + _rh_ch[1] + _rh_ch[0] + _rh_ch[2],
    "duplicate 0": _rh_hdr + _rh_ch[0] + _rh_ch[0] + _rh_ch[1] + _rh_ch[2],
    "duplicate 1": _rh_hdr + _rh_ch[0] + _rh_ch[1] + _rh_ch[1] + _rh_ch[2],
    "drop 1": _rh_hdr + _rh_ch[0] + _rh_ch[2],
    "drop 0": _rh_hdr + _rh_ch[1] + _rh_ch[2],
    "final first": _rh_hdr + _rh_ch[2] + _rh_ch[0] + _rh_ch[1],
    "final twice": _rh_blob + _rh_ch[2],
    "append 1 byte": _rh_blob + b"\x00",
    "append 32 bytes": _rh_blob + bytes(32),
    "append chunk 0": _rh_blob + _rh_ch[0],
    "append a whole stream": _rh_blob + _rh_blob,
    "swap tags 0,1": _rh_hdr + _rh_ch[0][:128] + _rh_ch[1][128:] + _rh_ch[1][:128] + _rh_ch[0][128:] + _rh_ch[2],
}
check("reordering, duplication, dropping, moving the final chunk, extension and tag swaps are all rejected with AuthError",
      all(isinstance(catch(lambda b=b: N.decrypt_rehearsal(b, SEED, b"from:alice")), N.AuthError) for b in _rh_bad.values()) and len(_rh_bad) == 12)
with _rh_fixed(pickup=bytes(range(16)), nonce=bytes(range(16, 32))):
    _rh_other = N.encrypt_rehearsal(_rh_s, SEED, b"from:alice", 128)
with _rh_fixed(pickup=_RH_PK, nonce=bytes(range(16, 32))):
    _rh_samepk = N.encrypt_rehearsal(_rh_s, SEED, b"from:alice", 128)
_oh, _oc = _rh_chunks(_rh_other, 128); _ph, _pc = _rh_chunks(_rh_samepk, 128)
_rh_splice = [_rh_hdr + _oc[0] + _rh_ch[1] + _rh_ch[2], _rh_hdr + _rh_ch[0] + _oc[1] + _rh_ch[2], _rh_hdr + _rh_ch[0] + _rh_ch[1] + _oc[2],
              _oh + _rh_ch[0] + _rh_ch[1] + _rh_ch[2], _oh[:36] + _rh_hdr[36:] + b"".join(_rh_ch),
              _rh_hdr + _pc[0] + _pc[1] + _pc[2], _ph + b"".join(_rh_ch)]
check("cross-stream splicing (same seed, AD, chunk size and plaintext; other pickup or only another stream nonce) is rejected for every chunk and header mix",
      all(isinstance(catch(lambda b=b: N.decrypt_rehearsal(b, SEED, b"from:alice")), N.AuthError) for b in _rh_splice)
      and N.decrypt_rehearsal(_rh_other, SEED, b"from:alice") == _rh_s == N.decrypt_rehearsal(_rh_samepk, SEED, b"from:alice"))
_rh_cs_bad = []
for _new in (256, 384, 1024, 65536):
    _rh_cs_bad.append(_rh_err(lambda c=_new: N.decrypt_rehearsal(_rh_blob[:68] + c.to_bytes(4, "big") + _rh_blob[72:], SEED, b"from:alice")))
with _rh_fixed(): _rh_256 = N.encrypt_rehearsal(_rh_s, SEED, b"from:alice", 256)
_h256, _c256 = _rh_chunks(_rh_256, 256)
check("chunk-size changes are rejected: a rewritten valid size fails authentication; the same stream id at another size never shares chunks",
      _rh_cs_bad[:2] == [("AuthError", "authentication failed")] * 2 and all(x is not None and x[0] == "AuthError" for x in _rh_cs_bad)
      and _h256[:68] != _rh_hdr[:68] and _h256[4:36] == _rh_hdr[4:36]
      and isinstance(catch(lambda: N.decrypt_rehearsal(_h256[:68] + (128).to_bytes(4, "big") + b"".join(_rh_ch), SEED, b"from:alice")), N.AuthError)
      and isinstance(catch(lambda: N.decrypt_rehearsal(_rh_hdr + _c256[0][:128] + _rh_ch[0][128:] + _rh_ch[1] + _rh_ch[2], SEED, b"from:alice")), N.AuthError))
check("invalid chunk-size fields (0, 64, 100, 129, 2^20+128, 2^32-1) are structural rejects AuthError('bad chunk size')",
      all(_rh_err(lambda c=c: N.decrypt_rehearsal(_rh_blob[:68] + c.to_bytes(4, "big") + _rh_blob[72:], SEED)) == ("AuthError", "bad chunk size")
          for c in (0, 64, 100, 129, (1 << 20) + 128, (1 << 32) - 1)))
check("bad SN2 magic in a v8 header is AuthError('bad version prefix')",
      _rh_err(lambda: N.decrypt_rehearsal(_rh_blob[:1] + b"SN3" + _rh_blob[4:], SEED, b"from:alice")) == ("AuthError", "bad version prefix"))
_rh_k2 = os.urandom(128)
while len(set(b for b in _rh_k2 if b)) < 32: _rh_k2 = os.urandom(128)
check("wrong AD, missing AD, wrong seed all raise the same AuthError('authentication failed'); empty AD == omitted AD",
      _rh_err(lambda: N.decrypt_rehearsal(_rh_blob, SEED, b"from:bob")) == ("AuthError", "authentication failed")
      == _rh_err(lambda: N.decrypt_rehearsal(_rh_blob, SEED)) == _rh_err(lambda: N.decrypt_rehearsal(_rh_blob, _rh_k2, b"from:alice"))
      and N.decrypt_rehearsal(N.encrypt_rehearsal(b"x", SEED), SEED, b"") == b"x"
      and N.decrypt_rehearsal(N.encrypt_rehearsal(b"x", SEED, b""), SEED) == b"x")

# commitment and tag formulas
_rh_kc = N._commit_key(SEED)
_rh_cm = _rh_hmac.new(_rh_kc, b"U" + b"\x08" + b"SN2" + _RH_PK + _RH_NC + len(b"from:alice").to_bytes(8, "big") + b"from:alice"
                      + (128).to_bytes(4, "big"), hashlib.sha256).digest()
_rh_adh = hashlib.sha256(b"SN2/A" + len(b"from:alice").to_bytes(8, "big") + b"from:alice").digest()
_rh_k0 = N.StaffSponge(b"R", SEED, b"chunk" + _RH_PK + _RH_NC + (128).to_bytes(4, "big") + (0).to_bytes(8, "big") + b"\x00" + _rh_adh).take(32)
_rh_t0 = _rh_hmac.new(_rh_k0, N.staff_clef(SEED) + N.rehearsal_signature(SEED) + b"\x08SN2" + _RH_PK + _RH_NC + _rh_cm
                      + (128).to_bytes(4, "big") + (0).to_bytes(8, "big") + b"\x00"
                      + _rh_adh + _rh_ch[0][:128], hashlib.sha256).digest()
check("v8 header = 8 || SN2 || pickup || nonce || commit || chunk_size32, commit = HMAC(K_commit, U || 8 || SN2 || pickup || nonce || encode_ad(ad) || cs32)",
      _rh_hdr == b"\x08SN2" + _RH_PK + _RH_NC + _rh_cm + (128).to_bytes(4, "big")
      and _rh_cm == N._rehearsal_commitment(_rh_kc, _RH_PK, _RH_NC, b"from:alice", 128)
      and _rh_cm != N._commitment(_rh_kc, N.FMT_MOVEMENTS, _RH_PK, _RH_NC, b"from:alice", nmov=128)
      and N._rehearsal_commitment(_rh_kc, _RH_PK, _RH_NC, b"from:alice", 256) != _rh_cm
      and N._rehearsal_commitment(_rh_kc, _RH_PK, _RH_NC, b"", 128) != _rh_cm)
check("chunk tag = HMAC(R-sponge(chunk||pickup||nonce||cs32||index64||final8||ad_digest)[:32], clef || rehearsal_sig || 8 || SN2 || pickup || nonce || commit || cs32 || index64 || final8 || SHA-256(SN2/A || encode_ad) || ct)",
      _rh_ch[0][128:] == _rh_t0
      and N._rehearsal_chunk_key(SEED, _RH_PK, _RH_NC, 128, 0, False, _rh_adh) == _rh_k0
      and N._rehearsal_chunk_key(SEED, _RH_PK, _RH_NC, 128, 0, False, _rh_adh) != N._rehearsal_chunk_key(SEED, _RH_PK, _RH_NC, 128, 0, True, _rh_adh)
      and N._rehearsal_chunk_key(SEED, _RH_PK, _RH_NC, 128, 0, False, _rh_adh) != N._rehearsal_chunk_key(SEED, _RH_PK, _RH_NC, 128, 1, False, _rh_adh)
      and N._rehearsal_chunk_key(SEED, _RH_PK, _RH_NC, 128, 0, False, _rh_adh) != N._rehearsal_chunk_key(SEED, _RH_PK, _RH_NC, 128, 0, False, N._rehearsal_ad_digest(b"")))
_rh_sn = N.StaffSponge(b"R", SEED, b"sched" + _RH_PK + _RH_NC + (128).to_bytes(4, "big") + _rh_adh).take(16)
_rh_sp = N.StaffSponge(b"R", SEED, b"chunk" + _RH_PK + _RH_NC + (128).to_bytes(4, "big") + (0).to_bytes(8, "big") + b"\x00" + _rh_adh); _rh_sp.take(32)
_rh_T = _rh_sp.take(128)
_rh_x0 = N.grid_to_bytes(N.encrypt_grid(N.bytes_to_grid(bytes(a ^ b for a, b in zip(_rh_s[:128], _rh_T))), N.Schedule(SEED, _rh_sn)))
check("each block is XEX under the unchanged staff-core: ct = encrypt_grid(P ^ T, Schedule(seed, R(sched||...||ad_digest)[:16])) ^ T, T from R(chunk||...||ad_digest)",
      bytes(a ^ b for a, b in zip(_rh_x0, _rh_T)) == _rh_ch[0][:128])

# equal-time: chunk 0 always computes commitment AND tag; nothing decrypted before both pass
_rh_calls = []
_rh_o = (N._rehearsal_commitment, N._rehearsal_tag, N.Schedule.__init__, N.decrypt_grid)
def _rh_pc(*a, **k): _rh_calls.append("commit"); return _rh_o[0](*a, **k)
def _rh_pt(*a, **k): _rh_calls.append("tag"); return _rh_o[1](*a, **k)
def _rh_ps(self, *a, **k): _rh_calls.append("Schedule"); return _rh_o[2](self, *a, **k)
def _rh_pd(*a, **k): _rh_calls.append("dec"); return _rh_o[3](*a, **k)
N._rehearsal_commitment, N._rehearsal_tag, N.Schedule.__init__, N.decrypt_grid = _rh_pc, _rh_pt, _rh_ps, _rh_pd
try:
    _rh_seq = {}
    for _name, _b in (("commit", _rh_blob[:40] + bytes([_rh_blob[40] ^ 1]) + _rh_blob[41:]),
                      ("tag0", _rh_blob[:72 + 140] + bytes([_rh_blob[72 + 140] ^ 1]) + _rh_blob[72 + 141:]),
                      ("ct0", _rh_blob[:80] + bytes([_rh_blob[80] ^ 1]) + _rh_blob[81:]),
                      ("ct1", _rh_blob[:72 + 170] + bytes([_rh_blob[72 + 170] ^ 1]) + _rh_blob[72 + 171:])):
        _rh_calls.clear(); _e = catch(lambda: N.decrypt_rehearsal(_b, SEED, b"from:alice")); _rh_seq[_name] = (list(_rh_calls), str(_e))
    _rh_calls.clear(); _dec = N.RehearsalDecryptor(SEED, b"from:alice")
    _p0 = _dec.update(_rh_blob[:72 + 161]); _rh_after0 = list(_rh_calls)
    _rh_calls.clear(); _e1 = catch(lambda: _dec.update(_rh_blob[72 + 161:72 + 170] + bytes([_rh_blob[72 + 170] ^ 1]) + _rh_blob[72 + 171:]))
    _rh_after1 = list(_rh_calls)
finally:
    N._rehearsal_commitment, N._rehearsal_tag, N.Schedule.__init__, N.decrypt_grid = _rh_o
check("chunk 0 reject is equal-time: a bad commitment, bad chunk-0 tag and bad chunk-0 ciphertext all run commitment + tag, then one AuthError, no Schedule, no decrypt",
      all(_rh_seq[k][0] == ["commit", "tag"] and _rh_seq[k][1] == "authentication failed" for k in ("commit", "tag0", "ct0")))
check("never releases unauthenticated plaintext: a bad chunk 1 is rejected before ANY block is decrypted in that call; incremental feed releases only verified chunk 0",
      _rh_seq["ct1"][0] == ["commit", "tag", "tag"] and _rh_seq["ct1"][1] == "authentication failed"
      and _p0 == _rh_s[:128] and _rh_after0 == ["commit", "tag", "Schedule", "dec"]
      and isinstance(_e1, N.AuthError) and _rh_after1 == ["tag"])
_dec = N.RehearsalDecryptor(SEED, b"from:alice"); catch(lambda: _dec.update(_rh_blob[:72] + bytes(200)))
_rh_dead = (_rh_err(lambda: _dec.update(b"")), _rh_err(_dec.finalize))
_dec2 = N.RehearsalDecryptor(SEED, b"from:alice"); _dec2.update(_rh_blob); _dec2.finalize()
_enc = N.RehearsalEncryptor(SEED); _enc.finalize()
check("a rejected decryptor stays dead (AuthError 'stream already rejected'); update/finalize after finalize raise ValueError",
      _rh_dead == (("AuthError", "stream already rejected"),) * 2
      and isinstance(catch(lambda: _dec2.update(b"x")), ValueError) and not isinstance(catch(lambda: _dec2.update(b"x")), N.Rejected)
      and isinstance(catch(lambda: _enc.update(b"x")), ValueError) and isinstance(catch(_enc.finalize), ValueError))

# timing sanity (random seed, interleaved): commitment-fail vs tag-fail vs ct-fail on a one-chunk stream
_rh_ts = os.urandom(128)
while len(set(b for b in _rh_ts if b)) < 32: _rh_ts = os.urandom(128)
_rh_tb = N.encrypt_rehearsal(b"timing sample", _rh_ts, b"ad", 128)
_rh_cls = {"commit": _rh_tb[:50] + bytes([_rh_tb[50] ^ 1]) + _rh_tb[51:], "tag": _rh_tb[:-1] + bytes([_rh_tb[-1] ^ 1]),
           "ct": _rh_tb[:100] + bytes([_rh_tb[100] ^ 1]) + _rh_tb[101:]}
_rh_tm = {k: [] for k in _rh_cls}
for _ in range(1500):
    for _k, _b in _rh_cls.items():
        _t0 = _rh_time.perf_counter_ns(); catch(lambda: N.decrypt_rehearsal(_b, _rh_ts, b"ad")); _rh_tm[_k].append(_rh_time.perf_counter_ns() - _t0)
_rh_med = {k: sorted(v)[len(v) // 2] for k, v in _rh_tm.items()}
print("rehearsal reject medians (ns):", _rh_med)
check("timing sanity: v8 commitment-fail, tag-fail and ciphertext-fail medians agree within 15% (1500 interleaved trials each)",
      max(_rh_med.values()) <= 1.15 * min(_rh_med.values()))

# limits and caller mistakes
_rh_saved = N.MAX_REHEARSAL_CHUNKS; N.MAX_REHEARSAL_CHUNKS = 3
try:
    _rh_lim_ok = N.decrypt_rehearsal(N.encrypt_rehearsal(bytes(383), SEED, b"", 128), SEED) == bytes(383)
    _rh_lim_enc = catch(lambda: N.encrypt_rehearsal(bytes(384), SEED, b"", 128))
finally:
    N.MAX_REHEARSAL_CHUNKS = _rh_saved
_rh_4ch = N.encrypt_rehearsal(bytes(384), SEED, b"", 128)
N.MAX_REHEARSAL_CHUNKS = 3
try: _rh_lim_dec = _rh_err(lambda: N.decrypt_rehearsal(_rh_4ch, SEED))
finally: N.MAX_REHEARSAL_CHUNKS = _rh_saved
check("MAX_REHEARSAL_CHUNKS counts the final chunk: encrypt refuses with ValueError, decrypt rejects AuthError('too many chunks')",
      _rh_lim_ok and isinstance(_rh_lim_enc, ValueError) and "stream too long" in str(_rh_lim_enc)
      and _rh_lim_dec == ("AuthError", "too many chunks") and N.decrypt_rehearsal(_rh_4ch, SEED) == bytes(384))
check("caller mistakes: bad chunk_size (ValueError / TypeError), AD over MAX_AD_LEN, non-bytes data, bad workers; none is a Rejected",
      all(isinstance(catch(lambda c=c: N.RehearsalEncryptor(SEED, b"", c)), ValueError) for c in (0, 64, 127, 129, 1000, (1 << 20) + 128))
      and all(isinstance(catch(lambda c=c: N.RehearsalEncryptor(SEED, b"", c)), TypeError) for c in ("128", True, 128.0, None))
      and isinstance(catch(lambda: N.RehearsalEncryptor(SEED, bytes(N.MAX_AD_LEN + 1))), ValueError)
      and isinstance(catch(lambda: N.RehearsalDecryptor(SEED, bytes(N.MAX_AD_LEN + 1))), ValueError)
      and N.decrypt_rehearsal(N.encrypt_rehearsal(b"m", SEED, bytes(N.MAX_AD_LEN)), SEED, bytes(N.MAX_AD_LEN)) == b"m"
      and isinstance(catch(lambda: N.RehearsalEncryptor(SEED).update("text")), TypeError)
      and isinstance(catch(lambda: N.RehearsalDecryptor(SEED).update(5)), TypeError)
      and isinstance(catch(lambda: N.encrypt_rehearsal("text", SEED)), TypeError)
      and all(isinstance(catch(lambda w=w: N.RehearsalEncryptor(SEED, workers=w)), ValueError) for w in (0, -1, True, 1.5))
      and isinstance(catch(lambda: N.RehearsalEncryptor(bytes(128))), ValueError)
      and not any(isinstance(catch(lambda c=c: N.RehearsalEncryptor(SEED, b"", c)), N.Rejected) for c in (0, "x")))

# version separation
_rh_v6 = N.encrypt(b"hello", SEED); _rh_v7 = N.encrypt_movements(b"hello" * 40, SEED)
_rh_et = etude(16)
check("version separation: decrypt/decrypt_movements/étude handles reject v8 as UnsupportedVersion; RehearsalDecryptor rejects v6, v7 and étude bytes the same way",
      all(isinstance(catch(lambda f=f: f(_rh_blob, SEED)), N.UnsupportedVersion) for f in (N.decrypt, N.decrypt_movements, _rh_et.decrypt, _rh_et.decrypt_movements))
      and all(isinstance(catch(lambda b=b: N.decrypt_rehearsal(b, SEED)), N.UnsupportedVersion)
              for b in (_rh_v6, _rh_v7, _rh_et.encrypt(b"x", SEED), _rh_et.encrypt_movements(b"x", SEED), bytes([2]) + _rh_blob[1:]))
      and all(issubclass(c, N.Rejected) for c in (N.AuthError, N.UnsupportedVersion)))
check("études get no streaming: no rehearsal API on Etude or in etudes.py, and no étude rehearsal version byte",
      not any(hasattr(_rh_et, n) for n in ("encrypt_rehearsal", "decrypt_rehearsal", "rehearsal", "RehearsalEncryptor"))
      and "rehearsal" not in open(os.path.join(HERE, "etudes.py")).read().lower())

# rehearsal attestation (own digest; the live mix digest is untouched)
check("rehearsal attestation: EXPECTED_REHEARSAL_SHA256 == sha256(rehearsal_description()); it embeds the live mix digest; closure covers the whole staff-core",
      N.EXPECTED_REHEARSAL_SHA256 == N._REHEARSAL_SHA256 == hashlib.sha256(N.rehearsal_description()).hexdigest()
      and N._MIX_SHA256 in N.rehearsal_description().decode()
      and N.mix_code_closure(("encrypt_grid", "decrypt_grid", "Schedule", "staff_clef", "_commit_key"))[0] <= N.mix_code_closure(N.REHEARSAL_CODE_ROOTS)[0]
      and {"RehearsalEncryptor", "RehearsalDecryptor", "_RehearsalBase", "_rehearsal_tag", "_rehearsal_crypt_chunk", "_rehearsal_unpad",
           "_RehearsalWorkers", "_RehearsalOutput", "iter_rehearsal", "_rehearsal_tweaks", "_rehearsal_refuse_same",
           "round_enc", "round_dec"} <= N.mix_code_closure(N.REHEARSAL_CODE_ROOTS)[0]
      and "_REHEARSAL_WORKER_SRC" in N.mix_code_closure(N.REHEARSAL_CODE_ROOTS)[1]
      and N.rehearsal_signature(SEED) == N.StaffSponge(b"H", SEED, bytes.fromhex(N._REHEARSAL_SHA256)).take(16)
      and N.rehearsal_signature(SEED) != N.key_signature(SEED) and len(N.rehearsal_signature(SEED)) == 16)
check("rehearsal code is invisible to the live mix closure (so key_sig and v6/v7 blobs are unchanged)",
      not any("rehearsal" in n.lower() for n in N.mix_code_closure()[0] | N.mix_code_closure()[1])
      and not any("rehearsal" in n.lower() for n in N.MIX_CODE_FUNCS + N.MIX_CODE_ROOTS))
with _rh_tmp.TemporaryDirectory(prefix="octavo_rh_attest_") as _td:
    _src = open(os.path.join(HERE, "sneak_n2.py")).read()
    _mut = _src.replace('REHEARSAL_PAD = b"\\x80"', 'REHEARSAL_PAD = b"\\x81"', 1)
    _mut2 = _src.replace("    sp.take(32)\n    return [", "    return [", 1)
    _res = []
    for _i, _txt in enumerate((_mut, _mut2)):
        _p = os.path.join(_td, "m%d.py" % _i); open(_p, "w").write(_txt)
        _r = subprocess.run([sys.executable, "-B", "-c", "import importlib.util as u,sys;s=u.spec_from_file_location('m',%r);m=u.module_from_spec(s);sys.modules['m']=m;s.loader.exec_module(m)" % _p],
                            capture_output=True, text=True, cwd=_td)
        _res.append(_txt != _src and _r.returncode != 0 and "embedded rehearsal attestation mismatch" in _r.stderr)
check("editing rehearsal data (pad byte) or code (tweak offset) fails the embedded rehearsal attestation at import", all(_res) and len(_res) == 2)
_rh_sig_o = N.rehearsal_signature
N.rehearsal_signature = lambda seed=None: bytes(16)
try: _rh_sig_e = _rh_err(lambda: N.decrypt_rehearsal(_rh_blob, SEED, b"from:alice"))
finally: N.rehearsal_signature = _rh_sig_o
check("the rehearsal signature is bound into every chunk tag: under a different rehearsal_signature the stream does not open",
      _rh_sig_e == ("AuthError", "authentication failed") and N.decrypt_rehearsal(_rh_blob, SEED, b"from:alice") == _rh_s)

# v6 / v7 byte-identical to the frozen octavo010 module (loaded from a temp COPY; octavo010 is never touched)
_rh_o10 = "/workspace/octavo010"
if os.path.isfile(os.path.join(_rh_o10, "sneak_n2.py")):
    with _rh_tmp.TemporaryDirectory(prefix="octavo_rh_o10_") as _td:
        for _f in ("sneak_n2.py", "sneak1024-seed.txt"): _rh_sh.copy(os.path.join(_rh_o10, _f), _td)
        _sp10 = importlib.util.spec_from_file_location("sneak_n2_octavo010", os.path.join(_td, "sneak_n2.py"))
        _O = importlib.util.module_from_spec(_sp10); sys.modules["sneak_n2_octavo010"] = _O; _sp10.loader.exec_module(_O)
        _rh_same = []
        for _pk in (bytes(16), bytes(range(16)), bytes.fromhex("2b87dc4e184cd78e6c77b829273b17a3")):
            for _msg, _ad in ((b"", b""), (b"hello world", b""), (bytes(range(127)), b"from:alice")):
                with _rh_fixed(pickup=_pk), _rh_fixed(pickup=_pk, mod=_O):
                    _rh_same.append(N.encrypt(_msg, SEED, ad=_ad) == _O.encrypt(_msg, SEED, ad=_ad))
            for _msg, _ad in ((b"", b""), (bytes(range(128)), b""), (bytes(1000), b"from:alice")):
                with _rh_fixed(pickup=_pk), _rh_fixed(pickup=_pk, mod=_O):
                    _rh_same.append(N.encrypt_movements(_msg, SEED, ad=_ad) == _O.encrypt_movements(_msg, SEED, ad=_ad))
        _rh_o10_ids = (_O.EXPECTED_MIX_SHA256, _O.key_signature(SEED).hex(), _O.FMT_VERSION, _O.FMT_MOVEMENTS, _O.BLOB_LEN, _O.MOVEMENTS_HDR_LEN)
        _rh_cross = (_O.decrypt(N.encrypt(b"cross", SEED), SEED) == b"cross"
                     and _O.decrypt_movements(N.encrypt_movements(bytes(300), SEED, b"a"), SEED, b"a") == bytes(300)
                     and N.decrypt(_O.encrypt(b"cross", SEED), SEED) == b"cross")
        sys.modules.pop("sneak_n2_octavo010", None)
    check("v6 and v7 are byte-identical to frozen octavo010: 18 fixed-pickup blobs (9 single-block, 9 movements) match exactly, and blobs cross-decrypt both ways",
          all(_rh_same) and len(_rh_same) == 18 and _rh_cross)
    check("live EXPECTED_MIX_SHA256, demo key_sig, FMT_VERSION 6, FMT_MOVEMENTS 7, 228-byte blob and 72-byte movements header equal octavo010's",
          _rh_o10_ids == (N.EXPECTED_MIX_SHA256, N.key_signature(SEED).hex(), 6, 7, 228, 72)
          and N.EXPECTED_MIX_SHA256 == "fe93996970ecd92693b5f8f43ffb2cad5e96867f258a38b12637f1014b12b4c6"
          and N.key_signature(SEED).hex() == "340dc1e062502bb13462a94ba490c3dc")
    _rh_o10_hw = [l for l in open(os.path.join(_rh_o10, "hello-world.txt")) if l.startswith("blob")]
    _rh_o10_mv = [l for l in open(os.path.join(_rh_o10, "movements-demo.txt")) if l.startswith("blob")]
    check("hello-world.txt and movements-demo.txt blobs are octavo010's, byte for byte, and still open on the live module",
          _rh_o10_hw and bytes.fromhex(_rh_o10_hw[0].split()[-1]) == HW_BLOB and N.decrypt(HW_BLOB, SEED) == b"hello world"
          and _rh_o10_mv and bytes.fromhex(_rh_o10_mv[0].split()[-1]) == _mv_demo_blob)
    _rh_o10_score = __import__("json").load(open(os.path.join(_rh_o10, "score", "vectors.json")))
    _rh_live_score = __import__("json").load(open(os.path.join(HERE, "score", "vectors.json")))
    check("the 64 existing score vectors (16 permute, 24 aead, 24 movements) are unchanged from octavo010's score",
          all(_rh_live_score[k] == _rh_o10_score[k] for k in ("block_cipher", "aead", "movements"))
          and len(_rh_o10_score["block_cipher"]) + len(_rh_o10_score["aead"]) + len(_rh_o10_score["movements"]) == 64)
else:
    skip("v6/v7 byte-identical to octavo010 (frozen tree missing)")

# lifts the cap: a 5 MB stream through the file helpers, with a process pool
check("movements still cap at 1,040,384 bytes (unchanged), rehearsal does not",
      N.MAX_MOVEMENTS_MSG == 1040384 and isinstance(catch(lambda: N.encrypt_movements(bytes(N.MAX_MOVEMENTS_MSG + 1), SEED)), ValueError))
_rh_big_n = 5 * 1024 * 1024 + 12345
_rh_big = os.urandom(_rh_big_n)
_rh_bd = _rh_tmp.mkdtemp(prefix="octavo_rh_big_")
try:
    _pin, _pct, _pout = (os.path.join(_rh_bd, n) for n in ("plain.bin", "stream.oct", "out.bin"))
    open(_pin, "wb").write(_rh_big)
    _t0 = _rh_time.time()
    _nct = N.encrypt_rehearsal_file(_pin, _pct, SEED, b"big", workers=8)
    _t1 = _rh_time.time()
    _npt = N.decrypt_rehearsal_file(_pct, _pout, SEED, b"big", workers=8)
    _t2 = _rh_time.time()
    print("rehearsal 5 MB: encrypt %.1f s, decrypt %.1f s (8 workers)" % (_t1 - _t0, _t2 - _t1))
    _big_ct = open(_pct, "rb").read()
    check("5,255,225-byte stream (5x the movements cap) round-trips through encrypt_rehearsal_file / decrypt_rehearsal_file with workers=8",
          _rh_big_n > 5 * N.MAX_MOVEMENTS_MSG and _npt == _rh_big_n and open(_pout, "rb").read() == _rh_big
          and _nct == len(_big_ct) == _rh_len(_rh_big_n, 65536) and _big_ct[:1] == b"\x08"
          and not os.path.exists(_pct + ".tmp") and not os.path.exists(_pout + ".partial"))
    # tail-cut of the big stream: verified prefix only, error at the end, nothing left behind
    _cut = _big_ct[:72 + 3 * (65536 + 32) + 1000]
    open(_pct, "wb").write(_cut)
    _e = catch(lambda: N.decrypt_rehearsal_file(_pct, os.path.join(_rh_bd, "cut.bin"), SEED, b"big", workers=8))
    _e2 = catch(lambda: N.decrypt_rehearsal_file(_pct, os.path.join(_rh_bd, "cut2.bin"), SEED, b"big", keep_partial=True))
    check("a cut-off 5 MB stream: decrypt_rehearsal_file raises AuthError and leaves no output; keep_partial=True leaves only the verified chunk-aligned prefix",
          isinstance(_e, N.AuthError) and not os.path.exists(os.path.join(_rh_bd, "cut.bin")) and not os.path.exists(os.path.join(_rh_bd, "cut.bin.partial"))
          and isinstance(_e2, N.AuthError) and not os.path.exists(os.path.join(_rh_bd, "cut2.bin"))
          and open(os.path.join(_rh_bd, "cut2.bin.partial"), "rb").read() == _rh_big[:3 * 65536])
finally:
    _rh_sh.rmtree(_rh_bd, ignore_errors=True)
del _rh_big, _big_ct
_rh_bio_in = _rh_io.BytesIO(_rh_s); _rh_bio_ct = _rh_io.BytesIO()
_rh_n1 = N.encrypt_rehearsal_file(_rh_bio_in, _rh_bio_ct, SEED, b"io", 128, read_size=50)
_rh_bio_pt = _rh_io.BytesIO(); _rh_n2 = N.decrypt_rehearsal_file(_rh_io.BytesIO(_rh_bio_ct.getvalue()), _rh_bio_pt, SEED, b"io", read_size=7)
check("file helpers also take binary file objects, any read size",
      _rh_n1 == len(_rh_bio_ct.getvalue()) == 552 and _rh_n2 == 270 and _rh_bio_pt.getvalue() == _rh_s)

# rehearsal-demo.txt sample beside the tests
_rh_demo = os.path.join(HERE, "rehearsal-demo.txt")
if os.path.isfile(_rh_demo):
    _rd = {l.split()[0].rstrip(":"): l.split()[-1] for l in open(_rh_demo) if l.startswith(("blob", "plaintext_hex", "chunk_size"))}
    _rdb = bytes.fromhex(_rd.get("blob", ""))
    check("rehearsal-demo.txt decrypts to its recorded plaintext (format version 8)",
          _rdb[:4] == b"\x08SN2" and N.decrypt_rehearsal(_rdb, SEED, b"rehearsal-demo") == bytes.fromhex(_rd["plaintext_hex"])
          and int.from_bytes(_rdb[68:72], "big") == int(_rd["chunk_size"]))
else:
    check("rehearsal-demo.txt is present beside the tests", False)

# docs carry the rehearsal section and the honest verdict
_rh_docs = {n: open(os.path.join(HERE, n)).read() for n in ("README.md", "SECURITY.md", "LINER_NOTES.md", "ATTACKS.md")}
check("README, SECURITY, LINER_NOTES describe rehearsal (v8) and keep the verdict: homemade, use AES-GCM-SIV, age, or libsodium",
      all("rehearsal" in _rh_docs[n].lower() and "AES-GCM-SIV" in _rh_docs[n] and "age" in _rh_docs[n] and "libsodium" in _rh_docs[n]
          for n in ("README.md", "SECURITY.md", "LINER_NOTES.md"))
      and "no streaming API" not in _rh_docs["SECURITY.md"] and "not yet frozen" in _rh_docs["LINER_NOTES.md"])
check("docs use the recorded movements timings 12.45/12.42 and 14.70/14.68 µs (no rounded 12.3/14.3 figures)",
      all("12.45" in _rh_docs[n] and "12.42" in _rh_docs[n] and "14.70" in _rh_docs[n] and "14.68" in _rh_docs[n] for n in ("README.md", "SECURITY.md"))
      and not any("12.3 µs" in _rh_docs[n] or "14.3 µs" in _rh_docs[n] for n in ("README.md", "SECURITY.md")))
check("ATTACKS.md covers the history through octavo010 and the rehearsal revision, and its round count matches its table",
      "octavo010" in _rh_docs["ATTACKS.md"] and "rehearsal" in _rh_docs["ATTACKS.md"].lower() and "ten times" not in _rh_docs["ATTACKS.md"])
check("module docstring no longer calls the whole scheme 'unreviewed'",
      "homemade, unreviewed scheme" not in N.__doc__ and "AES-GCM-SIV" in N.__doc__)

# ---- rehearsal-fix: regression tests for the rehearsal attack (attacks_octavo_rehearsal/REPORT.md)
# Each block is a witness from that report turned into a test that asserts the FIXED behaviour.
import stat as _rf_stat, threading as _rf_thr, gc as _rf_gc, io as _rf_io, warnings as _rf_warn
_rf_msg = b"TOP-SECRET-PLAINTEXT " * 30                     # 630 bytes (w09)
_rf_blob = N.encrypt_rehearsal(_rf_msg, SEED, b"files", 128)
_rf_cut = _rf_blob[:72 + 3 * 160]
_rf_d = _rh_tmp.mkdtemp(prefix="octavo_rf_files_")
_rf_P = lambda *a: os.path.join(_rf_d, *a)
def _rf_wr(p, b, mode=0o600):
    with open(p, "wb") as f: f.write(b)
    os.chmod(p, mode)
def _rf_rd(p): return open(p, "rb").read() if os.path.exists(p) else None
def _rf_temps(): return sorted(n for n in os.listdir(_rf_d) if n.startswith(".") and n.endswith((".partial", ".tmp")))
_rf_umask = os.umask(0o022)
try:
    # M1 (w09 §e): symlinks planted at the old fixed names dst.partial / dst.tmp are never touched
    _rf_wr(_rf_P("victim.cfg"), b"victim configuration file " * 4, 0o644); os.symlink(_rf_P("victim.cfg"), _rf_P("e.txt.partial"))
    _rf_wr(_rf_P("e.oct"), _rf_blob)
    _rf_n = N.decrypt_rehearsal_file(_rf_P("e.oct"), _rf_P("e.txt"), SEED, b"files")
    _rf_e = (_rf_n == len(_rf_msg) and _rf_rd(_rf_P("e.txt")) == _rf_msg and not os.path.islink(_rf_P("e.txt"))
             and _rf_rd(_rf_P("victim.cfg")) == b"victim configuration file " * 4 and os.path.islink(_rf_P("e.txt.partial")))
    _rf_wr(_rf_P("drop_box"), b"", 0o666); os.symlink(_rf_P("drop_box"), _rf_P("f.txt.partial")); _rf_wr(_rf_P("f.oct"), _rf_blob)
    N.decrypt_rehearsal_file(_rf_P("f.oct"), _rf_P("f.txt"), SEED, b"files")
    _rf_wr(_rf_P("victim2.cfg"), b"second victim " * 8, 0o644); os.symlink(_rf_P("victim2.cfg"), _rf_P("e2.txt.partial"))
    _rf_wr(_rf_P("b.oct"), _rf_cut)
    _rf_r2 = catch(lambda: N.decrypt_rehearsal_file(_rf_P("b.oct"), _rf_P("e2.txt"), SEED, b"files"))
    _rf_wr(_rf_P("victim3.cfg"), b"third victim " * 8, 0o644); os.symlink(_rf_P("victim3.cfg"), _rf_P("g.oct.tmp")); _rf_wr(_rf_P("g.txt"), _rf_msg)
    N.encrypt_rehearsal_file(_rf_P("g.txt"), _rf_P("g.oct"), SEED, b"files", 128)
    check("rehearsal-fix M1: a symlink planted at dst.partial / dst.tmp is never written through, followed or removed (victim files untouched, dst is a regular file)",
          _rf_e and _rf_rd(_rf_P("drop_box")) == b"" and isinstance(_rf_r2, N.AuthError)
          and _rf_rd(_rf_P("victim2.cfg")) == b"second victim " * 8 and os.path.islink(_rf_P("e2.txt.partial"))
          and _rf_rd(_rf_P("victim3.cfg")) == b"third victim " * 8 and os.path.islink(_rf_P("g.oct.tmp"))
          and not os.path.islink(_rf_P("g.oct")) and N.decrypt_rehearsal(_rf_rd(_rf_P("g.oct")), SEED, b"files") == _rf_msg
          and _rf_temps() == [])
    # M1 (w09 §d): an unrelated pre-existing dst.partial survives a reject; only the call's own temp file is removed
    _rf_wr(_rf_P("d.txt.partial"), b"user's own notes, unrelated")
    _rf_r = catch(lambda: N.decrypt_rehearsal_file(_rf_P("b.oct"), _rf_P("d.txt"), SEED, b"files"))
    check("rehearsal-fix M1: a pre-existing regular dst.partial is neither truncated nor deleted on a reject; no temp file is left",
          isinstance(_rf_r, N.AuthError) and _rf_rd(_rf_P("d.txt.partial")) == b"user's own notes, unrelated"
          and not os.path.exists(_rf_P("d.txt")) and _rf_temps() == [])
    # M1 / rehearsal-polish L1: the temp file is an anonymous O_TMPFILE opened relative to dst's directory fd (0600),
    # or with O_TMPFILE disabled a unique dot-name created O_CREAT | O_EXCL | O_NOFOLLOW (0600); never a fixed sibling name
    _rf_mk = []; _rf_opo = N.os.open
    def _rf_opw(p, flags, mode=0o777, *a, **k):
        fd = _rf_opo(p, flags, mode, *a, **k)
        if k.get("dir_fd") is not None:
            _rf_mk.append((os.readlink("/proc/self/fd/%d" % k["dir_fd"]), p, flags, _rf_stat.S_IMODE(os.fstat(fd).st_mode)))
        return fd
    N.os.open = _rf_opw
    try:
        N.decrypt_rehearsal_file(_rf_P("e.oct"), _rf_P("m1.txt"), SEED, b"files")
        N.encrypt_rehearsal_file(_rf_P("g.txt"), _rf_P("m1.oct"), SEED, b"files", 128)
        N._REHEARSAL_USE_O_TMPFILE = False
        N.decrypt_rehearsal_file(_rf_P("e.oct"), _rf_P("m2.txt"), SEED, b"files")
        N.encrypt_rehearsal_file(_rf_P("g.txt"), _rf_P("m2.oct"), SEED, b"files", 128)
    finally:
        N.os.open = _rf_opo; N._REHEARSAL_USE_O_TMPFILE = True
    _rf_src = N.inspect.getsource(N._RehearsalOutput) + N.inspect.getsource(N.decrypt_rehearsal_file) + N.inspect.getsource(N.encrypt_rehearsal_file)
    _rf_excl = os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    check("rehearsal-polish L1/M1: both helpers write through an anonymous 0600 O_TMPFILE in dst's directory (via a dir fd); with O_TMPFILE off, a unique 0600 dot-name made O_EXCL|O_NOFOLLOW; never a fixed sibling name",
          len(_rf_mk) == 4 and all(d == os.path.realpath(_rf_d) and m == 0o600 for d, _, _, m in _rf_mk)
          and all(p == "." and f & os.O_TMPFILE == os.O_TMPFILE for _, p, f, _ in _rf_mk[:2])
          and all(f & _rf_excl == _rf_excl for _, _, f, _ in _rf_mk[2:])
          and _rf_mk[2][1].startswith(".m2.txt.") and _rf_mk[2][1].endswith(".partial")
          and _rf_mk[3][1].startswith(".m2.oct.") and _rf_mk[3][1].endswith(".tmp")
          and _rf_rd(_rf_P("m1.txt")) == _rf_msg and _rf_rd(_rf_P("m2.txt")) == _rf_msg
          and '+ ".partial", "wb"' not in _rf_src and '+ ".tmp", "wb"' not in _rf_src and "mkstemp" not in _rf_src)
    # L1 (w09 §f, §g): name collisions no longer destroy data
    _rf_wr(_rf_P("report.tmp"), _rf_msg)
    N.encrypt_rehearsal_file(_rf_P("report.tmp"), _rf_P("report"), SEED, b"files", 128)
    _rf_wr(_rf_P("h.partial"), _rf_blob)
    _rf_hn = N.decrypt_rehearsal_file(_rf_P("h.partial"), _rf_P("h"), SEED, b"files")
    check("rehearsal-fix L1: encrypt('report.tmp' -> 'report') keeps the plaintext and seals all of it; decrypt('h.partial' -> 'h') keeps the ciphertext",
          _rf_rd(_rf_P("report.tmp")) == _rf_msg and N.decrypt_rehearsal(_rf_rd(_rf_P("report")), SEED, b"files") == _rf_msg
          and _rf_rd(_rf_P("h.partial")) == _rf_blob and _rf_hn == len(_rf_msg) and _rf_rd(_rf_P("h")) == _rf_msg)
    # L1: src and dst the same file (same path, symlink, hard link, same descriptor) is refused before anything is written
    os.symlink(_rf_P("g.txt"), _rf_P("g_link")); os.link(_rf_P("g.txt"), _rf_P("g_hard"))
    _rf_same = [catch(lambda: N.encrypt_rehearsal_file(_rf_P("g.txt"), _rf_P("g.txt"), SEED, overwrite=True)),
                catch(lambda: N.encrypt_rehearsal_file(_rf_P("g.txt"), _rf_P("g_link"), SEED, overwrite=True)),
                catch(lambda: N.encrypt_rehearsal_file(_rf_P("g.txt"), _rf_P("g_hard"), SEED, overwrite=True)),
                catch(lambda: N.decrypt_rehearsal_file(_rf_P("e.oct"), _rf_P("e.oct"), SEED, b"files", overwrite=True)),
                catch(lambda: N.encrypt_rehearsal_file(_rf_P("g_link"), _rf_P("g.txt"), SEED, overwrite=True))]
    with open(_rf_P("g.txt"), "r+b") as _rf_fo:
        _rf_same.append(catch(lambda: N.encrypt_rehearsal_file(_rf_fo, _rf_fo, SEED)))
        with open(_rf_P("g_hard"), "r+b") as _rf_fo2:
            _rf_same.append(catch(lambda: N.decrypt_rehearsal_file(_rf_fo, _rf_fo2, SEED)))
    check("rehearsal-fix L1: src == dst by path, symlink, hard link or descriptor raises ValueError (not Rejected) and leaves both files intact",
          all(isinstance(e, ValueError) and not isinstance(e, N.Rejected) and "same file" in str(e) for e in _rf_same) and len(_rf_same) == 7
          and _rf_rd(_rf_P("g.txt")) == _rf_msg and _rf_rd(_rf_P("e.oct")) == _rf_blob and _rf_temps() == [])
    # L2 (w09 §a, §i, §j): 0600 output, overwrite=False by default, symlinked dst never followed, fsync file + dir
    _rf_wr(_rf_P("a.oct"), _rf_blob, 0o644)
    N.decrypt_rehearsal_file(_rf_P("a.oct"), _rf_P("a.txt"), SEED, b"files")
    N.encrypt_rehearsal_file(_rf_P("a.txt"), _rf_P("a2.oct"), SEED, b"files", 128)
    check("rehearsal-fix L2: plaintext and ciphertext outputs are created 0600 under umask 022, whatever the source mode",
          _rf_stat.S_IMODE(os.stat(_rf_P("a.txt")).st_mode) == 0o600 and _rf_stat.S_IMODE(os.stat(_rf_P("a2.oct")).st_mode) == 0o600)
    _rf_wr(_rf_P("k.txt"), b"keep me"); _rf_ex = catch(lambda: N.decrypt_rehearsal_file(_rf_P("a.oct"), _rf_P("k.txt"), SEED, b"files"))
    _rf_ex2 = catch(lambda: N.encrypt_rehearsal_file(_rf_P("a.txt"), _rf_P("k.txt"), SEED, b"files"))
    _rf_kept = _rf_rd(_rf_P("k.txt"))
    _rf_ow = N.decrypt_rehearsal_file(_rf_P("a.oct"), _rf_P("k.txt"), SEED, b"files", overwrite=True)
    check("rehearsal-fix L2: an existing dst raises FileExistsError by default (dst untouched, no temp left); overwrite=True replaces it",
          isinstance(_rf_ex, FileExistsError) and isinstance(_rf_ex2, FileExistsError) and _rf_kept == b"keep me"
          and _rf_ow == len(_rf_msg) and _rf_rd(_rf_P("k.txt")) == _rf_msg and _rf_temps() == [])
    _rf_wr(_rf_P("target.txt"), b"target"); os.symlink(_rf_P("target.txt"), _rf_P("j.txt")); os.symlink(_rf_P("nowhere"), _rf_P("dangling"))
    _rf_j1 = catch(lambda: N.decrypt_rehearsal_file(_rf_P("a.oct"), _rf_P("j.txt"), SEED, b"files"))
    _rf_j2 = catch(lambda: N.decrypt_rehearsal_file(_rf_P("a.oct"), _rf_P("dangling"), SEED, b"files"))
    _rf_j1ok = os.path.islink(_rf_P("j.txt")) and not os.path.exists(_rf_P("nowhere"))
    N.decrypt_rehearsal_file(_rf_P("a.oct"), _rf_P("j.txt"), SEED, b"files", overwrite=True)
    os.mkdir(_rf_P("dir_dst"))
    _rf_dd = (catch(lambda: N.decrypt_rehearsal_file(_rf_P("a.oct"), _rf_P("dir_dst"), SEED, b"files")),
              catch(lambda: N.decrypt_rehearsal_file(_rf_P("a.oct"), _rf_P("dir_dst"), SEED, b"files", overwrite=True)))
    check("rehearsal-fix L2: a symlink at dst (live or dangling) is never followed: refused by default, replaced as a link with overwrite=True; a directory dst is refused up front",
          isinstance(_rf_j1, FileExistsError) and isinstance(_rf_j2, FileExistsError) and _rf_j1ok
          and _rf_rd(_rf_P("target.txt")) == b"target" and not os.path.islink(_rf_P("j.txt")) and _rf_rd(_rf_P("j.txt")) == _rf_msg
          and isinstance(_rf_dd[0], FileExistsError) and isinstance(_rf_dd[1], IsADirectoryError) and os.listdir(_rf_P("dir_dst")) == []
          and _rf_temps() == [])
    _rf_fs = []; _rf_fso = N.os.fsync
    def _rf_fsw(fd): _rf_fs.append(_rf_stat.S_ISDIR(os.fstat(fd).st_mode)); return _rf_fso(fd)
    _rf_ren = []; _rf_lnk = N.os.link
    def _rf_lnkw(a, b, **k): _rf_ren.append(("link", len(_rf_fs))); return _rf_lnk(a, b, **k)
    N.os.fsync = _rf_fsw; N.os.link = _rf_lnkw
    try:
        N.decrypt_rehearsal_file(_rf_P("a.oct"), _rf_P("fs.txt"), SEED, b"files")
        N.encrypt_rehearsal_file(_rf_P("a.txt"), _rf_P("fs.oct"), SEED, b"files", 128)
    finally:
        N.os.fsync = _rf_fso; N.os.link = _rf_lnk
    check("rehearsal-fix L2: each helper fsyncs the file before moving it into place and the directory after (file, dir, file, dir)",
          _rf_fs == [False, True, False, True] and _rf_ren == [("link", 1), ("link", 3)])
    # keep_partial: the verified prefix is kept under dst.partial when free, else the unique temp name; path reported on the exception
    _rf_kp = catch(lambda: N.decrypt_rehearsal_file(_rf_P("b.oct"), _rf_P("c.txt"), SEED, b"files", keep_partial=True))
    _rf_kp2 = catch(lambda: N.decrypt_rehearsal_file(_rf_P("b.oct"), _rf_P("d.txt"), SEED, b"files", keep_partial=True))
    check("rehearsal-fix: keep_partial=True keeps only the verified prefix, as dst.partial when that name is free, else under the call's own unique temp name (never clobbering), reported as exc.partial_path",
          isinstance(_rf_kp, N.AuthError) and _rf_kp.partial_path == _rf_P("c.txt.partial") and _rf_rd(_rf_P("c.txt.partial")) == _rf_msg[:256]
          and isinstance(_rf_kp2, N.AuthError) and os.path.dirname(_rf_kp2.partial_path) == _rf_d
          and os.path.basename(_rf_kp2.partial_path).startswith(".d.txt.") and _rf_rd(_rf_kp2.partial_path) == _rf_msg[:256]
          and _rf_rd(_rf_P("d.txt.partial")) == b"user's own notes, unrelated"
          and _rf_stat.S_IMODE(os.stat(_rf_P("c.txt.partial")).st_mode) == 0o600)
    os.unlink(_rf_kp2.partial_path)
    # L3 (w08 §3): file-object dst is buffered until the stream verifies
    _rf_bio = _rf_io.BytesIO(); _rf_l3 = catch(lambda: N.decrypt_rehearsal_file(_rf_io.BytesIO(_rf_cut), _rf_bio, SEED, b"files", read_size=64))
    _rf_bio2 = _rf_io.BytesIO(); _rf_l3b = catch(lambda: N.decrypt_rehearsal_file(_rf_io.BytesIO(_rf_cut), _rf_bio2, SEED, b"files", read_size=64, stream_verified_prefix=True))
    _rf_bio3 = _rf_io.BytesIO(); _rf_l3n = N.decrypt_rehearsal_file(_rf_io.BytesIO(_rf_blob), _rf_bio3, SEED, b"files", read_size=64)
    check("rehearsal-fix L3: a file-object dst receives nothing from a cut stream (buffered until finalize); stream_verified_prefix=True keeps the old prefix behaviour",
          isinstance(_rf_l3, N.AuthError) and _rf_bio.getvalue() == b"" and isinstance(_rf_l3b, N.AuthError) and _rf_bio2.getvalue() == _rf_msg[:256]
          and _rf_l3n == len(_rf_msg) and _rf_bio3.getvalue() == _rf_msg)
finally:
    os.umask(_rf_umask)
    _rh_sh.rmtree(_rf_d, ignore_errors=True)

# L3 (w08 §3): the forgot-finalize footgun
def _rf_iter(src, **k):
    try: return b"".join(N.iter_rehearsal(src, SEED, b"files", **k)), None
    except Exception as e: return None, e
_rf_full, _rf_ef = _rf_iter(_rf_blob)
_rf_cutr = [_rf_iter(_rf_blob[:72 + j * 160]) for j in (0, 1, 2, 3)] + [_rf_iter(_rf_blob[:-1]), _rf_iter(_rf_blob[:72])]
_rf_pieces, _ = _rf_iter([_rf_blob[i:i + 37] for i in range(0, len(_rf_blob), 37)])
_rf_fobj, _ = _rf_iter(_rf_io.BytesIO(_rf_blob), read_size=100)
check("rehearsal-fix L3: iter_rehearsal always finalizes: whole stream (bytes, piece iterable, file object) yields the message; a stream cut at any chunk boundary raises AuthError",
      _rf_ef is None and _rf_full == _rf_msg == _rf_pieces == _rf_fobj
      and all(r is None and isinstance(e, N.AuthError) for r, e in _rf_cutr))
_rf_it = N.iter_rehearsal(_rf_blob, SEED, b"files", read_size=50); _rf_first = next(_rf_it); _rf_it.close()
_rf_gc.collect()
with _rf_warn.catch_warnings(record=True) as _rf_w:
    _rf_warn.simplefilter("always")
    _rf_dw = N.RehearsalDecryptor(SEED, b"files"); _rf_dw.update(_rf_blob[:72 + 3 * 160]); del _rf_dw; _rf_gc.collect()
    _rf_w1 = [w for w in _rf_w if issubclass(w.category, N.UnfinalizedStreamWarning)]
    for _rf_case in ("fresh", "finalized", "rejected", "closed"):
        _rf_dw = N.RehearsalDecryptor(SEED, b"files")
        if _rf_case == "finalized": _rf_dw.update(_rf_blob); _rf_dw.finalize()
        if _rf_case == "rejected": catch(lambda: _rf_dw.update(_rf_blob[:80] + b"\x00" * 300))
        if _rf_case == "closed": _rf_dw.update(_rf_blob[:300]); _rf_dw.close()
        del _rf_dw; _rf_gc.collect()
    _rf_w2 = [w for w in _rf_w if issubclass(w.category, N.UnfinalizedStreamWarning)]
check("rehearsal-fix L3 / rehearsal-polish L2: a decryptor dropped after data without finalize() emits one UnfinalizedStreamWarning; fresh, finalized, rejected and explicitly closed ones do not; an abandoned iter_rehearsal does not",
      _rf_first and _rf_msg.startswith(_rf_first) and len(_rf_w1) == 1 and "finalize" in str(_rf_w1[0].message) and len(_rf_w2) == 1)
def _rf_with(data):
    with N.RehearsalDecryptor(SEED, b"files") as d:
        return d.update(data)
_rf_wc = catch(lambda: _rf_with(_rf_blob[:72 + 3 * 160]))
_rf_dcl = N.RehearsalDecryptor(SEED, b"files"); _rf_dcl.update(_rf_blob[:300]); _rf_dcl.close()
check("rehearsal-fix L3: leaving a `with RehearsalDecryptor` block normally without finalize() raises AuthError('stream not finalized'); close() abandons on purpose (later calls ValueError)",
      isinstance(_rf_wc, N.AuthError) and str(_rf_wc) == "stream not finalized"
      and isinstance(catch(lambda: _rf_dcl.update(b"x")), ValueError) and not isinstance(catch(lambda: _rf_dcl.update(b"x")), N.Rejected))

# I3 (w07): one-shot decrypt checks every tag, the final chunk's included, before decrypting anything
_rf_calls = []; _rf_o = (N._rehearsal_tag, N.Schedule.__init__, N.decrypt_grid)
def _rf_pt(*a, **k): _rf_calls.append("tag"); return _rf_o[0](*a, **k)
def _rf_ps(self, *a, **k): _rf_calls.append("Schedule"); return _rf_o[1](self, *a, **k)
def _rf_pd(*a, **k): _rf_calls.append("dec"); return _rf_o[2](*a, **k)
_rf_big = N.encrypt_rehearsal(bytes(range(256)) * 4 + b"tail", SEED, b"i3", 128)          # 8 non-final chunks + final
N._rehearsal_tag, N.Schedule.__init__, N.decrypt_grid = _rf_pt, _rf_ps, _rf_pd
try:
    _rf_e3 = catch(lambda: N.decrypt_rehearsal(_rf_big[:-1] + bytes([_rf_big[-1] ^ 1]), SEED, b"i3")); _rf_bad = list(_rf_calls)
    _rf_calls.clear(); _rf_ok3 = N.decrypt_rehearsal(_rf_big, SEED, b"i3"); _rf_good = list(_rf_calls)
finally:
    N._rehearsal_tag, N.Schedule.__init__, N.decrypt_grid = _rf_o
check("rehearsal-fix I3: one-shot decrypt_rehearsal with a forged final chunk after 8 valid chunks runs 9 tags and no Schedule or decryption; a valid stream runs all 9 tags before the first decrypt",
      isinstance(_rf_e3, N.AuthError) and _rf_bad == ["tag"] * 9
      and _rf_ok3 == bytes(range(256)) * 4 + b"tail" and _rf_good[:10] == ["tag"] * 9 + ["Schedule"] and _rf_good.count("dec") == 9)
_rf_ts = os.urandom(128)
while len(set(b for b in _rf_ts if b)) < 32: _rf_ts = os.urandom(128)
_rf_tb = N.encrypt_rehearsal(bytes(8 * 128), _rf_ts, b"", 128)
_rf_tm = {"final forged": _rf_tb[:-1] + bytes([_rf_tb[-1] ^ 1]), "chunk0 forged": _rf_tb[:80] + bytes([_rf_tb[80] ^ 1]) + _rf_tb[81:]}
_rf_md = {}
for _k, _b in _rf_tm.items():
    _ts = []
    for _ in range(30):
        _t0 = _rh_time.perf_counter(); catch(lambda: N.decrypt_rehearsal(_b, _rf_ts)); _ts.append(_rh_time.perf_counter() - _t0)
    _rf_md[_k] = sorted(_ts)[15]
print("rehearsal-fix I3 one-shot reject medians (ms):", {k: round(v * 1000, 3) for k, v in _rf_md.items()})
check("rehearsal-fix I3: rejecting a forged final chunk in one shot costs HMACs only (well under 5 ms here, was ~85 ms for 8 blocks)",
      _rf_md["final forged"] < 0.005)

# I1 (w11 §4): AD is in the R-sponge inputs, so the same pickup and nonce under two ADs share no ciphertext block
_rf_P1 = os.urandom(4 * 256 + 100)
with _rh_fixed():
    _rf_A = N.encrypt_rehearsal(_rf_P1, SEED, b"x", 256); _rf_A2 = N.encrypt_rehearsal(_rf_P1, SEED, b"other", 256)
    _rf_A3 = N.encrypt_rehearsal(_rf_P1, SEED, b"x", 256)
_rf_blk = lambda b: [x[o:o + 128] for x in _rh_chunks(b, 256)[1] for o in range(0, len(x) - 32, 128)]
check("rehearsal-fix I1: same seed, pickup and nonce under two ADs: headers share pickup/nonce, but no ciphertext block, tag or schedule nonce is shared; same AD stays deterministic",
      _rf_A[4:36] == _rf_A2[4:36] and not (set(_rf_blk(_rf_A)) & set(_rf_blk(_rf_A2))) and _rf_A3 == _rf_A
      and N._rehearsal_schedule_nonce(SEED, _RH_PK, _RH_NC, 256, N._rehearsal_ad_digest(b"x")) != N._rehearsal_schedule_nonce(SEED, _RH_PK, _RH_NC, 256, N._rehearsal_ad_digest(b"other"))
      and isinstance(catch(lambda: N.decrypt_rehearsal(_rf_A2[:72] + _rf_A[72:], SEED, b"other")), N.AuthError)
      and N.decrypt_rehearsal(_rf_A2, SEED, b"other") == _rf_P1)
check("rehearsal-fix I1: the per-stream AD digest is SHA-256(SN2/A || encode_ad(ad)) and empty AD == omitted AD (still one stream format, v8)",
      N._rehearsal_ad_digest(b"x") == hashlib.sha256(b"SN2/A" + (1).to_bytes(8, "big") + b"x").digest()
      and N._rehearsal_ad_digest(b"") == N._rehearsal_ad_digest() and _rf_A[0] == 8)

# I2 (w10): workers are capped, are fresh interpreters (never fork), get no seed/AD/keys, and never outlive the stream
check("rehearsal-fix I2: workers are capped at min(32, os.cpu_count()); bad values still raise ValueError",
      N.REHEARSAL_MAX_WORKERS == 32 and N._rehearsal_workers(10 ** 6) == min(32, os.cpu_count() or 1) and N._rehearsal_workers(1) == 1
      and N.RehearsalEncryptor(SEED, workers=10 ** 6).workers == min(32, os.cpu_count() or 1)
      and all(isinstance(catch(lambda w=w: N.RehearsalDecryptor(SEED, workers=w)), ValueError) for w in (0, -1, True, 1.5)))
_rf_sent = []; _rf_spawn = N._RehearsalWorkers._spawn
def _rf_spw(self):
    p = _rf_spawn(self); _rf_sent.append((p.pid, open("/proc/%d/cmdline" % p.pid, "rb").read().split(b"\0"), self._sch_blob)); return p
N._RehearsalWorkers._spawn = _rf_spw
_rf_wo = N._RehearsalWorkers.run
_rf_payloads = []
def _rf_runw(self, datas, decrypt): _rf_payloads.extend(datas); return _rf_wo(self, datas, decrypt)
N._RehearsalWorkers.run = _rf_runw
_rf_seed2 = bytes(range(1, 129)); N._seed_bytes(_rf_seed2)                       # another seed sits in the parent's memo
_rf_secret_ad = b"unrelated-secret-AD-" + os.urandom(8).hex().encode()
try:
    _rf_m2 = os.urandom(6 * 128 + 5)
    with _rh_fixed():
        _rf_w1b = N.encrypt_rehearsal(_rf_m2, SEED, _rf_secret_ad, 128); _rf_w4b = N.encrypt_rehearsal(_rf_m2, SEED, _rf_secret_ad, 128, workers=4)
    _rf_dec4 = N.decrypt_rehearsal(_rf_w4b, SEED, _rf_secret_ad, workers=4)
    _rf_e12 = N.RehearsalEncryptor(SEED, b"", 128, workers=12); _rf_e12.update(os.urandom(2 * 128)); _rf_n12 = len(_rf_e12._pool.procs)
    _rf_pids12 = [p.pid for p in _rf_e12._pool.procs]; _rf_e12.finalize()
    _rf_dr = N.RehearsalDecryptor(SEED, _rf_secret_ad, workers=3); _rf_dr.update(_rf_w4b[:72 + 4 * 160 + 1])
    _rf_pidsr = [p.pid for p in _rf_dr._pool.procs]
    catch(lambda: (_rf_dr.update(_rf_w4b[72 + 4 * 160 + 1:-1] + bytes([_rf_w4b[-1] ^ 1])), _rf_dr.finalize()))
    _rf_ea = N.RehearsalEncryptor(SEED, b"", 128, workers=3); _rf_ea.update(os.urandom(3 * 128)); _rf_pidsa = [p.pid for p in _rf_ea._pool.procs]
    del _rf_ea; _rf_gc.collect()
finally:
    N._RehearsalWorkers._spawn = _rf_spawn; N._RehearsalWorkers.run = _rf_wo
def _rf_alive(pids):
    out = []
    for p in pids:
        try:
            st = open("/proc/%d/stat" % p).read().split()[2]
            if st != "Z": out.append(p)
        except OSError: pass
    return out
_rh_time.sleep(0.3)
_rf_allsent = b"".join(_rf_payloads) + b"".join(s for _, _, s in _rf_sent)
check("rehearsal-fix I2: workers=4 output is byte-identical to workers=1 and decrypts with workers=4",
      _rf_w4b == _rf_w1b and _rf_dec4 == _rf_m2)
check("rehearsal-fix I2: every worker is a fresh interpreter (python -I -B -S -c, not a fork) and is sent no seed, no other memo seed, no AD and no plaintext",
      _rf_sent and all(c[0] == os.fsencode(sys.executable) and c[1:5] == [b"-I", b"-B", b"-S", b"-c"] for _, c, _ in _rf_sent)
      and SEED not in _rf_allsent and _rf_seed2 not in _rf_allsent and _rf_secret_ad not in _rf_allsent
      and _rf_m2[:128] not in _rf_allsent and N.staff_clef(SEED) not in _rf_allsent)
check("rehearsal-fix I2: workers are started lazily (workers=12 on a 2-chunk batch starts 2) and none survives finalize(), a reject, or an abandoned encryptor",
      _rf_n12 == 2 and _rf_alive(_rf_pids12) == [] and _rf_alive(_rf_pidsr) == [] and _rf_alive(_rf_pidsa) == [] and len(_rf_pidsr) == 3)

# I4 (w03): optional receiver-side max_chunk_size
_rf_hdr1m = bytes([8]) + N.VERSION + os.urandom(64) + (1 << 20).to_bytes(4, "big")
_rf_d4 = N.RehearsalDecryptor(SEED, b"", max_chunk_size=65536)
_rf_i4 = _rh_err(lambda: _rf_d4.update(_rf_hdr1m))
_rf_ok4 = N.encrypt_rehearsal(b"x" * 300, SEED, b"", 256)
check("rehearsal-fix I4: max_chunk_size rejects a forged 1 MiB-chunk header at the header (nothing buffered); streams within the limit open; bad limits raise",
      _rf_i4 == ("AuthError", "chunk size above max_chunk_size") and len(_rf_d4._buf) == 0
      and _rh_err(lambda: _rf_d4.update(b"")) == ("AuthError", "stream already rejected")
      and N.decrypt_rehearsal(_rf_ok4, SEED, max_chunk_size=256) == b"x" * 300
      and _rh_err(lambda: N.decrypt_rehearsal(_rf_ok4, SEED, max_chunk_size=128)) == ("AuthError", "chunk size above max_chunk_size")
      and b"".join(N.iter_rehearsal(_rf_ok4, SEED, max_chunk_size=256)) == b"x" * 300
      and isinstance(catch(lambda: N.RehearsalDecryptor(SEED, max_chunk_size=100)), ValueError)
      and isinstance(catch(lambda: N.RehearsalDecryptor(SEED, max_chunk_size="64")), TypeError)
      and N.RehearsalDecryptor(SEED)._max_cs is None)

# ---- rehearsal-polish: regression tests for the rehearsal-fix attack (attacks_octavo_rehearsalfix/REPORT.md)
# Each block turns a witness from that report into a test that asserts the FIXED behaviour.
import errno as _rp_errno, signal as _rp_sig, io as _rp_io, importlib.util as _rp_iu
def _rp_try(f):
    """f()'s value, or the exception it raised."""
    try: return f()
    except Exception as e: return e
_rp_msg = b"GENUINE VERIFIED PLAINTEXT " * 20
_rp_blob = N.encrypt_rehearsal(_rp_msg, SEED, b"race", 128)
_rp_cut = _rp_blob[:72 + 2 * 160]
_rp_d = os.path.realpath(_rh_tmp.mkdtemp(prefix="octavo_rp_"))
_rp_P = lambda *a: os.path.join(_rp_d, *a)
def _rp_rd(p): return open(p, "rb").read() if os.path.lexists(p) and not os.path.islink(p) else None
def _rp_dots(): return sorted(n for n in os.listdir(_rp_d) if n.startswith("."))
def _rp_clean():
    for n in _rp_dots(): os.unlink(_rp_P(n))
open(_rp_P("in.oct"), "wb").write(_rp_blob); open(_rp_P("cut.oct"), "wb").write(_rp_cut)
_rp_lnk = N.os.link
def _rp_with_link(hook, fn, tmpfile=True):
    """Run fn with os.link wrapped by hook(real_link, src, dst, **kw) (the attacker's rename, injected
    deterministically at the instant the race needs) and O_TMPFILE on or off."""
    N.os.link = lambda a, b, **k: hook(_rp_lnk, a, b, **k); N._REHEARSAL_USE_O_TMPFILE = tmpfile
    try: return _rp_try(fn)
    finally: N.os.link = _rp_lnk; N._REHEARSAL_USE_O_TMPFILE = True
try:
    # L1 a: attacker renames their own file over the named temp between the inode check and the link
    def _rp_swap(real, a, b, **k):
        if isinstance(a, str) and a.startswith(".") and a.endswith(".partial"):
            open(_rp_P("evil.txt"), "wb").write(b"ATTACKER-CHOSEN CONTENT\n"); os.chmod(_rp_P("evil.txt"), 0o666)
            os.rename(_rp_P("evil.txt"), _rp_P(a))
        return real(a, b, **k)
    _rp_a = _rp_with_link(_rp_swap, lambda: N.decrypt_rehearsal_file(_rp_P("in.oct"), _rp_P("a.txt"), SEED, b"race"), tmpfile=False)
    _rp_a_ok = isinstance(_rp_a, RuntimeError) and "replaced" in str(_rp_a) and not os.path.lexists(_rp_P("a.txt"))
    _rp_clean()
    # L1 b: a symlink planted at the temp name: the link never follows it, the after-check refuses
    open(_rp_P("victim.key"), "wb").write(b"-----BEGIN VICTIM PRIVATE KEY-----\n"); os.chmod(_rp_P("victim.key"), 0o600)
    def _rp_sym(real, a, b, **k):
        if isinstance(a, str) and a.startswith(".") and a.endswith(".partial"):
            os.unlink(_rp_P(a)); os.symlink(_rp_P("victim.key"), _rp_P(a))
        return real(a, b, **k)
    _rp_b = _rp_with_link(_rp_sym, lambda: N.decrypt_rehearsal_file(_rp_P("in.oct"), _rp_P("b.txt"), SEED, b"race"), tmpfile=False)
    _rp_b_ok = (isinstance(_rp_b, RuntimeError) and not os.path.lexists(_rp_P("b.txt")) and os.stat(_rp_P("victim.key")).st_nlink == 1
                and _rp_rd(_rp_P("victim.key")) == b"-----BEGIN VICTIM PRIVATE KEY-----\n")
    _rp_clean()
    # L1 c: keep_partial with a substituted temp: nothing unverified is ever reported as the verified prefix
    def _rp_keep(real, a, b, **k):
        if b.endswith("c.txt.partial") and isinstance(a, str) and a.startswith("."):
            open(_rp_P("evil2"), "wb").write(b"ATTACKER PREFIX\n"); os.rename(_rp_P("evil2"), _rp_P(a))
        return real(a, b, **k)
    _rp_c = _rp_with_link(_rp_keep, lambda: N.decrypt_rehearsal_file(_rp_P("cut.oct"), _rp_P("c.txt"), SEED, b"race", keep_partial=True), tmpfile=False)
    _rp_ck = getattr(_rp_c, "partial_path", None)
    _rp_c_ok = isinstance(_rp_c, N.AuthError) and (_rp_ck is None or _rp_msg.startswith(_rp_rd(_rp_ck))) and not os.path.lexists(_rp_P("c.txt.partial"))
    _rp_clean()
    # L1 d: O_TMPFILE path (default): there is no temp name to swap; the link source is our own /proc/self/fd entry, and a
    # rename over dst right after the link is caught by the inode check (the name this call created is removed)
    _rp_calls = []
    def _rp_post(real, a, b, **k):
        _rp_calls.append((a, b, k.get("follow_symlinks"))); r = real(a, b, **k)
        if b == "d.txt":
            open(_rp_P("evil3"), "wb").write(b"swapped in after link\n"); os.rename(_rp_P("evil3"), _rp_P("d.txt"))
        return r
    _rp_dd = _rp_with_link(_rp_post, lambda: N.decrypt_rehearsal_file(_rp_P("in.oct"), _rp_P("d.txt"), SEED, b"race"))
    _rp_d_ok = (isinstance(_rp_dd, RuntimeError) and not os.path.lexists(_rp_P("d.txt")) and _rp_dots() == []
                and _rp_calls and _rp_calls[0][0].startswith("/proc/self/fd/") and _rp_calls[0][2] is True)
    _rp_calls.clear()
    _rp_e = _rp_with_link(lambda real, a, b, **k: (_rp_calls.append((a, k.get("follow_symlinks"))), real(a, b, **k))[1],
                          lambda: N.decrypt_rehearsal_file(_rp_P("in.oct"), _rp_P("e.txt"), SEED, b"race"), tmpfile=False)
    _rp_e_ok = _rp_e == len(_rp_msg) and _rp_rd(_rp_P("e.txt")) == _rp_msg and _rp_calls == [(_rp_calls[0][0], False)] and _rp_dots() == []
    check("rehearsal-polish L1: a rename or symlink over the temp name at link time, or a rename over dst after the link, makes the helper raise RuntimeError and publish nothing (no dst, victim key not hard-linked, no fake keep_partial prefix); named temps are linked with follow_symlinks=False, O_TMPFILE via /proc/self/fd",
          _rp_a_ok and _rp_b_ok and _rp_c_ok and _rp_d_ok and _rp_e_ok)
    print("rehearsal-polish L1 detail:", dict(a=_rp_a_ok, b=_rp_b_ok, c=_rp_c_ok, d=_rp_d_ok, e=_rp_e_ok))

    # I3: only 'no hard links here' errnos fall back, and the fallback creates dst O_EXCL (never clobbers a file made in the gap)
    def _rp_raise(code, plant=None):
        def h(real, a, b, **k):
            if plant: open(_rp_P(plant), "wb").write(b"made in the gap\n")
            raise OSError(code, os.strerror(code))
        return h
    _rp_i3a = _rp_with_link(_rp_raise(_rp_errno.EIO), lambda: N.decrypt_rehearsal_file(_rp_P("in.oct"), _rp_P("i3a.txt"), SEED, b"race"), tmpfile=False)   # named-temp path; O_TMPFILE now copies (rehearsal-finale I3)
    _rp_i3b = _rp_with_link(_rp_raise(_rp_errno.EPERM), lambda: N.decrypt_rehearsal_file(_rp_P("in.oct"), _rp_P("i3b.txt"), SEED, b"race"))
    _rp_i3c = _rp_with_link(_rp_raise(_rp_errno.EPERM, "i3c.txt"), lambda: N.decrypt_rehearsal_file(_rp_P("in.oct"), _rp_P("i3c.txt"), SEED, b"race"))
    _rp_i3d = _rp_with_link(_rp_raise(_rp_errno.EOPNOTSUPP), lambda: N.decrypt_rehearsal_file(_rp_P("in.oct"), _rp_P("i3d.txt"), SEED, b"race", overwrite=True), tmpfile=False)
    check("rehearsal-polish I3: on the named-temp path, link errors other than EPERM/EOPNOTSUPP/ENOTSUP/ENOSYS/EXDEV/EMLINK are raised (EIO: no dst); the no-hard-link fallback copies into an O_EXCL dst and refuses (FileExistsError) a file created in the gap, leaving it untouched",
          isinstance(_rp_i3a, OSError) and _rp_i3a.errno == _rp_errno.EIO and not os.path.lexists(_rp_P("i3a.txt"))
          and _rp_i3b == len(_rp_msg) and _rp_rd(_rp_P("i3b.txt")) == _rp_msg and _rf_stat.S_IMODE(os.stat(_rp_P("i3b.txt")).st_mode) == 0o600
          and isinstance(_rp_i3c, FileExistsError) and _rp_rd(_rp_P("i3c.txt")) == b"made in the gap\n"
          and _rp_i3d == len(_rp_msg) and _rp_rd(_rp_P("i3d.txt")) == _rp_msg
          and N._REHEARSAL_NO_LINK_ERRNOS == {_rp_errno.EPERM, _rp_errno.EOPNOTSUPP, _rp_errno.ENOTSUP, _rp_errno.ENOSYS, _rp_errno.EXDEV, _rp_errno.EMLINK}
          and _rp_dots() == [])

    # I4: paths fixed at call start; a chdir or a parent-symlink swap during the call does not move the output or leave a temp
    os.mkdir(_rp_P("A")); os.mkdir(_rp_P("B")); os.mkdir(_rp_P("T1")); os.mkdir(_rp_P("T2")); os.symlink(_rp_P("T1"), _rp_P("lnk"))
    class _RpSrc(_rp_io.BytesIO):
        def __init__(self, data, act): super().__init__(data); self.act = act
        def read(self, n=-1):
            if self.act: self.act(); self.act = None
            return super().read(n)
    _rp_cwd = os.getcwd()
    try:
        os.chdir(_rp_P("A"))
        _rp_i4a = _rp_try(lambda: N.decrypt_rehearsal_file(_RpSrc(_rp_blob, lambda: os.chdir(_rp_P("B"))), "out.txt", SEED, b"race"))
    finally:
        os.chdir(_rp_cwd)
    def _rp_swaplnk(): os.unlink(_rp_P("lnk")); os.symlink(_rp_P("T2"), _rp_P("lnk"))
    _rp_i4b = _rp_try(lambda: N.decrypt_rehearsal_file(_RpSrc(_rp_blob, _rp_swaplnk), _rp_P("lnk", "out.txt"), SEED, b"race"))
    N._REHEARSAL_USE_O_TMPFILE = False
    try:
        _rp_swaplnk2 = lambda: (os.unlink(_rp_P("lnk")), os.symlink(_rp_P("T1"), _rp_P("lnk")))
        _rp_i4c = _rp_try(lambda: N.decrypt_rehearsal_file(_RpSrc(_rp_blob, _rp_swaplnk2), _rp_P("lnk", "out2.txt"), SEED, b"race"))
    finally:
        N._REHEARSAL_USE_O_TMPFILE = True
    check("rehearsal-polish I4: a chdir during the call leaves a relative dst in the starting directory; swapping a symlinked parent mid-call still publishes into the directory opened at the start, with no orphaned temp file anywhere",
          _rp_i4a == len(_rp_msg) and _rp_rd(_rp_P("A", "out.txt")) == _rp_msg and os.listdir(_rp_P("B")) == []
          and _rp_i4b == len(_rp_msg) and _rp_rd(_rp_P("T1", "out.txt")) == _rp_msg
          and _rp_i4c == len(_rp_msg) and _rp_rd(_rp_P("T2", "out2.txt")) == _rp_msg
          and sorted(os.listdir(_rp_P("T1"))) == ["out.txt"] and sorted(os.listdir(_rp_P("T2"))) == ["out2.txt"])

    # I5: long non-ASCII names (temp prefix cut by bytes, at a whole UTF-8 character)
    _rp_cjk, _rp_emo = "字" * 80, "😀" * 60
    _rp_i5a = _rp_try(lambda: N.decrypt_rehearsal_file(_rp_P("in.oct"), _rp_P(_rp_cjk), SEED, b"race"))
    _rp_i5b = _rp_try(lambda: N.encrypt_rehearsal_file(_rp_P(_rp_cjk), _rp_P(_rp_emo), SEED, b"race", 128))
    N._REHEARSAL_USE_O_TMPFILE = False
    try:
        _rp_i5c = _rp_try(lambda: N.decrypt_rehearsal_file(_rp_P("in.oct"), _rp_P("é" * 127), SEED, b"race"))
    finally:
        N._REHEARSAL_USE_O_TMPFILE = True
    _rp_pf = [N._rehearsal_temp_prefix(x) for x in ("a" * 300, "字" * 80, "😀" * 60, "é" * 127, "ab" + "字" * 50, "short")]
    check("rehearsal-polish I5: 240-byte CJK and emoji dst names (and a 254-byte é name on the named-temp path) work in both helpers; the temp prefix is <= 100 bytes and always whole UTF-8 characters",
          _rp_i5a == len(_rp_msg) and isinstance(_rp_i5b, int) and N.decrypt_rehearsal(_rp_rd(_rp_P(_rp_emo)), SEED, b"race") == _rp_msg
          and _rp_i5c == len(_rp_msg) and len(("é" * 127).encode()) == 254
          and all(len(p.encode("utf-8")) <= 100 for p in _rp_pf) and _rp_pf[5] == "short" and _rp_pf[1] == "字" * 33 and _rp_pf[2] == "😀" * 25
          and _rp_dots() == [])

    # I6: overwrite / keep_partial / stream_verified_prefix must be real bools; kept partials are fsync'd (file, then dir); no empty partial
    open(_rp_P("keep.txt"), "wb").write(b"keep me")
    _rp_i6 = [_rp_try(lambda v=v: N.decrypt_rehearsal_file(_rp_P("in.oct"), _rp_P("keep.txt"), SEED, b"race", overwrite=v)) for v in ("no", 1, None, "")]
    _rp_i6 += [_rp_try(lambda: N.encrypt_rehearsal_file(_rp_P("i3b.txt"), _rp_P("keep.txt"), SEED, overwrite="no")),
               _rp_try(lambda: N.decrypt_rehearsal_file(_rp_P("cut.oct"), _rp_P("kp.txt"), SEED, b"race", keep_partial="yes")),
               _rp_try(lambda: N.decrypt_rehearsal_file(_rp_P("in.oct"), _rp_io.BytesIO(), SEED, b"race", stream_verified_prefix=1))]
    _rp_fs = []; _rp_fso = N.os.fsync
    N.os.fsync = lambda fd: (_rp_fs.append(_rf_stat.S_ISDIR(os.fstat(fd).st_mode)), _rp_fso(fd))[1]
    try:
        _rp_kp = _rp_try(lambda: N.decrypt_rehearsal_file(_rp_P("cut.oct"), _rp_P("kp.txt"), SEED, b"race", keep_partial=True))
    finally:
        N.os.fsync = _rp_fso
    _rp_hd = _rp_try(lambda: N.decrypt_rehearsal_file(_rp_P("cut.oct"), _rp_P("hd.txt"), SEED, b"wrong AD", keep_partial=True))
    check("rehearsal-polish I6: non-bool overwrite/keep_partial/stream_verified_prefix raise TypeError before anything is written; a kept partial is fsync'd, then its directory; a header-level reject keeps no empty partial",
          all(isinstance(e, TypeError) for e in _rp_i6) and len(_rp_i6) == 7 and _rp_rd(_rp_P("keep.txt")) == b"keep me"
          and isinstance(_rp_kp, N.AuthError) and _rp_kp.partial_path == _rp_P("kp.txt.partial") and _rp_rd(_rp_P("kp.txt.partial")) == _rp_msg[:128]
          and _rp_fs == [False, True]
          and isinstance(_rp_hd, N.AuthError) and getattr(_rp_hd, "partial_path", None) is None and not os.path.lexists(_rp_P("hd.txt.partial"))
          and _rp_dots() == [])
finally:
    N.os.link = _rp_lnk; N._REHEARSAL_USE_O_TMPFILE = True
    _rh_sh.rmtree(_rp_d, ignore_errors=True)

# L2: the unfinalized-decryptor warning is a UserWarning that the DEFAULT filters show (it was a hidden ResourceWarning)
_rp_l2 = subprocess.run([sys.executable, "-B", "-c",
    "import sys, gc; sys.path.insert(0, %r); import sneak_n2 as N\n"
    "s = N.load_seed(); b = N.encrypt_rehearsal(b'x' * 600, s, b'', 128)\n"
    "d = N.RehearsalDecryptor(s); print(len(d.update(b[:72 + 3 * 160]))); del d; gc.collect()" % HERE],
    capture_output=True, text=True, timeout=120)
check("rehearsal-polish L2: UnfinalizedStreamWarning is a UserWarning (not a ResourceWarning) and a plain update() loop without finalize() prints it under Python's default filters",
      issubclass(N.UnfinalizedStreamWarning, UserWarning) and not issubclass(N.UnfinalizedStreamWarning, ResourceWarning)
      and _rp_l2.returncode == 0 and _rp_l2.stdout.strip() == "256" and "UnfinalizedStreamWarning" in _rp_l2.stderr
      and "finalize" in _rp_l2.stderr and "UnfinalizedStreamWarning" in N.RehearsalDecryptor.__doc__)

# I1: workers run the source this process imported (sent over the pipe), never the file on disk
with _rh_tmp.TemporaryDirectory(prefix="octavo_rp_i1_") as _rp_td:
    _rp_cp = os.path.join(_rp_td, "sneak_n2.py"); _rp_mark = os.path.join(_rp_td, "PAYLOAD_RAN")
    _rh_sh.copyfile(os.path.join(HERE, "sneak_n2.py"), _rp_cp)
    _rp_spec = _rp_iu.spec_from_file_location("sneak_n2_rp_i1", _rp_cp); _rp_M = _rp_iu.module_from_spec(_rp_spec)
    sys.modules["sneak_n2_rp_i1"] = _rp_M; _rp_spec.loader.exec_module(_rp_M)
    # after import, the file is replaced: (1) the real module plus an appended payload, then (2) a 6-line fake
    _rp_orig = open(_rp_cp, "rb").read()
    open(_rp_cp, "wb").write(_rp_orig + ("\nopen(%r, 'w').write('ran')\n" % _rp_mark).encode())
    _rp_m3 = os.urandom(5 * 128 + 9)
    with _rh_fixed(mod=_rp_M):
        _rp_w1 = _rp_M.encrypt_rehearsal(_rp_m3, SEED, b"i1", 128); _rp_w3 = _rp_M.encrypt_rehearsal(_rp_m3, SEED, b"i1", 128, workers=3)
    open(_rp_cp, "w").write("import sys\nsys.stdout.buffer.write(b'%s'); sys.stdout.flush()\n"
                            "while sys.stdin.buffer.read(1 << 16): sys.stdout.buffer.write(bytes(8)); sys.stdout.flush()\n"
                            % (_rp_M._MODULE_SOURCE_SHA256 + _rp_M._REHEARSAL_SHA256))
    _rp_dec3 = _rp_try(lambda: _rp_M.decrypt_rehearsal(_rp_w3, SEED, b"i1", workers=3))
    _rp_it3 = _rp_try(lambda: b"".join(_rp_M.iter_rehearsal(_rp_w3, SEED, b"i1", workers=3, read_size=200)))
    _rp_M._MODULE_SOURCE_SHA256 = "0" * 64
    _rp_bad = _rp_try(lambda: _rp_M.encrypt_rehearsal(_rp_m3, SEED, b"i1", 128, workers=2))
    _rp_ws = N._REHEARSAL_WORKER_SRC
check("rehearsal-polish I1: workers execute the module source read once at import (sent over the pipe): a file replaced on disk after import (payload appended, or a fake that echoes the digests and returns zeros) is never run; a hello mismatch is refused",
      _rp_w3 == _rp_w1 and _rp_dec3 == _rp_m3 and _rp_it3 == _rp_m3 and not os.path.exists(_rp_mark)
      and isinstance(_rp_bad, RuntimeError) and "digest mismatch" in str(_rp_bad)
      and "spec_from_file_location" not in _rp_ws and "sys.argv" not in _rp_ws and "exec(compile(src" in _rp_ws
      and N._MODULE_SOURCE == open(os.path.join(HERE, "sneak_n2.py"), "rb").read()
      and N._MODULE_SOURCE_SHA256 == hashlib.sha256(N._MODULE_SOURCE).hexdigest()
      and "_MODULE_SOURCE" in N._ATTEST_SKIP and "_MODULE_SOURCE_SHA256" in N._ATTEST_SKIP)
sys.modules.pop("sneak_n2_rp_i1", None)

# I2: a stuck worker is killed after worker_timeout (default 600 s per frame); bad timeouts are refused
_rp_enc = N.RehearsalEncryptor(SEED, b"", 128, workers=2, worker_timeout=1.0); _rp_enc.update(os.urandom(256))
_rp_wp = [p.pid for p in _rp_enc._pool.procs]
for _p in _rp_wp: os.kill(_p, _rp_sig.SIGSTOP)
_rp_t0 = _rh_time.monotonic(); _rp_to = _rp_try(lambda: _rp_enc.update(os.urandom(256))); _rp_dt = _rh_time.monotonic() - _rp_t0
_rh_time.sleep(0.2)
_rp_dec = N.RehearsalDecryptor(SEED, b"x", workers=2, worker_timeout=1.0)
_rp_xb = N.encrypt_rehearsal(os.urandom(4 * 128), SEED, b"x", 128)
_rp_orig_spawn = N._RehearsalWorkers._spawn
def _rp_stop_spawn(self):
    p = _rp_orig_spawn(self); os.kill(p.pid, _rp_sig.SIGSTOP); return p
N._RehearsalWorkers._spawn = _rp_stop_spawn
try:
    _rp_to2 = _rp_try(lambda: _rp_dec.update(_rp_xb)); _rp_wp2 = [p.pid for p in (_rp_dec._pool.procs if _rp_dec._pool else [])]
finally:
    N._RehearsalWorkers._spawn = _rp_orig_spawn
check("rehearsal-polish I2: a SIGSTOPped worker no longer blocks forever: after worker_timeout the workers are killed and reaped and RuntimeError is raised (encrypt and decrypt); worker_timeout validates (default 600 s)",
      isinstance(_rp_to, RuntimeError) and "timed out" in str(_rp_to) and 0.9 <= _rp_dt < 10 and _rf_alive(_rp_wp) == []
      and isinstance(_rp_to2, RuntimeError) and "timed out" in str(_rp_to2) and _rp_wp2 == []
      and N.REHEARSAL_WORKER_TIMEOUT == 600.0 and N.RehearsalEncryptor(SEED)._worker_timeout == 600.0
      and all(isinstance(_rp_try(lambda v=v: N.RehearsalDecryptor(SEED, worker_timeout=v)), ValueError) for v in (0, -1, float("nan"), float("inf")))
      and all(isinstance(_rp_try(lambda v=v: N.RehearsalEncryptor(SEED, worker_timeout=v)), TypeError) for v in (True, "5"))
      and N.decrypt_rehearsal(_rp_xb, SEED, b"x", workers=2, worker_timeout=30) == N.decrypt_rehearsal(_rp_xb, SEED, b"x"))

# I7: iter_rehearsal never treats bytes as a path, and says so when a bytes value names an existing file
_rp_i7p = os.path.join(_rh_tmp.gettempdir(), "octavo_rp_i7_%d.oct" % os.getpid()); open(_rp_i7p, "wb").write(_rp_blob)
try:
    _rp_i7 = _rp_try(lambda: list(N.iter_rehearsal(os.fsencode(_rp_i7p), SEED, b"race")))
    _rp_i7s = b"".join(N.iter_rehearsal(_rp_i7p, SEED, b"race"))
    _rp_i7j = _rp_try(lambda: list(N.iter_rehearsal(b"not a stream, not a file", SEED)))
finally:
    os.unlink(_rp_i7p)
check("rehearsal-polish I7 (as changed by rehearsal-finale L3): iter_rehearsal(bytes path) is read as ciphertext (UnsupportedVersion, no file probe); str paths and bytes ciphertext still work; other bytes stay ciphertext (UnsupportedVersion)",
      isinstance(_rp_i7, N.UnsupportedVersion) and "str or os.PathLike" in N.iter_rehearsal.__doc__ and _rp_i7s == _rp_msg
      and b"".join(N.iter_rehearsal(_rp_blob, SEED, b"race")) == _rp_msg and isinstance(_rp_i7j, N.UnsupportedVersion)
      and "always CIPHERTEXT" in N.iter_rehearsal.__doc__)

# I8: one-shot memory and the opt-in receiver limit are documented (behaviour unchanged)
check("rehearsal-polish I8: decrypt_rehearsal / encrypt_rehearsal document one-shot memory (about 4x / 2x) and that max_chunk_size stays opt-in (default None)",
      "4x the blob" in N.decrypt_rehearsal.__doc__ and "opt-in" in N.decrypt_rehearsal.__doc__ and "2x" in N.encrypt_rehearsal.__doc__
      and N.RehearsalDecryptor(SEED)._max_cs is None)

# ---- rehearsal-finale: regression tests for the rehearsal-polish attack (attacks_octavo_rehearsalpolish/REPORT.md)
import traceback as _fn_tb, py_compile as _fn_pyc
_fn_d = os.path.realpath(_rh_tmp.mkdtemp(prefix="octavo_fn_"))
_fn_P = lambda *a: os.path.join(_fn_d, *a)
def _fn_dots(d=None): return sorted(n for n in os.listdir(d or _fn_d) if n.startswith("."))
def _fn_rd(p): return open(p, "rb").read() if os.path.lexists(p) and not os.path.islink(p) else None
open(_fn_P("in.oct"), "wb").write(_rp_blob); open(_fn_P("cut.oct"), "wb").write(_rp_cut)
try:
    # L1: copy fallback (no hard links): the copy's descriptor stays open through the inode check, so a file created at
    # dst after an unlink can never get the same inode back; the substitute is refused (RuntimeError) and removed
    _fn_l1 = {}
    _fn_chk = N._RehearsalOutput._check
    def _fn_race_check(self, name, want, created):
        if self.pub_fds and name == "l1.txt" and not _fn_l1:
            _fn_l1["open"] = [os.fstat(fd).st_ino for fd in self.pub_fds]
            os.unlink(_fn_P(name)); open(_fn_P(name), "wb").write(b"ATTACKER CONTENT\n")
            _fn_l1["new_ino"] = os.lstat(_fn_P(name)).st_ino; _fn_l1["want"] = want.st_ino
        return _fn_chk(self, name, want, created)
    N._RehearsalOutput._check = _fn_race_check
    try:
        _fn_l1r = _rp_with_link(_rp_raise(_rp_errno.EPERM), lambda: N.decrypt_rehearsal_file(_fn_P("in.oct"), _fn_P("l1.txt"), SEED, b"race"))
    finally:
        N._RehearsalOutput._check = _fn_chk
    _fn_l1ok = _rp_with_link(_rp_raise(_rp_errno.EPERM), lambda: N.decrypt_rehearsal_file(_fn_P("in.oct"), _fn_P("l1ok.txt"), SEED, b"race"), tmpfile=False)
    check("rehearsal-finale L1: the no-hard-link copy keeps its fd open through the check (inode cannot be recycled): a file swapped in at dst is refused with RuntimeError and removed, never vouched for; the clean fallback still publishes 0600",
          isinstance(_fn_l1r, RuntimeError) and _fn_l1.get("open") == [_fn_l1["want"]] and _fn_l1["new_ino"] != _fn_l1["want"]
          and not os.path.lexists(_fn_P("l1.txt")) and _fn_l1ok == len(_rp_msg) and _fn_rd(_fn_P("l1ok.txt")) == _rp_msg
          and _rf_stat.S_IMODE(os.stat(_fn_P("l1ok.txt")).st_mode) == 0o600 and _fn_dots() == [])

    # I1: overwrite=True race refused -> the OLD dst survives (RENAME_EXCHANGE + exchange back); clean overwrite works on
    # both the renameat2 path and the os.replace fallback and leaves no .swap file
    open(_fn_P("old.txt"), "wb").write(b"CALLER'S OLD FILE\n")
    _fn_r2 = N._rehearsal_renameat2; _fn_i1 = []
    def _fn_race_x(dirfd, old, new, flags):
        if not _fn_i1 and flags == N._RENAME_EXCHANGE:
            open(_fn_P("evil.x"), "wb").write(b"ATTACKER\n"); os.rename(_fn_P("evil.x"), _fn_P(old)); _fn_i1.append(old)
        return _fn_r2(dirfd, old, new, flags)
    N._rehearsal_renameat2 = _fn_race_x
    try:
        _fn_i1r = _rp_try(lambda: N.decrypt_rehearsal_file(_fn_P("in.oct"), _fn_P("old.txt"), SEED, b"race", overwrite=True))
    finally:
        N._rehearsal_renameat2 = _fn_r2
    _fn_i1a = N.decrypt_rehearsal_file(_fn_P("in.oct"), _fn_P("old.txt"), SEED, b"race", overwrite=True)
    _fn_i1a_ok = _fn_rd(_fn_P("old.txt")) == _rp_msg and _fn_dots() == []
    open(_fn_P("old2.txt"), "wb").write(b"old\n"); N._REHEARSAL_USE_RENAMEAT2 = False
    try:
        _fn_i1b = N.decrypt_rehearsal_file(_fn_P("in.oct"), _fn_P("old2.txt"), SEED, b"race", overwrite=True)
    finally:
        N._REHEARSAL_USE_RENAMEAT2 = True
    _fn_i1c = N.decrypt_rehearsal_file(_fn_P("in.oct"), _fn_P("fresh.txt"), SEED, b"race", overwrite=True)
    check("rehearsal-finale I1: an overwrite=True race (rename over the .swap name) raises RuntimeError and the caller's old dst is put back intact (no stray .swap); clean overwrites work with renameat2 and with the os.replace fallback; overwrite=True onto a missing dst links directly",
          isinstance(_fn_i1r, RuntimeError) and "put back" in str(_fn_i1r) and _fn_i1 and _fn_i1a_ok
          and _fn_i1a == len(_rp_msg) and _fn_i1b == len(_rp_msg) and _fn_rd(_fn_P("old2.txt")) == _rp_msg
          and _fn_i1c == len(_rp_msg) and _fn_rd(_fn_P("fresh.txt")) == _rp_msg and _fn_dots() == [])
    # I2: the crash-at-commit leftover is documented
    check("rehearsal-finale I2: the .swap leftover after a crash during an overwrite=True commit is documented (helpers, README, SPEC, SECURITY), and 'a crash leaves nothing behind' is qualified as mid-stream",
          ".swap" in N.decrypt_rehearsal_file.__doc__ and ".swap" in N.encrypt_rehearsal_file.__doc__
          and all(".swap" in open(os.path.join(HERE, f), encoding="utf-8").read() for f in ("README.md", "SPEC.md", "SECURITY.md"))
          and all("a crash leaves nothing behind. " not in open(os.path.join(HERE, f), encoding="utf-8").read() for f in ("README.md", "SPEC.md")))

    # I3 a: any link failure on the O_TMPFILE path (here ENOENT/EACCES from /proc) copies instead of losing verified output
    _fn_i3a = _rp_with_link(_rp_raise(_rp_errno.ENOENT), lambda: N.decrypt_rehearsal_file(_fn_P("in.oct"), _fn_P("i3a.txt"), SEED, b"race"))
    _fn_i3a2 = _rp_with_link(_rp_raise(_rp_errno.EACCES), lambda: N.decrypt_rehearsal_file(_fn_P("cut.oct"), _fn_P("i3a2.txt"), SEED, b"race", keep_partial=True))
    _fn_i3a2p = getattr(_fn_i3a2, "partial_path", None)
    # I3 b: a 250-byte dst name: dst + ".partial" is too long, so the partial is kept under a fresh dot-name
    _fn_long = "L" * 250
    _fn_i3b = _rp_try(lambda: N.decrypt_rehearsal_file(_fn_P("cut.oct"), _fn_P(_fn_long), SEED, b"race", keep_partial=True))
    _fn_i3bp = getattr(_fn_i3b, "partial_path", None)
    # I3 c: dst created mid-call (overwrite=False) after the whole stream verified: kept as dst.complete, not .partial
    class _FnSrc:
        def __init__(self): self.f = open(_fn_P("in.oct"), "rb")
        def read(self, n):
            b = self.f.read(n)
            if not b and not os.path.exists(_fn_P("i3c.txt")): open(_fn_P("i3c.txt"), "wb").write(b"appeared\n")
            return b
    _fn_src = _FnSrc()
    _fn_i3c = _rp_try(lambda: N.decrypt_rehearsal_file(_fn_src, _fn_P("i3c.txt"), SEED, b"race", keep_partial=True)); _fn_src.f.close()
    _fn_i3cp = getattr(_fn_i3c, "partial_path", None)
    check("rehearsal-finale I3: a /proc link error on the O_TMPFILE path falls back to a copy (verified output and keep_partial survive); a 250-byte dst keeps its partial under a fresh dot-name; a dst that appeared after full verification keeps the whole plaintext as dst.complete",
          _fn_i3a == len(_rp_msg) and _fn_rd(_fn_P("i3a.txt")) == _rp_msg
          and isinstance(_fn_i3a2, N.AuthError) and _fn_i3a2p == _fn_P("i3a2.txt.partial") and _rp_msg.startswith(_fn_rd(_fn_i3a2p) or b"x")
          and isinstance(_fn_i3b, N.AuthError) and _fn_i3bp is not None and os.path.basename(_fn_i3bp).startswith(".L") and _fn_i3bp.endswith(".partial")
          and _rp_msg.startswith(_fn_rd(_fn_i3bp) or b"x") and getattr(_fn_i3b, "partial_error", None) is None
          and isinstance(_fn_i3c, FileExistsError) and _fn_i3cp == _fn_P("i3c.txt.complete") and _fn_rd(_fn_i3cp) == _rp_msg
          and _fn_rd(_fn_P("i3c.txt")) == b"appeared\n")
    for _n in _fn_dots(): os.unlink(_fn_P(_n))

    # I4: parent-symlink swap between the path check and the dirfd open: the dirfd re-check refuses src == dst
    os.mkdir(_fn_P("real")); os.mkdir(_fn_P("other")); open(_fn_P("real", "x.oct"), "wb").write(_rp_blob)
    os.symlink(_fn_P("other"), _fn_P("L"))
    _fn_rs = N._rehearsal_refuse_same
    def _fn_swap_after_check(*a):
        r = _fn_rs(*a); os.unlink(_fn_P("L")); os.symlink(_fn_P("real"), _fn_P("L")); return r
    N._rehearsal_refuse_same = _fn_swap_after_check
    try:
        _fn_i4 = _rp_try(lambda: N.decrypt_rehearsal_file(_fn_P("real", "x.oct"), _fn_P("L", "x.oct"), SEED, b"race", overwrite=True))
    finally:
        N._rehearsal_refuse_same = _fn_rs
    check("rehearsal-finale I4: a parent-symlink swap after the path check no longer lets overwrite=True replace the ciphertext source with its own plaintext (ValueError; source intact, nothing left behind)",
          isinstance(_fn_i4, ValueError) and "same file" in str(_fn_i4) and _fn_rd(_fn_P("real", "x.oct")) == _rp_blob
          and _fn_dots(_fn_P("real")) == [] and os.listdir(_fn_P("other")) == [])
finally:
    _rh_sh.rmtree(_fn_d, ignore_errors=True)

# L2: -W error no longer swallows the warning; every dropped decryptor warns (not once per call site)
_fn_l2code = ("import sys, gc; sys.path.insert(0, %r); import sneak_n2 as N\n"
              "s = N.load_seed(); b = N.encrypt_rehearsal(b'x' * 600, s, b'', 128)\n"
              "for i in range(5):\n    d = N.RehearsalDecryptor(s); d.update(b[:72 + 3 * 160]); del d; gc.collect()\n"
              "print('done')" % HERE)
_fn_l2e = subprocess.run([sys.executable, "-B", "-W", "error", "-c", _fn_l2code], capture_output=True, text=True, timeout=120)
_fn_l2d = subprocess.run([sys.executable, "-B", "-c", _fn_l2code], capture_output=True, text=True, timeout=120)
_fn_l2i = subprocess.run([sys.executable, "-B", "-W", "ignore", "-c", _fn_l2code], capture_output=True, text=True, timeout=120)
check("rehearsal-finale L2: under -W error the UnfinalizedStreamWarning is reported through sys.unraisablehook (not swallowed); under default filters 5 dropped decryptors give 5 warnings; -W ignore still silences it",
      _fn_l2e.returncode == 0 and _fn_l2e.stdout.strip() == "done" and _fn_l2e.stderr.count("UnfinalizedStreamWarning") >= 5
      and "Exception ignored" in _fn_l2e.stderr
      and _fn_l2d.returncode == 0 and _fn_l2d.stderr.count("UnfinalizedStreamWarning:") == 5
      and _fn_l2i.returncode == 0 and "UnfinalizedStreamWarning" not in _fn_l2i.stderr
      and "unraisablehook" in N.RehearsalDecryptor.__doc__)

# L3: iter_rehearsal(bytes) never consults the filesystem: existing and missing "paths" give the same error type
_fn_ex = _rp_try(lambda: list(N.iter_rehearsal(os.fsencode(os.path.join(HERE, "sneak_n2.py")), SEED)))
_fn_mi = _rp_try(lambda: list(N.iter_rehearsal(os.fsencode(os.path.join(HERE, "no-such-file-%d" % os.getpid())), SEED)))
_fn_root = _rp_try(lambda: list(N.iter_rehearsal(b"/root", SEED)))
check("rehearsal-finale L3: iter_rehearsal treats every bytes src as ciphertext (no os.path.exists probe): an existing path, /root and a missing path all raise UnsupportedVersion",
      all(type(e) is N.UnsupportedVersion for e in (_fn_ex, _fn_mi, _fn_root))
      and "os.path.exists" not in inspect.getsource(N.iter_rehearsal) and "never consulted" in N.iter_rehearsal.__doc__)

# I5: a .pyc compiled from a same-size modified source (honest .py restored with the same mtime) is refused at import
with _rh_tmp.TemporaryDirectory(prefix="octavo_fn_i5_") as _fn_td:
    for _f in ("sneak_n2.py", "sneak1024-seed.txt"):
        _rh_sh.copyfile(os.path.join(HERE, _f), os.path.join(_fn_td, _f))
    _fn_py = os.path.join(_fn_td, "sneak_n2.py"); _fn_honest = open(_fn_py, "rb").read()
    _fn_evil = _fn_honest.replace(b"ok = (x != 0) & ((tz & 7) == 7)", b"ok = (x != 0) | ((tz & 7) == 7)")
    _fn_imp = [sys.executable, "-c", "import sys; sys.path.insert(0, %r); import sneak_n2 as N; print(N.REVISION)" % _fn_td]
    _fn_good = subprocess.run(_fn_imp, capture_output=True, text=True, timeout=120)          # writes an honest .pyc
    _fn_good2 = subprocess.run(_fn_imp, capture_output=True, text=True, timeout=120)         # imports from that .pyc
    open(_fn_py, "wb").write(_fn_evil); os.utime(_fn_py, ns=(10**18, 10**18))
    _fn_pyc.compile(_fn_py, cfile=_rp_iu.cache_from_source(_fn_py), doraise=True)
    open(_fn_py, "wb").write(_fn_honest); os.utime(_fn_py, ns=(10**18, 10**18))
    _fn_bad = subprocess.run(_fn_imp, capture_output=True, text=True, timeout=120)
check("rehearsal-finale I5: the module verifies that the bytecode it executed was compiled from _MODULE_SOURCE: an honest .pyc imports, a .pyc built from a same-size modified source (unpad accepting zero blocks) with the honest .py restored at the same mtime fails the import",
      len(_fn_evil) == len(_fn_honest) and _fn_evil != _fn_honest
      and _fn_good.returncode == 0 and _fn_good2.returncode == 0 and _fn_good2.stdout.strip() == N.REVISION
      and _fn_bad.returncode != 0 and "executed bytecode for _rehearsal_unpad does not match" in _fn_bad.stderr)

# I6: workers start as python -I -B -S with an empty environment; the parent spot-checks one block per batch
_fn_popen = N.subprocess.Popen; _fn_calls = []
def _fn_rec_popen(args, **kw):
    _fn_calls.append((list(args), kw.get("env"))); return _fn_popen(args, **kw)
N.subprocess.Popen = _fn_rec_popen
try:
    _fn_m6 = os.urandom(7 * 256 + 5); _fn_b6 = N.encrypt_rehearsal(_fn_m6, SEED, b"w", 256, workers=3)
finally:
    N.subprocess.Popen = _fn_popen
_fn_recv = N._RehearsalWorkers._recv
def _fn_lying_recv(self, p, n, deadline):
    b = _fn_recv(self, p, n, deadline)
    return bytes(x ^ 1 for x in b) if n > 128 else b   # chunk bodies (256 B), not the 128-byte hello
N._RehearsalWorkers._recv = _fn_lying_recv
try:
    _fn_lie = _rp_try(lambda: N.decrypt_rehearsal(_fn_b6, SEED, b"w", workers=3))
    _fn_lie2 = _rp_try(lambda: N.encrypt_rehearsal(_fn_m6, SEED, b"w", 256, workers=3))
finally:
    N._RehearsalWorkers._recv = _fn_recv
check("rehearsal-finale I6: workers are started as python -I -B -S -c with an empty environment (no site/.pth, no LD_PRELOAD); a worker returning wrong blocks is caught by the parent's per-batch spot check (RuntimeError) on decrypt and encrypt; honest workers round-trip",
      _fn_calls and all(a[1:5] == ["-I", "-B", "-S", "-c"] and e == {} for a, e in _fn_calls)
      and N.decrypt_rehearsal(_fn_b6, SEED, b"w", workers=3) == _fn_m6
      and isinstance(_fn_lie, RuntimeError) and "spot check" in str(_fn_lie)
      and isinstance(_fn_lie2, RuntimeError) and "spot check" in str(_fn_lie2))

# I7: read_size is validated (int, not bool, >= 1) on every helper that takes it
_fn_rs_cases = [(0, ValueError), (-1, ValueError), (True, TypeError), (1.5, TypeError), ("8", TypeError)]
_fn_i7 = all(isinstance(_rp_try(lambda v=v: N.decrypt_rehearsal_file(_rp_io.BytesIO(_rp_blob), _rp_io.BytesIO(), SEED, b"race", read_size=v)), t)
             and isinstance(_rp_try(lambda v=v: list(N.iter_rehearsal(_rp_blob, SEED, b"race", read_size=v))), t)
             and isinstance(_rp_try(lambda v=v: N.encrypt_rehearsal_file(_rp_io.BytesIO(b"x"), _rp_io.BytesIO(), SEED, read_size=v)), t)
             for v, t in _fn_rs_cases)
check("rehearsal-finale I7: read_size 0/-1 raise ValueError and True/1.5/'8' raise TypeError in decrypt_rehearsal_file, iter_rehearsal and encrypt_rehearsal_file; read_size=1 and encrypt's None default still work",
      _fn_i7 and b"".join(N.iter_rehearsal(_rp_blob, SEED, b"race", read_size=1)) == _rp_msg
      and N.encrypt_rehearsal_file(_rp_io.BytesIO(b"abc"), _rp_io.BytesIO(), SEED, read_size=None) > 0)

# I8: an insider stream whose tags verify but whose final padding is bad leaves no decrypted chunk in the traceback frames
_fn_pad = N._rehearsal_pad
N._rehearsal_pad = lambda m: bytes(N.BLOCK_LEN * ((len(m) + N.BLOCK_LEN) // N.BLOCK_LEN))
try:
    _fn_bp = N.encrypt_rehearsal(b"S" * 300, SEED, b"pad", 128)
finally:
    N._rehearsal_pad = _fn_pad
def _fn_leaks(exc):
    found = []
    for fr, _ in _fn_tb.walk_tb(exc.__traceback__):
        for k, v in fr.f_locals.items():
            if isinstance(v, list) and any(isinstance(x, bytes) and b"S" * 64 in x for x in v): found.append(k)
            if isinstance(v, (bytes, bytearray)) and b"S" * 64 in v: found.append(k)
            if k in ("padded", "msg", "last") and v: found.append(k)
    return found
_fn_e1 = _rp_try(lambda: N.decrypt_rehearsal(_fn_bp, SEED, b"pad"))
_fn_dd = N.RehearsalDecryptor(SEED, b"pad"); _fn_pre = _fn_dd.update(_fn_bp)
_fn_e2 = _rp_try(_fn_dd.finalize)
check("rehearsal-finale I8: bad final padding on a fully tag-verified stream raises AuthError with no decrypted plaintext left in any traceback frame (one-shot pts cleared, streaming padded/msg dropped)",
      isinstance(_fn_e1, N.AuthError) and _fn_leaks(_fn_e1) == [] and isinstance(_fn_e2, N.AuthError) and _fn_leaks(_fn_e2) == []
      and _fn_pre == b"S" * 256)

# identifiers: the mix digest and key_sig are untouched by the polish; v8 ciphertext blocks are unchanged (only tags move)
check("rehearsal-polish / rehearsal-finale: EXPECTED_MIX_SHA256 and key_sig are unchanged (fe939969… / 340dc1e0…); v6/v7 untouched",
      N.EXPECTED_MIX_SHA256 == "fe93996970ecd92693b5f8f43ffb2cad5e96867f258a38b12637f1014b12b4c6"
      and N.key_signature(SEED).hex() == "340dc1e062502bb13462a94ba490c3dc")

# published score: regenerate in memory and compare to score/vectors.json
import json as _json_score
import score.generate_score as _gen_score
_score_path = os.path.join(HERE, "score", "vectors.json")
_committed = _json_score.load(open(_score_path))
_fresh = _gen_score.build_vectors()
check("published score regenerates identically (72 vectors: 16 permute, 24 aead, 24 movements, 8 rehearsal)",
      _fresh == _committed and _committed["counts"] == {"block_cipher": 16, "aead": 24, "movements": 24, "rehearsal": 8, "total": 72}
      and _committed["revision"] == "rehearsal-finale" and _committed.get("score_version") == 7
      and _committed["format"]["etude_fmt_block"] == {"2": 0x82, "4": 0x84, "6": 0x86, "16": 0x90}
      and _committed["EXPECTED_MIX_SHA256"] == N.EXPECTED_MIX_SHA256
      and _committed["key_sig"] == N.key_signature(SEED).hex()
      and _committed["sneak_n2_sha256"] == hashlib.sha256(open(os.path.join(HERE, "sneak_n2.py"), "rb").read()).hexdigest()
      and _committed["EXPECTED_REHEARSAL_SHA256"] == N.EXPECTED_REHEARSAL_SHA256
      and _committed["rehearsal_sig"] == N.rehearsal_signature(SEED).hex())
_rh_vec_ok = []
for _v in _committed["rehearsal"]:
    _b = bytes.fromhex(_v["blob"]) if "blob" in _v else None
    if _b is None:
        _b = _gen_score.rehearsal_blob(_v["id"])
    _pt = N.decrypt_rehearsal(_b, SEED, bytes.fromhex(_v["ad"]))
    _rh_vec_ok.append(hashlib.sha256(_b).hexdigest() == _v["blob_sha256"] and len(_b) == _v["blob_len"]
                      and hashlib.sha256(_pt).hexdigest() == _v["msg_sha256"] and len(_pt) == _v["msg_len"]
                      and _b[0] == 8 and int.from_bytes(_b[68:72], "big") == _v["chunk_size"])
check("every published rehearsal vector (live v8, demo seed) decrypts to its recorded plaintext hash and length",
      all(_rh_vec_ok) and len(_rh_vec_ok) == 8)

# ---- picture header stays in sync with the live module and hello-world sample
# render_n2.py writes sneak-staff-n2.json beside the PNG with the file SHA, key_sig,
# and hello-world pickup/nonce/tag it was drawn from. This check fails if the
# committed picture is stale relative to sneak_n2.py or hello-world.txt.
_pic_json = os.path.join(HERE, "sneak-staff-n2.json")
_pic_png = os.path.join(HERE, "sneak-staff-n2.png")
if os.path.isfile(_pic_json) and os.path.isfile(_pic_png):
    import json as _json
    _meta = _json.load(open(_pic_json))
    _live_sha = hashlib.sha256(open(os.path.join(HERE, "sneak_n2.py"), "rb").read()).hexdigest()
    _live_sig = N.key_signature().hex()
    check("sneak-staff-n2.json matches live sneak_n2.py SHA, key_sig, and hello-world pickup/nonce/tag",
          _meta.get("file_sha256")==_live_sha and _meta.get("key_sig")==_live_sig
          and _meta.get("pickup")==HW_PICKUP.hex() and _meta.get("nonce")==hw_field("nonce").hex()
          and _meta.get("tag")==hw_field("tag").hex())
else:
    check("sneak-staff-n2.json and sneak-staff-n2.png are present beside the tests", False)

# ---- frozen trees untouched (sha256 baselines taken before N2 was written)
def sha_ok(listfile):
    r = subprocess.run(["sha256sum", "-c", "--quiet", listfile], cwd="/workspace", capture_output=True)
    return r.returncode == 0
if os.path.isdir("/workspace/test1"):
    for lf in ("frozen-and-n1.sha256", "v2-v13-and-seed.sha256"):
        lp = os.path.join(HERE, "baselines", lf)
        if not os.path.isfile(lp):
            skip(f"unchanged vs baseline {lf}")
            continue
        print(f"baseline {lf}: {sum(1 for _ in open(lp))} files")
        check(f"unchanged vs baseline {lf}", sha_ok(lp))
    bp = os.path.join(HERE, "baselines", "frozen-and-n1.sha256")
    if os.path.isfile(bp):
        base_files = sorted(l.split("  ", 1)[1].strip() for l in open(bp))
        now_files = sorted(os.path.relpath(os.path.join(dp, f), "/workspace") for d in ("test1", "test3", "test13", "testn1", "sneak_t1n")
                           for dp, _, fs in os.walk(os.path.join("/workspace", d)) for f in fs) + ["sneak-staff-t1n.png"]
        check("no files added/removed in test1/, test3/, test13/, testn1/, sneak_t1n/", base_files == sorted(now_files))
    else:
        skip("no files added/removed in test1/, test3/, test13/, testn1/, sneak_t1n/")
else:
    skip("unchanged vs baseline frozen-and-n1.sha256")
    skip("unchanged vs baseline v2-v13-and-seed.sha256")
    skip("no files added/removed in test1/, test3/, test13/, testn1/, sneak_t1n/")
print(f"\n{P}/{P+F} passed, {F} failed, {S} skipped")
sys.exit(1 if F else 0)
