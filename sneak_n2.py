"""Sneak staff-core N2 (8-bit cells) — homemade 1024-bit block cipher (descended from N1) + HMAC-SHA256 seal.

WARNING: homemade scheme. NOT for real secrets. The 16-round function has had in-house
attacks and one independent, non-expert review (GitHub issue #1, around octavo003: no
distinguisher, forgery or key recovery reported). The outer construction (key commitment,
movements, études, equal-time rejects, rehearsal streaming) has had in-house attacks only
(rehearsal: two in-house attacks; rehearsal-fix and rehearsal-polish address their file-helper,
worker and API findings), and nothing here is expert cryptanalysis or a proof.
For anything that matters use AES-GCM-SIV (RFC 8452), age, or libsodium.

What is homemade: the whole 1024-bit block cipher (16 faces x 8 beats on dual octahedra, one BYTE per beat,
keyed SM4-affine 8-bit S-boxes, face-beat weave, staff butterflies on open (linear, unlooped) 8-beat staffs, seven
named pair mixes (keyed Latin B0, six field pairs) plus six overlapping triplet mixes per staff (four measures of 2/4) and shell bridges built from the two-cell SM4-field mix (u XOR v, u XOR (2 times v)), with nonlinear bow pressure, keyed Latin odd-beat rehair, and four matching-beat cross-staff layers after each bow). What is NOT homemade: SHA-256 is the one-way
"staff sponge" that expands seed+nonce into the schedule, HMAC-SHA256 is the integrity tag, and the base 8-bit
S-box table is the published SM4/SMS4 S-box (GB/T 32907-2016). No AES, AES S-box, MixColumns or GCM anywhere.
See SPEC.md.

Études (reduced-round variants at 2, 4 and 6 rounds, plus a 16-round
comparison handle) live in etudes.py and are for cryptanalysis only.
They are not selectable from encrypt / decrypt, and since the conductor
revision they run under their own derived key (never the live round
material). Published test vectors are in score/vectors.json.

Rehearsal (format version 8) is a STREAM-style chunked mode with no 1 MB cap:
RehearsalEncryptor / RehearsalDecryptor (update / finalize), encrypt_rehearsal /
decrypt_rehearsal, iter_rehearsal (safe reader that always finalizes) and the
*_rehearsal_file helpers (private 0600 O_TMPFILE / O_EXCL temp files, published by a
no-follow hard link and checked to be the inode written; no clobber by default). Every chunk is
verified before any of its plaintext is released. Études have no streaming mode.

The default seed file sneak1024-seed.txt is a PUBLIC DEMO SEED: its full
hex is published in score/vectors.json, so any blob made with seed=None
is readable by anyone.
"""
import hashlib, hmac, os, json, inspect, ast, textwrap, types, time, warnings, collections
import errno, pickle, subprocess, sys, tempfile
import io, linecache, selectors, stat

def _module_source_snapshot():
    """rehearsal-polish I1: the exact source of this module, read ONCE at import (or handed in by the
    worker loader), primed into linecache so both attestations hash these bytes and workers > 1 are
    sent these bytes over their pipe. A later change to the file on disk changes neither."""
    g = globals()
    src = g.pop("__octavo_worker_source__", None)
    path = g.get("__file__")
    if src is None:
        if not path or not path.endswith(".py"):
            return None
        try:
            with open(path, "rb") as f:
                src = f.read()
        except OSError:
            return None
    try:
        lines = io.StringIO(src.decode("utf-8-sig"), newline=None).readlines()
    except UnicodeDecodeError:
        return None
    if path:
        linecache.cache[path] = (len(src), None, lines, path)   # mtime None: checkcache never re-reads it
    return src
_MODULE_SOURCE = _module_source_snapshot()
_MODULE_SOURCE_SHA256 = None if _MODULE_SOURCE is None else hashlib.sha256(_MODULE_SOURCE).hexdigest()

VERSION = b"SN2"                 # magic after the format-version byte; sponge domains stay b"SN2/"
FMT_VERSION_V2 = 2              # legacy single-block (no tuning); decrypt_legacy() only
FMT_VERSION_V4 = 4              # unpublished tuning revision (AD not in commitment); rejected
FMT_VERSION = 6                 # current single-block: commitment binds associated data
NF, NB, NR = 16, 8, 16            # faces, beats, rounds (16 rounds <-> 16 faces)
CELL_BITS = 8                     # one byte per beat (was a 4-bit nibble)
NONCE_LEN, BLOCK_LEN, TAG_LEN = 16, 128, 32
PICKUP_LEN = 16                   # hardened anacrusis: sha256(SN2/P || urandom || time_ns || counter || pid)[:16]
COMMIT_LEN = 32                 # HMAC-SHA256 tuning / key-commitment value
COMMIT_DOMAIN = b"U"            # tUning; sponge domain and HMAC domain letter (not used elsewhere)
# Current single-block layout (v6):
#   version(1) || SN2(3) || pickup(16) || nonce(16) || commit(32) || ct(128) || tag(32)
PK0, N0 = 1 + len(VERSION), 1 + len(VERSION) + PICKUP_LEN      # pickup = blob[4:20], nonce = blob[20:36]
CM0, CM1 = N0 + NONCE_LEN, N0 + NONCE_LEN + COMMIT_LEN         # commit = blob[36:68]
CT0, CT1 = CM1, CM1 + BLOCK_LEN                                 # ct = blob[68:196], tag = blob[196:228]
BLOB_LEN = 1 + len(VERSION) + PICKUP_LEN + NONCE_LEN + COMMIT_LEN + BLOCK_LEN + TAG_LEN    # 228
# Legacy v2 (no tuning): version || SN2 || pickup || nonce || ct || tag
V2_BLOB_LEN = 1 + len(VERSION) + PICKUP_LEN + NONCE_LEN + BLOCK_LEN + TAG_LEN   # 196
V2_CT0, V2_CT1 = N0 + NONCE_LEN, N0 + NONCE_LEN + BLOCK_LEN     # ct = blob[36:164], tag = blob[164:196]
MAX_MSG = 127
MAX_AD_LEN = 65536            # associated-data cap (bytes); encrypt and decrypt reject anything longer
FMT_MOVEMENTS_V3 = 3          # legacy movements (no tuning); decrypt_movements_legacy() only
FMT_MOVEMENTS_V5 = 5          # unpublished tuning revision (AD/nmov not in commitment); rejected
FMT_MOVEMENTS = 7             # current movements: commitment binds AD and nmov; never confused with v6
MAX_MOVEMENTS = 8192          # sane cap: 8192 x 127-byte payloads
MAX_MOVEMENTS_MSG = MAX_MOVEMENTS * MAX_MSG   # 1_040_384 bytes
MOVEMENT_STRIDE = BLOCK_LEN + TAG_LEN         # 160 = ct(128) || cadence(32)
NMOV0 = CM1                     # v7 nmov starts after the commitment; blob[68:72]
MOVEMENTS_HDR_LEN = NMOV0 + 4   # 72 = ver||SN2||pickup||nonce||commit||nmov
V3_NMOV0 = N0 + NONCE_LEN       # 36
V3_MOVEMENTS_HDR_LEN = 1 + len(VERSION) + PICKUP_LEN + NONCE_LEN + 4   # 40
# Frozen octavo009 (etudes) mix digest. Used only by decrypt_legacy() /
# decrypt_movements_legacy() and the matching étude helpers, whose tags bind
# that revision's key_sig. The live mix hash has since moved because the
# attested wrappers now bind AD (and nmov) in the commitment.
LEGACY_MIX_SHA256 = "4e9a7ded574924fe9635e2b7b908ba7c5fa5c489062137203d3ce03341a06ee6"
# Resolved next to this file so a clone works. The runtime absolute value is not attested
# (see _ATTEST_SKIP); otherwise tags would depend on the install path.
SEED_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sneak1024-seed.txt")
# sha256(mix_description()) hex; used as the StaffSponge nonce for key_signature.
# Excluded from attestation so this constant is not part of what it names (chicken-and-egg).
EXPECTED_MIX_SHA256 = "fe93996970ecd92693b5f8f43ffb2cad5e96867f258a38b12637f1014b12b4c6"
# sha256(rehearsal_description()) hex (rehearsal, format version 8); sponge nonce for rehearsal_signature.
# Excluded from both attestations for the same chicken-and-egg reason. The live mix digest above is
# unchanged by rehearsal, so key_sig and every v6/v7 blob stay byte-identical.
EXPECTED_REHEARSAL_SHA256 = "f28badba6dcd70e80f2524d9adb00bc177374d609a0555453256fa10451804a4"

# Picture / documentation metadata. Not part of the mix or tag; excluded from
# attestation so a label or feature-list edit does not change key_sig or ciphertext.
REVISION = "rehearsal-finale"
REVISION_DATE = "2026-11-11"
FEATURES = (
    "keyed SM4 S-boxes",
    "latin B0 + field bar pairs",
    "six triplets",
    "bow-pressure",
    "latin odd restack",
    "cross-staff mix",
    "open 8-beat staffs",
    "SIV nonce SHA-256(clef‖pickup‖enc(msg)‖enc(AD))[:16]",
    "rehearsal v8 chunked stream",
    "HMAC tag over clef‖key_sig‖version‖SN2‖pickup‖nonce‖tuning‖ct‖AD",
    "movements: theme T; cadence HMAC-D over theme‖index‖ct; coda HMAC-O over header‖count‖ct‖cadences‖AD",
    "tuning: HMAC-U commitment over version‖SN2‖pickup‖nonce‖AD (and nmov)",
    "conductor-polish: equal-time rejects",
    "grid IS ciphertext",
    "études 2/4/6 (lab only, own key E)",
)
WARNING_LINE = "NOT for real secrets — use AES-GCM-SIV, age, or libsodium"

# SM4 (SMS4) 8-bit S-box, GB/T 32907-2016 Fig./Table "S-box", as printed in draft-ribose-cfrg-sm4-10 sec. 6.2.3
# (Tse, Wong, Saarinen, IRTF CFRG, 2018). Published DDT max 4/256 (2^-6), nonlinearity 112 (LAT max |bias| 16/256).
# Note (honest): like every GF(2^8)-inversion-based S-box, SM4's is affine-equivalent to the inversion map.
SM4_SBOX = bytes.fromhex(
    "d690e9fecce13db716b614c228fb2c05" "2b679a762abe04c3aa44132649860699" "9c4250f491ef987a33540b43edcfac62" "e4b31ca9c908e895"
    "80df94fa758f3fa6" "4707a7fcf37317ba83593c19e6854fa8" "686b81b27164da8bf8eb0f4b70569d35" "1e240e5e6358d1a2"
    "25227c3b01217887" "d40046579fd327524c3602e7a0c4c89e" "eabf8ad240c738b5a3f7f2cef96115a1" "e0ae5da49b341a55"
    "ad933230f58cb1e3" "1df6e22e8266ca60c02923ab0d534e6f" "d5db3745defd8e2f03ff6a726d6c5b51" "8d1baf92bbddbc7f"
    "11d95c411f105ad8" "0ac13188a5cd7bbd2d74d012b8e5b4b0" "8969974a0c96777e65b9f109c56ec684" "18f07dec3adc4d20"
    "79ee5f3ed7cb3948")
assert len(SM4_SBOX) == 256 and len(set(SM4_SBOX)) == 256

class Rejected(ValueError):
    """Common parent of every reject a decrypt API can raise for a bad or
    foreign blob (conductor-polish I3): AuthError, DecodeError and
    UnsupportedVersion. `except Rejected:` is the one clause that means
    "this blob was not accepted". It never means "try the legacy path":
    a legacy fallback must use an explicit allowlist or cutoff (SECURITY.md).
    Caller mistakes (wrong argument types, weak seed, a missing
    allow_noncommitting=True flag) stay plain TypeError / ValueError."""
class AuthError(Rejected):
    """Authentication or format failure. No payload is ever returned.

    Commitment, tag, cadence and coda failures all raise AuthError with
    the message "authentication failed", so the exception type and
    message do not distinguish a wrong key from wrong associated data.
    Single-block decrypt always computes and compares BOTH the commitment
    and the tag before raising (equal-time reject, conductor). Movements
    decrypt computes the commitment AND the coda before raising one
    combined AuthError (conductor-polish L1). Structural errors (bad
    length, bad version prefix, bad movement count) keep their own
    messages; they depend only on public data.
    """
class DecodeError(Rejected): """Tag was valid but the decrypted block is not a well-formed encoding."""
class UnsupportedVersion(Rejected):
    """Blob format version is not the one this API speaks.

    Deliberately NOT a subclass of AuthError (conductor), so a natural
    `except AuthError:` handler can never drift into a legacy fallback.
    It is a Rejected (conductor-polish), so `except Rejected:` catches it."""
class LegacyFormatWarning(UserWarning):
    """Emitted by every non-committing legacy helper (decrypt_legacy, decrypt_movements_legacy, étude equivalents).
    A UserWarning (conductor-polish L2), so Python's default filters SHOW it, including
    when a library module (not __main__) calls the helper."""

# ---------------------------------------------------------------- seed
def load_seed(path=None) -> bytes:
    """Same file and parsing as N1 (256 hex digits = 1024 bits), returned as 128 big-endian bytes.
    Default: sneak1024-seed.txt next to this module. No other location is read.
    That default file is a PUBLIC DEMO SEED (published in score/vectors.json); never use it for anything real.
    The default file is parsed once and cached. The cache key is (path, st_dev, st_ino, st_size,
    st_mtime_ns, st_ctime_ns) (conductor-polish I4): replacing the file (new inode) or rewriting it
    in place (new ctime, which cp -p, rsync -t and touch -r cannot set back) forces a re-read."""
    key = None
    if path is None:
        path = SEED_PATH
        st = os.stat(path)
        key = (path, st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        if load_seed.cache is not None and load_seed.cache[0] == key:
            return load_seed.cache[1]
    h = "".join(c for c in open(path).read().lower() if c in "0123456789abcdef")
    if len(h) != 256: raise ValueError(f"seed must be 256 hex digits, got {len(h)}")
    seed = bytes.fromhex(h)
    if key is not None:
        load_seed.cache = (key, seed)
    return seed
load_seed.cache = None

class _DerivedKey(bytes):
    """Marker for a key derived inside this package (étude keys K_e). _seed_bytes runs the
    weak-seed rule on it every time and never puts it in the seed memo (conductor-polish I5)."""
    __slots__ = ()

def _seed_bytes(seed) -> bytes:
    """Normalize and check a seed. A caller seed that already passed the weak-seed rule is
    remembered in a small LRU (at most _seed_bytes.size = 16 entries; the least recently used
    entry is dropped, never the whole memo) so the per-call cost does not depend on the seed's
    byte distribution (conductor I3, conductor-polish I5). Derived étude keys (_DerivedKey) are
    checked on every use and never remembered."""
    remember = type(seed) is not _DerivedKey
    if seed is None: seed = load_seed()
    elif isinstance(seed, int): seed = seed.to_bytes(128, "big")          # N1-style integer key
    else: seed = bytes(seed)
    if len(seed) != 128: raise ValueError("seed must be 128 bytes (1024 bits)")
    memo = _seed_bytes.ok
    if remember and seed in memo:
        memo.move_to_end(seed)
        return seed
    # Weak-seed rule: at least 32 distinct nonzero bytes (rejects all-zero, seed=1, repeated-byte keys).
    nonzero = [b for b in seed if b]
    if len(set(nonzero)) < 32:
        raise ValueError("weak seed: need at least 32 distinct nonzero bytes")
    if remember:
        memo[seed] = True
        while len(memo) > _seed_bytes.size:
            memo.popitem(last=False)
    return seed
_seed_bytes.ok = collections.OrderedDict()
_seed_bytes.size = 16

# ---------------------------------------------------------------- staff sponge (SHA-256 underneath)
class StaffSponge:
    """Squeezes SHA-256(b"SN2/" || domain || counter32 || seed || nonce) blocks, counter = 0,1,2,...
    Distinct one-byte domains separate the MAC key (b"M") from the round schedule (b"K").
    One-way: from squeezed output (round keys) + public nonce you cannot solve back for the seed
    without inverting SHA-256 (N1's schedule was a linear rotate/XOR map and was solved directly)."""
    def __init__(self, domain: bytes, seed: bytes, nonce: bytes):
        self.d, self.s, self.n, self.ctr, self.buf = domain, seed, nonce, 0, b""
    def _more(self):
        self.buf += hashlib.sha256(b"SN2/" + self.d + self.ctr.to_bytes(4, "big") + self.s + self.n).digest()
        self.ctr += 1
    def take(self, k: int) -> bytes:
        while len(self.buf) < k: self._more()
        out, self.buf = self.buf[:k], self.buf[k:]; return out
    def below(self, n: int) -> int:
        """Unbiased integer in [0, n) by rejection on single bytes (n <= 256)."""
        lim = 256 - 256 % n
        while True:
            b = self.take(1)[0]
            if b < lim: return b % n
    def perm(self, n: int):
        p = list(range(n))
        for i in range(n - 1, 0, -1):
            j = self.below(i + 1); p[i], p[j] = p[j], p[i]
        return p

# ---------------------------------------------------------------- GF(2)^8 affine layers for the S-box
def mat_apply(M, x):          # M = 8 rows, each an 8-bit mask; output bit i = parity(row_i & x)
    return sum(((bin(M[i] & x).count("1") & 1) << i) for i in range(8))
def mat_invertible(M):
    """GF(2) rank of the 8x8 matrix (rows as bit masks) == 8."""
    rows, rank = list(M), 0
    for bit in range(8):
        piv = next((i for i in range(rank, 8) if rows[i] >> bit & 1), None)
        if piv is None: continue
        rows[rank], rows[piv] = rows[piv], rows[rank]
        for i in range(8):
            if i != rank and rows[i] >> bit & 1: rows[i] ^= rows[rank]
        rank += 1
    return rank == 8

def keyed_sbox(A1, b1, A2, b2):
    """S'(x) = A2 * S_SM4(A1 * x + b1) + b2 over GF(2)^8. Affine-equivalent to the SM4 S-box, so the
    DDT and LAT spectra (DDT max 4, LAT max 16) are inherited exactly."""
    S = [mat_apply(A2, SM4_SBOX[mat_apply(A1, x) ^ b1]) ^ b2 for x in range(256)]
    inv = [0] * 256
    for i, v in enumerate(S): inv[v] = i
    return S, inv

def ddt_max(S):
    """max over a != 0, b of #{x : S[x] ^ S[x ^ a] == b}."""
    n = len(S); best = 0
    for a in range(1, n):
        cnt = [0] * n
        for x in range(n): cnt[S[x] ^ S[x ^ a]] += 1
        m = max(cnt)
        if m > best: best = m
    return best

def lat_max(S):
    """max over a, b != 0 of |#{x : a.x == b.S(x)} - n/2|, via a fast Walsh-Hadamard transform per output mask."""
    n = len(S); best = 0
    for b in range(1, n):
        w = [1 - 2 * (bin(b & S[x]).count("1") & 1) for x in range(n)]
        h = 1
        while h < n:
            for i in range(0, n, 2 * h):
                for j in range(i, i + h):
                    u, v = w[j], w[j + h]; w[j], w[j + h] = u + v, u - v
            h *= 2
        m = max(abs(x) for x in w[1:]) // 2
        if m > best: best = m
    return best

# ---------------------------------------------------------------- schedule
class Schedule:
    """All per-message material, derived from seed AND nonce together (repair 5)."""
    def __init__(self, seed, nonce: bytes):
        seed = _seed_bytes(seed)
        if len(nonce) != NONCE_LEN: raise ValueError("nonce must be 16 bytes")
        self.mac_key = StaffSponge(b"M", seed, nonce).take(32)
        sp = StaffSponge(b"K", seed, nonce)
        self.rounds = []
        for r in range(NR):
            rk = bytes_to_grid(sp.take(BLOCK_LEN))                       # 128-byte round key as a 16x8 byte grid
            A1 = A2 = None
            while A1 is None or not mat_invertible(A1): A1 = list(sp.take(8))   # resample until invertible
            while A2 is None or not mat_invertible(A2): A2 = list(sp.take(8))
            b1, b2 = sp.take(2)
            S, SI = keyed_sbox(A1, b1, A2, b2)
            SH = [sp.below(8) for _ in range(NF)]                        # face rotations (staves)
            SV = [sp.below(16) for _ in range(NB)]                       # beat-column rotations
            sigma = [sp.perm(NB) for _ in range(NF)]                     # staff butterfly beat order per face
            bridge = sp.perm(64)                                         # inner cell c <-> outer cell bridge[c]
            # Late coloring is squeezed only AFTER the existing round material.
            while True:
                A3 = A4 = None
                while A3 is None or not mat_invertible(A3): A3 = list(sp.take(8))
                while A4 is None or not mat_invertible(A4): A4 = list(sp.take(8))
                b3, b4 = sp.take(2)
                S2, SI2 = keyed_sbox(A3, b3, A4, b4)
                if S2 != S: break
            self.rounds.append(dict(S2=S2, SI2=SI2, A3=A3, A4=A4, b3=b3, b4=b4, rk=rk, S=S, SI=SI, A1=A1, A2=A2, b1=b1, b2=b2,
                                    SH=SH, SV=SV, sigma=sigma, bridge=bridge))
        self.white = bytes_to_grid(sp.take(BLOCK_LEN))
    def material(self) -> bytes:
        """Serialized round keys + whitening (for avalanche tests)."""
        return b"".join(grid_to_bytes(rk["rk"]) for rk in self.rounds) + grid_to_bytes(self.white)

# ---------------------------------------------------------------- two-cell mix (SM4 field; triplets stay integer)
MIX2_MATRIX = ((1, 1), (1, 2))
FIELD_POLY = 0x1F5

def mix2(u, v): return bar_apply(MIX2_MATRIX, u, v)
def mix2_inv(a, b): return bar_apply(MIX2_INV, a, b)

# ---------------------------------------------------------------- face-beat weave (N1 flavor, unchanged)
def weave(g, SH, SV):
    g = [g[f][SH[f]:] + g[f][:SH[f]] for f in range(NF)]
    out = [[0] * NB for _ in range(NF)]
    for b in range(NB):
        for f in range(NF): out[(f + SV[b]) % NF][b] = g[f][b]
    return out
def unweave(g, SH, SV):
    tmp = [[0] * NB for _ in range(NF)]
    for b in range(NB):
        for f in range(NF): tmp[f][b] = g[(f + SV[b]) % NF][b]
    return [tmp[f][-SH[f]:] + tmp[f][:-SH[f]] if SH[f] else tmp[f][:] for f in range(NF)]

# ---------------------------------------------------------------- staff butterfly (along each face)
LAYERS = (1, 2, 4)     # pair beat-order positions i and i^1, then i^2, then i^4: 3 matchings x 4 pairs per face
def staff_mix(g, sigma):
    g = [row[:] for row in g]
    for f in range(NF):
        s, row = sigma[f], g[f]
        for m in LAYERS:
            for i in range(NB):
                if i & m: continue
                a, b = s[i], s[i | m]
                row[a], row[b] = mix2(row[a], row[b])
    return g
def staff_unmix(g, sigma):
    g = [row[:] for row in g]
    for f in range(NF):
        s, row = sigma[f], g[f]
        for m in reversed(LAYERS):
            for i in range(NB):
                if i & m: continue
                a, b = s[i], s[i | m]
                row[a], row[b] = mix2_inv(row[a], row[b])
    return g

# ---------------------------------------------------------------- cross-staff dual-octahedron matchings
# Fixed order: opposite, radial, adjacent, then a partial bridge matching joining both components.
# Matching beats only; lower staff index is always the first mix2 argument.
CROSS_OPPOSITE = ((0,4), (1,5), (2,6), (3,7), (8,12), (9,13), (10,14), (11,15))
CROSS_RADIAL = tuple((f, f + 8) for f in range(8))
CROSS_ADJACENT = tuple((f, f + 1) for f in range(0, 16, 2))
CROSS_BRIDGE = ((1,2), (5,6), (9,10), (13,14))  # intentionally only four disjoint pairs
CROSS_LAYERS = (CROSS_OPPOSITE, CROSS_RADIAL, CROSS_ADJACENT, CROSS_BRIDGE)

def cross_staff_mix(g):
    """Copy and mix matching beats: opposite -> radial -> adjacent -> bridge, after each rehair."""
    g = [row[:] for row in g]
    for matching in CROSS_LAYERS:
        for f, h in matching:
            f, h = sorted((f, h))
            for t in range(NB): g[f][t], g[h][t] = mix2(g[f][t], g[h][t])
    return g

def cross_staff_unmix(g):
    """Undo cross-staff layers in reverse order, without mutating the input."""
    g = [row[:] for row in g]
    for matching in reversed(CROSS_LAYERS):
        for f, h in matching:
            f, h = sorted((f, h))
            for t in range(NB): g[f][t], g[h][t] = mix2_inv(g[f][t], g[h][t])
    return g

# ---------------------------------------------------------------- bar lines (five per staff, four measures of 2/4)
# Bar lines sit at beat boundaries 0, 2, 4, 6, 8 of each open 8-beat staff: | 0 1 | 2 3 | 4 5 | 6 7 |.
# B0 is a keyed Latin pair (field step, then the round's S and S2); the other six pairs use GF(2^8),
# SM4 polynomial 0x1F5 (nonzero field determinants). Applied in bar order B0..B4
# (pairs overlap at beats 1 and 6, so order matters); decrypt applies the inverses in reverse order.
# Plus two interior measure joins M2 (2,3) and M3 (4,5) so every adjacent pair 0-1..6-7 is mixed; 7 mixes total,
# applied in beat order B0,B1,M2,B2,M3,B3,B4 (mid-round bars AND the encore). No end-to-end loop: beat 7 is never paired with beat 0.
BARS = (                                   # (name, boundary, (i, j), matrix [[a, b], [c, d]] or None) : field products and XOR sums
    ("B0 start",  0, (0, 1), None),              # keyed Latin pair; no unused field matrix (review finding 6)
    ("B1 bar 2",  2, (1, 2), ((1, 1), (1, 2))),
    ("M2 beats 3-4", 3, (2, 3), ((3, 5), (1, 2))),   # interior measure join (not a bar line)
    ("B2 center", 4, (3, 4), ((1, 3), (1, 4))),
    ("M3 beats 5-6", 5, (4, 5), ((5, 2), (2, 1))),   # interior measure join (not a bar line)
    ("B3 bar 6",  6, (5, 6), ((2, 1), (1, 1))),
    ("B4 end",    8, (6, 7), ((3, 1), (2, 1))),
)
def _gf_mul_raw(a, b):
    """Polynomial multiplication modulo SM4's x^8+x^7+x^6+x^5+x^4+x^2+1."""
    out = 0
    for _ in range(8):
        if b & 1: out ^= a
        a = ((a << 1) ^ (FIELD_POLY if a & 0x80 else 0)) & 255
        b >>= 1
    return out

# Byte lookup avoids repeated polynomial reductions in every pair pass.
_GF_MUL = tuple(bytes(_gf_mul_raw(a, b) for b in range(256)) for a in range(256))
def gf_mul(a, b): return _GF_MUL[a][b]
def gf_inv(a):
    """Multiplicative inverse in the SM4 field; zero has no inverse."""
    if not a: raise ValueError("zero has no field inverse")
    out, base, power = 1, a, 254
    while power:
        if power & 1: out = gf_mul(out, base)
        base = gf_mul(base, base)
        power >>= 1
    return out

def bar_det(M): return gf_mul(M[0][0], M[1][1]) ^ gf_mul(M[0][1], M[1][0])
def bar_inv(M):
    """Field adjugate: minus equals plus in characteristic two."""
    di = gf_inv(bar_det(M))
    return ((gf_mul(M[1][1], di), gf_mul(M[0][1], di)),
            (gf_mul(M[1][0], di), gf_mul(M[0][0], di)))
MIX2_INV = bar_inv(MIX2_MATRIX)
BARS_INV = tuple(None if M is None else bar_inv(M) for _, _, _, M in BARS)
def bar_apply(M, u, v):
    return (gf_mul(M[0][0], u) ^ gf_mul(M[0][1], v),
            gf_mul(M[1][0], u) ^ gf_mul(M[1][1], v))
# Keyed Latin pair (B0 and the four odd-rehair pairs). Field step = MIX2_MATRIX ((1,1),(1,2)),
# then one keyed bijective S-box per output cell. round_enc passes the round's S (u') and S2 (v').
# A change in u alone changes x and y by the same nonzero d; a change in v alone changes x by d
# and y by gf_mul(2,d) != 0. Bijective S-boxes keep both changes, so a one-input change always
# changes BOTH outputs (for every pair of tables). Two-input changes can still cancel one output.
def latin_pair(u, v, Sa, Sb):
    """x = u ^ v, y = u ^ gf_mul(2, v); return (Sa[x], Sb[y])."""
    x, y = u ^ v, u ^ gf_mul(2, v)
    return Sa[x], Sb[y]

def latin_unpair(u, v, SIa, SIb):
    """Inverse: x = SIa[u], y = SIb[v]; x ^ y = gf_mul(3, v), so v = gf_mul(gf_inv(3), x ^ y); u = x ^ v."""
    x, y = SIa[u], SIb[v]
    v = gf_mul(gf_inv(3), x ^ y)
    return x ^ v, v

def b0_apply(u, v, Sa, Sb):
    """Keyed B0: Latin pair with the caller's tables (round S for u', round S2 for v')."""
    return latin_pair(u, v, Sa, Sb)

def b0_unapply(u, v, SIa, SIb):
    return latin_unpair(u, v, SIa, SIb)

def bar_mix(g, Sa, Sb):
    g = [row[:] for row in g]
    for row in g:
        for name, _, (i, j), M in BARS:
            row[i], row[j] = b0_apply(row[i], row[j], Sa, Sb) if name == "B0 start" else bar_apply(M, row[i], row[j])
    return g
def bar_unmix(g, SIa, SIb):
    g = [row[:] for row in g]
    for row in g:
        for k in range(len(BARS) - 1, -1, -1):
            i, j = BARS[k][2]
            row[i], row[j] = b0_unapply(row[i], row[j], SIa, SIb) if BARS[k][0] == "B0 start" else bar_apply(BARS_INV[k], row[i], row[j])
    return g

# ---------------------------------------------------------------- overlapping triplets (open staffs, Z/256Z)
# Every adjacent window of three beats, in ascending order; never wrap 7 to 0.
# Small det-1 matrices found by search. Each row/column has >=2 odd entries.
# Thus a nonzero difference in any ONE input changes >=2 outputs, for all values:
# odd multiplication is a unit mod 256. This is not an all-odd/MDS matrix claim.
TRIPLETS = (
    ("T0", (0, 1, 2), ((5, 1, 1), (2, 3, 1), (5, 5, 2))),
    ("T1", (1, 2, 3), ((1, 3, 1), (3, 5, 2), (3, 2, 1))),
    ("T2", (2, 3, 4), ((2, 1, 1), (1, 3, 1), (3, 3, 2))),
    ("T3", (3, 4, 5), ((3, 3, 1), (2, 5, 3), (1, 3, 2))),
    ("T4", (4, 5, 6), ((1, 1, 1), (1, 3, 2), (3, 2, 3))),
    ("T5", (5, 6, 7), ((2, 1, 3), (3, 1, 3), (1, 2, 5))),
)
def triplet_det(M):
    a, b, c = M[0]; d, e, f = M[1]; g, h, i = M[2]
    return (a * (e*i - f*h) - b * (d*i - f*g) + c * (d*h - e*g)) & 255

def triplet_inv(M):
    """Adjugate/determinant inverse over Z/256Z (determinant must be odd)."""
    di = pow(triplet_det(M), -1, 256)
    cof = []
    for i in range(3):
        row = []
        for j in range(3):
            minor = [[M[r][c] for c in range(3) if c != j] for r in range(3) if r != i]
            row.append((-1 if (i+j) & 1 else 1) * (minor[0][0]*minor[1][1] - minor[0][1]*minor[1][0]))
        cof.append(row)
    return tuple(tuple(cof[j][i] * di & 255 for j in range(3)) for i in range(3))

TRIPLETS_INV = tuple(triplet_inv(M) for _, _, M in TRIPLETS)
def triplet_apply(M, u, v, w):
    return tuple((a*u + b*v + c*w) & 255 for a, b, c in M)
def triplet_mix(g):
    g = [row[:] for row in g]
    for row in g:
        for _, (i, j, k), M in TRIPLETS:
            row[i], row[j], row[k] = triplet_apply(M, row[i], row[j], row[k])
    return g
def triplet_unmix(g):
    g = [row[:] for row in g]
    for row in g:
        for t in range(len(TRIPLETS) - 1, -1, -1):
            i, j, k = TRIPLETS[t][1]
            row[i], row[j], row[k] = triplet_apply(TRIPLETS_INV[t], row[i], row[j], row[k])
    return g

# ---------------------------------------------------------------- bow pressure (one open staff; pressure READ may wrap)
BOW_STROKES = ((0, 1, 2), (2, 3, 4), (4, 5, 0), (6, 7, 0),
               (1, 2, 3), (3, 4, 5), (5, 6, 0))
# Beat-7 fix (2026-11-09): the last stroke used to read its pressure from beat 7 ((5,6,7)). A beat-7-only
# change then also changed that stroke's rotations, so beat 5 could come out unchanged and the whole bow
# delta stayed inside rehair pair (6,7); when that two-cell delta hit the pair's field kernel (du=dv or
# du=2dv) the rehair left a single changed byte. With pressure read from beat 0 (never written after
# stroke (0,1,2)), a beat-7 change reaches beat 6 in (6,7,0) and then ALWAYS changes beat 5 in (5,6,0)
# (fixed rotation, u fixed, v changed), so the delta spans pairs (4,5) and (6,7). Beats 1, 3, 5 keep the
# same no-singleton argument (see SPEC.md "Bow pressure"). Strokes and unbow order are otherwise unchanged.
# Beat-6 fix (2026-11-09, after attacks_octavo_beat7): the third stroke used to read its pressure from beat 6
# ((4,5,6)). A beat-6-only change then changed that stroke's r2, shifted beat 5, and (5,6,0) could cancel the
# shift again, leaving a delta du=2dv inside rehair pair (6,7) -> one changed byte (~1e-6 of beat-6 changes).
# Now (4,5,0): beat 6 is read by no stroke before (6,7,0); there (fixed rotations) beat 7 always changes and
# is never written again, and (5,6,0) (fixed rotations) adds the changed beat 6 into an unchanged beat 5, so
# beats 5 and 7 both change -> the delta spans pairs (4,5) and (6,7). Cost: beat 0 now feeds the rotations of
# three strokes ((4,5,0), (6,7,0), (5,6,0)); bow-alone best beat-6 differential ~2^-7.75 -> ~2^-5.68 (the
# rehair S-boxes absorb it). Even beats 0, 2, 4 are covered by measurement only, not by this argument.
# Beat-0 pressure-rotation fix (2026-11-09, after attacks_octavo_beat6 §6): BOW_STROKES unchanged, but each
# beat-0 reader gets a different view of the pressure byte before the r1/r2 formulas. (4,5,0) uses p,
# (6,7,0) uses rotl8(p,3), (5,6,0) uses rotl8(p,5). Other strokes keep rot 0 (identity). Singleton
# arguments that only need "pressure unchanged => rotations fixed" still hold; beat 0 is not written after
# stroke 1, so the bow stays invertible. Lab screen: bow-alone best diffs beat 7/6/0 ~2^-4.7/2^-5.6/2^-8.1
# -> ~2^-7.4/2^-7.1/2^-10.2; integrals/cubes of fixed-rotation ARX are not removed.
BOW_ROT_BASE, BOW_ROT_MOD, BOW_R2_SHIFT = 1, 7, 3
# Per-stroke left-rotate of the pressure byte BEFORE r1/r2, aligned with BOW_STROKES. Non-beat-0 readers
# use 0 (identity). The three beat-0 readers use 0, 3, 5 so they no longer share identical (r1, r2).
BOW_PRESSURE_ROT = (0, 0, 0, 3, 0, 0, 5)

def rotl8(x, n): return ((x << n) | (x >> (8 - n))) & 255

def bow_stroke(u, v, p):
    r1 = BOW_ROT_BASE + (p % BOW_ROT_MOD)
    r2 = BOW_ROT_BASE + ((p >> BOW_R2_SHIFT) % BOW_ROT_MOD)
    u = (u + rotl8(v, r1)) & 255
    v = v ^ rotl8(u, r2)
    return u, v

def unbow_stroke(u, v, p):
    r1 = BOW_ROT_BASE + (p % BOW_ROT_MOD)
    r2 = BOW_ROT_BASE + ((p >> BOW_R2_SHIFT) % BOW_ROT_MOD)
    v = v ^ rotl8(u, r2)
    u = (u - rotl8(v, r1)) & 255
    return u, v

def bow_pressure(staff):
    s = list(staff)
    if len(s) != NB: raise ValueError("staff must have 8 bytes")
    for (i, j, p), k in zip(BOW_STROKES, BOW_PRESSURE_ROT):
        s[i], s[j] = bow_stroke(s[i], s[j], rotl8(s[p], k))
    return s

def unbow_pressure(staff):
    s = list(staff)
    if len(s) != NB: raise ValueError("staff must have 8 bytes")
    for (i, j, p), k in zip(reversed(BOW_STROKES), reversed(BOW_PRESSURE_ROT)):
        s[i], s[j] = unbow_stroke(s[i], s[j], rotl8(s[p], k))
    return s

# ---------------------------------------------------------------- odd-beat rehair (open staff, no pressure read)
def odd_restack(staff, Sa, Sb):
    """Copy; keyed Latin pair on each odd beat and its previous even neighbor, never (7,0)."""
    s = list(staff)
    if len(s) != NB: raise ValueError("staff must have 8 bytes")
    for t in (1, 3, 5, 7):
        s[t-1], s[t] = latin_pair(s[t-1], s[t], Sa, Sb)
    return s

def unodd_restack(staff, SIa, SIb):
    s = list(staff)
    if len(s) != NB: raise ValueError("staff must have 8 bytes")
    for t in (7, 5, 3, 1):
        s[t-1], s[t] = latin_unpair(s[t-1], s[t], SIa, SIb)
    return s

# Key-signature code coverage. MIX_CODE_ROOTS are the public entry points. mix_code_closure()
# walks, on EVERY call, the source of each reachable module-level function/class (ast.Name
# references resolved in this module's CURRENT globals), so a replaced function and any new
# module-level helper it names are followed. MIX_CODE_FUNCS is the explicit, ordered list of
# what the closure reaches today (a test asserts equality); mix_description() hashes the list
# plus anything extra the live closure finds. Module-level data reached by the closure
# (BARS, TRIPLETS, CROSS_*, BOW_*, SM4_SBOX, _GF_MUL, sizes, ...) is canonically encoded and
# hashed too. Unencodable data or unreadable source fails closed (raises), never silently skips.
# Limits (honest): this is source attestation of the running process, not runtime integrity.
# It cannot see C-level/interpreter changes, the stdlib (hashlib, hmac, os, json, inspect, ast),
# helpers defined in OTHER modules that a foreign replacement function calls, mutation of
# objects inside a function's runtime state, code whose __code__ differs from the file
# inspect reads, or an attacker who also patches inspect/mix_description consistently.
MIX_CODE_ROOTS = ("encrypt", "decrypt", "siv_nonce", "key_signature", "split_blob", "mix_description", "encrypt_movements", "decrypt_movements", "siv_nonce_movements", "decrypt_legacy", "decrypt_movements_legacy")
MIX_CODE_FUNCS = (
    "bar_mix", "bar_unmix", "triplet_mix", "triplet_unmix", "triplet_apply",
    "triplet_det", "triplet_inv", "bow_pressure", "unbow_pressure",
    "bow_stroke", "unbow_stroke", "rotl8", "cross_staff_mix", "cross_staff_unmix",
    "odd_restack", "unodd_restack", "b0_apply", "b0_unapply", "latin_pair", "latin_unpair",
    "round_enc", "round_dec", "mix2", "mix2_inv",
    "bar_apply", "bar_inv", "bar_det", "gf_mul", "gf_inv", "_gf_mul_raw",
    # added 2026-11-09 (signature-gap fix): everything else round_enc/round_dec, the schedule,
    # the block encoding, whitening, SIV nonce, MAC and the attestation itself reach.
    "staff_mix", "staff_unmix", "shell_mix", "shell_unmix", "weave", "unweave", "xor_grid",
    "encrypt_grid", "decrypt_grid", "bytes_to_grid", "grid_to_bytes", "encode_block",
    "Schedule", "StaffSponge", "keyed_sbox", "mat_apply", "mat_invertible",
    "staff_clef", "siv_nonce", "_tag", "_encode_ad", "_as_bytes", "_normalize_ad", "_fresh_pickup", "encrypt", "decrypt", "split_blob",
    "key_signature", "mix_description", "mix_code_closure", "_referenced_globals", "_canon_data",
    "_seed_bytes", "load_seed", "AuthError", "DecodeError", "UnsupportedVersion",
    "_commit_key", "_commitment", "_legacy_key_signature",
    "encrypt_movements", "decrypt_movements", "siv_nonce_movements",
    "decrypt_legacy", "decrypt_movements_legacy",
    "_chunk_movements", "_xor_bytes", "_theme_start", "_theme_next", "_movement_tweak",
    "_cadence_key", "_coda_key", "_cadence_tag", "_coda_tag", "_final_flag",
    "_decrypt_legacy_v2", "_decrypt_legacy_v3",
    # added 2026-11-11 (conductor): constant-structure unpad, legacy opt-in gate and its warning class.
    "_unpad_block", "_require_noncommitting", "LegacyFormatWarning",
    # added 2026-11-11 (conductor-polish): shared reject parent, derived-key marker.
    "Rejected", "_DerivedKey",
)

def _referenced_globals(obj):
    """Every bare name in obj's source (ast.Name); resolution happens in mix_code_closure."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(obj)))
    return {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}

# Runtime attestation helpers and path-dependent values. Not hashed: EXPECTED_MIX_SHA256
# is the digest of the hash itself, SEED_PATH is an absolute install location, and
# REVISION/REVISION_DATE/FEATURES/WARNING_LINE are picture-header metadata.
_ATTEST_SKIP = frozenset({
    "EXPECTED_MIX_SHA256", "_MIX_SHA256", "_SOURCE_AVAILABLE", "_ATTEST_SKIP",
    "SEED_PATH",
    "REVISION", "REVISION_DATE", "FEATURES", "WARNING_LINE",
    "EXPECTED_REHEARSAL_SHA256", "_REHEARSAL_SHA256",
    "_MODULE_SOURCE", "_MODULE_SOURCE_SHA256",
})

def mix_code_closure(roots=None):
    """(code names, data names) of module globals reachable from roots, recomputed per call."""
    g = globals(); code, data = set(), set()
    todo = list(MIX_CODE_ROOTS if roots is None else roots)
    while todo:
        name = todo.pop()
        if name in _ATTEST_SKIP: continue
        if name in code or name in data or name not in g: continue
        obj = g[name]
        if isinstance(obj, types.ModuleType): continue
        if isinstance(obj, (types.FunctionType, type)):
            code.add(name); todo.extend(sorted(_referenced_globals(obj)))
        else:
            data.add(name)
    return code, data

def _canon_data(x):
    """Canonical text for module data reached by the mix closure.

    None/bool/int/float/complex/str/bytes use type-name plus repr. bytearray and
    memoryview are encoded as their type name plus repr(bytes(...)). set and
    frozenset are encoded in _canon_data-sorted order so the digest does not
    depend on iteration order. tuples, lists, and dicts (keys sorted the same
    way) are nested. Any other type raises TypeError with the type name, so a
    new constant type is an explicit error rather than a silent skip.
    """
    if x is None or isinstance(x, (bool, int, float, complex, str, bytes)):
        return type(x).__name__ + ":" + repr(x)
    if isinstance(x, (bytearray, memoryview)):
        return type(x).__name__ + ":" + repr(bytes(x))
    if isinstance(x, (tuple, list)):
        return type(x).__name__ + "[" + ",".join(_canon_data(y) for y in x) + "]"
    if isinstance(x, (set, frozenset)):
        return type(x).__name__ + "{" + ",".join(_canon_data(y) for y in sorted(x, key=_canon_data)) + "}"
    if isinstance(x, dict):
        return "dict{" + ",".join(_canon_data(k) + "=" + _canon_data(x[k]) for k in sorted(x, key=_canon_data)) + "}"
    raise TypeError("cannot attest object of type " + type(x).__name__)

def mix_description():
    """Canonical ASCII JSON of parameters and listed mix function sources.
    Source is recomputed on each call; unavailable source fails closed, not silent.
    Length-framed names and sources make the digest unambiguous and stable.
    """
    reach, data_names = mix_code_closure()
    funcs = tuple(MIX_CODE_FUNCS) + tuple(sorted(reach - set(MIX_CODE_FUNCS)))
    code = hashlib.sha256()
    for name in funcs:
        obj = globals()[name]
        if not isinstance(obj, (types.FunctionType, type)): raise TypeError(name + " is not an attestable Python function/class")
        defaults = _canon_data((getattr(obj, "__defaults__", None), getattr(obj, "__kwdefaults__", None)))
        for part in (name.encode("utf-8"), inspect.getsource(obj).encode("utf-8"), defaults.encode("utf-8")):
            code.update(len(part).to_bytes(8, "big")); code.update(part)
    data = hashlib.sha256()
    for name in sorted(data_names):
        for part in (name.encode("utf-8"), _canon_data(globals()[name]).encode("utf-8")):
            data.update(len(part).to_bytes(8, "big")); data.update(part)
    bars = [dict(name=name, boundary=boundary, pair=pair, kind="field+keyed-sbox",
                 field=MIX2_MATRIX, tables="u'=S[x];v'=S2[y];inverse SI,SI2") if name == "B0 start" else
            dict(name=name, boundary=boundary, pair=pair, kind="GF(2^8)", matrix=M)
            for name, boundary, pair, M in BARS]
    return json.dumps(dict(bars=bars, triplets=TRIPLETS, mix2=MIX2_MATRIX,
        mix_code=dict(functions=funcs, roots=MIX_CODE_ROOTS, sha256=code.hexdigest(),
                      framing="per function: name, source, canonical defaults; each UTF-8 part prefixed by uint64be length"),
        mix_data=dict(names=tuple(sorted(data_names)), sha256=data.hexdigest(),
                      framing="per name (sorted): name, _canon_data(value); each UTF-8 part prefixed by uint64be length"),
        field_poly=FIELD_POLY, pair_ring="GF(2^8); B0 keyed Latin pair", triplet_ring="Z/256Z",
        bow=dict(strokes=BOW_STROKES, pressure_rot=BOW_PRESSURE_ROT,
                 rot_base=BOW_ROT_BASE, rot_mod=BOW_ROT_MOD, r2_shift=BOW_R2_SHIFT,
                 formula="view=rotl8(p,pressure_rot[stroke]);r1=base+view%mod;r2=base+(view>>shift)%mod;u=(u+rotl8(v,r1))&255;v=v^rotl8(u,r2)",
                 placement="after-mid-triplets-before-rehair;after-encore-triplets-before-rehair"),
        odd_restack=dict(beats=(1,3,5,7), pairs=((0,1),(2,3),(4,5),(6,7)),
                 kind="field+keyed-sbox", field=MIX2_MATRIX, tables="u'=S[x];v'=S2[y];inverse SI,SI2",
                 formula="x=u^v;y=u^gf_mul(2,v);u'=S[x];v'=S2[y]",
                 placement="after-each-bow-before-cross"),
        cross_staff=dict(opposite=CROSS_OPPOSITE, radial=CROSS_RADIAL,
                 adjacent=CROSS_ADJACENT, bridge=CROSS_BRIDGE, layers=CROSS_LAYERS,
                 order="opposite;radial;adjacent;bridge", orientation="lower-index-first",
                 beats="matching-beats-0..7", operation="mix2",
                 placement="after-mid-rehair-before-S2;after-encore-rehair")),
        sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")

def key_signature(seed=None):
    """Seed-keyed commitment to this revision's attested mix_description digest.
    The sponge nonce is the 32-byte sha256(mix_description()), computed once at
    import from source or taken from EXPECTED_MIX_SHA256 when source is absent
    (a .pyc-only install). Not a blob field or API override."""
    return StaffSponge(b"G", _seed_bytes(seed), bytes.fromhex(_MIX_SHA256)).take(16)

# ---------------------------------------------------------------- shell bridges (inner <-> outer)
def shell_mix(g, bridge, r):
    """64 disjoint pairs: inner cell c=(f,t), f<8, with outer cell bridge[c]. The 'u' side alternates
    by round (even: inner, odd: outer) — N1's alternating-shell idea kept as orientation."""
    g = [row[:] for row in g]
    for c in range(64):
        fi, ti = divmod(c, NB); fo, to = divmod(bridge[c], NB); fo += 8
        if r % 2 == 0: g[fi][ti], g[fo][to] = mix2(g[fi][ti], g[fo][to])
        else:          g[fo][to], g[fi][ti] = mix2(g[fo][to], g[fi][ti])
    return g
def shell_unmix(g, bridge, r):
    g = [row[:] for row in g]
    for c in range(64):
        fi, ti = divmod(c, NB); fo, to = divmod(bridge[c], NB); fo += 8
        if r % 2 == 0: g[fi][ti], g[fo][to] = mix2_inv(g[fi][ti], g[fo][to])
        else:          g[fo][to], g[fi][ti] = mix2_inv(g[fo][to], g[fi][ti])
    return g

# ---------------------------------------------------------------- round
def xor_grid(g, k): return [[g[f][t] ^ k[f][t] for t in range(NB)] for f in range(NF)]

def round_enc(g, rk, r):
    g = xor_grid(g, rk["rk"])                                            # 1. add round key
    S = rk["S"]; g = [[S[x] for x in row] for row in g]                  # 2. SubBytes (keyed 8-bit S-box), all 128 cells
    g = weave(g, rk["SH"], rk["SV"])                                     # 3. face-beat weave
    g = staff_mix(g, rk["sigma"])                                        # 4. staff butterfly (within faces)
    g = shell_mix(g, rk["bridge"], r)                                    # 5. shell bridges (across shells)
    g = bar_mix(g, rk["S"], rk["S2"])                                    # 6. seven named pair mixes
    g = triplet_mix(g)                                                  # 7. six overlapping triplets
    g = [bow_pressure(row) for row in g]                                 # nonlinear mid-stack restack
    g = [odd_restack(row, rk["S"], rk["S2"]) for row in g]                                  # lighter odd-beat rehair
    g = cross_staff_mix(g)                                              # between staffs, before S2
    S2 = rk["S2"]; g = [[S2[x] for x in row] for row in g]               # 8. late second coloring
    g = bar_mix(g, rk["S"], rk["S2"])                                    # 9. pair-mix encore
    g = triplet_mix(g)                                                  # 10. triplet encore
    g = [bow_pressure(row) for row in g]                                 # nonlinear encore restack
    g = [odd_restack(row, rk["S"], rk["S2"]) for row in g]                                  # encore rehair
    return cross_staff_mix(g)

def round_dec(g, rk, r):
    g = cross_staff_unmix(g)                                            # undo encore cross FIRST
    g = [unodd_restack(row, rk["SI"], rk["SI2"]) for row in g]
    g = [unbow_pressure(row) for row in g]
    g = triplet_unmix(g)                                                # undo encore triplets FIRST
    g = bar_unmix(g, rk["SI"], rk["SI2"])                                # then encore bars
    SI2 = rk["SI2"]; g = [[SI2[x] for x in row] for row in g]
    g = cross_staff_unmix(g)                                            # undo mid cross
    g = [unodd_restack(row, rk["SI"], rk["SI2"]) for row in g]
    g = [unbow_pressure(row) for row in g]
    g = triplet_unmix(g)
    g = bar_unmix(g, rk["SI"], rk["SI2"])
    g = shell_unmix(g, rk["bridge"], r)
    g = staff_unmix(g, rk["sigma"])
    g = unweave(g, rk["SH"], rk["SV"])
    SI = rk["SI"]; g = [[SI[x] for x in row] for row in g]
    return xor_grid(g, rk["rk"])

def encrypt_grid(g, sch: Schedule, rounds=NR, white=True):
    for r in range(rounds): g = round_enc(g, sch.rounds[r], r)
    return xor_grid(g, sch.white) if white else g
def decrypt_grid(g, sch: Schedule, rounds=NR):
    g = xor_grid(g, sch.white)
    for r in range(rounds - 1, -1, -1): g = round_dec(g, sch.rounds[r], r)
    return g

# ---------------------------------------------------------------- encoding: 128 bytes <-> 16 faces x 8 byte-beats
def bytes_to_grid(b: bytes):
    if len(b) != BLOCK_LEN: raise ValueError("block must be 128 bytes")
    return [list(b[8 * f: 8 * f + 8]) for f in range(NF)]
def grid_to_bytes(g):
    return bytes(x for row in g for x in row)
def grid_rows(g):
    """each staff as two measures of four 2-digit hex bytes: 'AA BB CC DD | EE FF 00 11'"""
    return [" ".join(f"{x:02X}" for x in row[:4]) + " | " + " ".join(f"{x:02X}" for x in row[4:]) for row in g]

def encode_block(msg: bytes) -> bytes:
    if len(msg) > MAX_MSG: raise ValueError("message too long (max 127 bytes)")
    return bytes([len(msg)]) + msg + bytes(MAX_MSG - len(msg))

# Fixed-width masks for _unpad_block (conductor-polish L3). Payload bytes 1..127 are read as one
# 1016-bit big-endian integer; _UNPAD_MASKS[L] selects the pad region (bytes L+1..127). Every mask
# and every accumulator carries the same top bit, so each operand is a 1017-bit integer whatever L is.
_UNPAD_TOP = 1 << (8 * MAX_MSG)
_UNPAD_MASKS = tuple(_UNPAD_TOP | ((1 << (8 * (MAX_MSG - L))) - 1) for L in range(MAX_MSG + 1))

def _unpad_block(b: bytes):
    """Fixed-width inverse of encode_block (conductor L4, conductor-polish L3): -> (ok, msg).

    bad_len is a 0/1 flag for L > 127. The 127 payload bytes become one
    integer, OR-ed with a fixed top bit and AND-ed with the pad-region mask
    for L & 127, so every big-int operation works on same-size operands
    and no loop or branch depends on L. ok is False exactly when the old
    check `L > 127 or any(b[1+L:])` was true. Python is still not
    constant-time (the final compare and the slice are not); the Rust
    port requirement in SECURITY.md stands."""
    L = b[0]
    bad = ((MAX_MSG - L) >> 8) & 1                      # 1 iff L > 127 (L is 0..255)
    payload = bytes(b[1:BLOCK_LEN])
    acc = (int.from_bytes(payload, "big") | _UNPAD_TOP) & _UNPAD_MASKS[L & MAX_MSG]
    bad |= (acc ^ _UNPAD_TOP) != 0                      # any nonzero byte in the pad region
    return bad == 0, payload[:L & MAX_MSG]

# ---------------------------------------------------------------- AE API
def staff_clef(seed=None) -> bytes:
    """seed-only clef: StaffSponge(b"C", seed, 16 zero bytes).take(16). Never stored in the blob."""
    return StaffSponge(b"C", _seed_bytes(seed), bytes(NONCE_LEN)).take(16)

def _as_bytes(name, value) -> bytes:
    """Accept bytes, bytearray, or memoryview; reject anything else with TypeError."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise TypeError("%s must be bytes-like, not %s" % (name, type(value).__name__))

def _normalize_ad(ad) -> bytes:
    """Type-check associated data and enforce MAX_AD_LEN."""
    ad = _as_bytes("ad", ad)
    if len(ad) > MAX_AD_LEN:
        raise ValueError("associated data too long (max %d bytes)" % MAX_AD_LEN)
    return ad

def _encode_ad(ad: bytes = b"") -> bytes:
    """Unambiguous associated-data encoding: uint64be(len(ad)) || ad. Not stored in the blob."""
    ad = _normalize_ad(ad)
    return len(ad).to_bytes(8, "big") + ad

def _fresh_pickup() -> bytes:
    """16-byte pickup that cannot repeat in-process even if os.urandom returns the same bytes.
    SHA-256(b"SN2/P" || urandom(16) || time_ns(8) || counter(8) || pid(4))[:16]."""
    _fresh_pickup.n += 1
    mix = (os.urandom(PICKUP_LEN)
           + time.time_ns().to_bytes(8, "big")
           + _fresh_pickup.n.to_bytes(8, "big")
           + os.getpid().to_bytes(4, "big"))
    return hashlib.sha256(b"SN2/P" + mix).digest()[:PICKUP_LEN]
_fresh_pickup.n = 0

def siv_nonce(msg: bytes, pickup: bytes, seed=None, ad: bytes = b"") -> bytes:
    """homemade SIV-style nonce = SHA-256(clef || pickup || encode_block(msg) || encode_ad(ad))[:16]"""
    msg = _as_bytes("msg", msg)
    pickup = _as_bytes("pickup", pickup)
    ad = _normalize_ad(ad)
    if len(pickup) != PICKUP_LEN: raise ValueError("pickup must be 16 bytes")
    return hashlib.sha256(staff_clef(seed) + pickup + encode_block(msg) + _encode_ad(ad)).digest()[:NONCE_LEN]

def _legacy_key_signature(seed=None):
    """key_signature as of the etudes / octavo009 mix digest. Used only to open
    legacy v2/v3 and old-étude blobs. Not a substitute for the live key_sig."""
    return StaffSponge(b"G", _seed_bytes(seed), bytes.fromhex(LEGACY_MIX_SHA256)).take(16)

def _commit_key(seed=None) -> bytes:
    """Seed-only tuning key: StaffSponge(b"U", seed, 16 zero bytes).take(32).
    Independent of the message nonce so decrypt can check the commitment
    before any nonce-derived MAC key or Schedule work."""
    return StaffSponge(COMMIT_DOMAIN, _seed_bytes(seed), bytes(NONCE_LEN)).take(32)

def _commitment(commit_key, version, pickup, nonce, ad=b"", nmov=None) -> bytes:
    """HMAC-SHA256(K_commit, b"U" || version || SN2 || pickup || nonce || encode_ad(ad) [|| nmov32]).
    The domain letter U is pinned in the HMAC input so this value cannot
    be confused with the M/D/O tags. Associated data is bound so a captured
    blob cannot confirm the key without AD. Movements also bind nmov
    (4-byte big-endian count) so a rewritten movement count fails the
    commitment before the body is parsed. Ciphertext is left to the tag
    or coda, so a wrong key still returns before a huge body is walked."""
    data = COMMIT_DOMAIN + bytes([version]) + VERSION + pickup + nonce + _encode_ad(ad)
    if nmov is not None:
        data += int(nmov).to_bytes(4, "big")
    return hmac.new(commit_key, data, hashlib.sha256).digest()

def _tag(mac_key, pickup, nonce, ct, clef, key_sig, ad: bytes = b"", version=None, commit: bytes = b""):
    if version is None:
        version = FMT_VERSION
    return hmac.new(mac_key, clef + key_sig + bytes([version]) + VERSION + pickup + nonce + commit + ct + _encode_ad(ad), hashlib.sha256).digest()

def encrypt(msg: bytes, seed=None, nonce: bytes = None, ad: bytes = b"") -> bytes:
    """blob = version(1)=6 || b"SN2" || pickup(16) || nonce(16) || commit(32) || ct(128) || HMAC-SHA256(mac_key, clef || key_sig || version || b"SN2" || pickup || nonce || commit || ct || encode_ad(ad)).
    commit = HMAC-SHA256(K_commit, b"U" || version || b"SN2" || pickup || nonce || encode_ad(ad)), with K_commit = StaffSponge(b"U", seed, 16 zero bytes).take(32).
    pickup = _fresh_pickup() every call (no public pickup argument, by design);
    nonce = SHA-256(clef || pickup || encode_block(msg) || encode_ad(ad))[:16]; a caller nonce must equal it (ValueError otherwise).
    ad is authenticated and not stored in the blob; empty and omitted AD are the same.
    msg and ad must be bytes-like (bytes, bytearray, memoryview); other types raise TypeError.
    Associated data longer than MAX_AD_LEN raises ValueError."""
    msg = _as_bytes("msg", msg); ad = _normalize_ad(ad); block = encode_block(msg); adb = _encode_ad(ad); clef = staff_clef(seed)
    pickup = _fresh_pickup()
    syn = hashlib.sha256(clef + pickup + block + adb).digest()[:NONCE_LEN]
    if nonce is not None and not hmac.compare_digest(_as_bytes("nonce", nonce), syn):
        raise ValueError("nonce must be the synthetic (SIV) nonce for this message and pickup")
    nonce = syn
    sch = Schedule(seed, nonce)
    ct = grid_to_bytes(encrypt_grid(bytes_to_grid(block), sch))
    commit = _commitment(_commit_key(seed), FMT_VERSION, pickup, nonce, ad)
    tag = _tag(sch.mac_key, pickup, nonce, ct, clef, key_signature(seed), ad, version=FMT_VERSION, commit=commit)
    return bytes([FMT_VERSION]) + VERSION + pickup + nonce + commit + ct + tag

def split_blob(blob: bytes):
    """-> (version_prefix, pickup, nonce, commit, ct, tag) for a current (v6 / committed) single-block blob."""
    return blob[:PK0], blob[PK0:N0], blob[N0:CM0], blob[CM0:CM1], blob[CM1:CT1], blob[CT1:]

def decrypt(blob: bytes, seed=None, ad: bytes = b"") -> bytes:
    """Format version is checked first, then length and prefix. Then, for
    every v6 blob, BOTH the tuning commitment and the tag are computed and
    compared (hmac.compare_digest each), the two results are combined
    without short-circuit, and one AuthError("authentication failed") is
    raised if either failed (equal-time reject, conductor M1). A wrong key,
    wrong AD, bad commitment, bad ciphertext and bad tag therefore all do
    the same work before rejecting. No Schedule is built before both pass.
    Legacy v2 and unpublished v4 blobs are rejected as UnsupportedVersion
    (not an AuthError). Use decrypt_legacy(..., allow_noncommitting=True)
    to open published octavo009 v2 blobs during the transition; that path
    is not key-committing.
    The same associated data supplied to encrypt must be supplied here; it is not in the blob.
    blob and ad must be bytes-like; other types raise TypeError. AD longer than MAX_AD_LEN raises ValueError.
    The HMAC is verified from the MAC key alone; the full round Schedule is built only after the tag passes."""
    blob = _as_bytes("blob", blob); ad = _normalize_ad(ad)
    if len(blob) < 1: raise AuthError("bad blob length")
    if blob[0] != FMT_VERSION: raise UnsupportedVersion("unsupported version")
    if len(blob) != BLOB_LEN: raise AuthError("bad blob length")
    v, pickup, nonce, commit, ct, tag = split_blob(blob)
    if not hmac.compare_digest(v, bytes([FMT_VERSION]) + VERSION): raise AuthError("bad version prefix")
    # Equal-time reject: always compute both, combine with & (no short-circuit), raise once.
    commit_ok = hmac.compare_digest(commit, _commitment(_commit_key(seed), FMT_VERSION, pickup, nonce, ad))
    clef = staff_clef(seed)
    mac_key = StaffSponge(b"M", _seed_bytes(seed), nonce).take(32)
    tag_ok = hmac.compare_digest(tag, _tag(mac_key, pickup, nonce, ct, clef, key_signature(seed), ad, version=FMT_VERSION, commit=commit))
    if not (commit_ok & tag_ok): raise AuthError("authentication failed")
    sch = Schedule(seed, nonce)
    b = grid_to_bytes(decrypt_grid(bytes_to_grid(ct), sch))
    ok, msg = _unpad_block(b)                  # secondary sanity check only; the MAC is the authenticity check
    if not ok: raise DecodeError("tag valid but block malformed")
    if not hmac.compare_digest(nonce, hashlib.sha256(clef + pickup + encode_block(msg) + _encode_ad(ad)).digest()[:NONCE_LEN]):
        raise AuthError("SIV nonce mismatch")
    return msg

def _require_noncommitting(allow, name, warn=True):
    """Gate for every non-committing legacy helper: refuse unless the caller passed
    allow_noncommitting=True (exactly True), then (warn=True) emit LegacyFormatWarning.
    The public wrappers check the flag first with warn=False; the private bodies check it
    again and emit the single warning (conductor-polish I2), so calling a private body
    directly is gated the same way."""
    if allow is not True:
        raise ValueError(name + " opens non-committing legacy blobs; pass allow_noncommitting=True")
    if warn:
        warnings.warn(name + ": legacy format is not key-committing; transition use only",
                      LegacyFormatWarning, stacklevel=4)

def decrypt_legacy(blob: bytes, seed=None, ad: bytes = b"", *, allow_noncommitting=False) -> bytes:
    """Open a published format-version-2 single-block blob (octavo009 and earlier).

    Transition helper only. Not key-committing: there is no tuning field,
    and tags bind the frozen octavo009 key_sig. Requires
    allow_noncommitting=True (ValueError otherwise) and emits
    LegacyFormatWarning on every call. Default decrypt() rejects these
    blobs with UnsupportedVersion. Do not use for new messages.
    Unpublished v4 (tuning) blobs are also rejected.
    """
    _require_noncommitting(allow_noncommitting, "decrypt_legacy", warn=False)
    blob = _as_bytes("blob", blob); ad = _normalize_ad(ad)
    if len(blob) < 1: raise AuthError("bad blob length")
    if blob[0] != FMT_VERSION_V2:
        raise UnsupportedVersion("unsupported version")
    return _decrypt_legacy_v2(blob, seed, ad, allow_noncommitting=allow_noncommitting)

def _decrypt_legacy_v2(blob: bytes, seed, ad: bytes, *, allow_noncommitting=False) -> bytes:
    """Open a format-version-2 single-block blob (no tuning). Tags bind the
    frozen octavo009 key_sig. Not key-committing. Same decode and SIV checks.
    Gated and version-pinned here too (conductor-polish I2): needs
    allow_noncommitting=True, emits LegacyFormatWarning, and opens only blob[0] == 2."""
    _require_noncommitting(allow_noncommitting, "decrypt_legacy")
    blob = _as_bytes("blob", blob); ad = _normalize_ad(ad)
    if len(blob) < 1: raise AuthError("bad blob length")
    if blob[0] != FMT_VERSION_V2: raise UnsupportedVersion("unsupported version")
    if len(blob) != V2_BLOB_LEN: raise AuthError("bad blob length")
    v, pickup, nonce, ct, tag = blob[:PK0], blob[PK0:N0], blob[N0:V2_CT0], blob[V2_CT0:V2_CT1], blob[V2_CT1:]
    if not hmac.compare_digest(v, bytes([FMT_VERSION_V2]) + VERSION): raise AuthError("bad version prefix")
    clef = staff_clef(seed)
    mac_key = StaffSponge(b"M", _seed_bytes(seed), nonce).take(32)
    if not hmac.compare_digest(tag, _tag(mac_key, pickup, nonce, ct, clef, _legacy_key_signature(seed), ad, version=FMT_VERSION_V2, commit=b"")): raise AuthError("authentication failed")
    sch = Schedule(seed, nonce)
    b = grid_to_bytes(decrypt_grid(bytes_to_grid(ct), sch))
    ok, msg = _unpad_block(b)
    if not ok: raise DecodeError("tag valid but block malformed")
    if not hmac.compare_digest(nonce, hashlib.sha256(clef + pickup + encode_block(msg) + _encode_ad(ad)).digest()[:NONCE_LEN]):
        raise AuthError("SIV nonce mismatch")
    return msg


# ---------------------------------------------------------------- movements mode (format version 7; legacy v3 only via decrypt_movements_legacy)
def _final_flag(final: bool) -> bytes:
    return b"\x01" if final else b"\x00"

def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def _chunk_movements(msg: bytes):
    """Split msg into 127-byte payloads. The empty message is one empty movement."""
    if len(msg) > MAX_MOVEMENTS_MSG:
        raise ValueError("message too long (max %d bytes)" % MAX_MOVEMENTS_MSG)
    if not msg:
        return [b""]
    return [msg[i:i + MAX_MSG] for i in range(0, len(msg), MAX_MSG)]

def siv_nonce_movements(msg: bytes, pickup: bytes, seed=None, ad: bytes = b"") -> bytes:
    """SIV-style nonce = SHA-256(clef || pickup || uint64be(len(msg)) || msg || encode_ad(ad))[:16].
    Length-prefixed so the framing is unambiguous for any payload up to MAX_MOVEMENTS_MSG."""
    msg = _as_bytes("msg", msg)
    pickup = _as_bytes("pickup", pickup)
    ad = _normalize_ad(ad)
    if len(msg) > MAX_MOVEMENTS_MSG:
        raise ValueError("message too long (max %d bytes)" % MAX_MOVEMENTS_MSG)
    if len(pickup) != PICKUP_LEN:
        raise ValueError("pickup must be 16 bytes")
    return hashlib.sha256(staff_clef(seed) + pickup + len(msg).to_bytes(8, "big") + msg + _encode_ad(ad)).digest()[:NONCE_LEN]

def _theme_start(seed, nonce: bytes) -> bytes:
    """Opening theme: StaffSponge domain b'T' over the message nonce, one block."""
    return StaffSponge(b"T", _seed_bytes(seed), nonce).take(BLOCK_LEN)

def _theme_next(seed, theme: bytes, ct: bytes, index: int, final: bool) -> bytes:
    """Carry the theme forward by absorbing this movement's ciphertext, index and final flag."""
    n = hashlib.sha256(b"SN2/T" + theme + ct + index.to_bytes(8, "big") + _final_flag(final)).digest()[:NONCE_LEN]
    return StaffSponge(b"T", _seed_bytes(seed), n).take(BLOCK_LEN)

def _movement_tweak(seed, nonce: bytes, index: int, final: bool) -> bytes:
    """Per-movement tweak bound to the nonce, index and final-movement flag."""
    mid = hashlib.sha256(b"SN2/I" + nonce + index.to_bytes(8, "big") + _final_flag(final)).digest()[:NONCE_LEN]
    return StaffSponge(b"W", _seed_bytes(seed), mid).take(BLOCK_LEN)

def _cadence_key(seed, nonce: bytes) -> bytes:
    return StaffSponge(b"D", _seed_bytes(seed), nonce).take(32)

def _coda_key(seed, nonce: bytes) -> bytes:
    return StaffSponge(b"O", _seed_bytes(seed), nonce).take(32)

def _cadence_tag(cad_key, pickup, nonce, index, final, theme, ct, clef, key_sig, ad: bytes = b"", version=None, commit: bytes = b""):
    if version is None:
        version = FMT_MOVEMENTS
    return hmac.new(cad_key, clef + key_sig + bytes([version]) + VERSION + pickup + nonce + commit
                    + index.to_bytes(8, "big") + _final_flag(final) + theme + ct + _encode_ad(ad), hashlib.sha256).digest()

def _coda_tag(coda_key, pickup, nonce, nmov, cts, cadences, clef, key_sig, ad: bytes = b"", version=None, commit: bytes = b""):
    """Coda covers version, SN2, pickup, nonce, commitment, movement count, every ciphertext, every cadence, and AD."""
    if version is None:
        version = FMT_MOVEMENTS
    return hmac.new(coda_key, clef + key_sig + bytes([version]) + VERSION + pickup + nonce + commit
                    + nmov.to_bytes(4, "big") + cts + cadences + _encode_ad(ad), hashlib.sha256).digest()

def encrypt_movements(msg: bytes, seed=None, ad: bytes = b"", nonce: bytes = None) -> bytes:
    """blob = version(1)=7 || b"SN2" || pickup(16) || nonce(16) || commit(32) || nmov(4) || (ct(128)||cadence(32))*nmov || coda(32).
    pickup = _fresh_pickup(); nonce = siv_nonce_movements(msg, pickup, seed, ad).
    commit = HMAC-SHA256(K_commit, b"U" || version || b"SN2" || pickup || nonce || encode_ad(ad) || nmov32), binding AD and the movement count.
    Each movement encrypts encode_block(chunk) XOR theme XOR tweak under one Schedule(seed, nonce).
    The theme is chained through ciphertext; each cadence authenticates that movement; the coda
    authenticates the header, commitment, count, every ciphertext, every cadence and the associated data.
    msg and ad must be bytes-like; associated data longer than MAX_AD_LEN or a message longer
    than MAX_MOVEMENTS_MSG raises ValueError. A caller nonce must equal the synthetic one."""
    msg = _as_bytes("msg", msg); ad = _normalize_ad(ad)
    chunks = _chunk_movements(msg)
    nmov = len(chunks)
    adb = _encode_ad(ad); clef = staff_clef(seed); key_sig = key_signature(seed)
    pickup = _fresh_pickup()
    syn = hashlib.sha256(clef + pickup + len(msg).to_bytes(8, "big") + msg + adb).digest()[:NONCE_LEN]
    if nonce is not None and not hmac.compare_digest(_as_bytes("nonce", nonce), syn):
        raise ValueError("nonce must be the synthetic (SIV) nonce for this message and pickup")
    nonce = syn
    commit = _commitment(_commit_key(seed), FMT_MOVEMENTS, pickup, nonce, ad, nmov=nmov)
    theme = _theme_start(seed, nonce)
    cad_key = _cadence_key(seed, nonce)
    coda_key = _coda_key(seed, nonce)
    sch = Schedule(seed, nonce)
    parts = []
    cts = []
    cadences = []
    for i, chunk in enumerate(chunks):
        final = (i == nmov - 1)
        tweak = _movement_tweak(seed, nonce, i, final)
        block = encode_block(chunk)
        xored = _xor_bytes(_xor_bytes(block, theme), tweak)
        ct = grid_to_bytes(encrypt_grid(bytes_to_grid(xored), sch))
        cadence = _cadence_tag(cad_key, pickup, nonce, i, final, theme, ct, clef, key_sig, ad, version=FMT_MOVEMENTS, commit=commit)
        parts.append(ct + cadence)
        cts.append(ct)
        cadences.append(cadence)
        theme = _theme_next(seed, theme, ct, i, final)
    coda = _coda_tag(coda_key, pickup, nonce, nmov, b"".join(cts), b"".join(cadences), clef, key_sig, ad, version=FMT_MOVEMENTS, commit=commit)
    return bytes([FMT_MOVEMENTS]) + VERSION + pickup + nonce + commit + nmov.to_bytes(4, "big") + b"".join(parts) + coda

def decrypt_movements(blob: bytes, seed=None, ad: bytes = b"") -> bytes:
    """Format version is checked first, then length and movement count. For
    every current (v7) blob, BOTH the tuning commitment and the coda (which
    covers the header, commitment, count, every ciphertext, every cadence
    and AD) are computed and compared (hmac.compare_digest each), combined
    without short-circuit, and one AuthError("authentication failed") is
    raised if either failed (equal-time reject, conductor-polish L1). A wrong
    key, wrong AD, bad commitment, bad ciphertext, bad cadence and bad coda
    therefore all do the same work: one commitment HMAC plus one coda HMAC
    over the body (O(nmov), body capped at MAX_MOVEMENTS). Nothing is
    decrypted before both pass. Only then are the cadences checked
    (every one, combined) and the Schedule built. Commitment, tag, cadence
    and coda failures all raise AuthError("authentication failed"); the
    type and message do not distinguish a wrong key from wrong associated
    data. Legacy v3 and unpublished v5 blobs are rejected as
    UnsupportedVersion (not an AuthError). Use
    decrypt_movements_legacy(..., allow_noncommitting=True) to open
    published octavo009 v3 blobs during the transition; that path is not
    key-committing.
    Timing: a commitment failure and a coda failure take the same time for
    the same blob size (the size is public). Before conductor-polish the
    commitment was checked first, so timing revealed which stage failed.
    blob and ad must be bytes-like; AD longer than MAX_AD_LEN raises ValueError."""
    blob = _as_bytes("blob", blob); ad = _normalize_ad(ad)
    if len(blob) < 1: raise AuthError("bad blob length")
    if blob[0] != FMT_MOVEMENTS: raise UnsupportedVersion("unsupported version")
    if len(blob) < MOVEMENTS_HDR_LEN + MOVEMENT_STRIDE + TAG_LEN: raise AuthError("bad blob length")
    if blob[1:4] != VERSION: raise AuthError("bad version prefix")
    pickup = blob[4:20]
    nonce = blob[20:36]
    commit = blob[CM0:CM1]
    nmov = int.from_bytes(blob[NMOV0:MOVEMENTS_HDR_LEN], "big")
    if nmov < 1 or nmov > MAX_MOVEMENTS: raise AuthError("bad movement count")
    expected = MOVEMENTS_HDR_LEN + nmov * MOVEMENT_STRIDE + TAG_LEN
    if len(blob) != expected: raise AuthError("bad blob length")
    # Equal-time reject (conductor-polish L1): always compute the commitment AND the coda,
    # combine with & (no short-circuit), raise once. Nothing is decrypted before both pass.
    commit_ok = hmac.compare_digest(commit, _commitment(_commit_key(seed), FMT_MOVEMENTS, pickup, nonce, ad, nmov=nmov))
    body = blob[MOVEMENTS_HDR_LEN:-TAG_LEN]
    coda = blob[-TAG_LEN:]
    cts, cadences = [], []
    for i in range(nmov):
        off = i * MOVEMENT_STRIDE
        cts.append(body[off:off + BLOCK_LEN])
        cadences.append(body[off + BLOCK_LEN:off + MOVEMENT_STRIDE])
    clef = staff_clef(seed); key_sig = key_signature(seed)
    coda_key = _coda_key(seed, nonce)
    coda_ok = hmac.compare_digest(coda, _coda_tag(coda_key, pickup, nonce, nmov, b"".join(cts), b"".join(cadences), clef, key_sig, ad, version=FMT_MOVEMENTS, commit=commit))
    if not (commit_ok & coda_ok): raise AuthError("authentication failed")
    cad_key = _cadence_key(seed, nonce)
    theme = _theme_start(seed, nonce)
    cad_ok = True
    themes = []
    for i in range(nmov):
        final = (i == nmov - 1)
        themes.append(theme)
        cad_ok = hmac.compare_digest(cadences[i], _cadence_tag(cad_key, pickup, nonce, i, final, theme, cts[i], clef, key_sig, ad, version=FMT_MOVEMENTS, commit=commit)) and cad_ok
        theme = _theme_next(seed, theme, cts[i], i, final)
    if not cad_ok:
        raise AuthError("authentication failed")
    sch = Schedule(seed, nonce)
    pieces = []
    dec_ok = True
    for i in range(nmov):
        final = (i == nmov - 1)
        tweak = _movement_tweak(seed, nonce, i, final)
        xored = grid_to_bytes(decrypt_grid(bytes_to_grid(cts[i]), sch))
        block = _xor_bytes(_xor_bytes(xored, themes[i]), tweak)
        ok, piece = _unpad_block(block)
        dec_ok &= ok
        pieces.append(piece)
    if not dec_ok: raise DecodeError("tag valid but block malformed")
    msg = b"".join(pieces)
    if not hmac.compare_digest(nonce, hashlib.sha256(clef + pickup + len(msg).to_bytes(8, "big") + msg + _encode_ad(ad)).digest()[:NONCE_LEN]):
        raise AuthError("SIV nonce mismatch")
    return msg

def decrypt_movements_legacy(blob: bytes, seed=None, ad: bytes = b"", *, allow_noncommitting=False) -> bytes:
    """Open a published format-version-3 movements blob (octavo009 and earlier).

    Transition helper only. Not key-committing: there is no tuning field,
    and tags bind the frozen octavo009 key_sig. Requires
    allow_noncommitting=True (ValueError otherwise) and emits
    LegacyFormatWarning on every call. Default decrypt_movements()
    rejects these blobs with UnsupportedVersion. Do not use for new messages.
    Unpublished v5 (tuning) blobs are also rejected.
    """
    _require_noncommitting(allow_noncommitting, "decrypt_movements_legacy", warn=False)
    blob = _as_bytes("blob", blob); ad = _normalize_ad(ad)
    if len(blob) < 1: raise AuthError("bad blob length")
    if blob[0] != FMT_MOVEMENTS_V3:
        raise UnsupportedVersion("unsupported version")
    return _decrypt_legacy_v3(blob, seed, ad, allow_noncommitting=allow_noncommitting)

def _decrypt_legacy_v3(blob: bytes, seed, ad: bytes, *, allow_noncommitting=False) -> bytes:
    """Open a format-version-3 movements blob (no tuning). Tags bind the
    frozen octavo009 key_sig. Not key-committing. Gated and version-pinned
    here too (conductor-polish I2): needs allow_noncommitting=True, emits
    LegacyFormatWarning, and opens only blob[0] == 3."""
    _require_noncommitting(allow_noncommitting, "decrypt_movements_legacy")
    blob = _as_bytes("blob", blob); ad = _normalize_ad(ad)
    if len(blob) < 1: raise AuthError("bad blob length")
    if blob[0] != FMT_MOVEMENTS_V3: raise UnsupportedVersion("unsupported version")
    if len(blob) < V3_MOVEMENTS_HDR_LEN + MOVEMENT_STRIDE + TAG_LEN: raise AuthError("bad blob length")
    if blob[1:4] != VERSION: raise AuthError("bad version prefix")
    pickup = blob[4:20]
    nonce = blob[20:36]
    nmov = int.from_bytes(blob[V3_NMOV0:V3_MOVEMENTS_HDR_LEN], "big")
    if nmov < 1 or nmov > MAX_MOVEMENTS: raise AuthError("bad movement count")
    expected = V3_MOVEMENTS_HDR_LEN + nmov * MOVEMENT_STRIDE + TAG_LEN
    if len(blob) != expected: raise AuthError("bad blob length")
    body = blob[V3_MOVEMENTS_HDR_LEN:-TAG_LEN]
    coda = blob[-TAG_LEN:]
    cts, cadences = [], []
    for i in range(nmov):
        off = i * MOVEMENT_STRIDE
        cts.append(body[off:off + BLOCK_LEN])
        cadences.append(body[off + BLOCK_LEN:off + MOVEMENT_STRIDE])
    clef = staff_clef(seed); key_sig = _legacy_key_signature(seed)
    coda_key = _coda_key(seed, nonce)
    if not hmac.compare_digest(coda, _coda_tag(coda_key, pickup, nonce, nmov, b"".join(cts), b"".join(cadences), clef, key_sig, ad, version=FMT_MOVEMENTS_V3, commit=b"")):
        raise AuthError("authentication failed")
    cad_key = _cadence_key(seed, nonce)
    theme = _theme_start(seed, nonce)
    cad_ok = True
    themes = []
    for i in range(nmov):
        final = (i == nmov - 1)
        themes.append(theme)
        cad_ok = hmac.compare_digest(cadences[i], _cadence_tag(cad_key, pickup, nonce, i, final, theme, cts[i], clef, key_sig, ad, version=FMT_MOVEMENTS_V3, commit=b"")) and cad_ok
        theme = _theme_next(seed, theme, cts[i], i, final)
    if not cad_ok:
        raise AuthError("authentication failed")
    sch = Schedule(seed, nonce)
    pieces = []
    dec_ok = True
    for i in range(nmov):
        final = (i == nmov - 1)
        tweak = _movement_tweak(seed, nonce, i, final)
        xored = grid_to_bytes(decrypt_grid(bytes_to_grid(cts[i]), sch))
        block = _xor_bytes(_xor_bytes(xored, themes[i]), tweak)
        ok, piece = _unpad_block(block)
        dec_ok &= ok
        pieces.append(piece)
    if not dec_ok: raise DecodeError("tag valid but block malformed")
    msg = b"".join(pieces)
    if not hmac.compare_digest(nonce, hashlib.sha256(clef + pickup + len(msg).to_bytes(8, "big") + msg + _encode_ad(ad)).digest()[:NONCE_LEN]):
        raise AuthError("SIV nonce mismatch")
    return msg

# ---------------------------------------------------------------- rehearsal: chunked streaming AEAD (format version 8)
# STREAM-style online AE (in the spirit of Hoang, Reyhanitabar, Rogaway and Vizar, "Online
# Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance", CRYPTO 2015). Homemade.
# Wire:   header(72) || chunk_0 || ... || chunk_{n-1}
# header: version(1)=8 || SN2(3) || pickup(16) || nonce(16) || commit(32) || chunk_size(4, uint32be)
# chunk i < n-1 (non-final): ct(chunk_size) || tag(32), carrying exactly chunk_size plaintext bytes
# chunk n-1 (final):         ct(128*k) || tag(32), carrying L in 0..chunk_size-1 bytes, padded
#                            msg || 0x80 || zeros to the next multiple of 128 (so 128*k <= chunk_size)
# Every stream has exactly one final chunk (an empty stream is one 128-byte final chunk).
# Per-chunk material comes from the sponge domain R over
#   b"chunk" || pickup || nonce || chunk_size32 || index64 || final8 || ad_digest32
# (first 32 bytes = chunk MAC key, then one 128-byte tweak per block), and one per-stream
# Schedule(seed, StaffSponge(R, seed, b"sched" || pickup || nonce || chunk_size32 || ad_digest32).take(16)),
# with ad_digest = SHA-256(b"SN2/A" || encode_ad(ad)). Each block is XEX'd under the unchanged
# 16-round staff-core: ct = E(P xor T) xor T.
# rehearsal-fix (I1): ad_digest is in both R inputs, so one pickup and nonce under two ADs give
# unrelated blocks. This changed every v8 ciphertext; v8 was never published, so there is no
# legacy v8 path.
# The nonce is a fresh random per-stream value (no SIV: a stream cannot be hashed before it is sent).
FMT_REHEARSAL = 8                  # rehearsal stream; never confused with v6/v7 or étude bytes
REHEARSAL_DOMAIN = b"R"            # sponge domain: per-stream schedule nonce, per-chunk MAC key and tweaks
REHEARSAL_SIG_DOMAIN = b"H"        # sponge domain: rehearsal signature (rehearsal hall); sponge nonce = rehearsal digest
REHEARSAL_AD_PREFIX = b"SN2/A"     # raw SHA-256 prefix for the per-stream AD digest (A is not a sponge domain)
REHEARSAL_NONCE_PREFIX = b"SN2/Q"  # raw SHA-256 prefix for the fresh per-stream nonce (Q is not a sponge domain)
REHEARSAL_CHUNK_DEFAULT = 65536    # 64 KiB of plaintext per non-final chunk (512 blocks)
REHEARSAL_CHUNK_MIN = BLOCK_LEN    # 128
REHEARSAL_CHUNK_MAX = 1 << 20      # 1 MiB (8192 blocks, the same block count as MAX_MOVEMENTS)
MAX_REHEARSAL_CHUNKS = 1 << 24     # chunks per stream, final included: 1 TiB at the default chunk size
REHEARSAL_MAX_WORKERS = 32         # rehearsal-fix I2: worker processes are capped at min(32, os.cpu_count())
REHEARSAL_WORKER_TIMEOUT = 600.0   # rehearsal-polish I2: default seconds a worker may take per frame (hello or one chunk)
RH_CS0 = CM1                       # chunk_size field = header[68:72]
REHEARSAL_HDR_LEN = RH_CS0 + 4     # 72
REHEARSAL_PAD = b"\x80"

def _fresh_stream_nonce() -> bytes:
    """Fresh 16-byte per-stream nonce, drawn like the pickup but under its own prefix:
    SHA-256(b"SN2/Q" || urandom(16) || time_ns(8) || counter(8) || pid(4))[:16]."""
    _fresh_stream_nonce.n += 1
    mix = (os.urandom(NONCE_LEN)
           + time.time_ns().to_bytes(8, "big")
           + _fresh_stream_nonce.n.to_bytes(8, "big")
           + os.getpid().to_bytes(4, "big"))
    return hashlib.sha256(REHEARSAL_NONCE_PREFIX + mix).digest()[:NONCE_LEN]
_fresh_stream_nonce.n = 0

def _rehearsal_chunk_size(chunk_size) -> int:
    """Caller-side check: an int (not bool), a multiple of 128, 128 <= chunk_size <= 1 MiB."""
    if isinstance(chunk_size, bool) or not isinstance(chunk_size, int):
        raise TypeError("chunk_size must be an int")
    if chunk_size % BLOCK_LEN or not REHEARSAL_CHUNK_MIN <= chunk_size <= REHEARSAL_CHUNK_MAX:
        raise ValueError("chunk_size must be a multiple of %d between %d and %d" % (BLOCK_LEN, REHEARSAL_CHUNK_MIN, REHEARSAL_CHUNK_MAX))
    return chunk_size

def _rehearsal_max_chunk_size(max_chunk_size):
    """Receiver-side limit (rehearsal-fix I4): None (any valid size) or a valid chunk size."""
    return None if max_chunk_size is None else _rehearsal_chunk_size(max_chunk_size)

def _rehearsal_workers(workers) -> int:
    """Validate workers (an int >= 1) and cap it at min(REHEARSAL_MAX_WORKERS, os.cpu_count()) (rehearsal-fix I2)."""
    if isinstance(workers, bool) or not isinstance(workers, int) or workers < 1:
        raise ValueError("workers must be an int >= 1")
    return max(1, min(workers, REHEARSAL_MAX_WORKERS, os.cpu_count() or 1))

def _rehearsal_worker_timeout(timeout) -> float:
    """rehearsal-polish I2: None (REHEARSAL_WORKER_TIMEOUT) or a finite number of seconds > 0."""
    if timeout is None:
        return REHEARSAL_WORKER_TIMEOUT
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise TypeError("worker_timeout must be a number of seconds or None")
    if not 0 < timeout < float("inf"):
        raise ValueError("worker_timeout must be finite and > 0")
    return float(timeout)

def _rehearsal_read_size(read_size, allow_none=False):
    """rehearsal-finale I7: read_size must be an int (not bool) >= 1 (or None where a default applies)."""
    if read_size is None and allow_none:
        return None
    if isinstance(read_size, bool) or not isinstance(read_size, int):
        raise TypeError("read_size must be an int")
    if read_size < 1:
        raise ValueError("read_size must be >= 1")
    return read_size

def _rehearsal_bool(name, value) -> bool:
    """rehearsal-polish I6: flags such as overwrite must be real bools (overwrite="no" used to overwrite)."""
    if not isinstance(value, bool):
        raise TypeError("%s must be True or False" % name)
    return value

class UnfinalizedStreamWarning(UserWarning):
    """rehearsal-polish L2 / rehearsal-finale L2: a RehearsalDecryptor was dropped after it received
    data but before finalize(), so the end of the stream was never verified. A UserWarning (not a
    ResourceWarning), so Python's default filters SHOW it. At import an "always" filter for this
    category is APPENDED to the warning filters, so every dropped decryptor warns (not once per call
    site); filters the user set (-W, PYTHONWARNINGS, simplefilter) come first and still win. It is
    raised outside the destructor's own error handling, so under -W error it reaches
    sys.unraisablehook ("Exception ignored in ... UnfinalizedStreamWarning" on stderr) instead of
    vanishing; a destructor can never make the program fail, so the exit code is unchanged."""

warnings.filterwarnings("always", category=UnfinalizedStreamWarning, append=True)

def _rehearsal_ad_digest(ad: bytes = b"") -> bytes:
    """SHA-256(b"SN2/A" || encode_ad(ad)); bound into every chunk tag and (rehearsal-fix I1) into the
    R-sponge inputs for the schedule nonce, chunk keys and tweaks. AD itself is in the commitment."""
    return hashlib.sha256(REHEARSAL_AD_PREFIX + _encode_ad(ad)).digest()

def _rehearsal_commitment(commit_key, pickup, nonce, ad, chunk_size) -> bytes:
    """HMAC-SHA256(K_commit, b"U" || 8 || SN2 || pickup || nonce || encode_ad(ad) || chunk_size32).
    Same seed-only K_commit and domain-U pattern as v6/v7; the version byte 8 keeps it apart from
    v7's nmov32 commitment, and the chunk size is bound so a rewritten size fails here."""
    data = (COMMIT_DOMAIN + bytes([FMT_REHEARSAL]) + VERSION + pickup + nonce + _encode_ad(ad)
            + chunk_size.to_bytes(4, "big"))
    return hmac.new(commit_key, data, hashlib.sha256).digest()

def _rehearsal_schedule_nonce(seed, pickup, nonce, chunk_size, ad_digest) -> bytes:
    """Per-stream schedule nonce: StaffSponge(R, seed, b"sched" || pickup || nonce || chunk_size32 || ad_digest).take(16)."""
    return StaffSponge(REHEARSAL_DOMAIN, _seed_bytes(seed),
                       b"sched" + pickup + nonce + chunk_size.to_bytes(4, "big") + ad_digest).take(NONCE_LEN)

def _rehearsal_chunk_sponge(seed, pickup, nonce, chunk_size, index, final, ad_digest) -> StaffSponge:
    """Per-chunk sponge, domain R, over b"chunk" || pickup || nonce || chunk_size32 || index64 || final8 || ad_digest.
    First 32 bytes: the chunk MAC key. Then one 128-byte XEX tweak per block."""
    return StaffSponge(REHEARSAL_DOMAIN, _seed_bytes(seed),
                       b"chunk" + pickup + nonce + chunk_size.to_bytes(4, "big")
                       + index.to_bytes(8, "big") + _final_flag(final) + ad_digest)

def _rehearsal_chunk_key(seed, pickup, nonce, chunk_size, index, final, ad_digest) -> bytes:
    return _rehearsal_chunk_sponge(seed, pickup, nonce, chunk_size, index, final, ad_digest).take(32)

def _rehearsal_tag(chunk_key, clef, rsig, pickup, nonce, commit, chunk_size, index, final, ad_digest, ct) -> bytes:
    """HMAC-SHA256(K_chunk, clef || rehearsal_sig || 8 || SN2 || pickup || nonce || commit || chunk_size32
    || index64 || final8 || ad_digest || ct). Everything before ct is fixed-length."""
    return hmac.new(chunk_key, clef + rsig + bytes([FMT_REHEARSAL]) + VERSION + pickup + nonce + commit
                    + chunk_size.to_bytes(4, "big") + index.to_bytes(8, "big") + _final_flag(final)
                    + ad_digest + ct, hashlib.sha256).digest()

def _rehearsal_tweaks(seed, pickup, nonce, chunk_size, index, final, ad_digest, nblocks) -> list:
    """The chunk's XEX tweaks: the chunk sponge's output after its 32-byte MAC key, 128 bytes per block."""
    sp = _rehearsal_chunk_sponge(seed, pickup, nonce, chunk_size, index, final, ad_digest)
    sp.take(32)
    return [sp.take(BLOCK_LEN) for _ in range(nblocks)]

def _rehearsal_mask(data, tweaks) -> bytes:
    """XOR block k of data with tweaks[k]."""
    return b"".join(_xor_bytes(data[k * BLOCK_LEN:(k + 1) * BLOCK_LEN], t) for k, t in enumerate(tweaks))

def _rehearsal_blocks(sch, data, decrypt) -> bytes:
    """Run the unchanged staff-core (encrypt_grid or decrypt_grid) on every 128-byte block of data."""
    out = []
    for off in range(0, len(data), BLOCK_LEN):
        g = bytes_to_grid(data[off:off + BLOCK_LEN])
        out.append(grid_to_bytes(decrypt_grid(g, sch) if decrypt else encrypt_grid(g, sch)))
    return b"".join(out)

def _rehearsal_crypt_chunk(seed, sch, pickup, nonce, chunk_size, index, final, ad_digest, data, decrypt) -> bytes:
    """XEX every 128-byte block of one chunk under the stream Schedule: ct = E(P ^ T) ^ T, with
    T the chunk's tweaks (_rehearsal_tweaks). len(data) % 128 == 0."""
    tw = _rehearsal_tweaks(seed, pickup, nonce, chunk_size, index, final, ad_digest, len(data) // BLOCK_LEN)
    return _rehearsal_mask(_rehearsal_blocks(sch, _rehearsal_mask(data, tw), decrypt), tw)

# Worker body for workers > 1 (rehearsal-fix I2, rehearsal-polish I1/I2, rehearsal-finale I6). Runs in
# a FRESH interpreter (python -I -B -S -c ..., empty environment), never a fork, so it inherits none
# of the parent's memory; -S skips site, so no .pth file in site-packages runs in it. It does NOT read
# sneak_n2.py from disk: the parent sends the exact source bytes it imported (_MODULE_SOURCE) over the
# pipe, the worker executes those bytes under a private module name (both attestations run on them),
# and answers with sha256(received source) || its rehearsal digest. It then receives the per-stream
# Schedule (round material only) and tweak-masked blocks, and returns the staff-core output. It never
# sees the seed, the AD, the AD digest, a MAC key or the commitment key. It is still part of the
# trusted base (SECURITY.md): its transcript plus the public ciphertext gives the plaintext, and an
# all-zero plaintext block reaches it as that block's tweak.
_REHEARSAL_WORKER_SRC = r"""
import hashlib, sys, types
rd, wr = sys.stdin.buffer, sys.stdout.buffer
h = rd.read(8)
src = rd.read(int.from_bytes(h, "big")) if len(h) == 8 else b""
if len(h) != 8 or len(src) != int.from_bytes(h, "big"):
    sys.exit(2)
name = "_octavo_rehearsal_worker"
m = types.ModuleType(name)
m.__file__ = "<octavo-rehearsal-worker>/sneak_n2.py"
m.__dict__["__octavo_worker_source__"] = src
sys.modules[name] = m
exec(compile(src, m.__file__, "exec", dont_inherit=True), m.__dict__)
wr.write(hashlib.sha256(src).hexdigest().encode("ascii") + m._REHEARSAL_SHA256.encode("ascii")); wr.flush()
sch = None
while True:
    h = rd.read(9)
    if len(h) < 9:
        break
    body = rd.read(int.from_bytes(h[1:], "big"))
    if h[:1] == b"S":
        rounds, white = m.pickle.loads(body)
        sch = types.SimpleNamespace(rounds=rounds, white=white)
        continue
    out = m._rehearsal_blocks(sch, body, h[:1] == b"D")
    wr.write(len(out).to_bytes(8, "big") + out); wr.flush()
"""

class _RehearsalWorkers:
    """Spawn-style worker processes for one stream (rehearsal-fix I2). Each worker is a fresh
    interpreter started with subprocess, not multiprocessing: multiprocessing's spawn and forkserver
    start methods re-run the caller's __main__ in every worker unless it is guarded, and fork copies
    the whole parent memory (other seeds in the seed memo, unrelated secrets). Workers are started
    lazily, at most min(workers, chunks in the batch), and each one gets only the module source this
    process imported, the stream's Schedule round material and masked blocks (rehearsal-polish I1:
    a file replaced on disk after import is never run; the hello is only a pipe/version sanity check).
    Every frame to or from a worker has a deadline (rehearsal-polish I2, worker_timeout seconds); a
    worker that misses it is killed and the call raises RuntimeError."""
    def __init__(self, n, sch, timeout=None):
        self.n = n
        self.timeout = _rehearsal_worker_timeout(timeout)
        self.procs = []
        self._sch = sch
        self._sch_blob = pickle.dumps((sch.rounds, sch.white), protocol=pickle.HIGHEST_PROTOCOL)

    def _send(self, p, data, deadline):
        """Write all of data to the worker's stdin (non-blocking fd) before deadline."""
        fd = p.stdin.fileno(); view = memoryview(data)
        with selectors.DefaultSelector() as sel:
            sel.register(fd, selectors.EVENT_WRITE)
            while view:
                left = deadline - time.monotonic()
                if left <= 0 or not sel.select(left):
                    raise TimeoutError("rehearsal worker timed out")
                try:
                    view = view[os.write(fd, view[:1 << 16]):]
                except BlockingIOError:
                    pass

    def _recv(self, p, n, deadline) -> bytes:
        """Read exactly n bytes from the worker's stdout before deadline (fewer only at EOF)."""
        fd = p.stdout.fileno(); out = bytearray()
        with selectors.DefaultSelector() as sel:
            sel.register(fd, selectors.EVENT_READ)
            while len(out) < n:
                left = deadline - time.monotonic()
                if left <= 0 or not sel.select(left):
                    raise TimeoutError("rehearsal worker timed out")
                b = os.read(fd, min(n - len(out), 1 << 20))
                if not b:
                    break
                out += b
        return bytes(out)

    def _spawn(self):
        if not sys.executable:
            raise RuntimeError("workers > 1 needs sys.executable")
        if _MODULE_SOURCE is None:
            raise RuntimeError("workers > 1 needs the module source (not available in this install)")
        p = subprocess.Popen([sys.executable, "-I", "-B", "-S", "-c", _REHEARSAL_WORKER_SRC],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, close_fds=True, bufsize=0,
                             env=_rehearsal_worker_env())
        try:
            os.set_blocking(p.stdin.fileno(), False)
            deadline = time.monotonic() + self.timeout
            self._send(p, len(_MODULE_SOURCE).to_bytes(8, "big") + _MODULE_SOURCE, deadline)
            hello = self._recv(p, 128, deadline)
            if hello != (_MODULE_SOURCE_SHA256 + _REHEARSAL_SHA256).encode("ascii"):
                raise RuntimeError("rehearsal worker did not load this process's sneak_n2.py source (digest mismatch)")
            self._send(p, b"S" + len(self._sch_blob).to_bytes(8, "big") + self._sch_blob, deadline)
        except BaseException:
            self._stop(p, kill=True)
            raise
        return p

    def run(self, datas, decrypt) -> list:
        """Staff-core over each masked chunk in datas, spread over the workers; order preserved."""
        need = min(self.n, len(datas))
        op = b"D" if decrypt else b"E"
        out = [None] * len(datas)
        try:
            while len(self.procs) < need:
                self.procs.append(self._spawn())
            for start in range(0, len(datas), need):
                batch = list(range(start, min(start + need, len(datas))))
                deadline = time.monotonic() + self.timeout
                for k, i in enumerate(batch):
                    self._send(self.procs[k], op + len(datas[i]).to_bytes(8, "big") + datas[i], deadline)
                for k, i in enumerate(batch):
                    p = self.procs[k]
                    deadline = time.monotonic() + self.timeout
                    h = self._recv(p, 8, deadline)
                    body = self._recv(p, int.from_bytes(h, "big"), deadline) if len(h) == 8 else b""
                    if len(h) != 8 or len(body) != len(datas[i]):
                        raise RuntimeError("rehearsal worker exited")
                    out[i] = body
                self._spot_check(datas, out, batch, decrypt)
        except TimeoutError as e:
            self.close(kill=True)
            raise RuntimeError("rehearsal worker timed out (worker_timeout=%gs); workers killed" % self.timeout) from e
        except (OSError, ValueError) as e:
            self.close(kill=True)
            raise RuntimeError("rehearsal worker failed") from e
        except BaseException:
            self.close(kill=True)
            raise
        return out

    def _spot_check(self, datas, out, batch, decrypt):
        """rehearsal-finale I6: recompute ONE randomly chosen block of the batch in this process and
        compare it with the worker's answer (about 1/(blocks in the batch) extra work). A worker that
        returns wrong blocks is caught with probability (wrong blocks)/(blocks) per batch; this is a
        spot check, not a proof (workers stay in the trusted base)."""
        r = int.from_bytes(os.urandom(8), "big")
        i = batch[r % len(batch)]
        k = (r >> 32) % (len(datas[i]) // BLOCK_LEN)
        blk = slice(k * BLOCK_LEN, (k + 1) * BLOCK_LEN)
        if not hmac.compare_digest(_rehearsal_blocks(self._sch, datas[i][blk], decrypt), out[i][blk]):
            raise RuntimeError("rehearsal worker returned a wrong block (spot check); workers killed")

    @staticmethod
    def _stop(p, kill=False):
        if kill:
            try: p.kill()
            except Exception: pass
        for f in (p.stdin, p.stdout):
            try: f.close()
            except Exception: pass
        try:
            p.wait(timeout=5)
        except Exception:
            try: p.kill(); p.wait(timeout=5)
            except Exception: pass

    def close(self, kill=False):
        procs, self.procs = self.procs, []
        for p in procs:
            self._stop(p, kill)

    def __del__(self):
        try: self.close()
        except Exception: pass

def _rehearsal_worker_env() -> dict:
    """rehearsal-finale I6: the environment a worker starts with. Empty on POSIX (no LD_PRELOAD,
    LD_LIBRARY_PATH, PYTHON* or locale variables; -I already ignores PYTHON*); on Windows only
    SYSTEMROOT, which the interpreter needs. A Python build that needs extra variables to start
    fails closed (RuntimeError on the hello)."""
    if os.name == "nt":
        return {k: os.environ[k] for k in ("SYSTEMROOT",) if k in os.environ}
    return {}

def _rehearsal_pad(msg: bytes) -> bytes:
    """Final-chunk padding: msg || 0x80 || zeros to the next multiple of 128."""
    n = len(msg) + 1
    return msg + REHEARSAL_PAD + bytes((-n) % BLOCK_LEN)

def _rehearsal_unpad(padded: bytes):
    """Fixed-structure inverse of _rehearsal_pad on the LAST block -> (ok, msg). The last block is
    read as one 1024-bit integer; its lowest set bit must be bit 7 of some byte (that byte is then
    exactly 0x80 and every later byte is zero). No loop or branch depends on the pad length."""
    x = int.from_bytes(padded[-BLOCK_LEN:], "big")
    tz = (x & -x).bit_length() - 1
    ok = (x != 0) & ((tz & 7) == 7)
    k = (tz >> 3) & (BLOCK_LEN - 1)
    return ok, padded[:len(padded) - 1 - k]

class _RehearsalBase:
    """Shared plumbing for RehearsalEncryptor / RehearsalDecryptor: the stream Schedule (built
    lazily, only after verification on the decrypt side) and the optional spawn-style worker
    processes (workers > 1). Chunk order is always preserved."""
    def _crypt_jobs(self, jobs, decrypt):
        if not jobs:
            return []
        if self._sch is None:
            self._sch = Schedule(self._seed, self._sched_nonce)
        if self._workers > 1 and len(jobs) > 1:
            if self._pool is None:
                self._pool = _RehearsalWorkers(self._workers, self._sch, self._worker_timeout)
            tws = [_rehearsal_tweaks(self._seed, self._pickup, self._nonce, self._cs, i, f, self._adh, len(d) // BLOCK_LEN)
                   for i, f, d in jobs]
            outs = self._pool.run([_rehearsal_mask(d, tw) for (i, f, d), tw in zip(jobs, tws)], decrypt)
            return [_rehearsal_mask(o, tw) for o, tw in zip(outs, tws)]
        return [_rehearsal_crypt_chunk(self._seed, self._sch, self._pickup, self._nonce, self._cs, i, f, self._adh, d, decrypt)
                for i, f, d in jobs]
    def _close_pool(self):
        pool = getattr(self, "_pool", None)
        if pool is not None:
            self._pool = None
            pool.close()
    def close(self):
        """Release the worker processes (if any). Called by finalize() and on every reject."""
        self._close_pool()
    def __enter__(self):
        return self
    def __exit__(self, *exc):
        self.close()
        return False
    def __del__(self):
        try: self._close_pool()
        except Exception: pass

class RehearsalEncryptor(_RehearsalBase):
    """Incremental rehearsal (format version 8) encryptor.

        enc = RehearsalEncryptor(seed, ad=b"...", chunk_size=65536)
        out = enc.update(part1) + enc.update(part2) + ... + enc.finalize()

    The first bytes returned (by update() or finalize()) are the 72-byte header
    version(1)=8 || SN2 || pickup(16) || nonce(16) || commit(32) || chunk_size(4).
    A non-final chunk is sealed and returned as soon as chunk_size plaintext bytes
    are buffered; finalize() seals the remaining 0..chunk_size-1 bytes as the final
    chunk (always present). pickup and nonce are fresh for every stream; there is no
    public nonce argument. workers > 1 encrypts batches of chunks in fresh worker
    interpreters (never fork; capped at min(32, os.cpu_count())); the output is
    byte-identical to workers=1. worker_timeout (seconds per worker frame, default
    REHEARSAL_WORKER_TIMEOUT) bounds how long a stuck worker can block a call. ad is bound in the commitment, every chunk tag, the
    chunk keys and tweaks, and the schedule nonce, and is not stored. Limits: MAX_AD_LEN,
    chunk_size in 128..1 MiB (multiple of 128), MAX_REHEARSAL_CHUNKS chunks (ValueError beyond)."""
    def __init__(self, seed=None, ad: bytes = b"", chunk_size: int = REHEARSAL_CHUNK_DEFAULT, *, workers: int = 1,
                 worker_timeout: float = None):
        ad = _normalize_ad(ad)
        self._pool = None
        self._cs = _rehearsal_chunk_size(chunk_size)
        self._workers = _rehearsal_workers(workers)
        self._worker_timeout = _rehearsal_worker_timeout(worker_timeout)
        self._seed = _seed_bytes(seed)
        self._pickup = _fresh_pickup()
        self._nonce = _fresh_stream_nonce()
        self._commit = _rehearsal_commitment(_commit_key(self._seed), self._pickup, self._nonce, ad, self._cs)
        self.header = (bytes([FMT_REHEARSAL]) + VERSION + self._pickup + self._nonce + self._commit
                       + self._cs.to_bytes(4, "big"))
        self._clef = staff_clef(self._seed)
        self._rsig = rehearsal_signature(self._seed)
        self._adh = _rehearsal_ad_digest(ad)
        self._sched_nonce = _rehearsal_schedule_nonce(self._seed, self._pickup, self._nonce, self._cs, self._adh)
        self._sch = None
        self._buf = bytearray()
        self._index = 0
        self._header_out = False
        self._state = "open"

    @property
    def workers(self) -> int:
        """Worker processes actually allowed (after the min(32, cpu_count) cap)."""
        return self._workers

    def _require_open(self):
        if self._state != "open":
            raise ValueError("RehearsalEncryptor is " + self._state)

    def _seal(self, jobs) -> bytes:
        cts = self._crypt_jobs(jobs, decrypt=False)
        out = []
        for (i, final, _), ct in zip(jobs, cts):
            key = _rehearsal_chunk_key(self._seed, self._pickup, self._nonce, self._cs, i, final, self._adh)
            out.append(ct + _rehearsal_tag(key, self._clef, self._rsig, self._pickup, self._nonce, self._commit,
                                           self._cs, i, final, self._adh, ct))
        return b"".join(out)

    def _take_header(self) -> bytes:
        if self._header_out:
            return b""
        self._header_out = True
        return self.header

    def update(self, data) -> bytes:
        """Absorb plaintext; return the header (first call) plus every chunk completed so far."""
        self._require_open()
        data = _as_bytes("data", data)
        self._buf += data
        cs = self._cs
        jobs, off = [], 0
        while len(self._buf) - off >= cs:
            if self._index + len(jobs) + 1 >= MAX_REHEARSAL_CHUNKS:
                self._state = "failed"; self.close()
                raise ValueError("stream too long (max %d chunks)" % MAX_REHEARSAL_CHUNKS)
            jobs.append((self._index + len(jobs), False, bytes(self._buf[off:off + cs])))
            off += cs
        del self._buf[:off]
        self._index += len(jobs)
        try:
            return self._take_header() + self._seal(jobs)
        except BaseException:
            self._state = "failed"; self.close()
            raise

    def finalize(self) -> bytes:
        """Seal the final chunk (0..chunk_size-1 bytes, padded) and return any header not yet returned."""
        self._require_open()
        try:
            out = self._take_header() + self._seal([(self._index, True, _rehearsal_pad(bytes(self._buf)))])
        finally:
            self._state = "finalized"; self._buf = bytearray(); self.close()
        return out

class RehearsalDecryptor(_RehearsalBase):
    """Incremental rehearsal (format version 8) decryptor.

        dec = RehearsalDecryptor(seed, ad=b"...")
        for piece in stream: out.write(dec.update(piece))   # verified plaintext only
        out.write(dec.finalize())                            # raises AuthError if cut short

    Prefer iter_rehearsal(), which always runs finalize(). Never releases unauthenticated
    plaintext: a chunk is decrypted only after its tag (and, for chunk 0, the commitment)
    has been checked, and every tag in one update() call is checked before any block of
    that call is decrypted. A chunk counts as non-final only once at least one byte beyond
    it has arrived, so update() holds back the last chunk_size + 32 bytes. A stream cut
    early (at any offset, including exactly at a chunk boundary) therefore yields only
    verified, chunk-aligned prefix plaintext from update(), and only finalize() raises
    AuthError. Callers that must not act on a prefix should buffer until finalize()
    returns (decrypt_rehearsal and decrypt_rehearsal_file do).

    Forgetting finalize() is caught (rehearsal-fix L3, rehearsal-polish L2, rehearsal-finale
    L2): leaving a `with` block normally after data arrived but before finalize() raises
    AuthError("stream not finalized"), and a decryptor garbage-collected in that state
    emits an UnfinalizedStreamWarning, a UserWarning shown under Python's default filters
    for EVERY dropped decryptor (an "always" filter is appended at import). Under -W error
    it is printed as "Exception ignored in ..." through sys.unraisablehook, because a
    destructor cannot raise into the caller; the exit code is unchanged and -W ignore or
    PYTHONWARNINGS=ignore silence it. It comes only when the object is collected, so a
    plain update() loop that never calls finalize() is still a footgun: the prefix it
    returned was verified chunk by chunk, but nothing proves the stream ended there. Use
    iter_rehearsal(), `with`, or the one-shot / file helpers. close() abandons a stream
    deliberately (no warning, later calls raise ValueError).

    A worker failure or timeout (workers > 1) raises RuntimeError and leaves the decryptor
    dead like a reject (later calls raise AuthError("stream already rejected")); it does not
    mean the stream was forged.

    max_chunk_size (rehearsal-fix I4) is an optional receiver limit: a header that
    declares a larger chunk size is rejected at once (AuthError "chunk size above
    max_chunk_size"), before any chunk is buffered.

    Rejects. Version byte != 8 raises UnsupportedVersion (like every other decrypt API).
    Everything else raises AuthError: "bad version prefix", "bad chunk size",
    "chunk size above max_chunk_size", "bad stream length", "too many chunks" (public
    structure), and "authentication failed" for commitment, tag and final-padding
    failures. Chunk 0 always computes BOTH the commitment and its tag before one combined
    reject (equal-time, like v6/v7). After any reject the decryptor is dead; every later
    call raises AuthError("stream already rejected"). If update() rejects, it returns
    nothing from that call, even for earlier chunks in the same call."""
    def __init__(self, seed=None, ad: bytes = b"", *, workers: int = 1, max_chunk_size: int = None,
                 worker_timeout: float = None):
        self._pool = None
        self._state = "init"
        self._ad = _normalize_ad(ad)
        self._workers = _rehearsal_workers(workers)
        self._worker_timeout = _rehearsal_worker_timeout(worker_timeout)
        self._max_cs = _rehearsal_max_chunk_size(max_chunk_size)
        self._seed = _seed_bytes(seed)
        self._clef = staff_clef(self._seed)
        self._rsig = rehearsal_signature(self._seed)
        self._adh = _rehearsal_ad_digest(self._ad)
        self._hdr = None
        self._sch = None
        self._buf = bytearray()
        self._index = 0
        self._commit_ok = False
        self._seen = False
        self._state = "open"

    @property
    def workers(self) -> int:
        """Worker processes actually allowed (after the min(32, cpu_count) cap)."""
        return self._workers

    def _require_open(self):
        if self._state == "rejected":
            raise AuthError("stream already rejected")
        if self._state != "open":
            raise ValueError("RehearsalDecryptor is " + self._state)

    def _reject(self, exc):
        self._state = "rejected"; self._buf = bytearray(); self.close()
        raise exc

    def _parse_header(self) -> bool:
        b = self._buf
        if len(b) >= 1 and b[0] != FMT_REHEARSAL:
            raise UnsupportedVersion("unsupported version")
        if len(b) < REHEARSAL_HDR_LEN:
            return False
        if bytes(b[1:PK0]) != VERSION:
            raise AuthError("bad version prefix")
        cs = int.from_bytes(b[RH_CS0:REHEARSAL_HDR_LEN], "big")
        if cs % BLOCK_LEN or not REHEARSAL_CHUNK_MIN <= cs <= REHEARSAL_CHUNK_MAX:
            raise AuthError("bad chunk size")
        if self._max_cs is not None and cs > self._max_cs:
            raise AuthError("chunk size above max_chunk_size")
        self._pickup, self._nonce = bytes(b[PK0:N0]), bytes(b[N0:CM0])
        self._commit, self._cs = bytes(b[CM0:CM1]), cs
        # Computed now, combined with chunk 0's tag later (no early reject on the commitment).
        self._commit_ok = hmac.compare_digest(self._commit, _rehearsal_commitment(
            _commit_key(self._seed), self._pickup, self._nonce, self._ad, cs))
        self._sched_nonce = _rehearsal_schedule_nonce(self._seed, self._pickup, self._nonce, cs, self._adh)
        self._hdr = bytes(b[:REHEARSAL_HDR_LEN])
        del self._buf[:REHEARSAL_HDR_LEN]
        return True

    def _verify(self, index, final, ct, tag) -> bool:
        key = _rehearsal_chunk_key(self._seed, self._pickup, self._nonce, self._cs, index, final, self._adh)
        ok = hmac.compare_digest(tag, _rehearsal_tag(key, self._clef, self._rsig, self._pickup, self._nonce,
                                                     self._commit, self._cs, index, final, self._adh, ct))
        if index == 0:
            ok = ok & self._commit_ok           # equal-time: both always computed, one reject
        return ok

    def _fail(self):
        self._state = "rejected"; self._buf = bytearray(); self.close()

    def update(self, data) -> bytes:
        """Absorb ciphertext; return the plaintext of every chunk verified so far (possibly b"")."""
        self._require_open()
        data = _as_bytes("data", data)
        self._buf += data
        if data:
            self._seen = True
        try:
            if self._hdr is None and not self._parse_header():
                return b""
            cs = self._cs; stride = cs + TAG_LEN
            jobs, off = [], 0
            while len(self._buf) - off > stride:          # more bytes follow, so this chunk is not final
                i = self._index + len(jobs)
                if i + 1 >= MAX_REHEARSAL_CHUNKS:
                    raise AuthError("too many chunks")
                ct = bytes(self._buf[off:off + cs]); tag = bytes(self._buf[off + cs:off + stride])
                if not self._verify(i, False, ct, tag):
                    raise AuthError("authentication failed")
                jobs.append((i, False, ct))
                off += stride
            pts = self._crypt_jobs(jobs, decrypt=True)
        except Rejected as e:
            self._reject(e)
        except BaseException:
            self._fail()
            raise
        del self._buf[:off]
        self._index += len(jobs)
        return b"".join(pts)

    def finalize(self) -> bytes:
        """Verify and open the final chunk. Raises AuthError if the stream is short, long or forged."""
        self._require_open()
        try:
            if self._hdr is None:
                self._parse_header()
                if self._hdr is None:
                    raise AuthError("bad stream length")
            n = len(self._buf)
            if n < BLOCK_LEN + TAG_LEN or n > self._cs + TAG_LEN or (n - TAG_LEN) % BLOCK_LEN:
                raise AuthError("bad stream length")
            ct = bytes(self._buf[:n - TAG_LEN]); tag = bytes(self._buf[n - TAG_LEN:])
            if not self._verify(self._index, True, ct, tag):
                raise AuthError("authentication failed")
            padded = self._crypt_jobs([(self._index, True, ct)], decrypt=True)[0]
            ok, msg = _rehearsal_unpad(padded)
            if not ok:
                padded = msg = None                     # rehearsal-finale I8: nothing decrypted stays reachable
                raise AuthError("authentication failed")
        except Rejected as e:
            self._reject(e)
        except BaseException:
            self._fail()
            raise
        self._state = "finalized"; self._buf = bytearray(); self.close()
        return msg

    def _open_all(self, blob) -> bytes:
        """One-shot open of a whole stream (rehearsal-fix I3): parse the header, check EVERY tag,
        including the final chunk's, and only then decrypt anything. A forged final chunk after
        valid chunks therefore costs HMACs only, never a decryption."""
        self._require_open()
        self._buf += blob
        if blob:
            self._seen = True
        try:
            if self._hdr is None and not self._parse_header():
                raise AuthError("bad stream length")
            b = self._buf; n = len(b); cs = self._cs; stride = cs + TAG_LEN
            jobs, off, i = [], 0, self._index
            while n - off > stride:
                if i + 1 >= MAX_REHEARSAL_CHUNKS:
                    raise AuthError("too many chunks")
                ct = bytes(b[off:off + cs]); tag = bytes(b[off + cs:off + stride])
                if not self._verify(i, False, ct, tag):
                    raise AuthError("authentication failed")
                jobs.append((i, False, ct)); off += stride; i += 1
            rest = n - off
            if rest < BLOCK_LEN + TAG_LEN or rest > stride or (rest - TAG_LEN) % BLOCK_LEN:
                raise AuthError("bad stream length")
            ct = bytes(b[off:n - TAG_LEN]); tag = bytes(b[n - TAG_LEN:])
            if not self._verify(i, True, ct, tag):
                raise AuthError("authentication failed")
            jobs.append((i, True, ct))
            pts = self._crypt_jobs(jobs, decrypt=True)       # every tag passed: only now decrypt
            ok, last = _rehearsal_unpad(pts[-1])
            if not ok:
                pts.clear(); last = None                # rehearsal-finale I8: no decrypted chunk stays reachable
                raise AuthError("authentication failed")
        except Rejected as e:
            self._reject(e)
        except BaseException:
            self._fail()
            raise
        self._state = "finalized"; self._buf = bytearray(); self.close()
        return b"".join(pts[:-1]) + last

    def close(self):
        """Release the worker processes. Called by finalize() and on every reject. Called by the
        caller after data arrived but before finalize(), it abandons the stream on purpose."""
        self._close_pool()
        if getattr(self, "_state", None) == "open" and getattr(self, "_seen", False):
            self._state = "closed"; self._buf = bytearray()

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None and self._state == "open" and self._seen:
            self._fail()
            raise AuthError("stream not finalized")
        self.close()
        return False

    def __del__(self):
        unfinished = getattr(self, "_state", None) == "open" and getattr(self, "_seen", False)
        try:
            self._close_pool()
        except Exception:
            pass
        if unfinished:
            # rehearsal-finale L2: outside any try/except, so a warning turned into an exception
            # (-W error) is reported through sys.unraisablehook instead of being swallowed here.
            warnings.warn("RehearsalDecryptor dropped after receiving data without finalize(): the end of the "
                          "stream was never verified (use iter_rehearsal or call finalize())", UnfinalizedStreamWarning, stacklevel=2)

def encrypt_rehearsal(msg: bytes, seed=None, ad: bytes = b"", chunk_size: int = REHEARSAL_CHUNK_DEFAULT, *, workers: int = 1,
                      worker_timeout: float = None) -> bytes:
    """One-shot rehearsal (v8) stream: RehearsalEncryptor(...).update(msg) + finalize(). No length cap
    beyond MAX_REHEARSAL_CHUNKS chunks. Byte-identical to any incremental split for the same pickup/nonce.
    Memory (rehearsal-polish I8): the caller's msg plus about 2x its size while sealing (the
    plaintext copy buffered in the encryptor and the joined output); use RehearsalEncryptor or
    encrypt_rehearsal_file for large inputs."""
    msg = _as_bytes("msg", msg)
    enc = RehearsalEncryptor(seed, ad, chunk_size, workers=workers, worker_timeout=worker_timeout)
    return enc.update(msg) + enc.finalize()

def decrypt_rehearsal(blob: bytes, seed=None, ad: bytes = b"", *, workers: int = 1, max_chunk_size: int = None,
                      worker_timeout: float = None) -> bytes:
    """One-shot rehearsal (v8) decrypt: all-or-nothing. Every chunk tag, the final chunk's included,
    is checked before any block is decrypted (rehearsal-fix I3). Returns the whole plaintext only if
    every chunk verified and the final padding is valid; otherwise raises (nothing is returned).
    Memory (rehearsal-polish I8): on top of the caller's blob, peak use is about 4x the blob for a
    genuine stream (5x at chunk_size 128: internal buffer, per-chunk copies, decrypted chunks and the
    joined result) and about 2x while rejecting. For large streams use iter_rehearsal or
    decrypt_rehearsal_file (memory bounded by read_size + chunk_size). max_chunk_size stays opt-in:
    without it a forged header can make a streaming reader buffer up to one 1 MiB chunk."""
    blob = _as_bytes("blob", blob)
    dec = RehearsalDecryptor(seed, ad, workers=workers, max_chunk_size=max_chunk_size, worker_timeout=worker_timeout)
    return dec._open_all(blob)

def iter_rehearsal(src, seed=None, ad: bytes = b"", *, read_size: int = 1 << 20, workers: int = 1,
                   max_chunk_size: int = None, worker_timeout: float = None):
    """Safe streaming reader (rehearsal-fix L3). Yields the verified plaintext of a rehearsal stream
    piece by piece and ALWAYS runs finalize() at the end, so a stream cut anywhere (including exactly
    at a chunk boundary) raises AuthError from the loop instead of ending quietly. src is a path (str
    or os.PathLike), a binary file object, a bytes-like object, or an iterable of bytes-like pieces.
    A bytes object is always CIPHERTEXT, never a path (rehearsal-polish I7; decrypt_rehearsal_file
    does accept bytes paths). rehearsal-finale L3: the filesystem is never consulted for a bytes
    src, so a bytes value that is not a stream always gets the same UnsupportedVersion/AuthError
    whether or not it happens to name a file. Pass paths as str or os.PathLike here. read_size must
    be an int >= 1 (rehearsal-finale I7).

        for piece in iter_rehearsal("msg.oct", seed, ad=b"..."):
            sink.write(piece)          # verified, but the stream is complete only when the loop ends

    Every yielded piece has passed its tag, but the stream as a whole is authentic only once the loop
    finishes without an exception: a consumer that acts on pieces as they arrive must be able to undo
    them. Breaking out of the loop early (break, islice, zip, dropping the generator) abandons the
    stream with no warning: the pieces already consumed are a verified prefix, nothing more."""
    read_size = _rehearsal_read_size(read_size)
    dec = RehearsalDecryptor(seed, ad, workers=workers, max_chunk_size=max_chunk_size, worker_timeout=worker_timeout)
    fin = None
    try:
        if isinstance(src, (str, os.PathLike)):
            fin = open(src, "rb")
            pieces = iter(lambda: fin.read(read_size), b"")
        elif hasattr(src, "read"):
            pieces = iter(lambda: src.read(read_size), b"")
        elif isinstance(src, (bytes, bytearray, memoryview)):
            pieces = (bytes(src),)                  # always ciphertext; never stat'd (rehearsal-finale L3)
        else:
            pieces = iter(src)
        for piece in pieces:
            out = dec.update(piece)
            if out:
                yield out
        out = dec.finalize()
        if out:
            yield out
    finally:
        dec.close()
        if fin is not None:
            fin.close()

# ---------------------------------------------------------------- rehearsal file helpers
# rehearsal-finale (L1, I1-I4): the copy fallback keeps its descriptor open through the inode check;
# overwrite=True swaps with renameat2(RENAME_EXCHANGE) on Linux and swaps back if the check fails, so a
# refused race keeps the old dst; any /proc link failure on the O_TMPFILE path falls back to a copy;
# a kept partial falls back to a fresh dot-name on ANY error (reason in partial_error); the same-file
# check is repeated against the opened directory fd. A crash during an overwrite=True commit can leave
# a 0600 ".<dst>.XXXXXXXX.swap" file (new plaintext, or the old dst): remove stale .*.swap / .*.tmp /
# .*.partial dot-files after a crash.
# rehearsal-fix M1 / L1 / L2, rehearsal-polish L1 / I3-I6. dst's directory is opened ONCE (a dirfd)
# from an absolute path fixed at call start, and every create, link, rename, stat and unlink is
# relative to that dirfd, so a chdir or a swapped parent symlink during the call cannot move the
# output. Output goes to a private 0600 file: on Linux an anonymous O_TMPFILE in dst's directory (no
# name anyone can swap, nothing left behind by a crash MID-STREAM), else a fresh dot-name created with
# O_CREAT | O_EXCL | O_NOFOLLOW. It is fsync'd and then published with a hard link that never
# follows a symlink and fails if dst exists (overwrite=True: link to a fresh name, then rename over
# dst). After publishing, dst must be the very inode this call wrote (checked with lstat against
# the open descriptor); otherwise the name this call just created is removed and RuntimeError is
# raised, so a helper never vouches for someone else's file. Only on filesystems without hard links
# (EPERM, EOPNOTSUPP/ENOTSUP, ENOSYS, EXDEV, EMLINK) is dst created with O_EXCL | O_NOFOLLOW and the
# bytes copied in; every other link error is raised. The directory is fsync'd last. dst's directory
# should not be writable by others (or should be sticky): such a user can still replace dst AFTER
# the call returns. src and dst (or src and the temporary file) being one file is refused before
# anything is written.
_REHEARSAL_NO_LINK_ERRNOS = frozenset(getattr(errno, n) for n in ("EPERM", "EOPNOTSUPP", "ENOTSUP", "ENOSYS", "EXDEV", "EMLINK")
                                      if hasattr(errno, n))
_REHEARSAL_USE_O_TMPFILE = True      # False forces the named-temp path (tests; systems without O_TMPFILE use it anyway)
_REHEARSAL_USE_RENAMEAT2 = True      # rehearsal-finale I1: False forces the os.replace path for overwrite=True (tests)
_RENAME_NOREPLACE, _RENAME_EXCHANGE = 1, 2
_REHEARSAL_PREFIX_BYTES = 100        # temp name = "." + prefix(<= 100 bytes) + "." + 8 hex + suffix  (<= 118 bytes)

def _rehearsal_open(f, mode):
    return (f, False) if hasattr(f, "read" if "r" in mode else "write") else (open(f, mode), True)

def _rehearsal_fstat(f):
    """os.fstat of a file object's descriptor, or None if it has none."""
    try:
        return os.fstat(f.fileno())
    except (AttributeError, OSError, ValueError):
        return None

def _rehearsal_same_inode(a, b) -> bool:
    return a is not None and b is not None and (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)

def _rehearsal_refuse_same(src, fin, dst):
    """ValueError if src and dst are the same file: same realpath, or same (st_dev, st_ino)
    (hard links and symlinks included), for paths and for file objects with a descriptor."""
    fst = _rehearsal_fstat(fin)
    if hasattr(dst, "write"):
        if fin is dst or _rehearsal_same_inode(fst, _rehearsal_fstat(dst)):
            raise ValueError("src and dst are the same file")
        return
    path = os.fspath(dst)
    if isinstance(src, (str, bytes, os.PathLike)) and os.path.realpath(os.fspath(src)) == os.path.realpath(path):
        raise ValueError("src and dst are the same file")
    try:
        dst_st = os.stat(path)
    except OSError:
        dst_st = None
    if _rehearsal_same_inode(fst, dst_st):
        raise ValueError("src and dst are the same file")

def _rehearsal_abspath(p):
    """rehearsal-polish I4: a str/bytes/PathLike path made absolute against the cwd AT CALL START (no
    normalisation, so ".." keeps its kernel meaning); file objects are returned unchanged."""
    if not isinstance(p, (str, bytes, os.PathLike)):
        return p
    p = os.fspath(p)
    if os.path.isabs(p):
        return p
    return os.path.join(os.getcwdb() if isinstance(p, bytes) else os.getcwd(), p)

def _rehearsal_temp_prefix(base) -> str:
    """rehearsal-polish I5: the first _REHEARSAL_PREFIX_BYTES BYTES of base (not characters), cut back to
    a whole UTF-8 character, so prefix + 18 bytes always fits a 255-byte name."""
    b = os.fsencode(base)[:_REHEARSAL_PREFIX_BYTES]
    k = len(b)
    while k > 0 and len(b) - k < 3 and (b[k - 1] & 0xC0) == 0x80:
        k -= 1
    if k > 0 and b[k - 1] >= 0xC0:
        lead = b[k - 1]
        need = 2 if lead < 0xE0 else 3 if lead < 0xF0 else 4
        if len(b) - (k - 1) < need:
            b = b[:k - 1]
    return os.fsdecode(b)

def _rehearsal_renameat2(dirfd, old, new, flags) -> bool:
    """rehearsal-finale I1: Linux renameat2(dirfd, old, dirfd, new, flags) through libc (ctypes, loaded
    on first use). True on success; False if renameat2 is unavailable here (no Linux/glibc symbol,
    ENOSYS, or EINVAL: this filesystem does not support the flag); any other failure raises OSError."""
    if not _REHEARSAL_USE_RENAMEAT2 or not sys.platform.startswith("linux"):
        return False
    fn = getattr(_rehearsal_renameat2, "fn", None)
    if fn is None:
        try:
            import ctypes
            fn = ctypes.CDLL(None, use_errno=True).renameat2
            fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
            fn.restype = ctypes.c_int
            fn.get_errno = ctypes.get_errno
        except Exception:
            fn = False
        _rehearsal_renameat2.fn = fn
    if fn is False:
        return False
    if fn(dirfd, os.fsencode(old), dirfd, os.fsencode(new), flags) == 0:
        return True
    err = fn.get_errno()
    if err in (errno.ENOSYS, errno.EINVAL):
        return False
    raise OSError(err, os.strerror(err), new)

def _rehearsal_fsync_dir(d):
    """fsync a directory given as a path or an open directory descriptor (int)."""
    if isinstance(d, int):
        try:
            os.fsync(d)
        except OSError:
            pass
        return
    try:
        fd = os.open(d, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)

class _RehearsalOutput:
    """A private temporary output file in dst's directory (see the comment above)."""
    def __init__(self, dst, fin, suffix, overwrite):
        path = os.fspath(dst)
        if isinstance(path, bytes):
            path = os.fsdecode(path)
        base = os.path.basename(path)
        if not base or base in (".", ".."):
            raise ValueError("dst must name a file")
        path = _rehearsal_abspath(path)
        self.path, self.overwrite, self.suffix = path, overwrite, suffix
        self.done, self.st, self.fd, self.dirfd, self.tmp, self.f = False, None, None, None, None, None
        self.pub_fds, self.keep_error = [], None
        self.src_st = _rehearsal_fstat(fin)
        self.dir, self.base = os.path.dirname(path), base
        self.prefix = "." + _rehearsal_temp_prefix(base) + "."
        self.dirfd = os.open(self.dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            self._refuse_src()
            st = self._lstat(base)
            if st is not None:
                if not overwrite:
                    raise FileExistsError(errno.EEXIST, "dst exists (pass overwrite=True to replace it)", path)
                if stat.S_ISDIR(st.st_mode):
                    raise IsADirectoryError(errno.EISDIR, "dst is a directory", path)
            if _REHEARSAL_USE_O_TMPFILE and hasattr(os, "O_TMPFILE") and os.path.isdir("/proc/self/fd"):
                try:
                    self.fd = os.open(".", os.O_TMPFILE | os.O_RDWR | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=self.dirfd)
                except OSError:
                    self.fd = None                # no O_TMPFILE on this filesystem/kernel: named temp below
            if self.fd is None:
                self.fd, self.tmp = self._create_free(suffix)
            os.fchmod(self.fd, 0o600)
            self.st = os.fstat(self.fd)
            if _rehearsal_same_inode(_rehearsal_fstat(fin), self.st):
                raise ValueError("src is the temporary output file")
            self.f = open(self.fd, "wb", closefd=False)
        except BaseException:
            self._unlink_own()
            self._close_fds()
            raise

    def _lstat(self, name):
        try:
            return os.stat(name, dir_fd=self.dirfd, follow_symlinks=False)
        except FileNotFoundError:
            return None

    def _refuse_src(self):
        """rehearsal-finale I4: the same-file check again, relative to the directory fd this call
        writes through (a symlink at dst is followed here, as in the path check)."""
        if self.src_st is None:
            return
        try:
            st = os.stat(self.base, dir_fd=self.dirfd, follow_symlinks=True)
        except OSError:
            return
        if _rehearsal_same_inode(st, self.src_st):
            raise ValueError("src and dst are the same file")

    def _create(self, name):
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        return os.open(name, flags, 0o600, dir_fd=self.dirfd)

    def _create_free(self, suffix):
        """O_EXCL-create a fresh unique dot-name in dst's directory -> (fd, name)."""
        for _ in range(100):
            name = self.prefix + os.urandom(4).hex() + suffix
            try:
                return self._create(name), name
            except FileExistsError:
                continue
        raise FileExistsError(errno.EEXIST, "no free temporary name", self.dir)

    def _check(self, name, want, created):
        """name must now be the inode `want` (lstat, never following a symlink). If not, remove the
        name this call created (it points at someone else's inode) and raise."""
        try:
            st = self._lstat(name)
        except OSError:
            st = None
        if not _rehearsal_same_inode(st, want):
            if created and st is not None:
                try: os.unlink(name, dir_fd=self.dirfd)
                except OSError: pass
            raise RuntimeError("output file was replaced while it was being moved into place (not published)")

    def _publish(self, name):
        """Give our file the new name `name` (FileExistsError if taken); verify it; return its stat."""
        try:
            if self.tmp is None:
                os.link("/proc/self/fd/%d" % self.fd, name, dst_dir_fd=self.dirfd, follow_symlinks=True)
            else:
                os.link(self.tmp, name, src_dir_fd=self.dirfd, dst_dir_fd=self.dirfd, follow_symlinks=False)
        except FileExistsError:
            raise
        except OSError as e:
            # rehearsal-polish I3: no hard links on this filesystem -> copy. rehearsal-finale I3: on the
            # O_TMPFILE path ANY link failure (odd /proc, hidepid, sandbox: ENOENT, EACCES, ...) also
            # copies, because the verified bytes are still in our descriptor and would be lost otherwise.
            if self.tmp is None or e.errno in _REHEARSAL_NO_LINK_ERRNOS:
                return self._copy_to(name)
            raise
        self._check(name, self.st, True)
        return self.st

    def _copy_to(self, name):
        """Copy fallback: O_EXCL | O_NOFOLLOW create name (never clobbers anything created in the
        meantime), copy our bytes in, fsync, verify. rehearsal-finale L1: fd2 stays OPEN through the
        check and until the helper finishes (closed in _close_fds), so its inode number cannot be
        freed and recycled for a file someone creates at name in the meantime."""
        fd2 = self._create(name)
        try:
            off = 0
            while True:
                data = os.pread(self.fd, 1 << 20, off)
                if not data:
                    break
                view = memoryview(data)
                while view:
                    view = view[os.write(fd2, view):]
                off += len(data)
            os.fsync(fd2)
            st2 = os.fstat(fd2)
        except BaseException:
            try:
                if _rehearsal_same_inode(self._lstat(name), os.fstat(fd2)):
                    os.unlink(name, dir_fd=self.dirfd)
            except OSError:
                pass
            os.close(fd2)
            raise
        self.pub_fds.append(fd2)
        self._check(name, st2, True)
        return st2

    def _publish_free(self, suffix):
        for _ in range(100):
            name = self.prefix + os.urandom(4).hex() + suffix
            try:
                return name, self._publish(name)
            except FileExistsError:
                continue
        raise FileExistsError(errno.EEXIST, "no free temporary name", self.dir)

    def _unlink_own(self):
        """Unlink the named temporary file (if any) only if it is still the inode this call created."""
        if self.tmp is None or self.dirfd is None:
            return
        try:
            if self.st is None or _rehearsal_same_inode(self._lstat(self.tmp), self.st):
                os.unlink(self.tmp, dir_fd=self.dirfd)
        except OSError:
            pass

    def _close_fds(self):
        fds, self.pub_fds = getattr(self, "pub_fds", []), []
        for v in fds:
            try: os.close(v)
            except OSError: pass
        for attr in ("f", "fd", "dirfd"):
            v = getattr(self, attr, None)
            setattr(self, attr, None)
            if v is None:
                continue
            try:
                v.close() if attr == "f" else os.close(v)
            except Exception:
                pass

    def commit(self):
        """fsync, publish (no clobber unless overwrite=True, never through a symlink, dst verified to be
        our inode afterwards), fsync the directory."""
        self.f.flush(); os.fsync(self.fd); self.f.close()
        if self.tmp is not None and not _rehearsal_same_inode(self._lstat(self.tmp), self.st):
            raise RuntimeError("temporary output file was replaced")
        self._refuse_src()                          # rehearsal-finale I4: once more, just before publishing
        if not self.overwrite:
            try:
                self._publish(self.base)            # atomic: fails if dst exists, even as a dangling symlink
            except FileExistsError:
                raise FileExistsError(errno.EEXIST, "dst exists (pass overwrite=True to replace it)", self.path)
        else:
            self._replace()
        self.done = True
        self._unlink_own()
        _rehearsal_fsync_dir(self.dirfd)
        self._close_fds()

    def _replace(self):
        """overwrite=True publish (rehearsal-finale I1/I2). dst absent: the no-clobber link (no hidden
        name at all). dst present: link our file to a fresh .swap name, then on Linux swap it with dst
        atomically (renameat2 RENAME_EXCHANGE). If dst is then not our inode (someone renamed over the
        .swap name in between), exchange back, so the caller's old dst survives a failed call, remove
        the stray name and raise. Otherwise unlink the old dst, now at the .swap name. Without
        renameat2 (other OS, old libc, unsupported filesystem) it falls back to os.replace + check,
        where a refused race can cost the old dst (documented). A crash between the .swap link and
        the end of commit can leave that 0600 .swap file holding the new plaintext or the old dst."""
        if self._lstat(self.base) is None:
            try:
                self._publish(self.base)
                return
            except FileExistsError:
                pass                                # dst appeared meanwhile: replace it below
        name, want = self._publish_free(".swap")
        try:
            self._refuse_src()
            swapped = _rehearsal_renameat2(self.dirfd, name, self.base, _RENAME_EXCHANGE)
        except FileNotFoundError:
            swapped = False                         # dst vanished: a plain rename below is safe
        except BaseException:
            try: os.unlink(name, dir_fd=self.dirfd)
            except OSError: pass
            raise
        if swapped:
            if not _rehearsal_same_inode(self._lstat(self.base), want):
                try:
                    _rehearsal_renameat2(self.dirfd, name, self.base, _RENAME_EXCHANGE)   # old dst back
                    os.unlink(name, dir_fd=self.dirfd)                                    # the stray file
                except OSError:
                    pass
                raise RuntimeError("output file was replaced while it was being moved into place "
                                   "(not published; the old dst was put back)")
            try: os.unlink(name, dir_fd=self.dirfd)  # the old dst, now under our .swap name
            except OSError: pass
        else:
            try:
                os.replace(name, self.base, src_dir_fd=self.dirfd, dst_dir_fd=self.dirfd)
            except BaseException:
                try: os.unlink(name, dir_fd=self.dirfd)
                except OSError: pass
                raise
        self._check(self.base, want, True)

    def discard(self, keep=False, suffix=None):
        """On failure: drop our file, or (keep=True, and only if it holds at least one verified byte)
        fsync it and publish it as dst + suffix (default self.suffix, ".partial") when that name can be
        created, else under a fresh unique dot-name (never clobbering or following anything); fsync the
        directory; return the absolute path of the kept file (rehearsal-polish I6). rehearsal-finale
        I3: ANY error on the dst + suffix name (taken, ENAMETOOLONG for a 248+ byte dst, a refused
        race) falls back to the fresh dot-name; if keeping still fails, the reason is stored in
        self.keep_error (the helper attaches it to the exception as partial_error)."""
        if self.done:
            return None
        kept = None
        suffix = self.suffix if suffix is None else suffix
        try:
            if self.f is not None:
                try: self.f.close()
                except Exception: pass
            if keep and self.fd is not None and os.fstat(self.fd).st_size > 0:
                os.fsync(self.fd)
                try:
                    self._publish(self.base + suffix)
                    kept = self.base + suffix
                except (OSError, RuntimeError):
                    kept = self._publish_free(suffix)[0]
                _rehearsal_fsync_dir(self.dirfd)
        except Exception as e:
            kept = None
            self.keep_error = e
        finally:
            self._unlink_own()
            self._close_fds()
        return None if kept is None else os.path.join(self.dir, kept)

def encrypt_rehearsal_file(src, dst, seed=None, ad: bytes = b"", chunk_size: int = REHEARSAL_CHUNK_DEFAULT, *,
                           workers: int = 1, read_size: int = None, overwrite: bool = False,
                           worker_timeout: float = None) -> int:
    """Stream src (path or binary file object) into a rehearsal stream at dst (path or binary file
    object), reading read_size bytes at a time (default: chunk_size * workers). Memory stays
    O(read_size + chunk_size). A dst PATH is written through a private 0600 temporary file in dst's
    directory (anonymous O_TMPFILE on Linux), fsync'd and published only on success, then checked
    to be the inode this call wrote; an existing dst raises FileExistsError unless overwrite=True
    (a real bool; overwrite=True replaces read-only files too, the result is 0600, and other hard
    links to the old dst keep the old content); src and dst being one file raises ValueError.
    read_size is None or an int >= 1. overwrite=True swaps with renameat2(RENAME_EXCHANGE) on
    Linux (a refused race keeps the old dst); a crash during that commit can leave a 0600
    ".dst.XXXXXXXX.swap" dot-file. Paths are made absolute when the call starts. Returns the
    number of ciphertext bytes written."""
    overwrite = _rehearsal_bool("overwrite", overwrite)
    read_size = _rehearsal_read_size(read_size, allow_none=True)
    src, dst = _rehearsal_abspath(src), _rehearsal_abspath(dst)
    enc = RehearsalEncryptor(seed, ad, chunk_size, workers=workers, worker_timeout=worker_timeout)
    rs = read_size or chunk_size * enc._workers
    fin, close_in = _rehearsal_open(src, "rb")
    out = None
    total = 0
    try:
        _rehearsal_refuse_same(src, fin, dst)
        if hasattr(dst, "write"):
            fout = dst
        else:
            out = _RehearsalOutput(dst, fin, ".tmp", overwrite)
            fout = out.f
        with enc:
            while True:
                piece = fin.read(rs)
                if not piece:
                    break
                data = enc.update(piece); fout.write(data); total += len(data)
            data = enc.finalize(); fout.write(data); total += len(data)
        if out is not None:
            out.commit()
    except BaseException:
        enc.close()
        if out is not None:
            out.discard()
        raise
    finally:
        if close_in: fin.close()
    return total

def decrypt_rehearsal_file(src, dst, seed=None, ad: bytes = b"", *, workers: int = 1, read_size: int = 1 << 20,
                           keep_partial: bool = False, overwrite: bool = False, max_chunk_size: int = None,
                           stream_verified_prefix: bool = False, worker_timeout: float = None) -> int:
    """Decrypt a rehearsal stream from src (path or binary file object) to dst. Plaintext is written
    only after each chunk verifies, and dst sees it only after finalize() succeeds:
    - dst PATH: written through a private 0600 temporary file in dst's directory (anonymous
      O_TMPFILE on Linux), fsync'd, and published as dst only after the whole stream verified; dst
      is then checked to be the inode this call wrote, and the directory is fsync'd. An existing
      dst raises FileExistsError unless overwrite=True (a symlink at dst is never followed). On any
      reject the temporary file is dropped, or with keep_partial=True kept (holding only verified
      chunk-aligned prefix plaintext, fsync'd, directory fsync'd) as dst + ".partial" if that name
      is free, else under a fresh unique dot-name; the kept absolute path is set as the exception's
      partial_path attribute. Nothing is kept when no chunk verified (e.g. a header reject). If
      the WHOLE stream verified but publishing failed (dst appeared meanwhile with overwrite=False,
      or a refused race), the kept file is named dst + ".complete" instead (rehearsal-finale I3).
      If dst + suffix cannot be created for any reason (taken, name too long) a fresh unique
      dot-name is used; if keeping fails altogether, the reason is the exception's partial_error.
      The error is re-raised. A SIGKILL mid-stream leaves nothing behind with O_TMPFILE; on the
      named-temp fallback it can leave a 0600 dot-file holding verified prefix plaintext. A crash
      during an overwrite=True commit can leave a 0600 ".dst.XXXXXXXX.swap" dot-file holding the
      new plaintext or the old dst (rehearsal-finale I2); clean up stale .*.swap files.
      overwrite=True swaps atomically with renameat2(RENAME_EXCHANGE) where Linux supports it and
      swaps back if the result is not this call's file, so a failed call keeps the old dst;
      elsewhere it uses os.replace, and a refused race can then cost the old dst.
    - dst FILE OBJECT: verified plaintext is buffered in an anonymous 0600 temporary file (in
      $TMPDIR, on that filesystem; RAM/swap on a tmpfs) and copied to dst only after finalize()
      succeeds, so after a reject dst has received nothing. stream_verified_prefix=True writes
      verified chunks to dst as they come instead (then, after a reject, dst holds a verified
      prefix the caller must discard). keep_partial has no effect for a file-object dst.
    overwrite, keep_partial and stream_verified_prefix must be real bools and read_size an int >= 1;
    paths are made absolute when the call starts.
    src and dst being one file raises ValueError before anything is written. max_chunk_size is the
    optional receiver limit (see RehearsalDecryptor). A forged final chunk is found only at the end
    of the stream, after the earlier verified chunks were decrypted (streaming keeps memory bounded);
    decrypt_rehearsal() checks every tag first. Returns the number of plaintext bytes written."""
    overwrite = _rehearsal_bool("overwrite", overwrite)
    keep_partial = _rehearsal_bool("keep_partial", keep_partial)
    stream_verified_prefix = _rehearsal_bool("stream_verified_prefix", stream_verified_prefix)
    read_size = _rehearsal_read_size(read_size)
    src, dst = _rehearsal_abspath(src), _rehearsal_abspath(dst)
    dec = RehearsalDecryptor(seed, ad, workers=workers, max_chunk_size=max_chunk_size, worker_timeout=worker_timeout)
    fin, close_in = _rehearsal_open(src, "rb")
    out = sink = None
    total = 0
    complete = False
    try:
        _rehearsal_refuse_same(src, fin, dst)
        if hasattr(dst, "write"):
            sink = dst if stream_verified_prefix else tempfile.TemporaryFile()
            fout = sink
        else:
            out = _RehearsalOutput(dst, fin, ".partial", overwrite)
            fout = out.f
        with dec:
            while True:
                piece = fin.read(read_size)
                if not piece:
                    break
                data = dec.update(piece); fout.write(data); total += len(data)
            data = dec.finalize(); fout.write(data); total += len(data)
        complete = True
        if out is not None:
            out.commit()
        elif sink is not dst:
            sink.seek(0)
            while True:
                data = sink.read(1 << 20)
                if not data:
                    break
                dst.write(data)
    except BaseException as e:
        dec.close()
        if out is not None:
            kept = out.discard(keep_partial, ".complete" if complete else ".partial")
            try:
                if kept is not None:
                    e.partial_path = kept
                if out.keep_error is not None:
                    e.partial_error = out.keep_error
            except Exception:
                pass
        raise
    finally:
        if sink is not None and sink is not dst:
            sink.close()
        if close_in: fin.close()
    return total

# Rehearsal attestation. The live mix digest (_MIX_SHA256, hence key_sig) is deliberately NOT
# changed by rehearsal: none of the code below is reachable from MIX_CODE_ROOTS, so v6/v7 blobs
# stay byte-identical. Instead rehearsal has its own digest over everything reachable from
# REHEARSAL_CODE_ROOTS (which includes the whole staff-core) plus the live mix digest, and its own
# seed-keyed rehearsal signature (domain H), bound into every chunk tag.
REHEARSAL_CODE_ROOTS = ("RehearsalEncryptor", "RehearsalDecryptor", "encrypt_rehearsal", "decrypt_rehearsal",
                        "encrypt_rehearsal_file", "decrypt_rehearsal_file", "iter_rehearsal",
                        "rehearsal_signature", "rehearsal_description")

def rehearsal_description():
    """Canonical ASCII JSON: the live mix digest, a framed hash of the source of every function/class
    reachable from REHEARSAL_CODE_ROOTS, a framed hash of the module data they name, and the v8 layout."""
    reach, data_names = mix_code_closure(REHEARSAL_CODE_ROOTS)
    funcs = tuple(sorted(reach))
    code = hashlib.sha256()
    for name in funcs:
        obj = globals()[name]
        defaults = _canon_data((getattr(obj, "__defaults__", None), getattr(obj, "__kwdefaults__", None)))
        for part in (name.encode("utf-8"), inspect.getsource(obj).encode("utf-8"), defaults.encode("utf-8")):
            code.update(len(part).to_bytes(8, "big")); code.update(part)
    data = hashlib.sha256()
    for name in sorted(data_names):
        for part in (name.encode("utf-8"), _canon_data(globals()[name]).encode("utf-8")):
            data.update(len(part).to_bytes(8, "big")); data.update(part)
    return json.dumps(dict(
        format=FMT_REHEARSAL, mix_sha256=_MIX_SHA256,
        code=dict(functions=funcs, roots=REHEARSAL_CODE_ROOTS, sha256=code.hexdigest()),
        data=dict(names=tuple(sorted(data_names)), sha256=data.hexdigest()),
        header="version(1)=8||SN2(3)||pickup(16)||nonce(16)||commit(32)||chunk_size(4)",
        chunk="ct||tag(32); non-final ct=chunk_size; final ct=128*ceil((L+1)/128), msg||0x80||0*",
        block=("E(P^T)^T under Schedule(seed, R-sponge(sched||pickup||nonce||cs32||ad_digest)[:16]); "
               "T from R-sponge(chunk||pickup||nonce||cs32||index64||final8||ad_digest)"),
        ad_digest="SHA-256(SN2/A||encode_ad(ad))",
        domains=dict(chunk=REHEARSAL_DOMAIN.decode(), signature=REHEARSAL_SIG_DOMAIN.decode(), commit=COMMIT_DOMAIN.decode()),
        limits=dict(chunk_min=REHEARSAL_CHUNK_MIN, chunk_max=REHEARSAL_CHUNK_MAX, chunk_default=REHEARSAL_CHUNK_DEFAULT,
                    max_chunks=MAX_REHEARSAL_CHUNKS, max_ad=MAX_AD_LEN, max_workers=REHEARSAL_MAX_WORKERS)),
        sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")

def rehearsal_signature(seed=None) -> bytes:
    """Seed-keyed commitment to the rehearsal digest: StaffSponge(H, seed, sha256(rehearsal_description())).take(16).
    Hidden in every chunk tag, never stored. Separate from key_signature (domain G)."""
    return StaffSponge(REHEARSAL_SIG_DOMAIN, _seed_bytes(seed), bytes.fromhex(_REHEARSAL_SHA256)).take(16)


def encrypt_hello(seed=None):
    blob = encrypt(b"hello world", seed)
    v, pk, n, commit, ct, tag = split_blob(blob); g = bytes_to_grid(ct)
    return dict(blob=blob, pickup=pk, nonce=n, commit=commit, ct=ct, tag=tag, grid=g, rows=grid_rows(g))

def _init_attestation():
    """Compute mix_description() once from source and check it against EXPECTED_MIX_SHA256.
    If inspect cannot read source (a .pyc-only install), use the embedded digest."""
    global _MIX_SHA256, _SOURCE_AVAILABLE
    try:
        digest = hashlib.sha256(mix_description()).hexdigest()
        _SOURCE_AVAILABLE = True
        if EXPECTED_MIX_SHA256 != "TO_BE_FILLED" and digest != EXPECTED_MIX_SHA256:
            raise RuntimeError("embedded mix attestation mismatch: computed %s != %s" % (digest, EXPECTED_MIX_SHA256))
        _MIX_SHA256 = digest
    except OSError:
        if EXPECTED_MIX_SHA256 == "TO_BE_FILLED":
            raise RuntimeError("no source and no embedded mix attestation")
        _SOURCE_AVAILABLE = False
        _MIX_SHA256 = EXPECTED_MIX_SHA256

_init_attestation()

def _init_rehearsal_attestation():
    """Compute sha256(rehearsal_description()) once and check it against EXPECTED_REHEARSAL_SHA256.
    Without source (a .pyc-only install) the embedded digest is used, as for the mix digest."""
    global _REHEARSAL_SHA256
    try:
        digest = hashlib.sha256(rehearsal_description()).hexdigest()
        if EXPECTED_REHEARSAL_SHA256 != "TO_BE_FILLED" and digest != EXPECTED_REHEARSAL_SHA256:
            raise RuntimeError("embedded rehearsal attestation mismatch: computed %s != %s" % (digest, EXPECTED_REHEARSAL_SHA256))
        _REHEARSAL_SHA256 = digest
    except OSError:
        if EXPECTED_REHEARSAL_SHA256 == "TO_BE_FILLED":
            raise RuntimeError("no source and no embedded rehearsal attestation")
        _REHEARSAL_SHA256 = EXPECTED_REHEARSAL_SHA256

_init_rehearsal_attestation()

def _verify_executed_code():
    """rehearsal-finale I5: the attestations hash _MODULE_SOURCE (the .py bytes read at import), but
    Python may have executed a cached .pyc instead (it trusts the .pyc when its recorded source mtime
    and size match). Compile _MODULE_SOURCE here and require that every function and method this
    module actually defined has exactly the code object compiled from it (bytecode, constants, names,
    line table). A .pyc built from different source, or a .py swapped between Python's read and the
    snapshot, makes the import fail. Module-level statements are not compared; the data the digests
    name is hashed from the live values anyway. Skipped when there is no source (.pyc-only install)."""
    if _MODULE_SOURCE is None:
        return
    want = {}
    todo = [compile(_MODULE_SOURCE, globals().get("__file__") or "<octavo>", "exec", dont_inherit=True)]
    while todo:
        for k in todo.pop().co_consts:
            if isinstance(k, types.CodeType):
                want.setdefault((k.co_qualname, k.co_firstlineno), k); todo.append(k)
    seen = 0
    for obj in list(globals().values()):
        if getattr(obj, "__module__", None) != __name__ or not isinstance(obj, (types.FunctionType, type)):
            continue
        members = [obj] if isinstance(obj, types.FunctionType) else list(vars(obj).values())
        for m in members:
            if isinstance(m, (staticmethod, classmethod)):
                m = m.__func__
            if isinstance(m, property):
                m = m.fget
            if not isinstance(m, types.FunctionType):
                continue
            c = m.__code__
            if want.get((c.co_qualname, c.co_firstlineno)) != c:
                raise RuntimeError("executed bytecode for %s does not match sneak_n2.py source "
                                   "(stale or tampered .pyc?); remove __pycache__ and re-import" % c.co_qualname)
            seen += 1
    if not seen:
        raise RuntimeError("executed-code check found nothing to compare")

_verify_executed_code()
