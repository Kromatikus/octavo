"""App-facing API for Octavo, a homemade experimental cipher.

This module is a thin front door around the current v6 single-message
format in sneak_n2.py. It does not change the cipher. seal() and open_()
always use format version 6, never enable legacy modes, and never write
keys to disk.

Octavo is a homemade demo cipher and is not for real secrets. Use
AES-GCM-SIV, age or libsodium.

Typical use::

    import octavo
    key = octavo.generate_key()          # 32 random bytes; or a libsodium X25519 shared key
    blob = octavo.seal(key, b"hello", ad=b"from:alice")
    assert octavo.open_(key, blob, ad=b"from:alice") == b"hello"

Keys are 32 or 64 bytes. They are expanded with HKDF-SHA512 (stdlib
hmac/hashlib; salt is the RFC 5869 default of 64 zero bytes; info is
APP_KEY_INFO == b'Octavo app key v1') into the 1024-bit seed Octavo
needs. Other lengths, str, None, and an all-zero key are rejected.

Call verify_install() to compare the published SHAs of sneak_n2.py,
etudes.py and score/generate_score.py with score/vectors.json, and to
recompute the package's key-expansion vectors. That check catches
mistakes; it is not a tamper guard (see SECURITY.md). The import-time
self-checks in sneak_n2.py are unchanged.
"""

from __future__ import annotations

from builtins import open as _fopen
import hashlib
import hmac
import json
import os
import secrets
import warnings

import sneak_n2 as _n2

# Re-export the cipher's reject family so apps can ``except octavo.Rejected``.
Rejected = _n2.Rejected
AuthError = _n2.AuthError
DecodeError = _n2.DecodeError
UnsupportedVersion = _n2.UnsupportedVersion

DEMO_ONLY = True
APP_KEY_INFO = b"Octavo app key v1"
APP_KEY_LENS = (32, 64)
APP_SEED_LEN = 128  # 1024-bit Octavo seed
APP_VECTORS_NAME = "app_vectors.json"

__all__ = [
    "DEMO_ONLY",
    "APP_KEY_INFO",
    "APP_KEY_LENS",
    "Rejected",
    "AuthError",
    "DecodeError",
    "UnsupportedVersion",
    "generate_key",
    "expand_key",
    "seal",
    "open_",
    "open",
    "verify_install",
]

_WARNED = False
_WARNING = (
    "Octavo is a homemade demo cipher and is not for real secrets. "
    "Use AES-GCM-SIV, age or libsodium."
)


def _emit_demo_warning():
    """Emit the demo-only UserWarning once per process."""
    global _WARNED
    if _WARNED:
        return
    _WARNED = True
    warnings.warn(_WARNING, UserWarning, stacklevel=3)


def _as_key_bytes(key) -> bytes:
    """Return the raw key bytes, or raise TypeError for illegal types."""
    if key is None or isinstance(key, (str, bool, int)):
        raise TypeError("key must be 32 or 64 bytes, not %s" % (type(key).__name__,))
    if isinstance(key, (bytes, bytearray, memoryview)):
        return memoryview(key).tobytes()
    raise TypeError("key must be 32 or 64 bytes, not %s" % (type(key).__name__,))


def _hkdf_sha512(ikm: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA512 (RFC 5869) with the default salt (HashLen zero bytes)."""
    hash_len = 64
    salt = b"\x00" * hash_len
    prk = hmac.new(salt, ikm, hashlib.sha512).digest()
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        if counter > 255:
            raise ValueError("HKDF output too long")
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha512).digest()
        okm += t
        counter += 1
    return okm[:length]


def expand_key(key) -> bytes:
    """Expand a 32- or 64-byte app key into a 128-byte Octavo seed.

    Uses HKDF-SHA512 with info APP_KEY_INFO (b'Octavo app key v1') and
    the RFC 5869 default salt (64 zero bytes). Rejects other lengths,
    str, None, and an all-zero key. Does not write the key or the seed
    to disk.
    """
    raw = _as_key_bytes(key)
    if len(raw) not in APP_KEY_LENS:
        raise ValueError("key must be 32 or 64 bytes, not %d" % len(raw))
    if raw == b"\x00" * len(raw):
        raise ValueError("all-zero key is rejected")
    return _hkdf_sha512(raw, APP_KEY_INFO, APP_SEED_LEN)


def generate_key() -> bytes:
    """Return a fresh 32-byte app key from secrets.token_bytes.

    Never written to disk. Pass the result to seal() / open_(), or use
    a 32-byte shared secret from a libsodium X25519 key exchange
    (crypto_kx) instead.
    """
    key = secrets.token_bytes(32)
    if type(key) is not bytes or len(key) != 32:
        raise RuntimeError("secrets.token_bytes(32) did not return 32 bytes")
    if key == b"\x00" * 32:
        raise RuntimeError("secrets.token_bytes(32) returned an all-zero key")
    return key


def seal(key, message, ad=b"") -> bytes:
    """Encrypt message under key and return a v6 Octavo blob.

    key must be 32 or 64 bytes (see expand_key). message and ad are
    bytes-like; ad is authenticated and is not stored in the blob.
    Always uses the current v6 single-message format. Legacy modes are
    not available through this function. Raises sneak_n2's Rejected
    family only for a bad or foreign blob on the open path; caller
    mistakes here are TypeError or ValueError.
    """
    _emit_demo_warning()
    seed = expand_key(key)
    return _n2.encrypt(message, seed, ad=ad)


def open_(key, blob, ad=b"") -> bytes:
    """Decrypt a v6 Octavo blob under key and return the message.

    The same key and associated data supplied to seal() must be
    supplied here. Non-v6 blobs raise UnsupportedVersion. Authentication
    failures raise AuthError with a short, non-leaking message.
    """
    _emit_demo_warning()
    seed = expand_key(key)
    return _n2.decrypt(blob, seed, ad=ad)


# Exposed inside this module's namespace. Prefer open_ at call sites so
# the builtin open() is not shadowed: ``from octavo import open_``.
open = open_


def _package_root() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def _read_json(path):
    with _fopen(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _sha256_file(path) -> str:
    with _fopen(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _require_file(path, label):
    if not os.path.isfile(path):
        raise RuntimeError("verify_install: missing %s (%s)" % (label, path))
    return path


def verify_install(root=None) -> dict:
    """Check published file SHAs and the package's key-expansion vectors.

    Compares sha256 of sneak_n2.py, etudes.py and score/generate_score.py
    with the values in score/vectors.json, then recomputes every key
    expansion in score/app_vectors.json. Returns a dict of the checked
    SHAs on success. Raises RuntimeError on any mismatch or missing
    file.

    This catches mistakes and honest drift (a file that does not match
    the published score, a broken key-expansion helper). It is not a
    tamper guard: whoever can edit the tree can also edit the score or
    this helper. Compare the published values with a copy you trust.
    The import-time self-checks in sneak_n2.py are left unchanged; this
    function does not skip them and does not import a copy of
    sneak_n2.py from *root*.

    root defaults to the directory containing this module (the repo
    folder, or site-packages after ``pip install``).
    """
    if root is None:
        root = _package_root()
    root = os.path.abspath(root)
    sneak = _require_file(os.path.join(root, "sneak_n2.py"), "sneak_n2.py")
    etudes = _require_file(os.path.join(root, "etudes.py"), "etudes.py")
    score_dir = os.path.join(root, "score")
    vectors_path = _require_file(os.path.join(score_dir, "vectors.json"), "score/vectors.json")
    gen_path = _require_file(os.path.join(score_dir, "generate_score.py"),
                             "score/generate_score.py")
    app_path = _require_file(os.path.join(score_dir, APP_VECTORS_NAME),
                             "score/" + APP_VECTORS_NAME)

    published = _read_json(vectors_path)
    checked = (
        ("sneak_n2_sha256", sneak, "sneak_n2.py"),
        ("etudes_sha256", etudes, "etudes.py"),
        ("generate_score_sha256", gen_path, "score/generate_score.py"),
    )
    actuals = {}
    errors = []
    for key, path, label in checked:
        actual = _sha256_file(path)
        actuals[key] = actual
        want = published.get(key)
        if want is None:
            errors.append("%s is not in the published score (computed SHA-256 %s)" % (label, actual))
        elif actual != want:
            errors.append("%s SHA-256 does not match the published score (computed %s, published %s)"
                          % (label, actual, want))

    app = _read_json(app_path)
    if app.get("kdf", {}).get("info") != APP_KEY_INFO.decode("ascii"):
        errors.append("score/%s kdf.info does not match APP_KEY_INFO" % APP_VECTORS_NAME)
    for entry in app.get("keys", []):
        ident = entry.get("id", "?")
        try:
            seed = expand_key(bytes.fromhex(entry["key"]))
        except (KeyError, ValueError, TypeError) as e:
            errors.append("key-expansion vector %s could not be expanded: %s" % (ident, e))
            continue
        want_seed = entry.get("seed")
        if seed.hex() != want_seed:
            errors.append("key-expansion vector %s does not match (computed seed %s)"
                          % (ident, seed.hex()))

    if errors:
        raise RuntimeError("verify_install failed: " + "; ".join(errors))
    return actuals
