#!/usr/bin/env python3
"""Octavo playground: a local, 127.0.0.1-only demo of N2, N3, and vetted AEAD.

Octavo is homemade and experimental — for real secrets use AES-GCM-SIV, age, or libsodium.

This server never writes keys to disk automatically. Temporary key files used to
call the official CLIs are created mode 0600 in a private directory and deleted
before the request returns. Bind address is localhost only.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import traceback
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "n3" / "python"))

import octavo  # noqa: E402
import sneak_n2 as n2  # noqa: E402
import n3_music  # noqa: E402

STATIC_DIR = HERE / "static"

# Official build commands (from the repository root).
OCTAVO_BUILD_CMD = "cargo build --release -p octavo-cli --manifest-path rust/Cargo.toml"
N3_BUILD_CMD = "cargo build --release --bin n3aead --manifest-path n3/rust/Cargo.toml"
OCTAVO_EXPECTED = "rust/target/release/octavo"
N3_EXPECTED = "n3/rust/target/release/n3aead"


def _resolve_cli(env_name: str, repo_rel: str, which_name: str) -> Optional[Path]:
    """Resolve a CLI: env override, then the repo release path, then PATH.

    If the env var is set, it wins (and a bad path means "not available").
    """
    raw = os.environ.get(env_name)
    if raw:
        p = Path(raw).expanduser()
        if p.is_file() and os.access(p, os.X_OK):
            return p
        return None
    p = REPO_ROOT / repo_rel
    if p.is_file() and os.access(p, os.X_OK):
        return p
    found = shutil.which(which_name)
    return Path(found) if found else None


def _cli_help(kind: str) -> str:
    if kind == "octavo":
        return (
            "The octavo CLI is not built yet. From the repository root run: "
            f"{OCTAVO_BUILD_CMD}. Expected at {OCTAVO_EXPECTED} "
            "(or set OCTAVO_BIN to the binary)."
        )
    return (
        "The n3aead CLI is not built yet. From the repository root run: "
        f"{N3_BUILD_CMD}. Expected at {N3_EXPECTED} "
        "(or set OCTAVO_N3AEAD_BIN to the binary)."
    )


OCTAVO_BIN = _resolve_cli("OCTAVO_BIN", OCTAVO_EXPECTED, "octavo")
N3_BIN = _resolve_cli("OCTAVO_N3AEAD_BIN", N3_EXPECTED, "n3aead")

# Repo-root images only (fixed allowlist; never serve arbitrary paths).
REPO_ASSETS = {
    "/logo.png": REPO_ROOT / "logo.png",
    "/static/logo.png": REPO_ROOT / "logo.png",
    "/sneak-staff-n2.png": REPO_ROOT / "sneak-staff-n2.png",
    "/static/sneak-staff-n2.png": REPO_ROOT / "sneak-staff-n2.png",
}

HONEST = (
    "Octavo is homemade and experimental — for real secrets use "
    "AES-GCM-SIV, age, or libsodium."
)

N2_APP_LENS = (32, 64)
SEED_LEN = 128
N3_NONCE_LEN = 16
N3_TAG_LEN = 32
N3_HEADER = b"SN3C/"
N3_FORMAT = 0x1C
N3_OVERHEAD = 54  # 5 + 1 + 16 + 32
VETTED_MAGIC = b"VGCM"
VETTED_NONCE_LEN = 12
VETTED_TAG_LEN = 16
VETTED_OVERHEAD = 4 + 12 + 16  # magic + nonce + tag (tag lives at end of ciphertext)
# File-tab vetted envelope (distinct from the text-tab VGCM wrapper).
SIV1_MAGIC = b"SIV1"
SIV1_OVERHEAD = 4 + 12 + 16  # SIV1 || nonce(12) || tag(16)
MAX_BODY = 2 * 1024 * 1024
MAX_PLAYGROUND_MSG = 1 * 1024 * 1024
MAX_FILE = 8 * 1024 * 1024
# 8 MiB file as base64 is ~11 MiB, plus JSON wrapping.
MAX_FILE_REQUEST = 12 * 1024 * 1024
N3_BACKENDS_ALL = ("avx512gfni", "avx2gfni", "avx2", "portable")
# `table` is a non-constant-time test path and is never auto-selected.
SUBPROCESS_TIMEOUT = 30
HEAR_TIMEOUT = 45

# ---------------------------------------------------------------------------
# Optional vetted cipher (real AES-GCM-SIV only; never faked)
# ---------------------------------------------------------------------------

AESGCMSIV = None
CRYPTO_VERSION = None
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV as _AESGCMSIV
    import cryptography as _crypto

    # Probe that AES-GCM-SIV actually works on this box.
    _k = _AESGCMSIV.generate_key(256)
    _c = _AESGCMSIV(_k)
    _n = b"\x00" * 12
    _ct = _c.encrypt(_n, b"probe", b"ad")
    assert _c.decrypt(_n, _ct, b"ad") == b"probe"
    AESGCMSIV = _AESGCMSIV
    CRYPTO_VERSION = getattr(_crypto, "__version__", "unknown")
except Exception:
    AESGCMSIV = None
    CRYPTO_VERSION = None

AGE_BIN = shutil.which("age")


class AppError(Exception):
    """User-facing error with an HTTP status."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _cpu_flags() -> set[str]:
    flags: set[str] = set()
    try:
        text = Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return flags
    for line in text.splitlines():
        if line.lower().startswith("flags") or line.lower().startswith("features"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                flags.update(parts[1].split())
    return flags


def detect_n3_backends() -> dict[str, Any]:
    flags = _cpu_flags()
    has_avx512 = "avx512f" in flags or "avx512vbmi" in flags or "avx512bw" in flags
    has_gfni = "gfni" in flags
    has_avx2 = "avx2" in flags
    available = ["portable"]
    if has_avx2:
        available.insert(0, "avx2")
    if has_avx2 and has_gfni:
        available.insert(0, "avx2gfni")
    if has_avx512 and has_gfni:
        available.insert(0, "avx512gfni")
    # Preserve advertised order, unique, portable last if somehow missing.
    ordered = [b for b in N3_BACKENDS_ALL if b in available]
    default = ordered[0] if ordered else "portable"
    return {
        "available": ordered,
        "default": default,
        "override_env": "OCTAVO_N3_BACKEND",
        "table_note": "table is a non-constant-time test path and is never auto-selected",
    }


def octavo_cli_version() -> str:
    if OCTAVO_BIN is None or not Path(OCTAVO_BIN).is_file():
        return "missing"
    try:
        r = subprocess.run(
            [str(OCTAVO_BIN), "--version"],
            capture_output=True,
            timeout=5,
            text=True,
        )
        out = (r.stdout or r.stderr or "").strip().splitlines()
        # Skip the honest-warning line if present.
        for line in out:
            line = line.strip()
            if line and "homemade" not in line.lower() and "WARNING" not in line:
                return line
        return out[0] if out else "unknown"
    except Exception:
        return "unknown"


N3_BACKEND_INFO = detect_n3_backends()
OCTAVO_VERSION = octavo_cli_version()


def _unhex(s: str, *, name: str) -> bytes:
    if s is None:
        raise AppError(f"{name} is missing")
    raw = "".join(str(s).split())
    if raw.startswith("0x") or raw.startswith("0X"):
        raw = raw[2:]
    if not raw:
        raise AppError(f"{name} is empty")
    if len(raw) % 2 != 0:
        raise AppError(f"{name} has an odd number of hex digits")
    try:
        return bytes.fromhex(raw)
    except ValueError:
        raise AppError(f"{name} is not valid hex") from None


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _is_all_zero(b: bytes) -> bool:
    return len(b) > 0 and set(b) == {0}



def _field(obj: dict, *names: str):
    """Return (present, value) for the first named key that was supplied (even if empty)."""
    for name in names:
        if name in obj and obj[name] is not None:
            return True, obj[name]
    return False, None


def require_key(data: bytes, allowed_lens: tuple[int, ...], name: str) -> bytes:
    if not data:
        raise AppError(f"{name} is empty")
    if len(data) not in allowed_lens:
        want = " or ".join(f"{n} bytes ({n * 2} hex digits)" for n in allowed_lens)
        raise AppError(f"{name} is the wrong length: got {len(data)} bytes, expected {want}")
    if _is_all_zero(data):
        raise AppError(f"all-zero {name} is rejected")
    return data


def fresh_n2_seed() -> bytes:
    """CSPRNG 128-byte seed that also passes N2's weak-seed policy when possible."""
    last_err: Optional[Exception] = None
    for _ in range(32):
        seed = secrets.token_bytes(SEED_LEN)
        if _is_all_zero(seed):
            continue
        try:
            n2._seed_bytes(seed)
            return seed
        except Exception as e:  # policy reject; try again
            last_err = e
            continue
    if last_err:
        raise AppError(f"could not generate a policy-passing N2 seed: {last_err}", 500)
    raise AppError("could not generate an N2 seed", 500)


def fresh_n3_seed() -> bytes:
    for _ in range(8):
        seed = secrets.token_bytes(SEED_LEN)
        if not _is_all_zero(seed):
            return seed
    raise AppError("could not generate an N3 seed", 500)


def fresh_app_key() -> bytes:
    return octavo.generate_key()


def decode_payload(obj: dict, field: str = "plaintext", *, optional: bool = False) -> bytes:
    """Read bytes from plaintext / plaintext_hex / plaintext_b64 (or ad*)."""
    hex_key = field + "_hex"
    b64_key = field + "_b64"
    if hex_key in obj and obj[hex_key] is not None and obj[hex_key] != "":
        return _unhex(str(obj[hex_key]), name=hex_key)
    if b64_key in obj and obj[b64_key] is not None and obj[b64_key] != "":
        try:
            return base64.b64decode(str(obj[b64_key]), validate=True)
        except Exception:
            raise AppError(f"{b64_key} is not valid base64") from None
    if field in obj and obj[field] is not None:
        val = obj[field]
        if isinstance(val, (bytes, bytearray)):
            return bytes(val)
        return str(val).encode("utf-8")
    if optional:
        return b""
    raise AppError(f"{field} is missing")


def cap_msg(data: bytes, *, name: str = "plaintext") -> bytes:
    if len(data) > MAX_PLAYGROUND_MSG:
        raise AppError(f"{name} is too long for this playground (max {MAX_PLAYGROUND_MSG} bytes)")
    return data


# ---------------------------------------------------------------------------
# Header breakdowns
# ---------------------------------------------------------------------------

def _section(name: str, offset: int, data: bytes, *, text: Optional[str] = None) -> dict[str, Any]:
    item = {
        "name": name,
        "offset": offset,
        "length": len(data),
        "value_hex": data.hex(),
    }
    if text is not None:
        item["value_text"] = text
    return item


def parse_n2_blob(blob: bytes) -> dict[str, Any]:
    if not blob:
        raise AppError("blob is empty")
    version = blob[0]
    magic = blob[1:4] if len(blob) >= 4 else blob[1:]
    magic_txt = ""
    try:
        magic_txt = magic.decode("ascii")
    except Exception:
        magic_txt = ""

    if version == 6 and len(blob) >= 4 and magic == b"SN2":
        # version(1) || SN2(3) || pickup(16) || nonce(16) || commit(32) || ct(128) || tag(32)
        if len(blob) != n2.BLOB_LEN:
            # Still try to label what we can, but flag the length.
            pass
        need = n2.BLOB_LEN
        if len(blob) < 68:
            raise AppError(f"N2 v6 blob is too short ({len(blob)} bytes)")
        pickup = blob[4:20]
        nonce = blob[20:36]
        commit = blob[36:68]
        # Remainder: ciphertext || tag(32) if long enough
        if len(blob) >= 100:
            ct = blob[68:-32]
            tag = blob[-32:]
        else:
            ct = blob[68:]
            tag = b""
        sections = [
            _section("version", 0, blob[0:1], text="6"),
            _section("magic", 1, blob[1:4], text="SN2"),
            _section("pickup", 4, pickup),
            _section("nonce", 20, nonce),
            _section("commit", 36, commit),
            _section("ciphertext", 68, ct),
        ]
        if tag:
            sections.append(_section("tag", 68 + len(ct), tag))
        return {
            "engine": "n2",
            "format": "v6",
            "version": 6,
            "magic": "SN2",
            "overhead": 100,  # 228 - 128; v6 always pads to one 128-byte block
            "ciphertext_length": len(ct),
            "total_length": len(blob),
            "expected_length": need,
            "sections": sections,
        }

    if version == 9 and len(blob) >= 4 and magic == b"SN2":
        # version(1) || SN2(3) || pickup(16) || nonce(16) || commit(32) || chunk_size(4) || body
        if len(blob) < 76:
            raise AppError(f"N2 v9 blob is too short ({len(blob)} bytes)")
        pickup = blob[4:20]
        nonce = blob[20:36]
        commit = blob[36:68]
        chunk_size = blob[68:72]
        body = blob[72:]
        # Last 32 bytes of the stream are the final chunk tag.
        tag = body[-32:] if len(body) >= 32 else b""
        ct = body[:-32] if len(body) >= 32 else body
        cs_int = int.from_bytes(chunk_size, "big")
        sections = [
            _section("version", 0, blob[0:1], text="9"),
            _section("magic", 1, blob[1:4], text="SN2"),
            _section("pickup", 4, pickup),
            _section("nonce", 20, nonce),
            _section("commit", 36, commit),
            _section("chunk_size", 68, chunk_size, text=str(cs_int)),
            _section("ciphertext", 72, ct),
        ]
        if tag:
            sections.append(_section("tag", 72 + len(ct), tag))
        return {
            "engine": "n2",
            "format": "v9",
            "version": 9,
            "magic": "SN2",
            "overhead": 72 + 32,  # header + at least one 32-byte tag (more tags if multi-chunk)
            "ciphertext_length": len(ct),
            "total_length": len(blob),
            "chunk_size": cs_int,
            "sections": sections,
        }

    return {
        "engine": "n2",
        "format": "unknown",
        "version": version,
        "magic": magic_txt or magic.hex(),
        "overhead": None,
        "ciphertext_length": None,
        "total_length": len(blob),
        "sections": [
            _section("version", 0, blob[0:1], text=str(version)),
            _section("rest", 1, blob[1:]),
        ],
        "note": "unrecognised N2 blob layout",
    }


def parse_n3_blob(blob: bytes) -> dict[str, Any]:
    if len(blob) < N3_OVERHEAD:
        raise AppError(f"N3 blob is too short ({len(blob)} bytes, need at least {N3_OVERHEAD})")
    magic = blob[:5]
    fmt = blob[5]
    nonce = blob[6:22]
    tag = blob[22:54]
    ct = blob[54:]
    if magic != N3_HEADER:
        raise AppError("N3 blob does not start with SN3C/")
    if fmt != N3_FORMAT:
        raise AppError(f"N3 blob format byte is 0x{fmt:02X}, expected 0x1C")
    return {
        "engine": "n3",
        "format": "0x1C",
        "version": fmt,
        "magic": "SN3C/",
        "overhead": N3_OVERHEAD,
        "ciphertext_length": len(ct),
        "total_length": len(blob),
        "sections": [
            _section("header", 0, blob[:6], text="SN3C/ + 0x1C"),
            _section("nonce", 6, nonce),
            _section("tag", 22, tag),
            _section("ciphertext", 54, ct),
        ],
    }


def parse_vetted_blob(blob: bytes) -> dict[str, Any]:
    if len(blob) < 4 + VETTED_NONCE_LEN + VETTED_TAG_LEN:
        raise AppError(f"vetted blob is too short ({len(blob)} bytes)")
    if blob[:4] != VETTED_MAGIC:
        raise AppError("vetted blob does not start with VGCM")
    nonce = blob[4:16]
    body = blob[16:]  # ciphertext || tag(16)
    if len(body) < VETTED_TAG_LEN:
        raise AppError("vetted blob is missing its tag")
    ct, tag = body[:-16], body[-16:]
    return {
        "engine": "vetted",
        "format": "AES-GCM-SIV",
        "version": None,
        "magic": "VGCM",
        "overhead": 4 + 12 + 16,
        "ciphertext_length": len(ct),
        "total_length": len(blob),
        "sections": [
            _section("header", 0, blob[:4], text="VGCM"),
            _section("nonce", 4, nonce),
            _section("ciphertext", 16, ct),
            _section("tag", 16 + len(ct), tag),
        ],
    }



def parse_siv1_blob(blob: bytes) -> dict[str, Any]:
    if len(blob) < SIV1_OVERHEAD:
        raise AppError(f"SIV1 blob is too short ({len(blob)} bytes)")
    if blob[:4] != SIV1_MAGIC:
        raise AppError("vetted file does not start with SIV1")
    nonce = blob[4:16]
    body = blob[16:]
    if len(body) < VETTED_TAG_LEN:
        raise AppError("SIV1 blob is missing its tag")
    ct, tag = body[:-16], body[-16:]
    return {
        "engine": "vetted",
        "format": "AES-GCM-SIV (SIV1 file envelope)",
        "version": None,
        "magic": "SIV1",
        "overhead": SIV1_OVERHEAD,
        "ciphertext_length": len(ct),
        "total_length": len(blob),
        "sections": [
            _section("header", 0, blob[:4], text="SIV1"),
            _section("nonce", 4, nonce),
            _section("ciphertext", 16, ct),
            _section("tag", 16 + len(ct), tag),
        ],
    }


def parse_blob_auto(blob: bytes) -> dict[str, Any]:
    if blob.startswith(N3_HEADER):
        return parse_n3_blob(blob)
    if blob.startswith(VETTED_MAGIC):
        return parse_vetted_blob(blob)
    if blob.startswith(SIV1_MAGIC):
        return parse_siv1_blob(blob)
    if len(blob) >= 4 and blob[1:4] == b"SN2":
        return parse_n2_blob(blob)
    raise AppError("unrecognised blob (expected SN2, SN3C/, or VGCM)")


def envelope(blob: bytes, header: dict[str, Any], **extra: Any) -> dict[str, Any]:
    out = {
        "ok": True,
        "warning": HONEST,
        "blob_hex": blob.hex(),
        "blob_b64": _b64(blob),
        "header": header,
    }
    out.update(extra)
    return out


# ---------------------------------------------------------------------------
# Engines
# ---------------------------------------------------------------------------

def n2_seal(obj: dict) -> dict[str, Any]:
    msg = cap_msg(decode_payload(obj, "plaintext"))
    ad = cap_msg(decode_payload(obj, "ad", optional=True), name="ad")
    has_key, key_raw = _field(obj, "key_hex", "key")
    has_seed, seed_raw = _field(obj, "seed_hex", "seed")

    if has_key:
        if key_raw == "":
            raise AppError("N2 app key is empty")
        key = require_key(_unhex(str(key_raw), name="key"), N2_APP_LENS, "N2 app key")
        if len(msg) > n2.MAX_MSG:
            # Auto-upgrade to the v9 rehearsal stream using the expanded seed,
            # so longer playground messages still work.
            seed = octavo.expand_key(key)
            blob = _n2_cli_seal(seed, msg, ad)
            header = parse_n2_blob(blob)
            return envelope(blob, header, engine="n2", used="octavo v9 (app key expanded; message > 127 bytes)")
        try:
            blob = octavo.seal(key, msg, ad)
        except (ValueError, TypeError) as e:
            raise AppError(str(e)) from e
        except n2.Rejected as e:
            raise AppError(str(e) or "rejected") from e
        header = parse_n2_blob(blob)
        return envelope(blob, header, engine="n2", used="octavo.py v6")

    if has_seed:
        if seed_raw == "":
            raise AppError("N2 seed is empty")
        seed = require_key(_unhex(str(seed_raw), name="seed"), (SEED_LEN,), "N2 seed")
        try:
            n2._seed_bytes(seed)
        except Exception as e:
            raise AppError(f"N2 seed rejected: {e}") from e
        blob = _n2_cli_seal(seed, msg, ad)
        header = parse_n2_blob(blob)
        return envelope(blob, header, engine="n2", used="octavo CLI v9")

    raise AppError("N2 seal needs a 32- or 64-byte app key, or a 128-byte seed")


def n2_open(obj: dict) -> dict[str, Any]:
    blob = _blob_from(obj)
    ad = cap_msg(decode_payload(obj, "ad", optional=True), name="ad")
    has_key, key_raw = _field(obj, "key_hex", "key")
    has_seed, seed_raw = _field(obj, "seed_hex", "seed")

    if has_key:
        if key_raw == "":
            raise AppError("N2 app key is empty")
        key = require_key(_unhex(str(key_raw), name="key"), N2_APP_LENS, "N2 app key")
        # v6 first; if the blob is v9, expand and use the CLI.
        if blob and blob[0] == 9:
            seed = octavo.expand_key(key)
            pt = _n2_cli_open(seed, blob, ad)
            return {
                "ok": True,
                "warning": HONEST,
                "engine": "n2",
                "used": "octavo CLI v9 (app key expanded)",
                "plaintext": _safe_text(pt),
                "plaintext_hex": pt.hex(),
                "plaintext_b64": _b64(pt),
                "header": parse_n2_blob(blob),
            }
        try:
            pt = octavo.open_(key, blob, ad)
        except n2.AuthError as e:
            raise AppError(str(e) or "authentication failed") from e
        except n2.UnsupportedVersion as e:
            raise AppError(str(e) or "unsupported version") from e
        except n2.Rejected as e:
            raise AppError(str(e) or "rejected") from e
        except (ValueError, TypeError) as e:
            raise AppError(str(e)) from e
        return {
            "ok": True,
            "warning": HONEST,
            "engine": "n2",
            "used": "octavo.py v6",
            "plaintext": _safe_text(pt),
            "plaintext_hex": pt.hex(),
            "plaintext_b64": _b64(pt),
            "header": parse_n2_blob(blob),
        }

    if has_seed:
        if seed_raw == "":
            raise AppError("N2 seed is empty")
        seed = require_key(_unhex(str(seed_raw), name="seed"), (SEED_LEN,), "N2 seed")
        pt = _n2_cli_open(seed, blob, ad)
        return {
            "ok": True,
            "warning": HONEST,
            "engine": "n2",
            "used": "octavo CLI v9",
            "plaintext": _safe_text(pt),
            "plaintext_hex": pt.hex(),
            "plaintext_b64": _b64(pt),
            "header": parse_n2_blob(blob),
        }

    raise AppError("N2 open needs a 32- or 64-byte app key, or a 128-byte seed")


@contextmanager
def _temp_key_file(seed: bytes):
    """Write a 0600 hex seed file for the official CLI, then delete it."""
    if OCTAVO_BIN is None or not Path(OCTAVO_BIN).is_file():
        raise AppError(_cli_help("octavo"), 503)
    d = tempfile.mkdtemp(prefix="octavo_app_", dir="/tmp")
    path = os.path.join(d, "key")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, seed.hex().encode("ascii") + b"\n")
        os.close(fd)
        fd = -1
        yield path, d
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        # Best-effort cleanup of everything we created.
        try:
            for name in os.listdir(d):
                try:
                    os.remove(os.path.join(d, name))
                except OSError:
                    pass
            os.rmdir(d)
        except OSError:
            pass


def _n2_cli_seal(seed: bytes, msg: bytes, ad: bytes) -> bytes:
    with _temp_key_file(seed) as (key_path, _d):
        cmd = [str(OCTAVO_BIN), "seal", "--key", key_path, "-o", "-", "-"]
        if ad:
            cmd.extend(["--ad-hex", ad.hex()])
        r = subprocess.run(
            cmd,
            input=msg,
            capture_output=True,
            timeout=SUBPROCESS_TIMEOUT,
        )
    if r.returncode != 0:
        err = _cli_err(r)
        raise AppError(err or "N2 CLI seal failed")
    return r.stdout


def _n2_cli_open(seed: bytes, blob: bytes, ad: bytes) -> bytes:
    with _temp_key_file(seed) as (key_path, _d):
        cmd = [str(OCTAVO_BIN), "open", "--key", key_path, "-o", "-", "-"]
        if ad:
            cmd.extend(["--ad-hex", ad.hex()])
        r = subprocess.run(
            cmd,
            input=blob,
            capture_output=True,
            timeout=SUBPROCESS_TIMEOUT,
        )
    if r.returncode != 0:
        err = _cli_err(r)
        # Normalise auth failures so the UI can show a short phrase.
        low = err.lower()
        if "auth" in low or "failed" in low or "reject" in low or "verify" in low:
            raise AppError("authentication failed")
        raise AppError(err or "N2 CLI open failed")
    return r.stdout


def _cli_err(r: subprocess.CompletedProcess) -> str:
    text = (r.stderr or r.stdout or b"").decode("utf-8", errors="replace").strip()
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    # Drop the honest-warning prefix so the actual reason is visible.
    kept = [
        ln
        for ln in lines
        if not ln.startswith("WARNING:")
        and "homemade" not in ln.lower()
        and "libsodium" not in ln.lower()
    ]
    msg = " ".join(kept) or " ".join(lines)
    # Never echo a key if a path leaked; keep it short.
    if len(msg) > 400:
        msg = msg[:400] + "…"
    return msg


def n3_seal(obj: dict) -> dict[str, Any]:
    if N3_BIN is None or not Path(N3_BIN).is_file():
        raise AppError(_cli_help("n3"), 503)
    msg = cap_msg(decode_payload(obj, "plaintext"))
    ad = cap_msg(decode_payload(obj, "ad", optional=True), name="ad")
    seed_raw = obj.get("seed_hex") or obj.get("seed") or obj.get("key_hex") or obj.get("key")
    if not seed_raw:
        raise AppError("N3 seal needs a 128-byte seed")
    seed = require_key(_unhex(str(seed_raw), name="seed"), (SEED_LEN,), "N3 seed")
    if obj.get("nonce") or obj.get("nonce_hex"):
        nonce = _unhex(str(obj.get("nonce_hex") or obj.get("nonce")), name="nonce")
        if len(nonce) != N3_NONCE_LEN:
            raise AppError(f"N3 nonce must be {N3_NONCE_LEN} bytes (got {len(nonce)})")
    else:
        nonce = secrets.token_bytes(N3_NONCE_LEN)
    backend = (obj.get("backend") or "").strip() or None
    blob = _n3_run(["seal", seed.hex(), nonce.hex(), ad.hex() if ad else "-"], stdin=msg, backend=backend)
    header = parse_n3_blob(blob)
    return envelope(blob, header, engine="n3", used="n3aead 0x1C", backend=backend or "auto")


def n3_open(obj: dict) -> dict[str, Any]:
    if N3_BIN is None or not Path(N3_BIN).is_file():
        raise AppError(_cli_help("n3"), 503)
    blob = _blob_from(obj)
    ad = cap_msg(decode_payload(obj, "ad", optional=True), name="ad")
    seed_raw = obj.get("seed_hex") or obj.get("seed") or obj.get("key_hex") or obj.get("key")
    if not seed_raw:
        raise AppError("N3 open needs a 128-byte seed")
    seed = require_key(_unhex(str(seed_raw), name="seed"), (SEED_LEN,), "N3 seed")
    backend = (obj.get("backend") or "").strip() or None
    try:
        # Even if the blob is foreign, let n3aead reject it (for the cross-open demo).
        pt = _n3_run(["open", seed.hex(), ad.hex() if ad else "-"], stdin=blob, backend=backend)
    except AppError:
        raise
    return {
        "ok": True,
        "warning": HONEST,
        "engine": "n3",
        "used": "n3aead 0x1C",
        "backend": backend or "auto",
        "plaintext": _safe_text(pt),
        "plaintext_hex": pt.hex(),
        "plaintext_b64": _b64(pt),
        "header": parse_n3_blob(blob) if blob.startswith(N3_HEADER) else {"total_length": len(blob)},
    }


def _n3_run(args: list[str], *, stdin: bytes, backend: Optional[str]) -> bytes:
    if backend and backend not in N3_BACKENDS_ALL and backend != "table":
        raise AppError(f"unknown N3 backend {backend!r} (try {', '.join(N3_BACKENDS_ALL)})")
    env = os.environ.copy()
    if backend:
        env["OCTAVO_N3_BACKEND"] = backend
    r = subprocess.run(
        [str(N3_BIN), *args],
        input=stdin,
        capture_output=True,
        timeout=SUBPROCESS_TIMEOUT,
        env=env,
    )
    if r.returncode != 0:
        err = _cli_err(r)
        low = err.lower()
        if any(k in low for k in ("tag", "auth", "reject", "mismatch", "bad prefix", "bad format", "too short")):
            # Keep the CLI's short reason when it is already clear.
            if err.startswith("n3aead:"):
                err = err[len("n3aead:") :].strip()
            raise AppError(err or "authentication failed")
        if err.startswith("n3aead:"):
            err = err[len("n3aead:") :].strip()
        raise AppError(err or "n3aead failed")
    return r.stdout


def vetted_available() -> dict[str, Any]:
    return {
        "live": AESGCMSIV is not None,
        "aes_gcm_siv": AESGCMSIV is not None,
        "cryptography": CRYPTO_VERSION,
        "age": bool(AGE_BIN),
        "age_path": AGE_BIN,
        "note": (
            "AES-GCM-SIV is available via the Python cryptography library."
            if AESGCMSIV is not None
            else "AES-GCM-SIV is not available on this box."
        )
        + (" age is not installed." if not AGE_BIN else f" age is at {AGE_BIN}."),
    }


def vetted_seal(obj: dict) -> dict[str, Any]:
    if AESGCMSIV is None:
        raise AppError("vetted mode is not available (cryptography AES-GCM-SIV is not installed)", 501)
    msg = cap_msg(decode_payload(obj, "plaintext"))
    ad = cap_msg(decode_payload(obj, "ad", optional=True), name="ad")
    key_raw = obj.get("key_hex") or obj.get("key") or obj.get("seed_hex") or obj.get("seed")
    if not key_raw:
        raise AppError("vetted seal needs a 32-byte AES-GCM-SIV key")
    key = require_key(_unhex(str(key_raw), name="key"), (32,), "vetted key")
    nonce = secrets.token_bytes(VETTED_NONCE_LEN)
    try:
        body = AESGCMSIV(key).encrypt(nonce, msg, ad)
    except Exception as e:
        raise AppError(f"AES-GCM-SIV seal failed: {e}") from e
    blob = VETTED_MAGIC + nonce + body
    return envelope(blob, parse_vetted_blob(blob), engine="vetted", used="cryptography AES-GCM-SIV")


def vetted_open(obj: dict) -> dict[str, Any]:
    if AESGCMSIV is None:
        raise AppError("vetted mode is not available (cryptography AES-GCM-SIV is not installed)", 501)
    blob = _blob_from(obj)
    ad = cap_msg(decode_payload(obj, "ad", optional=True), name="ad")
    key_raw = obj.get("key_hex") or obj.get("key") or obj.get("seed_hex") or obj.get("seed")
    if not key_raw:
        raise AppError("vetted open needs a 32-byte AES-GCM-SIV key")
    key = require_key(_unhex(str(key_raw), name="key"), (32,), "vetted key")
    if not blob.startswith(VETTED_MAGIC) or len(blob) < 4 + VETTED_NONCE_LEN + VETTED_TAG_LEN:
        raise AppError("vetted open rejected this blob (expected a VGCM AES-GCM-SIV envelope)")
    nonce = blob[4:16]
    body = blob[16:]
    try:
        pt = AESGCMSIV(key).decrypt(nonce, body, ad)
    except Exception:
        raise AppError("authentication failed") from None
    return {
        "ok": True,
        "warning": HONEST,
        "engine": "vetted",
        "used": "cryptography AES-GCM-SIV",
        "plaintext": _safe_text(pt),
        "plaintext_hex": pt.hex(),
        "plaintext_b64": _b64(pt),
        "header": parse_vetted_blob(blob),
    }


def _blob_from(obj: dict) -> bytes:
    if obj.get("blob_hex") or (obj.get("hex") and "target" not in obj and "bit_index" not in obj):
        raw = obj.get("blob_hex") or obj.get("hex")
        return cap_msg(_unhex(str(raw), name="blob_hex"), name="blob")
    if obj.get("blob_b64"):
        try:
            data = base64.b64decode(str(obj["blob_b64"]), validate=True)
        except Exception:
            raise AppError("blob_b64 is not valid base64") from None
        return cap_msg(data, name="blob")
    if obj.get("blob"):
        # Allow raw hex in `blob` as well.
        s = str(obj["blob"]).strip()
        try:
            return cap_msg(_unhex(s, name="blob"), name="blob")
        except AppError:
            try:
                return cap_msg(base64.b64decode(s, validate=True), name="blob")
            except Exception:
                raise AppError("blob is not valid hex or base64") from None
    raise AppError("blob_hex or blob_b64 is missing")


def _safe_text(data: bytes) -> Optional[str]:
    try:
        t = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    # Keep control characters out of the JSON text field (hex is always there).
    if any(ord(ch) < 32 and ch not in "\n\r\t" for ch in t):
        return None
    return t


# ---------------------------------------------------------------------------
# Flip / hear / info / keygen
# ---------------------------------------------------------------------------

def flip_blob(obj: dict) -> dict[str, Any]:
    if obj.get("blob_hex") or obj.get("hex") or obj.get("blob") or obj.get("blob_b64"):
        # Reuse blob reader; `hex` is also accepted as an alias.
        if "blob_hex" not in obj and "hex" in obj:
            obj = dict(obj)
            obj["blob_hex"] = obj["hex"]
        blob = bytearray(_blob_from(obj))
    else:
        raise AppError("blob_hex is missing")
    if not blob:
        raise AppError("blob is empty")

    header: Optional[dict[str, Any]] = None
    try:
        header = parse_blob_auto(bytes(blob))
    except AppError:
        header = None

    target = (obj.get("target") or obj.get("section") or "").strip().lower()
    bit_index = obj.get("bit_index")
    if bit_index is not None and bit_index != "":
        try:
            bit_index = int(bit_index)
        except (TypeError, ValueError):
            raise AppError("bit_index must be an integer") from None
        if bit_index < 0:
            raise AppError("bit_index must be >= 0")

    byte_index: int
    bit_in_byte: int
    section_name: Optional[str] = None

    if target and target not in ("bit_index", "bit", ""):
        if header is None:
            raise AppError("cannot map a named section on an unrecognised blob; pass bit_index instead")
        sections = {s["name"]: s for s in header.get("sections", [])}
        # Alias: "body" -> ciphertext, "header" already present on N3/vetted;
        # on N2, "header" means version+magic+pickup (bytes 0..20).
        if target == "body":
            target = "ciphertext"
        if target == "header" and "header" not in sections:
            # Flip the first bit of the version byte (the format header).
            byte_index = 0
            bit_in_byte = 0 if bit_index is None else (bit_index % 8)
            if bit_index is not None:
                # bit_index is an offset within the 20-byte N2 prefix (or whole header area).
                header_len = 20 if len(blob) >= 20 else len(blob)
                abs_bit = bit_index
                if abs_bit >= header_len * 8:
                    raise AppError(f"bit_index {bit_index} is outside the header ({header_len} bytes)")
                byte_index = abs_bit // 8
                bit_in_byte = abs_bit % 8
            section_name = "header"
        elif target in sections:
            sec = sections[target]
            off, length = sec["offset"], sec["length"]
            if length <= 0:
                raise AppError(f"section {target!r} is empty")
            if bit_index is None:
                byte_index = off
                bit_in_byte = 0
            else:
                if bit_index >= length * 8:
                    raise AppError(f"bit_index {bit_index} is outside section {target!r} ({length} bytes)")
                byte_index = off + (bit_index // 8)
                bit_in_byte = bit_index % 8
            section_name = target
        else:
            raise AppError(f"unknown section {target!r}; try header, nonce, tag, or ciphertext")
    else:
        if bit_index is None:
            raise AppError("pass bit_index or a section (header, nonce, tag, ciphertext)")
        if bit_index >= len(blob) * 8:
            raise AppError(f"bit_index {bit_index} is outside the blob ({len(blob)} bytes)")
        byte_index = bit_index // 8
        bit_in_byte = bit_index % 8
        if header:
            for sec in header.get("sections", []):
                o, l = sec["offset"], sec["length"]
                if o <= byte_index < o + l:
                    section_name = sec["name"]
                    break

    original = blob[byte_index]
    blob[byte_index] = original ^ (1 << bit_in_byte)
    new = blob[byte_index]
    tampered = bytes(blob)
    abs_bit = byte_index * 8 + bit_in_byte
    out = {
        "ok": True,
        "warning": HONEST,
        "blob_hex": tampered.hex(),
        "blob_b64": _b64(tampered),
        "byte_index": byte_index,
        "bit_in_byte": bit_in_byte,
        "bit_index": abs_bit,
        "section": section_name,
        "original_byte": f"{original:02x}",
        "new_byte": f"{new:02x}",
        "mask": f"{1 << bit_in_byte:02x}",
    }
    try:
        out["header"] = parse_blob_auto(tampered)
    except AppError:
        if header is not None:
            out["header"] = header
    return out


def hear_key(obj: dict) -> dict[str, Any]:
    engine = (obj.get("engine") or "n2").strip().lower()
    if engine == "n3":
        # Display only: a 3-voice tune from the sealed 0x1C blob.
        # This does not change the N3 cipher, format, or vectors.
        try:
            blob = _blob_from(obj)
        except AppError:
            raise AppError(
                "N3 Hear needs a sealed 0x1C blob (blob_hex or blob_b64). "
                "Seal a message first, then Hear the blob. The tune is "
                "derived from the blob, not the seed, and is not a way to hide a secret."
            ) from None
        try:
            n3_music.parse_n3_blob(blob)
        except ValueError as e:
            raise AppError(str(e)) from e
        try:
            style = n3_music.parse_style(obj.get("style") or obj.get("music_style") or "earworm")
        except ValueError as e:
            raise AppError(str(e)) from e
        rendered = n3_music.render(blob, style=style)
        wav, midi, sid = rendered["wav"], rendered["midi"], rendered["sid"]
        if not wav or len(wav) < 12 or wav[:4] != b"RIFF" or wav[8:12] != b"WAVE":
            raise AppError("N3 hear did not return a valid WAV file", 500)
        out = {
            "ok": True,
            "warning": HONEST,
            "engine": "n3",
            "notes": rendered["notes"],
            "wav_b64": _b64(wav),
            "wav_bytes": len(wav),
            "content_type": "audio/wav",
            "music_note": (
                "Display only: the 3-voice tune is derived from the sealed blob "
                "and is not a way to hide a secret. style=ultima and style=castle "
                "are original music in those chiptune textures, not copies of any "
                "Ultima or Mr. Do's Castle tune."
            ),
            "style": rendered.get("style", "earworm"),
        }
        if rendered.get("voices"):
            out["voices"] = rendered["voices"]
        if rendered.get("mode"):
            out["mode"] = rendered["mode"]
        if rendered.get("bpm"):
            out["bpm"] = rendered["bpm"]
        if midi:
            out["midi_b64"] = _b64(midi)
            out["midi_bytes"] = len(midi)
        if sid:
            out["sid_b64"] = _b64(sid)
            out["sid_bytes"] = len(sid)
        return out
    if engine == "vetted":
        raise AppError("Hear is an Octavo feature; the vetted cipher has no earworm.")
    if OCTAVO_BIN is None or not Path(OCTAVO_BIN).is_file():
        raise AppError(_cli_help("octavo"), 503)

    seed: Optional[bytes] = None
    if obj.get("seed") or obj.get("seed_hex"):
        seed = require_key(
            _unhex(str(obj.get("seed_hex") or obj.get("seed")), name="seed"),
            (SEED_LEN,),
            "N2 seed",
        )
    elif obj.get("key") or obj.get("key_hex"):
        key = require_key(
            _unhex(str(obj.get("key_hex") or obj.get("key")), name="key"),
            N2_APP_LENS,
            "N2 app key",
        )
        seed = octavo.expand_key(key)
    else:
        raise AppError("Hear needs an N2 seed (128 bytes) or an N2 app key (32 or 64 bytes)")

    try:
        n2._seed_bytes(seed)
    except Exception as e:
        raise AppError(f"N2 seed rejected: {e}") from e

    with _temp_key_file(seed) as (key_path, tmpdir):
        wav_path = os.path.join(tmpdir, "earworm.wav")
        midi_path = os.path.join(tmpdir, "earworm.mid")
        sid_path = os.path.join(tmpdir, "earworm.sid")
        cmd = [
            str(OCTAVO_BIN),
            "hear",
            "--key",
            key_path,
            "--wav",
            wav_path,
            "--midi",
            midi_path,
            "--sid",
            sid_path,
        ]
        r = subprocess.run(cmd, capture_output=True, timeout=HEAR_TIMEOUT)
        if r.returncode != 0:
            raise AppError(_cli_err(r) or "octavo hear failed")
        def _read(path: str) -> Optional[bytes]:
            try:
                with open(path, "rb") as f:
                    return f.read()
            except OSError:
                return None

        wav = _read(wav_path)
        midi = _read(midi_path)
        sid = _read(sid_path)

    if not wav or len(wav) < 12 or wav[:4] != b"RIFF" or wav[8:12] != b"WAVE":
        raise AppError("octavo hear did not return a valid WAV file", 500)

    out = {
        "ok": True,
        "warning": HONEST,
        "engine": "n2",
        "wav_b64": _b64(wav),
        "wav_bytes": len(wav),
        "content_type": "audio/wav",
    }
    if midi:
        out["midi_b64"] = _b64(midi)
        out["midi_bytes"] = len(midi)
    if sid:
        out["sid_b64"] = _b64(sid)
        out["sid_bytes"] = len(sid)
    return out


def api_info() -> dict[str, Any]:
    vetted = vetted_available()
    return {
        "ok": True,
        "warning": HONEST,
        "app": "playground",
        "piece": 2,
        "file": {
            "max_bytes": MAX_FILE,
            "n2": "v9 rehearsal stream via the octavo CLI (AD supported with --ad-hex)",
            "n3": "0x1C AEAD via the n3aead CLI (optional AD and OCTAVO_N3_BACKEND)",
            "vetted": "AES-256-GCM-SIV file envelope SIV1 || nonce(12) || ciphertext || tag(16)",
        },
        "bind": "127.0.0.1 only",
        "n2": {
            "label": "Octavo N2 (live)",
            "cli_version": OCTAVO_VERSION,
            "formats": ["v6 single-message (octavo.py, 32- or 64-byte app key)", "v9 rehearsal stream (octavo CLI, 128-byte seed)"],
            "binary": str(OCTAVO_BIN) if OCTAVO_BIN and Path(OCTAVO_BIN).is_file() else None,
            "available": bool(OCTAVO_BIN and Path(OCTAVO_BIN).is_file()),
            "build": OCTAVO_BUILD_CMD,
            "expected": OCTAVO_EXPECTED,
            "python_api": "octavo.py / sneak_n2.py",
        },
        "n3": {
            "label": "Octavo N3 (experimental 0x1C)",
            "format": "0x1C",
            "magic": "SN3C/",
            "overhead_bytes": N3_OVERHEAD,
            "nonce_bytes": N3_NONCE_LEN,
            "tag_bytes": N3_TAG_LEN,
            "binary": str(N3_BIN) if N3_BIN and Path(N3_BIN).is_file() else None,
            "available": bool(N3_BIN and Path(N3_BIN).is_file()),
            "build": N3_BUILD_CMD,
            "expected": N3_EXPECTED,
            "backends": N3_BACKEND_INFO,
            "music": True,
            "music_note": (
                "Hear derives a short 3-voice WAV/MIDI/SID tune (melody, bass, "
                "harmony) from a sealed 0x1C blob. style=earworm is the default; "
                "style=ultima is an original slower Ultima title/loading texture (not their tunes); "
                "style=castle is an original bouncy early-80s arcade texture (not the Mr. Do's Castle tune). "
                "Display only; it does not change the cipher."
            ),
            "music_styles": ["earworm", "ultima", "castle"],
        },
        "vetted": {
            "label": "Vetted (recommended for real secrets)",
            "live": vetted["live"],
            "aes_gcm_siv": vetted["aes_gcm_siv"],
            "cryptography": vetted["cryptography"],
            "age": vetted["age"],
            "envelope": "VGCM || nonce(12) || ciphertext || tag(16)",
            "note": vetted["note"],
        },
        "keys": "Ephemeral CSPRNG keys stay in memory. This server never writes keys to disk automatically.",
    }


def api_keygen() -> dict[str, Any]:
    n2_app = fresh_app_key()
    n2_seed = fresh_n2_seed()
    n3_seed = fresh_n3_seed()
    out: dict[str, Any] = {
        "ok": True,
        "warning": HONEST,
        "note": "Keys are ephemeral and were not written to disk. Keep them in memory only.",
        "n2_app": n2_app.hex(),
        "n2_app_bytes": len(n2_app),
        "n2_seed": n2_seed.hex(),
        "n2_seed_bytes": len(n2_seed),
        "n3_seed": n3_seed.hex(),
        "n3_seed_bytes": len(n3_seed),
    }
    if AESGCMSIV is not None:
        for _ in range(8):
            vk = secrets.token_bytes(32)
            if not _is_all_zero(vk):
                out["vetted_key"] = vk.hex()
                out["vetted_key_bytes"] = 32
                out["vetted_alg"] = "AES-256-GCM-SIV"
                break
    return out



# ---------------------------------------------------------------------------
# Files tab and vector runner
# ---------------------------------------------------------------------------

def _file_bytes(obj: dict) -> tuple[bytes, str]:
    name = str(obj.get("filename") or obj.get("name") or "message.bin")
    name = Path(name).name or "message.bin"
    if obj.get("data_b64") or obj.get("file_b64") or obj.get("blob_b64"):
        raw = obj.get("data_b64") or obj.get("file_b64") or obj.get("blob_b64")
        try:
            data = base64.b64decode(str(raw), validate=True)
        except Exception:
            raise AppError("data_b64 is not valid base64") from None
    elif obj.get("data_hex") or obj.get("file_hex") or obj.get("blob_hex"):
        data = _unhex(str(obj.get("data_hex") or obj.get("file_hex") or obj.get("blob_hex")), name="data_hex")
    else:
        raise AppError("data_b64 or data_hex is missing")
    if len(data) > MAX_FILE:
        raise AppError(f"file is too large for this playground (max {MAX_FILE} bytes, got {len(data)})")
    return data, name


def _n2_file_seed(obj: dict) -> bytes:
    has_key, key_raw = _field(obj, "key_hex", "key")
    has_seed, seed_raw = _field(obj, "seed_hex", "seed")
    if has_seed:
        if seed_raw == "":
            raise AppError("N2 seed is empty")
        seed = require_key(_unhex(str(seed_raw), name="seed"), (SEED_LEN,), "N2 seed")
        try:
            n2._seed_bytes(seed)
        except Exception as e:
            raise AppError(f"N2 seed rejected: {e}") from e
        return seed
    if has_key:
        if key_raw == "":
            raise AppError("N2 app key is empty")
        key = require_key(_unhex(str(key_raw), name="key"), N2_APP_LENS, "N2 app key")
        return octavo.expand_key(key)
    raise AppError("N2 file seal/open needs a 128-byte seed or a 32- or 64-byte app key")


def _download_name(filename: str, ext: str) -> str:
    stem = filename or "message.bin"
    lower = stem.lower()
    if lower.endswith(ext):
        return stem
    return stem + ext


def _opened_name(filename: str) -> str:
    name = filename or "opened.bin"
    for ext in (".oct", ".n3", ".siv"):
        if name.lower().endswith(ext):
            return name[: -len(ext)] or "opened.bin"
    return name + ".opened"


def file_seal(obj: dict) -> dict[str, Any]:
    engine = (obj.get("engine") or "").strip().lower()
    data, filename = _file_bytes(obj)
    ad = decode_payload(obj, "ad", optional=True)
    if len(ad) > n2.MAX_AD_LEN:
        raise AppError(f"associated data is too long (max {n2.MAX_AD_LEN} bytes)")
    if engine == "n2":
        seed = _n2_file_seed(obj)
        blob = _n2_cli_seal(seed, data, ad)
        header = parse_n2_blob(blob)
        download = _download_name(filename, ".oct")
        used = "octavo CLI v9 rehearsal stream"
    elif engine == "n3":
        seed_raw = obj.get("seed_hex") or obj.get("seed") or obj.get("key_hex") or obj.get("key")
        if not seed_raw:
            raise AppError("N3 file seal needs a 128-byte seed")
        seed = require_key(_unhex(str(seed_raw), name="seed"), (SEED_LEN,), "N3 seed")
        if obj.get("nonce") or obj.get("nonce_hex"):
            nonce = _unhex(str(obj.get("nonce_hex") or obj.get("nonce")), name="nonce")
            if len(nonce) != N3_NONCE_LEN:
                raise AppError(f"N3 nonce must be {N3_NONCE_LEN} bytes (got {len(nonce)})")
        else:
            nonce = secrets.token_bytes(N3_NONCE_LEN)
        backend = (obj.get("backend") or "").strip() or None
        blob = _n3_run(["seal", seed.hex(), nonce.hex(), ad.hex() if ad else "-"], stdin=data, backend=backend)
        header = parse_n3_blob(blob)
        download = _download_name(filename, ".n3")
        used = "n3aead 0x1C"
    elif engine == "vetted":
        if AESGCMSIV is None:
            raise AppError("vetted mode is not available (cryptography AES-GCM-SIV is not installed)", 501)
        key_raw = obj.get("key_hex") or obj.get("key") or obj.get("seed_hex") or obj.get("seed")
        if not key_raw:
            raise AppError("vetted file seal needs a 32-byte AES-GCM-SIV key")
        key = require_key(_unhex(str(key_raw), name="key"), (32,), "vetted key")
        nonce = secrets.token_bytes(VETTED_NONCE_LEN)
        try:
            body = AESGCMSIV(key).encrypt(nonce, data, ad)
        except Exception as e:
            raise AppError(f"AES-GCM-SIV seal failed: {e}") from e
        blob = SIV1_MAGIC + nonce + body
        header = parse_siv1_blob(blob)
        download = _download_name(filename, ".siv")
        used = "cryptography AES-256-GCM-SIV (SIV1 file envelope)"
    else:
        raise AppError('engine must be "n2", "n3", or "vetted"')
    return {
        "ok": True,
        "warning": HONEST,
        "engine": engine,
        "used": used,
        "filename": filename,
        "download_name": download,
        "plaintext_length": len(data),
        "sealed_length": len(blob),
        "overhead": len(blob) - len(data),
        "blob_hex": blob.hex(),
        "blob_b64": _b64(blob),
        "header": header,
    }


def file_open(obj: dict) -> dict[str, Any]:
    engine = (obj.get("engine") or "").strip().lower()
    blob, filename = _file_bytes(obj)
    ad = decode_payload(obj, "ad", optional=True)
    if engine == "n2":
        seed = _n2_file_seed(obj)
        pt = _n2_cli_open(seed, blob, ad)
        header = parse_n2_blob(blob) if len(blob) >= 4 and blob[1:4] == b"SN2" else {"total_length": len(blob)}
        used = "octavo CLI v9 rehearsal stream"
    elif engine == "n3":
        seed_raw = obj.get("seed_hex") or obj.get("seed") or obj.get("key_hex") or obj.get("key")
        if not seed_raw:
            raise AppError("N3 file open needs a 128-byte seed")
        seed = require_key(_unhex(str(seed_raw), name="seed"), (SEED_LEN,), "N3 seed")
        backend = (obj.get("backend") or "").strip() or None
        pt = _n3_run(["open", seed.hex(), ad.hex() if ad else "-"], stdin=blob, backend=backend)
        header = parse_n3_blob(blob) if blob.startswith(N3_HEADER) else {"total_length": len(blob)}
        used = "n3aead 0x1C"
    elif engine == "vetted":
        if AESGCMSIV is None:
            raise AppError("vetted mode is not available (cryptography AES-GCM-SIV is not installed)", 501)
        key_raw = obj.get("key_hex") or obj.get("key") or obj.get("seed_hex") or obj.get("seed")
        if not key_raw:
            raise AppError("vetted file open needs a 32-byte AES-GCM-SIV key")
        key = require_key(_unhex(str(key_raw), name="key"), (32,), "vetted key")
        if not blob.startswith(SIV1_MAGIC) or len(blob) < SIV1_OVERHEAD:
            raise AppError("vetted file open rejected this blob (expected a SIV1 AES-GCM-SIV envelope)")
        nonce, body = blob[4:16], blob[16:]
        try:
            pt = AESGCMSIV(key).decrypt(nonce, body, ad)
        except Exception:
            raise AppError("authentication failed") from None
        header = parse_siv1_blob(blob)
        used = "cryptography AES-256-GCM-SIV (SIV1 file envelope)"
    else:
        raise AppError('engine must be "n2", "n3", or "vetted"')
    return {
        "ok": True,
        "warning": HONEST,
        "engine": engine,
        "used": used,
        "filename": filename,
        "download_name": _opened_name(filename),
        "plaintext_length": len(pt),
        "plaintext_b64": _b64(pt),
        "plaintext_hex": pt.hex(),
        "header": header,
    }


def file_flip(obj: dict) -> dict[str, Any]:
    blob, filename = _file_bytes(obj)
    flip_obj = dict(obj)
    flip_obj["blob_hex"] = blob.hex()
    out = flip_blob(flip_obj)
    out["filename"] = filename
    ext = ".oct"
    if blob.startswith(N3_HEADER):
        ext = ".n3"
    elif blob.startswith(SIV1_MAGIC) or blob.startswith(VETTED_MAGIC):
        ext = ".siv"
    out["download_name"] = _download_name(filename if filename.endswith(ext) else filename, ext)
    # Keep blob_b64 (flip_blob already sets it).
    return out


def api_vectors_run(obj: dict) -> dict[str, Any]:
    import vector_runner

    suite = str(obj.get("suite") or "all")
    try:
        result = vector_runner.run_suite(suite)
    except ValueError as e:
        raise AppError(str(e)) from e
    except subprocess.TimeoutExpired:
        raise AppError("vector suite timed out", 504) from None
    result.setdefault("ok", False)
    result["warning"] = HONEST
    return result


def dispatch_seal(obj: dict) -> dict[str, Any]:
    engine = (obj.get("engine") or "").strip().lower()
    if engine == "n2":
        return n2_seal(obj)
    if engine == "n3":
        return n3_seal(obj)
    if engine == "vetted":
        return vetted_seal(obj)
    raise AppError('engine must be "n2", "n3", or "vetted"')


def dispatch_open(obj: dict) -> dict[str, Any]:
    engine = (obj.get("engine") or "").strip().lower()
    if engine == "n2":
        return n2_open(obj)
    if engine == "n3":
        return n3_open(obj)
    if engine == "vetted":
        return vetted_open(obj)
    raise AppError('engine must be "n2", "n3", or "vetted"')


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

SHUTDOWN_TOKEN = secrets.token_hex(16)
_httpd_holder: dict[str, Any] = {}


class Handler(BaseHTTPRequestHandler):
    server_version = "OctavoPlayground/1"

    def log_message(self, fmt: str, *args: Any) -> None:
        if _httpd_holder.get("quiet"):
            return
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, status: int, body: bytes, content_type: str, *, extra_headers: Optional[dict] = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        # HTTP headers must be latin-1; keep the honest warning ASCII here.
        # The JSON body and HTML banner keep the typographic wording.
        self.send_header(
            "X-Octavo-Warning",
            "Octavo is homemade and experimental -- for real secrets use AES-GCM-SIV, age, or libsodium.",
        )
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, obj: dict[str, Any]) -> None:
        obj.setdefault("warning", HONEST)
        data = json.dumps(obj, indent=2, sort_keys=False).encode("utf-8") + b"\n"
        self._send(status, data, "application/json; charset=utf-8")

    def _read_json(self) -> dict:
        length = self.headers.get("Content-Length")
        try:
            n = int(length) if length else 0
        except ValueError:
            raise AppError("invalid Content-Length")
        # File endpoints allow a larger body (8 MiB file, base64-wrapped).
        path = urlparse(self.path).path
        limit = MAX_FILE_REQUEST if path.startswith("/api/file/") else MAX_BODY
        if n > limit:
            raise AppError("request body too large", 413)
        raw = self.rfile.read(n) if n else b"{}"
        if not raw:
            return {}
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise AppError("request body is not valid JSON") from None
        if not isinstance(obj, dict):
            raise AppError("request JSON must be an object")
        return obj

    def do_GET(self) -> None:  # noqa: N802
        try:
            path = urlparse(self.path).path
            if path in ("/", "/index.html"):
                return self._file(STATIC_DIR / "index.html", "text/html; charset=utf-8", root=STATIC_DIR)
            if path in REPO_ASSETS:
                return self._file(REPO_ASSETS[path], "image/png", root="asset")
            if path == "/api/info":
                return self._json(200, api_info())
            if path == "/api/health":
                return self._json(200, {"ok": True, "warning": HONEST})
            if path == "/api/vectors/info":
                return self._json(200, {
                    "ok": True,
                    "warning": HONEST,
                    "suites": [
                        {"id": "n2_app", "label": "N2 app vectors", "expected": 6},
                        {"id": "n2_score", "label": "N2 score vectors", "expected": 79},
                        {"id": "n3", "label": "N3 004 AEAD 0x1C vectors", "expected": 6, "backends": 4},
                        {"id": "all", "label": "Run all"},
                    ],
                })
            self._json(404, {"ok": False, "error": "not found"})
        except AppError as e:
            self._json(e.status, {"ok": False, "error": e.message})
        except Exception:
            traceback.print_exc()
            self._json(500, {"ok": False, "error": "internal error"})

    def do_POST(self) -> None:  # noqa: N802
        try:
            path = urlparse(self.path).path
            obj = self._read_json()
            if path == "/api/keygen":
                return self._json(200, api_keygen())
            if path == "/api/seal":
                return self._json(200, dispatch_seal(obj))
            if path == "/api/open":
                return self._json(200, dispatch_open(obj))
            if path == "/api/flip":
                return self._json(200, flip_blob(obj))
            if path == "/api/hear":
                result = hear_key(obj)
                return self._json(200 if result.get("ok") else 200, result)
            if path == "/api/file/seal":
                return self._json(200, file_seal(obj))
            if path == "/api/file/open":
                return self._json(200, file_open(obj))
            if path == "/api/file/flip":
                return self._json(200, file_flip(obj))
            if path == "/api/vectors/run":
                return self._json(200, api_vectors_run(obj))
            if path == "/api/shutdown":
                # Local test helper: only succeeds with the process-private token.
                token = str(obj.get("token") or "")
                if not secrets.compare_digest(token, SHUTDOWN_TOKEN):
                    return self._json(403, {"ok": False, "error": "bad shutdown token"})
                self._json(200, {"ok": True, "message": "shutting down"})
                threading.Thread(target=_shutdown_soon, daemon=True).start()
                return
            self._json(404, {"ok": False, "error": "not found"})
        except AppError as e:
            self._json(e.status, {"ok": False, "error": e.message})
        except subprocess.TimeoutExpired:
            self._json(504, {"ok": False, "error": "subprocess timed out"})
        except Exception:
            traceback.print_exc()
            self._json(500, {"ok": False, "error": "internal error"})

    def _file(self, path: Path, content_type: str, *, root: Any = None) -> None:
        # Allowlist only: static/index.html, or the two repo-root images.
        try:
            resolved = path.resolve()
        except Exception:
            return self._json(404, {"ok": False, "error": "not found"})
        if root == "asset":
            allowed = {(REPO_ROOT / "logo.png").resolve(), (REPO_ROOT / "sneak-staff-n2.png").resolve()}
            if resolved not in allowed:
                return self._json(404, {"ok": False, "error": "not found"})
        else:
            try:
                resolved.relative_to(STATIC_DIR.resolve())
            except Exception:
                return self._json(404, {"ok": False, "error": "not found"})
        if not resolved.is_file():
            return self._json(404, {"ok": False, "error": "not found"})
        data = resolved.read_bytes()
        self._send(200, data, content_type, extra_headers={"Cache-Control": "public, max-age=3600"})

    def do_HEAD(self) -> None:  # noqa: N802
        # Enough for simple health pings.
        if urlparse(self.path).path in ("/", "/api/health", "/api/info"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()


def _shutdown_soon() -> None:
    import time

    time.sleep(0.05)
    httpd = _httpd_holder.get("httpd")
    if httpd is not None:
        httpd.shutdown()


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Octavo playground (local only). " + HONEST)
    p.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1; do not change unless you mean to)")
    p.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8780")), help="port (default 8780)")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("Refusing to bind to a non-localhost address. This playground is local-only.", file=sys.stderr)
        return 2
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    _httpd_holder["httpd"] = httpd
    _httpd_holder["quiet"] = args.quiet
    host, port = httpd.server_address[:2]
    print(f"listening on {host}:{port}", flush=True)
    print(HONEST, flush=True)
    print(f"open http://127.0.0.1:{port}/", flush=True)
    # Expose the shutdown token only on stdout when OCTAVO_APP_PRINT_TOKEN=1 (tests).
    if os.environ.get("OCTAVO_APP_PRINT_TOKEN") == "1":
        print(f"shutdown_token {SHUTDOWN_TOKEN}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping", flush=True)
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
