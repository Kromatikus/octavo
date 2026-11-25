#!/usr/bin/env python3
"""Automated checks for the Octavo playground (Piece 1).

Starts server.py on an ephemeral localhost port, exercises N2 / N3 / vetted
paths (text, files, and published vectors), and shuts the server down cleanly.

Octavo is homemade and experimental — for real secrets use AES-GCM-SIV, age, or libsodium.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
HONEST = (
    "Octavo is homemade and experimental — for real secrets use "
    "AES-GCM-SIV, age, or libsodium."
)


class Fail(Exception):
    pass


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def http(method: str, url: str, obj=None, timeout=60):
    data = None
    headers = {"Accept": "application/json"}
    if obj is not None:
        data = json.dumps(obj).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:
            body = res.read()
            return res.status, json.loads(body.decode("utf-8"))
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except Exception:
            parsed = {"ok": False, "error": raw.decode("utf-8", "replace")}
        return e.code, parsed


def expect(cond, msg):
    if not cond:
        raise Fail(msg)


def main() -> int:
    results = []
    port = free_port()
    env = os.environ.copy()
    env["OCTAVO_APP_PRINT_TOKEN"] = "1"
    proc = subprocess.Popen(
        [sys.executable, str(HERE / "server.py"), "--host", "127.0.0.1", "--port", str(port), "--quiet"],
        cwd=str(HERE),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    token = None
    deadline = time.time() + 20
    buf = b""
    try:
        # Read until we see "listening on" (and maybe the shutdown token).
        while time.time() < deadline:
            if proc.poll() is not None:
                err = (proc.stderr.read() or b"").decode("utf-8", "replace")
                out = (proc.stdout.read() or b"").decode("utf-8", "replace")
                raise Fail(f"server exited early ({proc.returncode}):\n{out}\n{err}")
            # peek without blocking too long
            line = b""
            # Use a short select-style wait via stdout's buffering: read byte by byte is slow;
            # instead poll /api/health once the listening line appears.
            if proc.stdout is not None:
                import select
                r, _, _ = select.select([proc.stdout], [], [], 0.2)
                if r:
                    chunk = os.read(proc.stdout.fileno(), 4096)
                    if chunk:
                        buf += chunk
                        if b"listening on" in buf:
                            break
            else:
                time.sleep(0.2)
        # Wait until the HTTP port answers even if stdout was slow.
        ready = False
        for _ in range(50):
            try:
                status, info = http("GET", f"http://127.0.0.1:{port}/api/info", timeout=2)
                if status == 200 and info.get("ok"):
                    ready = True
                    break
            except Exception:
                time.sleep(0.15)
        expect(ready, "server did not become ready on /api/info")
        for line in buf.decode("utf-8", "replace").splitlines():
            if line.startswith("shutdown_token "):
                token = line.split(" ", 1)[1].strip()

        def check(name, fn):
            try:
                fn()
                results.append((name, "PASS", ""))
                print(f"PASS  {name}")
            except Fail as e:
                results.append((name, "FAIL", str(e)))
                print(f"FAIL  {name}: {e}")
            except Exception as e:
                results.append((name, "FAIL", f"{type(e).__name__}: {e}"))
                print(f"FAIL  {name}: {type(e).__name__}: {e}")

        base = f"http://127.0.0.1:{port}"

        def info_ok():
            st, info = http("GET", f"{base}/api/info")
            expect(st == 200 and info.get("ok") is True, f"info failed: {st} {info}")
            expect(HONEST in info.get("warning", ""), "honest warning missing from /api/info")
            expect(info["n3"]["format"] == "0x1C", "N3 format should be 0x1C")
            expect("available" in info["n3"]["backends"], "N3 backends missing")
            # Static page should also carry the banner text.
            req = urllib.request.Request(f"{base}/", headers={"Accept": "text/html"})
            with urllib.request.urlopen(req, timeout=5) as res:
                html = res.read().decode("utf-8")
            expect("for real secrets use AES-GCM-SIV, age, or libsodium" in html, "banner missing from index.html")
            expect('id="tab-n2"' in html and 'id="tab-n3"' in html and 'id="tab-vetted"' in html, "engine tabs missing")

        def keygen():
            st, data = http("POST", f"{base}/api/keygen", {})
            expect(st == 200 and data.get("ok"), f"keygen failed: {st} {data}")
            for field, n in (("n2_app", 32), ("n2_seed", 128), ("n3_seed", 128)):
                raw = bytes.fromhex(data[field])
                expect(len(raw) == n, f"{field} is {len(raw)} bytes, expected {n}")
                expect(set(raw) != {0}, f"{field} was all-zero")
            if data.get("vetted_key"):
                raw = bytes.fromhex(data["vetted_key"])
                expect(len(raw) == 32, "vetted key should be 32 bytes")
            keygen.cache = data

        def n2_roundtrip():
            keys = keygen.cache
            st, sealed = http("POST", f"{base}/api/seal", {
                "engine": "n2",
                "key": keys["n2_app"],
                "plaintext": "N2 playground hello",
                "ad": "from:ohlo",
            })
            expect(st == 200 and sealed.get("ok"), f"n2 seal failed: {st} {sealed}")
            expect(sealed["header"]["version"] == 6, f"expected v6, got {sealed['header']}")
            expect(sealed["header"]["magic"] == "SN2", "v6 magic should be SN2")
            expect(sealed["header"]["overhead"] == 100, "v6 overhead should be 100")
            expect(len(bytes.fromhex(sealed["blob_hex"])) == 228, "v6 blob should be 228 bytes")
            st, opened = http("POST", f"{base}/api/open", {
                "engine": "n2",
                "key": keys["n2_app"],
                "blob_hex": sealed["blob_hex"],
                "ad": "from:ohlo",
            })
            expect(st == 200 and opened.get("ok"), f"n2 open failed: {st} {opened}")
            expect(opened.get("plaintext") == "N2 playground hello", f"plaintext mismatch: {opened}")
            n2_roundtrip.blob = sealed["blob_hex"]
            n2_roundtrip.key = keys["n2_app"]
            n2_roundtrip.seed = keys["n2_seed"]
            n2_roundtrip.n3_seed = keys["n3_seed"]

        def n2_ad_mismatch():
            st, data = http("POST", f"{base}/api/open", {
                "engine": "n2",
                "key": n2_roundtrip.key,
                "blob_hex": n2_roundtrip.blob,
                "ad": "from:eve",
            })
            expect(st >= 400 and data.get("ok") is False, f"AD mismatch should fail: {st} {data}")
            expect("auth" in data.get("error", "").lower() or "fail" in data.get("error", "").lower(),
                   f"unexpected AD-mismatch error: {data}")

        def n2_bitflip():
            st, flipped = http("POST", f"{base}/api/flip", {
                "blob_hex": n2_roundtrip.blob,
                "target": "tag",
            })
            expect(st == 200 and flipped.get("ok"), f"flip failed: {st} {flipped}")
            expect(flipped["blob_hex"] != n2_roundtrip.blob, "flip did not change the blob")
            expect(flipped.get("section") == "tag", f"expected tag section, got {flipped.get('section')}")
            expect(flipped["blob_hex"].count("0") >= 0, "hex missing")
            # Exact one-bit difference.
            a = bytes.fromhex(n2_roundtrip.blob)
            b = bytes.fromhex(flipped["blob_hex"])
            expect(len(a) == len(b), "length changed")
            diffs = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
            expect(len(diffs) == 1, f"expected one changed byte, got {diffs}")
            expect((a[diffs[0]] ^ b[diffs[0]]).bit_count() == 1, "more than one bit flipped")
            st, data = http("POST", f"{base}/api/open", {
                "engine": "n2",
                "key": n2_roundtrip.key,
                "blob_hex": flipped["blob_hex"],
                "ad": "from:ohlo",
            })
            expect(st >= 400 and data.get("ok") is False, f"flipped blob should fail: {st} {data}")
            n2_bitflip.flipped = flipped["blob_hex"]

        def n3_roundtrip():
            keys = keygen.cache
            st, sealed = http("POST", f"{base}/api/seal", {
                "engine": "n3",
                "seed": keys["n3_seed"],
                "plaintext": "N3 playground hello",
                "ad": "from:ohlo",
            })
            expect(st == 200 and sealed.get("ok"), f"n3 seal failed: {st} {sealed}")
            blob = bytes.fromhex(sealed["blob_hex"])
            expect(blob.startswith(b"SN3C/"), f"N3 magic missing: {blob[:8]!r}")
            expect(blob[5] == 0x1C, f"format byte is 0x{blob[5]:02x}, expected 0x1C")
            expect(sealed["header"]["overhead"] == 54, "N3 overhead should be 54")
            expect(sealed["header"]["magic"] == "SN3C/", "N3 magic label")
            expect(len(blob) == 54 + len("N3 playground hello"), "N3 length should be msg + 54")
            st, opened = http("POST", f"{base}/api/open", {
                "engine": "n3",
                "seed": keys["n3_seed"],
                "blob_hex": sealed["blob_hex"],
                "ad": "from:ohlo",
            })
            expect(st == 200 and opened.get("ok"), f"n3 open failed: {st} {opened}")
            expect(opened.get("plaintext") == "N3 playground hello", f"plaintext mismatch: {opened}")
            n3_roundtrip.blob = sealed["blob_hex"]
            n3_roundtrip.seed = keys["n3_seed"]

        def n3_ad_mismatch():
            st, data = http("POST", f"{base}/api/open", {
                "engine": "n3",
                "seed": n3_roundtrip.seed,
                "blob_hex": n3_roundtrip.blob,
                "ad": "from:eve",
            })
            expect(st >= 400 and data.get("ok") is False, f"N3 AD mismatch should fail: {st} {data}")

        def n3_bitflip():
            st, flipped = http("POST", f"{base}/api/flip", {
                "blob_hex": n3_roundtrip.blob,
                "target": "tag",
            })
            expect(st == 200 and flipped.get("ok"), f"n3 flip failed: {st} {flipped}")
            a = bytes.fromhex(n3_roundtrip.blob)
            b = bytes.fromhex(flipped["blob_hex"])
            diffs = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
            expect(len(diffs) == 1 and (a[diffs[0]] ^ b[diffs[0]]).bit_count() == 1, "n3 flip was not a single bit")
            st, data = http("POST", f"{base}/api/open", {
                "engine": "n3",
                "seed": n3_roundtrip.seed,
                "blob_hex": flipped["blob_hex"],
                "ad": "from:ohlo",
            })
            expect(st >= 400 and data.get("ok") is False, f"flipped N3 blob should fail: {st} {data}")

        def n3_section_flips():
            for section in ("header", "nonce", "ciphertext"):
                st, flipped = http("POST", f"{base}/api/flip", {
                    "blob_hex": n3_roundtrip.blob,
                    "target": section,
                })
                expect(st == 200 and flipped.get("ok"), f"flip {section} failed: {st} {flipped}")
                st, data = http("POST", f"{base}/api/open", {
                    "engine": "n3",
                    "seed": n3_roundtrip.seed,
                    "blob_hex": flipped["blob_hex"],
                    "ad": "from:ohlo",
                })
                expect(st >= 400 and data.get("ok") is False, f"N3 flip in {section} should fail to open: {data}")

        def cross_open():
            # N3 blob opened with N2
            st, data = http("POST", f"{base}/api/open", {
                "engine": "n2",
                "key": n2_roundtrip.key,
                "blob_hex": n3_roundtrip.blob,
                "ad": "from:ohlo",
            })
            expect(st >= 400 and data.get("ok") is False, f"N2 should reject an N3 blob: {st} {data}")
            # N2 blob opened with N3
            st, data = http("POST", f"{base}/api/open", {
                "engine": "n3",
                "seed": n3_roundtrip.seed,
                "blob_hex": n2_roundtrip.blob,
                "ad": "from:ohlo",
            })
            expect(st >= 400 and data.get("ok") is False, f"N3 should reject an N2 blob: {st} {data}")

        def bad_keys():
            cases = [
                ("n2", {"engine": "n2", "key": "00" * 32, "plaintext": "x"}, "all-zero"),
                ("n2-len", {"engine": "n2", "key": "ab" * 8, "plaintext": "x"}, "wrong length"),
                ("n2-empty", {"engine": "n2", "key": "", "plaintext": "x"}, "empty"),
                ("n3", {"engine": "n3", "seed": "00" * 128, "plaintext": "x"}, "all-zero"),
                ("n3-len", {"engine": "n3", "seed": "ab" * 16, "plaintext": "x"}, "wrong length"),
            ]
            st, info = http("GET", f"{base}/api/info")
            if info.get("vetted", {}).get("live"):
                cases.append(("vetted", {"engine": "vetted", "key": "00" * 32, "plaintext": "x"}, "all-zero"))
                cases.append(("vetted-len", {"engine": "vetted", "key": "ab" * 8, "plaintext": "x"}, "wrong length"))
            for name, body, kind in cases:
                st, data = http("POST", f"{base}/api/seal", body)
                expect(st >= 400 and data.get("ok") is False, f"{name} should be rejected: {st} {data}")
                err = data.get("error", "").lower()
                if kind == "all-zero":
                    expect("all-zero" in err, f"{name}: expected all-zero wording, got {data}")
                elif kind == "wrong length":
                    expect("length" in err or "wrong" in err, f"{name}: expected length wording, got {data}")
                else:
                    expect("empty" in err or "missing" in err or "odd" in err or "hex" in err,
                           f"{name}: expected empty-key wording, got {data}")

        def hear_wav():
            st, data = http("POST", f"{base}/api/hear", {
                "engine": "n2",
                "key": n2_roundtrip.key,
            }, timeout=60)
            expect(st == 200 and data.get("ok"), f"hear failed: {st} {data}")
            import base64
            wav = base64.b64decode(data["wav_b64"])
            expect(wav[:4] == b"RIFF" and wav[8:12] == b"WAVE", f"not a RIFF/WAV: {wav[:16]!r}")
            expect(len(wav) > 44, "WAV is too short")
            # N3 Hear without a blob should ask for one, not 500.
            st, data = http("POST", f"{base}/api/hear", {
                "engine": "n3",
                "seed": n3_roundtrip.seed,
            })
            expect(st >= 400 and data.get("ok") is False, f"N3 hear without a blob should fail: {st} {data}")
            err = (data.get("error") or "").lower()
            expect("blob" in err or "0x1c" in err, f"unexpected N3 missing-blob message: {data}")

        def n3_hear_headers():
            import base64
            st, data = http("POST", f"{base}/api/hear", {
                "engine": "n3",
                "blob_hex": n3_roundtrip.blob,
            }, timeout=60)
            expect(st == 200 and data.get("ok"), f"N3 hear failed: {st} {data}")
            wav = base64.b64decode(data["wav_b64"])
            mid = base64.b64decode(data["midi_b64"])
            sid = base64.b64decode(data["sid_b64"])
            expect(wav[:4] == b"RIFF" and wav[8:12] == b"WAVE", f"N3 WAV header: {wav[:16]!r}")
            expect(len(wav) > 44, "N3 WAV is too short")
            expect(mid[:4] == b"MThd", f"N3 MIDI header: {mid[:16]!r}")
            expect(sid[:4] == b"PSID", f"N3 SID header: {sid[:16]!r}")
            expect(int.from_bytes(sid[4:6], "big") == 2, "N3 SID version should be 2")
            n3_hear_headers.wav = wav
            n3_hear_headers.mid = mid
            n3_hear_headers.sid = sid

        def n3_hear_deterministic():
            import base64
            st, data = http("POST", f"{base}/api/hear", {
                "engine": "n3",
                "blob_hex": n3_roundtrip.blob,
            }, timeout=60)
            expect(st == 200 and data.get("ok"), f"N3 hear retry failed: {st} {data}")
            wav = base64.b64decode(data["wav_b64"])
            mid = base64.b64decode(data["midi_b64"])
            sid = base64.b64decode(data["sid_b64"])
            expect(wav == n3_hear_headers.wav, "N3 WAV is not deterministic")
            expect(mid == n3_hear_headers.mid, "N3 MIDI is not deterministic")
            expect(sid == n3_hear_headers.sid, "N3 SID is not deterministic")
            flipped = bytearray(bytes.fromhex(n3_roundtrip.blob))
            flipped[-1] ^= 0x01
            st, other = http("POST", f"{base}/api/hear", {
                "engine": "n3",
                "blob_hex": flipped.hex(),
            }, timeout=60)
            expect(st == 200 and other.get("ok"), f"N3 hear (other blob) failed: {st} {other}")
            wav2 = base64.b64decode(other["wav_b64"])
            mid2 = base64.b64decode(other["midi_b64"])
            sid2 = base64.b64decode(other["sid_b64"])
            expect(wav2 != wav, "different N3 blobs produced the same WAV")
            expect(mid2 != mid, "different N3 blobs produced the same MIDI")
            expect(sid2 != sid, "different N3 blobs produced the same SID")

        def n2_v9_seed():
            # Longer message + seed should go through the v9 CLI.
            msg = "A" * 200
            st, sealed = http("POST", f"{base}/api/seal", {
                "engine": "n2",
                "seed": n2_roundtrip.seed,
                "plaintext": msg,
                "ad": "file:demo",
            })
            expect(st == 200 and sealed.get("ok"), f"v9 seal failed: {st} {sealed}")
            expect(sealed["header"]["version"] == 9, f"expected v9, got {sealed['header']}")
            st, opened = http("POST", f"{base}/api/open", {
                "engine": "n2",
                "seed": n2_roundtrip.seed,
                "blob_hex": sealed["blob_hex"],
                "ad": "file:demo",
            })
            expect(st == 200 and opened.get("plaintext") == msg, f"v9 open failed: {st} {opened}")

        def vetted_path():
            st, info = http("GET", f"{base}/api/info")
            live = info.get("vetted", {}).get("live")
            if not live:
                # Must not fake it.
                st, data = http("POST", f"{base}/api/seal", {
                    "engine": "vetted",
                    "key": "11" * 32,
                    "plaintext": "nope",
                })
                expect(st == 501 and data.get("ok") is False, f"vetted should be 501 when unavailable: {st} {data}")
                return
            expect(info["vetted"]["aes_gcm_siv"] is True, "info said live but aes_gcm_siv is not true")
            expect(info["vetted"]["age"] is False, "age is not installed; info must not claim it is")
            key = keygen.cache["vetted_key"]
            st, sealed = http("POST", f"{base}/api/seal", {
                "engine": "vetted",
                "key": key,
                "plaintext": "vetted hello",
                "ad": "from:ohlo",
            })
            expect(st == 200 and sealed.get("ok"), f"vetted seal failed: {st} {sealed}")
            blob = bytes.fromhex(sealed["blob_hex"])
            expect(blob.startswith(b"VGCM"), "vetted envelope should start with VGCM")
            st, opened = http("POST", f"{base}/api/open", {
                "engine": "vetted",
                "key": key,
                "blob_hex": sealed["blob_hex"],
                "ad": "from:ohlo",
            })
            expect(st == 200 and opened.get("plaintext") == "vetted hello", f"vetted open failed: {opened}")
            st, bad = http("POST", f"{base}/api/open", {
                "engine": "vetted",
                "key": key,
                "blob_hex": sealed["blob_hex"],
                "ad": "from:eve",
            })
            expect(st >= 400 and bad.get("ok") is False, f"vetted AD mismatch should fail: {bad}")
            st, flipped = http("POST", f"{base}/api/flip", {"blob_hex": sealed["blob_hex"], "target": "tag"})
            expect(st == 200, f"vetted flip failed: {flipped}")
            st, bad = http("POST", f"{base}/api/open", {
                "engine": "vetted",
                "key": key,
                "blob_hex": flipped["blob_hex"],
                "ad": "from:ohlo",
            })
            expect(st >= 400 and bad.get("ok") is False, f"vetted flipped blob should fail: {bad}")


        def _b64(data: bytes) -> str:
            import base64
            return base64.b64encode(data).decode("ascii")

        def _unb64(s: str) -> bytes:
            import base64
            return base64.b64decode(s)

        BINARY_MSG = b"hello\x00\xff\xfe binary\x00payload \x01\x02\x03" + bytes(range(64))

        def file_n2_roundtrip():
            keys = keygen.cache
            st, sealed = http("POST", f"{base}/api/file/seal", {
                "engine": "n2",
                "seed": keys["n2_seed"],
                "filename": "sample.bin",
                "data_b64": _b64(BINARY_MSG),
                "ad": "file:n2",
            })
            expect(st == 200 and sealed.get("ok"), f"n2 file seal failed: {st} {sealed}")
            expect(sealed["header"]["version"] == 9, f"expected v9 file, got {sealed['header']}")
            expect(sealed["download_name"].endswith(".oct"), sealed.get("download_name"))
            blob = _unb64(sealed["blob_b64"])
            expect(blob[0] == 9 and blob[1:4] == b"SN2", f"bad n2 file magic: {blob[:8]!r}")
            st, opened = http("POST", f"{base}/api/file/open", {
                "engine": "n2",
                "seed": keys["n2_seed"],
                "filename": sealed["download_name"],
                "data_b64": sealed["blob_b64"],
                "ad": "file:n2",
            })
            expect(st == 200 and opened.get("ok"), f"n2 file open failed: {st} {opened}")
            expect(_unb64(opened["plaintext_b64"]) == BINARY_MSG, "n2 file plaintext mismatch")
            file_n2_roundtrip.blob = sealed["blob_b64"]
            file_n2_roundtrip.seed = keys["n2_seed"]

        def file_n3_roundtrip():
            keys = keygen.cache
            st, sealed = http("POST", f"{base}/api/file/seal", {
                "engine": "n3",
                "seed": keys["n3_seed"],
                "filename": "sample.bin",
                "data_b64": _b64(BINARY_MSG),
                "ad": "file:n3",
            })
            expect(st == 200 and sealed.get("ok"), f"n3 file seal failed: {st} {sealed}")
            blob = _unb64(sealed["blob_b64"])
            expect(blob.startswith(b"SN3C/") and blob[5] == 0x1C, f"bad n3 file header: {blob[:8]!r}")
            expect(sealed["overhead"] == 54, f"n3 file overhead {sealed.get('overhead')}")
            expect(sealed["download_name"].endswith(".n3"), sealed.get("download_name"))
            st, opened = http("POST", f"{base}/api/file/open", {
                "engine": "n3",
                "seed": keys["n3_seed"],
                "filename": sealed["download_name"],
                "data_b64": sealed["blob_b64"],
                "ad": "file:n3",
            })
            expect(st == 200 and opened.get("ok"), f"n3 file open failed: {st} {opened}")
            expect(_unb64(opened["plaintext_b64"]) == BINARY_MSG, "n3 file plaintext mismatch")
            # AD mismatch
            st, bad = http("POST", f"{base}/api/file/open", {
                "engine": "n3",
                "seed": keys["n3_seed"],
                "data_b64": sealed["blob_b64"],
                "ad": "file:eve",
            })
            expect(st >= 400 and bad.get("ok") is False, f"n3 file AD mismatch should fail: {bad}")
            file_n3_roundtrip.blob = sealed["blob_b64"]
            file_n3_roundtrip.seed = keys["n3_seed"]

        def file_vetted_roundtrip():
            st, info = http("GET", f"{base}/api/info")
            if not info.get("vetted", {}).get("live"):
                st, data = http("POST", f"{base}/api/file/seal", {
                    "engine": "vetted", "key": "11"*32, "data_b64": _b64(b"x"), "filename": "x.bin",
                })
                expect(st == 501, f"vetted file should be 501 when unavailable: {st} {data}")
                file_vetted_roundtrip.blob = None
                return
            key = keygen.cache["vetted_key"]
            st, sealed = http("POST", f"{base}/api/file/seal", {
                "engine": "vetted",
                "key": key,
                "filename": "secret.bin",
                "data_b64": _b64(BINARY_MSG),
                "ad": "file:siv",
            })
            expect(st == 200 and sealed.get("ok"), f"vetted file seal failed: {st} {sealed}")
            blob = _unb64(sealed["blob_b64"])
            expect(blob.startswith(b"SIV1"), f"expected SIV1 envelope, got {blob[:8]!r}")
            expect(sealed["download_name"].endswith(".siv"), sealed.get("download_name"))
            st, opened = http("POST", f"{base}/api/file/open", {
                "engine": "vetted",
                "key": key,
                "filename": sealed["download_name"],
                "data_b64": sealed["blob_b64"],
                "ad": "file:siv",
            })
            expect(st == 200 and opened.get("ok"), f"vetted file open failed: {opened}")
            expect(_unb64(opened["plaintext_b64"]) == BINARY_MSG, "vetted file plaintext mismatch")
            st, bad = http("POST", f"{base}/api/file/open", {
                "engine": "vetted", "key": key, "data_b64": sealed["blob_b64"], "ad": "file:eve",
            })
            expect(st >= 400 and bad.get("ok") is False, f"vetted file AD mismatch should fail: {bad}")
            file_vetted_roundtrip.blob = sealed["blob_b64"]
            file_vetted_roundtrip.key = key

        def file_bitflip_all():
            cases = [
                ("n2", {"engine": "n2", "seed": file_n2_roundtrip.seed, "data_b64": file_n2_roundtrip.blob, "ad": "file:n2"}),
                ("n3", {"engine": "n3", "seed": file_n3_roundtrip.seed, "data_b64": file_n3_roundtrip.blob, "ad": "file:n3"}),
            ]
            if file_vetted_roundtrip.blob:
                cases.append(("vetted", {"engine": "vetted", "key": file_vetted_roundtrip.key, "data_b64": file_vetted_roundtrip.blob, "ad": "file:siv"}))
            for name, open_body in cases:
                st, flipped = http("POST", f"{base}/api/file/flip", {
                    "data_b64": open_body["data_b64"],
                    "target": "tag",
                    "filename": "tampered",
                })
                expect(st == 200 and flipped.get("ok"), f"{name} file flip failed: {st} {flipped}")
                a = _unb64(open_body["data_b64"])
                b = _unb64(flipped["blob_b64"]) if flipped.get("blob_b64") else bytes.fromhex(flipped["blob_hex"])
                diffs = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
                expect(len(a) == len(b) and len(diffs) == 1 and (a[diffs[0]] ^ b[diffs[0]]).bit_count() == 1,
                       f"{name} file flip was not a single bit: {diffs}")
                body = dict(open_body)
                body["data_b64"] = flipped.get("blob_b64") or __import__("base64").b64encode(bytes.fromhex(flipped["blob_hex"])).decode()
                st, data = http("POST", f"{base}/api/file/open", body)
                expect(st >= 400 and data.get("ok") is False, f"{name} flipped file should fail: {st} {data}")

        def file_cross_open():
            st, data = http("POST", f"{base}/api/file/open", {
                "engine": "n3",
                "seed": file_n3_roundtrip.seed,
                "data_b64": file_n2_roundtrip.blob,
                "ad": "file:n2",
            })
            expect(st >= 400 and data.get("ok") is False, f"N3 should reject an N2 file: {st} {data}")
            st, data = http("POST", f"{base}/api/file/open", {
                "engine": "n2",
                "seed": file_n2_roundtrip.seed,
                "data_b64": file_n3_roundtrip.blob,
                "ad": "file:n3",
            })
            expect(st >= 400 and data.get("ok") is False, f"N2 should reject an N3 file: {st} {data}")

        def file_bad_keys_and_oversize():
            tiny = _b64(b"xy")
            cases = [
                ("n2-zero", {"engine": "n2", "seed": "00"*128, "data_b64": tiny, "filename": "x.bin"}),
                ("n2-len", {"engine": "n2", "seed": "ab"*16, "data_b64": tiny, "filename": "x.bin"}),
                ("n3-zero", {"engine": "n3", "seed": "00"*128, "data_b64": tiny, "filename": "x.bin"}),
                ("n3-len", {"engine": "n3", "seed": "ab"*8, "data_b64": tiny, "filename": "x.bin"}),
            ]
            for name, body in cases:
                st, data = http("POST", f"{base}/api/file/seal", body)
                expect(st >= 400 and data.get("ok") is False, f"{name} should be rejected: {st} {data}")
            # Just over the 8 MiB cap (8 MiB + 1).
            import base64
            huge = base64.b64encode(b"A" * (8 * 1024 * 1024 + 1)).decode("ascii")
            st, data = http("POST", f"{base}/api/file/seal", {
                "engine": "n3",
                "seed": file_n3_roundtrip.seed,
                "data_b64": huge,
                "filename": "huge.bin",
            }, timeout=30)
            expect(st >= 400 and data.get("ok") is False, f"oversize should be rejected: {st} {data}")
            expect("large" in data.get("error", "").lower() or "max" in data.get("error", "").lower(),
                   f"oversize wording: {data}")

        def vectors_n2_app():
            st, data = http("POST", f"{base}/api/vectors/run", {"suite": "n2_app"}, timeout=30)
            expect(st == 200 and data.get("ok"), f"n2 app vectors failed: {st} {data}")
            expect(data.get("passed") == 6 and data.get("total") == 6, f"expected 6/6, got {data}")

        def vectors_n2_score():
            st, data = http("POST", f"{base}/api/vectors/run", {"suite": "n2_score"}, timeout=90)
            expect(st == 200 and data.get("ok"), f"n2 score vectors failed: {st} {data}")
            expect(data.get("passed") == 79 and data.get("total") == 79, f"expected 79/79, got {data}")
            vectors_n2_score.ms = data.get("elapsed_ms")

        def vectors_n3():
            st, data = http("POST", f"{base}/api/vectors/run", {"suite": "n3"}, timeout=60)
            expect(st == 200 and data.get("ok"), f"n3 vectors failed: {st} {data}")
            expect(data.get("failed") == 0, f"n3 failures: {data}")
            expect(data.get("passed") == data.get("expected"), f"n3 expected {data.get('expected')} got {data}")
            vectors_n3.detail = f"{data.get('passed')}/{data.get('total')} in {data.get('elapsed_ms')} ms across {data.get('backends')}"

        def index_piece2():
            req = urllib.request.Request(f"{base}/", headers={"Accept": "text/html"})
            with urllib.request.urlopen(req, timeout=5) as res:
                html = res.read().decode("utf-8")
            expect("mode-files" in html and "mode-check" in html, "Files/Check tabs missing")
            expect("for real secrets use AES-GCM-SIV, age, or libsodium" in html, "banner missing")
            st, info = http("GET", f"{base}/api/info")
            expect(info.get("piece") == 2, f"expected piece 2 in /api/info, got {info.get('piece')}")

        def index_assets():
            for path, magic in (("/logo.png", b"\x89PNG"), ("/sneak-staff-n2.png", b"\x89PNG")):
                req = urllib.request.Request(f"{base}{path}")
                with urllib.request.urlopen(req, timeout=5) as res:
                    data = res.read(8)
                expect(data.startswith(magic), f"{path} is not a PNG")

        check("GET /api/info and honest banner", info_ok)
        check("POST /api/keygen (ephemeral, not all-zero)", keygen)
        check("N2 v6 seal/open with matching AD", n2_roundtrip)
        check("N2 AD mismatch is rejected", n2_ad_mismatch)
        check("N2 tag bit-flip is rejected", n2_bitflip)
        check("N3 0x1C seal/open with matching AD", n3_roundtrip)
        check("N3 AD mismatch is rejected", n3_ad_mismatch)
        check("N3 tag bit-flip is rejected", n3_bitflip)
        check("N3 header/nonce/ciphertext bit-flips are rejected", n3_section_flips)
        check("Cross-open N2↔N3 is rejected both ways", cross_open)
        check("All-zero and wrong-length keys are rejected", bad_keys)
        check("N2 hear returns a valid RIFF/WAV; N3 without a blob is rejected", hear_wav)
        check("N3 Hear returns valid WAV, MIDI and PSID headers", n3_hear_headers)
        check("N3 Hear is deterministic; different blobs differ", n3_hear_deterministic)
        check("N2 seed path seals/opens a v9 stream", n2_v9_seed)
        check("Vetted AES-GCM-SIV (or honest 501)", vetted_path)
        check("Logo and staff PNGs are served", index_assets)
        check("Files/Check tabs and piece 2 info", index_piece2)
        check("N2 v9 binary file round-trip with AD", file_n2_roundtrip)
        check("N3 0x1C binary file round-trip with AD", file_n3_roundtrip)
        check("Vetted SIV1 binary file round-trip with AD", file_vetted_roundtrip)
        check("File 1-bit tamper rejection on all engines", file_bitflip_all)
        check("File cross-open N2↔N3 is rejected both ways", file_cross_open)
        check("File oversize and invalid keys are rejected", file_bad_keys_and_oversize)
        check("Vector runner: N2 app vectors 6/6", vectors_n2_app)
        check("Vector runner: N2 score vectors 79/79", vectors_n2_score)
        check("Vector runner: N3 004 AEAD vectors", vectors_n3)

        # Shut the server down via the token if we have it; otherwise terminate.
        if token:
            st, data = http("POST", f"{base}/api/shutdown", {"token": token}, timeout=5)
            expect(st == 200 and data.get("ok"), f"shutdown rejected: {st} {data}")
            # Wait for the process to exit.
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.terminate()
                proc.wait(timeout=5)
                raise Fail("server did not exit after /api/shutdown")
        else:
            proc.terminate()
            proc.wait(timeout=5)

        # Confirm the port is gone.
        time.sleep(0.1)
        still = proc.poll()
        expect(still is not None, "server process still running")
        results.append(("server shut down cleanly", "PASS", ""))
        print("PASS  server shut down cleanly")

    except Exception as e:
        results.append(("harness", "FAIL", str(e)))
        print(f"FAIL  harness: {e}")
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)

    passed = sum(1 for _, s, _ in results if s == "PASS")
    failed = sum(1 for _, s, _ in results if s == "FAIL")
    print()
    print(f"{passed} passed, {failed} failed, {passed + failed} total")
    print(HONEST)
    # Write a machine-readable summary next to the tests for REPORT.md.
    summary = Path(os.environ.get("TMPDIR", "/tmp")) / "octavo_playground_test_results.txt"
    with summary.open("w", encoding="utf-8") as f:
        for name, status, detail in results:
            line = f"{status}  {name}"
            if detail:
                line += f"  — {detail}"
            f.write(line + "\n")
        f.write(f"\n{passed} passed, {failed} failed, {passed + failed} total\n")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
