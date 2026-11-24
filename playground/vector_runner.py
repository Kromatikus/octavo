#!/usr/bin/env python3
"""Run published Octavo test vectors for the playground Check tab.

Octavo is homemade and experimental — for real secrets use AES-GCM-SIV, age, or libsodium.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Optional

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
SCORE_APP = REPO_ROOT / "score" / "app_vectors.json"
SCORE_VECS = REPO_ROOT / "score" / "vectors.json"
IC_DIR = REPO_ROOT / "independent_check"
N3_AEAD = REPO_ROOT / "n3" / "vectors" / "aead_fix2_vectors.txt"
N3_BACKENDS = ("avx512gfni", "avx2gfni", "avx2", "portable")
N3_EXPECTED = "n3/rust/target/release/n3aead"
N3_BUILD_CMD = "cargo build --release --bin n3aead --manifest-path n3/rust/Cargo.toml"

# Import octavo / sneak_n2 from the repository root, not this folder.
sys.path.insert(0, str(REPO_ROOT))


def _resolve_n3aead() -> Optional[Path]:
    raw = os.environ.get("OCTAVO_N3AEAD_BIN")
    if raw:
        p = Path(raw).expanduser()
        return p if p.is_file() and os.access(p, os.X_OK) else None
    p = REPO_ROOT / N3_EXPECTED
    if p.is_file() and os.access(p, os.X_OK):
        return p
    found = __import__("shutil").which("n3aead")
    return Path(found) if found else None


N3_BIN = _resolve_n3aead()


def _ms(t0: float) -> int:
    return int(round((time.perf_counter() - t0) * 1000))


def run_n2_app() -> dict[str, Any]:
    """Six published app-API vectors via octavo.py (3 key expansions + 3 opens)."""
    import octavo

    t0 = time.perf_counter()
    data = json.loads(SCORE_APP.read_text(encoding="utf-8"))
    cases: list[dict[str, Any]] = []
    keys: dict[str, bytes] = {}
    passed = failed = 0

    for k in data["keys"]:
        raw = bytes.fromhex(k["key"])
        try:
            seed = octavo.expand_key(raw)
            ok = seed.hex() == k["seed"]
            note = "" if ok else "expanded seed did not match"
        except Exception as e:
            ok = False
            note = str(e)
        keys[k["id"]] = raw
        passed += int(ok)
        failed += int(not ok)
        cases.append({"id": f"app-key:{k['id']}", "ok": ok, "note": note})

    for b in data["blobs"]:
        ad = bytes.fromhex(b.get("ad_hex") or "")
        try:
            pt = octavo.open_(keys[b["key_id"]], bytes.fromhex(b["blob"]), ad)
            ok = pt.hex() == b["msg_hex"]
            note = "" if ok else "plaintext did not match"
        except Exception as e:
            ok = False
            note = str(e)
        passed += int(ok)
        failed += int(not ok)
        cases.append({"id": f"app-open:{b['id']}", "ok": ok, "note": note})

    total = passed + failed
    return {
        "suite": "n2_app",
        "label": "N2 app vectors (octavo.py)",
        "ok": failed == 0 and total == 6,
        "passed": passed,
        "failed": failed,
        "total": total,
        "expected": 6,
        "elapsed_ms": _ms(t0),
        "cases": cases,
    }


def run_n2_score() -> dict[str, Any]:
    """Full published score: 79 vectors via independent_check/run_check.py."""
    t0 = time.perf_counter()
    if not (IC_DIR / "run_check.py").is_file() or not SCORE_VECS.is_file():
        return {
            "suite": "n2_score",
            "label": "N2 score vectors (independent_check)",
            "ok": False,
            "passed": 0,
            "failed": 0,
            "total": 0,
            "expected": 79,
            "elapsed_ms": _ms(t0),
            "error": "vector files are missing",
        }
    r = subprocess.run(
        [sys.executable, "run_check.py"],
        cwd=str(IC_DIR),
        capture_output=True,
        text=True,
        timeout=90,
    )
    elapsed = _ms(t0)
    out = (r.stdout or "") + (("\n" + r.stderr) if r.stderr else "")
    failed_ids = []
    sections: dict[str, str] = {}
    score_line = ""
    for line in out.splitlines():
        if line.startswith("FAIL "):
            parts = line.split()
            failed_ids.append(" ".join(parts[1:3]) if len(parts) >= 3 else line[5:])
        if line.startswith("SCORE:"):
            score_line = line
        for name in ("block_cipher", "aead", "movements", "rehearsal", "nondemo"):
            if line.strip().startswith(name):
                sections[name] = line.strip()
    # SCORE: 79/79 of 79 vectors match (skipped 0)
    passed = failed = total = 0
    import re
    m = re.search(r"SCORE:\s+(\d+)/(\d+)\s+of\s+(\d+)", out)
    if m:
        passed, counted, total = int(m.group(1)), int(m.group(2)), int(m.group(3))
        failed = counted - passed
        total = counted
    else:
        failed = 1
        total = 79
    return {
        "suite": "n2_score",
        "label": "N2 score vectors (independent_check, 79)",
        "ok": r.returncode == 0 and failed == 0 and passed == 79,
        "passed": passed,
        "failed": failed,
        "total": total or 79,
        "expected": 79,
        "elapsed_ms": elapsed,
        "sections": sections,
        "failed_ids": failed_ids,
        "score_line": score_line,
        "returncode": r.returncode,
    }


def _hex_dash(s: str) -> bytes:
    return b"" if s == "-" else bytes.fromhex(s)


def _parse_aead_fix2(path: Path) -> list[tuple[str, bytes, bytes, bytes, bytes, bytes]]:
    rows = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 5:
            raise ValueError(f"{path.name} line {i}: expected 5 fields, got {len(parts)}")
        seed, nonce, ad, msg, blob = parts
        rows.append((f"aead-fix2-{len(rows)+1}", _hex_dash(seed), _hex_dash(nonce), _hex_dash(ad), _hex_dash(msg), _hex_dash(blob)))
    return rows


def run_n3(backends: Optional[list[str]] = None) -> dict[str, Any]:
    """Live N3 004 AEAD (format 0x1C) vectors, checked with bin/n3aead."""
    t0 = time.perf_counter()
    if N3_BIN is None or not Path(N3_BIN).is_file():
        return {
            "suite": "n3",
            "label": "N3 004 AEAD vectors (n3aead 0x1C)",
            "ok": False,
            "passed": 0,
            "failed": 0,
            "total": 0,
            "expected": 0,
            "elapsed_ms": _ms(t0),
            "error": "The n3aead CLI is not built yet. From the repository root run: " + N3_BUILD_CMD + ". Expected at " + N3_EXPECTED + " (or set OCTAVO_N3AEAD_BIN).",
        }
    rows = _parse_aead_fix2(N3_AEAD)
    use = list(backends or N3_BACKENDS)
    cases: list[dict[str, Any]] = []
    passed = failed = 0
    for backend in use:
        env = os.environ.copy()
        env["OCTAVO_N3_BACKEND"] = backend
        for vid, seed, nonce, ad, msg, blob in rows:
            note = ""
            ok = False
            try:
                ad_arg = ad.hex() if ad else "-"
                seal = subprocess.run(
                    [str(N3_BIN), "seal", seed.hex(), nonce.hex(), ad_arg],
                    input=msg,
                    capture_output=True,
                    timeout=15,
                    env=env,
                )
                if seal.returncode != 0:
                    note = (seal.stderr or seal.stdout or b"").decode("utf-8", "replace")[:200]
                elif seal.stdout != blob:
                    note = f"sealed blob mismatch ({len(seal.stdout)} bytes vs {len(blob)})"
                else:
                    opened = subprocess.run(
                        [str(N3_BIN), "open", seed.hex(), ad_arg],
                        input=blob,
                        capture_output=True,
                        timeout=15,
                        env=env,
                    )
                    if opened.returncode != 0:
                        note = (opened.stderr or opened.stdout or b"").decode("utf-8", "replace")[:200]
                    elif opened.stdout != msg:
                        note = "opened plaintext mismatch"
                    else:
                        ok = True
            except Exception as e:
                note = str(e)
            passed += int(ok)
            failed += int(not ok)
            cases.append({"id": f"{vid}@{backend}", "ok": ok, "note": note, "backend": backend})
    total = passed + failed
    expected = len(rows) * len(use)
    return {
        "suite": "n3",
        "label": "N3 004 AEAD vectors (n3aead 0x1C, four backends)",
        "ok": failed == 0 and total == expected and expected > 0,
        "passed": passed,
        "failed": failed,
        "total": total,
        "expected": expected,
        "vectors": len(rows),
        "backends": use,
        "elapsed_ms": _ms(t0),
        "cases": cases if failed else [{"id": c["id"], "ok": True} for c in cases],
    }


def run_suite(name: str) -> dict[str, Any]:
    name = (name or "").strip().lower()
    if name in ("n2_app", "app", "n2-app"):
        return run_n2_app()
    if name in ("n2_score", "score", "n2-score"):
        return run_n2_score()
    if name in ("n3", "n3_aead", "n3-004"):
        return run_n3()
    if name in ("all", ""):
        t0 = time.perf_counter()
        suites = [run_n2_app(), run_n2_score(), run_n3()]
        return {
            "suite": "all",
            "label": "All vector suites",
            "ok": all(s.get("ok") for s in suites),
            "passed": sum(s.get("passed", 0) for s in suites),
            "failed": sum(s.get("failed", 0) for s in suites),
            "total": sum(s.get("total", 0) for s in suites),
            "elapsed_ms": _ms(t0),
            "suites": suites,
        }
    raise ValueError(f"unknown vector suite {name!r} (try n2_app, n2_score, n3, or all)")


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    result = run_suite(which)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result.get("ok") else 1)
