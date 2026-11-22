#!/usr/bin/env python3
"""Locate this repository's Python Octavo sources (`sneak_n2.py` and `score/`).

Default: the git repo root (two parents above this file, which lives in rust/tools/).
Override with the OCTAVO_PY_DIR environment variable if the Python tree is elsewhere.
"""
from __future__ import annotations

import os
from pathlib import Path

EXPECT_SHA256 = "19181bc1623115c075dc5dee25edec388f5413466777d47b7f19fa66d1e71eee"


def py_dir() -> Path:
    override = os.environ.get("OCTAVO_PY_DIR")
    if override:
        return Path(override).expanduser().resolve()
    return Path(__file__).resolve().parents[2]
