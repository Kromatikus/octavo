# Changelog

Facts below are taken from the existing repository docs. This is not a complete
list of every historical revision; those remain in [README.md](README.md).

**Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.**

## 2026-11-22

- Published a byte-compatible [Rust port](rust/) and the `octavo` CLI in
  `rust/` on GitHub (commit `afa6659`), including `hear --midi` and
  `hear --sid` / `--sid-wav` (C64 SID). The cipher and formats are unchanged
  versus `sneak_n2.py` SHA-256 `19181bc1…e71eee`.
- In-house dudect timing tests: no evidence of a leak in the data path, tag
  compares, streaming open, or the VPSLLVW bow rotation; expected flags for
  key-schedule rejection sampling, valid-vs-tampered early exit, and a known
  many-key cache effect on `gfni-simd`. See [rust/dudect/REPORT.md](rust/dudect/REPORT.md).
- Fresh-clone fixes: test scripts and Python cross-compat use this
  repository's `sneak_n2.py` (or `$OCTAVO_PY_DIR`) instead of a machine-local
  path; `tools/run_all.sh` checks the committed `diff_random.json` fixture
  instead of rewriting it; README build steps work without `--offline`.

## 2026-11-21

- Independent checker in `independent_check/`, written from [SPEC.md](SPEC.md)
  alone, rebuilds all 79 score-v11 vectors and the 6 app vectors. Cipher unchanged.
- In-house reduced-round tests and automated trail search reports in
  [analysis/](analysis/). Cipher unchanged.

## 2026-11-15

- Live Python revision **rehearsal-honest2** (current). Fixes from the
  in-house rehearsal-honest attack (L1, L2, I1–I6). No ciphertext change:
  v6, v7 and v9 blobs, `key_sig` and `rehearsal_sig` are byte-identical to
  the previous revision. Score version 11 (79 vectors unchanged; header adds
  published SHAs for `etudes.py` and `generate_score.py`).
- App-ready `octavo.py` wrappers (`seal` / `open_`, 32- or 64-byte keys via
  HKDF-SHA512), `pip install .` as `octavo-demo` 0.1.0. Cipher unchanged.

Earlier Python revisions (rehearsal-honest back through packaging, beat and
bow work, and so on) are recorded in the README revision history.
