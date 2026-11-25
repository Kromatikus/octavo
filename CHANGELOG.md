# Changelog

Facts below are taken from the existing repository docs. This is not a complete
list of every historical revision; those remain in [README.md](README.md).

**Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.**

## 2026-11-25

- N3 Hear now renders three voices in WAV, MIDI and SID: the original 16-note
  melody (notes text unchanged), plus a slow pentatonic bass and a quieter
  harmony line, all derived from the sealed 0x1C blob. Display only — the N3
  cipher, 0x1C format, and vectors are unchanged.
- N3 Hear gained `--style ultima`: an original 3-voice chiptune texture in the
  spirit of 1980s Ultima III/IV (bright pulse lead, driving bass, fast
  arpeggios, 130–150 bpm, modal minor). It does not copy any Ultima tune.
  Default `--style earworm` is unchanged. The playground Hear blob (N3) button
  offers the choice.

## 2026-11-24

- Added a local localhost playground under [`playground/`](playground/) for
  trying **N2** (still the default), experimental **N3**, and a vetted
  AES-256-GCM-SIV path (text, files, and published test vectors). It binds to
  `127.0.0.1` only and does not write keys to disk automatically.
- N3 Hear: `n3/python/n3_music.py` renders WAV, MIDI and SID from a sealed
  0x1C blob by reusing N2's earworm renderer. Display only — the N3 cipher,
  format, and vectors are unchanged. The playground Hear button works for N3
  blobs too.
- No N2 or N3 cipher code or formats were changed. See
  [playground/README.md](playground/README.md).

## 2026-11-23

- Added the experimental N3 lab snapshot (`octavo_n3_004`) under [`n3/`](n3/)
  (block format `SN3C/` 0x1B, authenticated format `SN3C/` 0x1C, N3-PMAC-SIV).
  **N2 remains the default** (`sneak_n2.py`, `octavo.py`, [`rust/`](rust/)).
  No existing N2 code or formats were changed.
- N3 is a new cipher and a new blob format. It does not open N2 v6 / v7 / v9
  (`SN2`) data, and N2 does not open N3 data. Existing users who want to try N3
  must re-encrypt: decrypt with N2, verify, seal with `n3aead`, verify the
  round-trip. See [n3/MIGRATION.md](n3/MIGRATION.md) and `n3/migrate.py`.
- Recommend a **fresh** 1024-bit N3 seed. Do not reuse the public N2 demo seed
  or an N2 app key (32/64-byte HKDF input).
- Known limits: no external review of N3; lab CLI `n3aead` takes the seed as
  command-line hex; no MIDI/score in this snapshot.

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
