# Octavo published score

This folder is the published **score**: fixed test vectors for the staff-core
and for the sealed modes, together with a generator that rebuilds them.

Homemade. **Not for real secrets.** Use AES-GCM-SIV, age or libsodium.

The current score is **version 10** (revision `rehearsal-chainfix`,
2026-11-14). It holds **79 vectors**: the 72 vectors of score version 9,
byte-identical, plus 7 new vectors under a published non-demo test seed.
The JSON also records the live `sneak_n2.py` SHA-256 (`48d261e3…`),
`EXPECTED_MIX_SHA256` (`b6e0fa2a…`), `EXPECTED_REHEARSAL_SHA256`
(`d0550f7f…`), `EXPECTED_SEED_POLICY_SHA256` (`ab5cdce4…`), and, for the
demo seed, `key_sig` (`340dc1e0…`) and `rehearsal_sig` (`07172e74…`).

## Files

- `vectors.json` — the committed score.
- `generate_score.py` — rebuilds `vectors.json` from the live code and the
  fixed inputs below. Run `python3 score/generate_score.py` from this tree
  (or invoke the script by path). This overwrites `vectors.json`. The test
  suite regenerates the vectors in memory (`build_vectors()`) and compares
  them to this file.
- `nondemo-test-seed.txt` — the published non-demo test seed (128 bytes).

Legacy format-version-8 rehearsal vectors live next to this folder, in
`legacy_v8/`.

## What is in the score

**72 vectors under the public demo seed** `sneak1024-seed.txt` (full hex
and SHA-256 are in the JSON). This seed is public; it is not a key.

- **16 raw block-cipher (keyed permutation) vectors.** Four 128-byte
  plaintexts (`zero`, `ff`, `seq` = `00..7f`, and the encoded `hello world`
  block) at 2, 4, 6 and 16 rounds, with schedule nonce
  `0123456789abcdef0123456789abcdef`. Each entry gives the plaintext and
  ciphertext in hex. These use the étude key `K_e` (see below), not the raw
  demo seed as a schedule key.
- **24 single-block AEAD vectors.** Étude blobs. Message lengths 0, 1 and
  127, with and without associated data `from:alice`, at 2, 4, 6 and 16
  rounds. Pickup `000102…0e0f` is used with empty AD; pickup `101112…1e1f`
  is used with AD. The nonce is the ordinary SIV nonce for that pickup,
  message and AD (the étude version byte is hashed in). Every blob is 228
  bytes and is given in hex, always with SHA-256 and length.
- **24 movements-mode vectors.** Étude blobs. Payloads of 0, 128, 1000 and
  4096 bytes, plus 128- and 1000-byte messages with AD, at 2, 4, 6 and 16
  rounds. Messages longer than 128 bytes are identified by SHA-256 and
  length (the generator rebuilds them). Blobs longer than 2048 bytes
  (`blob_hex_limit`) are recorded the same way; that is the four 4096-byte
  movements blobs (5384 bytes each).
- **8 live format-version-9 rehearsal stream vectors.** Full 16 rounds,
  demo seed, pinned pickup and stream nonce, listed in the JSON. These are
  ordinary `encrypt_rehearsal` / `decrypt_rehearsal` blobs, not études.
  Payloads of 0, 1, 127 and 128 bytes at chunk size 128, 1000 bytes with
  and without AD at chunk size 256, 4096 bytes at chunk size 1024, and
  70000 bytes at chunk size 65536. Pickup `000102…0e0f` and stream nonce
  `202122…2e2f` are used with empty AD; pickup `101112…1e1f` and stream
  nonce `303132…3e3f` are used with AD. In v9 every chunk tag also covers
  the previous chunk's tag (`tag_{-1}` is 32 zero bytes), and the v9 sponge
  labels carry the version byte. The header is `version(1)=9 || SN2(3) ||
  pickup(16) || nonce(16) || commit(32) || chunk_size(4, uint32be)`. Blobs
  longer than 2048 bytes (the 4096- and 70000-byte cases) are recorded as
  SHA-256 and length; `generate_score.rehearsal_blob(id)` rebuilds them.
  `final_tag` is always recorded.

**7 vectors under the published non-demo test seed**
(`score/nondemo-test-seed.txt`), defined as
`SHAKE-256("Octavo published non-demo test seed v1", 128 bytes)`. The file
is public, so this seed is not a key. The JSON records that seed's
`key_sig` (`399f98cf…`) and `rehearsal_sig` (`4bc90949…`). The seven
vectors are:

- `nondemo-v6-hello` — live `encrypt` (v6), `hello world`, empty AD
- `nondemo-v6-127-ad` — live `encrypt` (v6), 127-byte message, AD `from:alice`
- `nondemo-v7-1000` — live `encrypt_movements` (v7), 1000-byte message, empty AD
- `nondemo-v7-128-ad` — live `encrypt_movements` (v7), 128-byte message, AD `from:alice`
- `nondemo-v9-128-cs128` — live `encrypt_rehearsal` (v9), 128-byte message, chunk size 128, empty AD
- `nondemo-v9-1000-ad-cs256` — live `encrypt_rehearsal` (v9), 1000-byte message, chunk size 256, AD `from:alice`
- `nondemo-etude-r4-aead-1-ad` — 4-round étude block (`0x84`), 1-byte message, AD `from:alice`

They use the same pinned pickups (and, for v9, the same stream nonces) as
the demo-seed vectors. All seven blobs are given in hex. They exist so a
change that affects only non-demo keys is visible in the score
(rehearsal-chain attack L1). The generator documents that they were made
by the rehearsal-chain code and reproduce byte for byte on
rehearsal-chainfix.

## Études, not the normal APIs

The 64 permutation, single-block and movements vectors are **étude blobs**
(unchanged since score version 3, conductor revision). They use distinct
format-version bytes so the normal `decrypt` / `decrypt_movements` APIs
reject them, and they carry the same 32-byte tuning commitment as live
v6/v7 blobs (associated data, and nmov in movements, are bound in the
commitment):

| Rounds | Single-block | Movements |
|--------|--------------|-----------|
| 2      | `0x82`       | `0x83`    |
| 4      | `0x84`       | `0x85`    |
| 6      | `0x86`       | `0x87`    |
| 16     | `0x90`       | `0x91`    |

**Key separation.** Every étude runs under its own derived key
`K_e = StaffSponge(b"E", seed, bytes([rounds]) + 15 zero bytes).take(128)`
(SHA-256 of each `K_e` is in the JSON), used for clef, commitment, MAC,
Schedule, theme, tweak, cadence and coda. The étude version byte is also
hashed into the SIV nonce. So no étude vector shares round material with a
live blob, and an étude handle cannot open a live ciphertext.

The demo seed is a **public demo seed**. `etude(r)` refuses it, and
`seed=None`, unless the handle is made with `lab_seed=True`, which the
generator uses. On the live v6/v7/v9 APIs, `seed=None` raises
`TypeError`; use `keygen()` or `load_seed()`.

2-, 4- and 6-round études are weakened on purpose, for cryptanalysis only.
A 16-round étude is published so another implementation can check itself
against the full cipher core: the 16-round raw permutation equals live
`encrypt_grid` under `Schedule(K_e, nonce)`. It is not equal to the live
cipher under the raw seed, by design.

The lab API is `etudes.etude(rounds, lab_seed=False)` in the parent
directory. It accepts a fixed `pickup` so these vectors stay
deterministic. Normal `encrypt`, `encrypt_movements` and
`encrypt_rehearsal` have no pickup argument and always run 16 rounds.

## Live samples (v6 / v7 / v9)

Full-round live blobs in the parent directory are the samples for the
ordinary APIs: `hello-world.txt` (version 6), `movements-demo.txt`
(version 7) and `rehearsal-demo.txt` (version 9). The v6 and v7 samples
also carry an AD-bound (and, for movements, nmov-bound) tuning
commitment.

## Legacy v8

Score version 8 (rehearsal-curtain, published with octavo014) was the last
score whose rehearsal vectors were format version 8. Those 8 vectors are
kept in `legacy_v8/score8_rehearsal_v8.json` (same case ids as the live v9
rehearsal set). They open only through
`decrypt_rehearsal_legacy(..., allow_unchained=True)`, which emits
`LegacyFormatWarning` on every call. `decrypt_rehearsal` rejects v8 as
`UnsupportedVersion`. A v8 sample stream is also in
`legacy_v8/rehearsal-demo-v8.txt`.

## Regenerating and verifying

From this tree:

    python3 score/generate_score.py

rebuilds and overwrites `score/vectors.json` from the live code and the
fixed inputs above. The test suite (`python3 test_sneak_n2.py`)
regenerates the score in memory with `score.generate_score.build_vectors()`
and requires it to equal the committed file, including `score_version == 10`
and counts `{block_cipher: 16, aead: 24, movements: 24, rehearsal: 8,
nondemo: 7, total: 79}`. `python3 quick_check.py` decrypts the published
v6 and v9 samples and checks that the committed score is version 10 with
79 vectors; it does not regenerate the file.

`load_seed` on `score/nondemo-test-seed.txt` must match the SHAKE-256
definition above, or the generator raises.

## Earlier score versions

- **Version 3** (conductor) introduced the 64 étude vectors above, which
  have been byte-identical in every later score. The unpublished
  tuning-fix étude bytes (`0xA2`/`0xA4`/`0xA6`/`0xB0` and
  `0xA3`/`0xA5`/`0xA7`/`0xB1`) and unpublished tuning bytes (`0xC2`… /
  `0xD1`) are rejected. Pre-tuning étude bytes from the published
  octavo009 score (`0xE2`/`0xE4`/`0xE6`/`0xF0` and
  `0xE3`/`0xE5`/`0xE7`/`0xF1`) open only through `Etude.decrypt_legacy()` /
  `decrypt_movements_legacy()` with `allow_noncommitting=True`; they are
  not key-committing.
- **Versions 4–8** added, then repeatedly regenerated, 8 live
  format-version-8 rehearsal vectors as the attested rehearsal code
  changed (`rehearsal_sig` and every chunk tag moved; in versions 6–8 the
  headers and ciphertext blocks stayed byte-identical to the previous v8
  score). Version 8 (rehearsal-curtain) is the last v8 score; those
  vectors are the ones in `legacy_v8/`.
- **Version 9** (rehearsal-chain) regenerated the 8 rehearsal vectors as
  format version 9 (chained tags and v9 sponge labels), so headers,
  ciphertext blocks and tags all changed. The 64 étude vectors were
  unchanged. Total: 72 vectors.
- **Version 10** (rehearsal-chainfix) adds the 7 non-demo vectors. The 72
  version-9 vectors are byte-identical. Total: 79 vectors.
