# Octavo published score

This folder is the published **score**: fixed test vectors for the staff-core
and for both sealed modes, together with a generator that rebuilds them.

Homemade. **Not for real secrets.** Use AES-GCM-SIV, age or libsodium.

## Files

- `vectors.json` — the committed score.
- `generate_score.py` — rebuilds `vectors.json` from the live code and the
  fixed inputs below. Run `python3 score/generate_score.py` from this tree
  (or pass the script path). The test suite regenerates the vectors in
  memory and compares them to this file.

## What is in the score

64 vectors, all under the demo seed `sneak1024-seed.txt` (full hex and SHA-256
are in the JSON):

- **16 raw block-cipher (keyed permutation) vectors.** Four 128-byte
  plaintexts (`zero`, `ff`, `seq` = `00..7f`, and the encoded `hello world`
  block) at 2, 4, 6 and 16 rounds, with schedule nonce
  `0123456789abcdef0123456789abcdef`. Each entry gives the plaintext and
  ciphertext in hex.
- **24 single-block AEAD vectors.** Message lengths 0, 1 and 127, with and
  without associated data `from:alice`, at 2, 4, 6 and 16 rounds. Pickup
  `000102…0e0f` is used with empty AD; pickup `101112…1e1f` is used with AD.
  The nonce is the ordinary SIV nonce for that pickup, message and AD.
  Blobs small enough to sit in the file are given in hex, always with
  SHA-256 and length.
- **24 movements-mode vectors.** Payloads of 0, 128, 1000 and 4096 bytes,
  plus 128- and 1000-byte messages with AD, at 2, 4, 6 and 16 rounds.
  Large messages are identified by SHA-256 and length (the generator
  rebuilds them). Blobs longer than 2048 bytes are recorded the same way.

## Études, not the normal APIs

These AEAD vectors are **étude blobs** (score version 3, conductor
revision). They use distinct format-version bytes so the normal
`decrypt` / `decrypt_movements` APIs reject them, and they carry the same
32-byte tuning commitment as live v6/v7 blobs (associated data, and nmov
in movements, are bound in the commitment):

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
hashed into the SIV nonce. So no étude vector shares round material with
a live blob, and an étude handle cannot open a live ciphertext.

**What changed from the tuning-fix score** (never published): the bytes
were `0xA2`/`0xA4`/`0xA6`/`0xB0` and `0xA3`/`0xA5`/`0xA7`/`0xB1`, études
used the live seed directly, and the 16-round étude ciphertext equalled the
live ciphertext. All 64 vectors changed. Those bytes are now rejected.
Pre-tuning étude bytes from the published octavo009 score
(`0xE2`/`0xE4`/`0xE6`/`0xF0` and `0xE3`/`0xE5`/`0xE7`/`0xF1`, frozen in
`/workspace/octavo009/score`) open only through `Etude.decrypt_legacy()` /
`decrypt_movements_legacy()` with `allow_noncommitting=True`; they are not
key-committing. Unpublished tuning étude bytes (`0xC2`…/`0xD1`) are rejected.

The demo seed is a **public demo seed**; `etude(r)` refuses it (and
`seed=None`) unless made with `lab_seed=True`, which the generator uses.

2-, 4- and 6-round études are weakened on purpose, for cryptanalysis only.
A 16-round étude is published so another implementation can check itself
against the full cipher core: the 16-round raw permutation equals live
`encrypt_grid` under `Schedule(K_e, nonce)`. It is no longer equal to the
live cipher under the raw seed, by design.

The lab API is `etudes.etude(rounds, lab_seed=False)` in the parent directory. It accepts a
fixed `pickup` so these vectors stay deterministic. Normal `encrypt` and
`encrypt_movements` have no pickup argument and always run 16 rounds.

Full-round live blobs (`hello-world.txt`, `movements-demo.txt`) are the
samples for the ordinary version-6 and version-7 APIs, and also carry
an AD-bound (and, for movements, nmov-bound) tuning commitment.

## Live rehearsal vectors (score versions 4, 5, 6 and 7)

Since the rehearsal revision the score also holds **8 live format-version-8
rehearsal stream vectors** (full 16 rounds, demo seed, pinned pickup and
stream nonce, listed in the JSON), so it has 72 vectors in all. Score
version 5 (rehearsal-fix) regenerated those 8 vectors because the AD
digest now enters the R-sponge chunk keys, tweaks and schedule nonce. v8
was never published, so there is no legacy v8. Score version 6
(rehearsal-polish) regenerated them again: the rehearsal digest attests the
whole v8 API code (file helpers and workers included), the polish fixes
changed that code, so `rehearsal_sig` and therefore every chunk **tag**
changed. Headers and ciphertext blocks are byte-identical to score version 5
(same pinned pickup and nonce). Score version 7 (rehearsal-finale)
regenerated them once more for the same reason: the rehearsal-polish attack
fixes changed attested v8 API code, so `rehearsal_sig` and every chunk tag
moved, while headers and ciphertext blocks are byte-identical to score
version 6. The 64 étude vectors above are unchanged.
