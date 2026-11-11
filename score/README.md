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

These AEAD vectors are **étude blobs**. They use distinct format-version
bytes so the normal `decrypt` / `decrypt_movements` APIs reject them:

| Rounds | Single-block | Movements |
|--------|--------------|-----------|
| 2      | `0xE2`       | `0xE3`    |
| 4      | `0xE4`       | `0xE5`    |
| 6      | `0xE6`       | `0xE7`    |
| 16     | `0xF0`       | `0xF1`    |

2-, 4- and 6-round études are weakened on purpose, for cryptanalysis only.
A 16-round étude is published so another implementation can check itself
against the full cipher: the raw permutation and the ciphertext (not the
tag) are byte-identical to live `encrypt_grid` / `encrypt` on the same
input. Tags differ because they bind the étude version byte.

The lab API is `etudes.etude(rounds)` in the parent directory. It accepts a
fixed `pickup` so these vectors stay deterministic. Normal `encrypt` and
`encrypt_movements` have no pickup argument and always run 16 rounds.

Full-round live blobs (`hello-world.txt`, `movements-demo.txt`) are unchanged
in this revision; they remain the samples for the ordinary version-2 and
version-3 APIs.
