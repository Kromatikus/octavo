# Independent Octavo checker

A from-scratch reimplementation of Octavo written **only from `SPEC.md`** (plus
`score/README.md` and the `kdf` block of `score/app_vectors.json`). It never imports or copies
`sneak_n2.py`, `octavo.py` or `etudes.py`; `run_check.py` asserts that at the end.

It rebuilds all **79 score-v11 vectors** byte for byte and opens them again
(16 permutation, 24 étude AEAD, 24 étude movements, 8 v9 rehearsal, 7 non-demo), checks
`key_sig` / `rehearsal_sig` for both published seeds, and opens the **6 app vectors**
(3 HKDF key expansions + 3 v6 blobs). `check_samples.py` opens the three live samples
(`hello-world.txt` v6, `movements-demo.txt` v7, `rehearsal-demo.txt` v9) and checks that
single-bit tampering is rejected.

Run from the repo root (pure Python 3, no dependencies):

    python3 independent_check/run_check.py          # full, about 15 s
    python3 independent_check/run_check.py --quick  # skips the 70,000-byte rehearsal vector
    python3 independent_check/check_samples.py

Files:
- `ic_core.py`: StaffSponge, key schedule, keyed SM4-affine S-boxes, every round layer and its inverse
- `ic_octavo.py`: the v6 and étude single-block format, v7 and étude movements, v9 rehearsal, app HKDF
- `sm4_sbox.py`: the SM4 S-box from the public IETF draft draft-ribose-cfrg-sm4-10, §6.2.3

Building it showed several details the spec left open. They are now written out in `SPEC.md`,
"Implementer's reference (2026-11-21)". This checker is a conformance check, not a security
review, and it is not constant-time.

**Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.**
