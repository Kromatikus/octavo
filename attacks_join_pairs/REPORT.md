# Attack report: LIVE N2 after the join-pairs fix (beats 3–4 and 5–6 now mixed)

> **Homemade, unreviewed cipher. Not for real secrets.** Use AES-GCM-SIV (RFC 8452), age, or libsodium for anything real. This is cryptanalysis only. Nothing in the cipher was changed, and nothing here shows the cipher is secure.

- **Date:** Sunday 2026-11-08, about 1:58–2:15 PM EST (America/New_York).
- **Target:** `/workspace/sneak_n2/sneak_n2.py`, imported live, SHA-256 `118a6729…d865`. I checked the source against the brief and it matches. Each round is XOR rk → S → weave → butterfly → shell bridges → bar_mix (7 mixes: B0, B1, **M2 (2,3) ((3,5),(1,2))**, B2, **M3 (4,5) ((5,2),(2,1))**, B3, B4) → S2 → encore (the same bar_mix again). Staffs are unlooped: there is no (7,0) pair. The blob is `SN2 || nonce || ct || HMAC-SHA256(mac_key, clef||SN2||nonce||ct)`, 179 bytes, and the nonce is SIV: `SHA-256(clef||encode_block(msg))[:16]`.
- **Hello-world check:** The live demo blob from `hello-world.txt` decrypts to `b'hello world'`. Re-encrypting gives the identical blob. Nonce `b98b9c38…0eb3`, tag `8ad949ee…9e76`.
- **Scope:** Black-box API tests, plus white-box reduced-round and structural tests that use the known seed. The reduced-round tests feed raw 128-byte blocks, which an outsider cannot submit through `encrypt()`.
- **Untouched:** 668 protected files were byte-identical before and after (`protected_verification.txt`). That covers the live library, tests, SPEC, README, render, hello-world, test_results, the seed, all `/workspace/*.png`, `test1`, `test3`, `test13`, `testn1`, `testn3`, `sneak_t1n`, `sneak_v2`–`v13`, `attacks/`, `attacks_8bit/`, `attacks_siv/`, `baselines/`, and every `/tmp/sneak_n2_*` backup. Old libraries were loaded read-only by file path. I made no fixes, did not start N3, and drew no PNGs.

## Verdict
The full 16-round cipher with whitening was **not broken** in these tests. I recovered no plaintext, seed, clef, or MAC forgery. **That is a negative experimental result, not a security proof.**

The joins do what they were meant to do. They remove the block-diagonal encore. However, reduced-round distinguishers are still easy at 1 and 2 rounds. High-bit (Δ=0x80) differences still slip through the even coefficients with probability 1 and touch only one cell. The deterministic-AE dictionary attack still works. Pre-join blobs still pass the tag. It is still homemade and **not for real secrets**.

## Closed or confirmed holding (re-measured on live code)
| Item | Status | Witness |
|---|---|---|
| Encore beat-group isolation {0,1,2},{3,4},{5,6,7} | **CLOSED** | The live encore's 8×8 per-staff matrix forms **one** super-box component [0..7]. The pre-join matrix measured with the same code gives three: [[0,1,2],[3,4],[5,6,7]]. The isolated 16/24-bit super-boxes are gone (`attack_structure_mixes_output.txt`). |
| Per-cell S2→XOR→S fusion | **Still closed** | Every next-round S input depends on at least 2 S2 outputs. Beat 0 depends on {0,1}, and beat k on {0..k+1}. |
| Beat-dependence through the round | 1 round: 5,504 of 16,384 byte pairs depend. **2 rounds: 16,384 of 16,384** (white-box support and an empirical test agree). | Full byte dependence comes at round 2, matching `test_results.txt`. |
| HMAC tag | **Holds** | All 1,432 single-bit flips of the hello blob gave AuthError (1,408 tag mismatch, 24 bad prefix). 500 ct corruptions, 200 splices, 1,000 random SN2 blobs, 200 random blobs, and 5 wrong lengths also all gave AuthError. 0 plaintexts. |
| Old generations | **Rejected at the tag** | 4-bit: 300/300 bad length. Pre-bar, pre-color2, and pre-clef: 300/300 each gave AuthError tag mismatch, and each archived hello blob did too. |
| SIV nonce binding | **Holds** | A caller-chosen nonce raises ValueError. Reusing msg A's nonce for msg B raises ValueError. `encrypt()` never calls `os.urandom`. A white-box nonce-reuse blob that carries a valid tag fails with `AuthError: SIV nonce mismatch`. |
| Key schedule | **No new hole** | 1-bit nonce and seed flips change about 0.50 of the schedule material and 107–141 of the 256 MAC-key bits. A seed flip changes 52–77 of the 128 clef bits. The M, K, and C domains are distinct. |
| No AES | **Confirmed** | There is no AES S-box head and no crypto import. The base table is SM4 (`d690e9fe…`). Keyed S has DDT 4 and LAT 16. **Disclosure:** SM4 and AES S-boxes both belong to the inversion-in-GF(2^8) family; they are affine-equivalent to inversion. |

## Leftovers that remain (with witnesses)
1. **Deterministic-AE dictionary attack (live demo).** The script drew a random 4-digit demo PIN, **5851**, and encrypted `PIN:5851`. Encrypting guesses `PIN:0000`… until one matched the blob found it in **5,852 guesses (106 s)**. Matching blob nonce: `da63c542f773fe2ded3530836f8ecdee`. The full blob is in `attack_siv_pin_results.json`. Identical messages also produce identical blobs (an equality leak).
2. **Pre-join blobs pass the live tag.** Clef, MAC key, and the `SN2` prefix are unchanged; MAC keys for the same nonce are identical. The archived testn3 hello blob and the `/tmp/sneak_n2_pre_join_pairs` hello blob both have `tag_valid_under_live_mac=True` and give `DecodeError`. Generated samples:
   - `/tmp/sneak_n2_pre_join_pairs` library: 2,000 blobs → **1,993 DecodeError, 7 `AuthError: SIV nonce mismatch`, 0 plaintexts**.
   - testn3 library: 300 blobs → **296 DecodeError, 4 SIV-mismatch, 0 plaintexts**.
   - Why: about 1/256 of the decrypted random blocks have b[0]=127, which passes decode. They are then caught by the SIV recheck. A wrong plaintext would need a 128-bit truncated SHA-256 match. That is not a guarantee, but it is about 2^-128 per blob, not the old "decode luck."
3. **Δ=0x80 still crosses mixes as a single cell (even coefficients).** No invertible 2×2 mod 256 can have all four entries odd (all odd ⇒ ad−bc even). Exhaustive test over all 65,536 (u,v) pairs and all 255 single-cell XOR deltas:
   | Mix | Matrix | Even coeffs | Single-cell output with probability 1 |
   |---|---|---|---|
   | B0 start (0,1) | ((1,5),(1,6)) | 6 | v Δ0x80 → first output only |
   | B1 bar 2 (1,2) | ((1,1),(1,2)) | 2 | v Δ0x80 → first |
   | M2 3–4 (2,3) **new** | ((3,5),(1,2)) | 2 | v Δ0x80 → first |
   | B2 center (3,4) | ((1,3),(1,4)) | 4 | v Δ **0x40, 0x80, 0xC0** → first |
   | M3 5–6 (4,5) **new** | ((5,2),(2,1)) | 2, 2 | u Δ0x80 → first; v Δ0x80 → second |
   | B3 bar 6 (5,6) | ((2,1),(1,1)) | 2 | u Δ0x80 → second |
   | B4 end (6,7) | ((3,1),(2,1)) | 2 | u Δ0x80 → first |
   | mix2 butterfly/shell | ((1,1),(1,2)) | 2 | v Δ0x80 → first |
   
   Every other delta gives a single-cell output with probability 0. M3 has two even coefficients, so it leaks in both directions. In the full encore, Δ0x80 on input beats 1–5 reaches **exactly one** output beat with probability 1 (1→0, 2→1, 3→2, 4→3, 5→6). Beat 4 also passes 0x40/0xC0 to a single beat. In the round's linear middle (weave + butterfly + shell + 7 bars), Δ0x80 at round-0 S-output cells 9, 18, 21, 29, 37, 53, and 56 reaches **exactly one S2 cell** with probability 1. Rounds 1 and 2 have 6 and 5 such cells.
4. **1-round truncated differential, demonstrated.** Start with a plaintext difference in cell 18 (face 2, beat 2). Whenever the round-0 S output difference is 0x80, only S2 cell 38 is active, so the 1-round output difference is confined to bytes **{37,38,39}**. Measured over 200,000 pairs:
   - random δ: 774 pairs (2^-8.0)
   - best white-box δ: 3,137 pairs (2^-6.0)
   
   For a random permutation this is about 2^-1000. Cells 37 and 9 behave the same way: 4 and 7 bytes, at 2^-8 and 2^-6. Control cells 0 and 64 never had fewer than 11 or 17 active bytes.
5. **2-round distinguisher, demonstrated.** I counted pairs whose output difference had ≥8 zero bytes, over 128 × 4,096 single-byte-difference pairs:
   - 2 rounds: **252 pairs, against 0.027 expected for random**. The best input cell (20) does it at about 2^-7.6.
   - Witness: an input difference in cell 20 left **53 zero bytes** after 2 rounds, verified with `N.encrypt_grid`.
   - 2-round statistics also deviate: the zero-diff-byte χ² is 206 on 127 df, above the 99.9% critical value of about 181, and the minimum avalanche was 310 bits against a mean of 512.
   - A 2-round all-0x80 truncated trail from cell 18 is estimated at about 2^-30 white-box and 2^-32 black-box. It is **estimated only, not demonstrated**.
6. **Bit-level leftovers in the encore.** Mod-256 LSBs are GF(2)-linear. The odd-coefficient support is small: the LSB of next-round S input beat 4 is the LSB of S2 beat 0 XOR a key bit. Beats 5 and 7 likewise get their LSB from a single S2 beat (6 and 7). The unlooped staff is still directional within one encore: output beat 0 sees only inputs {0,1}, and input beat 7 reaches only outputs {6,7}. After one full round every output cell depends on at least 24 input cells. After 2 rounds dependence is full. I did not turn this into an attack.

## Reduced-round results (white-box, raw blocks)
| Rounds | Byte dependence | Bit avalanche mean (sd, min) | Zero-diff χ² (df 127) | Δ0x80@18 histogram χ² (df 255) | Status |
|---|---|---|---|---|---|
| 1 | 5,504/16,384 | 169.9 (31.4, min 24) | 9.6e8 | 268.5 | **Distinguisher demonstrated** (dependence plus the 3-byte truncated differential) |
| 2 | full | 512.0 (16.3, **min 310**) | **206.0** | 213.3 | **Distinguisher demonstrated** (252 sparse pairs against 0.027) |
| 3 | full | 511.8 (16.1, min 459) | 149.2 | 296.5 | Not detected in these tests (0 sparse pairs out of 524,288) |
| 4 | full | 512.2 (15.7, min 457) | 156.4 | 242.1 | Not detected in these tests |
| 16 | full | 512.8 (16.2, min 458) | 131.8 | 260.2 | Not detected in these tests |

"Not detected in these tests" does not mean no distinguisher exists.

## Files
`attack_integrity_legacy.py`, `attack_siv_pin.py`, `attack_structure_mixes.py`, `attack_highbit_trail.py`, `attack_rounds_diffusion.py`, `attack_two_round_sparse.py`, `attack_schedule_noaes.py`. Each has an `*_output.txt` and a `*_results.json`. Also `common.py` (a NumPy accelerator, cross-checked against `N.round_enc`), `snapshot_protected.py`, and `protected_*.json` / `protected_verification.txt`.

## Bottom line
The joins closed the beat-group super-box isolation they targeted. The tag and SIV binding hold, and 3+ round distinguishers were not detected here. Still open: easy 1- and 2-round distinguishers, probability-1 high-bit single-cell crossings in every mix, a dictionary attack on low-entropy messages, and same-version blob acceptance at the tag. **Still homemade. Not for real secrets. Use AES-GCM-SIV, age, or libsodium.**
