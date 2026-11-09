# Attack report — Sneak staff-core N2 (homemade 512-bit block cipher + HMAC-SHA256 seal)

> **N2 is a homemade, unreviewed scheme. Do not use it for real secrets.** For anything that matters use **AES-GCM-SIV (RFC 8452), age, or libsodium**. This report attacks N2; it does not fix it.

- **Date:** 2026-11-08
- **Scope:** `/workspace/sneak_n2/sneak_n2.py` (unchanged), attacked black-box and white-box by importing the real internals.
- **Untouched:** every N2 source (library, SPEC, tests, render, demo files), all of N1 (`sneak_t1n/`), and the frozen snapshots (`test1/ test3/ test13/ testn1/`). Only this `attacks/` directory was added.

| Script | Output | Covers |
|---|---|---|
| `attack_integrity_n2.py` | `attack_integrity_output.txt` | random & SN2-prefixed blobs, every bit-flip class, byte corruption, splicing, truncation/extension, seedless chosen-message forgery, decode-success oracle, compare_digest |
| `attack_schedule_n2.py` | `attack_schedule_output.txt` | GF(2)-affineness of seed/nonce→material, the direct N1 inversion, domain separation, seed-leak-into-stream, counter, int-vs-bytes seed, avalanche |
| `attack_rounds_n2.py` | `attack_rounds_output.txt` | DDT/LAT of the keyed S-boxes, dependency/codebook split, Δ=8 and LSB-linear trails, integral/zero-sum, zero-difference, chi-bits, avalanche, reduced→full round distinguishers |
| `attack_nonce_n2.py` | `attack_nonce_output.txt` | nonce-reuse equality leak, keystream test, yes/no/maybe oracle guesser, ciphertext-only |

## Verdict (top line)
**Full 16-round N2 was not broken, and the two structural holes that defined N1 are closed.**
- **Integrity now holds.** 0 of 200,000 random blobs, 0 of 10,000 blobs carrying the correct `SN2` prefix (and 0 with the correct public nonce), and 0 of all 920 single-bit flips of a valid blob were accepted. N1 silently accepted about **1 in 255** random ciphertexts and 2–3 of 512 bit flips. No seedless forgery was found (HMAC-SHA256, ~2²⁵⁶).
- **The key-schedule seed leak is gone.** N1's schedule was GF(2)-linear, so one round's material plus the public nonce gave back the whole 1024-bit seed. N2's seed→material map fails every affineness test (≈50% of bits violate superposition), so the linear recovery cannot even be set up. The only remaining route is a SHA-256 preimage on a secret 128-byte suffix, which is not a scriptable break.
- **The cipher's security margin is larger than N1's, not smaller.** Every distinguisher I built dies by **round 3–4 of 16**, because N2 reaches full diffusion by round 3. N1's distinguishers survived to **round 9 of 16**. So against these attacks N2 has ~12–13 rounds of margin versus N1's ~7.
- **What is still true of any deterministic scheme:** reusing a (seed, nonce) leaks message equality and lets an oracle confirm guessed plaintexts. It is *not* keystream reuse. `encrypt()` draws a fresh `os.urandom(16)` nonce, so this needs deliberate misuse.

## 1. Integrity / authentication (the hole N1 failed) — **CLOSED**
`decrypt` checks length, then the `SN2` prefix, then the HMAC-SHA256 tag with `hmac.compare_digest`, and only then decrypts. Results on a valid "hello world" blob and on random inputs:

| Test | N2 | N1 (for contrast) |
|---|---|---|
| 200,000 random 115-byte blobs | **0 accepted** | ~0.39% of 64-byte cts accepted |
| 10,000 random blobs with correct `SN2` prefix | **0** | — |
| 10,000 blobs with `SN2` + real public nonce, random ct+tag | **0** | — |
| All 920 single-bit flips (version/nonce/ct/tag) | **0 accepted**, all `AuthError` | 2–3 of 512 ct flips decoded to wrong text |
| 3,000 random single-byte changes each in nonce / ct / tag | **0 / 0 / 0** | ~0.44% of byte changes silent |
| Splicing nonce/ct/tag across two valid blobs | all `AuthError` | n/a (no MAC) |
| Truncations (len 0–114) and extensions (+1..32 bytes) | all rejected | n/a |
| Seedless chosen-message forgery ("send $1000 to mallory"), 20,000 random tags | **not forged** (expected ~2²⁵⁶) | n/a |

**Decode-success oracle (N1's residual leak):** an attacker without the seed can never reach the decoder, because the tag is verified first — all 512 ciphertext-bit tampers raise `AuthError`, never `DecodeError`. The length/padding check (`DecodeError`) is reachable only by someone who already holds the seed and can MAC a malformed block, so it exposes no oracle to an outsider. This removes N1's "does it decrypt?" side channel.

## 2. Key schedule (N1's seed leak) — **CLOSED**
N1: `W_r` was an XOR of seed and nonce rotations, i.e. a GF(2)-linear circulant; from round-5 material I had recovered the entire seed by Gaussian elimination and decrypted the demo. N2 derives everything from `SHA-256("SN2/" ‖ domain ‖ ctr ‖ seed ‖ nonce)`.

| Test | Result |
|---|---|
| Affineness `M(a)⊕M(b)⊕M(c)⊕M(a⊕b⊕c)` in the seed | **4356 / 8704 bits nonzero** (linear ⇒ 0). Not affine. |
| Same test in the nonce | 4361 / 8704 nonzero. Not affine. |
| Direct N1 inversion: fit an affine model `M(0) ⊕ Σ (M(eᵢ)⊕M(0))` and predict a fresh seed | **4366 / 8704 bits wrong** ⇒ the linear system is garbage; no seed recovery |
| Domain separation (K-stream vs M-stream, 2048 bytes) | 9 coincidental equal bytes (~8 by chance); MAC key not present in schedule material |
| Seed copied into the stream? | no 8-byte run of the seed appears in 2048 stream bytes |
| Seed / nonce / counter actually used | yes; all 64 squeezed SHA blocks distinct |
| Int seed (N1-style) vs bytes seed | identical material (no loader ambiguity) |
| Avalanche, 1-bit nonce flip | **49.97%** of schedule bits change (min 48.7, max 51.3) |
| Avalanche, 1-bit seed flip | 49.91% (min 48.6, max 51.5) |

Related nonces, which in N1 gave an attacker-predictable material XOR, now give a SHA-256 output difference that is not predictable without the seed. **The only remaining path to the seed is inverting SHA-256, which I did not attempt and do not claim.**

## 3. Reduced-round cryptanalysis of the block cipher
Imported the real S-boxes, mix, weave and round keys; ran r = 1,2,3,… rounds (no whitening, which is a fixed XOR irrelevant to these statistics).

**Keyed S-boxes (as actually instantiated):** every one of the 16 round S-boxes has **DDT max 4/16 and LAT max 4/8** — the optimal bounds for a 4-bit permutation, inherited from PRESENT through the affine keying. N1's shuffled box was 8/16. Best single differences are things like `1→3`, `1→4`, `1→B` at 4/16.

**Dependency / codebook split (the N1 1-round break):**

| Rounds | ct nibble depends on (min/mean/max of 128) | largest independent input-component |
|---|---|---|
| 1 | 15 / 15.9 / 16 | **128 nibbles** |
| 2 | 96 / 112.8 / 128 | 128 |
| 3 | 128 / 128 / 128 | 128 |

N1 at 1 round split into 64 independent 2-nibble pieces, and I recovered `b'the vault code is 4471-AZ'` from a 16,384-entry codebook. **N2 has no such split: even at 1 round the smallest independent component is all 128 nibbles**, because SubNibbles touches every cell and the staff butterfly plus shell bridges fan each cell out within the round. The codebook attack does not apply at any round ≥ 1.

**Exploiting the documented mix weaknesses (Δ=8 and the linear LSB):**

| Attack | 1 r | 2 r | 3 r | 4 r |
|---|---|---|---|---|
| Best single-nibble output-diff prob for input Δ=8 | 1.0* | 1.0* | 0.136 | 0.076 (≈1/16) |
| \|corr − ½\| of (all input LSBs parity, all output LSBs parity) | 0.005 | 0.002 | 0.005 | 0.009 |
| Best sampled single-cell LSB→LSB bias | 0.009 | — | — | — |

\* The "1.0" at 1–2 rounds is just a not-yet-diffused output cell (output difference 0), the same effect as the zero-difference distinguisher — not a Δ=8 pass-through. The S-box sits at the top of every round, so the "Δ=8 passes the 2-cell mix" and "the mix LSB is linear" properties from the SPEC never chain across rounds: by round 3 the Δ=8 differential is down to 0.136 and by round 4 it is at the random 1/16, and the LSB linear correlation is at noise from round 1. These documented mix weaknesses are real but **do not produce a multi-round trail**, because the nonlinear S-box breaks them each round.

**Distinguishers, pushed as far as they go** (random baselines noted):

| Rounds | zero-sum nibbles, 256 chosen pts (random 8) | unchanged nibbles, 1-nibble diff (random 8) | avalanche mean/512 |
|---|---|---|---|
| 1 | 128.0 | 113.5 | — |
| 2 | 123.2 | 28.8 | — |
| 3 | **24.2** | 8.1 (≈random) | 254.3 |
| 4 | 6.5 (≈random) | 8.1 | 255.6 |
| 5 | 7.2 | 7.9 | — |
| 8 | — | — | 255.6 |
| 16 | — | — | 255.7 |

- **Zero-difference** (truncated-differential) distinguisher: clear through **2 rounds**, random from 3.
- **Integral / zero-sum**: clear through **3 rounds** (24.2 vs 8), random from 4. This is the strongest distinguisher I found.
- Chi-squared on output bits over a 16-set shows a near-constant bit through rounds 2–3 (the same incomplete-diffusion effect) and saturates by round 4.
- **Last clearly distinguishable round: 3 (integral). From round 4 everything looks random.**

**Full 16-round:** no seedless plaintext recovery, no seed recovery from known/chosen pairs, and no ciphertext-only distinguisher. Honest negative result, as with N1 — but N2's distinguishers reach only 3–4 rounds, versus N1's 9, so the margin here is far wider (≈12–13 rounds against these specific attacks).

**Why the margin looks better than N1's:** the attacks that carried N1 to round 9 (slow diffusion let truncated-differential and integral patterns survive) die quickly in N2 precisely because N2 diffuses fully by round 3. This is a statement about *these* attacks, not a proof: a dedicated differential/linear trail search with key guessing (which I did not run) typically adds rounds to a distinguisher, and N2's 4-bit S-boxes and partly-linear mod-16 mix are exactly the kind of structure such a search would target.

## 4. Nonce reuse
Same seed and nonce for every message tested; the 64-byte block is then one fixed keyed permutation.

| Test | Result |
|---|---|
| Identical messages → identical ciphertext / whole blob | yes (equality leaks; unavoidable for deterministic encryption) |
| `ct1⊕ct2 == pt1⊕pt2` (keystream structure) | **0 / 300** — N2 is **not** a keystream; it is a keyed permutation |
| ct-xor Hamming weight for two random messages | 255.7 / 512 (random ~256) |
| 1-byte plaintext change under reused nonce → ct distance | mean 255.3 / 512, min 225 (full permutation) |
| Yes/no/maybe guesser with an encryption oracle | confirms a correct guess; recovered a 3-digit PIN in ≤1000 oracle queries |
| Ciphertext-only (two ciphertexts, no oracle, no seed) | nothing recovered |

So nonce reuse leaks **message equality** and enables **oracle confirmation of guesses** — both generic to any deterministic cipher, the same as N1's "yes/no/maybe" — but it is **not** XOR-keystream reuse, so two ciphertexts alone do not reveal the messages. `encrypt()` draws a fresh random nonce, so a repeat is deliberate misuse.

## Which of the five N1 holes actually closed
1. **No integrity → closed.** HMAC-SHA256 checked first with `compare_digest`; 0 forgeries/garbage accepted across >230,000 attempts.
2. **Linear, invertible schedule / seed leak → closed.** SHA-256 sponge over seed‖nonce; map is non-affine, linear inversion fails, avalanche ≈50%.
3. **Leaky interval mix (p≈0.44) → improved.** Replaced by the (u+v, u+2v) staff butterflies + cross-shell bridges; full diffusion at round 3 and distinguishers die at round 3–4 instead of 9. The mix's own Δ=8/LSB linearity is real but does not chain past the S-box.
4. **Weak S-box (DDT 8/16) → closed.** Keyed PRESENT-affine S-boxes, DDT 4/16 and LAT 4/8 in all 16 rounds, applied to all 128 nibbles.
5. **Nonce-independent key material / codebook → closed** for the schedule (everything is a function of seed **and** nonce) and the 1-round codebook split no longer exists. **Not closed, by design:** deterministic encryption still leaks equality under a reused nonce.

## What a further repair would need (not implemented)
- **A proof, not statistics.** Count active S-boxes over the best differential/linear trails (e.g. with an MILP model) to bound 16-round probabilities. The numbers here are empirical.
- **A less-linear mix.** The low bit-plane of the mod-16 `(u+v, u+2v)` mix is GF(2)-linear and Δ=8 passes it deterministically; an MDS layer over GF(2⁴) (poly 0x13) with branch number 5 would remove the structure the S-box currently has to clean up alone.
- **Bigger or more S-boxes.** 4-bit boxes pass a difference with probability ≥ 1/4; 8-bit boxes or more boxes per round raise the active-S-box count.
- **Misuse resistance.** An SIV-style synthetic nonce (`nonce = HMAC(seed, msg)[:16]`) would make a reused nonce leak only equality of equal messages, nothing more.
- **Constant-time implementation.** The current Python uses data-dependent table lookups; only the tag compare is constant-time.

## Reminder
N2 is still a homemade, unreviewed SPN sealed with standard primitives. Nothing here breaks 16 rounds, and the two structural N1 holes are closed, but "survived my scripts" is not "secure." **Use AES-GCM-SIV (RFC 8452), age, or libsodium for real secrets.**
