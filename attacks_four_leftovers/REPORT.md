# Live N2: attack after the four leftover changes

**2026-11-08 evening, America/New_York (EST). Completed 2026-11-08 09:54:17 PM EST (America/New_York).**

## Bottom line

**No seed-free recovery of 16-round plaintext or seed, and no MAC forgery, was found.** This is a bounded local analysis, not a security claim. Reading the owner's seed and calling `decrypt()` is expected symmetric-key access, not a break. The raw-block experiments below are white-box/fixed-known-schedule tests; the public API changes its pickup and synthetic nonce for every encryption, so it does not provide that oracle.

Target: `/workspace/sneak_n2/sneak_n2.py`  
SHA-256: `991ae8f61ee53ec899003b57bc143d70dc9fcdb37de6bd2b334a18f020ebdf5f`

The bridge removed the old graph split, and no single-cell one-round staff confinement survived the 2,088,960-pair scan. The arithmetic-code commitment catches the listed source patches. **The ARX singleton problems remain**, with exact reproduction of both prescribed counts. Additional local observations: complementary rotations route one input bit directly to an output bit; the cross layer alone still has a two-active-staff to four-active-staff cancellation; the omitted `staff_mix` helper evades the source commitment. None was extended to a full-round attack or a seed-free forgery.

No fixes were made. The two known failing shape assertions were not weakened. The previously recorded 181/183 overall test result is background, not a new whole-suite execution; this run independently reproduced their underlying counterexamples and counts.

## 1. Integrity / authenticated encryption

The recorded 195-byte hello-world decrypted to `b'hello world'`:

- pickup: `724da1f42b3aa81489b97a1dcaeb14c4`
- synthetic nonce: `4c6c2d12c72419fcb721e2d2aad9800c`
- SIV formula and HMAC independently recomputed successfully; fresh encryption differed.

| Probe | Result |
|---|---|
| All 1,560 single-bit flips of the recorded blob | 0 payloads; 1,536 tag mismatches, 24 bad-version errors |
| 1,000 nonzero ciphertext-byte corruptions | 1,000 tag mismatches |
| 40 pickup swaps, plus a same-message pickup swap | all tag mismatches |
| 160 nonce/ciphertext/tag/partial-body splices | all tag mismatches |
| 1,000 random bodies with SN2 prefix | all tag mismatches |
| 200 completely random 195-byte blobs | all bad-version errors |
| Wrong lengths, including 115, 179 and 203 | bad blob length before any body processing |
| Valid tag + well-encoded block + incorrect synthetic nonce (seed-holder construction) | `AuthError: SIV nonce mismatch` |
| Valid tag + random ciphertext (seed-holder construction) | `DecodeError: tag valid but block malformed` |

Actual legacy 115/179/203-byte recorded blobs also failed on length. The immediately previous 195-byte sample, pickup `831a4499756825b07352034a552a9756`, nonce `381081f81ba65e22a15ab8f327de8e94`, failed as **tag mismatch**, not DecodeError. Pickup-era (`pre_three_fixes`), three-fixes/testn4 and pre-cross 195-byte samples also failed on tag. Old-module samples were checked with their own libraries, and ten extra samples per available legacy library were tested against live N2. These are backward-incompatibility checks, not evidence that old formats are generally insecure.

Full classifications, paths, lengths and construction details: `attack_integrity_pin_results.json`.

## 2. Public PIN matching versus seed-holder matching

The simulated public endpoint calls the real randomized `encrypt()`; using the local seed to run that endpoint does not grant the dictionary algorithm secret-derived internals.

- Correct PIN encrypted **512** more times: **0** target matches, **0** target nonce matches, **512** unique pickups.
- Complete 10,000-PIN dictionary, one fresh public encryption each: **0** blob matches.
- Seed-holder copied-pickup test, 10,000 guesses: **1** matching candidate, reproducing the full target blob. Direct `decrypt()` also recovered the PIN.

The latter requires the secret seed/clef, so is not stronger than decryption and is not a seed-free attack. The public matching path remained closed in this protocol; this does not prove resistance to every conceivable dictionary strategy.

## 3. What the four changes closed, and what remains

### 3.1 Staff graph bridge: split closed in these checks

All four layers have one connected component of 16 staffs. `CROSS_BRIDGE=((1,2),(5,6),(9,10),(13,14))` contains four disjoint pairs and touches eight vertices: it is **not** a perfect matching of all 16.

A full scan of **128 input cells × 255 conditioned first-S-output deltas × 64 random raw-block bases = 2,088,960 pairs** under the recorded current schedule found:

- **0** pairs with any wholly unchanged staff;
- all **16** staffs active in **every pair**;
- active bytes ranged **121–128**;
- every input-cell staff-footprint union was all 16 staffs.

Conditioning uses `SI[S[x xor rk] xor delta] xor rk`; it is a white-box search, not a public chosen-nonce API. It covers every cell and every nonzero S-output delta at 64 bases, **not every possible 1024-bit base or every nonce/seed**.

Cell 2 separately reached all 16 staffs in **300/300** pairs under each of the current hello-world and demo schedules (124–128 active bytes in each set). The old five-staff confinement was not reproduced. A connected static graph alone would not establish this dynamic result; the actual round was evaluated.

### 3.2 B0 ARX: old linear witness closed, singleton property not closed

B0 is bijective on all **65,536** input pairs, with **0** failures of either inverse direction and 65,536 distinct images.

Old differential `(0x05,0x01)`:

- zero-base output XOR is `(0x0d,0xa0)`, no longer `(0x00,0x03)`;
- over all 65,536 bases: **30** distinct output derivatives;
- **0** first-output wipes and **0** second-output wipes.

However, the new single-input property fails:

```python
N.b0_apply(0, 0)  # (0, 0)
N.b0_apply(0, 1)  # (8, 0)
```

The rotations 3+5 return a byte to its original orientation. When `u=0`, the second output is identically zero for all 256 values of `v`. When `u=0x80`, it is identically `0x10`.

Exact seeded reproduction: **2,609/40,000** single-input derivatives were singletons, all from changing the second input (`Random(4419)`, 20,000 bases, both input columns).

An expanded exhaustive scan evaluated **33,423,360** one-input XOR derivatives:

| Changed input | Cases | Singleton outputs |
|---|---:|---:|
| `u` only | 16,711,680 | 0 |
| `v` only | 16,711,680 | 2,173,952 |

These are local-layer derivatives, not whole-cipher plaintext recovery.

### 3.3 Bow + odd restack: improvement, but the asserted shape remains

The exact prior scan was replayed: 256 uniform staffs plus 256 PRNG staffs, all four odd beats and all 255 nonzero XOR deltas. PRNG state matches the B0 test above.

| Input class | Cases | Bow-only singletons | Bow + rehair singletons |
|---|---:|---:|---:|
| Odd beats, all deltas | 522,240 | 555 | 150 |
| Odd beats, delta 0x80 | 2,048 | 9 | 7 |
| Even beats, all deltas | 522,240 | 0 | 0 |
| Even beats, delta 0x80 | 2,048 | 0 | 0 |

The 150 remaining odd-input cases split by beat as 0, 37, 60 and 53 for beats 1, 3, 5 and 7. Invertibility is not the problem: both inverse directions passed on **20,256** staffs.

Prescribed witness (zero-based beat numbering):

```python
f = lambda s: N.odd_restack(N.bow_pressure(s))
a = [0xc0]*8
b = a.copy(); b[3] ^= 0x80
[x ^ y for x,y in zip(f(a), f(b))]
# [8, 0, 0, 0, 0, 0, 0, 0]
```

Simpler additional witnesses: from an all-zero staff, changing beat 3, 5 or 7 by `0x55` produces just `0x55` at output beat 0, 2 or 4 respectively after bow+rehair. Beat 7 still pairs only with beat 6; no 7-to-0 arithmetic pair was added.

### 3.4 Mix code commitment: listed changes caught; not whole-runtime attestation

Ten in-process parameter/source changes were tested separately, with full restoration between cases:

1. B0 r2 5→4;
2. skip B0;
3. modify T0 row;
4. skip T0;
5. change mix2 matrix;
6. bow rotation base 1→2;
7. skip bow via empty strokes;
8. remove bridge from both bridge parameter and ordered layer list;
9. rehair r2 6→5;
10. replace listed `odd_restack` function source with identity.

**All ten changed key_sig and failed live decryption as tag mismatch.** An isolated module skipping B0/T0 also failed on tag. A copied `bar_mix` that skipped B0 while keeping BARS identical now changed the signature and failed on tag: the previous code-only commitment hole is closed for this listed function. These are seed-holder alternate-implementation blobs, not attacker-created forgery attempts without the key.

Honest remaining hole reproduced: **`staff_mix` is not in MIX_CODE_FUNCS**. Replacing it in memory with a copying identity changes encryption behavior while leaving both `mix_code` and `key_sig` identical. Live N2 accepts that tag, then rejects the body with `DecodeError: tag valid but block malformed`. Building the demonstrated blob **requires the seed**, so this is incomplete arithmetic attestation, **not a MAC forgery**. Get-source commitments also do not authenticate cached arithmetic tables, omitted helpers, or arbitrary runtime changes invisible to those source objects.

## 4. Other local structural findings

### Remaining field pairs still cancel

All six remaining linear named pairs had **510** nonzero two-input delta pairs cancelling one output, and **0/510** singleton results from a single changed input. For example:

```python
N.bar_apply(N.BARS[1][3], 1, 1)  # B1 -> (0, 3)
N.mix2(0, 0x80)                 # (0x80, 0xf5), not (0x80, 0)
```

mix2 still has **0/510** single-input singleton deltas and 510 two-input cancellations. Invertible linear two-cell maps necessarily allow some two-input differences that annihilate an output; removing one historical witness does not remove the class.

For all six integer triplets, all three columns and all 256 coordinate bases × 255 XOR deltas were checked: **0 singleton outputs in 1,175,040 cases**. All delta-0x80 columns activated at least two outputs. Other-coordinate contributions add the same constant to both compared outputs and cannot change their equality, so this equality-count test covers all completions for those one-coordinate differences. Triplets are still ordinary Z/256Z arithmetic, not field multiplication.

### Additional exact bit relations in the ARX pairs

Bit numbering is least-significant-bit first. Exhaustive 65,536-pair checks and direct live-helper crosschecks found:

- B0: `u_out[0] = u_in[0] xor v_in[5]`; **`v_out[5] = u_in[0]`**.
- Each rehair pair: `u_out[0] = u_in[0] xor v_in[6]`; **`v_out[6] = u_in[0]`**.

All four relations hold exactly. The first relation in each is the carry-free low bit of addition; the second is the complementary-rotation cancellation. Thus “nonlinear” does not mean every bit relation is nonlinear. Rehair's second output is also constant 0 for `u=0` and constant `0x20` for `u=0x80`. No full-round linear trail was constructed from these local facts; the keyed S/S2 layers intervene.

### Cross-only cancellation despite graph connectivity

A single cross-layer application spreads any single active staff at a shared beat to **12**, not 16, staffs. Among **30,600** normalized two-active-staff input patterns (120 staff pairs × 255 ratios), minimum output activity is **four staffs**. Concrete exact field-linear witness:

```python
g = [[0]*8 for _ in range(16)]
g[0][0] = 1; g[1][0] = 0xfa
[row[0] for row in N.cross_staff_mix(g)]
# [0xfb,0,0,0, 0xfb,0,0,0, 0xfb,0,0,0, 0xfb,0,0,0]
```

This gives an upper bound of 6 on that layer's byte/staff branch number (2 inputs + 4 outputs), **not** a full-round confinement finding. Two cross applications and other layers occur in each actual round. The measured full-round single-cell scan above still reached all staffs.

## 5. Reduced-round search and diffusion

All vectorized round operations were independently crosschecked against live `round_enc`, across all 16 round positions (128 sequential round comparisons in the principal validation). B0/rehair/cross were included, not borrowed from the old cipher. Witnesses are also replayed directly through live helpers.

### Sparse-output test

Threshold: at least eight unchanged output bytes for a nonzero single-input-cell difference. For a random 1024-bit permutation the probability is about **5.11136e-8**, so 524,288 pairs give only **0.026798** expected hits; getting no hits is not a strong assurance.

| Rounds | Search | >=8 unchanged-byte pairs | Maximum unchanged bytes |
|---|---:|---:|---:|
| 2 | 128 cells × 4,096 = 524,288 | 0 | 6 |
| 3 | same 524,288 input pairs | 0 | 6 |
| 4 | additional 524,288 random single-cell pairs | 0 | 6 |
| 16 | 65,536 random single-cell pairs | 0 | 5 |

The historical cell-30 delta-0x33 two-round witness was replayed: its old ten unchanged positions are now only **[80]** under the current recorded nonce, **none** under the pickup-era nonce, and **[86]** under the demo nonce. Full original x/y blocks are in `attack_trails_results.json`.

The full one-round 2,088,960-pair scan had two samples with seven unchanged bytes (121 active), but no inactive staff. Ordinary unchanged bytes are expected: a random output difference averages 0.5 zero bytes. This is **not** a one-round distinguisher merely because activity is below 128; no sparse/confined whole-round trail was demonstrated here.

### Byte dependence and bit avalanche

For each listed round count, every one of **16,384** input-byte/output-byte dependencies was observed in 32 random bases per input cell. This is sampled dependence, not proof of dependence at every base.

Each avalanche row uses **8,192** independent one-input-bit flips; ideal mean is 512 changed bits out of 1024, ideal standard deviation 16.

| Rounds | Mean changed bits | Std. dev. | Range |
|---|---:|---:|---|
| 1 | 511.789 | 16.122 | 456–567 |
| 2 | 512.183 | 16.123 | 455–571 |
| 3 | 511.549 | 16.09 | 445–573 |
| 4 | 511.903 | 16.109 | 449–575 |
| 16 | 512.158 | 15.886 | 446–574 |

Across separate 65,536-pair random single-cell datasets, mean zero-byte counts at rounds 1/2/3/4/16 were 0.4991 / 0.5076 / 0.5000 / 0.4974 / 0.5003 (ideal 0.5). No sparse-output hit at the >=8 threshold appeared in those datasets. Avalanche is a coarse sanity check, not a cryptanalytic security argument.

## 6. Schedule, domains and keyed boxes

Thirty-two nonce-bit flips and 32 seed-bit flips were measured against the recorded schedule:

| Flip | Round-key/whitening material changed | MAC-key changed bits | Clef changed bits | key_sig changed bits |
|---|---|---|---|---|
| nonce | 49.40–51.02% | 111–140 / 256 | 0 / 128 | 0 / 128 |
| seed | 49.25–50.91% | 115–144 / 256 | 51–78 / 128 | 56–73 / 128 |

Clef and key_sig are seed/score-only, so invariance to nonce changes is intentional. No round-0 S table stayed identical in these samples. The sampled M/K/C/G domain outputs were distinct; this checks wiring, not a domain-separation proof.

The table starts `d690e9fe...`, is SM4 rather than AES, and passed the local SM4 reference-vector checker. Base SM4 and keyed S/S2 in rounds 0, 1 and 15 all had **DDT maximum 4** and **LAT maximum bias 16** (the implementation's definition `abs(equal_count - 128)`, equivalent Walsh magnitude 32). Affine wrapping preserves these spectra. SM4 and AES boxes both belong to the inversion/affine-equivalence family; “not AES” does not imply an unrelated algebraic structure.

## 7. Reproduction, scope and untouched files

All attack scripts import `common.py`, which checks the exact live source SHA-256 **before importing the cipher**, and checks it again after import. `snapshot_protected.py` has its own import-time source check. A mismatch aborts rather than attacking a different version. Bytecode writes are disabled.

Fast witness replay:

```bash
cd /workspace/sneak_n2/attacks_four_leftovers
PYTHONDONTWRITEBYTECODE=1 python3 attack_replay.py
```

Independent substantive runs:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 attack_integrity_pin.py
PYTHONDONTWRITEBYTECODE=1 python3 attack_key_signature.py
PYTHONDONTWRITEBYTECODE=1 python3 attack_structure.py
PYTHONDONTWRITEBYTECODE=1 python3 attack_arx_relations.py
PYTHONDONTWRITEBYTECODE=1 python3 attack_cross_local.py
PYTHONDONTWRITEBYTECODE=1 python3 attack_trails.py
PYTHONDONTWRITEBYTECODE=1 python3 attack_rounds.py
PYTHONDONTWRITEBYTECODE=1 python3 attack_schedule.py
```

Each saves JSON results and a dated text copy inside this folder. Public encryptions and several alternate-blob demonstrations draw fresh randomness, so blob/PIN values can change on replay; seeded structural counts are deterministic. `common.py` contains the NumPy batching and validation. `build_report.py` assembles this report from saved results.

Protected-file content was snapshotted before work and after all experiments. Coverage includes all pre-existing live N2 files, old attack folders, test1/test3/test13/testn1/testn3/testn4, sneak_t1n and sneak_v2–v13, the seed, workspace PNGs and temporary frozen N2 trees. See `protected_before.json`, `protected_after.json` and `protected_verification.txt` for exact hashes and verification. No picture was regenerated; no seed, live cipher, test, documentation, recorded hello-world, test_results, demo nonce, frozen file or old attack output was changed. All deliverables are in this new folder; N3 was not started.

Not explored in depth: full-cipher **linear, algebraic, slide, related-nonce** attacks; multi-round differential hulls and automated trail solving; broader seeds/nonces and exhaustive raw-block bases; timing/side-channel behavior, RNG-failure models, formal AE proofs or independent third-party review. The few exact local bit relations above are not an in-depth linear attack. No assumption that source attestation is runtime integrity or that a seed-holder construction is a forgery was used.

**Still homemade, not for real secrets; use AES-GCM-SIV, age, or libsodium. Negative result ≠ proof.**
