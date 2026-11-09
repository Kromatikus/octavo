from common import *
p=HERE
I=json.loads((p/'attack_integrity_pin_results.json').read_text());S=json.loads((p/'attack_structure_results.json').read_text());R=json.loads((p/'attack_rounds_results.json').read_text());P=json.loads((p/'attack_sparse_results.json').read_text());K=json.loads((p/'attack_schedule_results.json').read_text());T=json.loads((p/'attack_trails_results.json').read_text());V=json.loads((p/'verify_target_results.json').read_text())
ins=I['insider_nonce_dictionary'];match=ins['matches'][0];pub=I['public_pin_match'];trail=T['new_one_round_trail'];modes=trail['modes'];before=json.loads((p/'protected_before.json').read_text());after=json.loads((p/'protected_after.json').read_text());assert before==after
rows=[]
for n,x in R['rounds'].items():
 a=x['bit_avalanche'];z=x['zero_difference'];h=x['delta80_cell18'];status='Distinguisher demonstrated' if n in ('1','2') else 'Not detected in these tests'
 rows.append(f"| {n} | {x['byte_dependence']['empirical_pairs']:,}/16,384 | {a['mean']:.2f} ({a['sd']:.2f}, {a['min']}) | {z['chi2_128pos']:.1f} | {h['byte38_histogram_chi2_df255']:.1f} | {z['ge8_zero_pairs']:,}/65,536 | **{status}** |")
body=f'''# Attack report: CURRENT LIVE N2 after random pickup, field pairs, and triplets

> **Homemade, unreviewed cipher. Not for real secrets.** Use AES-GCM-SIV (RFC 8452), age, or libsodium for real secrets. This is cryptanalysis only: no fixes, no N3, no images regenerated. Negative results are not security proofs.

- **Date:** Sunday 2026-11-08; tests began {I['started']}; final target verification {V['timestamp']}. Report written {now()}.
- **Live target:** `/workspace/sneak_n2/sneak_n2.py`, SHA-256 `{I['library_sha256']}`. Exact expected hash matched, and the live source was read in full. No old cipher was substituted for the attack target.
- **Format:** `SN2(3) || pickup(16) || nonce(16) || ciphertext(128) || tag(32)` = **195 bytes**. `encrypt()` calls `os.urandom(16)` and has **no pickup argument**. Nonce is `SHA-256(clef || pickup || encode_block(msg))[:16]`. Tag is HMAC-SHA256 over `clef || SN2 || pickup || nonce || ciphertext`. Decrypt checks length and version, builds schedule, checks tag with `compare_digest`, then decrypts/decodes, then rechecks the SIV nonce. Message limit remains 127 bytes.
- **Round checked:** XOR rk → S → weave → integer butterfly → integer shell bridges → seven named **SM4-field** pairs (polynomial `0x1F5`) → six overlapping **integer mod-256** triplets → S2 → encore field pairs → encore integer triplets. No beat 7↔0 wrap. Names, coefficients, and order match the brief; full tables are in `verify_target_results.json`.
- **Hello-world:** Recorded pickup `{PICKUP.hex()}`, nonce `{NONCE.hex()}`, tag `{TAG.hex()}`. Live decrypt returns `b'hello world'`. Re-encryption gives a **different** blob.
- **Scope:** Public-encrypt-only matching experiments and authentication rejection tests, plus known-seed white-box raw-block/reduced-round tests. The latter hold one schedule fixed; they are **not** access available through the randomized public `encrypt()` oracle. Do not call those experiments a full API plaintext-recovery break.
- **Protected content:** **{len(before):,}/{len(after):,} files byte-identical**, including existing bytecode files; zero changed, removed, or added protected files outside `attacks_pickup/`. Coverage: live library/tests/docs/demo/render, seed, workspace PNGs, test1/test3/test13/testn1/testn3, sneak_t1n, sneak_v2–v13, previous attack folders, baselines, and `/tmp/sneak_n2_*` snapshots. See `protected_verification.txt` and full manifests. Old libraries were read-only imports with bytecode writing disabled. The only new work files are in this folder.

## Verdict

I did **not** demonstrate a seed-free full-16-round plaintext recovery, key recovery, or HMAC forgery. **That does not establish security.**

The random pickup closes the old **`encrypt(guess) == target_blob`** matching attack against an encrypt-only oracle. The field pairs close their single-input/single-output leakage, and the triplets prevent the old one-cell middle crossing in the measured cases. However, **1- and 2-round distinguishers still exist**. A new 1-round 8-byte truncated trail and a 2-round sparse-output distinguisher were demonstrated on the current live code. The tag still does not commit to the mix tables. Known-seed PIN recovery remains possible (and seed possession already enables direct decryption).

## Closed or confirmed holding (measured on live code)

| Item | Status | Witness |
|---|---|---|
| Old public PIN blob-matching attack | **CLOSED for public `encrypt()` only** | Random demo PIN **{pub['pin']}**; **0/{pub['correct_pin_encryptions']}** encryptions of the **correct** PIN matched its target; all {pub['unique_pickups']} sampled pickups distinct, {pub['seconds']:.3f} s. Repeated equal messages no longer give equal blobs. This is not a claim about other oracles or leaked secrets. |
| HMAC corruption rejection | **Holds in these tests** | All **1,560/1,560** single-bit flips rejected: 24 bad prefix, 1,536 tag mismatch. No payload. Also 500 ct corruptions, 200 splices (**40 pickup swaps**), 1,000 random SN2 blobs, 200 fully random blobs, and 8 wrong lengths rejected with AuthError. |
| Old formats | **Rejected at length, not a new mix commitment** | Nine generations: archived demo plus 20 newly generated blobs each = **189/189 AuthError: bad blob length**. Includes all four requested `/tmp` versions, testn3, pre-clef, pre-color2, pre-bar, and 4-bit. Old demos decrypt under their own libraries. |
| Pickup/nonce binding | **Holds in these tests** | Pickup splices fail tag. A well-encoded, valid-tag blob encrypted with the wrong synthetic nonce reaches **AuthError: SIV nonce mismatch**, not payload. Passing the recorded nonce to a new randomized encryption raises ValueError. |
| Named pair singleton derivatives | **CLOSED, including Δ0x80** | **0/3,570** nonzero single-input difference configurations yield one active output (7 pairs × 2 columns × 255 deltas). This exhausts the field-linear derivatives for **every base**, not just zero. Also 3,584 random-base helper checks matched the field-linear prediction. Field determinants `[3,3,3,7,1,3,1]`. |
| Combined bars+triplets / identical encore | **No singleton Δ0x80 observed** | 8 inputs × **8,449** staff bases = **67,592** tests, including zero, every constant-byte staff, and 8,192 random staffs. Minimum weights by input beat: **[6,6,6,6,5,5,5,2]**; singleton events **0**. These are sampled minima, not a universal theorem. |
| Full round middle high-bit crossing | **Old singleton not reproduced** | 128 cells × 257 bases × 2 rounds × 2 fixed schedules = **131,584** middle-layer trials; **0 singleton outputs**. Current-demo round-0 minimum 5 active S2 cells, round-1 minimum 2. Historical-nonce fixture minima 2 and 4. |
| Full empirical byte dependence | **Reached at 2 rounds** | 1 round **6,128/16,384** pairs; rounds 2,3,4,16 **16,384/16,384**, 32 random bases/deltas per input byte. Observed dependence is not a general diffusion proof. |
| Schedule and SM4 | **No new break from these checks** | 64 one-bit schedule tests, domain separation, DDT/LAT, and two SM4 reference vectors; details below. |

## Leftovers and attacks (with witnesses)

### 1. PIN recovery with secret material: pickup is not protection from a key holder

The independent attack loop copied the target pickup, derived the secret clef from the known seed, and checked the **nonce** for all 10,000 guesses. For the matching candidate it rebuilt `Schedule`, `encrypt_grid`, and HMAC, without calling `encrypt()` or adding a pickup argument.

- Recovered **PIN {match['pin']}** from `PIN:{match['pin']}`.
- **{ins['all_guesses']:,} guesses in {ins['seconds']:.6f} s** (nonce prefilter plus one full matching-candidate reconstruction, not 10,000 full encryptions).
- Copied pickup: `{match['pickup']}`.
- Matching nonce: `{match['nonce']}`.
- Reconstructed **entire blob equals target: {match['full_blob_matches']}**. Target blob is saved in `attack_integrity_pin_results.json`.

**Threat-model correction:** possession of the seed already permits direct `decrypt()`; I verified that too. This is **not a seed-free attack**. Once the secret clef is known, the published nonce permits cheap PIN verification without needing the cipher rounds. The experiment derives that clef from the known seed, not from the ciphertext. If a service exposed `siv_nonce(msg, copied_pickup)` or `staff_clef()` under its hidden seed, that would give a dictionary oracle even though `encrypt()` does not accept a pickup. No such external service was assumed or attacked here. Local library callers who can load the seed are not an encrypt-only adversary.

### 2. Remaining integer high-bit structure — and a correction about triplets

`mix2(u,v) = (u+v, u+2v) mod 256` still has **Δv=0x80 → (0x80,0)** for **all 65,536 base pairs**, exhaustively checked. In the current round-0 staff butterfly, **16/128 input cells** (one per staff) retain a singleton Δ0x80 crossing. The first staff's weights are `[4,4,8,2,4,1,2,2]`. Shell bridges use this same primitive.

**The earlier blanket claim that an isolated triplet can pass a high bit into only one output was wrong.** Each individual triplet has at least two odd entries in each column: Δ0x80 changes **2 or 3 outputs**, never one. Some even-coefficient branches vanish, but two or more survive. The whole six-triplet stack on its own has high-bit weights **[5,5,3,5,5,4,3,3]**, also no singleton. Triplet determinants are all 1 mod 256.

After the field pairs and triplets together, output differences depend on the base; treating the composition as a single integer matrix would be invalid. Measured zero-base weights are `[8,8,8,8,7,6,5,2]`. Across 8,449 bases the last input beat still always gave the sparse pattern **`[0,0,0,0,0x80,0,0,0x80]`**. Thus singleton leakage is gone in these samples, **not all structured high-bit propagation**.

### 3. Multi-input cancellation still exists in a named pair

Concrete B0 witness, at every base by field linearity:

```text
input XOR difference:  (0x05, 0x01)
output XOR difference: (0x00, 0x03)
```

Two nonzero inputs cancel in the first output. This is normal for an invertible linear mix, not itself a full-cipher break. The **named pairs** are XOR/field-linear; the integer layers are linear for modular addition, but need not be XOR-linear because of carries. Their composition must not be treated as linear over one common field. The full cipher also includes nonlinear S-boxes.

### 4. Old 3-byte trail gone; new 8-byte 1-round truncated trail demonstrated

The join-pairs report's cell **18 → {{37,38,39}}** trail was retested, not copied forward. For **32,768** pairs conditioned on ΔS=0x80:

- Current recorded nonce: **0** confined to the old 3 bytes; active output count 13–16.
- Historical join-report nonce `b98b9c38…0eb3`, using the **current live** round code: **0** confined; active count 6–8.

A different high-bit trail **does remain** in the current demo schedule:

- Change raw input **cell 34**. When its first S output difference is 0x80, the round output stays inside **cells 56–63**, one 8-byte staff.
- Random nonzero input δ: **{modes['random_delta']['confined_count']:,}/200,000** confined pairs (rate {modes['random_delta']['rate']:.6f}). Exactly those pairs had ΔS=0x80.
- Best fixed δ **0x{trail['best_input_xor_delta']:02X}**, selected white-box from the keyed S DDT (4/256): **{modes['best_fixed_delta']['confined_count']:,}/200,000** confined pairs (rate {modes['best_fixed_delta']['rate']:.6f}).
- Explicit ΔS=0x80 conditioning: **200,000/200,000** confined, 5–8 active output bytes. Conditioning is an explanatory white-box experiment; the random/fixed-δ counts are the actual truncated-differential demonstrations.
- Ideal random-permutation probability for a *specified* 8-byte output set is approximately **2^-960**. Full x/y witnesses are in `attack_trails_results.json`, checked against live `N.encrypt_grid`.

This is a **1-round raw-block distinguisher**, not an attack on the 16-round randomized API.

### 5. A 2-round sparse-output distinguisher still exists

Count output-difference pairs with **at least 8 unchanged bytes**, the same criterion as the previous report:

- Broad 65,536-pair test: **2** events at 2 rounds, versus **0.00335** expected for a random permutation.
- Per-input scan, 128 cells × 4,096 fresh pairs: **36/524,288** events at 2 rounds, versus **0.02680** random expectation. All events arose at input cells **30 and 61**, **18/4,096 each**. Maximum observed unchanged bytes: **11**.
- Saved, live-verified witness: input **cell 30**, XOR difference **0x33**, leaves **10** unchanged bytes after two rounds: **[64,65,66,67,68,69,70,71,80,116]**. Full raw blocks are in `attack_sparse_results.json`.
- Live stage trace for that witness: round-1 butterfly and shell each preserve **one** active cell; pairs expand to 8, triplets to 7, encore ends at 8. Round 2 ends with 118 active bytes / 10 unchanged bytes. The residual integer crossing is still relevant even though field pairs prevent its staying a singleton through the whole middle.
- At 3 rounds: **0/524,288** sparse events (same 0.02680 random expectation). At 4 and 16 rounds: **0/65,536** each in the smaller broad test.

The older join-pairs report had 252 events in 524,288 pairs; the current measured count is **36**, not 252. That is an historical comparison, **not a controlled improvement factor**: the current recorded pickup gives a different nonce/schedule, as well as the subsequent mix changes. The old 53-unchanged-byte witness was not claimed to survive. **Two-round distinguishability does survive.** No 3+ round distinguisher was detected by these tests.

### 6. The tag still does not commit to mix tables

The HMAC authenticates the ciphertext **bytes** and public metadata; it does not identify the BARS/TRIPLETS interpretation. The SHA-256 schedule and MAC key do not take those tables as inputs. At the same seed and nonce, the actual pre-pickup library has the **same MAC key and schedule material** as live N2.

A fresh isolated import was changed **in memory only**, skipping the first pair and triplet in forward encryption. The live module and all source files stayed unchanged. Its clef, MAC key, and schedule material were identical; the ciphertext differed; its **195-byte** tagged blob **passes the live HMAC check**, then raises **DecodeError: tag valid but block malformed**. Complete witness is in `attack_integrity_pin_results.json`.

This demonstrates the missing algorithm/mix commitment, **not a seed-free forgery**: making that witness requires the secret key. No actual pre-pickup same-length blobs exist; the old 179-byte blobs reject at the initial length check. Their rejection must **not** be credited to a key signature that was never added.

## Reduced-round results (white-box, raw blocks)

| Rounds | Empirical byte dependence | Bit avalanche mean (sd, min), 4,096 pairs | Zero-byte Pearson statistic | Δ0x80@18 / byte38 histogram χ² (255 df) | ≥8 unchanged bytes, broad sample | Status |
|---|---|---|---|---|---|---|
{chr(10).join(rows)}

- Dependence: 32 random bases/nonzero deltas per input byte. Full observed support is not proof that every base and delta spreads.
- Avalanche: one random input-bit flip, 1,024-bit raw block; ideal mean 512, sd 16. Strong 1-round bias, near-ideal sampled means from 2 rounds; these aggregate means miss the rare 2-round sparse events.
- Zero-byte statistic: `sum_pos (count - n/256)^2/(n/256)`, 65,536 random single-byte input-difference pairs. This has **128 marginal count terms**, not a fixed-total multinomial with 127 df. The prior report's df127 label was not carried forward. Correlations affect calibration, so it is a descriptive diagnostic here, not a formal calibrated p-value.
- Histogram: 65,536 fixed Δ0x80-in-cell-18 pairs; complete 256-bin difference histogram at output byte 38. Ideal expected 256 per bin. This marginal statistic need not expose sparse trails elsewhere.
- Sparse random expectation uses `P(Binomial(128,1/256) >= 8)`, approximately **5.1114e-8** per pair. This is the ordinary ideal-permutation approximation; exclusion of the all-zero 1024-bit difference is negligible.
- Independent NumPy accelerator includes **both field pair passes and both triplet passes**. `attack_structure.py` cross-checked **128 live round evaluations**, and `attack_rounds.py` another 64; each validation also checked a full whitened 16-round encryption against `encrypt_grid`. Saved sparse/truncated witnesses were separately checked using the live library.

## Schedule / no AES

32 distinct seed-bit flips and 32 distinct nonce-bit flips were measured on the live schedule. The measured material is the 2,176-byte serialization of **round keys plus whitening**, not every S-box/permutation entry.

- Nonce flips: changed material fraction **{K['summary']['nonce']['material_fraction_range'][0]:.4f}–{K['summary']['nonce']['material_fraction_range'][1]:.4f}**; MAC-key bit changes **105–152/256**. Clef unchanged, as designed (seed-only).
- Seed flips: changed material fraction **{K['summary']['seed']['material_fraction_range'][0]:.4f}–{K['summary']['seed']['material_fraction_range'][1]:.4f}**; MAC-key bit changes **117–143/256**; clef changes **52–77/128**. Round-0 S-box changed in every sampled flip.
- M/K/C domain outputs distinct. This is a spot check, not a KDF proof.
- Source imports only `hashlib`, `hmac`, `os`. The S-box starts `d690e9fecce13db7…`, not AES's `637c777b…`; **both existing SM4 reference vectors passed using the live table**. The field multiplication is the explicit polynomial `0x1F5`, not AES MixColumns.
- Measured DDT maxima: SM4 base 4, keyed S 4, keyed S2 4; keyed S LAT maximum absolute bias count 16/256.
- **Disclosure:** SM4 and AES S-boxes both belong to the inversion-in-GF(2^8) affine-equivalence family. “Not AES” does not mean an unrelated algebraic family or a new security argument.

## Files and reproducibility

All new files are under `/workspace/sneak_n2/attacks_pickup/`:

- `common.py`: read-only live import and validated NumPy accelerator.
- `attack_integrity_pin.py`: corruption/legacy tests, public matching closure, copied-pickup insider witness, changed-mix tag witness.
- `attack_structure.py`: pair derivatives, integer helpers, multi-base combined/encore tests, current and historical-nonce high-bit comparisons.
- `attack_rounds.py`: 1/2/3/4/16-round diagnostics and 524,288-pair 2/3-round sparse scans.
- `attack_trails.py`: new 1-round trail, exact live 2-round witness stage trace, SM4 reference-vector check.
- `attack_schedule.py`, `verify_target.py`: schedule/no-AES and source/SIV verification.
- Each attack has `*_results.json` and `*_output.txt`; shell run logs end in `_run_output.txt`. `attack_rounds.py` additionally writes `attack_sparse_*`.
- `snapshot_protected.py`, `protected_before.json`, `protected_after.json`, `protected_verification.txt`; `write_report.py`, this `REPORT.md`.

To reproduce, run each script with **`PYTHONDONTWRITEBYTECODE=1 OPENBLAS_NUM_THREADS=1 python3`**. Run snapshot `before` before attacks and `after` afterward. Randomized PIN/pickup results will differ on a rerun; raw-block test RNG seeds are fixed. Do not rerun report generation before all corresponding result files exist.

**Execution issue disclosed:** the initial setup command used unavailable executable `python` and exited 127 before creating the snapshot script. It was rerun with `python3`; recorded in `setup_output.txt`. No attack script failed; no cipher alteration was made to accommodate an attack. Existing test suites were not rerun or rewritten. No older attack folder, seed, demo, snapshot, or PNG was changed.

## Bottom line

The pickup fixes **public encrypt-and-compare PIN matching**, not compromise of the secret seed/clef. The field pairs fix singleton derivatives in those primitives. The triplets are **not** singleton leaks on their own; the integer butterfly/mix2 still are. The old cell-18 three-byte trail no longer reproduces, but a **new eight-byte 1-round trail** and **36 two-round sparse events versus 0.0268 expected** remain. Missing mix-table commitment is independently witnessed. The recorded hello-world still decrypts; protected files are unchanged.

**No full 16-round break was demonstrated. This is not a security proof. Still homemade; not for real secrets. Use AES-GCM-SIV, age, or libsodium.**
'''
(p/'REPORT.md').write_text(body)
print('REPORT.md written',len(body),'characters')
