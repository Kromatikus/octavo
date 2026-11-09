from pathlib import Path
import json,datetime
P=Path(__file__).resolve().parent
read=lambda n:json.loads((P/(n+'_results.json')).read_text())
r=read('attack_rounds');s=read('attack_schedule');c=read('attack_second_coloring');n=read('attack_nonce');i=read('attack_integrity');d=read('attack_dependency')
rows=[]
for pair,one in zip(r['pairs'],r['integral1']):
 rr=pair['round'];two=r['integral2'][str(rr)]
 rows.append(f"| {rr} | {pair['unchanged_mean']:.4f} | {pair['avalanche_mean']:.2f} | {one['zero_xor_mean']:.4f} | {two['mean']:.3f} | {pair['best_delta128_prob']:.5f} / {pair['random_multiple_search_max']:.5f} |")
avrows=[]
for typ in ['seed','nonce']:
 for name in ['keys_white','S_tables','S2_tables']:
  z=s['avalanche_'+typ][name];avrows.append(f"| {typ} ({z['n']} flips) | {name} | {100*z['mean']:.4f}% | {100*z['min']:.3f}%–{100*z['max']:.3f}% |")
text=f'''# Attack report — CURRENT 8-bit N2, five bar mixes, late second coloring

> **Homemade and unreviewed. Not for real secrets. Use AES-GCM-SIV, age, or libsodium for anything real.** This is cryptanalysis, not a cipher modification or security certification.

- **Date:** {datetime.datetime.now().strftime('%Y-%m-%d %I:%M %p')} EST (America/New_York).
- **Target:** `/workspace/sneak_n2/sneak_n2.py`, imported live: 128 byte cells, 16 rounds plus whitening; round = XOR key → S → weave → staff butterfly → shell bridges → B0–B4 → S2. Blob is `SN2 || nonce(16) || ct(128) || tag(32)`, 179 bytes. Length byte + message + zero padding, maximum 127 bytes.
- **Scope:** black-box public encrypt/decrypt tests, and white-box/reduced-round tests with known seed/schedule. Reduced-round raw-block chosen sets need not be API-encodable messages and are not an outsider's production oracle.
- **Untouched:** live cipher, tests, SPEC, README, render, demo/hello-world, PNGs, existing `attacks/`, `baselines/`, seed, `/workspace/test1`, `test3`, `test13`, `testn1`, `sneak_t1n`, and `sneak_v2`–`sneak_v13`. Old `/tmp/sneak_n2_8bit_precolor2` was imported read-only, with bytecode disabled. Every new script/output/report is inside `attacks_8bit/`. `protected_before.json` and `protected_verification.txt` check 198 protected files, including original attack artifacts and existing bytecode.

## Verdict

**No plaintext or seed recovery against the current full 16-round cipher was demonstrated. No fresh MAC forgery was found. This is a negative experimental result, not proof of security.** N1's specific linear schedule inversion and tiny independent codebook split remain absent.

**A real compatibility flaw WAS demonstrated:** authenticated pre-second-coloring blobs retain the same version and MAC domain. All 2,048 generated legacy tags verified under the current code; 2,041 blobs raised `DecodeError`, but **7 were accepted as DIFFERENT plaintext**. Archived old hello-world raises `DecodeError`. This is authenticated legacy replay / algorithm-version ambiguity, not a fresh HMAC forgery or recovery of current ciphertext plaintext.

**Diffusion correction:** the earlier universal “full byte dependence at round 2” claim is false. The demo schedule has 56 structurally absent input/output dependency pairs after two rounds: output byte dependencies min/mean/max **120 / 127.5625 / 128**. Full byte dependency was witnessed at **round 3**. Of 17 schedules, 16 still had structurally missing paths at two rounds; all had full structural coverage by three. Only one had full two-round structural coverage (an upper bound, not an empirical proof for that schedule).

The tested truncated-differential, integral and bit-imbalance signals persist through **round 2**, but were not detected from **round 3** onward at these budgets. Historical 4-bit N2 had its strongest integral signal through round 3, dying at round 4; historical N1 reached about round 9. These are different query sizes/alphabets, not directly comparable security-bit estimates.

## Artifacts and reproduction

| Script | Saved output | Coverage |
|---|---|---|
| `attack_integrity_n2_8bit.py` | `attack_integrity_output.txt` | framing, all 1,432 bit flips, corruptions, splices, tags, pre-decrypt check |
| `attack_schedule_n2_8bit.py` | `attack_schedule_output.txt` | affineness, N1 basis predictor, K/M separation, both-coloring avalanche |
| `attack_rounds_n2_8bit.py` | `attack_rounds_output.txt` | measured DDT/LAT, dependencies, delta128, LSB, integrals, bit imbalance, avalanche |
| `attack_second_coloring_n2_8bit.py` | `attack_second_coloring_output.txt` | fused boundary maps, exhaustive mix properties, distinct colorings, old-blob replay |
| `attack_nonce_n2_8bit.py` | `attack_nonce_output.txt` | equality, XOR-keystream check, synthetic PIN oracle |
| `attack_dependency_n2_8bit.py` | `attack_dependency_output.txt` | exact nonzero modular-matrix supports, 17 schedules, stronger demo witnesses |
| `verify_protected.py` | `protected_verification.txt` | protected tree inventories and SHA-256 before/after |

Scripts also save JSON results; complete accepted legacy witnesses are in `attack_second_coloring_results.json`. `legacy_witness_verification.txt` independently checks one witness with **unmodified public APIs**, no schedule cache or monkeypatch. `common.py` imports the live cipher and provides a local NumPy batching helper; the rounds suite checked **1,024 intermediate states** (64 texts × all 16 live rounds) against `N.round_enc` before using it. Nonce suite checked another 512. White-box batch results do not depend on replacing the target file.

Run `PYTHONDONTWRITEBYTECODE=1 python3 attacks_8bit/attack_<name>_n2_8bit.py` from the target directory. NumPy was already installed. Fixed public-nonce schedule objects are memoized **in process only** for integrity/legacy repeated-tag tests; their HMAC comparison and decrypt API checks are unchanged. Random-nonce integrity tests use actual full schedule generation. No measured cache timing is presented as target timing.

## 1. Integrity — fresh corruption attacks rejected, legacy exception is real

| Test | Result |
|---|---|
| 200,000 uniformly random 179-byte blobs | all `AuthError` (almost all fail prefix; not 200,000 HMAC challenges) |
| 1,000 `SN2` + random nonce/ct/tag blobs | all `AuthError` |
| 10,000 `SN2` + real nonce + random ct/tag | all `AuthError` |
| All version/nonce/ct/tag single-bit flips | **24 + 128 + 1,024 + 256 = 1,432**, all `AuthError` |
| 3,000 random byte changes in each of nonce/ct/tag | 0 accepted / 9,000 |
| Splices across two valid blobs | 0 / 4 |
| Every shorter length 0–178; extensions +1..32 | 0 / 179; 0 / 32 |
| Seedless random tag guesses on a known valid nonce/ct | 0 / 20,000 |
| Total newly generated invalid/corrupted inputs | **241,647 `AuthError`, zero decrypt-grid calls** |

Instrumentation wrapped `decrypt_grid` to count entry; none of these fresh invalid inputs reached it. Source verifies `hmac.compare_digest` is applied to tag before block decryption. A key-holder-created invalid length-200 block with a valid MAC raises `DecodeError`, as expected.

**Do not generalize this to “an outsider never reaches DecodeError.”** An outsider holding a previously valid legacy blob can replay it and reach the current decoder (section 5). Also, ordinary valid-message replay is not prevented. Random-tag rejection experiments are sanity checks, not an empirical proof of HMAC's 256-bit security. This run used 1,000 random-prefixed blobs rather than the historical 10,000.

## 2. Schedule — the specific N1 linear inversion fails

Serialized material includes keys/whitening, ALL affine parameters for S and S2, rotations, butterfly permutations and bridges: **49,664 bits**. Eight seed and eight nonce GF(2) parallelogram tests all violated affineness. Fractions of material bits violating superposition: seed **35.63–36.02%**, nonce **35.74–36.26%**. Not 50%, because rotations/permutation entries have constrained alphabets and permanently zero high bits; this serialization is not a uniform byte stream.

The N1-style affine singleton-basis predictor for a fresh 1,024-bit seed got **17,791 / 49,664 bits wrong**. Every column required by that target's set bits was evaluated; zero-bit columns do not enter its linear prediction. This rules out that exact affine seed-recovery model, not every possible key-recovery method. Raw SHA-256 K-stream superposition had **16,259 / 32,768** violating bits.

| Flipped input | Material | Mean changed bits | Per-flip range |
|---|---|---|---|
'''+'\n'.join(avrows)+f'''

K/M streams had **16 coincident byte positions / 4,096** (chance expectation 16), were unequal, and MAC key did not appear in serialized schedule. No contiguous eight-byte seed window appeared in the 4,096-byte K stream. All 128 counter blocks differed. Integer-vs-byte seed interpretation produced identical schedule material. Source uses disjoint `SN2/M` and `SN2/K` hash domains with fixed field lengths. None of these tests establishes entropy or a 1,024-bit security level; the seed's actual entropy still matters.

## 3. S-boxes, diffusion and reduced-round distinguishers

### S and S2 themselves

All **32 instantiated boxes** on the demo schedule measured **DDT max 4/256**, **LAT absolute bias 16/256** (Walsh magnitude 32; maximum linear correlation 1/8). These are affine-equivalent SM4 boxes; independent affine wraps do not introduce a new S-box family. `S2 != S` held for **272/272 round pairs** across the demo plus 16 other nonces, as required by the resampling code.

### Dependencies and the old N1 split

| Rounds | Demo output-byte dependency min / mean / max | Independent input component sizes |
|---|---|---|
| 1 | 16 / 27.375 / 32 | [128] |
| 2 | 120 / 127.5625 / 128 | [128] |
| 3 | 128 / 128 / 128 | [128] |

Dependency witnesses used eight random bases × three nonzero deltas per input; a further 128-base two-round test gave the **same 56 missing pairs**. Exact matrices for the intervening modular-linear layers confirm no path exists for those pairs, rather than a missed small-sample change. A missing pair was also checked by exhaustive variation of all 256 input-byte values; the output byte stayed constant (indices in output file).

A support union is an upper bound on functional dependencies because nonlinear paths can theoretically cancel. On the demo, the measured witnesses attain that bound at all three reported rounds. At two rounds, 17-schedule structural minima were 112, 120, or 128; all were 128 at round three. No general key/nonce-independent round-two diffusion guarantee exists.

There is **no N1-style disjoint two-cell codebook split**, even at one round: the input/output dependency graph is connected over all 128 bytes. Connectedness rules out that specific factorized codebook, not all conceivable low-round attacks.

### Measured distinguishers

Pair tests used **8,192 independent pairs** tracked through rounds. Avalanche uses one random input-bit flip; unchanged-byte counts use one random nonzero input-byte difference. One-active-byte integrals: **64 sets × 256 texts**. Two-active-byte integrals: **8 sets × 65,536 texts**, substantially more queries than historical two-active-nibble 256-text integrals. Random unchanged and zero-XOR byte count expectation is **128/256 = 0.5**, not historical 8.

| Rounds | Mean unchanged bytes | Avalanche changed bits / 1,024 | Zero-XOR bytes: 1 active byte | Zero-XOR bytes: 2 active bytes | Best delta128 differential / matched random search max |
|---|---|---|---|---|---|
'''+'\n'.join(rows)+'''

- **Truncated differential / zero difference:** clear at rounds 1–2; round 3 mean 0.4955 ± 0.0077 standard error, consistent with 0.5. The structural missing-pair test gives a deterministic white-box two-round distinguisher.
- **Integral:** clear through two rounds (32.83 or 57.5 zero-XOR bytes); round three gives 0.4844 or 0.375, consistent with 0.5 at these budgets. The eight-set two-byte values in some later rounds are 0.125; with only eight sets (four zeros expected overall), those small means are not evidence of a reverse bias or a break.
- **Chi-bit / imbalance:** 64 one-byte sets give 51,433 stuck output bits at round one and 216 at round two, out of 65,536 tested set/bit combinations. From round three, zero stuck bits; maximum count deviations from 128 are 33, 36, 34, 32, 34 at rounds 3,4,5,8,16. Matched random max was 35. This is a max-imbalance diagnostic, not a formal independent chi-square p-value.
- **LSB approximations:** 32,768 random texts; global input/output-LSB parity bias 0.00082 at round one, 0.00171 at round two, and ≤0.0040 at every sampled later round. Single-test sigma ≈0.00276. Best of 384 single-input/single-output LSB comparisons ranged 0.00818–0.00943, below an approximate 1%-familywise threshold 0.012. No LSB signal was detected from round one, after accounting for searching masks.
- **Delta128:** round-one probability 1.0 is an untouched output with difference **zero**, NOT a nonzero high-bit trail. At round two the best sampled differential remains 0.0233 versus matched random search maximum 0.00757. At rounds 3–16 the best values agree with the matched multiple-search baseline. Comparing a maximum over 32,768 bins directly to 1/256 would exaggerate evidence.
- **Avalanche:** round two is not fully random despite mean 509.26: sampled minimum is 115 and incomplete diffusion remains. Round three mean 511.73, full-round mean **512.04 ± 0.176** standard error. Full-round sampled range 454–572 is not a security bound. Neither a good mean nor a high minimum establishes resistance to differential cryptanalysis.

**Last clear signal among these tests: round 2; none detected at rounds 3,4,5,8,16.** This is not “every possible distinguisher dies at round three,” nor a quantified 13-round security margin. Most statistics use one fixed demo schedule. No MILP/SAT trail search, boomerang search, exhaustive key guessing, or complete cryptanalysis was performed.

## 4. What the second coloring does — and does not do

### Adjacent nonlinear layers DO fuse

At each round boundary, each cell undergoes

`C[r,j](x) = S[r+1](S2[r](x) XOR rk[r+1,j])`.

**This is exactly one 8-bit permutation table.** Two adjacent colorings with only XOR between them can always be fused; asserting that they cannot be “equivalent to one S-box” is mathematically wrong if “one S-box” means an arbitrary lookup table. There is no intervening diffusion. The entire construction can be expressed with 16 modular diffusion layers and 17 substitution stages (interior stages have cell-dependent fused tables), not 32 diffusion-separated nonlinear stages.

For all **1,524 distinct actually-used boundary/key-byte combinations** on the demo schedule:
- no fused table was affine or identity;
- DDT maxima ranged **10–18**, versus 4 for each component;
- every fused DDT max exceeded 4, so none was affine-equivalent to the original SM4 family;
- one representative per boundary had LAT absolute bias **32–40**, versus 16 for a component.

Thus there was no affine cancellation, but the fused local differential/linear maxima are **worse**, not automatically better, than a single component. This does not establish a full-cipher attack. It does invalidate the simplistic premise that adding nonlinear tables necessarily makes a cipher more secure, or that their probabilities simply multiply independently.

### Modular mix weaknesses remain local

For `mix2` and each B0–B4 matrix, **all 65,536 input pairs** obeyed the predicted linear LSB relation and deterministic propagation of a first-input XOR-0x80 difference according to matrix coefficient parity. Modular addition is linear over Z/256, **not GF(2)-linear on the entire byte** (carries are nonlinear in bits). Its LSB plane is GF(2)-linear, and XOR 0x80 equals addition 128 modulo 256.

Both S and S2 break that deterministic high-bit rule: for fixed input difference 0x80, every measured box's largest exact output-difference count is **4/256**, not 256/256. Delta128→delta128 appeared 16/4,096 cases through S and 14/4,096 through S2 across all 16 boxes. This blocks a trivial unchanged high-bit trail through the coloring, not all multi-round trails. Residual one-/two-round truncated/integral structure still exists as section 3 shows.

## 5. Legacy same-length blobs — demonstrated semantic acceptance flaw

Read-only source: `/tmp/sneak_n2_8bit_precolor2`. Its public hello-world blob is exactly 179 bytes and uses the same `SN2` prefix, seed/nonce MAC derivation and HMAC transcript. Current and legacy demo MAC keys matched.

| Legacy input | Current behavior |
|---|---|
| Archived old hello-world | HMAC verifies; `DecodeError` |
| 2,048 freshly generated valid legacy 127-byte-message blobs | **2,048 HMACs verify** |
| Of those 2,048 | **2,041 DecodeError; 7 accepted as wrong plaintext; zero AuthError** |

The deterministic reproduction and complete blob/message witnesses are saved in JSON. At least one accepted witness was rechecked using both original public decrypt functions with no monkeypatch: old decrypt returns its original 127 bytes; current decrypt returns **different** 127 bytes. An attacker need not forge a tag to replay an already obtained old blob. The test used known-key legacy generation to construct a corpus, not a claim that the attacker can manufacture arbitrary valid old blobs without a key.

The encoding check is not cryptographic authentication. If a wrong decoded block were uniform, the chance that its length/padding happens to pass is approximately **1/255** (dominant event: first byte 127, probability 1/256, requiring no zero padding). Observed 7/2,048 is compatible with this heuristic; uniformity is not proven. Therefore this is **not universal fail-closed**. No files or protocol versions were changed in this pass.

## 6. Nonce reuse and plaintext guessing

Same seed + nonce + message gave identical whole blobs. Full-cipher XOR-keystream identity `ct1 XOR ct2 == encoded_pt1 XOR encoded_pt2` held **0/300** random pairs. Mean ciphertext-XOR weight was **511.56/1,024**; one plaintext-bit change under reused nonce gave **511.99/1,024**, range 469–556 across 300 tests.

A deliberately fixed-nonce encryption oracle recovered the synthetic `PIN=731` by **732 sequential guesses** in a 1,000-value dictionary. This is generic deterministic encryption equality confirmation, not ciphertext-only recovery. Wrong guess + oracle says “no”; matching oracle result says “yes”; without oracle/key, these tests do not resolve a guess. No ciphertext-only plaintext was recovered.

`encrypt()` calls `os.urandom(16)` if nonce is omitted; all 32 sampled default nonces were distinct. Explicit caller-provided nonce reuse remains possible. Equality and replay are not the same as a stream-cipher XOR-reuse catastrophe.

## 7. Comparison and remaining issues

| Attack class | Historical N1 | Frozen 4-bit N2 report | Current 8-bit N2, bars + S2 |
|---|---|---|---|
| Fresh invalid ciphertext accepted | ~1/255; no MAC | 0 sampled, HMAC first | 0 / 241,647 fresh invalid attempts |
| GF(2) seed recovery | demonstrated | affine predictor fails | affine predictor fails, no recovered seed |
| One-round factorized codebook | 64 independent 2-nibble pieces | gone | gone, connected 128-byte graph |
| Strongest tested reduced-round signal | about round 9 | integral through 3; random-like from 4 | through 2; not detected from 3 |
| Full byte/nibble dependency | slow | round 3 | demo round 3; NOT universally round 2 |
| Nonce equality / oracle dictionary | remains | remains | remains |
| Legacy algorithm ambiguity | not assessed here | different 115-byte format | same-length pre-color2 tags authenticate; 7 wrong accepts shown |

Historical numbers are quoted from the untouched old report, not independently rerun against N1. Its “only possible remaining seed attack is SHA-256 inversion” and “security margin” phrasing are too strong: failure of one structural model does not prove all alternatives impossible. Statistical comparisons across changed block/S-box sizes and query budgets do not prove improvement is caused solely by S2.

Remaining concerns include unversioned authenticated legacy formats, fixed-nonce equality/dictionary and replay behavior, same affine S-box family, fused-boundary differential peaks, modular low-bit/high-bit structure, no rigorous active-S-box/trail bound, and data-dependent Python lookups/resampling. Only HMAC comparison is deliberately constant-time; neither the cipher nor key schedule is. The implementation constructs the entire keyed schedule before verifying a correctly framed blob's tag, so unauthenticated traffic can consume schedule-generation work. No side-channel extraction or operational DoS was attempted.

**Current full 16-round confidentiality was not broken by these scripts. That is not a claim of safety, proof, or comprehensive review. Not for real secrets: use AES-GCM-SIV, age, or libsodium.**
'''
(P/'REPORT.md').write_text(text)
print(P/'REPORT.md')
