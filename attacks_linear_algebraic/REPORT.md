# N2 linear + algebraic attack (live N2, keyed-Latin + signature-gap era)

Target: `/workspace/sneak_n2/sneak_n2.py`, SHA-256 `0eb6052f7ef1e48a952c5530983acead5932be469693134b65f2b21aaf5092c1` (asserted before every import).
Mode: attack only. White-box round functions under a fixed schedule (`Schedule(seed, hello-world nonce fc072c30…)`), with an independent NumPy batch checked against live `round_enc`/`encrypt_grid` before each run. Nothing in the cipher, tests, docs, hello-world, PNGs, render script, seed, snapshots, baselines or older attack folders was changed (see `protected_verification.txt`). No picture was drawn.

**Still homemade. A negative result here is not a proof. For real secrets use AES-GCM-SIV (RFC 8452), age, or libsodium.**

## Headline

**No break found.** No linear, algebraic, integral, cube, slide, related-nonce, integrity or differential weakness was found beyond round 1 in a fixed-schedule white-box model. The real API is harder still, because every message gets a fresh SHA-256 schedule.

* **Linear:** every keyed S and S2 table has max |correlation| 2^-3, the same as SM4. The cross-staff layer has linear and differential branch number **6** (exact). A relaxed but sound single-trail model gives at least **8 / 20 / 32 / 44** active S-boxes over 1 / 2 / 3 / 4 rounds and **188** over 16. That bounds correlation at ≤ 2^-24 / 2^-60 / 2^-96 / 2^-132, and ≤ 2^-564 at 16 rounds. In the experiments, all 2^20 single-bit approximations after 1 and 2 rounds stayed at the noise floor, and the largest ones were not there in fresh data.
* **Algebraic:** all S, S2 and inverse-S tables have degree 7. Each S-box has **23 bi-affine** and **39 fully quadratic** equations, the same counts as AES/SM4 inversion S-boxes. Cube sums (d = 1 to 16) and XOR-integrals are fully structured *before the triplets* in round 1 (positive control). After one full round they look random. An additive (mod 256) integral, which the triplets preserve, also dies inside round 1.
* **Slide / related nonce:** in 200 schedules, no two rounds matched (24,000 pairs). A one-bit nonce flip gives unrelated schedules (round-key HD 513 ± 16; S-table agreement 1.0 ± 1, the same as random permutations). Nonces are synthetic and HMAC-bound.
* **Regression:** all integrity checks fail closed. 1, 2, 3, 4 and 16-round sparse scans had 0 hits, with at most 6 unchanged bytes. Avalanche was 512.4 bits of 1024. B0/Latin singletons were **0**, and bow+restack singletons were **5** (all beat 7), which is the known leftover.

## 1. Linear cryptanalysis (`attack_linear.py`, `attack_linear_results.json`, `attack_followup_results.json`)

| item | result |
|---|---|
| LAT of S, S2 (16 rounds × 2 schedules = 64 tables) | max \|LAT\| 32/256 → corr **2^-3** in every table; full \|LAT\| spectrum identical to SM4 (affine equivalence) |
| field pairs B1, M2, B2, M3, B3, B4, mix2 | GF(2)-linear: correlation 1 along the transposed mask; byte-level linear and differential branch number 3 each |
| Latin pair (B0, rehair) | corr = LAT_S(a1,b1)·LAT_S2(a2,b2)/2^16 (300 brute-force checks, deviation 0). One output cell masked: ≤ 2^-3. Both masked: ≤ 2^-6. Active S-boxes = masked output cells |
| triplets mod 256 | **bit 0 exactly linear** (corr 1, verified on 20,000 grids), e.g. out cell 0 bit 0 = in bits 0 of cells 0⊕1⊕2. Bit 1 (exhaustive mod 4): best corr 2^-1 to 2^-3. Bit 2 (exhaustive mod 8): 2^-2 to 2^-3.9 |
| bow ARX (one staff, 2^20 samples) | strongest single-bit relation is in cell 6 bit 0 → out cell 7 bit 4, corr **0.0399 (≈2^-4.6, ~40σ)**. 9 relations at ≥ 0.01, none at ≥ 0.1 |
| cross layer per beat (16×16 over GF(2^8)) | **branch number 6** in both differential and linear directions (exhaustive over input weight ≤ 3 both ways ⇒ exact) |

**Trail model (sound lower bound on active S-boxes in a single trail):** S, S2 and both rehair Latin layers are counted exactly. Triplets plus bow are relaxed to an *arbitrary* staff-local bijection (any mask, correlation up to 1). B0 and the GF-linear layers count as free. Each cross layer forces (rehair-out masked cells) + (next S-layer masked cells) ≥ 6. That gives a minimum of (2R−1)·6 + 2 active S-boxes over R rounds:

| rounds | ≥ active S-boxes | trail corr ≤ | data ≈ 1/c² |
|---|---|---|---|
| 1 | 8 | 2^-24 | 2^48 |
| 2 | 20 | 2^-60 | 2^120 |
| 3 | 32 | 2^-96 | 2^192 |
| 4 | 44 | 2^-132 | 2^264 |
| 8 | 92 | 2^-276 | 2^552 |
| 16 | 188 | 2^-564 | 2^1128 (> 2^1024 codebook) |

Best trail found: no concrete multi-round trail was built. The best *bound* is the relaxed one above, and it is loose, because the real triplets and bow cannot produce every pattern. Linear hulls were not bounded.

**Empirical (fixed schedule):** I measured all 1024 × 1024 single-bit input → output correlations.
* 1 round, N = 2^18: max |c| = 0.00979 (5.0σ), against an expected null max of 0.0105. There was 1 entry over 5σ (≈0.6 expected), and the mean |c| matched the null to 4 digits. The argmax (in 39.3 → out 22.7) re-measured on 2^20 fresh samples was 0.00052 (0.5σ): noise.
* 2 rounds, N = 2^17: max |c| = 0.0140 (5.1σ), against an expected 0.0149. There were 2 entries over 5σ. The argmax (37.6 → 77.3) re-measured at 0.00044 (0.4σ): noise.
* LSB-plane full parity: −0.0042 (1 round) and +0.0052 (2 rounds), both ≈2σ.
* Positive control (one keyed S-box, best LAT mask): measured 0.1224 against a predicted 0.125.

**Reach, honestly:** under the relaxed bound, a fixed-schedule white-box linear distinguisher could in principle stay under the 2^1024 codebook up to about **14 rounds**, but only with absurd data (2^552 at 8 rounds). Within a 2^80 budget it reaches only **1 round**. In the real API, each message has its own schedule, so an outsider gets one block per schedule, and statistical linear attacks do not apply as written.

## 2. Algebraic (`attack_algebraic.py`, `attack_algebraic_results.json`, `attack_additive_integral_results.json`)

* **Degree:** every nonzero component of S, S2 and SI (48 tables) has degree **7**.
* **Quadratic equations per S-box:** **23 bi-affine** (81 monomials) and **39 fully quadratic** (137 monomials), for the SM4 base and for every keyed table. The keyed affine-equivalent S-box has the same counts. Note that the "39" is the full-quadratic count; the bi-affine count is 23.
* **Cube / higher-order differential** (8 random bases; random expectation is 4 always-zero bits and 8 constant bits):
  * Positive controls: S + weave + butterfly + shell gives all 1024 bits zero for every cube with d ≥ 7 in one cell, and for every multi-cell cube. "… + bars (before triplets)" gives 1024/1024 at d = 8 and for multi-cell cubes.
  * 1 round, 2 rounds and 3 rounds (d = 1 to 16, across cells, across shells, bit 7 of 12 cells) all gave 1 to 8 zero bits and 3 to 13 constant bits, which is random.
  * The two largest outliers (1-round d = 1 and 3-round d = 8, each 8 vs 4 expected) gave **0/1024** always-zero bits on a 32-base re-run.
* **Integral / square:**
  * One cell at all 256 values (every cell, 2 bases), before the triplets: 128/128 XOR sums are zero. After 1, 2 and 3 rounds the mean is 0.50, 0.45 and 0.50 zero-sum cells (random 0.5), and 0 balanced cells.
  * Staff diagonal and staff-shifted 256-sets: random by 1 round (0.44 zero sums).
  * Two cells at all 65,536 values at 1 and 2 rounds: 0 to 2 zero-sum cells, and 475 to 526 zero-sum bits (random 512).
  * Additive mod-256 sums survive the triplets (89% are 0 or 128, mostly from inactive cells) and the bow (59%), then are random after the full round (0.9%, random 0.8%).
* **System size, 16 rounds (rough):** 9,216 S-boxes (576 per round) give 359,424 quadratic equations in 73,728 state bits. Add about 33.8k mod-256 additions (triplets 1,888 and bow 224 per round) with about 237k carry variables and 473k carry equations. On top of that, 3,584 bow strokes with data-dependent rotations need 7-way multiplexers (p mod 7 is high-degree).
* **Key side:** there are about 1,933 unknown schedule bits per round, about 31.9k per schedule. One block gives 1,024 equations, so per-schedule key recovery is hugely underdetermined. The seed is behind SHA-256. Round-key-level algebra matters only for many-block distinguishers in the lab model, and the cube and integral tests found nothing past round 1.

## 3. Slide and related nonce (`attack_slide_nonce.py`, `attack_slide_nonce_results.json`)

* Every round runs the same code. The only things that differ per round are the schedule material (rk, S, S2, SH, SV, σ, bridge) and the shell orientation (r mod 2), and there is a final whitening.
* Across 200 schedules × 120 round pairs, equal rk / S / S2 / σ / bridge / SH / SV / full round counts were all **0**, and S = S2 in the same round was 0. No slide pair exists.
* One-bit nonce flips (64 pairs):
  * MAC-key HD 127.5 ± 9.6
  * whitening HD 511 ± 16
  * round-key HD 513.2 ± 16.2
  * S-table agreement 1.02 ± 1.02 and S2 agreement 1.03 ± 1.01 (random permutations: 1)
  * σ fixed fraction 0.127 (1/8 expected), bridge fixed points 1.02 (1 expected), SH 0.125, SV 0.062
  * equal rk or S across any (round, round′) pair: 0
  * per-key-bit flip rate over 16,384 bits: mean 0.5011, max |z| 3.75 (null max ≈ 4.56)
  * ciphertexts of the same block under nonces 1 bit apart: HD 512 ± 16
* In the API, flipping a nonce bit in the recorded blob gives `AuthError: tag mismatch`. Nonces are SHA-256(clef ‖ pickup ‖ block), so an attacker cannot choose them.

## 4. Regression (`attack_regression.py`, `attack_regression_results.json`)

* **Integrity:**
  * The recorded hello-world (pickup `76908595…`) decrypts.
  * All 1,560 single-bit flips fail: 1,536 tag mismatches and 24 bad-version errors.
  * The previous sample (pickup `24d554eb3d22f0b6412d7da59e504df1`) gives `AuthError: tag mismatch`.
  * 14/14 field splices with the previous sample give tag mismatches.
  * 198 wrong lengths give bad-length errors.
  * 100 random SN2 blobs give tag mismatches.
  * Nothing was accepted, and there was no DecodeError.
* **Sparse-output differential** (single-cell random delta, ≥ 8 unchanged bytes counts as a hit):

| rounds | pairs | hits | max unchanged |
|---|---|---|---|
| 1 | 262,144 | 0 | 6 |
| 2 | 262,144 | 0 | 6 |
| 3 | 131,072 | 0 | 6 |
| 4 | 65,536 | 0 | 5 |
| 16 | 16,384 | 0 | 5 |

  The mean number of unchanged bytes was 0.50 at every round count (random 0.5).
* **Avalanche:** one-bit flips change 512.36 bits after 1 round and 512.44 bits after 16 rounds (ideal 512; 4,096 pairs each).
* **Singletons:** B0/Latin has **0** over 2 × 255 × 65,536 cases, on the test tables and on all 16 hello-schedule rounds. Bow+restack has **5/522,240**, the test-suite set, all from beat 7. This is the known leftover. Witnesses (demo schedule, round-0 tables):
  `[26]*8 Δ36→beat7`, `[53]*8 Δ225→beat7`, `[117]*8 Δ78→beat6`, `[142,151,20,118,251,3,37,161] Δ39→beat6`, `[91,12,141,148,97,40,0,144] Δ177→beat6`.

## Copy-pasteable witnesses

```python
import sys; sys.dont_write_bytecode=True; sys.path.insert(0,'/workspace/sneak_n2'); import sneak_n2 as N
g=[[0]*8 for _ in range(16)]; g[0][0]=1; g[1][0]=250
[r[0] for r in N.cross_staff_mix(g)]            # [251,0,0,0]*4 : 2 -> 4 staffs, branch 6
# linear mask through cross (beat 0): out mask 1 on staffs 0,4  <->  in mask 3 on staffs 4,5,12,13 (corr 1), branch 6
# triplet LSB: (trip(x)[cell0] & 1) == (x0 ^ x1 ^ x2) & 1   for every staff
# bow: corr(in cell6 bit0, out cell7 bit4) ~ +0.040 over random staffs
# Latin pair: corr = LAT_S(a1,b1)/256 when only u' is masked -> max 2^-3
```

## Replay

`python3 /workspace/sneak_n2/attacks_linear_algebraic/attack_replay.py` (about 3 s; output in `replay_output.txt`).

## Not covered / limits

* The trail bound is single-trail and relaxed. No linear-hull bound was computed, and there was no MILP/SAT search for concrete best trails.
* The cube tests stopped at d ≤ 16, with 8 bases (32 bases for re-runs).
* The integral tests covered only 8-bit and 16-bit sets.
* There was no Gröbner or XL solving attempt; the system-size figures are only estimates.
* These are all lab models with a fixed schedule; the API rekeys per message.
* Still homemade, and not for real secrets: use AES-GCM-SIV, age, or libsodium.
