# OCT-2 — Reduced-round cryptanalysis of live Octavo (NR = 16)

Date: Sat Nov 21, 2026 (ET). Target: `/workspace/sneak_n2/sneak_n2.py`, SHA-256 `19181bc1623115c075dc5dee25edec388f5413466777d47b7f19fa66d1e71eee` (read-only; checked before every import and again at the end — unchanged). No live or frozen file was modified, nothing was pushed or posted, and no picture was drawn.

## Method
- White-box reduced rounds under fresh random **lab** seeds and nonces, with several schedules per test. `harness.py` (Stage 0) and `octavo_np.py` are a NumPy batch copy of the live round, checked bit-exact against `harness.enc_r` on 96 cases including 16 rounds (`octavo_np_check.txt`). It runs at about 11 µs per block per round.
- Granularity is finer than whole rounds. One Octavo round has four keyed S-box layers (S, the mid B0 and odd-rehair Latin pairs, S2, and the encore Latin pairs) plus many mixing layers, so results are also given at sub-round checkpoints. **"0.5 round"** means through the first `cross_staff_mix`, before S2.
- **Free peel:** the last layer of every round (`cross_staff_mix`) is unkeyed and XOR-linear, so an attacker can invert it on output differences and XOR-sums at no cost. Every test was run both raw and peeled.
- Positive controls (earlier checkpoints) confirm that each test detects structure where it exists.

## Results

| Attack | Most rounds distinguished (empirical) | Evidence | Sample size |
|---|---|---|---|
| Diffusion (Stage 1) | **Full diffusion in 1 round**, and already at 0.5 round | After one round every input byte reaches every output byte, with 127.5/128 active bytes (random). The 1024×1024 bit SAC matrix matches random at 1–4 rounds, and at the 0.5-round checkpoint. | 4 schedules × 128 pos × 64; SAC 2 × 1024 bits × 512 |
| Differential (Stage 2) | **0.5 round** (peeled) | With the peel, 0.5 round shows 72 always-zero difference bytes. Raw output at 0.5 round, and 1, 1.5 and 2 rounds peeled: max z ≤ 4.4, at the noise level (threshold 5). Also tested 2^20 pairs at 1 round: nothing. | 2^16 pairs × 3 schedules × 8 differences; 2^20 at r=1 |
| Linear (Stage 3) | **< 0.5 round** for this mask family | 0.5, 1, 1.5 and 2 rounds: max z 4.9–5.3. The null expectation is about 5.4 over 2M statistics, so this is noise. Positive control right after the first S layer: \|corr\| 0.138 (z 35). | 2^18 texts × 2 schedules × (2044 in-masks × 1024 out-bits) |
| Integral / square (Stage 4) | **0.5 round** (peeled) | One active byte: at least 72 of 128 bytes balanced at 0.5 round peeled. Two active bytes: at least 88. After S2 (0.6 round) it looks random. A 2^24 three-byte set at 1 round gave 2/128 balanced, which is random. | 8 trials per set; one 2^24 trial |
| Algebraic / cube (Stage 5) | **0.5 round** | Spread cubes give full zero-sums from d = 8 (degree about 4–5) at 0.5 round. After S2, and at 1 and 2 rounds, the zero-sum fraction is 0.49–0.52 (random) for every d ≤ 20. | d = 4…20, 3 trials each |
| Single-shell trails | **None beyond about 0.4 round** | A difference or integral confined to one shell reaches 13% of the other shell after the shell bridge, 48% after odd_restack, and 99.6% (random) after the first `cross_staff_mix`. Balanced-byte counts for inner and outer are symmetric. The weave also moves bytes between shells before the bridge. | Stage 1(c), 1b, 4 |

**Overall: the best empirical distinguisher reaches about half a round of 16** (structural, chosen-plaintext, under one schedule).

### Bound reasoning (not empirical)
- Keyed S-boxes are affine-equivalent to SM4. DDT max is 4 (DP 2^-6) and LAT max is 16 (|corr| 2^-3); both were re-checked on 12 sampled boxes.
- **My own simple but rigorous bound:** every nonzero state difference or mask activates at least one keyed S-box in each of the four S-box layers per round. For the Latin layers this holds because the odd-rehair pairs cover all 8 beats. That gives at least 4 active S-boxes per round, so a trail has EDP and ELP ≤ 2^-24 per round.
- **Prior sound relaxed bound** (from `sneak_n2/attacks_linear_algebraic/REPORT.md`, not re-derived here): the cross-staff branch number is 6, giving at least (2R−1)·6+2 active S-boxes. That is ≥ 20 / 32 / 44 for R = 2 / 3 / 4, and 188 for R = 16.
  - At 4 rounds the trail bound is ≤ 2^-264. So **no single differential or linear trail better than 2^-256 exists beyond 3 rounds.**
  - This covers trails only. Differentials and linear hulls (clustering) are **not** bounded.
- **Algebraic:** after the half round the degree is about 5. S2 (degree 7) could keep the degree ≤ ~35 just after S2. In principle that allows a 2^36-text zero-sum at about 0.6 round; this was **not tested**. The keyed B0 and odd2 S-boxes push the degree past that inside round 1.

## Key-recovery extension and margin
- **Extension estimate: +1 to +2 rounds, granted generously.**
  - In practice it is much harder than in AES-like designs. Diffusion is complete within one round, and each round has its own 1024-bit round key plus four keyed affine S-box parameter sets, all squeezed from SHA-256 and independent of each other.
  - Peeling one round to check a guess needs essentially the whole round's material, which is well over 2^256 guesses.
  - Even so, the usual +1–2 is allowed below.
- **Attackable rounds:**
  - Empirical: 0.5 round distinguisher plus 2 rounds of key recovery, so **≤ 2.5 rounds**.
  - Bound-based (trail bound crosses 2^-256 after 3 rounds): **≤ 5 rounds**.
- **Safety margin against 16 rounds:**
  - Empirical: **≥ 13.5 rounds (about 84%)**.
  - Against the bound-based estimate: **≥ 11 rounds**.
- These margins are larger than AES-128 (best attacks around 7 of 10 rounds). This is a statement about the limited tests run here, not a proof.

## Caveats
1. **Per-schedule model.** Every test fixes one Schedule (seed + nonce) and makes many chosen-plaintext queries under it. In the real API each message gets a fresh SHA-256-derived schedule.
   - An outsider normally sees one block, or one rehearsal chunk, per schedule.
   - Rehearsal chunks do put many blocks under one schedule, but each block is masked with a secret per-block tweak. So chosen differences between blocks are not known to the attacker.
   - These are white-box, best-case-for-attacker lab results, not a multi-message attack.
2. **Sample sizes are modest:** 2^16 to 2^20 pairs, 2^18 texts for linear, cubes up to d = 20, and a single 2^24 integral trial. Weak biases (below about 2^-9 correlation, or differentials below about 2^-10 per byte) would not be seen.
3. **Narrow search families:** single bit/byte input differences, a few structured ones (shell-wide, two-byte), single-bit output masks plus one free peel, byte-aligned integrals, and packed/spread cubes.
4. **Not tested:** automated trail search (MILP/SAT), truncated or impossible differentials, boomerang/rectangle, multidimensional or zero-correlation linear, division-property integrals, cubes above 2^20, related-key and related-nonce (partly covered in prior work), slide, and side channels.
5. Bounds cover **trails, not hulls or differentials**. The prior relaxed bound treats the triplets and bow as arbitrary bijections, which is sound but loose.
6. **A negative result is not a proof of security.**

## Files (all in `/workspace/reduced_round_octavo`)
- `PROGRESS.md`
- `harness.py`, `octavo_np.py` (+ `octavo_np_check.txt`), `stage2b_peeled_lib.py`, `stage5_lib.py`
- `stage1_diffusion.py`, `stage1b_subround.py`
- `stage2_differential.py`, `stage2b_peeled.py`
- `stage3_linear.py`, `stage3b_control.py`
- `stage4_integral.py` (+ `stage4_run1_partial_output.txt`)
- `stage5_algebraic.py` (+ `stage5_run1_*`), `stage5b_fullround_check.py`
- Each script has a matching `*_output.txt` and `*_results.json`.

## Honest verdict
Octavo is still homemade. These tests found nothing beyond about half a round of 16, but a negative result is not a proof, and no outside cryptanalyst has reviewed it. For real secrets use AES-GCM-SIV, age, or libsodium.
