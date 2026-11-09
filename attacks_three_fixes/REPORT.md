# Attack report: CURRENT LIVE N2 after the three leftover-shape fixes

> **This is a homemade, unreviewed cipher. Do not use it for real secrets.** Use AES-GCM-SIV (RFC 8452), age, or libsodium for those. This report is cryptanalysis only. I made no fixes, did not start N3, and did not redraw or regenerate any picture. Negative results are not security proofs.

- **Date:** Sunday 2026-11-08. Snapshot before: 06:40:13 PM EST. Runs: 06:40–06:52 PM EST. Snapshot after: 06:52:37 PM EST (America/New_York).
- **Live target:** `/workspace/sneak_n2/sneak_n2.py`, SHA-256 `46274b690e3d3ae53649b810591681b94f53983c72f6fb9789a19c8670003f45`. The hash matched the expected value before and after the runs. `common.py` asserts this hash on import. Every script imports the live file read-only, and no cipher copy was "fixed".
- **Changes since `attacks_pickup/`:**
  1. The HMAC now covers a **key signature**: `key_sig = StaffSponge(b"G", seed, mix_description()).take(16)`, so `tag = HMAC(mac_key, clef || key_sig || SN2 || pickup || nonce || ct)`. `key_sig` is not stored in the blob.
  2. `mix2` (butterfly and shell bridges) is now `((1,1),(1,2))` over the SM4 field GF(2^8), polynomial `0x1F5`. It used to be the integer map `(u+v, u+2v)`.
  3. **Bow pressure** (overlapping ARX strokes) now runs after the mid-round triplets and again after the encore triplets.
- **Blob:** 195 bytes. Pickup is `[3:19]`, nonce `[19:35]`, ct `[35:163]` and tag `[163:195]`. `encrypt(msg, seed=None, nonce=None)` has no pickup argument.
- **Scope:** I ran (a) public-API tests: the randomized `encrypt()` oracle and tampering with `decrypt()`. I also ran (b) **known-seed white-box** raw-block reduced-round tests on one fixed schedule. Unless noted otherwise, that schedule is `Schedule(seed, db8839e79ca2a40a9a68932502a72982)`, the nonce of the current recorded hello-world. The randomized public API does not give an attacker access of type (b).
- **Protected files:** **1226/1226 byte-identical**: 0 changed, 0 added, 0 removed outside this folder. See `protected_verification.txt`. The check covered the live cipher, tests, SPEC/README, hello-world, demo-nonce, render_n2.py, all workspace PNGs (both sneak-staff-n2.png copies included), the seed, test1/3/13, testn1/testn3, sneak_t1n, sneak_v2–v13, every older attack folder, and all `/tmp/sneak_n2_*` frozen snapshots.

## Verdict

I did **not** recover plaintext, recover the seed, or forge a tag against the full 16-round cipher. All three fixes do what they claimed in these tests. The 2-round sparse distinguisher from the pickup era is **gone at the current test size**: 0 events in 524,288 pairs, against about 0.027 expected at random. The cell-34 one-staff trail is gone. One structural distinguisher remains, and every version of this cipher has had it: a **probability-1 one-round truncated differential**. A single input cell only reaches 5–8 of the 16 staffs after one round. It did not survive to 2 rounds in my tests. None of these results proves the cipher secure.

## What held

| Check | Result |
|---|---|
| Recorded hello-world (pickup `28c124012bb2fb435a6928e1c8dc62aa`, nonce `db8839e79ca2a40a9a68932502a72982`) | decrypts to `b'hello world'`. The nonce formula `SHA-256(clef‖pickup‖encode_block(msg))[:16]` and the full HMAC (with key_sig) were recomputed independently and match. Re-encryption gives a different blob. |
| All 1,560 single-bit flips | 1,560 AuthError (1,536 tag mismatch, 24 bad version prefix). **0 payloads.** |
| 1,000 random ciphertext-byte corruptions | 1,000 AuthError (tag mismatch) |
| 40 pickup swaps + 160 other splices (nonce, ct, tag, half-ct) | 200/200 AuthError (tag mismatch). A same-message pickup swap also gives tag mismatch. |
| 1,000 random `SN2`-prefixed blobs + 200 random blobs | 1,000 tag mismatch + 200 bad version prefix |
| Wrong lengths 0,1,2,3,19,35,163,178,179,180,194,196,211,300 | all AuthError "bad blob length" |
| Legacy blobs | testn3 and the 179-byte pre_pickup, pre_triplet, pre_join_pairs, pre_field_retune, pre_clef_encore_siv, 8bit_prebar and 8bit_precolor2 blobs: AuthError bad length. The 115-byte (premeter/preloop/4bit) and 203-byte (looped/unlooped meter) blobs: AuthError bad length. Each old library still decrypts its own blob, and 10 fresh blobs from each old library are all rejected by the live code. |
| **Pickup-era 195-byte hello-world** (pickup `8b9291ce06eaf92767cfa2c89d68b639`, nonce `4ea3cefffeabc7257c7f26181a63f08a`, from `/tmp/sneak_n2_pre_three_fixes/hello-world.txt`) | **AuthError: tag mismatch**, with no payload. 10/10 fresh blobs from the pre-three-fixes library also give tag mismatch. |
| Valid tag but non-synthetic nonce (seed-holder white-box construction, nonce `00…00`, well-formed block) | **AuthError: SIV nonce mismatch** |
| Valid tag over random ct (seed-holder only) | DecodeError. This is expected: building it requires the seed. |
| **Public PIN rematch** (PIN `0989` as `PIN:0989`) | **0/512** re-encryptions of the correct PIN matched the target. 0 nonce matches, 512 unique pickups. One public `encrypt()` of each of all 10,000 PINs: **0** matches. |
| Seed-holder copied-pickup path (**not seed-free**) | With the seed (clef) and the target's pickup, a nonce prefilter over 10,000 PINs found `0989` in 0.03 s, and the rebuilt blob matched exactly. **This needs the seed, and anyone with the seed can just call `decrypt()`. It is not a break.** |

### Key signature (leftover now CLOSED)

I rebound the live module constants in memory, called `encrypt()`, restored them, and then decrypted with the live tables (`attack_key_signature_results.json`):

| Alteration | key_sig changed | Live decrypt | Same ct re-tagged by a seed-holder under the live key_sig |
|---|---|---|---|
| pair B0 `((1,5),(1,6))→((1,5),(1,7))` | yes (`99f56567…`) | **AuthError: tag mismatch** | DecodeError |
| skip pair B0 | yes | **AuthError** | DecodeError |
| triplet T0 row 0 `(5,1,1)→(5,1,3)` | yes | **AuthError** | DecodeError |
| skip triplet T0 | yes | **AuthError** | DecodeError |
| mix2 `((1,1),(1,2))→((1,1),(1,3))` | yes | **AuthError** | DecodeError |
| bow `BOW_ROT_BASE 1→2` | yes | **AuthError** | DecodeError |
| skip B0 and T0 (the pickup-era leftover shape) | yes | **AuthError** | DecodeError |
| isolated module copy with `BARS[1:]`, `TRIPLETS[1:]` (pickup-era method) | yes | **AuthError: tag mismatch** | — |

The last column shows that, before this fix, these blobs would have passed the tag and then failed as malformed. They now fail as authentication errors. After each test I restored the live constants and confirmed that the live key_sig and hello-world decryption were unchanged.

**Honest limit, demonstrated:** I patched `bar_mix()`'s *code* to skip B0 and left the `BARS` constant textually identical. The key_sig did not change, and the live decrypt returned **DecodeError: tag valid but block malformed**. The commitment covers the serialized parameters in `mix_description()`, not the arithmetic code. That is the documented scope. It is not a forgery, because building such a blob requires the seed.

### Field mix2 (singleton CLOSED)

- `mix2(0,0) XOR mix2(0,0x80) = (0x80, 0xF5)`. Across **all 65,536 base pairs**, the Δv=0x80 output is always `(0x80,0xF5)` and never `(0x80,0)`. The Δu=0x80 output is always `(0x80,0x80)`.
- mix2 singleton events across all 510 single-input deltas: **0**. Like any invertible 2×2 linear map, it has 510 two-input deltas that cancel one output. That is generic, not a leak.
- Butterfly alone (rounds 0 and 1): every single-cell delta, 0x80 and all 255 values, activates **at least 8 cells**. Bridges alone: at least 2. Butterfly plus bridges: **at least 16**. There are **0 singleton cells**.
- Full middle layer (weave→butterfly→bridges→bars→triplets[→bow]), Δ0x80 in every one of 128 cells over 257 bases: minimum weight 31 without bow and 35 with bow (round 0), 36/37 (round 1). **0 singletons.**

### Named pairs and triplets

- Named field pairs: **0/3570** singleton crossings, including Δ0x80. Each pair has 510 two-input cancelling deltas (generic for 2×2 linear maps).
- **B0 still cancels at the mix itself:** input Δ`(0x05,0x01)` → output Δ`(0x00,0x03)` at every base, as expected because the map is field-linear.
- Triplets alone (integer Z/256Z): **0 singleton** Δ0x80 crossings. Each column sends 0x80 to 2 or 3 outputs, for example T0: col0→`(80,00,80)`, col1→`(80,80,80)`, col2→`(80,80,00)`; see `attack_structure_results.json`. Minimum one-staff output weights over 16,642 bases by input beat: 5,5,3,5,5,4,3,3. The triplets are integer mixes; I make no singleton claim against them.
- One staff stack, Δ0x80 (minimum active bytes by input beat 0..7):
  - bars only: 8,8,7,6,5,4,3,2
  - bars+triplets: 5,6,6,6,5,5,5,2
  - **bars+triplets+bow (= the encore stack): 6,6,6,6,6,5,5,4**
  - With random deltas the last beat's minimum is 3.
  - **0 singletons in any combined stack.**

### Bow pressure

- Invertibility: `unbow(bow(s)) == s` held for 100,000 random staffs and 386 edge staffs (all-zero, all-0xFF, every single-bit staff, every single-cleared-bit-of-0xFF staff, and all 256 constant staffs): **0 failures**. 100,000 random inputs gave 100,000 distinct images. `bow(0…0) = 0…0`, which is a fixed point because ARX with zero is zero. The XOR-affine relation held in 0/2000 random checks, so bow is not XOR-linear.
- **B0 restack:** with Δ`(0x05,0x01)` at beats 0,1 through all 7 pairs, every one of 20,000 bases ends with exactly 7 active bytes. That is the linear field pairs spreading the residual 0x03. After the triplets the weight is 6–8. **After bow: 20,000/20,000 have more than one active byte** (6: 6, 7: 624, 8: 19,370).
- Parent-style test, a singleton Δ0x03 at beat 1 fed straight into bow: **19,998/20,000** restacked to more than one byte. **2/20,000 stayed singleton.**
- **Caveat (new leftover):** bow *alone* is a weak diffuser on odd beats. A singleton at beat 1, 3, 5 or 7 can leave bow as a singleton. With Δ0x80 over 16,642 bases: beat 1: 13, beat 3: 82, beat 5: 101, beat 7: 100 singleton events. Even beats 0, 2, 4, 6 never stay singleton (minimum weight 3). In the live round, bow only ever sees the pairs+triplets output, and that output never had a singleton in my tests, so this did not translate into a trail.

## Reduced-round distinguishers and trails

All numbers below use the current hello-world nonce schedule unless noted otherwise. The NumPy batch evaluator was cross-checked against live `round_enc` for all 16 rounds, against whitened `encrypt_grid`, and against `bow_pressure`.

- **Old cell-18 trail (cell 18 → {37,38,39}): GONE.** It gave 0/32,768 ΔS=0x80-conditioned pairs on the current, pickup-era (`4ea3…`) and demo (`b98b…`) schedules. The active output bytes were 44–48, 59–64 and 29–32 respectively.
- **Pickup-era cell-34 one-staff trail (→ bytes 56–63): GONE.** It was confined in **0/200,000** pairs in each mode: random δ, best fixed δ (0x8B on this schedule; `S_delta80` occurred 3,079 times) and explicit ΔS=0x80. The pickup-era schedule `4ea3…` gave the same 0 counts. The output always touched 6 staffs, with 44–48 active bytes. The field mix2 removed the one-staff confinement.
- **New one-round search:** 128 cells × 255 S-output deltas × 64 bases = 2,088,960 pairs. Active output bytes ranged from **36 to 64**, never more. Active staffs: 5 in 652,800 pairs, 6 in 913,920, 7 in 391,680 and 8 in 130,560.
  - **Strongest: a probability-1 truncated differential.** Input cell **2**, with any nonzero delta, stays inside **staffs {6, 8, 10, 14, 15}** (output bytes 48–55, 64–71, 80–87, 112–127). That held in **200,000/200,000** random-δ pairs, with a minimum of 36 active bytes. For a random permutation the probability would be about 2^-704.
  - The 128 per-cell staff footprints have sizes 5 (40 cells), 6 (56), 7 (24) and 8 (8). Full footprints are in `attack_one_round_confinement_results.json`.
  - Live-verified witness: `x = a898c5d9dc10153c…485d` and `y` = x with cell 2 XOR 0x5a (full hex in the JSON). Its active positions are exactly inside those staffs.
  - The smallest single pair: cell 26, S-delta 0x22, 36 active bytes in staffs {0,3,6,7,10}. It was live-verified, and `x`/`y` are in `attack_trails_results.json`.
  - **Why:** after S, a single cell reaches only its butterfly face (8 cells) plus their bridge partners. S2, pairs, triplets and bow all stay within a staff. So this is incomplete one-round diffusion that every version of this design has had, not something the fixes introduced. It is an easy white-box 1-round distinguisher.
- **Two rounds:**
  - **The old witness died.** The cell-30 Δ0x33 witness left 10 bytes unchanged at [64..71, 80, 116]. On the current cipher it leaves **0** unchanged bytes on the current schedule, 0 on the pickup-era `4ea3…` schedule (the schedule that witness was actually found on) and 1 (byte 125) on demo-nonce. As a control, the read-only pre-three-fixes library on `4ea3…` still reproduces exactly 10 zeros at the same positions.
  - **New per-input scan** (same size as before, 128 cells × 4,096 random-δ pairs = 524,288): **0** pairs with ≥8 unchanged bytes, against **0.0268** expected at random. Maximum unchanged bytes was 6. The zero-count histogram (0: 317,112, 1: 159,715, 2: 40,034, 3: 6,540, 4: 798, 5: 83, 6: 6) matches Binomial(128, 1/256).
  - No staff stayed unchanged in 65,536 random single-cell pairs. There is no live witness to save because there were no events.
- **Three rounds:** 0/524,288 pairs with ≥8 unchanged bytes (0.0268 expected), maximum 6. **Four rounds:** 0/524,288 (broad random-cell scan) and 0/65,536. **Sixteen rounds:** 0/65,536. Expected at random is about 0.0034 for 65,536 pairs.
- **Byte dependence (32 bases per input):** 1 round: 6,144/16,384 input→output dependencies, with at least 40 outputs per input. Rounds 2, 3, 4 and 16: **16,384/16,384**.
- **Bit avalanche (8,192 single-bit pairs; ideal 512 ± 16):**

| Rounds | Mean | SD | Min–Max | Worst bit-rate deviation |
|---|---|---|---|---|
| 1 | 191.99 | 29.5 | 130–286 | 0.356 |
| 2 | 512.14 | 15.9 | 450–587 | 0.020 |
| 3 | 511.71 | 16.0 | 439–568 | 0.020 |
| 4 | 512.24 | 16.0 | 448–577 | 0.018 |
| 16 | 511.79 | 15.9 | 452–569 | 0.023 |

  The tests printed about 201.6 at 1 round on a different sample. My 1-round mean is 192.0, and the difference is sampling and bit selection. Both are far from 512, which is consistent with the one-round confinement above.

## Schedule and S-boxes

- Nonce-bit flips (32): round material changed 49.0–50.6%, mac_key changed 111–143 of 256 bits, and **clef and key_sig changed 0 bits**. They are seed-only. S0 differed in all 32 samples.
- Seed-bit flips (32): material changed 48.8–50.7%, mac_key 107–149 bits, **clef 51–78 bits** and **key_sig 56–79 bits**.
- The four sponge domains M, K, C and G give distinct outputs. key_sig is `54e93f36…` and does **not** appear in the blob. `mix_description()` SHA-256: `2376cc67…`. The source imports only hashlib, hmac, os and json.
- The SM4 table starts `d690e9fe…`, not AES `637c777b…`, and the read-only `sm4_vector_check.py` reference vectors pass.
- Measured DDT max is 4 and LAT max is 16 for base SM4 and for keyed S/S2 in rounds 0, 1 and 15.
- **"Not AES" does not mean an unrelated algebraic family.** SM4 and AES S-boxes are both affine-equivalent to inversion over GF(2^8), and the keyed affine wrapping keeps the spectra exactly.

## Corrections and closed leftovers

- **CLOSED:** blobs built under altered mixes or bow parameters now fail as **AuthError**, not DecodeError. The remaining scope is code-only changes, shown above.
- **CLOSED:** the butterfly/bridge `0x80 → (0x80,0)` singleton. It now maps to `(0x80,0xF5)` for every base.
- **GONE:** the cell-18 trail, the cell-34 one-staff trail and the cell-30 Δ0x33 2-round witness. 2-round sparse events: 0/524,288.
- **Triplets:** no singleton leak, now or after the earlier correction. They remain integer Z/256Z mixes and are not field-linear. Nothing I found exploits that.

## Leftover structure (honest)

1. **B0 still cancels at the mix:** Δ`(0x05,0x01)→(0x00,0x03)`. The later field pairs and bow restack it, and bow left 0/20,000 single-byte results in the stack test.
2. **Bow alone can pass a singleton on odd beats.** For Δ0x80 the counts are 13–101 per 16,642 bases, and a Δ0x03 at beat 1 stayed singleton in 2/20,000 cases. In the live round, bow only sees outputs with at least 2–6 active bytes, so I found no exploit.
3. **One-round, probability-1 truncated differential:** a single input cell reaches only 5–8 of 16 staffs. This is an easy 1-round white-box distinguisher. It did not survive to 2 rounds in these tests.
4. The key signature covers serialized constants, not implementation code.
5. With the seed, anyone can decrypt. The copied-pickup PIN recovery is only a slower version of that.
6. **This is homemade, and it is still not for real secrets.**

## No break claimed

I demonstrated no 16-round plaintext recovery, seed recovery or MAC forgery. Neither the distinguishers I found nor the clean results at 2+ rounds amount to a proof of security. My tests cover only the differential and truncated-differential shapes listed here. Linear, algebraic, related-nonce, slide and other attacks were not explored in depth. **For real secrets, use AES-GCM-SIV, age, or libsodium.**

## Files and replay

- `common.py` (hash assert and validated batch evaluator)
- `snapshot_protected.py` → `protected_before.json`, `protected_after.json`, `protected_verification.txt`
- `attack_integrity_pin.py` → integrity, legacy blobs, public PIN, seed-holder PIN
- `attack_key_signature.py` → altered-mix blobs (full hex in JSON) and the code-only limit
- `attack_structure.py` → mix2, pairs, triplets, stacks, butterfly/bridges, middle layer, B0 restack, bow invertibility
- `attack_trails.py` → cell 18, cell 34, 1-round search, old 2-round witness replay
- `attack_one_round_confinement.py` → the probability-1 truncated trail and its witness
- `attack_rounds.py` → dependence, avalanche, zero-difference (1/2/3/4/16), 2/3-round per-input sparse scan, 4-round broad scan (`attack_sparse_results.json`)
- `attack_schedule.py` → seed/nonce flips, key_sig/clef, S-box checks
- Each script has `*_results.json`, `*_output.txt` (timestamped) and a `*_run_output.txt` console log.

Run any script with `python3 <script>.py` from this folder. The scripts are deterministic per RNG seed, except for `os.urandom` pickups.
