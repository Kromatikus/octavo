# Octavo N3 design spec (written only)

**Date:** 22 November 2026, America/New_York  
**Status:** layer cuts, golden-ratio drop, version tags, block-function-only first draft, public-S-box drop, and 0x11B defer recorded (same day). No cipher code, no live N2 changes, no picture, no push.  
**Folder:** `/workspace/octavo_n3_spec` (backups: `N3_SPEC.md.bak_20261122` first draft, `N3_SPEC.md.bak2_20261122` pre-tag decision). Frozen snapshots and `/workspace/sneak_n2` are untouched.

Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.

This note records the N3 design choices so far. It does not write a round function or start a mutation lab.

Sources used: `/workspace/octavo_app_ideas.md`; live N2 structure in `/workspace/sneak_n2/SPEC.md` (implementer's reference R1–R7); the 2% mutation lab in `/workspace/mutation_lab_2pct/REPORT.md`; reduced-round and trail-search notes already in the repo; measured N2 Rust speeds in `/workspace/octavo_decrypt_speed/PROGRESS.md`. No N3 speeds are guessed.

---

## 1. Goals, what stays, and the approved cuts

N3 is a **new format version**, not a silent edit of live N2. The aims are:

- Keep the dual-octahedra and hex-grid motif, the music naming, and the 16-face × 8-beat staff.
- Keep a 128-byte block, a 1024-bit seed, and 16 rounds unless a later, measured decision says otherwise.
- Make the round easier to implement fast on the existing GFNI / AES-NI / constant-time Rust backends, and easier to bound with the trail search.
- Cut layers that do not earn their place, rather than only stacking new ones.
- Stay honest: in-house analysis is not an external review, and N3 will still be homemade.

N3 will **not** open N2 blobs. Live identifiers (`SN2`, v6 / v7 / v9, score v11 vectors, `key_sig` / `rehearsal_sig`, field 0x1F5, and `sneak_n2.py` SHA `19181bc1…`) stay as the N2 record.

**Version identifiers (decided 22 November 2026).** N2 blobs are `ver ‖ SN2 ‖ …`, with sponge domains under `SN2/`. Used first bytes are 2–9 for live and legacy formats, and étude bytes in high nibbles `0x8*`, `0x9*`, `0xA*`, `0xB*`, `0xC*`, `0xD*`, `0xE*`, `0xF*`. N3 uses a parallel layout with a distinct magic and unused first bytes:

- Magic (bytes 1–3): `SN3`
- Sponge / domain prefix: `SN3/` (same inner labels as N2: `SN3/I`, `SN3/T`, `SN3/A`, …), so the same seed cannot share N2 schedule material
- Single-block: `0x16` (analogue of N2 `0x06`)
- Movements: `0x17` (analogue of N2 `0x07`)
- Rehearsal: `0x19` (analogue of N2 `0x09`)

N2 parsers that accept only their own first bytes, or that check bytes 1–3 against `SN2`, will reject N3. N3 must reject `SN2` and N2's version bytes. N3 étude bytes are unassigned until études are written.

**First code draft (decided 22 November 2026):** change only the block function. Keep N2's chaining and format layer (pickup, nonce, commitment, tags, and the v6 / v7 / v9-style layouts), swapping in the `SN3` / `0x16` / `0x17` / `0x19` identifiers above.

**Motif:** unchanged. The dual octahedra, the two shells, the hex grid, and the 16-face × 8-beat staff all come from the block layout, which does not change. The shell bridges that fold the two octahedra together stay. The current picture still fits, so it need not be redrawn unless OHLO asks. Earworm songs are unaffected: each is always 16 notes from a hash of the key signature, and the cipher's rounds and encore play no part in it.

The live N2 round, for reference, is:

```
g ^= rk_r ; g = S_r[g] ; weave ; butterfly ; bridges
bars ; triplets ; bow ; odd_restack ; cross
g = S2_r[g]
bars ; triplets ; bow ; odd_restack ; cross      # encore
# after last round: g ^= white
```

### Draft N3 round sketch

```
g ^= rk_r ; g = S_r[g] ; chord ; bridges ; triplets ; bow ; cross
g = S2_r[g]
# after last round: g ^= white
```

**Keep**

- **Two keyed SM4-affine S-box layers per round**, `S` then `S2`, each `A2·SM4[A1·x ⊕ b1] ⊕ b2` with its own per-round keying, sandwiching the mix and the bow. One layer would let an attacker peel free linear steps the way N2's reduced-round tests already reached about 0.5 round. Cutting the encore already spends unmeasured margin; a second box is nearly free on GFNI and keeps N2's "round S-box material depends on seed and nonce" posture.
- **`chord`:** one merged field-linear diffusion step replacing weave, butterfly, and bars. Exact wiring is not chosen yet; it should be a single named step with a bound the trail search can count, and its patterns should line up with 64-byte registers (the old weave/sigma constraint, now on `chord`).
- **Shell bridges** and **one** cross-staff mix (`cross`), folding N2's four cross layers into a single step. These are what fold the inner and outer shells together.
- **The bow,** unchanged (add-rotate-XOR). It is the only other ARX step, and dudect did not flag it on N2.
- **Triplets,** as the experimental change from add-mod-256 to a GF(2^8)-linear mix. Adopt only if the checks in the note below stay clean.

**Cut**

- The **encore** (the repeated second half of each N2 round).
- **`odd_restack`.**
- The **four separate cross layers**, folded into the one `cross` above.

S and S2 stay keyed SM4-affine boxes. The field stays GF(2^8) with polynomial **0x1F5** unless a later decision switches it (still deferred). Inner faces are 0–7, outer faces 8–15.

### Must verify before adoption

Cutting the encore and `odd_restack` is a **judgment call**, not a measurement. It leans on N2's in-house margin of roughly 9–10 of 16 rounds at a 256-bit trail target. That margin is for the full N2 round, including the parts now cut, and it is not a proof of this slimmer round. Before any talk of adopting N3, rerun all of:

- the trail-search bound,
- the reduced-round tests,
- the mutation lab at **1% and 5%**,

on the slimmer N3 round (including experimental GF-linear triplets). If those come out thin, put back margin (or do not cut).

On the current N2 Rust library (same box, after the decrypt-speed work, gfni-simd): about **2.52 µs encrypt / 2.91 µs decrypt** per 128-byte block; batched about **0.75 / 0.80 µs**; v9 seal/open about **121 / 116 MB/s** on one thread and **599 / 555 MB/s** on eight. AES-256-GCM on the same box was measured at **1613 MB/s** on one thread (that figure is from an earlier run, when Octavo v9 was 37 MB/s; no new AES number was taken after the later library speedup). N3 must be re-measured; none of these numbers is a prediction.

In-house N2 analysis (not a proof of N3): reduced-round tests did not go past about 0.5 round; the trail search proved about 12–15 active S-boxes per round and a margin of roughly 9–10 of 16 rounds at a 256-bit trail target. Single-shell trails were already impossible on N2. dudect on the N2 data path, tag compare, VPSLLVW, and bow showed no leaks; key setup is not constant-time, a valid-vs-tampered v9 open has an expected timing gap, and gfni-simd shows a many-key cache effect.

---

## 2. Held ideas

For each idea: what it is, expected security effect, speed effect, compatibility, and a recommendation (include / defer / drop).

### 2.1 Simplification

**Decided (22 November 2026).** The first draft uses the slimmer round in §1: keep two keyed S-box layers, `chord`, shell bridges, one `cross`, the bow, and experimental GF-linear triplets; cut the encore and `odd_restack`; fold the four cross layers into one. Security: can be positive if the remaining layers still meet a wide-trail floor, or harmful if a useful layer was cut by taste alone — that is why the checks in §1 are required before adoption. Speed: a shorter round should help; the size of the gain is **unknown** until measured. Compatibility: a full break with N2.

### 2.2 Golden ratio

**Dropped (22 November 2026, OHLO).** Using φ as a public constant (as TEA/XTEA and RC5/RC6 do with 2³²/φ) would be a small, transparent source of round constants, but it is not novel and the number itself adds no extra security over any other well-chosen public constant. It is left out of N3. The only remaining mention of φ in N2 is as one of the public constants a seed is refused for being equal to.

### 2.3 Fixed S-box

N2 already uses a **public** SM4 table (itself the AES S-box with fixed affine maps) wrapped in **per-key** affine maps and biases, `A2·SM4[A1·x ⊕ b1] ⊕ b2`. That wrapping is exactly what GFNI's `GF2P8AFFINEINVQB` / `GF2P8AFFINEQB` compute, and the November 21 GFNI plan says to keep it. “Fixed S-box” as a change would mean dropping that keying and using a single public box. Security: some trail proofs get simpler (one DDT/LAT for every round), but the “every round's S-box material depends on seed and nonce” posture is weaker; N2's own spec already lists a fixed-S-box / nonce-reuse guesser as something the keyed schedule is meant to block. Speed: key setup might get slightly cheaper; the data-path S-box is already near-free on GFNI, so a large encrypt/decrypt gain is unlikely and is **unmeasured**. Compatibility: a full break. **Decided (22 November 2026): drop** as a replacement for keyed affine S-boxes. If the intent was only “keep the public SM4/AES table and the affine keying,” that is already N2 and is what N3 keeps.

### 2.4 Safety ideas (motif list of 21 November 2026)

These five were saved on paper in `octavo_app_ideas.md`. They are listed separately because they are not one change.

**Harmony proof (wide-trail).** Choose mixing so any input change forces a proved minimum number of active S-boxes over a few rounds. N2 already has an in-house bound (about 12–15 active S-boxes per round). N3 should treat a rerun of that bound as a **requirement**, especially with GF-linear triplets and the slimmer round. Security: this is the main reason to do N3 carefully. Speed: none by itself. Compatibility: only breaks N2 if the mix is changed to meet the bound. **Recommendation: include** as a gate on the first draft, not as an extra layer.

**Counterpoint key schedule.** Give each round key its own independent “voice” so keys never repeat or line up, to blunt slide and related-key attacks. N2 already draws a fresh 128-byte round key and two keyed S-box parameter sets per round from `StaffSponge("K", seed, nonce)`. Security: a proof that those streams do not collide or slide is useful; a redesigned schedule is only needed if that proof, or an attack, fails. Speed of a redesign is **unknown**. Compatibility: a new schedule breaks N2. **Recommendation: include the proof goal; defer a redesign** unless the proof or an attack demands one.

**Octave folding.** Make each shell half a cipher, and fold one onto the other every round so a single-shell trail cannot survive. The November 21 note already says N2 does most of this (shell bridges on 64 inner/outer pairs, alternating who leads; cross-staff mix2). The N2 trail search already found single-shell trails impossible. N3 keeps the bridges and one `cross`. **Recommendation: include the proof on the N3 draft; defer any new folding layer.**

**Tempo randomization.** In a constant-time port, shuffle the order of independent steps inside a round so timing and power traces change from run to run, with the same output. This is an implementation trick, not a new mix. Security: maybe helpful against some side channels if it is done without introducing data-dependent timing; easy to get wrong. Speed: **unknown**. Compatibility: none if the output is truly identical. dudect already flags that N2 key setup is not constant-time and that gfni-simd has a many-key cache effect. **Recommendation: defer** until the N3 math is frozen.

**Conductor's checksum.** A second pass that proves the first pass happened, so a glitch yields garbage instead of a key leak. This is an infective or verifying check, not the mixing encore that N3 cuts. Security: a reasonable fault-attack idea, unproven here. Speed: likely a noticeable cost if it adds a full extra pass; **unmeasured**. Compatibility: breaks N2 if the ciphertext or tag changes. **Recommendation: defer** until after the first math draft.

### 2.5 GFNI 0x11B field tweaks (list of 21 November 2026)

These were written for the start of a new version, not for a Python-only change. Do not change the round count or the block size as part of this bundle.

**Switch the field polynomial from 0x1F5 to AES's 0x11B** so `GF2P8MULB` can implement `chord`, bridges, and the linear triplets directly. Security: a new field needs the trail search and the mutation lab rerun; there is no reason to expect a free security win. Speed: the current N2 Rust path already runs 0x1F5 mixes on GFNI (as linear maps) without a switch, and is already in the low-microsecond range; any further gain from 0x11B is **unknown**. Compatibility: breaks all vectors, blobs, signatures, and analysis. **Decided (22 November 2026): defer.** Only switch if a later, measured draft shows a real need for a direct `GF2P8MULB` path.

**Replace the Z/256 triplets with a GF(2^8)-linear mix.** This is the largest proposed math change. The six overlapping 3-beat additive triplets were added in an earlier attack round; in the 2% mutation lab they were the biggest single-point family (**54** coefficients), and last-row corners that broke the “at least two odd entries” rule left some trials short of full diffusion. A field-linear version would vectorize cleanly and sit inside the trail model, but it also removes the only between-S-box modular addition besides the bow, so algebraic and trail behaviour will change and must be re-proved. Speed: expected to vectorize better than add-mod-256; **not measured**. Compatibility: a full break. **Recommendation: include as the main experimental change in the first draft, and adopt only if the trail search and the 1%/5% mutation lab stay clean.** This is the highest-risk include.

**Keep the affine S-box keying.** This is the current N2 wrapping, and it matches GFNI. **Recommendation: include** (do not drop; see 2.3). N3 keeps two such layers per round.

**Line up `chord` and the remaining keyed bridge/cross patterns with 64-byte registers** (patterns that stay inside one 64-byte half, or a fixed cross-half pattern), instead of arbitrary 128-byte key-dependent shuffles. Security: fewer irregular permutations could help or hurt trails; the bound has to be rerun. Speed: intended to help AVX-512; **unmeasured**. Compatibility: breaks N2. **Recommendation: include as a layout constraint** in the first draft.

**Leave the bow as it is.** Its add-rotate-XOR strokes are already vector-friendly, and dudect did not flag the N2 bow. **Recommendation: include** (do not redesign the bow).

### 2.6 Odd meters (22 November 2026)

A **fixed, public** per-round meter schedule (for example 4/4, 7/8, 5/4, …) so mix groupings do not always line up with the 8-beat staffs or repeat from round to round. The meter must **not** be chosen by the key (that could leak in timing). The November 22 note already says the triplets give most of the cross-rhythm benefit and the extra gain is likely modest. Security: maybe a little harder for slide and alignment attacks; must be proved with the trail search and a mutation lab before adoption. Speed: **unknown**, and a key-independent schedule should not be a timing oracle. Compatibility: a break, and it tensions with the 8-beat picture motif (the picture should not be redrawn unless OHLO asks). **Recommendation: defer** past the first math draft. Revisit if the triplets become field-linear and some of that cross-rhythm is lost.

---

## 3. Plan (small steps, no silent start of code)

N2 stays frozen as the live cipher until OHLO asks for code. Policy picks in §4 are recorded. Then, in order:

1. **Rust reference** for the N3 block function only (clear, not the fastest possible), keeping N2's chaining and format layer with the `SN3` / `0x16` / `0x17` / `0x19` identifiers. New work folder only. Do not edit `/workspace/sneak_n2`, frozen snapshots, or the repo clones.
2. **A slow, independent Python cross-check**, written from the N3 spec, not by translating the Rust line for line — the same idea as today's `independent_check/` for N2.
3. **Test vectors** (short blocks, a few reduced-round études, and at least one full-round published vector) that both implementations must match.
4. **Mutation lab at 1% and 5%** on that first draft, right after the constants and structure exist, together with the trail search and reduced-round tests required in §1. The last lab was 2%. This is the reminder that was saved for “after the first N3 draft.”
5. **Attack rounds** on the draft (linear, differential, algebraic, slide / related-nonce, plus a regression pass), in a new report folder, before any talk of replacing live N2.
6. Only after that: a decision on whether N3 is worth a format bump, new vectors, and — with an explicit go-ahead — any later repo work. No GitHub push and no public post is implied by this spec.

Keep jobs small. Usage is limited until the next reset.

---

## 4. Decisions (all policy picks recorded)

No policy question is still open. Recorded: layer cuts and two S-box layers; `chord` and folded `cross`; experimental GF-linear triplets; golden ratio dropped; public unkeyed S-box dropped; 0x11B field switch deferred; first code draft is the block function only, with N2 chaining kept; version tags are `SN3` and `0x16` / `0x17` / `0x19`, with sponge prefix `SN3/`.

Still unchosen, but not policy: the exact wiring of `chord` and the GF-linear triplet tables (to be set in the first code draft, then run through the §1 checks). N3 étude format bytes are unassigned until études are written. Odd meters, tempo randomization, and the conductor's checksum stay deferred.

---

Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.

## Held idea: cross-sticking (added 2026-11-22)

Like a drummer's rim click on the same beat: a fixed, public per-beat pattern that switches which operation hits a byte (e.g. GF(2^8) multiply on some beats, add-mod-256 on others), mixing algebraic structures to resist algebraic attacks. Must never be key-chosen (timing leak). Overlaps with odd meters and with what the bow already provides. **Recommendation: defer.** Revisit as a fix if the reduced-round attack suite finds the field-linear layers too uniform; would need a new trail proof and a 1%/5% mutation lab before adoption.

---

## 5. fix1 amendments (cipher format 0x1B), fix2 AEAD (format 0x1C), and fix3 key setup (23 November 2026)

Working copy for `/workspace/octavo_n3_fix3`. The block cipher is the fix1 design (8-stroke bow, corrected trail bound, format 0x1B). The authenticated mode is the aead2 PMAC-SIV adopted in fix2, blob format 0x1C. fix3 changes only how key setup is implemented; formats and ciphertexts are unchanged from fix2 (see §5.4). The old 0x1B CMAC-S2V mode is **not** implemented here (keeping both stacks is not cheap); open those blobs with the untouched fix1 tree. Cipher format 0x1B is **not** interchangeable with 0x1A (`octavo_n3_002` / `003`) or 0x16/0x17/0x19 (`001`). AEAD format 0x1C is **not** interchangeable with fix1's 0x1B blobs.
This supersedes §2.5 "Leave the bow as it is".

### 5.1 Corrected trail bound (finding a)

Round: `rk ; S ; chord ; bridges ; triplets ; bow ; S_mid ; cross ; S2`. Between `S2` of round r and `S` of round r+1
there is only the XOR with `rk_{r+1}`, on the same byte. In any multi-round trail those two boxes are **one keyed
8-bit S-box**, `S_{r+1}(S2_r(x) ⊕ k)`, and must be counted once.

| Count | 1 round | 2 rounds | per round in a long chain |
|---|---|---|---|
| Old claim (double count) | 18 | 36 | 18 |
| **Corrected (merged S2·S)** | **18** standalone (S, S_mid, S2 all distinct) | **35** (OPTIMAL) | **17** |

The minimum trail is `[1, 16, 1]` per round (1 active byte at S, 16 at S_mid, 1 at S2). With merging the chain
costs 16 S_mid boxes plus 1 merged box per round. The merged box is weaker than a single keyed box: on real schedules
its max DDT entry is 10–16/256 (worst 2^-4.0) and max |Walsh| 64–76/256 (|corr| ≤ 2^-1.75), versus 4/256 (2^-6) and
32/256 (2^-3) for one box. Per-round estimate in a chain: differential ≈ 16·6 + 4 = **2^-100**, linear potential
≈ 16·6 + 3.5 = **2^-99.5**. Sixteen rounds ≈ 2^-1600 in this model; the margin is essentially unchanged.
Re-derived after the bow change (5.2): unchanged, because the model treats the bow as free (cancellation allowed).
Evidence: `results/fix1/merged_bound.txt`, `results/fix1/merged_sbox.txt`.
Model caveats: bow modeled as free; counts ignore clustering/hulls; bridges are 2 sampled schedules, not all keys.

### 5.2 8-stroke bow (finding b)

Old bow (7 strokes) had incomplete inverse diffusion: under bow⁻¹ output beat 7 only reached input beats 6 and 7,
which gave a probability-1, 1-round impossible differential.

The fix1 bow keeps the stroke maths unchanged (`u += rotl(v, r1(p)); v ^= rotl(u, r2(p))`, `r1 = 1 + p mod 7`,
`r2 = 1 + (p >> 3) mod 7`, `p` the pressure byte) and uses a new 8-stroke list `(i, j, p)`:

```
(2,3,4) (5,7,1) (0,7,3) (4,7,6) (1,6,0) (1,7,2) (2,5,4) (0,3,1)
pressure rotations: all 0 (no pressure byte is reused unchanged)
inverse: same strokes in reverse order, each stroke inverted
```

- Structural diffusion: every output beat depends on every input beat **forward and inverse** (the old bow was full in
  neither). No reordering of the old 7 strokes, no 7-stroke list from a 300k random sample, and no single inserted stroke achieves
  this. 8 strokes is the smallest found (random search, `lab/bow_cand.py`; candidates ranked by `lab/bow_eval.py`).
- Empirical (single-bit flips, real ARX): every (input beat → output beat) pair changes with probability ≥ 0.79 forward
  and ≥ 0.63 inverse.
- Constant time: fixed stroke list, data-independent rotations implemented by masked shifts/VPSLLVW as before.
- **OHLO's choice (23 Nov 2026, about 10:35 AM ET):** a 10-stroke "sawtooth bow" was also built. It is a forward ramp
  `(0,1,2)…(6,7,0)` plus a backward snap `(7,4,3)(3,2,5)(1,0,2)`, and 3 snap strokes is the minimum for that ramp. It has the same diffusion,
  bound and attack results, but 2 more strokes, which made decryption about 7% slower. OHLO picked the 8-stroke bow. The sawtooth is kept in
  `lab/sawtooth10` for comparison only.

### 5.3 Authenticated mode: SN3C/ AEAD "N3-PMAC-SIV" (format 0x1C)

Nonce-misuse-resistant, SIV-style, over the 1024-bit block, with a PMAC-style tag that can use the batch-64 path. Adopted in fix2 from the `/workspace/octavo_n3_aead2` lab. Rust: `rust/src/aead.rs`; Python reference: `tools/aead_ref.py`. The block cipher remains format 0x1B.

- **Subkeys:** `seed_X = SHA-256(“SN3C/” ‖ 0x1C ‖ “AEAD-KDF” ‖ X ‖ u32be(c) ‖ seed)` for c = 0..3 (128 bytes), X = 'M' or 'E'.
  `E_mac = N3(seed_M, nonce = "SN3C/AEAD-MAC\0\0\0")`, `E_enc = N3(seed_E, nonce = "SN3C/AEAD-ENC\0\0\0")`.
  Key setup is done once per master seed (two N3 schedules; about 0.6 ms each on AVX-512 in fix3, about 1.4 ms in fix2). The 0x1C domain byte means these subkeys differ from fix1's.
- **Transcript** (the only string that is MACed), uniquely length-prefixed and streamed (never fully allocated):
  `u64le(|H|) ‖ H ‖ u64le(|AD|) ‖ AD ‖ u64le(16) ‖ nonce ‖ u64le(|M|) ‖ M`, with `H = "SN3C/" ‖ 0x1C`.
  Minimum length is 54 bytes, so the PMAC always has at least one (usually partial) block.
- **PMAC** with E_mac and 128-byte blocks. `dbl` = multiply by x in GF(2^1024) mod x^1024 + x^19 + x^6 + x + 1
  (big-endian; irreducible, `tools/check_poly1024.py`).
  `L = E_mac(0)`, `L[j] = x^j L` (`dbl` applied j times), `L[0] = L`.
  Gray-code offsets: `Δ_0 = L[1] = 2L`; for k ≥ 1, `Δ_k = Δ_{k-1} ⊕ L[ntz(k+1)+1]`
  (closed form: `Δ_k = XOR_{i=1}^{k+1} L[ntz(i)+1]`).
  Final masks: `K_full = 3L = L ⊕ 2L`, `K_part = 5L = L ⊕ 4L` (so a single full-block transcript does not cancel `Δ_0 = 2L`).
  Middle full blocks 0..n-2 are encrypted through the batch-64 path: `Σ ^= E_mac(M_i ⊕ Δ_i)`.
  Last full: `Σ ^= last ⊕ Δ_{n-1} ⊕ K_full`. Last partial: `Σ ^= pad10*(last) ⊕ Δ_{n-1} ⊕ K_part`.
  `tag_block = E_mac(Σ)`; **tag = tag_block[0..32]** (256 bits).
- **CTR:** block i = `tag (32) ‖ "SN3C/CTR" (8) ‖ 0^80 ‖ u64le(i)`; `C = M ⊕ E_enc(block_0) ‖ E_enc(block_1) …` (truncated). Already uses the batch-64 path.
- **Blob:** `"SN3C/" (5) ‖ 0x1C (1) ‖ nonce (16) ‖ tag (32) ‖ C (|M|)`; overhead 54 bytes; |M| ≤ 2^30.
  The `n3aead` CLI seals and opens 0x1C blobs only.
- **Open:** strict parse (`TooShort` < 54 bytes, `BadPrefix`, `BadFormat` including 0x1B, `TooLong`), CTR-decrypt, recompute the tag,
  constant-time 32-byte compare, wipe plaintext and return only `AuthFailed` on mismatch. No panics on any input.
- **Legacy 0x1B:** not implemented in this tree. A fix1 CMAC-S2V blob is rejected as `BadFormat`. Open those with `/workspace/octavo_n3_fix1`.
- **Claims (in-house, not proven for N3):** if N3 behaves as a strong PRP and the tag is a PRF, this is the generic SIV argument (PRF tag, then CTR keyed by the tag):
  deterministic AE, misuse-resistant. With a repeated nonce only equality of identical (AD, nonce, M) is revealed.
  Forgery ≈ q/2^256 per attempt set (tag 256 bits). Birthday terms in the 1024-bit block are ~σ²/2^1024 (irrelevant);
  the binding limit is the 256-bit tag/IV: keep total messages well below 2^100 per key. CTR blocks of different
  messages collide only if two tags collide (≈ q²/2^257). Per-position offsets are what stop a reordering of 128-byte
  blocks from preserving the tag. This is not the RFC 5297 S2V/CMAC composition. Not claimed: security if N3 is weak,
  a PMAC proof for N3 (N3 is not a proven PRP), side-channel freedom beyond what dudect measured, key-committing
  behaviour, or anything about the per-key setup cost.

### 5.4 Faster constant-time key setup (implementation only, fix3)

Adopted from the `/workspace/octavo_n3_keysetup1` lab. This does **not** change the format byte, the schedule, or any ciphertext. The keyed S-box is still `S(x) = A2·SM4[A1·x ⊕ b1] ⊕ b2`, equivalently `Mout·inv(Min·x ⊕ cin) ⊕ cout` over GF(2^8)/0x1F5. Setup now fills the 256-byte forward and inverse tables from that closed form with a table-free Fermat inverse (`x^{254}`, `inv(0)=0`), instead of a 256×256 constant-time scan of the public SM4 table. A process-lifetime cache holds the field isomorphism `PHI^{-1}` and the key-independent fallback `mulc` / Frobenius tables. The SHA-256 sponge draws are unchanged. Vectors are bit-identical to fix2. Key setup remains constant-time; a HashSet bijectivity check used by the old scan is gone.

Typical `Cipher::with_backend` times on this box (core 2): AVX-512 about 0.58 ms (was 1.44 ms in fix2); AVX2 and portable about 0.91–0.93 ms (were about 1.8 ms). The leftover on those slower backends is still the per-round Beneš masks and backend S-box forms.

Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.
