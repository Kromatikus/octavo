# Liner notes — Octavo (staff-core N2)

These notes explain how Octavo works and why each piece is there. They were written against the frozen snapshot `/workspace/octavo010`, the conductor-polish revision of 2026-11-11 (America/New_York), and have since been updated for the **rehearsal** revision (streaming, format version 8) the **rehearsal-fix** revision, which applied the first rehearsal attack's fixes, and the live **rehearsal-polish** revision, which applies the second rehearsal attack's fixes and is **not yet frozen**. Everything about octavo010 below still holds for the live tree: rehearsal adds a mode and leaves the round function, v6 and v7 byte-identical.

- Module: `sneak_n2.py`, SHA-256 `c07707bfde75ed4b77a4ad4f09797526f9fabe1509914fb3a49fa5288bd39d50`
- Mix attestation: `EXPECTED_MIX_SHA256` `fe93996970ecd92693b5f8f43ffb2cad5e96867f258a38b12637f1014b12b4c6`
- Demo-seed key signature: `340dc1e062502bb13462a94ba490c3dc`
- Tests: 366/366 on the live tree, a fresh copy, and inside octavo010
- Score: `score/vectors.json`, score version 3, 64 vectors
- Picture: `sneak-staff-n2.png` (dual octahedra on a hex grid). The header reads conductor-polish, v6, a 228-byte blob, SHA `c07707bf…`, and key_sig `340dc1e0…`

Live tree (rehearsal-polish, not yet frozen):

- Module: `sneak_n2.py`, SHA-256 `7ea3dd843b19b6712a00c535d6232da449972737ea54752217a913d8265c111f`
- Mix attestation: `EXPECTED_MIX_SHA256` unchanged, `fe939969…`; demo-seed key signature unchanged, `340dc1e0…`
- Rehearsal attestation: `EXPECTED_REHEARSAL_SHA256` `dd02f7078f46f48c14ac6ca09243a72a56c7d378f476d4ec312c960c145f1a50`; demo-seed rehearsal signature `1f8097d2d6554347d28b15b412641fcd`. Both moved because the rehearsal digest attests all v8 API code and the polish changed the file helpers and workers. v8 headers and ciphertext blocks are unchanged; only chunk tags differ
- Tests: 448/448 passed (live and a fresh copy; new checks turn the rehearsal-fix attack's witnesses into regression tests)
- Score: score version 6, 72 vectors (the 64 étude vectors unchanged; the 8 rehearsal vectors differ from score version 5 only in their tags)
- Picture: re-rendered; the header reads rehearsal-polish, v6, a 228-byte blob, SHA `7ea3dd84…`, key_sig `340dc1e0…`, and the footer shows the v8 stream layout and `rehearsal_sig 1f8097d2…`

The previous revision, rehearsal-fix, was attacked in `attacks_octavo_rehearsalfix/` (2 Low, 9 Info, no cryptographic break) and was never frozen:

- Module: `sneak_n2.py`, SHA-256 `81686d301c6d43746a8e691223d61e53cca7093a9e187c29a014d6d404078539`
- Mix attestation: `EXPECTED_MIX_SHA256` unchanged, `fe939969…`; demo-seed key signature unchanged, `340dc1e0…`
- Rehearsal attestation: `EXPECTED_REHEARSAL_SHA256` `584758f7550f51913da0b723e8c90d73bf296aa1ecde1963ab03cfe0b1ef527e`; demo-seed rehearsal signature `4ed3c0f3817acda643a5c44a50c55f57`
- Tests: 437/437 on the live tree and on a fresh copy (23 new checks turn the rehearsal attack's witnesses into regression tests)
- Score: score version 5, 72 vectors (the 64 étude vectors unchanged, the 8 rehearsal vectors regenerated because v8 changed)
- Picture: re-rendered; the header reads rehearsal-fix, v6, a 228-byte blob, SHA `81686d30…`, key_sig `340dc1e0…`, and the footer shows the v8 stream layout and `rehearsal_sig 4ed3c0f3…`

The revision before that, rehearsal (`sneak_n2.py` SHA `85a67178…`, `EXPECTED_REHEARSAL_SHA256` `e767ae50…`, rehearsal_sig `d33225ce…`, 414/414), was attacked in `attacks_octavo_rehearsal/` and was never frozen.

The wire formats and the 16-round function are unchanged from the conductor revision immediately before this freeze. The same seed, pickup and input still give the same nonce, commitment and ciphertext; only key-signature-bound tags, cadences and the coda moved. Full-round ciphertexts are also unchanged from octavo009 for the same seed, nonce and block.

This is a design document, not a specification. Exact layouts, matrices and APIs live in `sneak_n2.py`, `etudes.py`, `SPEC.md` and `SECURITY.md`. Attack and review folders are cited by path. Figures come from those files; anything not written down there is omitted or marked unverified.

**Octavo is still homemade. It is not for real secrets.** For anything that matters, use AES-GCM-SIV (RFC 8452), [age](https://age-encryption.org), or [libsodium](https://doc.libsodium.org).


## 1. What Octavo is

Octavo is OHLO's homemade experimental cipher. The working name is N2, and the files still use `sneak_n2` names: the magic after the format-version byte is `SN2`, and the staff sponge domains are prefixed `SN2/`. It is a 1024-bit block cipher with an HMAC-SHA256 seal. The state is a 16-by-8 grid of 8-bit cells — sixteen faces, eight beats each — drawn as dual octahedra (an inner shell of eight faces and an outer shell of eight) on a hexagonal grid. One 128-byte block is that grid; the grid *is* the ciphertext. Messages longer than 127 bytes go through movements mode, which chains up to 8,192 such blocks under one schedule, or (since the rehearsal revision) through a rehearsal stream of fixed-size, separately tagged chunks with no 1 MB cap.

The cipher core is homemade: the grid, the keyed S-boxes, the weaves, butterflies, shell bridges, bar mixes, triplets, bow, restack, cross-staff layers and encore. Three pieces are not: SHA-256 is the one-way staff sponge that expands a seed and a nonce into the schedule; HMAC-SHA256 is the integrity tag, the commitment, the cadence and the coda; and the base 8-bit S-box is the published SM4/SMS4 S-box (GB/T 32907-2016). There is no AES, no AES S-box, no MixColumns and no GCM.

N2 was built to close holes that showed up in its predecessor, N1. N1's schedule was a linear rotate-and-XOR map, so one round's material plus the public nonce gave back the 1024-bit seed, and N1 silently accepted about one in 255 random ciphertexts. The first N2 attack (`/workspace/octavo010/attacks/`) found both of those holes closed. The cells were 4-bit then, so that early report still describes a 512-bit block; the live cipher has used 8-bit cells and a 1024-bit block since the second-coloring era.

The default seed file, `sneak1024-seed.txt`, is a **public demo seed**. Its full hex is published in `score/vectors.json` and in every frozen snapshot, so any blob made with `seed=None` or with that file can be read by anyone. Use it only for samples and tests. Études refuse it unless the handle is made with `etude(r, lab_seed=True)`.

A long series of in-house attacks and one independent look at the round function have not produced a break of the full 16-round cipher. That is a negative experimental result, not a proof of security, and it is not third-party cryptanalysis of the current outer construction. The honest status has not changed.


## 2. Threat model and goals

Octavo aims to be an authenticated-encryption scheme under a 1024-bit seed: given the seed, encrypt a message (and optional associated data) so that only a holder of that seed can recover the message, and so that a tampered, spliced, truncated, replayed-from-another-revision, or wrongly labelled blob is rejected without returning plaintext.

The goals that actually show up in the code and the reports are these:

- **Confidentiality of the payload**, under a seed the attacker does not have, for a single 127-byte block, a movements payload up to 1,040,384 bytes, or a rehearsal stream (format version 8) of up to 2^24 chunks.
- **Integrity and authenticity**, with HMAC-SHA256 over a seed-derived MAC key. The tag (or the movements coda and cadences) binds the version, the magic, the pickup, the nonce, the commitment, the ciphertext, a hidden clef, a hidden key signature, and length-prefixed associated data.
- **Key commitment**, added in the tuning revisions: a blob should not open under two seeds. The public commitment is an HMAC under a seed-only key, checked before any schedule is built.
- **Nonce binding**, in a homemade SIV style: the 16-byte nonce is a SHA-256 truncation of the clef, the pickup, the message and the associated data, so a caller-chosen nonce that does not match is rejected, and different messages (or different AD) do not share a nonce for a given pickup.
- **Associated-data authenticity**, without storing the AD in the blob. The same AD must be supplied on decrypt. AD is capped at 65,536 bytes and encoded as `uint64be(len(ad)) || ad` so message/AD pairs do not collide.
- **Format and version separation.** Current decrypt APIs speak only v6 (single-block), v7 (movements) and, since rehearsal, v8 (streams), each only its own. Foreign or unpublished versions raise `UnsupportedVersion`, which is not an `AuthError`, so a natural `except AuthError:` handler cannot drift into a legacy path.
- **Equal-time rejects at the outer checks**, as far as Python control flow allows: a wrong key, wrong AD, bad commitment, bad ciphertext and bad tag (or coda) do the same work and raise the same `AuthError("authentication failed")`.

What the scheme does not claim, and what the reports keep repeating:

- It is **not constant-time**. The Python reference can be made uniform in control flow at the commitment and tag. The round function uses secret-indexed tables, a GF(2^8) lookup, data-dependent rotations, rejection sampling and key-dependent permutation addresses. CPython cannot be made constant-time.
- It is **not a proof of security**, and a failed attack is not a certificate.
- It has **no anti-replay** beyond a fresh pickup and a synthetic nonce. A captured blob decrypts again under the same seed and AD.
- It had **no streaming API** and a hard 1 MB-class cap in movements mode up to octavo010. The rehearsal revision adds streaming (format version 8). That mode has had two in-house attacks, whose fixes are in rehearsal-fix and the live rehearsal-polish revision, and it is not nonce-misuse-resistant (no SIV nonce for a stream).
- The **demo seed is public**. Weak seeds (all zeros, all `FF`, integer `1`, or fewer than 32 distinct nonzero bytes) are rejected, but a guessable application seed is still the caller's problem.
- A holder of the seed can, of course, decrypt, and can confirm a guessed plaintext by re-encrypting under a known pickup. The pickup was added to stop a public encrypt-only dictionary attack; it is not protection against a key holder.
- Offline seed confirmation is possible whenever the associated data is known, because the commitment (and the tag) can be recomputed from public fields plus a seed guess.

The attack series treated a fairly wide adversary: black-box encrypt/decrypt, bit flips and splices, version confusion and downgrade, associated-data and key-commitment tricks, two-key and partitioning-oracle constructions, reduced-round distinguishers with a known schedule, linear and algebraic tests, slide and related-nonce tests, and (in the conductor's mark review) timing of the outer checks. Reduced-round work is white-box: it feeds raw 128-byte blocks under a fixed schedule, which the public `encrypt()` API does not offer, because every call draws a fresh pickup and therefore a fresh nonce and schedule.


## 3. Overall structure

### The state

The block is a grid of 16 faces by 8 beats, one byte per cell, 128 bytes in all. Faces 0–7 are the inner shell and faces 8–15 the outer shell of a pair of octahedra. Each face is an open 8-beat staff: there is no wrap from beat 7 back to beat 0. The staff is written as four measures of 2/4,

```
| 0 1 | 2 3 | 4 5 | 6 7 |
```

with bar lines at the even boundaries 0, 2, 4, 6 and 8. That picture is what `sneak-staff-n2.png` draws, and it is also how `grid_rows` prints a block.

### The round function

There are 16 rounds, one per face, plus a whitening XOR at the end of encryption (and at the start of decryption). One encryption round, in order, is:

1. XOR the 128-byte round key into the grid.
2. Apply the round's first keyed 8-bit S-box `S` to every cell.
3. Weave: rotate each face along its staff by a key-derived amount `SH[f]`, then rotate each beat-column across faces by a key-derived amount `SV[b]`.
4. Staff butterfly: on each face, three matchings of the eight beats (`LAYERS = (1, 2, 4)`) in a key-derived beat order `sigma[f]`, each pair mixed with `mix2`.
5. Shell bridges: 64 disjoint pairs joining an inner-shell cell to an outer-shell cell under a key-derived permutation `bridge`. The orientation of `mix2` alternates with the round index.
6. Seven named pair mixes (`bar_mix`), in beat order: B0, B1, M2, B2, M3, B3, B4.
7. Six overlapping triplet mixes (`triplet_mix`) on windows (0,1,2) through (5,6,7).
8. Bow pressure on each staff.
9. Odd-beat restack (rehair) on pairs (0,1), (2,3), (4,5), (6,7).
10. Cross-staff mix, four matchings of faces, mix2 on matching beats.
11. The late second coloring: the round's second keyed S-box `S2` on every cell.
12. Encore: bar mixes, triplets, bow, restack and cross-staff mix again, in that order.

Decrypt undoes the same steps in reverse, with inverse S-boxes, inverse mixes, unbow and unweave.

**Keyed S-boxes.** Each round has two independent boxes, `S` and `S2` (and their inverses). Each is an affine recoding of the SM4 S-box over GF(2)^8: `S'(x) = A2 · SM4(A1 · x ⊕ b1) ⊕ b2`, with invertible 8-by-8 matrices and 8-bit constants squeezed from the sponge until both matrices are invertible and `S2` is not identical to `S`. Because the recoding is affine, every table inherits SM4's DDT maximum of 4/256 and LAT maximum of 16/256 (correlation 2^-3). The linear-and-algebraic attack (`attacks_linear_algebraic/`) measured that on 64 tables.

**mix2 and the field.** The two-cell mixer used by the butterfly, the shell bridges, the cross-staff layers and the Latin pair's field step is the matrix `((1,1),(1,2))` over the SM4 field GF(2^8), polynomial `0x1F5` (that is `x^8+x^7+x^6+x^5+x^4+x^2+1`). In code: `x = u ⊕ v`, `y = u ⊕ 2v`. The six non-B0 bar pairs use other invertible 2-by-2 matrices over the same field. The Python reference multiplies through a 64 KiB table `_GF_MUL`; a branch-free masked-doubling multiply is tested as bit-identical on all 65,536 inputs and is the required form for a native port.

**B0 and the restack** are keyed Latin pairs: the mix2 field step, then `S` on the first output and `S2` on the second. A change in only one input always changes both outputs, for every pair of tables. Two-input changes can still cancel one output.

**Triplets** are 3-by-3 matrices over the integers modulo 256, not over the field. Each listed matrix has determinant 1, and each row and column has at least two odd entries, so a change in any one input changes at least two outputs. They are not claimed to be MDS. Bit 0 of a triplet is exactly GF(2)-linear (the linear-and-algebraic attack verified this); that linearity is confined by the surrounding nonlinear layers.

**Bow pressure** is a chain of seven ARX strokes on an open staff. Each stroke mixes two beats under rotations derived from a pressure byte. The live strokes are `(0,1,2)`, `(2,3,4)`, `(4,5,0)`, `(6,7,0)`, `(1,2,3)`, `(3,4,5)`, `(5,6,0)`. The last three of those read beat 0 for pressure; they do not share the same view of it. `BOW_PRESSURE_ROT = (0, 0, 0, 3, 0, 0, 5)` left-rotates the pressure byte by 0, 3 or 5 bits before the `r1`/`r2` formulas, so the three beat-0 readers no longer share identical rotations. The bow is invertible because beat 0 is not written after the first stroke.

**Cross-staff mix** runs four fixed matchings of faces, in order: opposite, radial, adjacent, then a partial bridge `((1,2), (5,6), (9,10), (13,14))`. Each matching mixes the same beat on both faces with mix2, lower face index first. The bridge was added so the dual-octahedron graph is not two disconnected components.

Staffs stay open: beat 7 is never paired with beat 0, in the bars, the triplets, the restack or the bow writes. Pressure *reads* may use beat 0, which is a different thing.

### The key schedule and the seed

The seed is 128 bytes (1024 bits). It can be passed in, or `load_seed()` reads 256 hex digits from `sneak1024-seed.txt` next to the module — never from any other default path. A seed must have at least 32 distinct nonzero bytes. The default file is cached under a key of path, device, inode, size, mtime and ctime, so replacing the file or rewriting it in place forces a re-read. Seeds that have already passed the weak-seed rule are remembered in a 16-entry LRU; derived étude keys are checked every time and never stored there.

All per-message material comes from the **staff sponge**: successive SHA-256 blocks of `b"SN2/" || domain || counter32 || seed || nonce`, with the counter starting at 0. One-byte domains keep the uses apart. The live letters are:

| Letter | Role |
|--------|------|
| `C` | Clef (seed only, 16 zero bytes of sponge nonce) |
| `G` | Key signature (sponge nonce is the mix digest) |
| `K` | Round schedule (keys, S-box matrices, weave amounts, butterfly order, bridges, whitening) |
| `M` | MAC key |
| `U` | Commitment key (seed only, 16 zero bytes of sponge nonce) |
| `T` | Movements theme |
| `W` | Movements tweak |
| `D` | Cadence key |
| `O` | Coda key |
| `E` | Étude key (used only in `etudes.py`) |
| `R` | Rehearsal: per-stream schedule nonce, per-chunk MAC key and block tweaks (rehearsal revision) |
| `H` | Rehearsal signature (sponge nonce is the rehearsal digest; rehearsal revision) |

Raw SHA-256 prefixes `SN2/P` (pickup), `SN2/T` (theme carry) and `SN2/I` (tweak mid-hash) — and, in rehearsal, `SN2/A` (AD digest) and `SN2/Q` (stream nonce), whose letters are never sponge domains — are not StaffSponge squeezes; the tuning attack checked that they do not collide with the sponge outputs under `I` or `T`.

`Schedule(seed, nonce)` squeezes a 32-byte MAC key from domain `M`, then from domain `K` a 128-byte round key, two affine layers for `S`, weave and butterfly parameters, a 64-entry bridge, and two more affine layers for `S2`, for each of 16 rounds, plus a 128-byte whitening grid. Invertible matrices and a distinct `S2` are found by rejection sampling. That variable squeeze count is one of the reasons a native port cannot copy this schedule as-is.

The **clef** is `StaffSponge(C, seed, 16 zero bytes).take(16)`. It is never stored in the blob. It is hashed into every SIV nonce and every tag, so a tag computed under a different seed, or under an older mix that had no clef, does not verify.

The **key signature** is a 16-byte, seed-keyed commitment to this revision's mix: `StaffSponge(G, seed, sha256(mix_description())).take(16)`. It is not a blob field. `mix_description()` is a canonical JSON of the mix parameters plus a hash of the source of every function the public entry points can reach, and of the module data those functions name. The expected digest is embedded as `EXPECTED_MIX_SHA256`. This is source attestation of the running process, not runtime integrity. It cannot see C-level or interpreter changes, a patched `inspect`, or an in-process edit of a function's `__code__`. Those in-process blind spots were demonstrated in `attacks_octavo_beat6/` and `attacks_octavo_beat7/` and are left as a documented limit.

The round function itself — the thing that turns a 128-byte grid into another 128-byte grid — has been frozen since octavo002 (the beat-0 pressure-rotation fix, 2026-11-09). Every later snapshot changed packaging, the seed path, the outer seal, movements, études or reject timing, not the 16-round staff-core.


## 4. The outer construction

### Pickup and the SIV nonce

Every encryption draws a fresh 16-byte **pickup** (anacrusis). There is no public pickup argument on the normal APIs, by design. Since the info-fix revision the pickup is

```
SHA-256(b"SN2/P" || urandom(16) || time_ns(8) || counter(8) || pid(4))[:16]
```

so two in-process encryptions cannot share a pickup even if the OS generator repeats. A recorded pickup, as in the hello-world sample or the score, is just that 16-byte value written down after the fact.

The single-block nonce is homemade SIV:

```
SHA-256(clef || pickup || encode_block(msg) || encode_ad(ad))[:16]
```

Movements use a length-prefixed payload instead of a single encoded block:

```
SHA-256(clef || pickup || uint64be(len(msg)) || msg || encode_ad(ad))[:16]
```

A caller-supplied nonce must equal the synthetic one or `encrypt` raises `ValueError`. After a valid tag, decrypt recomputes the nonce and raises `AuthError("SIV nonce mismatch")` if it does not match. The version byte is *not* in the live SIV nonce; it is in the commitment and the tag. Études also hash their version byte into the SIV nonce, which is one of the reasons an étude handle cannot reproduce a live blob's nonce.

### Key commitment (tuning, domain U)

The commitment key is seed-only: `StaffSponge(U, seed, 16 zero bytes).take(32)`. The public field is

```
HMAC-SHA256(K_commit, b"U" || version || SN2 || pickup || nonce || encode_ad(ad) [|| nmov32])
```

Movements also bind the 4-byte movement count, so a rewritten `nmov` fails the commitment before the body is parsed. Ciphertext is deliberately left to the tag or coda, so a wrong key can be rejected without walking a huge body — except that conductor-polish, for equal-time movements rejects, always walks the body once for the coda HMAC as well.

Because associated data is in the commitment, a captured blob cannot confirm a seed guess without the AD. If the AD is known, offline confirmation is still possible, the same as for the tag. The commitment does not bind the message body; two valid blobs share a commitment only if their 128-bit SIV nonces collide.

### The tag, associated data, and padding

The single-block tag is HMAC-SHA256 under the per-nonce MAC key, over

```
clef || key_sig || version || SN2 || pickup || nonce || commit || ct || encode_ad(ad)
```

Associated data is never stored in the blob. Empty and omitted AD are the same. Both encrypt and decrypt reject AD longer than 65,536 bytes before any tag work. Inputs must be bytes-like (`bytes`, `bytearray`, `memoryview`); other types raise `TypeError`.

A single-block message is encoded as `len || msg || zero padding` to 128 bytes, with a maximum of 127 payload bytes. `_unpad_block` inverts that with fixed-width integer masks: the 127 payload bytes are one integer, OR-ed with a fixed top bit and AND-ed with a precomputed pad-region mask, so every big-integer operation has same-size operands. The helper returns exactly the old rule's result (checked on every length 0–255, every single-byte pad position, and 200,000 random blocks in the documentation; `test_results.txt` records 313,408 blocks and 0 mismatches). A valid tag with a bad pad raises `DecodeError`, which is a `Rejected` but not an `AuthError`.

### Format version 6 (single-block)

A current single-block blob is 228 bytes:

```
version(1)=6 || SN2(3) || pickup(16) || nonce(16) || commit(32) || ct(128) || tag(32)
```

Minimum overhead is 101 bytes (228 − 127). `decrypt()` accepts only this version. It checks the version byte first, then length and prefix, then computes **both** the commitment and the tag, combines the two `hmac.compare_digest` results with `&` (no short-circuit), and raises one `AuthError("authentication failed")` if either failed. No `Schedule` is built until both pass. On the conductor revision, a measured suite of 20,000 interleaved trials per class put wrong key, wrong AD, bad commitment, bad pickup or nonce, bad ciphertext and bad tag all at about 10.6 µs, within 0.5% of each other (`attacks_octavo_conductor/`). Before that change the split was about 8 µs versus 24 µs (SECURITY.md; the same report measured 7.9 µs versus 23.2 µs). Conductor-polish did not change this single-block path; a fresh single-block timing run on octavo010 is not in the files.

### Movements mode, format version 7

Movements lift the 127-byte cap without a streaming API. The payload is split into 127-byte chunks (the empty message is one empty movement), at most 8,192 movements, so the maximum payload is 1,040,384 bytes. The blob is

```
version(1)=7 || SN2(3) || pickup(16) || nonce(16) || commit(32) || nmov(4)
  || (ct(128) || cadence(32)) * nmov
  || coda(32)
```

The header is 72 bytes. There is no length collision with a 228-byte v6 blob, or with the older 196-byte v2 blob.

One `Schedule` is derived from the seed and the message-wide SIV nonce. Each movement encrypts `encode_block(chunk) XOR theme XOR tweak` under that schedule. The **theme** starts as `StaffSponge(T, seed, nonce).take(128)` and is updated from each movement's ciphertext, index and final flag. The **tweak** is bound to the nonce, the index and the final flag through domain `W`. Identical plaintext sections therefore do not produce identical ciphertexts, and a bit flip in an earlier ciphertext, even in a tags-ignored diagnostic, is not classic CBC malleability (`attacks_octavo_movements/`).

Each **cadence** is an HMAC under domain `D`, bound to the clef, key signature, version, pickup, nonce, commitment, index, final flag, theme, that movement's ciphertext, and the AD. The **coda** is an HMAC under domain `O` over the header, the commitment, the count, every ciphertext, every cadence, and the AD. Since movements-polish, a cadence-only edit is caught by the coda as well as by the cadence check.

`decrypt_movements()` checks version, length and `nmov` first (`nmov` outside 1…8192 is `bad movement count`, before any `nmov`-sized loop). Then it always computes the commitment **and** the coda, combines them without short-circuit, and raises one `AuthError("authentication failed")` if either failed. Nothing is decrypted, and no cadence key or `Schedule` is derived, before both pass. Only then are all cadences checked (every compare runs; the results are combined) and the schedule built. A forged blob with a stolen header now walks the body once, the same as a bad coda always did. Timing still grows with the public blob size.

`test_results.txt` records the movements reject timing on a random seed, 4,000 interleaved trials per class:

| Revision        | 3 movements (commit vs coda) | 10 movements |
|-----------------|------------------------------|--------------|
| conductor       | 4.84 µs vs 11.87 µs (Welch t ≈ −628) | 5.22 µs vs 14.75 µs (t ≈ −370) |
| conductor-polish | 12.45 µs vs 12.42 µs (t ≈ 1.7) | 14.70 µs vs 14.68 µs (t ≈ 0.7) |

SECURITY.md and the README now quote these recorded values exactly (they used to round them to 12.3 µs and 14.3 µs).

Blob length leaks the movement count, not the exact message length: empty through 127 bytes share one size, 128–254 share the next, and so on.

### Rehearsal streaming, format version 8 (live, not yet frozen)

Rehearsal lifts the 1,040,384-byte cap. It is an online AE mode in the STREAM style of Hoang, Reyhanitabar, Rogaway and Vizar (CRYPTO 2015): a stream is split into fixed-size chunks, each sealed with its own tag, and each chunk's key depends on the stream, its counter and a final-chunk flag. It reuses the staff-core and the outer pieces that already exist: the pickup, the seed-only commitment key `K_commit`, the clef, HMAC-SHA256 and the staff sponge.

```
header = version(1)=8 || SN2(3) || pickup(16) || nonce(16) || commit(32) || chunk_size(4, uint32be)   (72 bytes)
stream = header || chunk_0 || … || chunk_{n-1}
non-final chunk = ct(chunk_size) || tag(32)        (exactly chunk_size plaintext bytes)
final chunk     = ct(128·k) || tag(32)             (0 … chunk_size−1 bytes, padded msg || 0x80 || zeros)
```

- **Chunk size** is any multiple of 128 from 128 bytes to 1 MiB, default 64 KiB. It is in the header, in the commitment, in every chunk key and in every tag.
- **Nonce.** There is no SIV nonce: a stream cannot be hashed before its first chunk goes out. The pickup and a separate per-stream nonce are both fresh (`SHA-256(SN2/Q || urandom || time_ns || counter || pid)[:16]` for the nonce). So rehearsal is not nonce-misuse-resistant; a repeated pickup and nonce under one seed and one AD would reuse every chunk key (since rehearsal-fix, a different AD gives unrelated chunk keys).
- **Commitment**: `HMAC-SHA256(K_commit, U || 8 || SN2 || pickup || nonce || encode_ad(ad) || chunk_size32)`, the domain-U pattern of v6/v7. The version byte keeps it apart from the v7 commitment, which has the same shape with `nmov32` in that slot.
- **Per-chunk keys.** A new sponge domain `R` over `chunk || pickup || nonce || chunk_size32 || index64 || final8 || ad_digest` gives the 32-byte chunk MAC key, then one 128-byte tweak per block, with `ad_digest = SHA-256(SN2/A || encode_ad(ad))`. One `Schedule` serves the whole stream, with its nonce `StaffSponge(R, seed, sched || pickup || nonce || chunk_size32 || ad_digest).take(16)`. The AD digest was added to both inputs in rehearsal-fix (finding I1), which changed every v8 ciphertext; v8 had never been published, so no legacy v8 path exists. Each block is `E(P ⊕ T) ⊕ T` under the unchanged 16-round function, so equal chunks (or equal blocks) never give equal ciphertext.
- **Chunk tag**: HMAC-SHA256 under the chunk key over `clef || rehearsal_sig || 8 || SN2 || pickup || nonce || commit || chunk_size32 || index64 || final8 || SHA-256(SN2/A || encode_ad(ad)) || ct`. Every field before `ct` has a fixed length.
- **What that rejects.** Truncation at any offset fails because the last chunk present was sealed non-final. Extension, reordering, duplication and dropping fail on the index. Cross-stream splicing fails because the pickup, nonce and chunk size are in every key. A rewritten chunk size fails the commitment. Wrong AD or a wrong seed fails the commitment and the tag. The tests cover a single-bit flip in every byte of a three-chunk stream, a cut at every offset, and each of those rearrangements.
- **API.** `RehearsalEncryptor` / `RehearsalDecryptor` have `update()` / `finalize()`; there are also `encrypt_rehearsal` / `decrypt_rehearsal` (one-shot; decrypt is all-or-nothing and checks every tag before decrypting anything), the safe reader `iter_rehearsal` (always runs `finalize()`), and `encrypt_rehearsal_file` / `decrypt_rehearsal_file`. `workers=N` (capped at `min(32, cpu_count)`) runs already-verified chunks through fresh worker interpreters that see only the stream's round material and masked blocks, with byte-identical output. `max_chunk_size` is an optional receiver limit.
- **Release rule.** The decryptor decrypts a chunk only after its tag verifies, and within one `update()` call it verifies every chunk before decrypting any. It treats a chunk as non-final only once at least one byte past it has arrived, so it holds back the last `chunk_size + 32` bytes. **A stream cut early yields only verified, chunk-aligned prefix chunks, then `finalize()` raises `AuthError`.** Since rehearsal-fix, forgetting `finalize()` is caught: `iter_rehearsal` always calls it, a `with` block left without it raises `AuthError("stream not finalized")`, and a dropped unfinalized decryptor emits a warning (since rehearsal-polish a default-visible `UnfinalizedStreamWarning`, a `UserWarning`). The file helpers write through a private 0600 file in dst's directory (since rehearsal-polish an anonymous `O_TMPFILE`, opened through a directory fd), fsync it, publish it only on success with a no-follow hard link, and check that dst is then the inode they wrote; they refuse an existing dst unless `overwrite=True`, never follow a symlink at dst, refuse src == dst, and buffer a file-object dst until the stream verifies.
- **Rejects.** A foreign version byte raises `UnsupportedVersion`, as in every other decrypt API. Everything else raises `AuthError`: `bad version prefix`, `bad chunk size`, `bad stream length` and `too many chunks` for public structure, and `authentication failed` for the commitment, the tag and the final padding. Chunk 0 always computes both the commitment and its tag before one combined reject, the same equal-time pattern as v6/v7. On a one-chunk stream, a test measured the commit-fail, tag-fail and ciphertext-fail medians within 1% of each other (about 15–17 µs each, depending on the run).
- **Limits.** At most 2^24 chunks per stream, final chunk included (1 TiB at the default chunk size); AD at most 65,536 bytes. Pure-Python throughput is roughly 19 KB/s per core to encrypt and 13 KB/s to decrypt; the 5 MB test stream took about 37 s and 53 s with 8 workers.
- **Attestation.** The rehearsal code is not reachable from `MIX_CODE_ROOTS`, so `EXPECTED_MIX_SHA256` and `key_sig` did not move and v6/v7 stay byte-identical (the tests compare 18 fixed-pickup blobs with octavo010's module). Rehearsal has its own `EXPECTED_REHEARSAL_SHA256`, computed over everything reachable from `REHEARSAL_CODE_ROOTS` (the staff-core included) plus the live mix digest. It also has its own `rehearsal_signature` (domain `H`), which is hidden in every chunk tag.
- **Études** have no streaming mode.

### Errors, legacy, and études

Every reject a decrypt API raises for a bad or foreign blob is a `Rejected` (a `ValueError`): `AuthError` (authentication, length, prefix, movement count, SIV mismatch), `DecodeError` (valid tag, malformed block), and `UnsupportedVersion` (a format this API does not speak, including an étude round-count mismatch). Caller mistakes stay plain `TypeError` or `ValueError`. `AuthError` and `UnsupportedVersion` are deliberately disjoint. Do not write `except UnsupportedVersion: decrypt_legacy(...)`: the first byte is attacker-chosen, and that would make the non-committing downgrade an attacker-selectable path. SECURITY.md asks for an explicit allowlist or a cutoff date instead.

Published v2 single-block and v3 movements blobs (octavo009 and earlier) open only through `decrypt_legacy()` / `decrypt_movements_legacy()` with `allow_noncommitting=True`. Those helpers are not key-committing: there is no tuning field, and their tags bind the frozen octavo009 mix digest `4e9a7ded…`. They refuse without the flag and emit `LegacyFormatWarning` on every call. Since conductor-polish that warning is a `UserWarning`, so Python's default filters show it even when a library module makes the call. The private bodies behind the helpers check the flag, emit the warning, and pin the version byte themselves. Unpublished v4/v5 blobs (the short-lived tuning revision, never frozen as a snapshot) are rejected outright.

**Études** (`etudes.py`) are lab-only reduced-round variants at 2, 4 and 6 rounds, plus a 16-round comparison handle. They are not selectable from `encrypt` / `decrypt`. Since the conductor revision each étude derives its own key

```
K_e = StaffSponge(b"E", seed, bytes([rounds]) || 15 zero bytes).take(128)
```

and uses `K_e` everywhere the live code uses the seed. The étude version byte is hashed into the SIV nonce. `Etude(r)` opens only its own round count; another étude's byte raises `UnsupportedVersion("étude round count mismatch")`. Current étude bytes are `0x82`/`0x84`/`0x86`/`0x90` (block) and `0x83`/`0x85`/`0x87`/`0x91` (movements). Never-published tuning-fix and tuning étude bytes are rejected. Published octavo009 étude blobs (`0xE*` / `0xF*`) open only through the legacy étude helpers with `allow_noncommitting=True`. Those legacy étude helpers will be removed in the first revision after this freeze that touches `etudes.py`, and no later than 2027-03-01; after that the octavo009 score opens only from the frozen octavo009 tree.

`etude(r)` refuses `seed=None` and the public demo seed unless it was made with `lab_seed=True`. `Etude.lab_seed` is read-only after construction. `etude_key(seed, r)` is the documented ungated low-level path (no demo-seed check). The published score is 64 étude vectors under the demo seed with `lab_seed=True`: 16 raw permutations, 24 single-block AEAD vectors, and 24 movements vectors. A 16-round étude permutation equals the live `encrypt_grid` under `Schedule(K_e, nonce)`, not under the raw seed.


## 5. Design rationale

Almost every layer is a response to a concrete finding. The short version is: close the hole that the last attack actually demonstrated, leave the rest, and write down what is still open. None of this makes the cipher less homemade.

**HMAC-SHA256 and the staff sponge** exist because N1 failed both integrity and key-schedule secrecy. The first N2 attack (`attacks/`, 2026-11-08) found 0 of 200,000 random blobs accepted, 0 of 920 single-bit flips accepted, and a seed-to-material map that failed every affineness test. The remaining route to the seed is a SHA-256 preimage on a secret 128-byte suffix.

**8-bit cells, named bar mixes, and a late second coloring** were the first expansion of the 4-bit design. The 8-bit attack (`attacks_8bit/`) found no plaintext, seed or MAC break, but it did find a compatibility flaw: 7 of 2,048 authenticated pre-coloring blobs decrypted as different plaintext under the new code, because the version and MAC domain had not changed.

**The clef in the MAC, the bar-line encore, and the SIV nonce** were the answer to that report. `attacks_siv/` found the clef closed legacy replay (all archived and newly generated old blobs failed with a tag mismatch), the encore stopped per-cell S2-to-S fusion, and the SIV nonce bound the nonce to the message. The encore still only mixed within beat groups `{0,1,2}`, `{3,4}` and `{5,6,7}`, and identical messages still produced identical blobs, so a public encrypt-only dictionary attack still recovered a PIN in a linear number of guesses.

**Joining beats 3–4 and 5–6** (`M2` and `M3` in the bar list) removed that block-diagonal encore. `attacks_join_pairs/` confirmed one connected super-box per staff, and full byte dependence at two rounds. High-bit (`Δ = 0x80`) differences could still slip through even coefficients with probability 1, 1- and 2-round distinguishers remained, and the dictionary attack remained.

**Field pair mixes over SM4 GF(2^8), six overlapping triplets, and a random 16-byte pickup** addressed those leftovers. `attacks_pickup/` found the public PIN-matching attack closed (0 of 256 encryptions of the correct PIN matched its target; equal messages no longer gave equal blobs), and the old one-cell middle crossing gone in the measured cases. A new 8-byte 1-round truncated trail and a 2-round sparse-output distinguisher appeared, the tag still did not commit to the mix tables, and some named pairs could still cancel under two-input changes.

**The key signature, field mix2, and bow pressure** were the three leftover-shape fixes. `attacks_three_fixes/` found all three held at the test size: the 2-round sparse distinguisher was gone (0 events in 524,288 pairs), and mix2 no longer leaked a single input to a single output. A probability-1 one-round truncated differential remained (a single input cell reached only 5–8 of 16 staffs after one round) but did not survive to two rounds in those tests.

**Cross-staff mix, the bridge matching, nonlinear B0, odd-beat restack, and a listed mix-code key signature** were the next four changes. `attacks_four_leftovers/` found the graph split closed and no single-cell one-round staff confinement in a 2,088,960-pair scan. The arithmetic-code commitment caught listed source patches. ARX singleton leaks in B0, the bow and the restack remained, and `staff_mix` was at first omitted from the source commitment.

**Replacing B0 and the restack ARX with keyed Latin S-box pairs, and closing the key-signature coverage gap** (adding `staff_mix` and the rest of the reachable closure) set up the linear and algebraic attack. `attacks_linear_algebraic/` found no break beyond round 1 in a fixed-schedule white-box model. S-boxes matched SM4's linearity (2^-3). The cross-staff layer has linear and differential branch number 6. A relaxed single-trail model bound 188 active S-boxes over 16 rounds. Slide and related-nonce tests on 200 schedules found no matching rounds. The leftover was five bow-plus-restack single-byte leaks, all on beat 7.

**Bow stroke `(5,6,7)` became `(5,6,0)`** so a beat-7-only change can no longer keep its delta inside rehair pair (6,7). `attacks_octavo_beat7/` confirmed 0 singletons on odd beats, then found the same mechanism one stroke earlier: about 1 in a million beat-6 changes left a single changed byte. The last two strokes also shared beat 0's rotations, which made some bow-only patterns more predictable, all of them wiped by the rehair and the cross-staff layer within the same half-round.

**Bow stroke `(4,5,6)` became `(4,5,0)`** for the same reason. `attacks_octavo_beat6/` scanned 2.69 billion one-beat changes and found no single-byte leak on any beat, with written no-singleton arguments for beats 0, 4 and 6, and a partial argument plus measurement for beat 2. The cost was a stronger three-way shared rotation from beat 0, still confined to one half-round.

**`BOW_PRESSURE_ROT = (0, 0, 0, 3, 0, 0, 5)`** gave each beat-0 reader a different view of the pressure byte. That is the last change to the round function (octavo002). Verification in `fix_beat0rot_verification/` reported 0 singletons on all beats and a 2^21-base even-beat scan. The bow-alone best differentials improved in the lab screen recorded in the source comments (beat 7/6/0 from about 2^-4.7 / 2^-5.6 / 2^-8.1 to about 2^-7.4 / 2^-7.1 / 2^-10.2). Integrals and cubes of fixed-rotation ARX were not removed. The round function has not had a full attack pass since.

**Packaging** (octavo003) was triggered by an independent review, [@liqdmetal](https://github.com/liqdmetal) in [issue #1](https://github.com/Kromatikus/octavo/issues/1). The reviewer rebuilt the round function, ran on the order of 535 million probes, and reported no distinguisher, forgery or key recovery. That is still a negative experimental result, not expert cryptanalysis. The packaging bugs were real: a hardcoded seed path, stale attack-folder paths, `inspect.getsource` on every call, no version byte, and weak seeds accepted. The fix was a module-relative seed, a cached and embedded key-signature digest, a one-byte format version (blobs became 196 bytes), weak-seed rejection, and portable tests. The round function was not touched.

**Hardened pickup and associated data** (octavo004, the info-fix) closed leftovers from the beat-6 report: an RNG-failure equality leak if `urandom` repeated, and the absence of AD. Constant-time and single-block limits were documented, not redesigned. Format version became 2; blobs stayed 196 bytes.

**Seed-only load** (octavo005) stopped `load_seed()` from falling back to `/workspace/sneak1024-seed.txt` when the module-relative file was missing.

**Dropping the unused B0 field matrix** (octavo006) took a `None` slot out of `BARS` so it was no longer hashed into the key signature, after a review finding that the unused matrix was being attested as if it were live. `_canon_data` was extended so new constant types fail closed rather than skip.

**Outer-layer tightening** followed `attacks_octavo_outer/` (2 Minor, 8 Info): `bytes()` coercion made `encrypt(5)` mean five NUL bytes, and the full `Schedule` was built before the HMAC check, about 17 ms of extra work on garbage. `attacks_octavo_outerfix/` confirmed both Minors closed in octavo007: strict bytes-like types, the MAC key verified before `Schedule` is built, and `MAX_AD_LEN = 65,536`. A 2% mutation lab (`mutation_lab_2pct/`) had also found that the statistical diffusion checks would accept a weaker one-round `mix2`; octavo007 added tighter one-round diffusion and mix-structure tests. The lab itself was never applied to the live mixer.

**Movements mode** (format version 3, later polished into the v7 shape) is the answer to the 127-byte cap short of a streaming API. `attacks_octavo_movements/` found no break, but the coda did not yet cover cadence bytes, so a cadence-only edit still had a valid coda and was rejected only afterwards. **Movements-polish** (octavo008) put every cadence byte under the coda and derived the cadence key only after the coda check. Domain letters `T`, `D`, `O`, `W` and `I` are pinned in the tests.

**Études and the published score** (octavo009) exist so reduced-round work and foreign implementations have a shared target. The first étude API still ran under the live seed, which later became a Low finding.

**Key commitment** was added in the unpublished tuning revision (v4/v5) after the usual AEAD observation that the tag does not, by itself, stop a blob from being valid under more than one key. `attacks_octavo_tuning/` found no two-key blob and no outsider downgrade that stripped the commitment, and then two Lows: default decrypt still opened non-committing v2/v3, and associated data was not in the commitment, so a captured blob confirmed a seed guess offline and a decryption oracle distinguished `CommitError` (wrong seed) from `AuthError` (right seed, wrong AD).

**Tuning-fix** (v6/v7) bound `encode_ad(ad)` and movements `nmov` in the commitment, rejected legacy by default, rejected unpublished v4/v5, and collapsed `CommitError` into `AuthError("authentication failed")`. `attacks_octavo_tuningfix/` found both Lows closed, and a new Low: the étude API had no key, schedule or version separation from live — `Etude(16).unpermute` could decrypt a live ciphertext without checking the commitment or the tag. It also noted that `UnsupportedVersion` still subclassed `AuthError`, and that commitment-fail versus tag-fail timing was a 1-bit oracle.

The **conductor's mark** review (`review_octavo_conductor/`) was a constant-time and timing review of that tuning-fix tree. Comparisons themselves were correct (`hmac.compare_digest` everywhere that matters; a flip in byte 0 of a tag was indistinguishable from a flip in byte 31). Wrong key, wrong AD, bad commitment, bad pickup and bad nonce could not be told apart. Timing *did* reveal which check failed: about 8.4 µs for a commitment failure versus about 24.5 µs for a tag failure (Medium, M1). The round function was not constant-time by construction (Medium M2, and Lows L1–L5: the GF table, data-dependent rotations, schedule rejection sampling, padding-length timing, and key-dependent permutation addressing). Those last five remain open in Python and are written down as Rust-port requirements.

**Conductor** applied M1 for single-block (always run both checks), key-separated the études, pinned the étude round count, stopped `UnsupportedVersion` from being an `AuthError`, required `allow_noncommitting=True` on legacy helpers, and moved unpad to constant-structure control flow. `attacks_octavo_conductor/` found no break, the étude Low fixed, and three new Lows: movements still checked the commitment first (about 4.7 µs versus 11.7 µs in that report), `LegacyFormatWarning` was a `DeprecationWarning` that Python hides by default, and the new unpad was slower and still leaked length at the nanosecond scale.

**Conductor-polish** (the octavo010 freeze) is those three Lows, plus the Info suggestions from the same report: equal-time movements rejects, `LegacyFormatWarning` as a `UserWarning`, fixed-width mask unpad, private legacy bodies gated and version-pinned, the `Rejected` base class, a 2027-03-01 end date for legacy étude helpers, a seed-file cache keyed on device, inode, size, mtime and ctime, a 16-entry LRU seed memo that never stores étude keys, and a read-only `Etude.lab_seed`. There is not a separate attack folder for conductor-polish; the claim that the Lows landed is the verification in `conductorpolish_verification/` and `test_results.txt`.

**Rehearsal** (live, not yet frozen) answers the open question this freeze left: lifting the 1 MB cap with a streaming API. STREAM was chosen because its security argument is simple. If each chunk is sealed by an AE under a key or nonce that is unique to (stream, counter, last-flag), then a valid stream can only be a prefix-closed sequence of the sender's chunks, and the last-flag stops an attacker from presenting a proper prefix as complete. Here the per-chunk AE is the existing pattern (HMAC-SHA256 over the ciphertext and the bound header fields), and per-chunk keys come from the keyed sponge instead of a nonce counter. Per-block XEX tweaks replace movements' theme chaining, because chunk order is already enforced by the tags. Keeping rehearsal out of the live mix closure was deliberate: if `key_sig` had moved, every v6/v7 tag would have moved with it. The first attack on rehearsal (`attacks_octavo_rehearsal/`) found no cryptographic break; its findings were in the file helpers (fixed names, collisions, modes), the streaming API (forgetting `finalize()`), the workers (fork, no cap), and three hardening items (AD in chunk keys, verify-all-first in one shot, a receiver chunk-size limit). Rehearsal-fix applies all of them. The interesting design choice there was I1: putting the AD digest into the chunk keys costs nothing and removes the one place where two streams with different AD still shared ciphertext blocks under a repeated nonce, and changing v8 was free because it had never been published.


## 6. Revision history

Frozen snapshots `/workspace/octavo001` through `/workspace/octavo011`. Dates are America/New_York. SHA-256 values are of `sneak_n2.py`. A blank key_sig means the snapshot file does not record one. Test counts are those written in each snapshot at freeze time.

| Snapshot | Date | Revision | `sneak_n2.py` SHA-256 (short) | Tests | Live format | What changed |
|----------|------|----------|-------------------------------|-------|-------------|--------------|
| octavo001 | 2026-11-09, about 9:52 AM | beat-6 bow fix, post latin-pair / cross-staff / pickup | `922a29d8…fe56fe10` | 229/229 | 195-byte `SN2 \|\| pickup \|\| nonce \|\| ct \|\| tag` | The staff-core as attacked in `attacks_octavo_beat6/`: Latin B0, odd restack, field bars, six triplets, bow strokes including the beat-7 and beat-6 fixes, cross-staff mix with bridge, pickup, clef, encore, SIV nonce, HMAC tag, code-closure key signature. |
| octavo002 | 2026-11-09, about 10:36 AM | beat-0 pressure rotation | `25cfe812…64612ff0` | 237/237 | 195 bytes, same layout | `BOW_PRESSURE_ROT = (0,0,0,3,0,0,5)`. Round function frozen from here on. key_sig `1946c5ac57f19d045eeacd9e5ed823fb`. |
| octavo003 | 2026-11-09 | packaging | `127a9628…354778cd` | 245/245 | 196 bytes, version 1 | Module-relative seed, cached/embedded key signature, format version byte, weak-seed rejection, portable tests. Triggered by issue #1. key_sig `e5f54546ca530ee6103b8420578a6aca`. |
| octavo004 | 2026-11-09 | info-fix | `2d7c18e2…c3a6a39f` | 253/253 | 196 bytes, version 2 | Hardened pickup; optional AD in the SIV nonce and HMAC; constant-time and single-block limits documented. key_sig `6fcc97151089539a8084e4cc3886921a`. |
| octavo005 | 2026-11-10 | seed-only | `082d5c80…8cdfb331` | 254/254 | 196 bytes, version 2 | `load_seed()` no longer falls back to `/workspace/sneak1024-seed.txt`. key_sig `55daf5b7fde67625397935b918af6c1a`. |
| octavo006 | 2026-11-10 | unused-B0 attestation and picture | `3eb1da8f…75f8798d` | 258/258 | 196 bytes, version 2 | Unused B0 matrix dropped from `BARS`; `_canon_data` extended; picture redrawn. key_sig `f716aa939283e46ea7760717a22a7307`. |
| octavo007 | 2026-11-10 | outer-fix | `3e61bdcd…958cb7ed` | 279/279 | 196 bytes, version 2 | Strict bytes-like types; verify HMAC before `Schedule`; `MAX_AD_LEN = 65536`; one-round mix tests from the 2% mutation lab. key_sig `42ded003543b35fa0695a2e767f4415e`. |
| octavo008 | 2026-11-10 | movements-polish | `48cf88ac…5ac0b559` | 295/295 | 196-byte v2 single-block; movements v3 | Coda covers every cadence byte; cadence key derived after the coda check. key_sig `d8a1358aae4116aaafcee90ec74a4d8e`. |
| octavo009 | 2026-11-11 | etudes | `38301026…3eb83784` | 306/306 | v2 / v3 unchanged | `etudes.py` and published score (64 vectors). Full-round ciphertexts unchanged from octavo008. key_sig still `d8a1358aae4116aaafcee90ec74a4d8e`. |
| octavo010 | 2026-11-11 | conductor-polish | `c07707bf…8bd39d50` | 366/366 | v6 228-byte single-block; v7 72-byte movements header | Key commitment (via unpublished v4/v5 and the tuning-fix to v6/v7); equal-time single-block and movements rejects; key-separated études; legacy opt-in; `Rejected`; mask unpad; seed-cache and memo hygiene. Full-round ciphertexts unchanged from octavo009 for the same seed, nonce and block. key_sig `340dc1e062502bb13462a94ba490c3dc`. |

| not frozen | 2026-11-11 | rehearsal | `85a67178…2047030f` | 414/414 | v6 / v7 unchanged; new v8 streams (72-byte header, chunked) | Rehearsal streaming mode (STREAM-style chunks, domains `R`/`H`, own attestation); docs and labels fixed (ATTACKS.md through octavo010, module docstring, exact movements timings, FEATURES nonce). v6/v7, `EXPECTED_MIX_SHA256` and key_sig unchanged. Attacked in `attacks_octavo_rehearsal/` (no cryptographic break). |
| rehearsal-fix, not frozen (superseded) | 2026-11-11 | rehearsal-fix | `81686d30…04078539` | 437/437 | v6 / v7 unchanged; v8 layout unchanged, v8 ciphertexts changed (AD digest in chunk keys) | Fixes from the rehearsal attack: private mkstemp temp files, same-file refusal, 0600 output, fsync, `overwrite=False`, `iter_rehearsal`, unfinalized-decryptor error and `ResourceWarning`, buffered file-object output, one-shot verify-all-first, AD digest in the R-sponge inputs, spawn-style workers capped at min(32, cpu_count), `max_chunk_size`. `EXPECTED_REHEARSAL_SHA256` `584758f7…`, rehearsal_sig `4ed3c0f3…`; score version 5. Not attacked again. |
| rehearsal-polish, not frozen (superseded) | 2026-11-11 | rehearsal-polish | `7ea3dd84…265c111f` | 448/448 | v6 / v7 unchanged; v8 layout, headers and ciphertext blocks unchanged, v8 tags changed (rehearsal digest moved) | Fixes from the rehearsal-fix attack: anonymous `O_TMPFILE` (or `O_EXCL|O_NOFOLLOW`) output opened through a directory fd, no-follow link publish with post-publish inode check, overwrite via a private swap name, empty partials removed, `.partial` names that cannot clobber (L1, I3, I6); absolute paths fixed at call time (I4); UTF-8-safe temp prefix (I5); `UnfinalizedStreamWarning` (L2); workers get the parent's import-time source over the pipe and run `python -I -B` (I1), deadline I/O with `worker_timeout` (I2); bool validation (I7); bytes-path `TypeError`; memory documented (I8). `load_seed` handle left (mix-attested). `EXPECTED_REHEARSAL_SHA256` `dd02f707…`, rehearsal_sig `1f8097d2…`; score version 6. Attacked in `attacks_octavo_rehearsalpolish/` (3 Low, 9 Info, no cryptographic break). |
| octavo011 | 2026-11-11 | rehearsal-finale | `929bacc1…107b772f` | 459/459 | v6 / v7 unchanged; v8 layout, headers and ciphertext blocks unchanged, v8 tags changed (rehearsal digest moved) | Fixes from the rehearsal-polish attack: copy-fallback fd held open through the inode check (L1); `UnfinalizedStreamWarning` survives `-W error` and warns every time (L2); `iter_rehearsal` bytes are always ciphertext, no file probe (L3); `renameat2(RENAME_EXCHANGE)` overwrite that keeps the old dst on a refused race, `.swap` crash leftovers documented (I1/I2); `O_TMPFILE` link failures copy, partial kept under a fresh name on any error with `partial_error`, `dst.complete` (I3); same-file re-check via the dirfd (I4); executed-bytecode check against `_MODULE_SOURCE` (I5); workers `-I -B -S`, empty env, per-batch spot check (I6); `read_size` validation (I7); plaintext cleared before a padding reject (I8). `EXPECTED_REHEARSAL_SHA256` `f28badba…`, rehearsal_sig `a3b4c820…`; score version 7. key_sig `340dc1e062502bb13462a94ba490c3dc`. Not attacked. |

Between octavo009 and octavo010 the live tree also passed through unpublished revisions named tuning, tuning-fix and conductor. Those were not frozen as `octavo0xx` snapshots. Their identifiers are in the live-tree notes at the top of `SNAPSHOT.md` and in the corresponding attack and review folders.

Older frozen trees (`test1`, `test3`, `test13`, `testn1`, `testn3`, `testn4`, `testn5`, `sneak_t1n`, `sneak_v2`–`sneak_v13`, and `/workspace/sneak1024-seed.txt`) are also never overwritten. They are earlier N2 or N1 points, not this revision series.


## 7. Known limits and open questions

**It is still homemade.** For real secrets use AES-GCM-SIV, age, or libsodium. A long streak of negative attack results is not a proof, and there is no third-party cryptanalysis of the current outer construction. The one independent review rebuilt the round function around octavo003; that function has not changed since octavo002, but movements, key commitment, études, equal-time rejects and rehearsal did not exist then. Conductor-polish itself has no dedicated attack folder. Rehearsal has had two in-house attacks (`attacks_octavo_rehearsal/`, `attacks_octavo_rehearsalfix/`), and the rehearsal-polish changes have not been attacked.

**Size limits and streaming.** Single-block messages stop at 127 bytes. Movements mode stops at 8,192 movements, 1,040,384 bytes, and has to be supplied all at once. Rehearsal (v8, live, not yet frozen) lifts that cap: chunks of 128 bytes to 1 MiB, at most 2^24 chunks, AD at most 65,536 bytes. It is new attack surface. A cut stream releases a verified prefix before the error, so applications that must not act on partial data have to buffer or use `iter_rehearsal` and treat pieces as provisional until the loop ends. A repeated pickup and nonce under the same AD would reuse every chunk key, because there is no SIV protection. The streaming decryptor (unlike one-shot `decrypt_rehearsal`) still decrypts every verified chunk before it can see a forged final chunk. Worker processes no longer fork or see the seed, but they do hold the stream's round material. Throughput is low (tens of KB/s per core). The lanes prototype exists only as a stopped lab (`lab_octavo_lanes/`) and is not part of the live cipher.

**Timing.** Python Octavo is not constant-time. What conductor and conductor-polish actually equalized is the outer reject path: single-block commitment versus tag, and movements commitment versus coda. Structural rejects (length, version, prefix, `nmov`) stay faster, and they depend only on public data. Timing still grows with public blob size and with AD length. After a valid tag, `_unpad_block` is much tighter than before (the L=0 versus L=127 gap fell from about 780 ns to under 100 ns) but is still not a constant-time primitive. The seed memo can still show, within one process, whether a seed was used recently (a miss versus a hit). The round function still leaks in any model where table lookups, data-dependent rotations, rejection sampling or key-dependent addresses are visible: those are review findings M2 and L1–L5, and they were not changed.

**Rust port requirements** (from SECURITY.md; a native port of the current Python structure would leak clearly):

1. No 256-entry S-box tables. Use a bitsliced or tower-field SM4 S-box, and evaluate the keyed affine layers as constant-time bit-matrix products.
2. No `_GF_MUL` table. Use masked `xtime` and fixed-iteration schoolbook multiplication (already checked bit-identical to the table).
3. Permutations via SIMD byte shuffles or full-scan masked gathers, and no `if SH[f]` branch in `unweave`.
4. `rotate_left` only on cores with a barrel shifter, or a masked rotate network.
5. Fixed-budget schedule derivation: no data-dependent loop counts, no rejection sampling.
6. `subtle` (`ConstantTimeEq`, `Choice`, `ConditionallySelectable`) for commitment, tag, cadence, coda, SIV and padding checks; one combined `Choice` and one error return for single-block.
7. `zeroize` on the seed and all derived keys and tables; `black_box` / `#[inline(never)]` around constant-time selects.
8. dudect-style tests, Valgrind/ctgrind secret marking, and binary-level checks in CI.

**Leftovers that are accepted or only partly closed.**

- The key signature cannot see in-process bytecode or builtin patches (`attacks_octavo_beat6/`, Low). That is outside what a source hash can promise.
- Triplet bit 0 is exactly linear; bow-alone linear relations exist (a 2-bit relation of magnitude 0.145, a single-bit relation of about 0.039) and are reduced to about 0.0038 after the rehair. Nothing in the later reports took these to round level.
- Beat 2 still has only a partial written no-singleton argument; the even-beat scans found 0 leaks.
- Three strokes still read beat 0. They no longer share identical rotations, but integrals and cubes of fixed-rotation ARX were not removed.
- The commitment does not bind ciphertext. A two-key blob still needs on the order of 2^128 work for the commitment alone in the random-key model used in `attacks_octavo_tuningfix/`.
- Offline seed confirmation is possible when the AD is known.
- There is no anti-replay. A repeated pickup, seed, message and AD still reproduce a blob bit for bit (SIV determinism).
- Legacy v2/v3 and legacy étude helpers remain as an opt-in, non-committing transition path until they are removed (étude helpers: no later than 2027-03-01).
- The published demo seed will decrypt any `seed=None` sample.

**Open design questions**: an attack pass on rehearsal (v8) — splicing and truncation with chosen chunk sizes, the XEX tweak derivation, the first-chunk equal-time path, the prefix-release rule, and the worker pool; whether rehearsal should get a misuse-resistant (SIV-like or nonce-derived) variant; a native port that actually meets the requirements above; and a third-party review of the v6/v7 outer construction and of the round function as it stands after the beat-0 rotation fix.


## 8. Glossary

**Anacrusis** — another name for the pickup: the unstressed note before the first bar line.

**Bar, bar mix** — a named two-cell mix on an adjacent pair of beats of each staff. B0, B1, B2, B3 and B4 sit on the written bar lines; M2 and M3 are interior joins so every adjacent pair is mixed.

**Beat** — one of the eight positions along a staff, a single byte in the live cipher.

**Bow, bow pressure** — a chain of ARX strokes that restack a staff, with rotation amounts read from a pressure beat. Applied mid-round and again in the encore.

**Cadence** — the per-movement HMAC (domain `D`) in movements mode.

**Clef** — a seed-only 16-byte value, never stored, hashed into every nonce and tag so legacy or foreign-key tags fail.

**Coda** — the final HMAC (domain `O`) over a movements blob: header, commitment, count, every ciphertext, every cadence, and the AD.

**Conductor, conductor-polish** — the revisions that equalized reject timing, separated étude keys, and tidied legacy and seed hygiene. This freeze is conductor-polish.

**Cross-staff mix** — mix2 between faces on matching beats, in four layers (opposite, radial, adjacent, bridge).

**Encore** — the second pass of bars, triplets, bow, restack and cross-staff mix, after the late S-box `S2`.

**Étude** — a lab-only reduced-round (or 16-round comparison) handle in `etudes.py`, running under its own derived key.

**Face** — one of the sixteen 8-beat staffs; eight inner, eight outer.

**Key signature** — a 16-byte, seed-keyed hash of the attested mix description; hidden in the tag, not stored in the blob.

**Latin pair** — mix2 followed by two keyed S-boxes, used for B0 and the odd-beat restack.

**Liner notes** — these notes: the prose commentary that sits with a score.

**Movements** — the multi-block mode (live format version 7) that chains up to 8,192 padded 127-byte sections under one schedule.

**Pickup** — a per-encryption 16-byte random value sitting at the front of the blob, hashed into the SIV nonce and the tags, so equal messages do not produce equal blobs.

**Rehair, restack, odd-beat restack** — the keyed Latin pairs on (0,1), (2,3), (4,5) and (6,7) that follow each bow.

**Rehearsal** — the streaming mode (format version 8): fixed-size chunks, each with its own tag, bound to the chunk counter and a final-chunk flag.

**Rejected** — the common parent of `AuthError`, `DecodeError` and `UnsupportedVersion`.

**Score** — the published test-vector file `score/vectors.json`: 64 étude vectors (score version 3 at octavo010) plus, since rehearsal, 8 live rehearsal vectors (score version 4, 72 vectors; regenerated in score version 5 for rehearsal-fix and in score version 6 for rehearsal-polish, where only the v8 tags changed).

**Shell, shell bridges** — the inner and outer octahedra, and the 64 mix2 pairings that join them.

**Staff** — one face's eight beats, written as four measures of 2/4, open (no wrap from 7 to 0).

**Staff sponge** — the SHA-256 expander `SHA-256(SN2/ || domain || counter || seed || nonce)`.

**Theme, tweak** — the running 128-byte mask and the per-movement 128-byte mask in movements mode (domains `T` and `W`).

**Triplet** — a 3-cell mix over the integers modulo 256, on every adjacent window of three beats.

**Tuning** — the key-commitment layer, HMAC domain `U`.

**Weave** — the keyed rotation of beats along each staff and of faces along each beat-column.

**Whitening** — a final 128-byte key XOR after the 16th round.

## Origin (lore)

*This section is myth, not math. Nothing in it describes how the cipher works.*

Before the octahedra, there was the Point: no width, no edge, only time. The Point dreamed. Its first dream was a seed, and the seed unfolded into a schedule, the schedule into sixteen faces, and the faces into staffs of eight beats each. Every message sealed in Octavo is a phrase hummed back into the dream; only someone who holds the seed can hear it as music, and to everyone else it is noise.

Outside the myth, Octavo is still homemade and not for real secrets: use AES-GCM-SIV, age, or libsodium.
