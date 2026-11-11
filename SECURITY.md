# Security

Octavo is an experimental, homemade cipher made for learning and for fun. It is not constant-time, and nothing here is a proof of security. An independent reviewer ([@liqdmetal](https://github.com/liqdmetal), [issue #1](https://github.com/Kromatikus/octavo/issues/1)) rebuilt the round function and reported no distinguisher, forgery or key recovery; that is a negative experimental result, not expert cryptanalysis and not a proof.

**Do not use Octavo to protect real data.** Use a vetted, well-reviewed tool such as AES-GCM-SIV (RFC 8452), [age](https://age-encryption.org), or [libsodium](https://doc.libsodium.org).

Found a weakness? That's the point of publishing it. Please open an issue with a description and, ideally, a script that reproduces it. Credible findings get added to [ATTACKS.md](ATTACKS.md) with credit.


## The demo seed is public

`sneak1024-seed.txt`, the file `load_seed()` and every `seed=None` call use, is a **public demo seed**. Its full hex is published in `score/vectors.json` (and in every frozen snapshot), so any blob made with `seed=None` or with that file can be read by anyone. Use it only for samples and tests. Études refuse it (and `seed=None`) unless the handle is made with `etude(r, lab_seed=True)`.

## Timing side channels (Info 7, conductor's mark review)

Octavo is not constant-time. The 16-round function looks up keyed 256-entry S-box tables, uses a 64 KiB GF(2^8) multiplication table, uses data-dependent rotations in the bow-pressure layer (`r1` and `r2` come from a pressure byte), permutes cells with key-dependent indices, and builds its schedule with rejection sampling. Those operations can leak through cache timing and other microarchitectural side channels. CPython cannot be made constant-time: integers are objects, every index touches a value-dependent object, and the interpreter adds microseconds of jitter. The Python reference can only be made **uniform in control flow**. The deliberate constant-time primitives are `hmac.compare_digest` and OpenSSL-backed SHA-256 / HMAC.

What the conductor revision does:

- **Single-block rejects are equal-time (M1 fixed).** `decrypt()` (and `Etude.decrypt()`) always compute and compare both the commitment and the tag, combine the two results without short-circuit, and raise one `AuthError("authentication failed")`. A wrong key, wrong AD, bad commitment, bad pickup/nonce, bad ciphertext and bad tag all do the same work before rejecting. Before this change a commitment failure took about 8 µs and a tag failure about 24 µs; now both take the commitment-plus-tag time. No `Schedule` is ever built before both checks pass.
- **Movements rejects are equal-time too (conductor-polish, attack L1).** `decrypt_movements()` (and `Etude.decrypt_movements()`) always compute the commitment AND the coda (one HMAC over header, commitment, count, every ciphertext, every cadence and AD), combine the two results without short-circuit, and raise one `AuthError("authentication failed")`. Nothing is decrypted, and no cadence key or `Schedule` is derived, before both pass. Measured on a random seed (medians, `conductorpolish_verification/`): before, commitment failure 4.8 µs vs coda failure 11.9 µs (3 movements, Welch |t| ≈ 630); after, 12.3 µs vs 12.3 µs (|t| < 1); at 10 movements 5.2 vs 14.8 µs before, 14.3 vs 14.3 µs after. The cost: a forged blob with a stolen header now walks the body once (one HMAC, O(nmov), capped at MAX_MOVEMENTS), the same as a blob with a bad coda always did. Timing still grows with the (public) blob size.
- **Padding check is fixed-width (conductor L4, conductor-polish L3).** `_unpad_block` reads the 127 payload bytes as one integer, ORs in a fixed top bit and ANDs with a precomputed pad-region mask for `L & 127`, so every big-int operation has same-size operands. It is about 12× faster than the conductor per-byte loop (about 0.6 µs vs 7 µs) and its L=0 vs L=127 gap fell from about 780 ns to under 100 ns. It returns exactly the old rule's result (checked on every L 0–255 with every single-byte pad position and 200,000 random blocks).
- **Seed caches (conductor I3, conductor-polish I4/I5).** The default seed file is parsed once; the cache key is `(path, st_dev, st_ino, st_size, st_mtime_ns, st_ctime_ns)`, so replacing the file (new inode) or rewriting it in place (new ctime, which `cp -p`, `rsync -t` and `touch -r` cannot set back) forces a re-read. Seeds that passed the weak-seed rule are remembered in a 16-entry LRU (least recently used dropped, never a clear-all). Derived étude keys are never put in that memo; they are checked on every use. Within one process, timing of a memo miss vs hit can still show whether a seed was used recently.
- **Not changed in Python (port requirements below):** the secret-indexed S-box tables (M2), the GF(2^8) table (L1; a branch-free masked-doubling multiply is bit-identical and tested, but about 3× slower in CPython, so the table stays), data-dependent rotations (L2), schedule rejection sampling (L3) and key-dependent permutation addressing (L5).

## Rust port requirements

Anyone porting Octavo to Rust, C, Go or WASM must not copy the Python structure. A native port of the current design leaks clearly. Requirements:

1. **S-boxes (M2):** no 256-entry tables. Use a bitsliced or tower-field SM4 S-box circuit, and evaluate the keyed affine layers `A2·S(A1·x ⊕ b1) ⊕ b2` (and their inverses for SI/SI2) as constant-time bit-matrix products.
2. **GF(2^8) (L1):** no `_GF_MUL` table. Use masked `xtime` (`(a << 1) ^ (0xF5 & 0u8.wrapping_sub(a >> 7))`) and fixed-iteration schoolbook multiplication. The test suite checks that this is bit-identical to the table on all 65,536 inputs.
3. **Permutations (L5):** use SIMD byte shuffles (`pshufb`, `vpermb`, NEON `tbl`) with secret index vectors, or full-scan masked gathers. Replace the `if SH[f]` branch in `unweave` with an unconditional rotate.
4. **Rotations (L2):** `rotate_left` is constant-time on x86, ARMv7+ and AArch64. Exclude cores without a barrel shifter or use a masked rotate network.
5. **Schedule (L3):** fixed-budget derivation, no data-dependent loop counts: squeeze a fixed number of bytes, use wide modular reduction, build invertible matrices without rejection, and compute parity branch-free.
6. **Comparisons and padding (M1, L4):** use the `subtle` crate (`ConstantTimeEq`, `Choice`, `ConditionallySelectable`) for commitment, tag, cadence, coda and SIV checks and for the padding/length check. One combined `Choice` and one error return for single-block.
7. **Hygiene:** `zeroize` the seed and all derived keys and tables; use `black_box` / `#[inline(never)]` around constant-time selects.
8. **Verification:** dudect-style tests, Valgrind/ctgrind secret marking, and binary-level checks in CI.

## Format limits (Info 8)

Single-block messages are at most 127 bytes in a 228-byte version-6 blob (32-byte commitment plus 32-byte tag). Movements mode takes payloads up to 1,040,384 bytes (8,192 movements) in a version-7 blob with a 72-byte header. There is no streaming API. Associated data is authenticated — bound into the SIV nonce, the HMAC-U commitment, and the tag or coda, with an unambiguous length prefix — but is not stored in the blob, so the same AD must be supplied on decrypt. Minimum single-block overhead is 101 bytes (228 − 127).

Default `decrypt()` / `decrypt_movements()` accept only the current committing formats (v6/v7). Any other version raises `UnsupportedVersion`, which is a `ValueError` but **not** an `AuthError`, so an `except AuthError:` handler cannot drift into a legacy fallback. Published v2/v3 blobs open only through `decrypt_legacy()` / `decrypt_movements_legacy()` with `allow_noncommitting=True`; those helpers are not key-committing, refuse without the flag, and emit `LegacyFormatWarning` on every call. Since conductor-polish that warning is a `UserWarning`, so Python's default filters show it even when a library module (not `__main__`) makes the call. The private bodies behind those helpers (`_decrypt_legacy_v2/_v3`, `Etude._decrypt_legacy_block/_movements`) check the flag, emit the warning and pin the version byte themselves, so calling them directly is gated the same way. Unpublished v4/v5 blobs are rejected. Commitment, tag, cadence and coda failures all raise `AuthError("authentication failed")`, so the error type does not distinguish a wrong key from wrong associated data. Offline seed confirmation is possible whenever the AD is known (same as for the tag).

Études (`etudes.py`, lab only) run under their own derived key (`StaffSponge(b"E", seed, rounds‖0…)`), hash their version byte into the SIV nonce, and open only blobs of their own round count, so an étude handle can no longer decrypt or share round material with a live blob.

Guessable seeds (all zeros, all `FF`, integer `1`, or fewer than 32 distinct nonzero bytes) are rejected. A broken or repeating OS generator cannot force two in-process encryptions to share a pickup.

## Reject classes and legacy fallback (conductor-polish)

Every reject a decrypt API raises for a bad or foreign blob is a `Rejected` (a `ValueError`): `AuthError` (authentication, length, prefix, movement count, SIV mismatch), `DecodeError` (valid tag, malformed block) and `UnsupportedVersion` (a format this API does not speak, including an étude round-count mismatch). Write `except Rejected:` to mean "this blob was not accepted". `AuthError` and `UnsupportedVersion` remain disjoint. Caller mistakes stay plain `TypeError` / `ValueError` (wrong argument types, a weak seed, a missing `allow_noncommitting=True`).

Do **not** build a legacy fallback as `except UnsupportedVersion: decrypt_legacy(...)`. The first byte is attacker-chosen, so that turns the non-committing downgrade into an attacker-selectable path. If an application must still read octavo009 blobs, use an explicit **allowlist** (for example the SHA-256 of each known legacy blob, or a stored per-record "legacy" flag set when it was written) and a hard **cutoff** date after which the fallback is deleted.

**Legacy end date.** `decrypt_legacy()`, `decrypt_movements_legacy()` and the legacy étude helpers (`Etude.decrypt_legacy` / `decrypt_movements_legacy`, bytes `0xE*`/`0xF*`) are deprecated. The legacy étude helpers will be removed in the first revision after the octavo010 freeze that touches `etudes.py`, and no later than 2027-03-01; the octavo009 étude score then opens only from the frozen octavo009 tree. `etude_key(seed, r)` is the deliberate, documented ungated low-level path (no demo-seed check); `Etude.lab_seed` is read-only after the handle is made.
