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
- **Movements: timing reveals which stage failed (accepted, documented).** `decrypt_movements()` still checks the commitment first, so a wrong key never walks a large body (the denial-of-service property the commitment exists for). A commitment failure (about 8 µs) is therefore faster than a coda or cadence failure (about 26 µs plus body hashing, growing with `nmov`). The exception type and message are identical, but timing reveals whether a blob's header matches this receiver's key and AD. A receiver that already reveals accept/reject leaks nothing extra.
- **Padding check is constant-structure (L4).** `_unpad_block` visits all 127 payload bytes with the same masked operations whatever the length byte says, then cuts a fixed 127-byte copy. The old `any(b[1+L:])` scan took time proportional to `127 - L`.
- **Seed check and default seed are cached (I3).** The default seed file is parsed once (keyed by path, mtime and size), and a seed that passed the weak-seed rule is remembered in a small bounded set, so per-call cost no longer depends on the seed's byte distribution.
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

Default `decrypt()` / `decrypt_movements()` accept only the current committing formats (v6/v7). Any other version raises `UnsupportedVersion`, which is a `ValueError` but **not** an `AuthError`, so an `except AuthError:` handler cannot drift into a legacy fallback. Published v2/v3 blobs open only through `decrypt_legacy()` / `decrypt_movements_legacy()` with `allow_noncommitting=True`; those helpers are not key-committing, refuse without the flag, and emit `LegacyFormatWarning` (a `DeprecationWarning`) on every call. Unpublished v4/v5 blobs are rejected. Commitment, tag, cadence and coda failures all raise `AuthError("authentication failed")`, so the error type does not distinguish a wrong key from wrong associated data. Offline seed confirmation is possible whenever the AD is known (same as for the tag).

Études (`etudes.py`, lab only) run under their own derived key (`StaffSponge(b"E", seed, rounds‖0…)`), hash their version byte into the SIV nonce, and open only blobs of their own round count, so an étude handle can no longer decrypt or share round material with a live blob.

Guessable seeds (all zeros, all `FF`, integer `1`, or fewer than 32 distinct nonzero bytes) are rejected. A broken or repeating OS generator cannot force two in-process encryptions to share a pickup.
