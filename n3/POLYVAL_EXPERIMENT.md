# EXPERIMENTAL: N3 POLYVAL-SIV (lab format 0x1E)

Lab only. A homemade composition. For real secrets use AES-GCM-SIV, age, or libsodium.
The 0x1C AEAD and SN3F format are unchanged; this lives in `rust/src/aead_pv.rs`, CLI `n3aeadpv`,
bench `n3pvbench`, timing harness `n3dudect_pv` (lab feature). Design text is in the module docs of `aead_pv.rs`.

## Format history
- **0x1D** (unreleased, `/workspace/octavo_n3_polyval1`): first POLYVAL-SIV cut. CTR counter block was
  `tag(32) || "SN3V/CTR" || 0^80 || u64le(i)`. Because the CTR key is per master key and the IV was
  only the tag (a function of a 128-bit hash), a tag collision *across different nonces* would reuse
  a keystream. That cut was never pushed and is rejected as `BadFormat`.
- **0x1E** (this revision): same POLYVAL-SIV construction, but each counter block is
  `tag(32) || "SN3V/CTR" || nonce(16) || 0^64 || u64le(i)`. A tag collision across nonces no longer
  reuses a keystream. Keys, domain labels, and the 0x1E format byte in the KDF make 0x1E blobs
  distinct from 0x1D. Output is not compatible with 0x1D.

## Shape (RFC 8452 pattern)
Per-nonce POLYVAL key = N3 block-cipher output; S = POLYVAL(pad AD || pad M || lengths) ^ nonce;
tag/SIV = N3(S in a domain-separated 1024-bit block)[0..32]; CTR from (tag, nonce). One full cipher
pass per seal (the CTR), instead of two (PMAC + CTR). POLYVAL comes from the RustCrypto `polyval`
crate (built with its `zeroize` feature); large messages hash in parallel segments recombined with
powers of the key (bit-identical to the sequential hash, tested).

## Collision / misuse bounds (0x1E)
- **Forgery**, fixed (key, nonce): about L/2^128 per attempt (L = POLYVAL blocks of AD+M+length), same
  shape as AES-GCM-SIV. The 32-byte tag is a 128-bit hash expanded, not 256-bit security.
- **Nonce reuse**: identical (AD, M) under the same nonce produce an identical blob (the only leak
  of a SIV). Distinct messages under one nonce have unrelated tags and keystreams unless their
  POLYVAL^nonce values collide.
- **Same-nonce tag collision** (two different messages, one nonce, colliding S): still shares a
  keystream and leaks m1^m2. Per-nonce birthday bound about q_n^2 * L / 2^129. After 2^40 messages
  under one nonce this is about 2^-49; it reaches 1/2 near 2^64 messages under that nonce. Normal
  use is nowhere near that. A per-nonce encryption key (as in RFC 8452) would close this too, but
  costs an N3 key setup (~1.5 ms) per message.
- **Cross-nonce tag collision**: tags may still collide (birthday on the 128-bit S^nonce, across the
  whole master key). In 0x1D that reused a keystream. In 0x1E the nonce is inside every counter
  block, so the keystreams are distinct and the collision does not leak m1^m2.

## Zeroization (this revision)
`polyval` is built with `zeroize`. Per-segment POLYVAL sums, the derived POLYVAL key, and the
full 128-byte tag-cipher block are wiped after use. `Cipher`, `Aead` (0x1C), and `AeadPv` (0x1E)
implement `zeroize::Zeroize` and wipe expanded key material on Drop. Encrypt/decrypt output is
unchanged.

Needs its own attack round on 0x1E before any trust (0x1D was attacked; this is the fix plus a
new format byte).
