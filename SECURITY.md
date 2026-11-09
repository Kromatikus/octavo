# Security

Octavo is an experimental, homemade cipher made for learning and for fun. It is not constant-time, and nothing here is a proof of security. An independent reviewer ([@liqdmetal](https://github.com/liqdmetal), [issue #1](https://github.com/Kromatikus/octavo/issues/1)) rebuilt the round function and reported no distinguisher, forgery or key recovery; that is a negative experimental result, not expert cryptanalysis and not a proof.

**Do not use Octavo to protect real data.** Use a vetted, well-reviewed tool such as AES-GCM-SIV (RFC 8452), [age](https://age-encryption.org), or [libsodium](https://doc.libsodium.org).

Found a weakness? That's the point of publishing it. Please open an issue with a description and, ideally, a script that reproduces it. Credible findings get added to [ATTACKS.md](ATTACKS.md) with credit.


## Timing side channels (Info 7)

Octavo is not constant-time. The 16-round function looks up keyed 256-entry S-box tables and uses data-dependent rotations in the bow-pressure layer (`r1` and `r2` are computed from a pressure byte). Those operations can leak through cache timing and other microarchitectural side channels.

Pure Python cannot offer a meaningful constant-time implementation: even a bitsliced or masked rewrite would still run in CPython. Closing this would mean a new implementation in a systems language, which is out of scope. The HMAC tag comparison uses `hmac.compare_digest`; that is the only deliberate constant-time step.

## Format limits (Info 8)

A message is a single 127-byte block. There is no multi-block mode and no streaming API. Associated data is authenticated (bound into the SIV nonce and the HMAC with an unambiguous length prefix) but is not stored in the 196-byte blob, so the same AD must be supplied on decrypt. Minimum overhead is 69 bytes (196 − 127).

Guessable seeds (all zeros, all `FF`, integer `1`, or fewer than 32 distinct nonzero bytes) are rejected. A broken or repeating OS generator cannot force two in-process encryptions to share a pickup.
