# EXPERIMENTAL: N3 POLYVAL-SIV (lab format 0x1D)

Lab only. A homemade composition that has not been attacked. For real secrets use AES-GCM-SIV, age, or libsodium.
The 0x1C AEAD and SN3F format are unchanged; 0x1D lives in `rust/src/aead_pv.rs`, CLI `n3aeadpv`,
bench `n3pvbench`, timing harness `n3dudect_pv` (lab feature). Design text is in the module docs of `aead_pv.rs`.

Shape (RFC 8452 pattern): per-nonce POLYVAL key = N3 block cipher output; S = POLYVAL(pad AD || pad M || lengths) ^ nonce;
tag/SIV = N3(S in a domain-separated 1024-bit block)[0..32]; CTR from the tag. One full cipher pass per seal (the CTR),
instead of two (PMAC + CTR). POLYVAL comes from the RustCrypto `polyval` crate; large messages hash in parallel segments
recombined with powers of the key (bit-identical to the sequential hash, tested).

Caveats: ~128-bit forgery bound (hash output is 128 bits, the 32-byte tag is not 256-bit security); a POLYVAL collision under a
repeated nonce would reuse a keystream; no per-nonce encryption key (cost); needs its own attack round before any trust.
