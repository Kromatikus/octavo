# Octavo seed policy (octavo CLI)

```
A key is a 1024-bit seed: 128 bytes, stored as 256 hex digits in a 0600 file
(the same file format as Python sneak_n2.save_seed / load_seed).

1. `octavo keygen` draws the seed once from the OS CSPRNG (getrandom). It never
   redraws: if the draw fails the weak-seed rule, keygen stops with an error
   (the RNG or the policy is broken). This is the real protection.
2. Every seed the CLI reads (keygen output or a user-supplied key file) must
   pass the weak-seed rule, a port of Python _weak_seed_reason. It refuses:
   fewer than 32 distinct nonzero bytes (all-same or few-valued seeds); any byte
   value more than 11 times (zero padding, text); Hamming weight outside
   384..640 of 1024; all printable ASCII (a password or hex text); all bytes
   below 0x80; more than 13 equal bytes at any distance 1..64 (repeats); more
   than 13 equal differences (mod 256 or XOR) at distance 1,2,3,4,8,16,32,64
   (counters, arithmetic sequences); a rising or falling run of 16; and 16
   listed public constants (pi, e, SHA/AES/SM4 tables ...).
3. No passphrases. There is no option to turn a password into a key: a
   passphrase-derived seed would need a slow, memory-hard KDF (e.g. Argon2id),
   which this tool does not have, and a passphrase typed as the seed itself is
   printable text, which rule 2 refuses.
4. Key files: at most 16384 bytes, UTF-8, only hex digits and whitespace,
   exactly 256 hex digits; a symlink or a non-regular file is refused; a file
   readable or writable by group/others gets a warning (chmod 600).
5. The PUBLIC demo seed (sneak1024-seed.txt) passes rule 2 but is public:
   `seal` refuses it unless --allow-demo-seed; `open` and `hear` warn.

The rule is a sanity check against guessable STRUCTURE, not an entropy test.
Many guessable seeds still pass it (hashed passwords, seeded PRNG output, a
flipped byte of a public seed). Never derive a key from anything someone else
could guess. Octavo is still homemade; for real secrets use AES-GCM-SIV, age,
or libsodium.
```

Source: `crates/octavo-cli/src/policy.rs` (a port of Python `_weak_seed_reason`; the test `weak_seed_rule_matches_python` checks identical verdicts and reason text on 298 seeds). Also printed by `octavo policy`.
