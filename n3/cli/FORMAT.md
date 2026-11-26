# SN3F v1 — n3file streaming container

**Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.**

SN3F is a chunked, online (STREAM-style) file format. The cipher is the N3 0x1C AEAD (PMAC-SIV
over the 1024-bit N3 block cipher), used **unchanged** as a primitive. The 0x1C single-blob format
and its vectors are untouched.

## Layout

```
header (26 bytes):  "SN3F/" (5) | version 0x01 (1) | chunk_size u32le (4) | file_nonce (16)
record 0:           tag (32) | ct (chunk_size bytes)
record 1:           tag (32) | ct (chunk_size bytes)
...
record n-1 (final): tag (32) | ct (1..=chunk_size bytes; 0 bytes only for an empty file)
```

* `chunk_size` is a multiple of 128 in 128..=1048576 (default 65536). Overhead: 26 + 32 per chunk.
* `file_nonce` is 16 bytes drawn once from the OS CSPRNG (getrandom) per seal. A hidden test-only flag
  (`--test-file-nonce`) fixes it so tests can compare bytes.
* Each record is the 0x1C blob `"SN3C/" | 0x1C | nonce_i | tag | ct` with the 22-byte prefix left
  out. The reader rebuilds the prefix from `nonce_i`.
* The reader decides which record is final by length: a short record, or a full record followed
  by EOF, is the final one. A file whose size is an exact multiple of `chunk_size` has no empty
  tail chunk.

## Per-chunk nonce and AD

```
H      = the 26 header bytes
nonce_i = SHA-256("SN3F/nonce" | H | u64le(i) | final_i)[0..16]
ad_i    = "SN3F/ad" | H | SHA-256(user_ad) | u64le(i) | final_i        (74 bytes)
record_i = 0x1C-seal(key, nonce_i, ad_i, chunk_i) without its 22-byte prefix
```

`final_i` is 1 for the last chunk and 0 for every other chunk. Every chunk's tag covers the whole
header (magic, version, chunk size, file nonce), the user AD, its own index, and whether it is final:

| attack                                 | why it fails                                             |
|----------------------------------------|----------------------------------------------------------|
| edit header (any byte)                 | magic/version/size parse check, or every ad_i/nonce_i changes |
| edit a chunk byte or tag               | PMAC-SIV tag check                                       |
| reorder / duplicate / drop a mid chunk | index i is in nonce_i and ad_i                           |
| drop the tail / truncate at a boundary | the new last chunk was sealed with final=0               |
| truncate mid-record                    | the short record is now read as final, so its index/flag/tag no longer match |
| append anything                        | the real final chunk is now read with final=0            |
| splice a chunk from another file       | file_nonce (in H) differs                                |
| wrong key / wrong AD                   | tag check on chunk 0                                     |

SIV means that if a file nonce ever repeats, the only leak is whether two equal chunks (same key,
same AD, same index and final flag) are equal.

## Opening

Chunks verify in parallel batches. Each plaintext goes into a private 0600 temporary file in the
output directory (O_TMPFILE, or a dot-named file as a fallback). The temp file is published with
an atomic link/rename only after every chunk **and** the final flag verify. On any failure it is
wiped and removed, nothing is written, and the exit code is 1. You can write to stdout only with
`-o - --stdout-unverified-tail`. The tool warns that a verified prefix may already be out by the
time a later chunk fails.

Memory is bounded at about 2 × threads × 4 × chunk_size, independent of file size. Output bytes do
not depend on `-j`.
