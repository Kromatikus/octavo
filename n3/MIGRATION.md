# Migrating from live N2 to N3 (`octavo_n3_004`)

**In this repository:** N2 is still the default (`sneak_n2.py`, `octavo.py`, `rust/`). N3 lives in [`n3/`](.) and is experimental. Build the lab tool with `cd n3/rust && ~/.cargo/bin/cargo build --release --bin n3aead` (needs rustc 1.100 for the AVX-512 path; 1.85 is too old). Then:

```
python3 n3/migrate.py --n2-seed N2.seed --n3-seed N3.seed --in message.n2 --out message.n3 --ad -
```

Use a **fresh** 1024-bit N3 seed. The helper below started as a lab note; some `/workspace/...` paths refer to the machine where N3 was developed. In a clone of this repo, use the paths in this box and in `n3/README.md`.


Written 2026-11-23, about 5:10 PM ET, in `/workspace/octavo_n3_migration1`.
N2 is described from the latest frozen live snapshot `/workspace/octavo018` (rehearsal-honest2, cipher byte-identical to octavo016/017; this is the Kromatikus/octavo tree as last snapshotted). N3 is the frozen, read-only lab snapshot `/workspace/octavo_n3_004`. Neither tree was modified, and nothing was committed or pushed.

**Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.** If you are moving real secrets, stop and use one of those instead of either Octavo.

## What changes

| | Live N2 (`octavo018` / Kromatikus/octavo) | N3 (`octavo_n3_004`) |
|---|---|---|
| Block size | 128 bytes | 128 bytes |
| Master seed | 128 bytes (1024 bits), usually a 256-hex-digit file from `keygen()` / `save_seed()` | 128 bytes (1024 bits), 256 hex digits on the `n3aead` command line |
| App keys | `octavo.seal` / `open_` take a 32- or 64-byte key and expand it with HKDF-SHA512, info `b'Octavo app key v1'`, default salt, into the 128-byte seed | No app-key wrapper. `n3aead` wants the 128-byte seed itself |
| Blob magic | Version byte + `SN2` | `SN3C/` + a format byte |
| Current authenticated formats | **v6** single message (max 127 bytes, 228-byte blob, 100 bytes of overhead); **v7** movements (up to 1,040,384 bytes); **v9** rehearsal stream (header 72 bytes, then chunk ciphertext + 32-byte tag, default 64 KiB chunks) | **0x1C** N3-PMAC-SIV only. Header `SN3C/` (5) + `0x1C` (1) + nonce (16) + tag (32) + ciphertext. Overhead is **54 bytes**. Messages up to 2^30 bytes |
| Block-function format | Not a standalone blob | `SN3C/` + `0x1B` is the block cipher's domain. The 004 `n3aead` tool does **not** open fix1's old `0x1B` CMAC-S2V blobs (those stay in `/workspace/octavo_n3_fix1`) |
| How you encrypt | Python: `octavo.seal` (v6 only), or `sneak_n2.encrypt` (v6), `encrypt_movements` (v7), `encrypt_rehearsal` / `encrypt_rehearsal_file` (v9). The published package (`octavo-demo` 0.1.0) has no `console_scripts` entry point | Rust lab CLI `n3aead seal <seed_hex> <nonce_hex> <ad_hex\|->` and `n3aead open <seed_hex> <ad_hex\|->` (stdin/stdout) |
| Pickup | N2 v6/v7/v9 draw a 16-byte pickup into the blob. It is part of N2's format, not N3's | No pickup. The 16-byte nonce is stored in the 0x1C header |
| Nonce | v6/v7: SIV-style, derived from the message. v9: a fresh random per-stream nonce | You must supply a 16-byte nonce at seal time (stored in the blob). Do not reuse a nonce under the same seed |
| Backends | Python reference, plus a later local Rust port/CLI in `/workspace/octavo_merged` (not in `octavo018`, and its own CLI.md says it was not pushed) | Runtime pick: avx512gfni, avx2gfni, avx2, portable. Override with `OCTAVO_N3_BACKEND`. `table` is a non-constant-time test path and is never auto-selected |
| Constant time | Data-path work has been reviewed in-house; **key setup is not constant-time** | Key setup and the data path are written to be constant-time (short dudect on 004 was clean; that is not a proof). The `table` backend is not |
| Music / MIDI / score | Live N2 ships `etudes.py`, score version 11, `key_sig` / `rehearsal_sig`, and (in the later unpushed local CLI) `octavo hear --midi`, a 16-note earworm from `SHA-256("Octavo earworm v1" ‖ key_sig)` | **004 has none of this.** No etudes, no score, no earworm, no MIDI tool |

N3's authenticated mode **replaces** N2's v6/v7/v9 blobs and pickup. There is no combined container and no "upgrade in place."

A later local tree, `/workspace/octavo_merged`, adds a Rust `octavo` CLI (`keygen`, `seal`/`open` for **v9 only**, `hear --wav/--midi`). That CLI is not in the `octavo018` freeze and, according to its own notes, has not been pushed. If you use it, it still produces N2 v9 `SN2` streams, not N3.

## Incompatibility

**Neither side can read the other's data.** A 004 `n3aead open` of an N2 blob fails. An N2 `decrypt` / `open_` of an N3 blob fails. You have to decrypt with N2, then seal with N3.

Detect a blob by its header, before you try a key:

```
starts with  SN3C/\x1c     → N3 authenticated blob (004 / fix2 / fix3)
starts with  SN3C/\x1b     → N3 fix1 CMAC-S2V (not implemented in 004; use octavo_n3_fix1)
byte 0 = 6,  bytes 1–3 = SN2  → N2 v6 single message (228 bytes)
byte 0 = 7,  bytes 1–3 = SN2  → N2 v7 movements
byte 0 = 9,  bytes 1–3 = SN2  → N2 v9 rehearsal stream (usual long-message format)
byte 0 = 2 or 8, bytes 1–3 = SN2  → N2 legacy (v2 single block, v8 unchained rehearsal). Open with the N2 legacy helpers, then migrate
byte 0 = 4,  bytes 1–3 = SN2  → rejected unpublished N2 revision; not a migration path
```

Associated data is not stored in either family's blob. You must keep the same AD, if you used one, and pass it to N3 as well (or decide to drop it, which is a new encryption, not a translation).

## Keys: can an N2 seed be reused?

Both ciphers take a 128-byte seed. The file shape is the same (256 hex digits, optional whitespace; N2 `load_seed` / `save_seed`). The sponges are **not** the same:

- N2: `SHA-256("SN2/" ‖ domain ‖ counter32 ‖ seed ‖ nonce)`
- N3: `SHA-256("SN3C/" ‖ 0x1B ‖ domain ‖ counter32 ‖ seed ‖ nonce)`

So the same seed bytes do not produce the same round keys, and an N3 ciphertext under that seed is not an N2 ciphertext. That is domain separation in the hash, not a reason to recycle a secret.

**Use a fresh N3 seed.** Do not feed one secret to two ciphers. In particular:

- Do not reuse the **public demo seed** (`sneak1024-seed.txt` / the published score seed). N2 already warns against that.
- A 32- or 64-byte N2 **app key** is not an N3 seed. Expanding it with the same HKDF (`Octavo app key v1`) and handing the 128-byte output to `n3aead` would tie both systems to one app key. Don't do that; make a new 128-byte N3 seed (`os.urandom(128)` or N2's `keygen()`, saved as hex).
- If you only have an N2 seed file and you temporarily use those 128 bytes as the N3 seed anyway, understand that you are sharing one secret across two protocols. I recommend against it.

`n3aead` currently takes the seed as a command-line hex string, which can show up in process lists. That is a real limitation of the lab tool; 004 is frozen, so this note does not change it. Prefer a private machine, and do not run `n3aead` on a shared box with a valuable seed.

## Music, score, and MIDI

N2's published score, etudes, `key_sig`, and `rehearsal_sig` are N2-only. They will not verify an N3 tree, and 004 does not generate them.

The later local command `octavo hear --midi` sings an earworm derived from N2 `key_sig`. A new N3 seed has no `key_sig` and no earworm in 004. Even if you reused the 128 N2 seed bytes in N3, the N2 tune still comes from N2's signature sponge, not from N3. Migrating means that music-side output does not come along.

The live repository now ships a separate presentation tool, `n3/python/n3_music.py`, which derives a WAV/MIDI/SID earworm from a sealed 0x1C blob using the N2 renderer. That is display only: it is not in the 004 freeze, and it does not migrate N2 scores or change any N3 ciphertext.

## Security comparison (in-house, not a proof)

| | Live N2 (`octavo018`) | N3 (`octavo_n3_004`) |
|---|---|---|
| Rounds / block | 16 rounds, 128-byte block | 16 rounds, 128-byte block |
| Trail bound | In-house trail search; the repo describes about 9–10 of 16 rounds of margin in that model | 18 S-boxes in one standalone round, 35 over two (merged S2·S), about 17 per round in a chain, roughly 2^{-100} per round in that model |
| Best practical attack reach (in-house) | No full 16-round break after many design rounds; the latest published round-function report is `attacks_octavo_beat6` | No full 16-round break. Best distinguisher: **5 of 9 layers of round 1** (integral, 2^{24}). The old 1-round impossible differential is gone. Report: `/workspace/attacks_octavo_n3_004` |
| Constant-time key setup | No | Yes, as written (short dudect clean; not a proof) |
| Authenticated mode | Homemade v6 / v7 / v9 (SIV-style v6/v7; v9 is a chained stream) | Homemade N3-PMAC-SIV (0x1C). Nonce reuse is designed to reveal only whether two (AD, nonce, message) triples were identical, assuming N3 is a strong PRP, which is not proven |
| External review | One independent review of the **round function** (not the later outer layer), plus extensive in-house work | **None.** Only in-house attacks |

## What is not done

- No outside review of N3.
- No related-key trail proof for N3.
- N3 is not in the GitHub repo. Pushing it needs a separate, explicit OK.
- 004 has no packaged `octavo-demo` equivalent, no app-key HKDF, no Python install, no MIDI/score.
- `n3aead` is a lab CLI (seed on the command line, hex only, 0x1C only).
- N2 and N3 still should not be used for real secrets.

## Step-by-step re-encryption

Do this on a quiet, private machine. Keep the N2 originals until you have opened a sample of the new N3 blobs.

1. **Inventory.** For each file, read the first bytes and classify it with the table above. Skip anything that is already `SN3C/`. Set aside v2/v8 legacy: open those with N2's legacy helpers (`decrypt_legacy`, `decrypt_rehearsal_legacy(..., allow_unchained=True)`) and treat the plaintext like any other.
2. **Make a new N3 seed.** 128 random bytes, written as 256 lowercase hex digits in a new file, mode 0600. Do not use the public demo seed. Keep the N2 key file as well until you are done.
3. **Decrypt with N2.** Use the matching function: `sneak_n2.decrypt` (v6), `decrypt_movements` (v7), or `decrypt_rehearsal` / `decrypt_rehearsal_file` (v9). If you used `octavo.seal`, you must pass the same 32- or 64-byte app key into `octavo.open_`, not the expanded seed, unless you expanded it yourself the same way. Pass the same associated data you used when sealing. Write the plaintext to a private temporary file, mode 0600, not in a shared directory.
4. **Verify the N2 open.** The N2 function has already checked the tag. Optionally decrypt a second time, or for a v6/v7 blob seal a fresh N2 copy and check that it opens to the same message (the blob will differ because the pickup is fresh).
5. **Encrypt with N3.** Draw a fresh 16-byte nonce. Run `n3aead seal <n3_seed_hex> <nonce_hex> <ad_hex or -> < plaintext > blob`. Empty AD is `-`. Build the tool from 004 (`~/.cargo/bin/cargo build --release --bin n3aead` in a writable copy of `octavo_n3_004/rust`; rustc 1.100). The 0x1C blob already contains the nonce, so you do not need a separate nonce file to open it.
6. **Verify the N3 round-trip.** `n3aead open <n3_seed_hex> <ad_hex or -> < blob > roundtrip` and compare the output to the plaintext (`cmp`). They must match exactly.
7. **Only then** consider deleting intermediates. Delete the plaintext temps first. `rm` is not a secure wipe; on this Linux box `shred -u` is the usual attempt, and it is still not a guarantee (SSDs, snapshots, backups). When you are satisfied that the N3 blobs open, you can retire the N2 ciphertexts the same way if you no longer need them. Keep the N2 key until you are sure you will not need the old blobs.

A small helper that does steps 3–6 for one file lives in this folder: `migrate.py` (wrapper `migrate.sh`). It writes into an output path you name. It does not delete the N2 blob unless you pass `--shred-plain` (plaintext only) and it will not shred anything outside this folder's sample runs unless you point it there yourself.

## Helper

```
PYTHONDONTWRITEBYTECODE=1 python3 /workspace/octavo_n3_migration1/migrate.py \
  --n2-seed samples/n2.seed --n3-seed samples/n3.seed \
  --in samples/hello.n2 --out samples/hello.n3 --ad -
```

It detects v6, v7 and v9, decrypts with `/workspace/octavo018` (read-only), seals with `n3aead`, and opens the result back for comparison. See `samples/README.txt`.

## Draft repo notes (not applied)

`draft/README_snippet.md` and `draft/CHANGELOG_snippet.md` are short texts you could paste into the GitHub repo **if** you later decide to publish N3. They are not committed. N3 is not in the repo today. Do not push them without a separate OK.

Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.
