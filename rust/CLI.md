# `octavo` command-line tool (phase 4)

**Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.**

Built on the Rust port (`crates/octavo-core`, copied from `/workspace/octavo_rust_port`, which is
untouched). Local only; nothing pushed.

```
export PATH=$HOME/.cargo/bin:$PATH
cargo build --release -p octavo-cli          # -> target/release/octavo  (feature `parallel` on by default)
```

## Commands

| Command | What it does |
|---|---|
| `octavo keygen -o KEY` | 128 bytes from the OS CSPRNG (getrandom), one draw, checked by the weak-seed rule (never redrawn), written as 256 hex digits + newline to a NEW file, mode 0600, via an anonymous O_TMPFILE that is fsync'd and then linked (never clobbers; a crash leaves nothing). Same format as Python `save_seed`/`load_seed`. The key is never printed. |
| `octavo check-key -k KEY` | Loads the key file and runs the policy. Prints ok / the refusal reason, never the key. |
| `octavo seal -k KEY [IN] [-o OUT] [--ad TEXT\|--ad-hex HEX] [--chunk-size N] [-j THREADS] [-f]` | v9 rehearsal stream, byte-compatible with `sneak_n2.encrypt_rehearsal_file`. Fresh pickup and nonce like Python (`SHA-256(prefix ‖ urandom ‖ time ‖ counter ‖ pid)[:16]`). Streams: memory is bounded (≈16 MiB of chunk buffers by default) whatever the file size. `IN`/`OUT` default to stdin/stdout (`-` too); refuses to write ciphertext to a terminal. |
| `octavo open -k KEY [IN] [-o OUT] [--ad ...] [-j THREADS] [-f] [--stream-verified-prefix]` | Verifies and decrypts. Each chunk's tag (and the tag chain) is checked before that chunk is decrypted; output becomes visible ONLY after the whole stream verified: a file OUT is written through a private 0600 O_TMPFILE and linked/renamed into place at the end; stdout is spooled through a private anonymous temp file in `$TMPDIR` and copied out at the end. `--stream-verified-prefix` writes verified chunks straight to stdout instead (on a reject, discard what you got). |
| `octavo hear -k KEY [--wav FILE] [--midi FILE [--program N]] [--sid FILE] [--sid-wav FILE] [-f]` | The "key earworm": 16 notes (C-major pentatonic, two octaves) derived one-way from the key (`SHA-256("Octavo earworm v1" ‖ key_sig)`), printed as note names. `--wav` also writes a small WAV; `--midi` also writes a standard MIDI file (format 0, one track, channel 1, 120 bpm, 480 ticks per quarter) with the same 16 notes, pitches, order and lengths as the note names (a trailing `-` = two eighths), played on General MIDI program `--program` (0..=127, default 0 = Acoustic Grand Piano). `--sid` / `--sid-wav`: Commodore 64 SID versions of the same tune (see *C64 SID earworm* below). All output files are written mode 0600 via a private temp file and refuse to overwrite an existing file unless `--force`/`-f` (then replaced atomically). The tune identifies a key by ear; it is not the key and does not reveal it. Same key, same bytes. |
| `octavo policy` | Prints the weak-seed policy (also in `SEED_POLICY.md`). |

`--help` (top level and every subcommand) shows the homemade warning; the first run also prints it
once (marker file in `$OCTAVO_HOME`, else `$XDG_CONFIG_HOME/octavo`, else `~/.config/octavo`).

Other safety behaviour: an existing output is refused unless `--force` (then replaced atomically; a
failed open keeps the old file); input and output being the same file is refused; key files that
are symlinks or not regular files are refused, group/other-readable ones warn; the PUBLIC demo seed
is refused by `seal` unless `--allow-demo-seed`.

Exit codes: 0 ok; 1 rejected or failed (weak/malformed key, auth/format error, I/O); 2 usage error.

## C64 SID earworm (`--sid`, `--sid-wav`)

`octavo hear -k KEY --sid tune.sid` writes a **PSID v2** file (124-byte header; one song; VBI speed;
flags PAL + MOS6581; `loadAddress` 0 with the real load address `$1000` in the first two data bytes;
init `$1000`, play `$1003`). The C64 code is a small 6502 player written for Octavo and assembled by a
tiny assembler in `crates/octavo-cli/src/sid.rs` (no third-party C64 code). Verified to load and
play in sidplayfp 2.12 (Debian package); VICE's `vsid` and real hardware were not tried.

- **Voice 1, melody:** pulse wave (50 %), the 16 earworm notes in the same order and lengths as the
  printed note names. ADSR A0 D9 S10 R6.
- **Voice 2, bass:** sawtooth, from the melody only: in each group of 4 steps the group's first note,
  two octaves down on even steps and one octave down on odd steps. ADSR A0 D8 S9 R4.
- **Voice 3, arpeggio:** pulse (25 %), a new note every frame (50 Hz), cycling the pitch classes of
  melody notes i, i+1, i+2 placed in the C5 octave. ADSR A0 D0 S7 R0.
- PAL timing: play is called once per 50 Hz frame; 12 frames per eighth (0.24 s, ~125 bpm; the WAV /
  MIDI outputs use 0.25 s); each step's gate is released for its last 2 frames so notes re-attack.
  After the 16th note the tune loops forever. Frequencies are `f * 2^24 / 985248` (PAL clock).
- The bass and arpeggio are derived only from the 16 notes, never from the key directly, so the
  `.sid` reveals nothing beyond the (already printed) note names.

`--sid-wav tune.wav` renders two passes of that same player (~10 s, 16-bit mono 44.1 kHz, short
fade-out) by running the `.sid`'s 6502 code on a small built-in 6502 core and feeding its SID register
writes, once per PAL frame, to a pure-Rust SID-style synth: three 24-bit phase accumulators
(pulse/saw/triangle/noise, combined waveforms ANDed, ring-mod bit honoured), the SID's ADSR rate
periods with its piecewise-exponential decay/release, master volume, and a one-pole ~12 kHz low-pass
plus 20 Hz DC block standing in for the 6581 output stage. No filter emulation (the player never uses
the filter), no 6581 combined-waveform tables, no ADSR delay bug: it sounds roughly like a 6581, not
exactly. For an accurate render use `sidplayfp -w out.wav tune.sid` (reSIDfp).

Checks: `tests/hear_sid.rs` parses the PSID header strictly, runs init + two passes of play calls on an
independent 6502 emulator written for the test (`tests/common/mos6502.rs`, official opcodes), and checks
voice 1's note-on frequencies and frame positions against the printed note names, the bass and
arpeggio rules, gate timing, determinism per key, WAV structure, 0600 and no-overwrite; it also checks
that the built-in core produces exactly the same register writes. If `sidplayfp` is installed, it renders
the file and `tools/check_sid_render.py` confirms the melody is a clear spectral peak in every step of
both renders (two passes, so the loop too) and that they match spectrally. Samples from the PUBLIC demo
seed (never a real key): `samples/demo_seed_earworm.sid`, `samples/demo_seed_earworm_sid.wav`.

## Secrets in memory

Seeds, key-file text and plaintext batch buffers are `Zeroizing`; chunk keys, MAC keys and the
commitment key are wiped after use; the key schedule, the GFNI/AES-NI/SIMD round tables and the
format `Ctx` keys are wiped on drop (core feature `zeroize`, `src/wipe.rs`, volatile writes).
Best effort only: copies the compiler made (moves, registers, spills), the stdio buffers, the page
cache, and swap are out of reach. The spooled plaintext temp file is truncated on failure, but the
filesystem may keep old blocks.

## What changed in the core copy (additive; no cipher or format change)

- `Cargo.toml`: features `zeroize` and `stream`.
- `src/wipe.rs`, plus `Drop` for `Schedule`, `SimdKey`, `HwBackend`, `Ctx` (all under `zeroize`).
- `src/stream.rs` (`formats::stream`): `seal_stream` / `open_stream` over `std::io::{Read, Write}`,
  batched, multithreaded with `parallel`; bytes identical to `seal_rehearsal` for any thread count.

## Tests

See `PROGRESS.md` for counts. Re-run: `cargo test --release --workspace --all-features`
(Python cross-compat needs `/workspace/sneak_n2/sneak_n2.py` at SHA 19181bc1…e71eee; it is imported
read-only with `python3 -B` / `PYTHONDONTWRITEBYTECODE=1`). Timed fuzz:
`OCTAVO_FUZZ_SECS=180 cargo test --release -p octavo-cli --test fuzz_open -- --ignored --nocapture`.
Throughput: `tools/bench_cli.sh 256`.

## Limits

- Octavo itself: homemade, ~9–10 of 16 rounds of in-house margin, one non-expert outside review, no proof.
- Only v9 rehearsal files. v6 single-block / v7 movements messages, legacy formats, étude modes and
  the app HKDF are not exposed in the CLI (the core library has them).
- No passphrase mode (would need Argon2id or similar). No public-key / recipient mode (use age).
- Open streams: a forged or truncated FINAL chunk is only found at the end of the stream, which is
  why output is held back until then (file temp / stdout spool), costing temporary disk space equal
  to the plaintext. With `--stream-verified-prefix` the caller must discard output on error.
- Error kinds can differ from the whole-buffer `open_rehearsal` for malformed input (e.g. a short
  blob with a valid header is `Format` in both, but a short blob under the wrong key is `Auth` here,
  `Format` there); both reject.
- Key schedule is not constant time (same as Python). Constant-time behaviour of the whole tool has
  not been measured here (separate dudect job).
- x86-64 Linux tested only (O_TMPFILE / linkat via /proc; a named 0600 dot-temp fallback exists).
- Decrypt is ~2x slower than encrypt (inverse layers; separate speed job).
