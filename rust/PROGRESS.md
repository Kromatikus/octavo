# octavo_merged: progress

**Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.**

Started 2026-11-22 ~9:50 AM ET. Local only: local git repo, no remote, nothing pushed.
Sources (read-only, untouched): /workspace/octavo_decrypt_speed (core base), /workspace/octavo_cli (CLI crate +
zeroize/stream additions), /workspace/octavo_dudect (timing harness).

## Steps
- [x] 1. New tree: decrypt_speed core (no target/, no baseline/ A/B copy) + octavo-cli crate + CLI's wipe.rs/stream.rs,
      workspace has both crates. Old PROGRESS/README files kept under docs/.
- [x] 2. Ported zeroize (Schedule, SimdKey, HwBackend, Ctx) and the stream feature. New: the sha_mb sponge template
      (holds the seed) and its heap copies are wiped too under `zeroize`. Release build of the workspace OK.
- [x] 3. Streaming fast paths (src/stream.rs):
      seal: workers encrypt chunks round-robin and hand them back in order (mpsc), the HMAC tag chain and the
      writes run on the calling thread while later chunks are still encrypting; write errors are reported.
      open: each batch is read raw (ct+tag, 1 look-ahead byte) into an arena, the ciphertexts are copied into a
      private Zeroizing buffer; with threads > 1, threads-1 workers decrypt that buffer WHILE the calling thread
      walks the tag chain over the raw bytes; on any mismatch the buffer is wiped and Err(Auth) is returned and
      nothing from that batch is written. threads = 1: verify the batch, then decrypt. Keystream = sha_mb
      multi-buffer sponge (automatic via reh_keys -> sponge). CLI still publishes files / stdout only after Ok.
- [x] 4. New test crates/octavo-cli/tests/overlap.rs: forged chunk k (ct or tag) for 8 thread/batch combos x 13
      chunks x 2 = 208 cases -> Auth, and output == exactly the verified earlier batches; seal write errors
      surface as Io for 1/2/8 threads.
- [x] 5. Core feature `dudect-hooks` (off by default): simd::dudect_hooks (vrot chains xmm/zmm, bow/unbow
      layers xmm/zmm) for the timing harness only.
- [x] 6. Verify (9:57-10:03 AM ET): tools/run_all.sh -> exit 0 (logs/run_all.log, not committed):
      all 6 backends 79/79 (block 16 + formats 63) + app 6/6 + samples 3/3; Python->Rust 74/74 each;
      Rust->Python 21/21 each + default 21/21. Workspace tests: core 21 passed (1 ignored), CLI 25 passed
      (1 ignored = timed fuzz) incl. python_compat 2/2 (python3 -B; no new __pycache__ anywhere in /workspace).
      Feature builds: core no-features, alloc, zeroize, formats, formats+zeroize, std, parallel, stream,
      stream+parallel, dudect-hooks, table-backend, default; CLI without parallel; workspace all-features
      release; check --all-targets: all clean (0 warnings).
      Fix: `table-backend` alone did not compile (needs alloc; same in the source tree) -> table-backend = ["alloc"].
      Fuzz 120 s: 1,420,000 cases (710k mutated streams + 710k random inputs), 0 panics, 0 forgeries.
      sneak_n2.py SHA unchanged.
- [x] 7. Commit 1 (10:04 AM ET): b23e06b, merged core + CLI (code only, local repo, no remote).
- [x] 8. Dudect (10:04-10:34 AM ET), see dudect/REPORT.md: 66 main cases (6 backends x enc/dec pt+key, 8-block
      batches, v9 tag compare, streaming open + tag compare; gfni-simd VPSLLVW and bow micro tests; 2-thread
      streaming; expected schedule/tamper cases) + reruns, A/A controls and 4x-work checks. VPSLLVW rotation and
      bow layers: no evidence of a leak in the final (matched-memory) design. Data path, tag compares and
      streaming open: no evidence on any backend. Only flags: gfni-simd many-key cache effect (known), key
      schedule and valid-vs-tampered (expected). First-design micro-test flags explained in the report.
- [x] 9. Added scope from OHLO (10:30 AM ET): `octavo hear --midi FILE [--program N] [-f]`: standard MIDI file,
      format 0, one track, channel 1, 120 bpm, 480 PPQ, GM program 0 (piano) by default; same 16 notes, pitches,
      order and lengths as the note names. --wav and --midi now both write mode 0600 through a private temp file
      and refuse to overwrite without --force (then atomic replace). New tests/hear_midi.rs (3 tests: strict
      SMF parse of header+track, notes == note-name output for 4 keys, 0600; deterministic per key, other key
      differs, --program 40 changes only the instrument, 128 refused; overwrite refused without --force for
      both --midi and --wav). `file` identifies the output as "Standard MIDI data (format 0) using 1 track".
      CLI.md updated.
- [x] 10. Final test run (10:36 AM ET): core 21 passed (1 ignored), CLI 28 passed (1 ignored = timed fuzz);
      check --all-targets and CLI no-default build clean; no new __pycache__; sneak_n2.py SHA unchanged.
- [x] 11. CLI throughput (tools/bench_cli_rep.sh 256 3 1 8; 256 MiB file -> file incl. fsync; logs/bench_cli.log):
      1 thread: seal 92-99 MB/s, open 88-96 MB/s; 8 threads: seal 369-415 MB/s, open 332-348 MB/s
      (was 33/18 and 117/80 in octavo_cli). Library v9 (in memory, 4 MiB): 105/101 MB/s 1T, 548/514 MB/s 8T.
      The CLI's 8-thread gap: reading, the per-batch barrier and the file write are not yet pipelined.

## octavo_sid: C64 SID output for the key earworm (started 2026-11-22 10:45 AM ET)
Copy of /workspace/octavo_merged at 7378360 (`cp -a`); the source tree is not touched. Local commits only.
- [ ] 1. `octavo hear --sid FILE`: PSID v2, own 6502 player assembled by a tiny in-crate assembler (src/sid.rs).
- [ ] 2. `octavo hear --sid-wav FILE`: the same player run on an in-crate 6502 core, register writes fed to a
      small pure-Rust SID-style synth (3 oscillators, ADSR, no filter).
- [ ] 3. Tests (tests/hear_sid.rs): PSID header, independent 6502 emulator in the test, voice 1 notes, determinism, WAV.
- [ ] 4. sidplayfp from apt (Debian trixie 2.12.0-1) to verify.
- [ ] 5. CLI.md, samples/, full test rerun + run_all on gfni-simd and ct-soft, commit.
