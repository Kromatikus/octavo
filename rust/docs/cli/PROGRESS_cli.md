# octavo_cli: progress (phase 4, command-line tool)

**Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.**

Folder made 2026-11-22 by `cp -a /workspace/octavo_rust_port /workspace/octavo_cli` (the original is untouched).
The port's own progress log was renamed to `PROGRESS_port_phase1-3.md` in this copy.
Local only: no git, no remote, nothing pushed.

## Steps
- [x] 1. Copy port to new folder.
- [x] 2. Core copy (additive only, no cipher/format change): feature `zeroize` (wipe Schedule, SIMD/GFNI/AES-NI
      tables and `Ctx` keys on drop, `src/wipe.rs`) and feature `stream` (`src/stream.rs`: constant-memory
      v9 `seal_stream` / `open_stream` over `std::io`, batched + threaded under `parallel`).
- [x] 3. CLI crate `crates/octavo-cli`, binary `octavo`: keygen, check-key, seal, open, hear, policy. Smoke test OK
      (300 kB file round trip, pipe round trip, 0600 key).
- [x] 4. Tests: stream (vectors + stream==buffer), tamper (exhaustive flips/truncations), cli (end to end), large
      (256 MiB, bounded RSS). All passing.
- [x] 5. Fuzz (proptest): quick 2x512 cases in the normal suite; timed run 180 s: 2,576,000 cases, 0 panics, 0 forgeries.
- [x] 6. Throughput (`tools/bench_cli.sh 256`, 256 MiB file->file, box shared with other jobs so numbers are noisy):
      1 thread: seal ~33 MB/s, open ~18 MB/s; 4 threads: ~100 / ~61 MB/s; 8 threads (batch 16, now default):
      ~117 / ~80 MB/s; pipe stdin->stdout: seal ~119 MB/s, open (spooled) ~59 MB/s. Peak RSS for a
      256 MiB round trip: 6.8–12.6 MiB. Batch memory is capped at ~16 MiB of chunk buffers.
- [x] 7. Full run `cargo test --release --workspace --all-features` (2026-11-22): 39 test functions passed, 0 failed,
      2 ignored (timed fuzz, one slow core test). Core copy still 79/79 score, 6/6 app, 3/3 samples, 74/74 Python
      differential on all 6 backends. `--no-default-features` (no_std) builds, with and without `zeroize`.
- [x] 8. Docs: `CLI.md` (commands, safety, limits), `SEED_POLICY.md`. `hear` was trivial, so it is included.

## Test counts (octavo-cli)
| Test | Result |
|---|---|
| published v9 vectors + rehearsal-demo sample via streaming API (4 thread/batch combos each) | 11/11 |
| streaming == whole-buffer seal/open, random sizes x chunk sizes x threads | 792/792 |
| single-bit flips of a 3-chunk blob (every bit) rejected | 7488/7488 |
| truncations (every length), extensions, chunk swap/drop/dup, header splice rejected | 1234/1234 |
| wrong key / wrong AD / header fields / empty / short | all rejected |
| CLI round trips (0 B .. 2 MB, chunk 128 .. 1 MiB; file->file, stdin->stdout, both open modes) | 11/11 |
| CLI rejects with no output written (file and stdout) | 17/17 |
| weak / malformed / unsafe key cases | 16/16 |
| output safety (no clobber, --force atomic, same-file refused, failed open keeps old file) | ok |
| hear deterministic, key-specific, WAV header | ok |
| 256 MiB file round trip, bounded RSS | ok |
| OS-random seeds pass the rule | 100000/100000 |
| Rust CLI -> Python decrypt_rehearsal_file | 11/11 |
| Python encrypt_rehearsal_file -> Rust CLI (file and stdin) | 11/11 |
| Rust keygen file read by Python load_seed | 1/1 |
| tampered Rust blob refused by Python | 1/1 |
| weak-seed verdict + reason text == Python `_weak_seed_reason` | 298/298 |
| proptest fuzz, quick (in suite) | 2 x 512 cases |
| proptest fuzz, timed 180 s | 2,576,000 cases, 0 panics, 0 forgeries |

`/workspace/sneak_n2` unchanged (SHA 19181bc1…e71eee; the test checks its folder and `__pycache__` listing and
mtimes before/after). `/workspace/octavo_rust_port` unchanged. Test scratch dirs under `target/` were removed.
