#!/usr/bin/env bash
# Re-run everything for the Octavo Rust port (local only).
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"   # rustc >= 1.89 (user-local rustup)
cd "$(dirname "$0")/.."
sha256sum /workspace/sneak_n2/sneak_n2.py | grep -q 19181bc1623115c075dc5dee25edec388f5413466777d47b7f19fa66d1e71eee
python3 -B tools/export_vectors.py          # score v11 + app + samples -> vectors/octavo_vectors.json
python3 -B tools/diff_python.py             # random cases from real sneak_n2.py -> vectors/diff_random.json
cargo test --offline --all-features -- --nocapture 2>&1 | grep -E "SUMMARY|^  [a-z_]+ +[0-9]+/|differential|match the software|available backends|SKIP|test result"
for b in gfni-simd gfni-512 gfni-256 gfni-128 aes-ni ct-soft; do OCTAVO_BACKEND=$b python3 -B tools/check_rust_blobs.py | sed "s/^/$b: /"; done
python3 -B tools/check_rust_blobs.py        # Rust-sealed blobs opened by sneak_n2.py
cargo run -q --offline --release --all-features --example bench
python3 -B tools/bench_python.py
