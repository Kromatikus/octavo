#!/usr/bin/env bash
# Re-run everything for the Octavo Rust port.
# Needs Rust 1.89+ (rustup recommended). Python sneak_n2.py is this repo's
# copy, or $OCTAVO_PY_DIR if set.
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
if [ -n "${OCTAVO_PY_DIR:-}" ]; then
  REPO="$(cd "$OCTAVO_PY_DIR" && pwd)"
else
  REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
fi
sha256sum "$REPO/sneak_n2.py" | grep -q 19181bc1623115c075dc5dee25edec388f5413466777d47b7f19fa66d1e71eee
python3 -B tools/export_vectors.py "$REPO"  # score v11 + app + samples -> vectors/octavo_vectors.json
python3 -B tools/diff_python.py --check     # verify committed vectors/diff_random.json (do not rewrite)
cargo test --release --all-features -- --nocapture 2>&1 | grep -E "SUMMARY|^  [a-z_]+ +[0-9]+/|differential|match the software|available backends|SKIP|test result"
for b in gfni-simd gfni-512 gfni-256 gfni-128 aes-ni ct-soft; do OCTAVO_BACKEND=$b python3 -B tools/check_rust_blobs.py | sed "s/^/$b: /"; done
python3 -B tools/check_rust_blobs.py        # Rust-sealed blobs opened by sneak_n2.py
cargo run -q --release --all-features --example bench
python3 -B tools/bench_python.py
