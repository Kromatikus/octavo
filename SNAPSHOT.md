# octavo006 — frozen Octavo snapshot

Saved 2026-11-10 from live /workspace/sneak_n2 (Python caches excluded), plus sneak1024-seed.txt.

This is the unused-B0 attestation and picture revision on top of octavo005 (seed-only). The round function is unchanged from octavo005. The picture was redrawn from the new hello-world sample.

- sneak_n2.py SHA-256: 3eb1da8fd3aec1c9b76a1e962b0973cdde15224e895672fad0aca0ba75f8798d
- EXPECTED_MIX_SHA256: a368523b89b85d2e7bbfa2f0c0934086c1908b83fac55d68b79d356e1a00f1b1
- key_sig (demo seed): f716aa939283e46ea7760717a22a7307
- Tests at freeze: 258/258 (0 skipped on the author's machine)
- Blob size: 196 bytes (version byte 2 || SN2 || pickup || nonce || ct || tag)
- hello-world pickup 25e3a20bca148ff3931e8c2eaef008b0, nonce 6eff97c6129e9a14ba3d75dd4e119490 (empty AD)
- Changes: drop the unused B0 field matrix from BARS and BARS_INV (both slots are None) so it is no longer hashed into key_signature; _canon_data encodes set/frozenset/bytearray/memoryview/float/complex deterministically and still raises TypeError for any other type; regenerate hello-world.txt; redraw sneak-staff-n2.png; render_n2.py resolves paths from the script folder, reads hello-world fields from the start of their lines, and prepends FMT_VERSION. Round function unchanged vs octavo005.
- Picture redrawn from this sample.

Homemade, NOT for real secrets. Use AES-GCM-SIV, age, or libsodium.
