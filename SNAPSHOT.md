# octavo005 — frozen Octavo snapshot

Saved 2026-11-10 from live /workspace/sneak_n2 (Python caches excluded), plus sneak1024-seed.txt.

This is the seed-only revision on top of octavo004. The round function is unchanged from octavo004. The picture was not redrawn.

- sneak_n2.py SHA-256: 082d5c808085500ab5f0516bc4d032e09a0b2dc466ed5c0df97c77818cdfb331
- EXPECTED_MIX_SHA256: 90ebb01d5668d84d29567fafd4708eca90e949610085a0b6e0f7662d7950f8da
- key_sig (demo seed): 55daf5b7fde67625397935b918af6c1a
- Tests at freeze: 254/254 (0 skipped on the author's machine)
- Blob size: 196 bytes (version byte 2 || SN2 || pickup || nonce || ct || tag)
- hello-world pickup 6b8f46a0f6d032103e7bbd17dda25444, nonce a293ac73d853e5948e24223b9b158aab (empty AD)
- Change: `load_seed()` no longer falls back to `/workspace/sneak1024-seed.txt`. With no argument it reads only the module-relative seed file. If that file is missing, it raises instead of quietly loading another file. Round function unchanged vs octavo004.
- Picture not redrawn.

Homemade, NOT for real secrets. Use AES-GCM-SIV, age, or libsodium.
