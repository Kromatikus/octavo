# Live tree note (not a freeze)

Live `/workspace/sneak_n2` is the outer-fix revision (2026-11-10)
on top of the unused-B0 / seed-only tree. The round function is unchanged.
The picture header is generated from live module metadata so a re-render stays current.

- sneak_n2.py SHA-256: 3e61bdcd151771001b9d0e0307bde5d2f373a1fa31c21ccb173b110e958cb7ed
- EXPECTED_MIX_SHA256: 389b90afbc68ab02636b922a0331a7d7ed4f55d97db164a044cfbe1a096d1641
- key_sig (demo seed): 42ded003543b35fa0695a2e767f4415e
- hello-world pickup f50732d765b08bbb2556fc989087f4fa, nonce b2ab07a9cc0d1f1e46b1812316eb69a8 (empty AD)
- Changes: strict bytes-like msg/blob/ad (TypeError otherwise); decrypt verifies HMAC from the MAC key before building Schedule; MAX_AD_LEN=65536; FEATURES mention version byte and AD; REVISION=outer-fix; regenerate hello-world.txt; redraw sneak-staff-n2.png.

# octavo004 — frozen Octavo snapshot

Saved 2026-11-09 from live /workspace/sneak_n2 (Python caches excluded), plus sneak1024-seed.txt.

This is the info-fix revision on top of octavo003 (packaging). The round function is unchanged.

- sneak_n2.py SHA-256: 2d7c18e2c9a00146361bc7cdf0708af181fb692a1c121aadb200af1cc3a6a39f
- EXPECTED_MIX_SHA256: 8c12ae0d2a88b0aed3bf6d14e2031903a18d801ee5c7f56c7fc34cb7437ac31c
- key_sig (demo seed): 6fcc97151089539a8084e4cc3886921a
- Tests at freeze: 253/253 (0 skipped on the author's machine)
- Blob size: 196 bytes (version byte 2 || SN2 || pickup || nonce || ct || tag)
- hello-world pickup 3f703b2e5515d2613767372de752343e, nonce 0a08ea35ec9a2ac650773b407f6d93df (empty AD)
- Changes: hardened pickup (sha256 of urandom || time_ns || counter || pid); optional associated data bound into the SIV nonce and HMAC with uint64be length prefix; FMT_VERSION = 2; documented constant-time and single-block limits. Round function unchanged vs octavo003.
- Picture not redrawn.

Homemade, NOT for real secrets. Use AES-GCM-SIV, age, or libsodium.
