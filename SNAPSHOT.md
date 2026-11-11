# Live tree note (not a freeze)

Live `/workspace/sneak_n2` is the etudes revision (2026-11-11)
on top of the movements-polish tree. The round function and full-round
wrappers are unchanged, so hello-world and movements-demo blobs still
open. The picture header is generated from live module metadata so a
re-render stays current. This is not a frozen snapshot.

- sneak_n2.py SHA-256: 38301026bad66f177e848a68ea4f56f78e28c43085bc0df3549737423eb83784
- EXPECTED_MIX_SHA256: 4e9a7ded574924fe9635e2b7b908ba7c5fa5c489062137203d3ce03341a06ee6 (unchanged)
- key_sig (demo seed): d8a1358aae4116aaafcee90ec74a4d8e (unchanged)
- hello-world pickup c9a332594dfc60c3f16795a3cba3b16b, nonce eeb1b7f8afbc85008b1258efe3dc038d (empty AD; same blob as movements-polish)
- Changes: etudes.py lab API (etude(rounds) at 2/4/6/16, distinct version bytes); published score in score/vectors.json (64 vectors) with generator and README; FEATURES/REVISION updated (still in _ATTEST_SKIP); tests cover études and regenerate the score; redraw sneak-staff-n2.png.

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
