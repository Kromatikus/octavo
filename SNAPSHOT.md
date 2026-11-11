# Live tree note (not a freeze)

Live `/workspace/sneak_n2` is the tuning-fix revision (2026-11-11)
on top of the tuning tree. The round function is unchanged. New blobs
are format v6 (single-block, 228 bytes, commitment binds AD) and v7
(movements, commitment binds AD and nmov). Default decrypt rejects
legacy v2/v3 and unpublished v4/v5; `decrypt_legacy()` /
`decrypt_movements_legacy()` open published octavo009 v2/v3 only and
are not key-committing. Commitment, tag, cadence and coda failures
share `AuthError("authentication failed")`. The picture header is
generated from live module metadata so a re-render stays current.
This is not a frozen snapshot. Not pushed, not frozen.

- sneak_n2.py SHA-256: e845419417b9d9d157636d7863c26dcb605f99767d54a5e61f3c5df397b24221
- EXPECTED_MIX_SHA256: 947eb322addb5fd5177dd5fde4ca6e6593429088cbb009c26113154995f3d62b
- key_sig (demo seed): 37e14a077a546e12a40c8013e78e949b
- hello-world pickup 2b87dc4e184cd78e6c77b829273b17a3, nonce d4a86fc3847623035bbe3a19ceda33b1 (empty AD)
- Changes: bind encode_ad(ad) and movements nmov in the HMAC-U commitment; formats v6/v7; reject v2/v3 by default with named decrypt_legacy helpers; reject unpublished v4/v5 outright; collapse CommitError into AuthError("authentication failed"); new étude bytes 0xA*/0xB*; score regenerated; FEATURES/REVISION updated (still in _ATTEST_SKIP); redraw sneak-staff-n2.png.

# Previous live tree note — tuning (superseded by tuning-fix above)

Live `/workspace/sneak_n2` was the tuning revision (2026-11-11)
on top of the etudes tree. The round function is unchanged. Blobs
were format v4 (single-block, 228 bytes, with a 32-byte tuning
commitment) and v5 (movements). Legacy v2/v3 blobs still opened under
the frozen octavo009 key_sig; they were not key-committing. This
revision was not frozen or pushed.

- sneak_n2.py SHA-256: 53d0f3afbef1166bade608123d008fe229123a2e36cc9acd08b5e599ce0ad10c
- EXPECTED_MIX_SHA256: edbf9b90d95640e1c2c0595a49a956f987356df5b0d1c2cf0750744e74b1e1b9
- key_sig (demo seed): 5af75cc47068872de8a7513365cc9a03
- hello-world pickup bba68569633acd16123080de10fedc2e, nonce 00fe980e268c6dbf21b47ecab3577d9e (empty AD)
- Changes: key commitment (tuning, domain U) on single-block and movements; format versions 4 and 5; CommitError; legacy v2/v3 and pre-tuning études still decrypt with LEGACY_MIX_SHA256; études updated to committed version bytes; score regenerated; FEATURES/REVISION updated (still in _ATTEST_SKIP); tests cover commitment, domain pinning and legacy blobs; redraw sneak-staff-n2.png.

# Previous live tree note — etudes (superseded by tuning above)

Live `/workspace/sneak_n2` was the etudes revision (2026-11-11)
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
