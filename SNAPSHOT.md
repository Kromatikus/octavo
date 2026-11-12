# Live tree note — rehearsal-finale (frozen as /workspace/octavo011)

Live `/workspace/sneak_n2` is the rehearsal-finale revision (2026-11-11). Since
octavo010 (conductor-polish) it went through rehearsal (new v8 streaming mode),
rehearsal-fix, rehearsal-polish and rehearsal-finale, each fixing the previous
in-house rehearsal attack (`attacks_octavo_rehearsal`, `_rehearsalfix`,
`_rehearsalpolish`). The round function and the v6/v7 formats are unchanged
(byte-identical to octavo010); only v8 was added and then hardened.

- sneak_n2.py SHA-256: 929bacc1bef5ebd6dee7df817aba6061ca58e871d4a18992d33fc0bc107b772f
- EXPECTED_MIX_SHA256: fe93996970ecd92693b5f8f43ffb2cad5e96867f258a38b12637f1014b12b4c6 (unchanged)
- key_sig (demo seed): 340dc1e062502bb13462a94ba490c3dc (unchanged)
- EXPECTED_REHEARSAL_SHA256: f28badba6dcd70e80f2524d9adb00bc177374d609a0555453256fa10451804a4; rehearsal_sig a3b4c820528562ac17a74eb414a389a3
- hello-world and movements-demo: unchanged from octavo010; rehearsal-demo.txt re-sealed (same pickup/nonce, new tags); score version 7
- Changes in rehearsal-finale: see README "Current live revision — rehearsal-finale" (L1–L3, I1–I8 of attacks_octavo_rehearsalpolish).

Still homemade, NOT for real secrets. Use AES-GCM-SIV, age, or libsodium.

# Previous live tree note — conductor-polish (frozen as octavo010)

Live `/workspace/sneak_n2` is the conductor-polish revision (2026-11-11)
on top of the conductor tree. The round function and the v6/v7 formats are
unchanged (same nonce, commitment and ciphertext for the same inputs).
Movements rejects are now equal-time (commitment and coda combined).

- sneak_n2.py SHA-256: c07707bfde75ed4b77a4ad4f09797526f9fabe1509914fb3a49fa5288bd39d50
- EXPECTED_MIX_SHA256: fe93996970ecd92693b5f8f43ffb2cad5e96867f258a38b12637f1014b12b4c6
- key_sig (demo seed): 340dc1e062502bb13462a94ba490c3dc
- hello-world pickup 2b87dc4e184cd78e6c77b829273b17a3, nonce d4a86fc3847623035bbe3a19ceda33b1 (empty AD; same ciphertext as conductor, new tag)
- Changes: equal-time movements rejects (L1); LegacyFormatWarning is a UserWarning (L2); fixed-width mask unpad (L3); private legacy bodies gated + version-pinned (I2); Rejected base class + allowlist/cutoff guidance (I3); legacy étude end date 2027-03-01 (I1); seed-file cache keyed on dev/inode/size/mtime/ctime (I4); 16-entry LRU seed memo, étude keys never memoized (I5); read-only Etude.lab_seed (I6); score regenerated (score version 3); picture re-rendered.

# Previous live tree note — conductor (superseded by conductor-polish above)

Live `/workspace/sneak_n2` was the conductor revision (2026-11-11)
on top of the tuning-fix tree. The round function is unchanged and the
live formats are still v6 (single-block, 228 bytes) and v7 (movements).
Single-block rejects always run both the commitment and the tag check.
Études are key-separated (domain E) with new bytes 0x82/0x84/0x86/0x90
and 0x83/0x85/0x87/0x91. Legacy helpers need allow_noncommitting=True.
This is not a frozen snapshot. Not pushed, not frozen.

- sneak_n2.py SHA-256: 469c7b0b3bc755966a8274703e64e187fd79b805c0807cbe6bc391d4a43ae062
- EXPECTED_MIX_SHA256: 53df74e18aa01bc0de218680fe88af6f4d166f7ad5cac70d81f43c5575fae797
- key_sig (demo seed): 46d1acfb174975057fb7b63cf2002d74
- hello-world pickup 2b87dc4e184cd78e6c77b829273b17a3, nonce d4a86fc3847623035bbe3a19ceda33b1 (empty AD; same ciphertext as tuning-fix)
- Changes: equal-time single-block rejects (M1); étude key separation + version byte in étude SIV nonce + demo-seed gate (lab_seed=True); Etude(r) pins round count; UnsupportedVersion no longer an AuthError; legacy helpers need allow_noncommitting=True and warn (LegacyFormatWarning); constant-structure _unpad_block (L4); cached seed load/check (I3); docs (public demo seed, stage timing for movements, Rust-port requirements); score regenerated (score version 3); picture re-rendered.

# Previous live tree note — tuning-fix (superseded by conductor above)

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
