# Live tree note — rehearsal-honest2 (2026-11-15, live, not frozen)

Live `/workspace/sneak_n2` is rehearsal-honest plus fixes for `/workspace/attacks_octavo_honest/REPORT.md` (L1, L2, I1–I6).
No ciphertext, key_sig or rehearsal_sig changed; all 79 vectors are byte-identical. The score is now version 11
(header adds `etudes_sha256` and `generate_score_sha256`; `--check-sha` verifies all three files; regeneration needs `--write`).

- sneak_n2.py SHA-256: 19181bc1623115c075dc5dee25edec388f5413466777d47b7f19fa66d1e71eee (was 476f8a8b…)
- EXPECTED_MIX_SHA256: 1fafb4adc1cae574a1158fc19695b5a7c354e405666278ab5f66444122f8f34a (was 2bc45b77…); core 9b8ac067676c92f2150d897c7ea9fa1021952ee6c728269ba9bdecf6a4b1efb1 (was e48c6878…)
- EXPECTED_REHEARSAL_SHA256: 44ad0a4a2eb86b7b98ff147ecf0374552e16bd9fe031fbe32b6b7ed0b1f67737 (was 8987bf9f…); core 636d48eea97eb29449fbd0270d41d75826d6b9cab6a743e19e5cbb3a8319da72 (was 0d6d9122…)
- EXPECTED_SEED_POLICY_SHA256: 0fc482e65533814588ade098f6c8d5e68693aca76e6a1232f76466b5e609cd5e (unchanged)
- key_sig 340dc1e062502bb13462a94ba490c3dc, rehearsal_sig 07172e74d02a04a42ea0a51b8e69cbf1 (both unchanged)
- Tests: 544/544 passed, 27 skipped (about 13 min, 11:17–11:30 AM ET; honest2_verification/test_run_final.txt)
- Pre-change backup: /workspace/sneak_n2_backups_rebuilt/pre_honest2/. Work: /workspace/honest2_work/. Verification: honest2_verification/. Witness re-check: /workspace/honest2_work/witness_recheck/closed_results.json.

# Previous live tree note — rehearsal-honest (backup pre_honest2; attacked in attacks_octavo_honest/)



Live `/workspace/sneak_n2` is rehearsal-seedguard plus fixes for `/workspace/attacks_octavo_seedguard/REPORT.md` (L1, L2, I1–I6)
and a plain statement that the import self-checks are not a tamper guard (SECURITY.md). No ciphertext, key_sig or
rehearsal_sig changed; score version 10 regenerates byte for byte (header identifiers only).

- sneak_n2.py SHA-256: 476f8a8b1a4e924d302401e42d5914f882b5dfbc0ac961cc656902548f4496e3 (was 21213355…)
- EXPECTED_MIX_SHA256: 2bc45b7785ef96f5aeed181bb24180fa87bdfe9152e072570d056406dc6010a9 (was e41a177c…); core e48c68782f5280a199f9a62b3f066d01ac2a53ac2c3d82d1d80fd353027c7dab (was 43cd3014…)
- EXPECTED_REHEARSAL_SHA256: 8987bf9fd0129d440cdc90e26e7fe71a995bc76bf5b9dce7b531949bcbda2785 (was 40a58c01…); core 0d6d9122ce920a2e31cf588a5dc3c2052f82a08a0bae61edc18e80717798d04b (was e4dc803c…)
- EXPECTED_SEED_POLICY_SHA256: 0fc482e65533814588ade098f6c8d5e68693aca76e6a1232f76466b5e609cd5e (was 612ff6ce…)
- key_sig 340dc1e062502bb13462a94ba490c3dc, rehearsal_sig 07172e74d02a04a42ea0a51b8e69cbf1 (both unchanged)
- Tests: 533/533 passed, 27 skipped (honest_verification/test_run_final.txt)
- Pre-change backup: /workspace/sneak_n2_backups_rebuilt/pre_seedguard2/. Work: /workspace/seedguard2_work/. Verification: honest_verification/.

# Previous live tree note — rehearsal-seedguard (backup pre_seedguard2)

Live `/workspace/sneak_n2` is the rehearsal-seedguard revision: rehearsal-chainfix (frozen as /workspace/octavo015)
plus fixes for every finding of `/workspace/attacks_octavo_chainfix/REPORT.md` (L1, I1–I6). No ciphertext, key_sig
or rehearsal_sig changed; score version 10 regenerates byte for byte (header identifiers only).

- sneak_n2.py SHA-256: 21213355199f45c934358a83a2a49c230068129d80195c238e9a8b490e97c42c
- EXPECTED_MIX_SHA256: e41a177c2ee6b15d55122eb2f360a70d12536047997309d7420f3696983836b6 (was b6e0fa2a…); core 43cd301469d5ea3fd6c62882a1d216fc58d72aee0f3beb20f6e66e68870c14dc (was a4b54e7e…)
- EXPECTED_REHEARSAL_SHA256: 40a58c015443c7bd6ccb386247b30b9514f6bc3330321977fa5377f5935d6cdb (was d0550f7f…); core e4dc803c5921f20ee753e5934008289ea4678bdf30c6d0908a17598d88519939 (was f1e21f50…)
- EXPECTED_SEED_POLICY_SHA256: 612ff6ce280d48e4b4ea888414f63eed41157e2f040ff4fc427b91b0e983bc24 (was ab5cdce4…); a change to it needs the same review as a core-pin change
- key_sig 340dc1e062502bb13462a94ba490c3dc, rehearsal_sig 07172e74d02a04a42ea0a51b8e69cbf1 (both unchanged)
- Tests: 523/523 passed, 0 failed, 27 skipped (about 20 min, 08:48-09:08 ET; seedguard_verification/test_run_final.txt)
- Pre-change backup: /workspace/sneak_n2_backups_rebuilt/pre_chainfix2/ (full rehearsal-chainfix tree). Work notes and the T1/T2 re-check: /workspace/chainfix2_work/. Verification: seedguard_verification/.

# Previous live tree note — rehearsal-chainfix (frozen as /workspace/octavo015)

Live `/workspace/sneak_n2` is the rehearsal-chainfix revision: rehearsal-chain plus fixes for every finding of
`/workspace/attacks_octavo_rehearsalchain/` (L1–L4, I1–I7). No ciphertext changed: v6/v7/v9 blobs, key_sig and
rehearsal_sig are byte-identical to rehearsal-chain; the 72 score-version-9 vectors are unchanged and 7 non-demo
vectors were added (score version 10).

- sneak_n2.py SHA-256: 48d261e36671a35b15000e68dbd82469e631be14cc77a3f391e115d19e8b9786
- EXPECTED_MIX_SHA256: b6e0fa2a5852a1bddb2aa407101080f989fb1efe1e4ddc590a58c8cdfe261991 (was 8b2c59fa…); core a4b54e7e2ac6d311ed461235b02a91472dd411ddaf2c0db332bc83fcc14202ff (was 4947e89d…); key_sig 340dc1e062502bb13462a94ba490c3dc (unchanged)
- EXPECTED_REHEARSAL_SHA256: d0550f7fdb09d4f823c27f2497f40b30dd1f31627b643089af555c435bd6a491 (was a21cf6e7…); core f1e21f5006a27ff5b19f352ce17c2d24c042252586c515dd99763b1934cd5432 (was 5e91e290…); rehearsal_sig 07172e74d02a04a42ea0a51b8e69cbf1 (unchanged)
- EXPECTED_SEED_POLICY_SHA256 (new): ab5cdce45c3078c80a0fd0af3ca573bd5d73267cea8ef81d7cc8bb2db272a2a0
- KEY_SIG_PIN / REHEARSAL_SIG_PIN: core halves re-pinned to the new cores; signature halves fe939969… / a21cf6e7… unchanged
- score version 10 (79 vectors; non-demo test seed key_sig 399f98cf52595841cabaade39428b3cb); tests 516/516 passed, 0 failed, 27 skipped
- Pre-change backup: /workspace/sneak_n2_backups_rebuilt/pre_chainfix/ (full rehearsal-chain tree). Work notes: /workspace/chainfix_work/. Verification: chainfix_verification/.

Still homemade, NOT for real secrets. Use AES-GCM-SIV, age, or libsodium.

# Previous live tree note — rehearsal-chain (backup /workspace/sneak_n2_backups_rebuilt/pre_chainfix/)

Live `/workspace/sneak_n2` is the rehearsal-chain revision: key-fix plus
rehearsal format version 9 (each chunk tag covers the previous tag; v9 sponge
labels). v8 opens only via `decrypt_rehearsal_legacy(..., allow_unchained=True)`.
v6/v7 blobs byte-identical to octavo014; the tester's w1 splice witness fails.

- sneak_n2.py SHA-256: b0e25f4d3bcb31eae7a64413376ab23f34665f97316876746f57642a1dd0c0d7
- EXPECTED_MIX_SHA256: 8b2c59fa8756e269ad11c35d6e812bdea7b83ea36c2c4be39a9c4257dd85bee5 (unchanged); key_sig 340dc1e062502bb13462a94ba490c3dc (unchanged)
- EXPECTED_REHEARSAL_SHA256: a21cf6e768a88cc21b4698b54426cf2d1527936f101f783862a609efa8bbad45 (core 5e91e290…); rehearsal_sig 07172e74d02a04a42ea0a51b8e69cbf1 (was 7ea74c1e…)
- REHEARSAL_V8_SHA256 (frozen, legacy reader): 50c077f3b2105b36e027bf0c94770dcad64f7242974c4b7e67d3f0226810a4a8
- score version 9 (8 rehearsal vectors regenerated; 64 others unchanged); legacy v8 vectors in legacy_v8/
- Pre-change backup: /workspace/sneak_n2_backups_rebuilt/keyfix/ (rebuilt after the /tmp copy was lost in a reboot). Verification: rehearsalchain_verification/, /workspace/review_tester_claims_rerun_chain/.

Still homemade, NOT for real secrets. Use AES-GCM-SIV, age, or libsodium.

# Previous live tree note — key-fix (backup /workspace/sneak_n2_backups_rebuilt/keyfix/)

Live `/workspace/sneak_n2` is the key-fix revision: rehearsal-curtain (frozen as
octavo014) plus `keygen()` / `save_seed()`, `seed=None` refused (`TypeError`;
the demo seed only via explicit `load_seed()`), and a stricter weak-seed rule
(false-reject rate 0 of 1,000,000 random seeds). v6/v7/v8 blobs and all 72
score vectors are byte-identical to octavo014.

- sneak_n2.py SHA-256: fca305833b4413ba4d141b4d2bfbcb6b2755d0c4e974024c0a360c92d6f8146f
- EXPECTED_MIX_SHA256: 8b2c59fa8756e269ad11c35d6e812bdea7b83ea36c2c4be39a9c4257dd85bee5 (was fe939969…); core 4947e89d…
- EXPECTED_REHEARSAL_SHA256: efd31092b9c98cf6419cebe66cbc65ed9ae28322e49576b85ca1d704e5b2bae4 (was 50c077f3…); core 59ff3036…
- key_sig 340dc1e062502bb13462a94ba490c3dc and rehearsal_sig 7ea74c1edbfe3c7eee503d04c2ff6391 (demo seed) unchanged via KEY_SIG_PIN / REHEARSAL_SIG_PIN
- score version 8 (vectors unchanged); tests 495/495
- Pre-change backup: was /tmp/sneak_n2_pre_keyfix (lost in a reboot; module = frozen octavo014). Changes: README "Current live revision — key-fix".

Still homemade, NOT for real secrets. Use AES-GCM-SIV, age, or libsodium.

# Previous live tree note — rehearsal-curtain (frozen as /workspace/octavo014)

Live `/workspace/sneak_n2` is the rehearsal-curtain revision (2026-11-14): the
rehearsal-finale tree (frozen as octavo011 / octavo013) plus the fixes for the
fourth in-house rehearsal attack (`attacks_octavo_rehearsalfinale`: L1, I1–I6;
I7 needed none). The round function, key schedule, constants and the v6/v7/v8
formats are unchanged; v6/v7 are byte-identical to octavo010, and v8 headers
and ciphertext blocks are byte-identical to rehearsal-finale. Only v8 tags
moved (the rehearsal digest attests the v8 API code), so published
rehearsal-finale v8 streams do not open here.

- sneak_n2.py SHA-256: 329c0647989a35019a06b00ef2ae660494a8e8ad0c1523787b37436562cd78a4
- EXPECTED_MIX_SHA256: fe93996970ecd92693b5f8f43ffb2cad5e96867f258a38b12637f1014b12b4c6 (unchanged)
- key_sig (demo seed): 340dc1e062502bb13462a94ba490c3dc (unchanged)
- EXPECTED_REHEARSAL_SHA256: 50c077f3b2105b36e027bf0c94770dcad64f7242974c4b7e67d3f0226810a4a8; rehearsal_sig 7ea74c1edbfe3c7eee503d04c2ff6391 (was f28badba… / a3b4c820…)
- hello-world and movements-demo: blobs unchanged from octavo010 (SHA labels updated); rehearsal-demo.txt re-sealed (same pickup/nonce, new tags); score version 8
- Pre-change backup: /tmp/sneak_n2_pre_finale_fixes. Verification: rehearsalcurtain_verification/.
- Changes: see README "Current live revision — rehearsal-curtain".

Still homemade, NOT for real secrets. Use AES-GCM-SIV, age, or libsodium.

# Previous live tree note — rehearsal-finale (frozen as /workspace/octavo011)

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
