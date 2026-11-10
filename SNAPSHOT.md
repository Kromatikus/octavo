# Live tree note (not a freeze)

Live `/workspace/sneak_n2` is the movements revision (2026-11-10)
on top of the outer-fix / octavo007 tree. The round function is unchanged.
The picture header is generated from live module metadata so a re-render stays current.
This is not a frozen snapshot.

- sneak_n2.py SHA-256: e5dd55e13eb0aa8df140f99aab514629477fbc60e48454bc7180243ed9692eff
- EXPECTED_MIX_SHA256: f7049b7f4aede9ab1ecc778220c13e982dedd890becb4510d7f954d0b528bae2
- key_sig (demo seed): 925d1cd5341a9126dfa731475ef8c4fb
- hello-world pickup fdb720ab5f5641df76b480010d7e8b4e, nonce 65283ad51c8025a7cf369f44b2dac34c (empty AD)
- Changes: encrypt_movements / decrypt_movements (format version 3, theme/cadence/coda); MAX_MOVEMENTS_MSG=1040384; single-block version 2 kept; attestation updated so key_sig changed; regenerate hello-world.txt and movements-demo.txt; redraw sneak-staff-n2.png.

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
