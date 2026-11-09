# octavo002 — frozen Octavo snapshot

Saved 2026-11-09 ~10:36 AM EST from live /workspace/sneak_n2 (Python caches excluded), plus sneak1024-seed.txt.

Contents: Octavo as in octavo001 plus the beat-0 pressure rotation fix: BOW_STROKES unchanged, BOW_PRESSURE_ROT = (0,0,0,3,0,0,5), so strokes (4,5,0), (6,7,0), (5,6,0) read beat 0 rotated by 0, 3, 5 bits.

- sneak_n2.py SHA-256: 25cfe812ac6a5d5c22a26ba17440843f417dd44e060498850a78b68964612ff0
- key_sig: 1946c5ac57f19d045eeacd9e5ed823fb
- Tests at freeze: 237/237 (recorded on live)
- hello-world pickup 7d4b4694011a7ab66e7f5f24c235c3f8, nonce 8855fdf3a1cb2cc843c4d1250f484697
- Verification: fix_beat0rot_verification/ (0 singletons on all beats; 2^21-base even-beat scan)
- Latest attack report: attacks_octavo_beat6/ (made on the previous revision)
- sneak-staff-n2.png redrawn after the snapshot for this revision (current).

Homemade, NOT for real secrets. Use AES-GCM-SIV, age, or libsodium.
