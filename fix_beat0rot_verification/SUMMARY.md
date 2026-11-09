# Beat-0 pressure-rotation fix — verification summary

- Live SHA: `25cfe812ac6a5d5c22a26ba17440843f417dd44e060498850a78b68964612ff0`
- BOW_PRESSURE_ROT: `[0, 0, 0, 3, 0, 0, 5]`
- Even-beat scan PASS (0 hits): **True** (total_hits=0)
- Scan A (2^21 even): hits/cases/one_pair_both per beat: 0: 0/534773760/0, 2: 0/534773760/0, 4: 0/534773760/0
- Scan B (2^18 all beats) hits: 0:0, 1:0, 2:0, 3:0, 4:0, 5:0, 6:0, 7:0
- Forced changes F: `{'0': [0, 1, 2], '1': [0], '2': [], '3': [], '4': [5, 6], '5': [], '6': [5, 7], '7': [5]}`
- Differentials (2^13 bases) log2 vs pre-fix report: beat0: -10.19 (was -8.1), beat6: -7.07 (was -5.6), beat7: -7.33 (was -4.9)
- Same-bases old-model log2: `{'0': -8.09, '6': -5.47, '7': -4.72}`
- Improved vs report: `{'0': True, '6': True, '7': True}`
- Wall: even 106.0s, diffs 2.1s

Still homemade. For real secrets use AES-GCM-SIV, age, or libsodium.
