# Octavo N3 draft-3 design notes

This folder is `/workspace/octavo_n3_draft3`, a copy of draft-2 with
branch-number tests added. The block function and public maps are
unchanged from draft-2. See `tools/test_branch_numbers.py` and
`rust/src/branch.rs`.

# Octavo N3 draft-2 design notes

Lab draft of the N3 **block function** only, in `/workspace/octavo_n3_draft2`.
Copied from draft-1, then a keyed S-box `S_mid` was added after the bow, as
modelled in `/workspace/octavo_n3_trail2`. It follows
`/workspace/octavo_n3_spec/N3_SPEC.md` plus `SPEC_DELTA.md` in this folder.
The original spec file, draft-1, trail folders, and live N2 were not edited.
It is not for real secrets. Use AES-GCM-SIV, age, or libsodium for those.

No chaining or formats are implemented here. A 1- and 2-round trail-bound
check is in `tools/confirm_bound.py`. The mutation lab was not run.
Live `/workspace/sneak_n2`, frozen snapshots, and repo clones were not edited.

## Round

```
g ^= rk_r ; g = S_r[g] ; chord ; bridges ; triplets ; bow
g = S_mid_r[g] ; cross ; g = S2_r[g]
# after last round: g ^= white
```

This is the trail-2 restored-S-box variant. `S_mid` is a third keyed SM4-affine
S-box, distinct from both `S` and `S2` of the same round.

16 rounds, 128-byte block, 16 faces × 8 beats, field GF(2^8) with polynomial
**0x1F5**. Inner faces 0–7, outer faces 8–15. Block byte `8f+t` is face `f`,
beat `t`.

## What was reused from N2 (read, not copied into live trees)

- Key schedule consumption order: for each of 16 rounds, squeeze `rk` (128),
  invertible `A1`/`A2`, `b1`/`b2`, then `SH[16]`, `SV[8]`, `sigma[16]`
  (Fisher–Yates on 8), `bridge` (Fisher–Yates on 64), then resample
  `A3`/`A4`/`b3`/`b4` until `S2 ≠ S`; then a third keyed S-box
  `S_mid` from `A5`/`A6`/`b5`/`b6`, resampling until `S_mid ≠ S` and
  `S_mid ≠ S2`; then 128-byte `white`. Drawing `S_mid` after `S2` keeps
  `S`, `S2`, and `bridge` in the same stream positions as draft-1 / N2
  for the same seed and nonce; only `white` moves later in the stream.
- Keyed S-boxes `S(x) = A2·SM4[A1·x ⊕ b1] ⊕ b2` (and the same for S2), with
  the public SM4 table (GB/T 32907-2016) and the N2 bit-matrix convention
  (output bit i is the parity of row i AND x; bit 0 is LSB).
- Shell bridges: 64 pairs, inner cell `c` with outer cell `bridge[c]`,
  mix2 `(u⊕v, u⊕2v)` in this field, `u`/`v` orientation flipped on odd
  rounds. Inverse uses the closed form `v = 3^{-1}⊗(a⊕b)`, `u = a⊕v`.
- Bow: `BOW_STROKES`, `BOW_PRESSURE_ROT = (0,0,0,3,0,0,5)`, and the
  add-rotate-XOR stroke, exactly as in live N2 (including the beat-0/6/7
  pressure-read fixes).
- `randint` / Fisher–Yates, SHA-256 sponge layout, 16-byte nonce, 128-byte
  seed.

The sponge prefix is **`SN3/`**, not `SN2/`, so the same seed and nonce do
not share N2 schedule material. `SH`, `SV`, and `sigma` are still drawn so
the later S-box and bridge bytes stay in the same stream positions as N2;
they are not used on the N3 data path (weave and butterfly were folded into
`chord`).

This draft does **not** implement N2 seed-policy / weak-seed checks or the
MAC-key sponge (`domain M`). Callers pass a raw 128-byte seed.

## New public linear maps

All three are **Cauchy MDS** matrices `C[i][j] = 1/(x_i ⊕ y_j)` over this
field. A Cauchy matrix is MDS when the `x`'s and the `y`'s are pairwise
distinct (standard theorem). Invertibility was also checked by constructing
the inverse and multiplying on unit vectors; the 8×8 and all six 3×3 maps
were checked to be MDS by testing every square minor; the 16×16 map was
checked to have a nonzero determinant, all entries nonzero, and all 2×2
minors nonzero (a full 16×16 minor sweep was not run; the Cauchy theorem
covers MDS).

### `chord` (replaces weave + butterfly + bars)

One field-linear step, aligned to the two 64-byte shells.

- Matrix: 8×8 Cauchy with `x = (0..7)`, `y = (8..15)`. Branch number 9 (MDS).
- Forward, on each shell independently: multiply the 8 beats of each face
  by this matrix, then multiply the 8 faces of each beat by the same
  matrix.
- Inverse: faces, then staffs, with the matrix inverse.

There is no key-dependent 128-byte shuffle. The two shells are not mixed
by `chord`; that is left to the bridges and the folded `cross`.

### Triplets (experimental GF-linear change)

The six overlapping windows are the same as N2 and do not wrap beat 7 to 0:
`(0,1,2), (1,2,3), (2,3,4), (3,4,5), (4,5,6), (5,6,7)`. Applied on each
staff, T0..T5 forward and T5..T0 on the inverse.

Window `t` uses a 3×3 Cauchy MDS matrix with `x = (0,1,2)` and
`y = (3+3t, 4+3t, 5+3t)`. So the six matrices are distinct. Each has
branch number 4. This replaces N2's add-mod-256 matrices. The between-S-box
modular addition is now only in the bow; that is why the spec still calls
this experimental and requires a later trail search and a 1%/5% mutation
lab before adoption.

### Folded `cross` (replaces four N2 matchings)

One 16×16 Cauchy MDS map on the 16 faces, independently at each of the 8
beats. Parameters: `x = (0..15)`, `y = (16..31)`. This is a single named
step that mixes both shells at every beat. It is **not** the composition of
N2's four mix2 matchings (opposite, radial, adjacent, partial bridge); it
is a simpler map with a bound the trail search can count (branch number 17
if the Cauchy MDS claim holds). Shell bridges remain a separate, keyed,
possibly off-beat pairing.

## Ambiguities resolved in this draft

1. Exact `chord` wiring — chosen as above (beats then faces, per shell).
2. Exact GF-linear triplet tables — six distinct 3×3 Cauchy MDS matrices
   on N2's windows.
3. How to fold the four cross layers — one 16×16 MDS per beat, not the
   composed mix2 matchings.
4. Whether unused `SH`/`SV`/`sigma` are still squeezed — yes, to keep S-box
   and bridge derivation aligned with N2's schedule order.
5. Seed policy — not part of this block-function draft.
6. Chaining / version bytes `SN3` / `0x16` / `0x17` / `0x19` — specified,
   but not implemented in this piece.

## Checks in this piece (and not in this piece)

`tools/verify_draft.py` builds the Rust binary, checks the linear maps,
writes a few deterministic vectors, requires Rust == Python and
`decrypt(encrypt(x)) == x` on 1000 random blocks under a fixed key, and
reports a measured one-bit avalanche fraction over full 16-round
encryptions. It does **not** run the trail search, reduced-round attacks,
or the 1%/5% mutation lab. The trail-2 model of this exact round (with `S_mid`) proved 18 and 36
active S-boxes over 1 and 2 rounds. This folder re-runs those 1- and
2-round bounds on the implemented wiring. The mutation lab at 1% and 5%
is the next required check, and was not run here.
