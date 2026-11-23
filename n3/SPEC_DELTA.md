# N3 spec delta for draft-2

This file records what changed relative to `/workspace/octavo_n3_spec/N3_SPEC.md`.
That spec file was **not** edited. Live N2, draft-1, trail folders, freezes, and
the repo were not edited either.

Homemade; for real secrets use AES-GCM-SIV, age, or libsodium.

## Round

The written spec's slimmer round was:

```
g ^= rk_r ; g = S_r[g] ; chord ; bridges ; triplets ; bow ; cross
g = S2_r[g]
```

Draft-2, following the trail-2 "restored S-box after the bow" variant, is:

```
g ^= rk_r ; g = S_r[g] ; chord ; bridges ; triplets ; bow
g = S_mid_r[g] ; cross ; g = S2_r[g]
# after last round: g ^= white
```

`S_mid` is a keyed SM4-affine S-box of the same form as `S` and `S2`:

```
S_mid(x) = A6 · SM4[A5 · x ⊕ b5] ⊕ b6
```

`A5` and `A6` are invertible 8×8 bit-matrices; `b5` and `b6` are bytes. The
bit-matrix convention is the same as N2 / draft-1.

There are three S-box layers per round (384 S-boxes counted in the trail
model). Decrypt applies the inverses in reverse: `S2⁻¹`, `cross⁻¹`,
`S_mid⁻¹`, `bow⁻¹`, then the rest as in draft-1.

## Why

The trail-1 search on the slimmer draft-1 round only proved 2 active S-boxes
per round under a conservative bow model; the tightened trail-2 search raised
that to 6, still weaker than N2's 12–15. The same model with `S_mid` after
the bow proved 18 per round (36 over two rounds), a 256-bit margin slightly
better than N2. That variant is what this draft implements.

## Key schedule

Unchanged up through `S2`. After `S2` is accepted (`S2 ≠ S`), the sponge
draws `A5`/`A6`/`b5`/`b6` (invertible-matrix retries as usual) and resamples
until `S_mid ≠ S` and `S_mid ≠ S2`. Then 128-byte `white`, as before.

Drawing `S_mid` *after* `S2` keeps `rk`, `S`, unused `SH`/`SV`/`sigma`,
`bridge`, and `S2` in the same stream positions as draft-1 and N2 for the
same seed and nonce. Only `white` (and anything after) shifts.

The sponge prefix remains `SN3/`. Version tags `SN3` and `0x16` / `0x17` /
`0x19` are unchanged in the written spec; this piece is still the block
function only (no chaining).

## What is unchanged

Block size, 16 rounds, field `0x1F5`, `chord`, shell bridges, experimental
GF-linear triplets, bow, folded 16×16 `cross`, motif, and earworm length.
The public unkeyed S-box and the `0x11B` field switch stay dropped / deferred.
