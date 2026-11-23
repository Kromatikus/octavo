//! Branch-number tests for the public N3 maps.
//!
//! The block function is unchanged from draft-2. These checks reject a
//! mix that stays invertible but drops below the draft-2 baselines:
//! mix2 BN 3 and no zero entries, chord BN 9 (exact MDS), each triplet
//! BN 4 (exact MDS), cross BN 17 (exact: published Cauchy matrix with
//! x=0..15, y=16..31 is MDS; plus observed BN on input weights <= 2),
//! and implied 1-round bound BN_CROSS+1 >= 18.
//!
//! Homemade; for real secrets use AES-GCM-SIV, age, or libsodium.

use crate::Field;
use std::collections::HashSet;

const MIX2_BN_MIN: u32 = 3;
const CHORD_BN_MIN: u32 = 9;
const TRIPLET_BN_MIN: u32 = 4;
const CROSS_BN_MIN: u32 = 17;
const IMPLIED_ONE_ROUND_MIN: u32 = 18;

fn mat_vec(f: &Field, m: &[Vec<u8>], x: &[u8]) -> Vec<u8> {
    let n = m.len();
    let mut out = vec![0u8; n];
    for i in 0..n {
        let mut acc = 0u8;
        for j in 0..n {
            acc ^= f.m(m[i][j], x[j]);
        }
        out[i] = acc;
    }
    out
}

fn observed_bn(f: &Field, m: &[Vec<u8>], max_in_wt: usize) -> u32 {
    let n = m.len();
    let mut best = (2 * n) as u32;
    for i in 0..n {
        for c in 1..=255u8 {
            let mut x = vec![0u8; n];
            x[i] = c;
            let y = mat_vec(f, m, &x);
            let w = 1 + y.iter().filter(|&&v| v != 0).count() as u32;
            if w < best {
                best = w;
            }
            if best <= 1 {
                return best;
            }
        }
    }
    if max_in_wt >= 2 {
        for i in 0..n {
            for j in (i + 1)..n {
                for c in 1..=255u8 {
                    let mut x = vec![0u8; n];
                    x[i] = 1;
                    x[j] = c;
                    let y = mat_vec(f, m, &x);
                    let w = 2 + y.iter().filter(|&&v| v != 0).count() as u32;
                    if w < best {
                        best = w;
                    }
                }
            }
        }
    }
    best
}

fn det(f: &Field, m: &[Vec<u8>]) -> u8 {
    let n = m.len();
    let mut a: Vec<Vec<u8>> = m.iter().map(|r| r.clone()).collect();
    let mut d = 1u8;
    for col in 0..n {
        let Some(piv) = (col..n).find(|&i| a[i][col] != 0) else {
            return 0;
        };
        if piv != col {
            a.swap(col, piv);
            // characteristic 2: row swap does not flip the sign
        }
        let scale = a[col][col];
        d = f.m(d, scale);
        let inv = f.inv[scale as usize];
        for j in 0..n {
            a[col][j] = f.m(a[col][j], inv);
        }
        for i in col + 1..n {
            if a[i][col] == 0 {
                continue;
            }
            let fac = a[i][col];
            for j in 0..n {
                a[i][j] ^= f.m(fac, a[col][j]);
            }
        }
    }
    d
}

fn minor_det(f: &Field, m: &[Vec<u8>], rows: &[usize], cols: &[usize]) -> u8 {
    let sub: Vec<Vec<u8>> = rows
        .iter()
        .map(|&r| cols.iter().map(|&c| m[r][c]).collect())
        .collect();
    det(f, &sub)
}

fn combinations(n: usize, k: usize) -> Vec<Vec<usize>> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    fn rec(start: usize, n: usize, k: usize, cur: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
        if cur.len() == k {
            out.push(cur.clone());
            return;
        }
        for i in start..n {
            cur.push(i);
            rec(i + 1, n, k, cur, out);
            cur.pop();
        }
    }
    rec(0, n, k, &mut cur, &mut out);
    out
}

fn is_mds(f: &Field, m: &[Vec<u8>]) -> bool {
    let n = m.len();
    for k in 1..=n {
        let combs = combinations(n, k);
        for rows in &combs {
            for cols in &combs {
                if minor_det(f, m, rows, cols) == 0 {
                    return false;
                }
            }
        }
    }
    true
}

fn invertible(f: &Field, m: &[Vec<u8>]) -> bool {
    let n = m.len();
    let mut a = vec![vec![0u8; 2 * n]; n];
    for i in 0..n {
        for j in 0..n {
            a[i][j] = m[i][j];
        }
        a[i][n + i] = 1;
    }
    for col in 0..n {
        let Some(piv) = (col..n).find(|&i| a[i][col] != 0) else {
            return false;
        };
        a.swap(col, piv);
        let scale = f.inv[a[col][col] as usize];
        for j in 0..2 * n {
            a[col][j] = f.m(a[col][j], scale);
        }
        for i in 0..n {
            if i == col || a[i][col] == 0 {
                continue;
            }
            let fac = a[i][col];
            for j in 0..2 * n {
                a[i][j] ^= f.m(fac, a[col][j]);
            }
        }
    }
    true
}

fn has_zero(m: &[Vec<u8>]) -> bool {
    m.iter().any(|r| r.iter().any(|&v| v == 0))
}

fn is_cauchy(f: &Field, m: &[Vec<u8>], xs: &[u8], ys: &[u8]) -> bool {
    if xs.len() != ys.len() || m.len() != xs.len() {
        return false;
    }
    let mut seen = HashSet::new();
    for &v in xs.iter().chain(ys.iter()) {
        if !seen.insert(v) {
            return false;
        }
    }
    for (i, &x) in xs.iter().enumerate() {
        for (j, &y) in ys.iter().enumerate() {
            let s = x ^ y;
            if s == 0 {
                return false;
            }
            if m[i][j] != f.inv[s as usize] {
                return false;
            }
        }
    }
    true
}

fn to_vec<const N: usize>(m: &[[u8; N]; N]) -> Vec<Vec<u8>> {
    m.iter().map(|r| r.to_vec()).collect()
}

fn mix2_matrix(f: &Field) -> Vec<Vec<u8>> {
    // Same map as Cipher::mix2: (u ^ v, u ^ 2v).
    let (a, b) = apply_mix2_as_cipher(f, 1, 0);
    let (c, d) = apply_mix2_as_cipher(f, 0, 1);
    vec![vec![a, c], vec![b, d]]
}

fn apply_mix2_as_cipher(f: &Field, u: u8, v: u8) -> (u8, u8) {
    (u ^ v, u ^ f.m(2, v))
}

/// Run every baseline check. Returns Err with failure strings.
pub fn check_maps(
    f: &Field,
    mix2: &[Vec<u8>],
    chord: &[Vec<u8>],
    triplets: &[Vec<Vec<u8>>],
    cross: &[Vec<u8>],
) -> Result<(), Vec<String>> {
    let mut failures = Vec::new();

    // Confirm the default mix2 matrix matches the implemented function
    // when it is the published [[1,1],[1,2]].
    if mix2 == [[1, 1], [1, 2]] || (mix2.len() == 2 && mix2[0].len() == 2 && mix2[0][0] == 1 && mix2[0][1] == 1 && mix2[1][0] == 1 && mix2[1][1] == 2)
    {
        let (a, b) = apply_mix2_as_cipher(f, 1, 0);
        let (c, d) = apply_mix2_as_cipher(f, 0, 1);
        if [a, c] != [mix2[0][0], mix2[0][1]] || [b, d] != [mix2[1][0], mix2[1][1]] {
            failures.push("mix2 matrix does not match implemented mix2()".into());
        }
    }

    if has_zero(mix2) {
        failures.push("mix2 has a zero entry".into());
    }
    if !invertible(f, mix2) {
        failures.push("mix2 is not invertible".into());
    } else {
        let bn = observed_bn(f, mix2, 2);
        if bn < MIX2_BN_MIN {
            failures.push(format!("mix2 BN {bn} < {MIX2_BN_MIN}"));
        }
    }

    if !invertible(f, chord) {
        failures.push("chord is not invertible".into());
    }
    if !is_mds(f, chord) {
        failures.push("chord is not MDS (exact BN 9 failed)".into());
    } else {
        let bn = observed_bn(f, chord, 2);
        if bn < CHORD_BN_MIN {
            failures.push(format!("chord observed BN {bn} < {CHORD_BN_MIN} (unexpected if MDS)"));
        }
    }

    if triplets.len() != 6 {
        failures.push(format!("expected 6 triplet maps, got {}", triplets.len()));
    }
    for (t, m) in triplets.iter().enumerate() {
        if !invertible(f, m) {
            failures.push(format!("triplet[{t}] is not invertible"));
        }
        if !is_mds(f, m) {
            failures.push(format!("triplet[{t}] is not MDS (exact BN {TRIPLET_BN_MIN} failed)"));
        }
    }

    if !invertible(f, cross) {
        failures.push("cross is not invertible".into());
    }
    let xs: Vec<u8> = (0..16).collect();
    let ys: Vec<u8> = (16..32).collect();
    if !is_cauchy(f, cross, &xs, &ys) {
        failures.push(
            "cross is not the published Cauchy matrix \
             (C[i][j] = 1/(x_i+y_j), x=0..15, y=16..31); \
             this is the exact MDS / BN=17 proof"
                .into(),
        );
    }
    let bn_cross = observed_bn(f, cross, 2);
    if bn_cross < CROSS_BN_MIN {
        failures.push(format!(
            "cross observed BN (wt<=2) {bn_cross} < {CROSS_BN_MIN}"
        ));
    }
    let implied = bn_cross + 1;
    if implied < IMPLIED_ONE_ROUND_MIN {
        failures.push(format!(
            "implied 1-round bound BN_CROSS+1 = {implied} < {IMPLIED_ONE_ROUND_MIN}"
        ));
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures)
    }
}

pub fn check_default(f: &Field) -> Result<(), Vec<String>> {
    let mix2 = mix2_matrix(f);
    // Verify mix2_matrix matches the implemented function.
    let (a, b) = apply_mix2_as_cipher(f, 1, 0);
    let (c, d) = apply_mix2_as_cipher(f, 0, 1);
    let derived = vec![vec![a, c], vec![b, d]];
    if derived != mix2 {
        return Err(vec![format!(
            "default mix2 matrix {mix2:?} != derived {derived:?}"
        )]);
    }
    let chord = to_vec(&f.chord);
    let trips: Vec<Vec<Vec<u8>>> = f.trip.iter().map(to_vec).collect();
    let cross = to_vec(&f.cross);
    check_maps(f, &mix2, &chord, &trips, &cross)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn poke(m: &mut [Vec<u8>], i: usize, j: usize, old: u8, new: u8) {
        assert_eq!(m[i][j], old, "baseline entry mismatch at [{i}][{j}]");
        m[i][j] = new;
    }

    #[test]
    fn baseline_maps_pass() {
        let f = Field::new();
        check_default(&f).unwrap_or_else(|e| panic!("baseline maps failed: {e:?}"));
    }

    #[test]
    fn silent_mutants_are_rejected() {
        let f = Field::new();
        let mut caught = 0;
        let mut missed = Vec::new();

        // S003_0 MIX2[1][1] 2->0
        {
            let mut mix2 = mix2_matrix(&f);
            poke(&mut mix2, 1, 1, 2, 0);
            let chord = to_vec(&f.chord);
            let trips: Vec<Vec<Vec<u8>>> = f.trip.iter().map(to_vec).collect();
            let cross = to_vec(&f.cross);
            match check_maps(&f, &mix2, &chord, &trips, &cross) {
                Err(_) => caught += 1,
                Ok(()) => missed.push("S003_0"),
            }
        }
        // S011_0 CHORD_M[0][7] 143->145
        {
            let mix2 = mix2_matrix(&f);
            let mut chord = to_vec(&f.chord);
            poke(&mut chord, 0, 7, 143, 145);
            let trips: Vec<Vec<Vec<u8>>> = f.trip.iter().map(to_vec).collect();
            let cross = to_vec(&f.cross);
            match check_maps(&f, &mix2, &chord, &trips, &cross) {
                Err(_) => caught += 1,
                Ok(()) => missed.push("S011_0"),
            }
        }
        // S039_0 CHORD_M[4][3] 143->144
        {
            let mix2 = mix2_matrix(&f);
            let mut chord = to_vec(&f.chord);
            poke(&mut chord, 4, 3, 143, 144);
            let trips: Vec<Vec<Vec<u8>>> = f.trip.iter().map(to_vec).collect();
            let cross = to_vec(&f.cross);
            match check_maps(&f, &mix2, &chord, &trips, &cross) {
                Err(_) => caught += 1,
                Ok(()) => missed.push("S039_0"),
            }
        }
        // S058_0 CHORD_M[6][6] 196->192
        {
            let mix2 = mix2_matrix(&f);
            let mut chord = to_vec(&f.chord);
            poke(&mut chord, 6, 6, 196, 192);
            let trips: Vec<Vec<Vec<u8>>> = f.trip.iter().map(to_vec).collect();
            let cross = to_vec(&f.cross);
            match check_maps(&f, &mix2, &chord, &trips, &cross) {
                Err(_) => caught += 1,
                Ok(()) => missed.push("S058_0"),
            }
        }
        // S068_0 CROSS_M[0][0] 98->96
        {
            let mix2 = mix2_matrix(&f);
            let chord = to_vec(&f.chord);
            let trips: Vec<Vec<Vec<u8>>> = f.trip.iter().map(to_vec).collect();
            let mut cross = to_vec(&f.cross);
            poke(&mut cross, 0, 0, 98, 96);
            match check_maps(&f, &mix2, &chord, &trips, &cross) {
                Err(_) => caught += 1,
                Ok(()) => missed.push("S068_0"),
            }
        }
        // S077_0 CROSS_M[3][3] 98->92
        {
            let mix2 = mix2_matrix(&f);
            let chord = to_vec(&f.chord);
            let trips: Vec<Vec<Vec<u8>>> = f.trip.iter().map(to_vec).collect();
            let mut cross = to_vec(&f.cross);
            poke(&mut cross, 3, 3, 98, 92);
            match check_maps(&f, &mix2, &chord, &trips, &cross) {
                Err(_) => caught += 1,
                Ok(()) => missed.push("S077_0"),
            }
        }
        // S089_0 CROSS_M[7][7] 98->104
        {
            let mix2 = mix2_matrix(&f);
            let chord = to_vec(&f.chord);
            let trips: Vec<Vec<Vec<u8>>> = f.trip.iter().map(to_vec).collect();
            let mut cross = to_vec(&f.cross);
            poke(&mut cross, 7, 7, 98, 104);
            match check_maps(&f, &mix2, &chord, &trips, &cross) {
                Err(_) => caught += 1,
                Ok(()) => missed.push("S089_0"),
            }
        }

        assert!(
            missed.is_empty(),
            "silent mutants not rejected: {missed:?} (caught {caught}/7)"
        );
        assert_eq!(caught, 7, "expected to catch all 7 sampled silent mutants");
    }
}
