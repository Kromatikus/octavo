//! fallback1: portable constant-time Benes router (no PEXT, no SIMD).
//!
//! Same looping algorithm and output as perm1's AVX-512 `benes_route`, written
//! with 64-bit SWAR scans: every secret-indexed lookup reads all 64 entries
//! and keeps the matching one with a mask. Fixed trip counts, no secret
//! branches, no secret addresses. Bit extraction uses public positions only,
//! so there is no PEXT (which is microcoded with data-dependent latency on
//! AMD Zen 1 / Zen 2).

const H: u64 = 0x8080_8080_8080_8080;
const LO7: u64 = 0x7F7F_7F7F_7F7F_7F7F;
const L1: u64 = 0x0101_0101_0101_0101;

const IDW: [u64; 8] = {
    let mut w = [0u64; 8];
    let mut i = 0;
    while i < 64 {
        w[i / 8] |= (i as u64) << (8 * (i % 8));
        i += 1;
    }
    w
};

/// 0xFF in each byte of z that is zero.
#[inline(always)]
fn zero_bytes(z: u64) -> u64 {
    let y = (z & LO7).wrapping_add(LO7);
    let hb = !(y | z | LO7) & H;
    (hb >> 7).wrapping_mul(0xFF)
}

#[inline(always)]
fn fold_byte(mut a: u64) -> u8 {
    a ^= a >> 32;
    a ^= a >> 16;
    a ^= a >> 8;
    a as u8
}

fn to_words(v: &[u8; 64]) -> [u64; 8] {
    let mut w = [0u64; 8];
    for i in 0..8 {
        let mut a = [0u8; 8];
        a.copy_from_slice(&v[8 * i..8 * i + 8]);
        w[i] = u64::from_le_bytes(a);
    }
    w
}

/// out[j] = v[idx[j] & 63], constant time in idx and v.
fn gather(idx: &[u8; 64], v: &[u8; 64]) -> [u8; 64] {
    let vw = to_words(v);
    let mut out = [0u8; 64];
    for j in 0..64 {
        let x = ((idx[j] & 63) as u64).wrapping_mul(L1);
        let mut acc = 0u64;
        for w in 0..8 {
            acc ^= vw[w] & zero_bytes(IDW[w] ^ x);
        }
        out[j] = fold_byte(acc);
    }
    out
}

/// Inverse permutation, constant time.
fn invert(s: &[u8; 64]) -> [u8; 64] {
    let sw = to_words(s);
    let mut out = [0u8; 64];
    for x in 0..64 {
        let xs = (x as u64).wrapping_mul(L1);
        let mut acc = 0u64;
        for w in 0..8 {
            acc ^= IDW[w] & zero_bytes(sw[w] ^ xs);
        }
        out[x] = fold_byte(acc);
    }
    out
}

#[inline(always)]
fn lt_mask(a: u8, b: u8) -> u8 {
    // 0xFF if a < b
    (((a as u16).wrapping_sub(b as u16)) >> 8) as u8
}

/// Benes switch bits for out[j] = in[src[j]]: bit k of word st = switch k of
/// stage st (strides 32,16,8,4,2,1,2,4,8,16,32).
pub(crate) fn benes_route_bits(src: &[u8; 64]) -> [u32; 11] {
    let mut s = *src;
    let mut bits = [0u32; 11];
    let (mut lo, mut hi) = (0usize, 10usize);
    let mut m = 32usize;
    while m >= 2 {
        let sinv = invert(&s);
        let mut sx = [0u8; 64];
        for j in 0..64 {
            sx[j] = sinv[j] ^ m as u8;
        }
        let mut f = gather(&sx, &s);
        for j in 0..64 {
            f[j] ^= m as u8;
        }
        let mut c = [0u8; 64];
        for j in 0..64 {
            c[j] = j as u8;
        }
        let mut g = f;
        for _ in 0..6 {
            let cg = gather(&g, &c);
            for j in 0..64 {
                let lt = lt_mask(cg[j], c[j]);
                c[j] ^= (c[j] ^ cg[j]) & lt;
            }
            g = gather(&g, &g);
        }
        // partner index j ^ m is public: direct reads are fine.
        let mut col = [0u8; 64]; // 0xFF = bottom subnet
        for j in 0..64 {
            col[j] = lt_mask(c[j ^ m], c[j]);
        }
        let cs = gather(&s, &col);
        let (mut b_lo, mut b_hi, mut k) = (0u32, 0u32, 0u32);
        for j in 0..64 {
            if j & m == 0 {
                b_lo |= ((col[j] & 1) as u32) << k;
                b_hi |= ((cs[j] & 1) as u32) << k;
                k += 1;
            }
        }
        bits[lo] = b_lo;
        bits[hi] = b_hi;
        let mut ns = [0u8; 64];
        for j in 0..64 {
            let low = if j & m == 0 { 0xFFu8 } else { 0 }; // public
            let sel = cs[j] ^ !low; // 0xFF -> take partner
            let pick = s[j] ^ ((s[j] ^ s[j ^ m]) & sel);
            ns[j] = ((j & !(m - 1)) as u8) | (pick & (m as u8 - 1));
        }
        s = ns;
        lo += 1;
        hi -= 1;
        m /= 2;
    }
    let mut b5 = 0u32;
    for k in 0..32 {
        let j = 2 * k;
        let ne = !(zero_bytes((s[j] ^ j as u8) as u64) as u8) & 1;
        b5 |= (ne as u32) << k;
    }
    bits[5] = b5;
    bits
}

/// PEXT with a *public* mask, branch-free in `x`. Used instead of the BMI2
/// instruction where that instruction is microcoded (AMD family 17h/18h).
#[allow(dead_code)]
#[inline]
pub(crate) fn pext_pub(x: u64, mask: u64) -> u64 {
    let mut r = 0u64;
    let mut k = 0u32;
    for i in 0..64 {
        if (mask >> i) & 1 == 1 {
            r |= ((x >> i) & 1) << k;
            k += 1;
        }
    }
    r
}

/// True when the BMI2 PEXT instruction is fast and data-independent here:
/// BMI2 present and not AMD/Hygon family 17h/18h (Zen 1, Zen+, Zen 2, Dhyana).
#[cfg(target_arch = "x86_64")]
pub(crate) fn hw_pext_ok() -> bool {
    // CPUID is slow (and traps under a hypervisor): decide once, cache.
    static CACHE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *CACHE.get_or_init(|| std::is_x86_feature_detected!("bmi2") && !amd_slow_pext())
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn amd_slow_pext() -> bool {
    use core::arch::x86_64::__cpuid;
    let v = unsafe { __cpuid(0) };
    let mut vendor = [0u8; 12];
    vendor[0..4].copy_from_slice(&v.ebx.to_le_bytes());
    vendor[4..8].copy_from_slice(&v.edx.to_le_bytes());
    vendor[8..12].copy_from_slice(&v.ecx.to_le_bytes());
    let amd = &vendor == b"AuthenticAMD" || &vendor == b"HygonGenuine";
    if !amd {
        return false;
    }
    let l1 = unsafe { __cpuid(1) };
    let base = (l1.eax >> 8) & 0xF;
    let ext = (l1.eax >> 20) & 0xFF;
    let family = if base == 0xF { base + ext } else { base };
    family == 0x17 || family == 0x18
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pext_pub_matches_definition() {
        let mut x = 0x0123_4567_89AB_CDEFu64;
        for _ in 0..1000 {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let m = x.rotate_left(17) ^ 0x5555_0000_FFFF_00F0;
            let mut want = 0u64;
            let mut k = 0;
            for i in 0..64 {
                if m >> i & 1 == 1 {
                    want |= (x >> i & 1) << k;
                    k += 1;
                }
            }
            assert_eq!(pext_pub(x, m), want);
        }
    }

    #[test]
    fn gather_invert_ok() {
        let mut p = [0u8; 64];
        for i in 0..64 {
            p[i] = ((i * 37 + 11) % 64) as u8;
        }
        let inv = invert(&p);
        for i in 0..64 {
            assert_eq!(inv[p[i] as usize] as usize, i);
        }
        let v: [u8; 64] = core::array::from_fn(|i| (i as u8).wrapping_mul(7) ^ 0xA5);
        let g = gather(&p, &v);
        for j in 0..64 {
            assert_eq!(g[j], v[p[j] as usize]);
        }
    }
}
