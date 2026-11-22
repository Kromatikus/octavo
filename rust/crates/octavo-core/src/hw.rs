//! Hardware S-box backends (x86-64): GFNI (512/256/128-bit) and AES-NI (+SSSE3).
//! Both are constant time: GF2P8AFFINE(INV)QB, AESENCLAST and PSHUFB have data-independent timing
//! and no memory lookups. Each batch call processes up to 64 bytes (one zmm / 2 ymm / 4 xmm).
#![allow(unsafe_code)]

use crate::iso::{AesForm, A_AES};
use crate::schedule::{RoundKey, Schedule};
use crate::NR;
use core::arch::x86_64::*;

// ------------------------------------------------------------------ GFNI
#[derive(Clone, Copy, Default)]
pub struct GfniForm {
    pre: u64,
    pre_c: u8,
    post: u64,
    post_c: u8,
}
impl GfniForm {
    fn new(f: &AesForm) -> Self {
        GfniForm { pre: crate::iso::gfni_qword(&f.p_mat), pre_c: f.p, post: crate::iso::gfni_qword(&f.q_mat), post_c: f.q }
    }
}
/// [round][S fwd, S2 fwd, S inv, S2 inv]
pub type GfniTables = [[GfniForm; 4]; NR];

pub fn gfni_tables(sch: &Schedule) -> GfniTables {
    let mut t = [[GfniForm::default(); 4]; NR];
    for (r, rk) in sch.rounds.iter().enumerate() {
        t[r] = [
            GfniForm::new(&AesForm::forward(&rk.s)),
            GfniForm::new(&AesForm::forward(&rk.s2)),
            GfniForm::new(&AesForm::inverse(&rk.s)),
            GfniForm::new(&AesForm::inverse(&rk.s2)),
        ];
    }
    t
}

#[target_feature(enable = "gfni,avx512f,avx512bw")]
unsafe fn gfni512(f: &GfniForm, buf: &mut [u8; 64]) {
    let x = _mm512_loadu_si512(buf.as_ptr() as *const _);
    let y = _mm512_xor_si512(_mm512_gf2p8affine_epi64_epi8::<0>(x, _mm512_set1_epi64(f.pre as i64)), _mm512_set1_epi8(f.pre_c as i8));
    let z = _mm512_xor_si512(_mm512_gf2p8affineinv_epi64_epi8::<0>(y, _mm512_set1_epi64(f.post as i64)), _mm512_set1_epi8(f.post_c as i8));
    _mm512_storeu_si512(buf.as_mut_ptr() as *mut _, z);
}

#[target_feature(enable = "gfni,avx")]
unsafe fn gfni256(f: &GfniForm, buf: &mut [u8; 64]) {
    let a = _mm256_set1_epi64x(f.pre as i64);
    let ac = _mm256_set1_epi8(f.pre_c as i8);
    let b = _mm256_set1_epi64x(f.post as i64);
    let bc = _mm256_set1_epi8(f.post_c as i8);
    for k in 0..2 {
        let p = buf.as_mut_ptr().add(32 * k) as *mut __m256i;
        let x = _mm256_loadu_si256(p);
        let y = _mm256_xor_si256(_mm256_gf2p8affine_epi64_epi8::<0>(x, a), ac);
        let z = _mm256_xor_si256(_mm256_gf2p8affineinv_epi64_epi8::<0>(y, b), bc);
        _mm256_storeu_si256(p, z);
    }
}

#[target_feature(enable = "gfni,sse2")]
unsafe fn gfni128(f: &GfniForm, buf: &mut [u8; 64]) {
    let a = _mm_set1_epi64x(f.pre as i64);
    let ac = _mm_set1_epi8(f.pre_c as i8);
    let b = _mm_set1_epi64x(f.post as i64);
    let bc = _mm_set1_epi8(f.post_c as i8);
    for k in 0..4 {
        let p = buf.as_mut_ptr().add(16 * k) as *mut __m128i;
        let x = _mm_loadu_si128(p);
        let y = _mm_xor_si128(_mm_gf2p8affine_epi64_epi8::<0>(x, a), ac);
        let z = _mm_xor_si128(_mm_gf2p8affineinv_epi64_epi8::<0>(y, b), bc);
        _mm_storeu_si128(p, z);
    }
}

// ------------------------------------------------------------------ AES-NI
/// Affine map L(x) ⊕ c as two 16-entry nibble tables for PSHUFB.
#[derive(Clone, Copy, Default)]
pub struct Nib {
    lo: [u8; 16],
    hi: [u8; 16],
}
impl Nib {
    fn new(m: &crate::affine::Mat8, c: u8) -> Nib {
        let mut n = Nib::default();
        for v in 0..16u8 {
            n.lo[v as usize] = m.apply(v) ^ c;
            n.hi[v as usize] = m.apply(v << 4);
        }
        n
    }
}
#[derive(Clone, Copy, Default)]
pub struct AesniForm {
    pre: Nib,
    post: Nib,
}
impl AesniForm {
    /// y = Q·inv_G(P·x ⊕ p) ⊕ q, with inv_G(z) = A^-1·SubBytes(z) ⊕ A^-1·0x63:
    /// y = (Q·A^-1)·SubBytes(P·x ⊕ p) ⊕ (Q·A^-1·0x63 ⊕ q)
    fn new(f: &AesForm) -> Self {
        let qa = f.q_mat.mul(&A_AES.inverse());
        AesniForm { pre: Nib::new(&f.p_mat, f.p), post: Nib::new(&qa, qa.apply(0x63) ^ f.q) }
    }
}
pub type AesniTables = [[AesniForm; 4]; NR];

pub fn aesni_tables(sch: &Schedule) -> AesniTables {
    let mut t = [[AesniForm::default(); 4]; NR];
    for (r, rk) in sch.rounds.iter().enumerate() {
        t[r] = [
            AesniForm::new(&AesForm::forward(&rk.s)),
            AesniForm::new(&AesForm::forward(&rk.s2)),
            AesniForm::new(&AesForm::inverse(&rk.s)),
            AesniForm::new(&AesForm::inverse(&rk.s2)),
        ];
    }
    t
}

/// AESENCLAST applies ShiftRows after SubBytes; this PSHUFB index undoes it so byte k stays at k.
const INV_SHIFT_ROWS: [u8; 16] = {
    let mut idx = [0u8; 16];
    let mut k = 0;
    while k < 16 {
        let r = k % 4;
        let c = k / 4;
        idx[k] = (r + 4 * ((c + 4 - r) % 4)) as u8;
        k += 1;
    }
    idx
};

#[target_feature(enable = "aes,ssse3,sse2")]
unsafe fn nib_apply(n: &Nib, x: __m128i) -> __m128i {
    let m = _mm_set1_epi8(0x0f);
    let lo = _mm_and_si128(x, m);
    let hi = _mm_and_si128(_mm_srli_epi16::<4>(x), m);
    _mm_xor_si128(
        _mm_shuffle_epi8(_mm_loadu_si128(n.lo.as_ptr() as *const _), lo),
        _mm_shuffle_epi8(_mm_loadu_si128(n.hi.as_ptr() as *const _), hi),
    )
}

#[target_feature(enable = "aes,ssse3,sse2")]
unsafe fn aesni64(f: &AesniForm, buf: &mut [u8; 64]) {
    let unshift = _mm_loadu_si128(INV_SHIFT_ROWS.as_ptr() as *const _);
    let zero = _mm_setzero_si128();
    for k in 0..4 {
        let p = buf.as_mut_ptr().add(16 * k) as *mut __m128i;
        let x = _mm_loadu_si128(p);
        let t = nib_apply(&f.pre, x);
        let u = _mm_shuffle_epi8(_mm_aesenclast_si128(t, zero), unshift);
        _mm_storeu_si128(p, nib_apply(&f.post, u));
    }
}

// ------------------------------------------------------------------ dispatch helpers
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HwKind {
    Gfni512,
    Gfni256,
    Gfni128,
    AesNi,
}

impl HwKind {
    #[cfg(feature = "std")]
    pub fn available(self) -> bool {
        match self {
            HwKind::Gfni512 => {
                std::is_x86_feature_detected!("gfni") && std::is_x86_feature_detected!("avx512f") && std::is_x86_feature_detected!("avx512bw")
            }
            HwKind::Gfni256 => std::is_x86_feature_detected!("gfni") && std::is_x86_feature_detected!("avx"),
            HwKind::Gfni128 => std::is_x86_feature_detected!("gfni"),
            HwKind::AesNi => std::is_x86_feature_detected!("aes") && std::is_x86_feature_detected!("ssse3"),
        }
    }
    #[cfg(not(feature = "std"))]
    pub fn available(self) -> bool {
        match self {
            HwKind::Gfni512 => cfg!(all(target_feature = "gfni", target_feature = "avx512f", target_feature = "avx512bw")),
            HwKind::Gfni256 => cfg!(all(target_feature = "gfni", target_feature = "avx")),
            HwKind::Gfni128 => cfg!(target_feature = "gfni"),
            HwKind::AesNi => cfg!(all(target_feature = "aes", target_feature = "ssse3")),
        }
    }
}

pub enum HwTables {
    Gfni(alloc::boxed::Box<GfniTables>),
    AesNi(alloc::boxed::Box<AesniTables>),
}

pub struct HwBackend {
    kind: HwKind,
    t: HwTables,
}

impl HwBackend {
    /// Returns None if the CPU lacks the features for `kind`.
    pub fn new(kind: HwKind, sch: &Schedule) -> Option<HwBackend> {
        if !kind.available() {
            return None;
        }
        let t = match kind {
            HwKind::AesNi => HwTables::AesNi(alloc::boxed::Box::new(aesni_tables(sch))),
            _ => HwTables::Gfni(alloc::boxed::Box::new(gfni_tables(sch))),
        };
        Some(HwBackend { kind, t })
    }
    pub fn kind(&self) -> HwKind {
        self.kind
    }
    #[inline]
    pub fn batch(&self, _rk: &RoundKey, r: usize, which: usize, xs: &mut [u8]) {
        for chunk in xs.chunks_mut(64) {
            let mut buf = [0u8; 64];
            buf[..chunk.len()].copy_from_slice(chunk);
            // SAFETY: HwBackend::new verified the CPU features for self.kind at runtime.
            unsafe {
                match (&self.t, self.kind) {
                    (HwTables::Gfni(t), HwKind::Gfni512) => gfni512(&t[r][which], &mut buf),
                    (HwTables::Gfni(t), HwKind::Gfni256) => gfni256(&t[r][which], &mut buf),
                    (HwTables::Gfni(t), _) => gfni128(&t[r][which], &mut buf),
                    (HwTables::AesNi(t), _) => aesni64(&t[r][which], &mut buf),
                }
            }
            chunk.copy_from_slice(&buf[..chunk.len()]);
        }
    }
}

// wipe the per-round S-box tables on drop (feature `zeroize`).
#[cfg(feature = "zeroize")]
impl Drop for HwBackend {
    fn drop(&mut self) {
        match &mut self.t {
            HwTables::Gfni(t) => crate::wipe::wipe_flat(&mut **t),
            HwTables::AesNi(t) => crate::wipe::wipe_flat(&mut **t),
        }
    }
}
