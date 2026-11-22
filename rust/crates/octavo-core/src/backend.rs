//! S-box backends. The round code is generic over `SboxBackend`, so a hardware path can be
//! dropped in later without touching the layers.
//!
//! - `CtSoft` (default): table-free, branch-free affine·inv·affine evaluation, bitsliced over
//!   64 lanes (u64 bit-planes). Constant time with respect to the data.
//! - `CtScalar`: the same math one byte at a time (constant time, slower; cross-check).
//! - `Table` (feature `table-backend`): precomputed 256-byte tables. NOT constant time
//!   (data-dependent memory lookups). Reference / speed comparison only.
//! - GFNI / AES-NI: phase 2 (features `gfni`, `aesni` are reserved hooks and do nothing yet).

use crate::schedule::{RoundKey, Schedule};
use crate::NR;

pub trait SboxBackend: Sized {
    /// Precompute whatever the backend needs for this schedule.
    fn prepare(sch: &Schedule) -> Self;
    /// Forward S-box of round `r`; `second == false` is S (A1/A2), `true` is S2 (A3/A4).
    fn s(&self, rk: &RoundKey, r: usize, second: bool, x: u8) -> u8;
    /// Inverse S-box.
    fn si(&self, rk: &RoundKey, r: usize, second: bool, y: u8) -> u8;
    /// Forward S-box on a batch of bytes (default: one at a time). Backends override this to
    /// process many lanes at once (bitslicing, SIMD, GFNI ...).
    #[inline(always)]
    fn s_batch(&self, rk: &RoundKey, r: usize, second: bool, xs: &mut [u8]) {
        for x in xs.iter_mut() {
            *x = self.s(rk, r, second, *x);
        }
    }
    /// Inverse S-box on a batch of bytes.
    #[inline(always)]
    fn si_batch(&self, rk: &RoundKey, r: usize, second: bool, ys: &mut [u8]) {
        for y in ys.iter_mut() {
            *y = self.si(rk, r, second, *y);
        }
    }
    /// Encrypt independent blocks under the same schedule. Default: one at a time through the
    /// generic layers. Full-round engines override this (and may interleave blocks).
    fn encrypt_blocks(&self, sch: &Schedule, blocks: &mut [[u8; 128]], rounds: usize) {
        for b in blocks.iter_mut() {
            crate::round::encrypt_block(sch, self, b, rounds);
        }
    }
    /// Decrypt independent blocks under the same schedule.
    fn decrypt_blocks(&self, sch: &Schedule, blocks: &mut [[u8; 128]], rounds: usize) {
        for b in blocks.iter_mut() {
            crate::round::decrypt_block(sch, self, b, rounds);
        }
    }
    /// Short name for diagnostics / benchmarks.
    const NAME: &'static str;
    /// Whether this backend is constant time with respect to the data.
    const CONSTANT_TIME: bool;
}

/// Portable constant-time software backend (default): bitsliced 64-lane batches.
#[derive(Clone, Copy, Default)]
pub struct CtSoft;

impl SboxBackend for CtSoft {
    fn prepare(_: &Schedule) -> Self {
        CtSoft
    }
    #[inline(always)]
    fn s(&self, rk: &RoundKey, _r: usize, second: bool, x: u8) -> u8 {
        if second { rk.s2.fwd(x) } else { rk.s.fwd(x) }
    }
    #[inline(always)]
    fn si(&self, rk: &RoundKey, _r: usize, second: bool, y: u8) -> u8 {
        if second { rk.s2.inv(y) } else { rk.s.inv(y) }
    }
    fn s_batch(&self, rk: &RoundKey, _r: usize, second: bool, xs: &mut [u8]) {
        crate::bitslice::sbox_slice(if second { &rk.s2 } else { &rk.s }, xs, false)
    }
    fn si_batch(&self, rk: &RoundKey, _r: usize, second: bool, ys: &mut [u8]) {
        crate::bitslice::sbox_slice(if second { &rk.s2 } else { &rk.s }, ys, true)
    }
    const NAME: &'static str = "ct-soft (bitsliced)";
    const CONSTANT_TIME: bool = true;
}

/// Portable constant-time scalar backend: one byte at a time, affine·x^254·affine.
#[derive(Clone, Copy, Default)]
pub struct CtScalar;

impl SboxBackend for CtScalar {
    fn prepare(_: &Schedule) -> Self {
        CtScalar
    }
    #[inline(always)]
    fn s(&self, rk: &RoundKey, _r: usize, second: bool, x: u8) -> u8 {
        if second { rk.s2.fwd(x) } else { rk.s.fwd(x) }
    }
    #[inline(always)]
    fn si(&self, rk: &RoundKey, _r: usize, second: bool, y: u8) -> u8 {
        if second { rk.s2.inv(y) } else { rk.s.inv(y) }
    }
    const NAME: &'static str = "ct-scalar";
    const CONSTANT_TIME: bool = true;
}

/// Lookup-table backend. NOT constant time.
#[cfg(feature = "table-backend")]
#[derive(Clone)]
pub struct Table {
    // [round][S, S2, SI, SI2][256]
    t: alloc::boxed::Box<[[[u8; 256]; 4]; NR]>,
}

#[cfg(feature = "table-backend")]
impl SboxBackend for Table {
    fn prepare(sch: &Schedule) -> Self {
        let mut t = alloc::boxed::Box::new([[[0u8; 256]; 4]; NR]);
        for (r, rk) in sch.rounds.iter().enumerate() {
            t[r][0] = rk.s.table();
            t[r][1] = rk.s2.table();
            for x in 0..256 {
                t[r][2][t[r][0][x] as usize] = x as u8;
                t[r][3][t[r][1][x] as usize] = x as u8;
            }
        }
        Table { t }
    }
    #[inline(always)]
    fn s(&self, _rk: &RoundKey, r: usize, second: bool, x: u8) -> u8 {
        self.t[r][second as usize][x as usize]
    }
    #[inline(always)]
    fn si(&self, _rk: &RoundKey, r: usize, second: bool, y: u8) -> u8 {
        self.t[r][2 + second as usize][y as usize]
    }
    const NAME: &'static str = "table (NOT constant time)";
    const CONSTANT_TIME: bool = false;
}

#[allow(dead_code)]
const _NR_USED: usize = NR;

// ======================================================================== runtime selection
/// Which S-box implementation an [`Auto`] backend uses.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum BackendKind {
    /// Full-round SIMD engine: GFNI S-boxes AND GFNI/AVX-512 (VBMI) linear layers, multi-block.
    GfniSimd = 6,
    /// GFNI on 512-bit zmm registers (AVX-512 F+BW), S-boxes only.
    Gfni512 = 1,
    /// GFNI on 256-bit ymm registers (AVX).
    Gfni256 = 2,
    /// GFNI on 128-bit xmm registers (SSE encoding).
    Gfni128 = 3,
    /// AES-NI AESENCLAST + SSSE3 PSHUFB nibble affines.
    AesNi = 4,
    /// Portable bitsliced constant-time software.
    CtSoft = 5,
}

impl BackendKind {
    pub const ALL: [BackendKind; 6] =
        [BackendKind::GfniSimd, BackendKind::Gfni512, BackendKind::Gfni256, BackendKind::Gfni128, BackendKind::AesNi, BackendKind::CtSoft];
    pub fn name(self) -> &'static str {
        match self {
            BackendKind::GfniSimd => "gfni-simd",
            BackendKind::Gfni512 => "gfni-512",
            BackendKind::Gfni256 => "gfni-256",
            BackendKind::Gfni128 => "gfni-128",
            BackendKind::AesNi => "aes-ni",
            BackendKind::CtSoft => "ct-soft",
        }
    }
    pub fn from_name(s: &str) -> Option<BackendKind> {
        BackendKind::ALL.into_iter().find(|k| k.name() == s)
    }
    #[cfg(all(target_arch = "x86_64", feature = "alloc"))]
    fn hw(self) -> Option<crate::hw::HwKind> {
        use crate::hw::HwKind;
        match self {
            BackendKind::GfniSimd => Some(HwKind::Gfni512),
            BackendKind::Gfni512 => Some(HwKind::Gfni512),
            BackendKind::Gfni256 => Some(HwKind::Gfni256),
            BackendKind::Gfni128 => Some(HwKind::Gfni128),
            BackendKind::AesNi => Some(HwKind::AesNi),
            BackendKind::CtSoft => None,
        }
    }
    /// Whether this CPU (and build) can run this backend.
    pub fn available(self) -> bool {
        #[cfg(all(target_arch = "x86_64", feature = "alloc"))]
        {
            match self.hw() {
                Some(h) => h.available() && (self != BackendKind::GfniSimd || crate::simd::available()),
                None => true,
            }
        }
        #[cfg(not(all(target_arch = "x86_64", feature = "alloc")))]
        {
            self == BackendKind::CtSoft
        }
    }
    /// Best available: GFNI-SIMD (full round), GFNI-512, GFNI-256, GFNI-128, AES-NI, then ct-soft.
    pub fn detect() -> BackendKind {
        BackendKind::ALL.into_iter().find(|k| k.available()).unwrap_or(BackendKind::CtSoft)
    }
}

#[cfg(feature = "std")]
std::thread_local! {
    static FORCED: core::cell::Cell<u8> = const { core::cell::Cell::new(0) };
}
#[cfg(not(feature = "std"))]
static FORCED: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

fn forced_raw() -> u8 {
    #[cfg(feature = "std")]
    {
        FORCED.with(|f| f.get())
    }
    #[cfg(not(feature = "std"))]
    {
        FORCED.load(core::sync::atomic::Ordering::SeqCst)
    }
}

/// Force every subsequently prepared [`Auto`] backend to `kind` (None = automatic). Per thread in
/// std builds (so parallel tests don't interfere), process-wide in no_std builds. Meant for tests
/// and benchmarks. Forcing an unavailable kind makes `Auto::prepare` panic.
pub fn force_backend(kind: Option<BackendKind>) {
    let v = kind.map_or(0, |k| k as u8);
    #[cfg(feature = "std")]
    FORCED.with(|f| f.set(v));
    #[cfg(not(feature = "std"))]
    FORCED.store(v, core::sync::atomic::Ordering::SeqCst);
}

/// The kind `Auto::prepare` will pick right now: forced kind, else env `OCTAVO_BACKEND`
/// (std builds), else [`BackendKind::detect`].
pub fn selected_backend() -> BackendKind {
    let f = forced_raw();
    if let Some(k) = BackendKind::ALL.into_iter().find(|k| *k as u8 == f) {
        return k;
    }
    #[cfg(feature = "std")]
    {
        static ENV: std::sync::OnceLock<Option<BackendKind>> = std::sync::OnceLock::new();
        if let Some(k) = *ENV.get_or_init(|| std::env::var("OCTAVO_BACKEND").ok().and_then(|s| BackendKind::from_name(&s))) {
            return k;
        }
    }
    BackendKind::detect()
}

/// Runtime-dispatching backend: GFNI, then AES-NI, then constant-time software.
pub struct Auto {
    kind: BackendKind,
    #[cfg(all(target_arch = "x86_64", feature = "alloc"))]
    hw: Option<crate::hw::HwBackend>,
    #[cfg(all(target_arch = "x86_64", feature = "alloc"))]
    simd: Option<alloc::boxed::Box<crate::simd::SimdKey>>,
}

impl Auto {
    pub fn kind(&self) -> BackendKind {
        self.kind
    }
}

impl SboxBackend for Auto {
    fn prepare(sch: &Schedule) -> Self {
        let kind = selected_backend();
        assert!(kind.available(), "Octavo backend {} is not available on this CPU/build", kind.name());
        #[cfg(all(target_arch = "x86_64", feature = "alloc"))]
        {
            let hw = kind.hw().map(|h| crate::hw::HwBackend::new(h, sch).expect("checked available"));
            let simd = if kind == BackendKind::GfniSimd {
                Some(crate::simd::SimdKey::new(sch).expect("checked available"))
            } else {
                None
            };
            Auto { kind, hw, simd }
        }
        #[cfg(not(all(target_arch = "x86_64", feature = "alloc")))]
        {
            let _ = sch;
            Auto { kind }
        }
    }
    #[inline(always)]
    fn s(&self, rk: &RoundKey, _r: usize, second: bool, x: u8) -> u8 {
        if second { rk.s2.fwd(x) } else { rk.s.fwd(x) }
    }
    #[inline(always)]
    fn si(&self, rk: &RoundKey, _r: usize, second: bool, y: u8) -> u8 {
        if second { rk.s2.inv(y) } else { rk.s.inv(y) }
    }
    #[inline]
    fn s_batch(&self, rk: &RoundKey, r: usize, second: bool, xs: &mut [u8]) {
        #[cfg(all(target_arch = "x86_64", feature = "alloc"))]
        if let Some(hw) = &self.hw {
            return hw.batch(rk, r, second as usize, xs);
        }
        CtSoft.s_batch(rk, r, second, xs)
    }
    #[inline]
    fn si_batch(&self, rk: &RoundKey, r: usize, second: bool, ys: &mut [u8]) {
        #[cfg(all(target_arch = "x86_64", feature = "alloc"))]
        if let Some(hw) = &self.hw {
            return hw.batch(rk, r, 2 + second as usize, ys);
        }
        CtSoft.si_batch(rk, r, second, ys)
    }
    fn encrypt_blocks(&self, sch: &Schedule, blocks: &mut [[u8; 128]], rounds: usize) {
        #[cfg(all(target_arch = "x86_64", feature = "alloc"))]
        if let Some(k) = &self.simd {
            return k.encrypt_blocks(blocks, rounds);
        }
        for b in blocks.iter_mut() {
            crate::round::encrypt_block(sch, self, b, rounds);
        }
    }
    fn decrypt_blocks(&self, sch: &Schedule, blocks: &mut [[u8; 128]], rounds: usize) {
        #[cfg(all(target_arch = "x86_64", feature = "alloc"))]
        if let Some(k) = &self.simd {
            return k.decrypt_blocks(blocks, rounds);
        }
        for b in blocks.iter_mut() {
            crate::round::decrypt_block(sch, self, b, rounds);
        }
    }
    const NAME: &'static str = "auto (gfni-simd > gfni > aes-ni > ct-soft)";
    const CONSTANT_TIME: bool = true;
}
