//! Octavo N3 block function with a constant-time key schedule (format 0x1B; fix1 8-stroke bow).
//!
//! Same 16-round block function as draft-3 (S_mid after the bow). The key
//! schedule no longer uses rejection sampling; ciphertexts differ from draft-3.
//! Lab draft, not live N2.
//! Homemade; for real secrets use AES-GCM-SIV, age, or libsodium.

use sha2::{Digest, Sha256};

mod affine;
mod gf;
mod sbox_aff;
mod iso;
#[cfg(target_arch = "x86_64")]
mod gfni;
mod key_ct;
mod benes_soft;
mod fallback;
pub mod aead;

#[cfg(target_arch = "x86_64")]
use crate::gfni::GfniKey;
use crate::fallback::FbKey;
use crate::sbox_aff::KeyedSbox;

pub const NF: usize = 16;
pub const NB: usize = 8;
pub const NR: usize = 16;
pub const BLOCK_LEN: usize = 128;
pub const NONCE_LEN: usize = 16;
pub const SEED_LEN: usize = 128;
pub const FIELD_POLY: u16 = 0x1F5;
/// Domain-separation prefix for the constant-time key schedule.
pub const SPONGE_PREFIX: &[u8] = b"SN3C/";
/// Distinct format marker for this key schedule. Not interchangeable with
/// draft-3's 0x16 / 0x17 / 0x19. Absorbed into the sponge after the prefix.
pub const FORMAT_BYTE: u8 = 0x1B;

/// True when this CPU can run the AVX-512 GFNI data path.
pub fn gfni_available() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        crate::gfni::available()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// Data path choice (fallback1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    /// AVX-512 (F/BW/VL/VBMI) + GFNI: the perm1 path.
    Avx512Gfni,
    /// AVX2 + GFNI (VEX 256-bit), 4 blocks per pass.
    Avx2Gfni,
    /// AVX2 only, constant-time soft S-box, 4 blocks per pass.
    Avx2,
    /// Portable u64 SWAR, constant time, any CPU.
    Portable,
    /// Old lookup-table reference. NOT constant time; never auto-selected.
    Table,
}

impl Backend {
    pub const ALL: [Backend; 5] =
        [Backend::Avx512Gfni, Backend::Avx2Gfni, Backend::Avx2, Backend::Portable, Backend::Table];

    pub fn name(self) -> &'static str {
        match self {
            Backend::Avx512Gfni => "avx512gfni",
            Backend::Avx2Gfni => "avx2gfni",
            Backend::Avx2 => "avx2",
            Backend::Portable => "portable",
            Backend::Table => "table",
        }
    }

    pub fn parse(s: &str) -> Option<Backend> {
        match s.trim().to_ascii_lowercase().as_str() {
            "avx512gfni" | "avx512" | "gfni512" => Some(Backend::Avx512Gfni),
            "avx2gfni" | "gfni256" | "avx2+gfni" => Some(Backend::Avx2Gfni),
            "avx2" | "avx2soft" => Some(Backend::Avx2),
            "portable" | "swar" | "scalar" => Some(Backend::Portable),
            "table" | "reference" => Some(Backend::Table),
            _ => None,
        }
    }

    /// Whether this CPU can run the backend.
    pub fn supported(self) -> bool {
        match self {
            Backend::Avx512Gfni => gfni_available(),
            #[cfg(target_arch = "x86_64")]
            Backend::Avx2Gfni => {
                std::is_x86_feature_detected!("avx2")
                    && std::is_x86_feature_detected!("avx")
                    && std::is_x86_feature_detected!("gfni")
            }
            #[cfg(target_arch = "x86_64")]
            Backend::Avx2 => std::is_x86_feature_detected!("avx2"),
            #[cfg(not(target_arch = "x86_64"))]
            Backend::Avx2Gfni | Backend::Avx2 => false,
            Backend::Portable | Backend::Table => true,
        }
    }

    /// Fastest constant-time backend this CPU supports.
    pub fn best() -> Backend {
        for b in [Backend::Avx512Gfni, Backend::Avx2Gfni, Backend::Avx2] {
            if b.supported() {
                return b;
            }
        }
        Backend::Portable
    }

    /// `best()`, unless `OCTAVO_N3_BACKEND` names a supported backend.
    pub fn detect() -> Backend {
        if let Ok(v) = std::env::var("OCTAVO_N3_BACKEND") {
            match Backend::parse(&v) {
                Some(b) if b.supported() => return b,
                Some(b) => eprintln!(
                    "OCTAVO_N3_BACKEND={} not supported on this CPU; using {}",
                    b.name(),
                    Backend::best().name()
                ),
                None => eprintln!("OCTAVO_N3_BACKEND={v:?} not recognised; using auto"),
            }
        }
        Backend::best()
    }
}


/// Published SM4/SMS4 S-box, GB/T 32907-2016.
pub const SM4_SBOX: [u8; 256] = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
];

// fix1 (format 0x1B): 8-stroke bow, full diffusion in both directions (OHLO's choice over the
// 10-stroke sawtooth, kept in lab/sawtooth10).
const BOW_STROKES: [(usize, usize, usize); 8] =
    [(2, 3, 4), (5, 7, 1), (0, 7, 3), (4, 7, 6), (1, 6, 0), (1, 7, 2), (2, 5, 4), (0, 3, 1)];
const BOW_PRESSURE_ROT: [u32; 8] = [0; 8];
const BOW_ROT_BASE: u32 = 1;
const BOW_ROT_MOD: u32 = 7;
const BOW_R2_SHIFT: u32 = 3;
const TRIPLET_WINDOWS: [(usize, usize, usize); 6] = [
    (0, 1, 2),
    (1, 2, 3),
    (2, 3, 4),
    (3, 4, 5),
    (4, 5, 6),
    (5, 6, 7),
];

#[inline]
fn idx(face: usize, beat: usize) -> usize {
    8 * face + beat
}

fn mul_raw(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        b >>= 1;
        let hi = a & 0x80;
        a = a.wrapping_shl(1);
        if hi != 0 {
            a ^= FIELD_POLY as u8; // 0xF5 of the low 8 bits of 0x1F5
        }
    }
    p
}

/// Tables and public linear maps, filled once.
struct Field {
    mul: [[u8; 256]; 256],
    inv: [u8; 256],
    inv3: u8,
    chord: [[u8; 8]; 8],
    chord_inv: [[u8; 8]; 8],
    cross: [[u8; 16]; 16],
    cross_inv: [[u8; 16]; 16],
    trip: [[[u8; 3]; 3]; 6],
    trip_inv: [[[u8; 3]; 3]; 6],
}

impl Field {
    fn new() -> Self {
        let mut mul = [[0u8; 256]; 256];
        for a in 0..256 {
            for b in 0..256 {
                mul[a][b] = mul_raw(a as u8, b as u8);
            }
        }
        let mut inv = [0u8; 256];
        for a in 1..256 {
            let mut x = a as u8;
            for _ in 0..253 {
                x = mul[x as usize][a];
            }
            inv[a] = x;
            debug_assert_eq!(mul[a][x as usize], 1);
        }
        let mut f = Field {
            mul,
            inv,
            inv3: inv[3],
            chord: [[0; 8]; 8],
            chord_inv: [[0; 8]; 8],
            cross: [[0; 16]; 16],
            cross_inv: [[0; 16]; 16],
            trip: [[[0; 3]; 3]; 6],
            trip_inv: [[[0; 3]; 3]; 6],
        };
        f.chord = f.cauchy_8(&(0..8).collect::<Vec<_>>(), &(8..16).collect::<Vec<_>>());
        f.chord_inv = f.invert_n(&f.chord.iter().map(|r| r.to_vec()).collect::<Vec<_>>());
        let xs: Vec<u8> = (0..16).collect();
        let ys: Vec<u8> = (16..32).collect();
        f.cross = f.cauchy_16(&xs, &ys);
        f.cross_inv = f.invert_n(&f.cross.iter().map(|r| r.to_vec()).collect::<Vec<_>>());
        for t in 0..6 {
            let ys = [3 + 3 * t as u8, 4 + 3 * t as u8, 5 + 3 * t as u8];
            f.trip[t] = f.cauchy_3(&[0, 1, 2], &ys);
            f.trip_inv[t] = f.invert_3(&f.trip[t]);
        }
        f
    }

    #[inline]
    fn m(&self, a: u8, b: u8) -> u8 {
        self.mul[a as usize][b as usize]
    }

    fn cauchy(&self, xs: &[u8], ys: &[u8]) -> Vec<Vec<u8>> {
        xs.iter()
            .map(|&x| {
                ys.iter()
                    .map(|&y| {
                        let s = x ^ y;
                        assert!(s != 0);
                        self.inv[s as usize]
                    })
                    .collect()
            })
            .collect()
    }

    fn cauchy_8(&self, xs: &[u8], ys: &[u8]) -> [[u8; 8]; 8] {
        let m = self.cauchy(xs, ys);
        let mut out = [[0u8; 8]; 8];
        for i in 0..8 {
            out[i].copy_from_slice(&m[i]);
        }
        out
    }

    fn cauchy_16(&self, xs: &[u8], ys: &[u8]) -> [[u8; 16]; 16] {
        let m = self.cauchy(xs, ys);
        let mut out = [[0u8; 16]; 16];
        for i in 0..16 {
            out[i].copy_from_slice(&m[i]);
        }
        out
    }

    fn cauchy_3(&self, xs: &[u8], ys: &[u8]) -> [[u8; 3]; 3] {
        let m = self.cauchy(xs, ys);
        let mut out = [[0u8; 3]; 3];
        for i in 0..3 {
            out[i].copy_from_slice(&m[i]);
        }
        out
    }

    fn invert_n<const N: usize>(&self, m: &[Vec<u8>]) -> [[u8; N]; N] {
        let n = m.len();
        assert_eq!(n, N);
        let mut a = vec![vec![0u8; 2 * n]; n];
        for i in 0..n {
            for j in 0..n {
                a[i][j] = m[i][j];
            }
            a[i][n + i] = 1;
        }
        for col in 0..n {
            let piv = (col..n).find(|&i| a[i][col] != 0).expect("singular");
            a.swap(col, piv);
            let scale = self.inv[a[col][col] as usize];
            for j in 0..2 * n {
                a[col][j] = self.m(a[col][j], scale);
            }
            for i in 0..n {
                if i == col || a[i][col] == 0 {
                    continue;
                }
                let f = a[i][col];
                for j in 0..2 * n {
                    a[i][j] ^= self.m(f, a[col][j]);
                }
            }
        }
        let mut out = [[0u8; N]; N];
        for i in 0..n {
            out[i].copy_from_slice(&a[i][n..]);
        }
        out
    }

    fn invert_3(&self, m: &[[u8; 3]; 3]) -> [[u8; 3]; 3] {
        let v: Vec<Vec<u8>> = m.iter().map(|r| r.to_vec()).collect();
        self.invert_n(&v)
    }

    fn mat_vec(&self, rows: &[&[u8]], vec: &[u8], out: &mut [u8]) {
        for (i, row) in rows.iter().enumerate() {
            let mut acc = 0u8;
            for (j, &x) in vec.iter().enumerate() {
                acc ^= self.m(row[j], x);
            }
            out[i] = acc;
        }
    }
}

fn bitmat_apply(rows: &[u8; 8], x: u8) -> u8 {
    let mut out = 0u8;
    for i in 0..8 {
        if (rows[i] & x).count_ones() & 1 == 1 {
            out |= 1 << i;
        }
    }
    out
}

fn bitmat_invertible(rows: &[u8; 8]) -> bool {
    let mut work = *rows;
    let mut rank = 0;
    for bit in 0..8 {
        let mut piv = None;
        for i in rank..8 {
            if (work[i] >> bit) & 1 == 1 {
                piv = Some(i);
                break;
            }
        }
        let Some(piv) = piv else { continue };
        work.swap(rank, piv);
        for i in 0..8 {
            if i != rank && (work[i] >> bit) & 1 == 1 {
                work[i] ^= work[rank];
            }
        }
        rank += 1;
    }
    rank == 8
}

#[allow(dead_code)]
fn keyed_sbox(a1: &[u8; 8], b1: u8, a2: &[u8; 8], b2: u8) -> ([u8; 256], [u8; 256]) {
    let mut fwd = [0u8; 256];
    let mut inv = [0u8; 256];
    for x in 0..256 {
        let inner = bitmat_apply(a1, x as u8) ^ b1;
        let y = bitmat_apply(a2, SM4_SBOX[inner as usize]) ^ b2;
        fwd[x] = y;
        inv[y as usize] = x as u8;
    }
    fwd
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>()
        .len()
        .eq(&256)
        .then_some(())
        .expect("keyed S-box not bijective");
    (fwd, inv)
}

struct Sponge {
    domain: u8,
    seed: [u8; SEED_LEN],
    nonce: [u8; NONCE_LEN],
    ctr: u32,
    buf: Vec<u8>,
}

impl Sponge {
    fn new(domain: u8, seed: &[u8; SEED_LEN], nonce: &[u8; NONCE_LEN]) -> Self {
        Self {
            domain,
            seed: *seed,
            nonce: *nonce,
            ctr: 0,
            buf: Vec::new(),
        }
    }

    fn more(&mut self) {
        let mut h = Sha256::new();
        h.update(SPONGE_PREFIX);
        h.update([crate::FORMAT_BYTE]);
        h.update([self.domain]);
        h.update(self.ctr.to_be_bytes());
        h.update(self.seed);
        h.update(self.nonce);
        self.buf.extend_from_slice(&h.finalize());
        self.ctr += 1;
    }

    fn take(&mut self, n: usize) -> Vec<u8> {
        while self.buf.len() < n {
            self.more();
        }
        self.buf.drain(..n).collect()
    }

    fn take_n<const N: usize>(&mut self) -> [u8; N] {
        while self.buf.len() < N {
            self.more();
        }
        let mut a = [0u8; N];
        a.copy_from_slice(&self.buf[..N]);
        self.buf.drain(..N);
        a
    }

    #[allow(dead_code)]
    fn below(&mut self, n: u32) -> u32 {
        let lim = 256 - (256 % n);
        loop {
            let b = self.take(1)[0] as u32;
            if b < lim {
                return b % n;
            }
        }
    }

    #[allow(dead_code)]
    fn perm(&mut self, n: usize) -> Vec<u8> {
        let mut p: Vec<u8> = (0..n as u8).collect();
        for i in (1..n).rev() {
            let j = self.below((i + 1) as u32) as usize;
            p.swap(i, j);
        }
        p
    }
}

struct Round {
    rk: [u8; BLOCK_LEN],
    s: [u8; 256],
    si: [u8; 256],
    s2: [u8; 256],
    si2: [u8; 256],
    sm: [u8; 256],
    sim: [u8; 256],
    bridge: [u8; 64],
    ks: KeyedSbox,
    ks2: KeyedSbox,
    ksm: KeyedSbox,
}

pub struct Cipher {
    field: Field,
    rounds: Vec<Round>,
    white: [u8; BLOCK_LEN],
    #[cfg(target_arch = "x86_64")]
    gfni: Option<Box<GfniKey>>,
    fb: Option<Box<FbKey>>,
    backend: Backend,
}

impl Cipher {
    /// Key setup with the auto-selected backend (`Backend::detect()`).
    pub fn new(seed: &[u8; SEED_LEN], nonce: &[u8; NONCE_LEN]) -> Self {
        Self::with_backend(seed, nonce, Backend::detect()).expect("detected backend is supported")
    }

    /// Key setup forcing one backend. Errors if this CPU can't run it.
    pub fn with_backend(
        seed: &[u8; SEED_LEN],
        nonce: &[u8; NONCE_LEN],
        backend: Backend,
    ) -> Result<Self, String> {
        if !backend.supported() {
            return Err(format!("backend {} not supported on this CPU", backend.name()));
        }
        let field = Field::new();
        let mut sp = Sponge::new(b'K', seed, nonce);
        let mut rounds = Vec::with_capacity(NR);
        for _ in 0..NR {
            let rk = sp.take_n::<BLOCK_LEN>();
            let a1 = key_ct::gl2_from_bytes(&sp.take_n::<{ key_ct::GL2_LEN }>());
            let a2 = key_ct::gl2_from_bytes(&sp.take_n::<{ key_ct::GL2_LEN }>());
            let b = sp.take_n::<2>();
            let (s, si) = key_ct::keyed_sbox_ct(&a1, b[0], &a2, b[1]);
            let ks = KeyedSbox::new(&a1, b[0], &a2, b[1]);
            let a3 = key_ct::gl2_from_bytes(&sp.take_n::<{ key_ct::GL2_LEN }>());
            let a4 = key_ct::gl2_from_bytes(&sp.take_n::<{ key_ct::GL2_LEN }>());
            let b34 = sp.take_n::<2>();
            let (s2_raw, _) = key_ct::keyed_sbox_ct(&a3, b34[0], &a4, b34[1]);
            let t2 = key_ct::ct_tables_equal(&s, &s2_raw);
            let b4 = b34[1] ^ t2;
            let (s2, si2) = key_ct::keyed_sbox_ct(&a3, b34[0], &a4, b4);
            let ks2 = KeyedSbox::new(&a3, b34[0], &a4, b4);
            let a5 = key_ct::gl2_from_bytes(&sp.take_n::<{ key_ct::GL2_LEN }>());
            let a6 = key_ct::gl2_from_bytes(&sp.take_n::<{ key_ct::GL2_LEN }>());
            let b56 = sp.take_n::<2>();
            let (sm_raw, _) = key_ct::keyed_sbox_ct(&a5, b56[0], &a6, b56[1]);
            let dmid = key_ct::sbox_distinct_delta(&s, &s2, &sm_raw);
            let b6 = b56[1] ^ dmid;
            let (sm, sim) = key_ct::keyed_sbox_ct(&a5, b56[0], &a6, b6);
            let ksm = KeyedSbox::new(&a5, b56[0], &a6, b6);
            let tags = key_ct::tags_from_bytes::<64>(&sp.take_n::<{ key_ct::PERM64_LEN }>());
            let bridge = key_ct::shuffle_from_tags(&tags);
            rounds.push(Round {
                rk,
                s,
                si,
                s2,
                si2,
                sm,
                sim,
                bridge,
                ks,
                ks2,
                ksm,
            });
        }
        let white = sp.take_n::<BLOCK_LEN>();
        #[cfg(target_arch = "x86_64")]
        let gfni = if backend == Backend::Avx512Gfni {
            GfniKey::new(&field, &rounds, &white)
        } else {
            None
        };
        let fb = match backend {
            Backend::Avx2Gfni | Backend::Avx2 | Backend::Portable => {
                Some(FbKey::new(&field, &rounds, &white))
            }
            _ => None,
        };
        Ok(Cipher {
            field,
            rounds,
            white,
            #[cfg(target_arch = "x86_64")]
            gfni,
            fb,
            backend,
        })
    }

    /// Whether this cipher will use the GFNI / AVX-512 data path.
    pub fn uses_gfni(&self) -> bool {
        self.backend == Backend::Avx512Gfni
    }

    pub fn backend(&self) -> Backend {
        self.backend
    }

    fn run_blocks(&self, blocks: &mut [[u8; BLOCK_LEN]], enc: bool) {
        match self.backend {
            #[cfg(target_arch = "x86_64")]
            Backend::Avx512Gfni => {
                let g = self.gfni.as_ref().expect("gfni key");
                if enc {
                    g.encrypt_blocks(blocks)
                } else {
                    g.decrypt_blocks(blocks)
                }
            }
            #[cfg(target_arch = "x86_64")]
            Backend::Avx2Gfni => unsafe {
                fallback::avx2::gfni_blocks(self.fb.as_ref().expect("fb key"), blocks, enc)
            },
            #[cfg(target_arch = "x86_64")]
            Backend::Avx2 => unsafe {
                fallback::avx2::soft_blocks(self.fb.as_ref().expect("fb key"), blocks, enc)
            },
            Backend::Portable => {
                let k = self.fb.as_ref().expect("fb key");
                for b in blocks.iter_mut() {
                    if enc {
                        fallback::swar_encrypt(k, b)
                    } else {
                        fallback::swar_decrypt(k, b)
                    }
                }
            }
            _ => {
                for b in blocks.iter_mut() {
                    *b = if enc {
                        self.encrypt_block_portable_inner(b)
                    } else {
                        self.decrypt_block_portable_inner(b)
                    };
                }
            }
        }
    }

    pub fn encrypt_block_portable(&self, pt: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
        self.encrypt_block_portable_inner(pt)
    }

    pub fn decrypt_block_portable(&self, ct: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
        self.decrypt_block_portable_inner(ct)
    }

    /// Independent blocks, same schedule, on the selected backend.
    pub fn encrypt_blocks(&self, blocks: &mut [[u8; BLOCK_LEN]]) {
        self.run_blocks(blocks, true)
    }

    pub fn decrypt_blocks(&self, blocks: &mut [[u8; BLOCK_LEN]]) {
        self.run_blocks(blocks, false)
    }

    pub fn encrypt_block(&self, pt: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
        #[cfg(target_arch = "x86_64")]
        if let Some(g) = self.gfni.as_ref() {
            return g.encrypt_block(pt);
        }
        let mut b = [*pt];
        self.run_blocks(&mut b, true);
        b[0]
    }

    pub fn decrypt_block(&self, ct: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
        #[cfg(target_arch = "x86_64")]
        if let Some(g) = self.gfni.as_ref() {
            return g.decrypt_block(ct);
        }
        let mut b = [*ct];
        self.run_blocks(&mut b, false);
        b[0]
    }

    fn encrypt_block_portable_inner(&self, pt: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
        let mut g = *pt;
        for r in 0..NR {
            self.round_enc(&mut g, r);
        }
        xor_in_place(&mut g, &self.white);
        g
    }

    fn decrypt_block_portable_inner(&self, ct: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
        let mut g = *ct;
        xor_in_place(&mut g, &self.white);
        for r in (0..NR).rev() {
            self.round_dec(&mut g, r);
        }
        g
    }

    fn round_enc(&self, g: &mut [u8; BLOCK_LEN], r: usize) {
        let rk = &self.rounds[r];
        xor_in_place(g, &rk.rk);
        sub_bytes(g, &rk.s);
        self.chord(g, false);
        self.bridges(g, &rk.bridge, r, false);
        self.triplets(g, false);
        bow(g, false);
        sub_bytes(g, &rk.sm);
        self.cross(g, false);
        sub_bytes(g, &rk.s2);
    }

    fn round_dec(&self, g: &mut [u8; BLOCK_LEN], r: usize) {
        let rk = &self.rounds[r];
        sub_bytes(g, &rk.si2);
        self.cross(g, true);
        sub_bytes(g, &rk.sim);
        bow(g, true);
        self.triplets(g, true);
        self.bridges(g, &rk.bridge, r, true);
        self.chord(g, true);
        sub_bytes(g, &rk.si);
        xor_in_place(g, &rk.rk);
    }

    fn chord(&self, g: &mut [u8; BLOCK_LEN], inverse: bool) {
        let m: &[[u8; 8]; 8] = if inverse {
            &self.field.chord_inv
        } else {
            &self.field.chord
        };
        let rows: Vec<&[u8]> = m.iter().map(|r| r.as_slice()).collect();
        let apply_staffs = |g: &mut [u8; BLOCK_LEN], lo: usize| {
            for f in lo..lo + 8 {
                let mut v = [0u8; 8];
                v.copy_from_slice(&g[idx(f, 0)..idx(f, 0) + 8]);
                let mut out = [0u8; 8];
                self.field.mat_vec(&rows, &v, &mut out);
                g[idx(f, 0)..idx(f, 0) + 8].copy_from_slice(&out);
            }
        };
        let apply_faces = |g: &mut [u8; BLOCK_LEN], lo: usize| {
            for t in 0..NB {
                let mut v = [0u8; 8];
                for i in 0..8 {
                    v[i] = g[idx(lo + i, t)];
                }
                let mut out = [0u8; 8];
                self.field.mat_vec(&rows, &v, &mut out);
                for i in 0..8 {
                    g[idx(lo + i, t)] = out[i];
                }
            }
        };
        for lo in [0, 8] {
            if !inverse {
                apply_staffs(g, lo);
                apply_faces(g, lo);
            } else {
                apply_faces(g, lo);
                apply_staffs(g, lo);
            }
        }
    }

    fn bridges(&self, g: &mut [u8; BLOCK_LEN], bridge: &[u8; 64], r: usize, inverse: bool) {
        for c in 0..64 {
            let fi = c / NB;
            let ti = c % NB;
            let oc = bridge[c] as usize;
            let fo = oc / NB + 8;
            let to = oc % NB;
            let (ia, ib) = if r % 2 == 0 {
                (idx(fi, ti), idx(fo, to))
            } else {
                (idx(fo, to), idx(fi, ti))
            };
            let (u, v) = if inverse {
                self.mix2_inv(g[ia], g[ib])
            } else {
                self.mix2(g[ia], g[ib])
            };
            g[ia] = u;
            g[ib] = v;
        }
    }

    fn mix2(&self, u: u8, v: u8) -> (u8, u8) {
        (u ^ v, u ^ self.field.m(2, v))
    }

    fn mix2_inv(&self, a: u8, b: u8) -> (u8, u8) {
        let v = self.field.m(self.field.inv3, a ^ b);
        let u = a ^ v;
        (u, v)
    }

    fn triplets(&self, g: &mut [u8; BLOCK_LEN], inverse: bool) {
        let mats: &[[[u8; 3]; 3]; 6] = if inverse {
            &self.field.trip_inv
        } else {
            &self.field.trip
        };
        let order: Box<dyn Iterator<Item = usize>> = if inverse {
            Box::new((0..6).rev())
        } else {
            Box::new(0..6)
        };
        // Collect order first; applying per face for each t.
        let seq: Vec<usize> = order.collect();
        for f in 0..NF {
            for &t in &seq {
                let (i, j, k) = TRIPLET_WINDOWS[t];
                let v = [g[idx(f, i)], g[idx(f, j)], g[idx(f, k)]];
                let rows: Vec<&[u8]> = mats[t].iter().map(|r| r.as_slice()).collect();
                let mut out = [0u8; 3];
                self.field.mat_vec(&rows, &v, &mut out);
                g[idx(f, i)] = out[0];
                g[idx(f, j)] = out[1];
                g[idx(f, k)] = out[2];
            }
        }
    }

    fn cross(&self, g: &mut [u8; BLOCK_LEN], inverse: bool) {
        let m: &[[u8; 16]; 16] = if inverse {
            &self.field.cross_inv
        } else {
            &self.field.cross
        };
        let rows: Vec<&[u8]> = m.iter().map(|r| r.as_slice()).collect();
        for t in 0..NB {
            let mut v = [0u8; 16];
            for f in 0..NF {
                v[f] = g[idx(f, t)];
            }
            let mut out = [0u8; 16];
            self.field.mat_vec(&rows, &v, &mut out);
            for f in 0..NF {
                g[idx(f, t)] = out[f];
            }
        }
    }
}

fn xor_in_place(g: &mut [u8; BLOCK_LEN], k: &[u8; BLOCK_LEN]) {
    for i in 0..BLOCK_LEN {
        g[i] ^= k[i];
    }
}

fn sub_bytes(g: &mut [u8; BLOCK_LEN], box_: &[u8; 256]) {
    for b in g.iter_mut() {
        *b = box_[*b as usize];
    }
}

fn rotl8(x: u8, n: u32) -> u8 {
    let n = n & 7;
    if n == 0 {
        x
    } else {
        x.rotate_left(n)
    }
}

fn bow_stroke(u: u8, v: u8, p: u8) -> (u8, u8) {
    let r1 = BOW_ROT_BASE + (p as u32 % BOW_ROT_MOD);
    let r2 = BOW_ROT_BASE + ((p as u32 >> BOW_R2_SHIFT) % BOW_ROT_MOD);
    let u = u.wrapping_add(rotl8(v, r1));
    let v = v ^ rotl8(u, r2);
    (u, v)
}

fn unbow_stroke(u: u8, v: u8, p: u8) -> (u8, u8) {
    let r1 = BOW_ROT_BASE + (p as u32 % BOW_ROT_MOD);
    let r2 = BOW_ROT_BASE + ((p as u32 >> BOW_R2_SHIFT) % BOW_ROT_MOD);
    let v = v ^ rotl8(u, r2);
    let u = u.wrapping_sub(rotl8(v, r1));
    (u, v)
}

fn bow(g: &mut [u8; BLOCK_LEN], inverse: bool) {
    for f in 0..NF {
        let mut s = [0u8; 8];
        s.copy_from_slice(&g[idx(f, 0)..idx(f, 0) + 8]);
        if !inverse {
            for (stroke, &k) in BOW_STROKES.iter().zip(BOW_PRESSURE_ROT.iter()) {
                let (i, j, p) = *stroke;
                let (u, v) = bow_stroke(s[i], s[j], rotl8(s[p], k));
                s[i] = u;
                s[j] = v;
            }
        } else {
            for (stroke, &k) in BOW_STROKES.iter().zip(BOW_PRESSURE_ROT.iter()).rev() {
                let (i, j, p) = *stroke;
                let (u, v) = unbow_stroke(s[i], s[j], rotl8(s[p], k));
                s[i] = u;
                s[j] = v;
            }
        }
        g[idx(f, 0)..idx(f, 0) + 8].copy_from_slice(&s);
    }
}

#[cfg(test)]
mod branch;
#[cfg(test)]
mod fallback_tests;
#[cfg(test)]
mod aead_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_one() {
        let mut seed = [0u8; SEED_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        let mut pt = [0u8; BLOCK_LEN];
        for i in 0..SEED_LEN {
            seed[i] = (3u8.wrapping_mul(i as u8)).wrapping_add(7);
        }
        for i in 0..NONCE_LEN {
            nonce[i] = i as u8;
        }
        for i in 0..BLOCK_LEN {
            pt[i] = (5u8.wrapping_mul(i as u8)).wrapping_add(1);
        }
        let c = Cipher::new(&seed, &nonce);
        let ct = c.encrypt_block(&pt);
        let pt2 = c.decrypt_block(&ct);
        assert_eq!(pt, pt2);
        assert_ne!(pt, ct);
        let ct_p = c.encrypt_block_portable(&pt);
        assert_eq!(ct, ct_p, "GFNI and portable encrypt must match");
        assert_eq!(c.decrypt_block_portable(&ct_p), pt);
    }

    fn hex_to_arr<const N: usize>(s: &str) -> [u8; N] {
        let mut a = [0u8; N];
        for i in 0..N {
            a[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        a
    }

    fn parse_vector_records(raw: &str) -> Vec<[String; 5]> {
        let keys = ["name", "seed", "nonce", "pt", "ct"];
        let toks: Vec<&str> = raw.split('"').collect();
        let mut recs = Vec::new();
        let mut cur = [String::new(), String::new(), String::new(), String::new(), String::new()];
        let mut have = 0u8;
        let mut i = 0;
        while i + 2 < toks.len() {
            if let Some(idx) = keys.iter().position(|&x| x == toks[i]) {
                cur[idx] = toks[i + 2].to_string();
                have |= 1 << idx;
                if have == 0b11111 {
                    recs.push(cur.clone());
                    have = 0;
                }
            }
            i += 1;
        }
        recs
    }

    #[test]
    fn fix1_vectors_match_portable_and_gfni() {
        let raw = include_str!("../../vectors/fix1_vectors.json");
        let recs = parse_vector_records(raw);
        assert!(recs.len() >= 5, "parsed {} vectors", recs.len());
        for rec in &recs {
            let seed = hex_to_arr::<SEED_LEN>(&rec[1]);
            let nonce = hex_to_arr::<NONCE_LEN>(&rec[2]);
            let pt = hex_to_arr::<BLOCK_LEN>(&rec[3]);
            let ct_exp = hex_to_arr::<BLOCK_LEN>(&rec[4]);
            let c = Cipher::new(&seed, &nonce);
            let ct_p = c.encrypt_block_portable(&pt);
            assert_eq!(ct_p, ct_exp, "portable mismatch on {}", rec[0]);
            let ct = c.encrypt_block(&pt);
            assert_eq!(ct, ct_exp, "dispatch mismatch on {}", rec[0]);
            assert_eq!(c.decrypt_block(&ct), pt);
            assert_eq!(c.decrypt_block_portable(&ct_p), pt);
        }
    }

    #[test]
    fn random_10k_gfni_matches_portable() {
        let mut st = 0xC0FF_EE12_3456_7891u64;
        let mut next = || {
            st ^= st << 13;
            st ^= st >> 7;
            st ^= st << 17;
            st
        };
        let mut fill = |buf: &mut [u8]| {
            let mut i = 0;
            while i < buf.len() {
                let r = next().to_le_bytes();
                let n = (buf.len() - i).min(8);
                buf[i..i + n].copy_from_slice(&r[..n]);
                i += n;
            }
        };
        let mut n = 0usize;
        while n < 10_000 {
            let mut seed = [0u8; SEED_LEN];
            let mut nonce = [0u8; NONCE_LEN];
            fill(&mut seed);
            fill(&mut nonce);
            if seed.iter().all(|&b| b == 0) {
                seed[0] = 1;
            }
            let c = Cipher::new(&seed, &nonce);
            // 500 blocks per key, 20 keys
            for _ in 0..500 {
                let mut pt = [0u8; BLOCK_LEN];
                fill(&mut pt);
                let ct_p = c.encrypt_block_portable(&pt);
                let ct = c.encrypt_block(&pt);
                assert_eq!(ct, ct_p);
                assert_eq!(c.decrypt_block(&ct), pt);
                assert_eq!(c.decrypt_block_portable(&ct_p), pt);
                n += 1;
            }
        }
        assert_eq!(n, 10_000);
    }

    fn packed_width_match_portable(width: usize, seed_tag: u64) {
        let mut st = seed_tag;
        let mut next = || {
            st ^= st << 13;
            st ^= st >> 7;
            st ^= st << 17;
            st
        };
        let mut fill = |buf: &mut [u8]| {
            let mut i = 0;
            while i < buf.len() {
                let r = next().to_le_bytes();
                let n = (buf.len() - i).min(8);
                buf[i..i + n].copy_from_slice(&r[..n]);
                i += n;
            }
        };
        let mut seed = [0u8; SEED_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        fill(&mut seed);
        fill(&mut nonce);
        seed[0] |= 1;
        let c = Cipher::new(&seed, &nonce);
        let mut blocks = vec![[0u8; BLOCK_LEN]; width];
        let mut expect = vec![[0u8; BLOCK_LEN]; width];
        for b in 0..width {
            fill(&mut blocks[b]);
            expect[b] = c.encrypt_block_portable(&blocks[b]);
        }
        c.encrypt_blocks(&mut blocks);
        assert_eq!(blocks, expect, "encrypt_blocks width={width}");
        let cts = blocks.clone();
        let mut rec = cts.clone();
        c.decrypt_blocks(&mut rec);
        let mut rec_p = cts.clone();
        for b in 0..width {
            rec_p[b] = c.decrypt_block_portable(&cts[b]);
        }
        assert_eq!(rec, rec_p, "decrypt_blocks width={width}");
    }

    #[test]
    fn packed_4_and_8_match_portable() {
        packed_width_match_portable(4, 0x1111_2222_3333_4444);
        packed_width_match_portable(8, 0x1111_2222_3333_4445);
    }

    #[test]
    fn packed_16_and_32_and_remainders_match_portable() {
        packed_width_match_portable(16, 0x1111_2222_3333_4410);
        packed_width_match_portable(32, 0x1111_2222_3333_4420);
        // remainders exercise the dispatcher (32+8+4+1, 16+1, 5)
        packed_width_match_portable(5, 0x1111_2222_3333_4005);
        packed_width_match_portable(17, 0x1111_2222_3333_4017);
        packed_width_match_portable(45, 0x1111_2222_3333_4045);
    }

    #[test]
    fn packed_64_and_sliced_remainders_match_portable() {
        packed_width_match_portable(64, 0x1111_2222_3333_4464);
        packed_width_match_portable(32, 0x1111_2222_3333_4432); // sliced-32
        packed_width_match_portable(65, 0x1111_2222_3333_4065); // 64 + 1
        packed_width_match_portable(96, 0x1111_2222_3333_4096); // 64 + 32
        packed_width_match_portable(80, 0x1111_2222_3333_4080); // 64 + 16
    }

    fn ddt_max(box_: &[u8; 256]) -> u32 {
        let mut ddt = [[0u32; 256]; 256];
        for x in 0..256 {
            for dx in 0..256 {
                let dy = box_[x] ^ box_[x ^ dx];
                ddt[dx][dy as usize] += 1;
            }
        }
        let mut m = 0u32;
        for dx in 1..256 {
            for dy in 0..256 {
                if ddt[dx][dy] > m {
                    m = ddt[dx][dy];
                }
            }
        }
        m
    }

    #[test]
    fn key_schedule_sboxes_distinct_bijective_and_sm4_ddt() {
        let sm4_max = ddt_max(&SM4_SBOX);
        assert_eq!(sm4_max, 4, "unexpected SM4 DDT max {sm4_max}");
        let mut st = 0xA5A5_C3C3_1234_5678u64;
        let mut next = || {
            st ^= st << 13;
            st ^= st >> 7;
            st ^= st << 17;
            st
        };
        let mut fill = |buf: &mut [u8]| {
            let mut i = 0;
            while i < buf.len() {
                let r = next().to_le_bytes();
                let n = (buf.len() - i).min(8);
                buf[i..i + n].copy_from_slice(&r[..n]);
                i += n;
            }
        };
        // 32 random keys: every S/S2/S_mid bijective and pairwise distinct,
        // every bridge a permutation. DDT checked on the first 4 keys.
        for k in 0..32 {
            let mut seed = [0u8; SEED_LEN];
            let mut nonce = [0u8; NONCE_LEN];
            fill(&mut seed);
            fill(&mut nonce);
            seed[0] |= 1;
            let c = Cipher::new(&seed, &nonce);
            assert_eq!(c.rounds.len(), NR);
            for (r, rd) in c.rounds.iter().enumerate() {
                let mut seen = [false; 256];
                for x in 0..256 {
                    seen[rd.s[x] as usize] = true;
                    assert_eq!(rd.si[rd.s[x] as usize], x as u8);
                    assert_eq!(rd.si2[rd.s2[x] as usize], x as u8);
                    assert_eq!(rd.sim[rd.sm[x] as usize], x as u8);
                }
                assert!(seen.iter().all(|&b| b), "S not bijective r={r} k={k}");
                assert_ne!(rd.s, rd.s2, "S == S2 r={r} k={k}");
                assert_ne!(rd.s, rd.sm, "S == S_mid r={r} k={k}");
                assert_ne!(rd.s2, rd.sm, "S2 == S_mid r={r} k={k}");
                let mut got = [false; 64];
                for i in 0..64 {
                    got[rd.bridge[i] as usize] = true;
                }
                assert!(got.iter().all(|&b| b), "bridge not a perm r={r} k={k}");
            }
            if k < 4 {
                for rd in &c.rounds {
                    assert_eq!(ddt_max(&rd.s), sm4_max);
                    assert_eq!(ddt_max(&rd.s2), sm4_max);
                    assert_eq!(ddt_max(&rd.sm), sm4_max);
                }
            }
        }
    }
}
