//! StaffSponge: SHA-256(b"SN2/" || domain || counter32_be || seed || nonce), counter = 0,1,2,...

use sha2::{Digest, Sha256};

pub struct StaffSponge<'a> {
    domain: &'a [u8],
    seed: &'a [u8],
    nonce: &'a [u8],
    ctr: u32,
    buf: [u8; 32],
    pos: usize,
}

impl<'a> StaffSponge<'a> {
    pub fn new(domain: &'a [u8], seed: &'a [u8], nonce: &'a [u8]) -> Self {
        StaffSponge { domain, seed, nonce, ctr: 0, buf: [0; 32], pos: 32 }
    }

    fn more(&mut self) {
        let mut h = Sha256::new();
        h.update(b"SN2/");
        h.update(self.domain);
        h.update(self.ctr.to_be_bytes());
        h.update(self.seed);
        h.update(self.nonce);
        self.buf.copy_from_slice(&h.finalize());
        self.ctr += 1;
        self.pos = 0;
    }

    pub fn fill(&mut self, out: &mut [u8]) {
        for b in out.iter_mut() {
            if self.pos == 32 {
                self.more();
            }
            *b = self.buf[self.pos];
            self.pos += 1;
        }
    }

    pub fn byte(&mut self) -> u8 {
        let mut b = [0u8; 1];
        self.fill(&mut b);
        b[0]
    }

    pub fn take<const N: usize>(&mut self) -> [u8; N] {
        let mut o = [0u8; N];
        self.fill(&mut o);
        o
    }

    /// Unbiased integer in [0, n) by rejection on single bytes (n <= 256).
    pub fn below(&mut self, n: u32) -> u8 {
        let lim = 256 - 256 % n;
        loop {
            let b = self.byte() as u32;
            if b < lim {
                return (b % n) as u8;
            }
        }
    }

    /// Fisher-Yates (downward), identical to sneak_n2.StaffSponge.perm.
    pub fn perm<const N: usize>(&mut self) -> [u8; N] {
        let mut p = [0u8; N];
        for (i, v) in p.iter_mut().enumerate() {
            *v = i as u8;
        }
        let mut i = N - 1;
        while i > 0 {
            let j = self.below(i as u32 + 1) as usize;
            p.swap(i, j);
            i -= 1;
        }
        p
    }
}

/// One-shot squeeze of `out.len()` bytes.
/// Long outputs take the multi-buffer path in `sha_mb` (same bytes, tested against `StaffSponge`).
pub fn sponge(domain: &[u8], seed: &[u8], nonce: &[u8], out: &mut [u8]) {
    #[cfg(feature = "alloc")]
    if out.len() >= 256 {
        return crate::sha_mb::squeeze(domain, seed, nonce, out);
    }
    StaffSponge::new(domain, seed, nonce).fill(out);
}
