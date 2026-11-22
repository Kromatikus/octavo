//! Hardware backends vs the constant-time software S-box: exhaustive on all 256 inputs for every
//! keyed S-box (S, S2 and both inverses, all 16 rounds) of several schedules, plus whole-block
//! agreement of every available backend on random inputs.

use octavo_core::{force_backend, BackendKind, Cipher, CtSoft, Schedule};

struct X(u64);
impl X {
    fn next(&mut self) -> u8 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 >> 32) as u8
    }
    fn fill(&mut self, b: &mut [u8]) {
        for x in b {
            *x = self.next();
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[test]
fn hw_sboxes_exhaustive() {
    use octavo_core::hw::{HwBackend, HwKind};
    let mut rng = X(0x9e3779b97f4a7c15);
    for kind in [HwKind::Gfni512, HwKind::Gfni256, HwKind::Gfni128, HwKind::AesNi] {
        if !kind.available() {
            println!("SKIP {:?} (untested: CPU lacks it)", kind);
            continue;
        }
        let mut count = 0;
        for _ in 0..6 {
            let mut seed = [0u8; 128];
            let mut nonce = [0u8; 16];
            rng.fill(&mut seed);
            rng.fill(&mut nonce);
            let sch = Schedule::new(&seed, &nonce);
            let hw = HwBackend::new(kind, &sch).unwrap();
            for (r, rk) in sch.rounds.iter().enumerate() {
                for which in 0..4 {
                    let mut xs: Vec<u8> = (0..=255u8).collect();
                    hw.batch(rk, r, which, &mut xs);
                    for x in 0..256usize {
                        let want = match which {
                            0 => rk.s.fwd(x as u8),
                            1 => rk.s2.fwd(x as u8),
                            2 => rk.s.inv(x as u8),
                            _ => rk.s2.inv(x as u8),
                        };
                        assert_eq!(xs[x], want, "{kind:?} round {r} which {which} x {x}");
                    }
                    // short (tail) batches too
                    let mut short = [x_of(r), 0xff, 0x00, 0x80, 0x01];
                    let orig = short;
                    hw.batch(rk, r, which, &mut short[..]);
                    for i in 0..5 {
                        let w = match which { 0 => rk.s.fwd(orig[i]), 1 => rk.s2.fwd(orig[i]), 2 => rk.s.inv(orig[i]), _ => rk.s2.inv(orig[i]) };
                        assert_eq!(short[i], w);
                    }
                    count += 1;
                }
            }
        }
        println!("{kind:?}: {count} keyed S-box tables x 256 inputs match the software S-box");
    }
}
fn x_of(r: usize) -> u8 {
    (r * 37) as u8
}

#[test]
fn backends_agree_on_random_blocks() {
    let mut rng = X(0x0123_4567_89ab_cdef);
    let kinds: Vec<_> = BackendKind::ALL.into_iter().filter(|k| k.available()).collect();
    println!("available backends: {:?}", kinds.iter().map(|k| k.name()).collect::<Vec<_>>());
    for case in 0..60 {
        let mut seed = [0u8; 128];
        let mut nonce = [0u8; 16];
        let mut pt = [0u8; 128];
        rng.fill(&mut seed);
        rng.fill(&mut nonce);
        rng.fill(&mut pt);
        let rounds = [16, 16, 2, 4, 6, 1 + case % 16][case % 6];
        let soft: Cipher<CtSoft> = Cipher::with_rounds(&seed, &nonce, rounds);
        let mut want = pt;
        soft.encrypt_block(&mut want);
        for &k in &kinds {
            force_backend(Some(k));
            let c: Cipher = Cipher::with_rounds(&seed, &nonce, rounds);
            let mut x = pt;
            c.encrypt_block(&mut x);
            assert_eq!(x, want, "backend {} case {case}", k.name());
            c.decrypt_block(&mut x);
            assert_eq!(x, pt, "backend {} decrypt case {case}", k.name());
        }
    }
    force_backend(None);
}

#[test]
fn multi_block_matches_single_block_every_backend() {
    let mut rng = X(0xdead_beef_0bad_f00d);
    let kinds: Vec<_> = BackendKind::ALL.into_iter().filter(|k| k.available()).collect();
    for case in 0..12 {
        let mut seed = [0u8; 128];
        let mut nonce = [0u8; 16];
        rng.fill(&mut seed);
        rng.fill(&mut nonce);
        let rounds = [16, 2, 4, 6, 16, 9][case % 6];
        let nblk = [1usize, 2, 3, 4, 5, 7, 8, 9, 13, 16, 17, 33][case];
        let mut pts = vec![[0u8; 128]; nblk];
        for p in pts.iter_mut() {
            rng.fill(p);
        }
        let soft: Cipher<CtSoft> = Cipher::with_rounds(&seed, &nonce, rounds);
        let want: Vec<[u8; 128]> = pts
            .iter()
            .map(|p| {
                let mut x = *p;
                soft.encrypt_block(&mut x);
                x
            })
            .collect();
        for &k in &kinds {
            force_backend(Some(k));
            let c: Cipher = Cipher::with_rounds(&seed, &nonce, rounds);
            let mut x = pts.clone();
            c.encrypt_blocks(&mut x);
            assert_eq!(x, want, "{} n={nblk}", k.name());
            c.decrypt_blocks(&mut x);
            assert_eq!(x, pts, "{} decrypt n={nblk}", k.name());
        }
    }
    force_backend(None);
}

#[cfg(feature = "parallel")]
#[test]
fn threaded_rehearsal_identical_bytes() {
    use octavo_core::formats;
    let mut rng = X(0x5eed);
    let mut seed = [0u8; 128];
    rng.fill(&mut seed);
    for (cs, len) in [(128usize, 0usize), (128, 5000), (1024, 70_001), (4096, 4096 * 9), (65536, 300_000)] {
        let mut msg = vec![0u8; len];
        rng.fill(&mut msg);
        force_backend(Some(BackendKind::CtSoft));
        let (want, wtag) = formats::seal_rehearsal(&seed, &msg, &[3; 16], &[4; 16], cs, b"ad").unwrap();
        for k in BackendKind::ALL.into_iter().filter(|k| k.available()) {
            force_backend(Some(k));
            for threads in [1usize, 2, 3, 8] {
                let (b, t) = formats::seal_rehearsal_threads(&seed, &msg, &[3; 16], &[4; 16], cs, b"ad", threads).unwrap();
                assert!(b == want && t == wtag, "{} threads={threads} cs={cs} len={len}", k.name());
                assert_eq!(formats::open_rehearsal_threads(&seed, &b, b"ad", threads).unwrap(), msg);
                let mut bad = b.clone();
                let pos = bad.len() / 3;
                bad[pos] ^= 0x10;
                assert!(formats::open_rehearsal_threads(&seed, &bad, b"ad", threads).is_err());
            }
        }
    }
    force_backend(None);
}
