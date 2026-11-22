//! proptest-based fuzzing of the open/parse path (streaming v9 open + key-file parser).
//! Quick run: `cargo test --release -p octavo-cli --test fuzz_open`.
//! Timed run: `OCTAVO_FUZZ_SECS=180 cargo test --release -p octavo-cli --test fuzz_open -- --ignored --nocapture`.
//! Properties: never panics; a mutated stream is accepted only if it equals the original blob
//! (any other accepted input would be a forgery); accepted output equals the sealed message.
mod common;
use common::*;
use octavo_cli::{open_stream, seal_stream, StreamOptions};
use proptest::prelude::*;
use proptest::test_runner::{Config, TestCaseError, TestRunner};
use std::sync::OnceLock;

struct Fixture {
    seed: [u8; 128],
    blobs: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>, // (blob, msg, ad)
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let mut rng = Rng(0xf022);
        let seed = good_seed(&mut rng);
        let mut blobs = Vec::new();
        for &(len, cs, ad) in &[(0usize, 128usize, &b""[..]), (100, 128, b"a"), (300, 128, b""), (700, 256, b"ad"), (2000, 512, b""), (130, 128, b"z")] {
            let msg = rng.bytes(len);
            let mut out = Vec::new();
            seal_stream(&seed, &mut &msg[..], &mut out, &[1; 16], &[2; 16], ad, &StreamOptions { chunk_size: cs, threads: 1, batch_chunks: 2 }).unwrap();
            blobs.push((out, msg, ad.to_vec()));
        }
        Fixture { seed, blobs }
    })
}

#[derive(Debug, Clone)]
enum Mut {
    Flip(usize, u8),
    Set(usize, u8),
    Insert(usize, Vec<u8>),
    Delete(usize, usize),
    Truncate(usize),
    Append(Vec<u8>),
    SetChunkSize(u32),
    Splice(usize, usize, usize),
}

fn mut_strategy() -> impl Strategy<Value = Mut> {
    prop_oneof![
        (any::<usize>(), 1u8..=255).prop_map(|(i, b)| Mut::Flip(i, b)),
        (any::<usize>(), any::<u8>()).prop_map(|(i, b)| Mut::Set(i, b)),
        (any::<usize>(), proptest::collection::vec(any::<u8>(), 1..300)).prop_map(|(i, v)| Mut::Insert(i, v)),
        (any::<usize>(), 1usize..400).prop_map(|(i, n)| Mut::Delete(i, n)),
        any::<usize>().prop_map(Mut::Truncate),
        proptest::collection::vec(any::<u8>(), 1..300).prop_map(Mut::Append),
        prop_oneof![Just(0u32), Just(127), Just(128), Just(256), Just(512), Just(1 << 20), Just((1 << 20) + 128), Just(u32::MAX), any::<u32>()].prop_map(Mut::SetChunkSize),
        (any::<usize>(), any::<usize>(), 1usize..600).prop_map(|(a, b, n)| Mut::Splice(a, b, n)),
    ]
}

fn apply(b: &mut Vec<u8>, m: &Mut) {
    let l = b.len().max(1);
    match m {
        Mut::Flip(i, x) => {
            if !b.is_empty() {
                let i = i % b.len();
                b[i] ^= x;
            }
        }
        Mut::Set(i, x) => {
            if !b.is_empty() {
                let i = i % b.len();
                b[i] = *x;
            }
        }
        Mut::Insert(i, v) => {
            let i = i % (b.len() + 1);
            b.splice(i..i, v.iter().copied());
        }
        Mut::Delete(i, n) => {
            if !b.is_empty() {
                let i = i % b.len();
                let e = (i + n).min(b.len());
                b.drain(i..e);
            }
        }
        Mut::Truncate(n) => b.truncate(n % l),
        Mut::Append(v) => b.extend_from_slice(v),
        Mut::SetChunkSize(c) => {
            if b.len() >= 72 {
                b[68..72].copy_from_slice(&c.to_be_bytes());
            }
        }
        Mut::Splice(a, c, n) => {
            if !b.is_empty() {
                let a = a % b.len();
                let c = c % b.len();
                let n = (*n).min(b.len() - a).min(b.len() - c);
                let src = b[a..a + n].to_vec();
                b[c..c + n].copy_from_slice(&src);
            }
        }
    }
}

fn open(seed: &[u8; 128], blob: &[u8], ad: &[u8], th: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    open_stream(seed, &mut &blob[..], &mut out, ad, &StreamOptions { chunk_size: 0, threads: th, batch_chunks: 2 }).ok().map(|_| out)
}

fn check_mutated(which: usize, muts: &[Mut], th: usize) -> Result<(), TestCaseError> {
    let f = fixture();
    let (blob, msg, ad) = &f.blobs[which % f.blobs.len()];
    let mut b = blob.clone();
    for m in muts {
        apply(&mut b, m);
    }
    match open(&f.seed, &b, ad, th) {
        Some(out) => {
            prop_assert!(&b == blob, "FORGERY: mutated blob accepted: {:?}", muts);
            prop_assert_eq!(&out, msg);
        }
        None => prop_assert!(&b != blob, "original blob rejected"),
    }
    Ok(())
}

fn check_random(data: &[u8], prefix_v9: bool) -> Result<(), TestCaseError> {
    let f = fixture();
    let mut b = data.to_vec();
    if prefix_v9 && b.len() >= 4 {
        b[..4].copy_from_slice(b"\x09SN2");
    }
    prop_assert!(open(&f.seed, &b, b"", 1).is_none(), "random bytes accepted");
    let _ = octavo_cli::parse_seed_text(data);
    Ok(())
}

fn muts() -> impl Strategy<Value = (usize, Vec<Mut>, usize)> {
    (0usize..6, proptest::collection::vec(mut_strategy(), 1..4), 1usize..4)
}
fn randoms() -> impl Strategy<Value = (Vec<u8>, bool)> {
    (proptest::collection::vec(any::<u8>(), 0..3000), any::<bool>())
}

proptest! {
    #![proptest_config(Config { cases: 512, ..Config::default() })]
    #[test]
    fn mutated_streams_never_forge((w, m, th) in muts()) { check_mutated(w, &m, th)?; }
    #[test]
    fn random_bytes_never_open((d, p) in randoms()) { check_random(&d, p)?; }
}

/// Time-bounded fuzz loop: alternates the two properties until OCTAVO_FUZZ_SECS elapse.
#[test]
#[ignore]
fn fuzz_timed() {
    let secs: u64 = std::env::var("OCTAVO_FUZZ_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(60);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    let start = std::time::Instant::now();
    let (mut n_mut, mut n_rand, mut rounds) = (0u64, 0u64, 0u64);
    while std::time::Instant::now() < deadline {
        let cfg = Config { cases: 2000, failure_persistence: None, rng_algorithm: proptest::test_runner::RngAlgorithm::ChaCha, ..Config::default() };
        let mut r = TestRunner::new_with_rng(cfg.clone(), proptest::test_runner::TestRng::from_seed(proptest::test_runner::RngAlgorithm::ChaCha, &{
            let mut s = [0u8; 32];
            s[..8].copy_from_slice(&rounds.to_le_bytes());
            s[8..16].copy_from_slice(&0x0c7a_f022u64.to_le_bytes());
            s
        }));
        r.run(&muts(), |(w, m, th)| check_mutated(w, &m, th)).expect("mutation fuzz found a failure");
        n_mut += cfg.cases as u64;
        let mut r = TestRunner::new_with_rng(cfg.clone(), proptest::test_runner::TestRng::from_seed(proptest::test_runner::RngAlgorithm::ChaCha, &{
            let mut s = [0u8; 32];
            s[..8].copy_from_slice(&rounds.to_le_bytes());
            s[8..16].copy_from_slice(&0x0c7a_f023u64.to_le_bytes());
            s
        }));
        r.run(&randoms(), |(d, p)| check_random(&d, p)).expect("random fuzz found a failure");
        n_rand += cfg.cases as u64;
        rounds += 1;
    }
    println!(
        "fuzz_timed: {:.0}s, {} mutated-stream cases + {} random-input cases ({} total), 0 panics, 0 forgeries",
        start.elapsed().as_secs_f64(),
        n_mut,
        n_rand,
        n_mut + n_rand
    );
}
