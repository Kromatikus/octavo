//! Merged tree: the streaming fast paths (seal: tag chain overlapped with encryption; open: tag
//! chain overlapped with decryption into a private buffer) never release unverified plaintext.
mod common;
use common::*;
use octavo_cli::{open_stream, seal_stream, StreamError, StreamOptions};
use std::io::{self, Write};

const CS: usize = 1024;

fn seal(seed: &[u8; 128], msg: &[u8], th: usize, bc: usize) -> Vec<u8> {
    let mut out = Vec::new();
    seal_stream(seed, &mut &msg[..], &mut out, &[3; 16], &[4; 16], b"ov", &StreamOptions { chunk_size: CS, threads: th, batch_chunks: bc }).unwrap();
    out
}

/// Tamper chunk k (ciphertext or tag); with any thread count / batch size, open must fail and
/// the output must hold exactly the chunks of the batches before the failing batch, nothing more.
#[test]
fn forged_batch_is_never_released() {
    let mut rng = Rng(77);
    let seed = good_seed(&mut rng);
    let nchunks = 13;
    let msg = rng.bytes(nchunks * CS - 300);
    let blob = seal(&seed, &msg, 1, 4);
    assert_eq!(blob, seal(&seed, &msg, 8, 3), "thread count changed the bytes");
    let mut cases = 0;
    for &(th, bc) in &[(1usize, 1usize), (1, 4), (2, 1), (2, 2), (3, 2), (4, 4), (8, 1), (8, 16)] {
        let batch = th.max(1) * bc;
        for k in 0..nchunks {
            for &in_tag in &[false, true] {
                let mut bad = blob.clone();
                let start = 72 + k * (CS + 32);
                let ctlen = (bad.len() - start - 32).min(CS);
                let off = start + if in_tag { ctlen + 5 } else { 17 };
                bad[off] ^= 0x40;
                let mut out = Vec::new();
                let r = open_stream(&seed, &mut &bad[..], &mut out, b"ov", &StreamOptions { chunk_size: 0, threads: th, batch_chunks: bc });
                assert!(matches!(r, Err(StreamError::Crypto(octavo_core::formats::Error::Auth))), "th {th} bc {bc} k {k}: {r:?}");
                let released_chunks = (k / batch) * batch;
                assert_eq!(out.len(), released_chunks * CS, "th {th} bc {bc} k {k}: released {} bytes", out.len());
                assert_eq!(&out[..], &msg[..out.len()]);
                cases += 1;
            }
        }
        let mut out = Vec::new();
        open_stream(&seed, &mut &blob[..], &mut out, b"ov", &StreamOptions { chunk_size: 0, threads: th, batch_chunks: bc }).unwrap();
        assert_eq!(out, msg);
    }
    println!("forged-batch cases: {cases}");
}

struct FailAfter(usize, Vec<u8>);
impl Write for FailAfter {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        if self.1.len() + b.len() > self.0 {
            return Err(io::Error::other("disk full (test)"));
        }
        self.1.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A write error inside the overlapped seal is reported (not swallowed) and stops output.
#[test]
fn seal_write_error_is_reported() {
    let mut rng = Rng(78);
    let seed = good_seed(&mut rng);
    let msg = rng.bytes(40 * CS);
    for th in [1usize, 2, 8] {
        for limit in [10usize, 72 + CS / 2, 72 + 3 * (CS + 32) + 1, 72 + 20 * (CS + 32)] {
            let mut w = FailAfter(limit, Vec::new());
            let r = seal_stream(&seed, &mut &msg[..], &mut w, &[3; 16], &[4; 16], b"", &StreamOptions { chunk_size: CS, threads: th, batch_chunks: 4 });
            assert!(matches!(r, Err(StreamError::Io(_))), "th {th} limit {limit}");
            assert!(w.1.len() <= limit);
        }
    }
}
