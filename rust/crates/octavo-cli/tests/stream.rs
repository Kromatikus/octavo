//! Streaming v9 == whole-buffer v9 == published vectors.
mod common;
use common::*;
use octavo_cli::{open_stream, seal_stream, StreamOptions};
use octavo_core::formats::{open_rehearsal, open_rehearsal_threads, seal_rehearsal, seal_rehearsal_threads};
use sha2::{Digest, Sha256};

fn seal_s(seed: &[u8; 128], msg: &[u8], p: &[u8; 16], n: &[u8; 16], cs: usize, ad: &[u8], th: usize, bc: usize) -> (Vec<u8>, [u8; 32]) {
    let mut out = Vec::new();
    let (sum, ft) = seal_stream(seed, &mut &msg[..], &mut out, p, n, ad, &StreamOptions { chunk_size: cs, threads: th, batch_chunks: bc }).unwrap();
    assert_eq!(sum.bytes_in, msg.len() as u64);
    assert_eq!(sum.bytes_out, out.len() as u64);
    (out, ft)
}
fn open_s(seed: &[u8; 128], blob: &[u8], ad: &[u8], th: usize, bc: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    open_stream(seed, &mut &blob[..], &mut out, ad, &StreamOptions { chunk_size: 65536, threads: th, batch_chunks: bc }).map_err(|e| e.to_string())?;
    Ok(out)
}

#[test]
fn published_v9_vectors_streaming() {
    let v = vectors();
    let mut n = 0;
    for f in v["formats"].as_array().unwrap() {
        if f["mode"] != "rehearsal" {
            continue;
        }
        let seed: [u8; 128] = hx(&v["seeds"][f["seed"].as_str().unwrap()]).try_into().unwrap();
        let msg = hx(&f["msg"]);
        let ad = hx(&f["ad"]);
        let p: [u8; 16] = hx(&f["pickup"]).try_into().unwrap();
        let no: [u8; 16] = hx(&f["nonce"]).try_into().unwrap();
        let cs = f["chunk_size"].as_u64().unwrap() as usize;
        for (th, bc) in [(1, 1), (1, 4), (3, 1), (8, 4)] {
            let (blob, ft) = seal_s(&seed, &msg, &p, &no, cs, &ad, th, bc);
            assert_eq!(hex::encode(Sha256::digest(&blob)), f["blob_sha256"].as_str().unwrap(), "{}", f["id"]);
            assert_eq!(blob.len() as u64, f["blob_len"].as_u64().unwrap());
            if let Some(t) = f.get("final_tag") {
                assert_eq!(hex::encode(ft), t.as_str().unwrap());
            }
            assert_eq!(open_s(&seed, &blob, &ad, th, bc).unwrap(), msg);
        }
        n += 1;
    }
    // the live rehearsal-demo.txt sample (demo seed, AD "rehearsal-demo")
    let demo: [u8; 128] = hx(&v["seeds"]["demo"]).try_into().unwrap();
    for s in v["samples"].as_array().unwrap() {
        if s["mode"] == "rehearsal" {
            let blob = hx(&s["blob"]);
            let ad = hx(&s["ad"]);
            let want = open_rehearsal(&demo, &blob, &ad).unwrap();
            assert_eq!(open_s(&demo, &blob, &ad, 1, 1).unwrap(), want);
            assert_eq!(open_s(&demo, &blob, &ad, 4, 2).unwrap(), want);
            n += 1;
        }
    }
    println!("published v9 vectors + rehearsal sample via streaming API: {n}/{n}");
    assert_eq!(n, 11);
}

#[test]
fn stream_matches_whole_buffer_random() {
    let mut rng = Rng(0x0c7a_0001);
    let mut cases = 0;
    for _ in 0..12 {
        let seed = good_seed(&mut rng);
        for &cs in &[128usize, 256, 384, 1024, 4096, 65536] {
            let sizes = [0usize, 1, 127, 128, 129, cs - 1, cs, cs + 1, 2 * cs, 3 * cs + 77, rng.below(5 * cs as u64) as usize];
            for &len in &sizes {
                let msg = rng.bytes(len);
                let adl = rng.below(40) as usize;
                let ad = rng.bytes(adl);
                let p: [u8; 16] = rng.bytes(16).try_into().unwrap();
                let no: [u8; 16] = rng.bytes(16).try_into().unwrap();
                let th = 1 + rng.below(8) as usize;
                let bc = 1 + rng.below(4) as usize;
                let (want, wft) = seal_rehearsal(&seed, &msg, &p, &no, cs, &ad).unwrap();
                let (got, gft) = seal_s(&seed, &msg, &p, &no, cs, &ad, th, bc);
                assert_eq!(got, want, "len {len} cs {cs} th {th} bc {bc}");
                assert_eq!(gft, wft);
                let (want_t, _) = seal_rehearsal_threads(&seed, &msg, &p, &no, cs, &ad, th).unwrap();
                assert_eq!(want_t, want);
                assert_eq!(open_s(&seed, &got, &ad, th, bc).unwrap(), msg);
                assert_eq!(open_rehearsal_threads(&seed, &got, &ad, th).unwrap(), msg);
                cases += 1;
            }
        }
    }
    println!("stream == whole-buffer (bytes, final tag, open both ways): {cases}/{cases}");
}

#[test]
fn bad_chunk_sizes_and_ad_rejected() {
    let mut rng = Rng(3);
    let seed = good_seed(&mut rng);
    for cs in [0usize, 64, 127, 129, 200, (1 << 20) + 128, 2 << 20] {
        let mut out = Vec::new();
        assert!(seal_stream(&seed, &mut &b"x"[..], &mut out, &[0; 16], &[0; 16], b"", &StreamOptions { chunk_size: cs, threads: 1, batch_chunks: 1 }).is_err());
    }
    let big_ad = vec![0u8; 65537];
    let mut out = Vec::new();
    assert!(seal_stream(&seed, &mut &b"x"[..], &mut out, &[0; 16], &[0; 16], &big_ad, &StreamOptions::default()).is_err());
}
