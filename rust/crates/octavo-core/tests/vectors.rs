//! Published Octavo vectors (score v11: 79 + 6 app + 3 live samples), exported by
//! tools/export_vectors.py into vectors/octavo_vectors.json.

use octavo_core::formats::{self, Ctx, Error};
use octavo_core::{force_backend, BackendKind, Cipher};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

fn load() -> Value {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/octavo_vectors.json");
    serde_json::from_str(&std::fs::read_to_string(p).expect("run tools/export_vectors.py first")).unwrap()
}
fn hx(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}
fn seed128(v: &Value) -> [u8; 128] {
    hx(v).try_into().unwrap()
}
fn a16(v: &Value) -> [u8; 16] {
    hx(v).try_into().unwrap()
}

struct Tally(BTreeMap<String, (usize, usize)>, Vec<String>);
impl Tally {
    fn rec(&mut self, sec: &str, id: &str, ok: bool) {
        let e = self.0.entry(sec.to_string()).or_default();
        e.1 += 1;
        if ok {
            e.0 += 1;
        } else {
            self.1.push(format!("{sec}/{id}"));
        }
        println!("{} {sec} {id}", if ok { "PASS" } else { "FAIL" });
    }
}

#[test]
fn published_vectors_every_backend() {
    let mut ran = vec![];
    for kind in BackendKind::ALL {
        if !kind.available() {
            println!("SKIP backend {} (not available on this CPU)", kind.name());
            continue;
        }
        force_backend(Some(kind));
        println!("\n===== backend {} =====", kind.name());
        run_vectors(kind);
        ran.push(kind.name());
    }
    force_backend(None);
    println!("\nbackends run: {:?}", ran);
}

fn run_vectors(kind: BackendKind) {
    let v = load();
    let demo = seed128(&v["seeds"]["demo"]);
    let nondemo = seed128(&v["seeds"]["nondemo"]);
    let mut t = Tally(BTreeMap::new(), vec![]);

    // seed-derived values
    {
        use sha3::digest::{ExtendableOutput, Update, XofReader};
        let mut x = sha3::Shake256::default();
        x.update(b"Octavo published non-demo test seed v1");
        let mut s = [0u8; 128];
        x.finalize_xof().read(&mut s);
        assert_eq!(s, nondemo, "non-demo seed definition");
    }
    for (name, s) in [("demo", &demo), ("nondemo", &nondemo)] {
        assert_eq!(hex::encode(formats::key_sig(s)), v["sigs"][name]["key_sig"].as_str().unwrap());
        assert_eq!(hex::encode(formats::rehearsal_sig(s)), v["sigs"][name]["rehearsal_sig"].as_str().unwrap());
    }
    for r in [2u8, 4, 6, 16] {
        let k = formats::etude_key(&demo, r);
        assert_eq!(hex::encode(Sha256::digest(k)), v["etude_key_sha256"][r.to_string()].as_str().unwrap());
    }
    println!("key_sig / rehearsal_sig (both seeds), etude keys, non-demo SHAKE definition: OK");

    // raw block permutation
    for b in v["block_cipher"].as_array().unwrap() {
        let rounds = b["rounds"].as_u64().unwrap() as u8;
        let k = formats::etude_key(&demo, rounds);
        let c: Cipher = Cipher::with_rounds(&k, &hx(&b["nonce"]), rounds as usize);
        assert_eq!(octavo_core::selected_backend(), kind);
        let pt: [u8; 128] = hx(&b["plaintext"]).try_into().unwrap();
        let mut x = pt;
        c.encrypt_block(&mut x);
        let ok_e = hex::encode(x) == b["ciphertext"].as_str().unwrap();
        c.decrypt_block(&mut x);
        t.rec("block_cipher", b["id"].as_str().unwrap(), ok_e && x == pt);
    }

    // AEAD formats
    for f in v["formats"].as_array().unwrap() {
        let sec = f["section"].as_str().unwrap();
        let id = f["id"].as_str().unwrap();
        let seed = if f["seed"] == "demo" { &demo } else { &nondemo };
        let msg = hx(&f["msg"]);
        let ad = hx(&f["ad"]);
        let pickup = a16(&f["pickup"]);
        let rounds = f["rounds"].as_u64().unwrap() as u8;
        let mode = f["mode"].as_str().unwrap();
        let ctx = match mode {
            "block" | "movements" => Ctx::live(seed),
            "etude-block" | "etude-movements" => Ctx::etude(seed, rounds).unwrap(),
            _ => Ctx::live(seed),
        };
        let (blob, extra_ok) = match mode {
            "block" | "etude-block" => {
                let b = formats::seal_block(&ctx, &msg, &pickup, &ad).unwrap();
                let back = formats::open_block(&ctx, &b, &ad);
                (b, back.as_deref() == Ok(&msg[..]))
            }
            "movements" | "etude-movements" => {
                let b = formats::seal_movements(&ctx, &msg, &pickup, &ad).unwrap();
                let back = formats::open_movements(&ctx, &b, &ad);
                (b, back.as_deref() == Ok(&msg[..]))
            }
            "rehearsal" => {
                let cs = f["chunk_size"].as_u64().unwrap() as usize;
                let (b, ft) = formats::seal_rehearsal(seed, &msg, &pickup, &a16(&f["nonce"]), cs, &ad).unwrap();
                let ft_ok = f.get("final_tag").map_or(true, |x| x.as_str().unwrap() == hex::encode(ft));
                let back = formats::open_rehearsal(seed, &b, &ad);
                (b, ft_ok && back.as_deref() == Ok(&msg[..]))
            }
            m => panic!("unknown mode {m}"),
        };
        let blob_ok = blob.len() as u64 == f["blob_len"].as_u64().unwrap()
            && hex::encode(Sha256::digest(&blob)) == f["blob_sha256"].as_str().unwrap()
            && f.get("blob").map_or(true, |x| x.as_str().unwrap() == hex::encode(&blob));
        // single-bit tamper must be rejected
        let mut tam = blob.clone();
        let pos = tam.len() / 2;
        tam[pos] ^= 1;
        let tamper_rejected = match mode {
            "block" | "etude-block" => formats::open_block(&ctx, &tam, &ad).is_err(),
            "movements" | "etude-movements" => formats::open_movements(&ctx, &tam, &ad).is_err(),
            _ => formats::open_rehearsal(seed, &tam, &ad).is_err(),
        };
        t.rec(sec, id, blob_ok && extra_ok && tamper_rejected);
    }

    // app vectors: HKDF key expansion + open recorded v6 blobs
    let mut app_seeds = BTreeMap::new();
    for k in v["app_keys"].as_array().unwrap() {
        let s = formats::app_seed(&hx(&k["key"])).unwrap();
        t.rec("app", &format!("key/{}", k["id"].as_str().unwrap()), hex::encode(s) == k["seed"].as_str().unwrap());
        app_seeds.insert(k["id"].as_str().unwrap().to_string(), s);
    }
    for b in v["app_blobs"].as_array().unwrap() {
        let s = &app_seeds[b["key_id"].as_str().unwrap()];
        let m = formats::open_block(&Ctx::live(s), &hx(&b["blob"]), &hx(&b["ad"]));
        t.rec("app", &format!("open/{}", b["id"].as_str().unwrap()), m.as_deref() == Ok(&hx(&b["msg"])[..]));
    }

    // live samples (not part of the 79/6 count)
    let ctx = Ctx::live(&demo);
    for s in v["samples"].as_array().unwrap() {
        let blob = hx(&s["blob"]);
        let ad = hx(&s["ad"]);
        let open = |b: &[u8]| -> Result<Vec<u8>, Error> {
            match s["mode"].as_str().unwrap() {
                "block" => formats::open_block(&ctx, b, &ad),
                "movements" => formats::open_movements(&ctx, b, &ad),
                _ => formats::open_rehearsal(&demo, b, &ad),
            }
        };
        let m = open(&blob);
        let mut ok = m.is_ok() && s.get("msg").map_or(true, |x| hx(x) == m.clone().unwrap());
        for pos in [0, 5, 25, 50, 100, blob.len() - 1] {
            let mut tb = blob.clone();
            tb[pos] ^= 1;
            ok &= open(&tb).is_err();
        }
        t.rec("samples", s["id"].as_str().unwrap(), ok);
    }

    println!("\nSUMMARY [{}]", kind.name());
    for (sec, (p, n)) in &t.0 {
        println!("  {sec:13} {p}/{n}");
    }
    assert!(t.1.is_empty(), "failures: {:?}", t.1);
}
