//! Differential check against blobs/ciphertexts produced by the real sneak_n2.py on random inputs
//! (tools/diff_python.py -> vectors/diff_random.json).

use octavo_core::formats::{self, Ctx};
use octavo_core::{force_backend, BackendKind, Cipher, CtSoft};
use serde_json::Value;

fn hx(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

#[test]
fn matches_python_reference_every_backend() {
    for kind in BackendKind::ALL {
        if !kind.available() {
            println!("SKIP backend {}", kind.name());
            continue;
        }
        force_backend(Some(kind));
        run(kind);
    }
    force_backend(None);
}

fn run(kind: BackendKind) {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/diff_random.json");
    let Ok(txt) = std::fs::read_to_string(p) else {
        eprintln!("skip: run tools/diff_python.py first");
        return;
    };
    let v: Value = serde_json::from_str(&txt).unwrap();
    let mut n = 0;
    for c in v["block"].as_array().unwrap() {
        let seed = hx(&c["seed"]);
        let rounds = c["rounds"].as_u64().unwrap() as usize;
        let ci: Cipher = Cipher::with_rounds(&seed, &hx(&c["nonce"]), rounds);
        let _soft: Cipher<CtSoft> = Cipher::with_rounds(&seed, &hx(&c["nonce"]), 1);
        let pt: [u8; 128] = hx(&c["pt"]).try_into().unwrap();
        let mut x = pt;
        ci.encrypt_block(&mut x);
        assert_eq!(hex::encode(x), c["ct"].as_str().unwrap(), "block rounds={rounds}");
        ci.decrypt_block(&mut x);
        assert_eq!(x, pt);
        {
            let sc: Cipher<octavo_core::CtScalar> = Cipher::with_rounds(&seed, &hx(&c["nonce"]), rounds);
            let mut y = pt;
            sc.encrypt_block(&mut y);
            assert_eq!(hex::encode(y), c["ct"].as_str().unwrap(), "ct-scalar backend");
            sc.decrypt_block(&mut y);
            assert_eq!(y, pt);
        }
        #[cfg(feature = "table-backend")]
        {
            let tb: Cipher<octavo_core::Table> = Cipher::with_rounds(&seed, &hx(&c["nonce"]), rounds);
            let mut y = pt;
            tb.encrypt_block(&mut y);
            assert_eq!(hex::encode(y), c["ct"].as_str().unwrap(), "table backend");
        }
        n += 1;
    }
    for c in v["v6"].as_array().unwrap() {
        let seed: [u8; 128] = hx(&c["seed"]).try_into().unwrap();
        let m = formats::open_block(&Ctx::live(&seed), &hx(&c["blob"]), &hx(&c["ad"])).unwrap();
        assert_eq!(m, hx(&c["msg"]));
        // re-seal with the same pickup must give the identical blob (deterministic SIV)
        let blob = hx(&c["blob"]);
        let pickup: [u8; 16] = blob[4..20].try_into().unwrap();
        assert_eq!(formats::seal_block(&Ctx::live(&seed), &m, &pickup, &hx(&c["ad"])).unwrap(), blob);
        n += 1;
    }
    for c in v["v7"].as_array().unwrap() {
        let seed: [u8; 128] = hx(&c["seed"]).try_into().unwrap();
        let blob = hx(&c["blob"]);
        let m = formats::open_movements(&Ctx::live(&seed), &blob, &hx(&c["ad"])).unwrap();
        assert_eq!(m, hx(&c["msg"]));
        let pickup: [u8; 16] = blob[4..20].try_into().unwrap();
        assert_eq!(formats::seal_movements(&Ctx::live(&seed), &m, &pickup, &hx(&c["ad"])).unwrap(), blob);
        n += 1;
    }
    for c in v["v9"].as_array().unwrap() {
        let seed: [u8; 128] = hx(&c["seed"]).try_into().unwrap();
        let blob = hx(&c["blob"]);
        let m = formats::open_rehearsal(&seed, &blob, &hx(&c["ad"])).unwrap();
        assert_eq!(m, hx(&c["msg"]));
        let pickup: [u8; 16] = blob[4..20].try_into().unwrap();
        let nonce: [u8; 16] = blob[20..36].try_into().unwrap();
        let cs = c["chunk_size"].as_u64().unwrap() as usize;
        assert_eq!(formats::seal_rehearsal(&seed, &m, &pickup, &nonce, cs, &hx(&c["ad"])).unwrap().0, blob);
        n += 1;
    }
    println!("[{}] differential vs sneak_n2.py: {n} cases OK", kind.name());
}
