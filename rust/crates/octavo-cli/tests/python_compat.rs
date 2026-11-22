//! Cross-compat with the real Python sneak_n2.py (read-only; python3 -B, no bytecode written).
mod common;
use common::*;
use serde_json::{json, Value};
use std::path::Path;

fn s(p: &Path) -> String {
    p.to_str().unwrap().to_string()
}

fn pycache_snapshot() -> Vec<(String, u128)> {
    let mut v = Vec::new();
    for dir in ["/workspace/sneak_n2", "/workspace/sneak_n2/__pycache__"] {
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                let m = e.metadata().unwrap();
                let t = m.modified().unwrap().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
                v.push((e.path().display().to_string(), t));
            }
        }
    }
    v.sort();
    v
}

fn python(jobs: &Value, dir: &Path) -> Vec<Value> {
    let jf = dir.join(format!("jobs-{}.json", rand_tag()));
    std::fs::write(&jf, serde_json::to_vec(jobs).unwrap()).unwrap();
    let o = std::process::Command::new("timeout")
        .args(["600", "python3", "-B"])
        .arg(ws().join("tools/py_compat.py"))
        .arg(&jf)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .unwrap();
    assert!(o.status.success(), "python failed: {}", String::from_utf8_lossy(&o.stderr));
    serde_json::from_slice(&o.stdout).unwrap()
}
fn rand_tag() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64
}

#[test]
fn python_cross_compat_files_and_keys() {
    let ref_sha = std::process::Command::new("sha256sum").arg("/workspace/sneak_n2/sneak_n2.py").output().unwrap();
    assert!(String::from_utf8_lossy(&ref_sha.stdout).starts_with("19181bc1623115c075dc5dee25edec388f5413466777d47b7f19fa66d1e71eee"));
    let before = pycache_snapshot();
    let d = scratch("pycompat");
    // key made by the Rust CLI keygen, read by Python load_seed
    let k = d.join("k.key");
    let o = run(&d, &["keygen", "-o", &s(&k)], None);
    assert!(o.status.success());
    let seed = octavo_cli::load_key(&k).unwrap().0;
    let mut rng = Rng(41);
    // (len, chunk_size, ad)
    let cases: Vec<(usize, usize, &str)> = vec![
        (0, 128, ""), (1, 128, ""), (127, 128, "ad"), (128, 128, ""), (129, 256, "x"), (1000, 256, "from:alice"),
        (4096, 1024, ""), (5000, 1024, "ad"), (20_000, 4096, ""), (70_000, 65536, ""), (131_072, 65536, "big"),
    ];
    // Rust seals -> Python opens; Python seals -> Rust opens
    let mut jobs = vec![json!({"op": "loadkey", "key": s(&k)})];
    for (i, &(len, cs, ad)) in cases.iter().enumerate() {
        let msg = rng.bytes(len);
        let p = d.join(format!("p{i}"));
        std::fs::write(&p, &msg).unwrap();
        let rc = d.join(format!("rust{i}.oct"));
        let o = run(&d, &["seal", "-k", &s(&k), "--chunk-size", &cs.to_string(), "--ad", ad, &s(&p), "-o", &s(&rc)], None);
        assert!(o.status.success());
        jobs.push(json!({"op": "dec", "key": s(&k), "src": s(&rc), "dst": s(&d.join(format!("py_opened{i}"))), "ad": hex::encode(ad)}));
        jobs.push(json!({"op": "enc", "key": s(&k), "src": s(&p), "dst": s(&d.join(format!("py{i}.oct"))), "ad": hex::encode(ad), "cs": cs}));
    }
    // tampered Rust blob must be refused by Python too
    let mut t = std::fs::read(d.join("rust5.oct")).unwrap();
    t[100] ^= 4;
    std::fs::write(d.join("tampered.oct"), &t).unwrap();
    jobs.push(json!({"op": "dec", "key": s(&k), "src": s(&d.join("tampered.oct")), "dst": s(&d.join("py_tampered")), "ad": hex::encode("from:alice")}));
    let res = python(&json!(jobs), &d);
    assert_eq!(res[0]["sha"].as_str().unwrap(), octavo_cli::policy::sha256_hex(&*seed), "Python load_seed reads the Rust key file");
    let (mut r2p, mut p2r) = (0, 0);
    for (i, &(_, _, ad)) in cases.iter().enumerate() {
        let msg = std::fs::read(d.join(format!("p{i}"))).unwrap();
        assert!(res[1 + 2 * i]["ok"].as_bool().unwrap(), "py dec {i}: {}", res[1 + 2 * i]);
        assert_eq!(std::fs::read(d.join(format!("py_opened{i}"))).unwrap(), msg);
        r2p += 1;
        assert!(res[2 + 2 * i]["ok"].as_bool().unwrap(), "py enc {i}: {}", res[2 + 2 * i]);
        let out = d.join(format!("rust_opened{i}"));
        let o = run(&d, &["open", "-k", &s(&k), "--ad", ad, &s(&d.join(format!("py{i}.oct"))), "-o", &s(&out)], None);
        assert!(o.status.success(), "rust open of python blob {i}: {}", String::from_utf8_lossy(&o.stderr));
        assert_eq!(std::fs::read(&out).unwrap(), msg);
        // and the stdin path
        let o = run(&d, &["open", "-k", &s(&k), "--ad", ad], Some(&std::fs::read(d.join(format!("py{i}.oct"))).unwrap()));
        assert!(o.status.success());
        assert_eq!(o.stdout, msg);
        p2r += 1;
    }
    let last = res.last().unwrap();
    assert!(!last["ok"].as_bool().unwrap(), "python accepted a tampered blob");
    assert!(!d.join("py_tampered").exists());
    println!("Rust CLI -> Python decrypt_rehearsal_file: {r2p}/{}; Python encrypt_rehearsal_file -> Rust CLI: {p2r}/{}; key file Rust->Python: 1/1; tampered refused by Python: 1/1", cases.len(), cases.len());
    assert_eq!(pycache_snapshot(), before, "sneak_n2 folder or its __pycache__ changed");
}

#[test]
fn weak_seed_rule_matches_python() {
    let d = scratch("pypolicy");
    let mut rng = Rng(42);
    let mut seeds: Vec<Vec<u8>> = Vec::new();
    // random seeds (pass), and structured ones aimed at every rule and near its thresholds
    for _ in 0..200 {
        seeds.push(rng.bytes(128));
    }
    for distinct in [8usize, 31, 32, 33, 40] {
        let pal = rng.bytes(distinct);
        seeds.push((0..128).map(|_| pal[rng.below(distinct as u64) as usize]).collect());
    }
    for reps in [10usize, 11, 12, 13] {
        let mut s = rng.bytes(128);
        for i in 0..reps {
            s[i * 9] = 0x5a;
        }
        seeds.push(s);
    }
    for w in [0x0fu8, 0x1f, 0x3f, 0xf0, 0xfc] {
        seeds.push((0..128).map(|_| rng.next() as u8 & w | if w >= 0xf0 { w } else { 0 }).collect());
    }
    seeds.push((0..128).map(|_| 0x20 + (rng.below(95) as u8)).collect());
    seeds.push((0..128).map(|_| rng.below(128) as u8).collect());
    for period in [1usize, 2, 7, 16, 63, 64, 65] {
        let base = rng.bytes(period);
        let mut s: Vec<u8> = (0..128).map(|i| base[i % period]).collect();
        for _ in 0..rng.below(60) {
            let i = rng.below(128) as usize;
            s[i] = rng.next() as u8;
        }
        seeds.push(s);
    }
    for stride in [1usize, 2, 3, 4, 5, 8, 16, 32, 64] {
        let mut s = rng.bytes(128);
        for i in stride..128 {
            if rng.below(3) == 0 {
                s[i] = s[i - stride].wrapping_add(17);
            }
        }
        seeds.push(s);
        let mut s = rng.bytes(128);
        for i in stride..128 {
            if rng.below(3) == 0 {
                s[i] = s[i - stride] ^ 0xa5;
            }
        }
        seeds.push(s);
    }
    for run_len in [14usize, 15, 16, 17] {
        let mut s = rng.bytes(128);
        let mut v: Vec<u8> = rng.bytes(run_len);
        v.sort();
        v.dedup();
        s[30..30 + v.len()].copy_from_slice(&v);
        seeds.push(s);
    }
    let demo = hx(&vectors()["seeds"]["demo"]);
    seeds.push(demo);
    seeds.push(vec![0; 128]);
    seeds.push((0..128u8).collect());
    // single-byte mutations of random seeds
    for _ in 0..50 {
        let mut s = rng.bytes(128);
        let i = rng.below(128) as usize;
        s[i] = 0;
        seeds.push(s);
    }
    let jobs = json!([{"op": "policy", "seeds": seeds.iter().map(hex::encode).collect::<Vec<_>>()}]);
    let res = python(&jobs, &d);
    let reasons = res[0]["reasons"].as_array().unwrap();
    let (mut pass, mut fail) = (0, 0);
    for (sd, r) in seeds.iter().zip(reasons) {
        let mine = octavo_cli::policy::weak_seed_reason(sd);
        let theirs = r.as_str().map(|x| x.to_string());
        assert_eq!(mine, theirs, "seed {}", hex::encode(sd));
        if mine.is_none() { pass += 1 } else { fail += 1 }
    }
    println!("weak-seed rule == Python _weak_seed_reason on {} seeds ({pass} pass, {fail} refused, same reason text)", seeds.len());
}
