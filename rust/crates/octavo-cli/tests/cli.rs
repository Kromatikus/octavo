//! End-to-end tests of the `octavo` binary.
mod common;
use common::*;
use std::os::unix::fs::PermissionsExt;

const W: &str = "Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.";

fn ok(o: &std::process::Output) {
    assert!(o.status.success(), "stderr: {}", String::from_utf8_lossy(&o.stderr));
}
fn s(p: &std::path::Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn keygen_perms_format_no_overwrite_no_key_printed() {
    let d = scratch("keygen");
    let k = d.join("a.key");
    let o = run(&d, &["keygen", "-o", s(&k)], None);
    ok(&o);
    let meta = std::fs::metadata(&k).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    let text = std::fs::read_to_string(&k).unwrap();
    assert_eq!(text.len(), 257);
    assert!(text.ends_with('\n') && text[..256].chars().all(|c| c.is_ascii_hexdigit()));
    // key never printed
    let all = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    assert!(!all.contains(&text[..32]));
    // refuses to overwrite, file unchanged
    let o2 = run(&d, &["keygen", "-o", s(&k)], None);
    assert!(!o2.status.success());
    assert_eq!(std::fs::read_to_string(&k).unwrap(), text);
    // two keys differ, both pass check-key
    let k2 = d.join("b.key");
    ok(&run(&d, &["keygen", "-o", s(&k2)], None));
    assert_ne!(std::fs::read(&k2).unwrap(), text.as_bytes());
    ok(&run(&d, &["check-key", "-k", s(&k)], None));
    // no temp files left behind
    let names: Vec<_> = std::fs::read_dir(&d).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
    assert!(names.iter().all(|n| !n.starts_with('.')), "{names:?}");
}

#[test]
fn help_and_first_use_warning() {
    let d = scratch("warn");
    let h = run(&d, &["--help"], None);
    assert!(String::from_utf8_lossy(&h.stdout).contains(W));
    for sub in ["seal", "open", "keygen"] {
        let h = run(&d, &[sub, "--help"], None);
        assert!(String::from_utf8_lossy(&h.stdout).contains(W), "{sub} --help");
    }
    let k = d.join("k.key");
    let o = run(&d, &["keygen", "-o", s(&k)], None);
    let e = String::from_utf8_lossy(&o.stderr);
    assert!(e.contains("First run"), "{e}");
    let o = run(&d, &["check-key", "-k", s(&k)], None);
    assert!(!String::from_utf8_lossy(&o.stderr).contains("First run"));
}

#[test]
fn round_trips_files_and_pipes() {
    let d = scratch("rt");
    let mut rng = Rng(21);
    let k = write_key(&d, "k.key", &good_seed(&mut rng));
    let mut n = 0;
    for &(len, cs) in &[(0usize, 65536usize), (1, 65536), (127, 128), (128, 128), (129, 128), (65535, 65536), (65536, 65536), (65537, 65536), (300_001, 4096), (1_048_579, 65536), (2_000_000, 1 << 20)] {
        let msg = rng.bytes(len);
        let p = d.join(format!("p{len}"));
        std::fs::write(&p, &msg).unwrap();
        let c = d.join(format!("c{len}"));
        let r = d.join(format!("r{len}"));
        let css = cs.to_string();
        ok(&run(&d, &["seal", "-k", s(&k), "--chunk-size", &css, "--ad", "hdr", s(&p), "-o", s(&c)], None));
        assert_eq!(std::fs::metadata(&c).unwrap().permissions().mode() & 0o777, 0o600);
        let nch = len / cs + 1;
        let fin = (len % cs + 1).div_ceil(128) * 128;
        assert_eq!(std::fs::metadata(&c).unwrap().len() as usize, 72 + (nch - 1) * cs + fin + 32 * nch);
        ok(&run(&d, &["open", "-k", s(&k), "--ad", "hdr", s(&c), "-o", s(&r)], None));
        assert_eq!(std::fs::read(&r).unwrap(), msg);
        // stdin -> stdout both ways, different thread counts
        let o = run(&d, &["seal", "-k", s(&k), "--chunk-size", &css, "-j", "1"], Some(&msg));
        ok(&o);
        let o2 = run(&d, &["open", "-k", s(&k), "-j", "8", "-"], Some(&o.stdout));
        ok(&o2);
        assert_eq!(o2.stdout, msg);
        let o3 = run(&d, &["open", "-k", s(&k), "--stream-verified-prefix"], Some(&o.stdout));
        ok(&o3);
        assert_eq!(o3.stdout, msg);
        n += 1;
    }
    println!("CLI round trips (file->file, stdin->stdout, 3 open modes): {n}/{n}");
}

#[test]
fn tampered_or_wrong_inputs_release_nothing() {
    let d = scratch("tamper");
    let mut rng = Rng(22);
    let k = write_key(&d, "k.key", &good_seed(&mut rng));
    let k2 = write_key(&d, "k2.key", &good_seed(&mut rng));
    let msg = rng.bytes(200_000);
    let p = d.join("p");
    std::fs::write(&p, &msg).unwrap();
    let c = d.join("c");
    ok(&run(&d, &["seal", "-k", s(&k), "--chunk-size", "1024", s(&p), "-o", s(&c)], None));
    let blob = std::fs::read(&c).unwrap();
    let mut cases: Vec<(String, Vec<u8>, &std::path::Path, Vec<&str>)> = Vec::new();
    for pos in [0usize, 3, 10, 40, 70, 72, 500, 1100, blob.len() / 2, blob.len() - 33, blob.len() - 1] {
        let mut t = blob.clone();
        t[pos] ^= 0x10;
        cases.push((format!("flip@{pos}"), t, &k, vec![]));
    }
    cases.push(("truncate-final".into(), blob[..blob.len() - (blob.len() - 72) % (1024 + 32)].to_vec(), &k, vec![]));
    cases.push(("truncate-mid".into(), blob[..blob.len() / 2].to_vec(), &k, vec![]));
    cases.push(("extra-byte".into(), [blob.clone(), vec![0]].concat(), &k, vec![]));
    cases.push(("wrong-key".into(), blob.clone(), &k2, vec![]));
    cases.push(("wrong-ad".into(), blob.clone(), &k, vec!["--ad", "x"]));
    cases.push(("empty".into(), vec![], &k, vec![]));
    let mut n = 0;
    for (name, data, key, extra) in &cases {
        let t = d.join(format!("t-{name}"));
        std::fs::write(&t, data).unwrap();
        let out = d.join(format!("o-{name}"));
        let mut a = vec!["open", "-k", s(key), s(&t), "-o", s(&out)];
        a.extend(extra.iter());
        let o = run(&d, &a, None);
        assert_eq!(o.status.code(), Some(1), "{name}");
        assert!(!out.exists(), "{name}: output file was created");
        let mut a = vec!["open", "-k", s(key)];
        a.extend(extra.iter());
        let o = run(&d, &a, Some(data));
        assert_eq!(o.status.code(), Some(1), "{name} (stdin)");
        assert!(o.stdout.is_empty(), "{name}: stdout got {} bytes", o.stdout.len());
        n += 1;
    }
    let names: Vec<_> = std::fs::read_dir(&d).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
    assert!(names.iter().all(|n| !n.starts_with('.')), "temp files left: {names:?}");
    println!("CLI rejects with no output (file and stdout): {n}/{n}");
}

#[test]
fn weak_and_malformed_keys_refused() {
    let d = scratch("weak");
    let mut seeds: Vec<(&str, Vec<u8>)> = vec![
        ("all-zero", vec![0; 128]),
        ("all-0x41", vec![0x41; 128]),
        ("all-0xff", vec![0xff; 128]),
        ("counter", (0..128u8).collect()),
        ("passphrase-as-seed", b"correct horse battery staple ".repeat(5)[..128].to_vec()),
        ("repeat-16", (0..128).map(|i| [0x13u8, 0x8f, 0xa2, 0x55, 0x01, 0xee, 0x7c, 0x39, 0xd4, 0x60, 0xb1, 0x2a, 0xf7, 0x48, 0x9d, 0xc6][i % 16]).collect()),
    ];
    let mut short = vec![0u8; 128];
    let mut rng = Rng(23);
    short[..16].copy_from_slice(&rng.bytes(16)); // 128-bit secret zero-padded
    seeds.push(("zero-padded", short));
    let mut n = 0;
    for (name, sd) in &seeds {
        assert_eq!(sd.len(), 128, "{name}");
        let k = write_key(&d, &format!("{name}.key"), sd);
        let o = run(&d, &["check-key", "-k", s(&k)], None);
        assert_eq!(o.status.code(), Some(1), "{name}");
        assert!(String::from_utf8_lossy(&o.stderr).contains("weak seed"), "{name}");
        let o = run(&d, &["seal", "-k", s(&k)], Some(b"hi"));
        assert_eq!(o.status.code(), Some(1));
        assert!(o.stdout.is_empty());
        n += 1;
    }
    // malformed files
    let bad = |name: &str, content: &[u8]| {
        let p = d.join(name);
        std::fs::write(&p, content).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let o = run(&d, &["check-key", "-k", s(&p)], None);
        assert_eq!(o.status.code(), Some(1), "{name}");
    };
    bad("short.key", b"abcdef\n");
    bad("passphrase.key", b"hunter2\n");
    bad("long.key", "ab".repeat(129).as_bytes());
    bad("dashes.key", format!("{}-", hex::encode(good_seed(&mut rng))).as_bytes());
    bad("binary.key", &[0xffu8; 300]);
    bad("huge.key", &vec![b'a'; 20000]);
    n += 6;
    // symlink refused
    let real = write_key(&d, "real.key", &good_seed(&mut rng));
    let link = d.join("link.key");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert_eq!(run(&d, &["check-key", "-k", s(&link)], None).status.code(), Some(1));
    // loose permissions: warning, still works
    let loose = write_key(&d, "loose.key", &good_seed(&mut rng));
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644)).unwrap();
    let o = run(&d, &["check-key", "-k", s(&loose)], None);
    ok(&o);
    assert!(String::from_utf8_lossy(&o.stderr).contains("chmod 600"));
    n += 2;
    // public demo seed: seal refused unless --allow-demo-seed
    let demo = hx(&vectors()["seeds"]["demo"]);
    let dk = write_key(&d, "demo.key", &demo);
    let o = run(&d, &["seal", "-k", s(&dk)], Some(b"x"));
    assert_eq!(o.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&o.stderr).contains("PUBLIC demo seed"));
    let o = run(&d, &["seal", "-k", s(&dk), "--allow-demo-seed"], Some(b"x"));
    ok(&o);
    let o2 = run(&d, &["open", "-k", s(&dk)], Some(&o.stdout));
    ok(&o2);
    assert_eq!(o2.stdout, b"x");
    n += 1;
    println!("weak / malformed / unsafe key cases handled: {n}/{n}");
}

#[test]
fn output_safety() {
    let d = scratch("outsafe");
    let mut rng = Rng(24);
    let k = write_key(&d, "k.key", &good_seed(&mut rng));
    let p = d.join("p");
    std::fs::write(&p, b"hello").unwrap();
    let c = d.join("c");
    std::fs::write(&c, b"old").unwrap();
    // existing output refused, untouched
    assert_eq!(run(&d, &["seal", "-k", s(&k), s(&p), "-o", s(&c)], None).status.code(), Some(1));
    assert_eq!(std::fs::read(&c).unwrap(), b"old");
    ok(&run(&d, &["seal", "-k", s(&k), s(&p), "-o", s(&c), "--force"], None));
    assert_ne!(std::fs::read(&c).unwrap(), b"old");
    // same file in and out refused
    assert_eq!(run(&d, &["seal", "-k", s(&k), s(&p), "-o", s(&p), "--force"], None).status.code(), Some(1));
    assert_eq!(std::fs::read(&p).unwrap(), b"hello");
    // a failed open with --force keeps the old file
    let r = d.join("r");
    std::fs::write(&r, b"keep me").unwrap();
    let mut bad = std::fs::read(&c).unwrap();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    let b = d.join("bad");
    std::fs::write(&b, &bad).unwrap();
    assert_eq!(run(&d, &["open", "-k", s(&k), s(&b), "-o", s(&r), "--force"], None).status.code(), Some(1));
    assert_eq!(std::fs::read(&r).unwrap(), b"keep me");
    ok(&run(&d, &["open", "-k", s(&k), s(&c), "-o", s(&r), "--force"], None));
    assert_eq!(std::fs::read(&r).unwrap(), b"hello");
}

#[test]
fn hear_is_deterministic_and_key_specific() {
    let d = scratch("hear");
    let mut rng = Rng(25);
    let k1 = write_key(&d, "1.key", &good_seed(&mut rng));
    let k2 = write_key(&d, "2.key", &good_seed(&mut rng));
    let a = run(&d, &["hear", "-k", s(&k1)], None);
    let b = run(&d, &["hear", "-k", s(&k1)], None);
    let c = run(&d, &["hear", "-k", s(&k2)], None);
    ok(&a);
    assert_eq!(a.stdout, b.stdout);
    assert_ne!(a.stdout, c.stdout);
    assert_eq!(String::from_utf8_lossy(&a.stdout).split_whitespace().count(), 16);
    let w = d.join("t.wav");
    ok(&run(&d, &["hear", "-k", s(&k1), "--wav", s(&w)], None));
    let wav = std::fs::read(&w).unwrap();
    assert_eq!(&wav[..4], b"RIFF");
    assert_eq!(&wav[8..16], b"WAVEfmt ");
}
