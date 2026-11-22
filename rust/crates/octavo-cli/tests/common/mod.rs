#![allow(dead_code)]
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

pub const BIN: &str = env!("CARGO_BIN_EXE_octavo");

pub fn ws() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A fresh scratch dir under rust/target/cli-test-scratch (not /tmp).
pub fn scratch(name: &str) -> PathBuf {
    let d = ws().join("target/cli-test-scratch").join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Small deterministic PRNG (splitmix64) for test data.
pub struct Rng(pub u64);
impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// A policy-passing seed from the PRNG.
pub fn good_seed(rng: &mut Rng) -> [u8; 128] {
    loop {
        let s: [u8; 128] = rng.bytes(128).try_into().unwrap();
        if octavo_cli::policy::weak_seed_reason(&s).is_none() {
            return s;
        }
    }
}

pub fn write_key(dir: &Path, name: &str, seed: &[u8]) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join(name);
    std::fs::write(&p, format!("{}\n", hex::encode(seed))).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    p
}

pub fn cmd(home: &Path) -> Command {
    let mut c = Command::new(BIN);
    c.env("OCTAVO_HOME", home.join("home"));
    c
}

pub fn run(home: &Path, args: &[&str], stdin: Option<&[u8]>) -> Output {
    use std::io::Write;
    let mut c = cmd(home);
    c.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    c.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() });
    let mut ch = c.spawn().unwrap();
    if let Some(d) = stdin {
        let mut si = ch.stdin.take().unwrap();
        let d = d.to_vec();
        std::thread::spawn(move || {
            let _ = si.write_all(&d);
        });
    }
    ch.wait_with_output().unwrap()
}

pub fn vectors() -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(ws().join("vectors/octavo_vectors.json")).unwrap()).unwrap()
}
pub fn hx(v: &serde_json::Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}
