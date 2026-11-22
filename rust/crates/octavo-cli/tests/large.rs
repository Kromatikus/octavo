//! Large file through the CLI with bounded memory (own test binary so RUSAGE_CHILDREN is ours).
mod common;
use common::*;
use std::io::Write;

fn child_maxrss_kib() -> i64 {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, &mut ru) };
    ru.ru_maxrss
}

#[test]
fn large_file_round_trip_bounded_memory() {
    let mb: usize = std::env::var("OCTAVO_LARGE_MB").ok().and_then(|s| s.parse().ok()).unwrap_or(256);
    let d = scratch("large");
    let mut rng = Rng(31);
    let k = write_key(&d, "k.key", &good_seed(&mut rng));
    let p = d.join("p");
    {
        let mut f = std::io::BufWriter::new(std::fs::File::create(&p).unwrap());
        for _ in 0..mb {
            f.write_all(&rng.bytes(1 << 20)).unwrap();
        }
        f.write_all(b"tail-not-a-chunk-multiple").unwrap();
    }
    let c = d.join("c");
    let r = d.join("r");
    let t0 = std::time::Instant::now();
    let o = cmd(&d).args(["seal", "-k", k.to_str().unwrap(), p.to_str().unwrap(), "-o", c.to_str().unwrap()]).output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let ts = t0.elapsed();
    let t1 = std::time::Instant::now();
    let o = cmd(&d).args(["open", "-k", k.to_str().unwrap(), c.to_str().unwrap(), "-o", r.to_str().unwrap()]).output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let to = t1.elapsed();
    let rss = child_maxrss_kib();
    let size = std::fs::metadata(&p).unwrap().len();
    // compare without loading whole files
    let same = std::process::Command::new("cmp").arg(&p).arg(&r).status().unwrap().success();
    assert!(same, "round trip differs");
    println!(
        "large: {:.1} MiB  seal {:.2}s ({:.1} MB/s)  open {:.2}s ({:.1} MB/s)  peak child RSS {} KiB",
        size as f64 / 1048576.0,
        ts.as_secs_f64(),
        size as f64 / 1e6 / ts.as_secs_f64(),
        to.as_secs_f64(),
        size as f64 / 1e6 / to.as_secs_f64(),
        rss
    );
    assert!(rss < 64 * 1024, "peak RSS {rss} KiB: not streaming?");
    for f in [&p, &c, &r] {
        let _ = std::fs::remove_file(f);
    }
}
