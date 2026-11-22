//! Weak-seed policy and key-file parsing (no Python needed).
mod common;
use common::*;
use octavo_cli::policy::weak_seed_reason;

#[test]
fn os_random_seeds_pass() {
    let mut n = 0;
    for _ in 0..100_000 {
        let mut s = [0u8; 128];
        getrandom::getrandom(&mut s).unwrap();
        assert_eq!(weak_seed_reason(&s), None, "{}", hex::encode(s));
        n += 1;
    }
    println!("OS-random seeds passing the rule: {n}/{n}");
}

#[test]
fn obvious_weak_seeds_refused() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("zeros", vec![0; 128]),
        ("ones", vec![0xff; 128]),
        ("same 0x41", vec![0x41; 128]),
        ("counter", (0..128u8).collect()),
        ("down counter", (0..128u8).map(|i| 255 - i).collect()),
        ("ascii", b"Tr0ub4dor&3 ".repeat(11)[..128].to_vec()),
        ("hex text", b"0123456789abcdef".repeat(8)),
        ("short", vec![1, 2, 3]),
    ];
    for (name, s) in cases {
        assert!(weak_seed_reason(&s).is_some(), "{name}");
    }
    // the public demo seed passes the structural rule (Python keeps it usable for samples)
    let demo = hx(&vectors()["seeds"]["demo"]);
    assert_eq!(weak_seed_reason(&demo), None);
    assert!(octavo_cli::policy::is_demo_seed(&demo));
}

#[test]
fn seed_text_parsing() {
    let mut rng = Rng(5);
    let s = good_seed(&mut rng);
    let h = hex::encode(s);
    assert_eq!(*octavo_cli::parse_seed_text(h.as_bytes()).unwrap(), s);
    assert_eq!(*octavo_cli::parse_seed_text(format!("  {}\n", h.to_uppercase()).as_bytes()).unwrap(), s);
    let spaced: String = h.as_bytes().chunks(8).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join(" \n");
    assert_eq!(*octavo_cli::parse_seed_text(spaced.as_bytes()).unwrap(), s);
    assert!(octavo_cli::parse_seed_text(&h.as_bytes()[..254]).is_err());
    assert!(octavo_cli::parse_seed_text(format!("{h}00").as_bytes()).is_err());
    assert!(octavo_cli::parse_seed_text(format!("{h}g").as_bytes()).is_err());
    assert!(octavo_cli::parse_seed_text(&[0xff, 0xfe]).is_err());
}

#[test]
fn keygen_seed_is_fresh_and_passes() {
    let a = octavo_cli::keygen_seed().unwrap();
    let b = octavo_cli::keygen_seed().unwrap();
    assert_ne!(*a, *b);
    assert!(weak_seed_reason(&*a).is_none());
}
