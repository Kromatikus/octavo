//! `octavo hear --midi`: standard MIDI file of the same 16 earworm notes as the note-name output.
mod common;
use common::*;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}
fn ok(o: &std::process::Output) {
    assert!(o.status.success(), "stderr: {}", String::from_utf8_lossy(&o.stderr));
}

/// Name -> MIDI note number, independent of the CLI's table (C4 = 60).
fn name_to_midi(n: &str) -> u8 {
    let (l, o) = n.split_at(1);
    let pc = match l {
        "C" => 0,
        "D" => 2,
        "E" => 4,
        "F" => 5,
        "G" => 7,
        "A" => 9,
        "B" => 11,
        _ => panic!("note {n}"),
    };
    (12 * (o.parse::<i32>().unwrap() + 1) + pc) as u8
}

fn vlq(b: &[u8], i: &mut usize) -> u32 {
    let mut v = 0u32;
    loop {
        let x = b[*i];
        *i += 1;
        v = (v << 7) | (x & 0x7f) as u32;
        if x & 0x80 == 0 {
            return v;
        }
    }
}

struct Parsed {
    ppq: u16,
    program: Option<u8>,
    tempo: Option<u32>,
    notes: Vec<(u8, u32)>, // (key, duration ticks)
}

/// Minimal strict SMF parser: one MThd (format 0, 1 track), one MTrk that ends exactly with End of Track.
fn parse(m: &[u8]) -> Parsed {
    assert_eq!(&m[0..4], b"MThd");
    assert_eq!(u32::from_be_bytes(m[4..8].try_into().unwrap()), 6);
    assert_eq!(u16::from_be_bytes(m[8..10].try_into().unwrap()), 0, "format 0");
    assert_eq!(u16::from_be_bytes(m[10..12].try_into().unwrap()), 1, "one track");
    let ppq = u16::from_be_bytes(m[12..14].try_into().unwrap());
    assert!(ppq > 0 && ppq & 0x8000 == 0);
    assert_eq!(&m[14..18], b"MTrk");
    let len = u32::from_be_bytes(m[18..22].try_into().unwrap()) as usize;
    assert_eq!(22 + len, m.len(), "track length must cover the rest of the file exactly");
    let t = &m[22..];
    let (mut i, mut now, mut ended) = (0usize, 0u32, false);
    let mut on: Option<(u8, u32)> = None;
    let mut p = Parsed { ppq, program: None, tempo: None, notes: vec![] };
    while i < t.len() {
        assert!(!ended, "data after End of Track");
        now += vlq(t, &mut i);
        let st = t[i];
        i += 1;
        match st {
            0xFF => {
                let ty = t[i];
                i += 1;
                let l = vlq(t, &mut i) as usize;
                let d = &t[i..i + l];
                i += l;
                match ty {
                    0x51 => p.tempo = Some(u32::from_be_bytes([0, d[0], d[1], d[2]])),
                    0x2F => ended = true,
                    _ => {}
                }
            }
            0xC0 => {
                p.program = Some(t[i]);
                i += 1;
            }
            0x90 => {
                let (k, v) = (t[i], t[i + 1]);
                i += 2;
                assert!(v > 0 && k < 128);
                assert!(on.is_none(), "overlapping notes");
                on = Some((k, now));
            }
            0x80 => {
                let k = t[i];
                i += 2;
                let (k0, t0) = on.take().expect("note off without note on");
                assert_eq!(k, k0);
                p.notes.push((k, now - t0));
            }
            x => panic!("unexpected status {x:#x}"),
        }
    }
    assert!(ended && on.is_none());
    p
}

#[test]
fn midi_parses_and_matches_note_names() {
    let d = scratch("midi");
    let mut rng = Rng(41);
    for k in 0..4 {
        let key = write_key(&d, &format!("{k}.key"), &good_seed(&mut rng));
        let mid = d.join(format!("{k}.mid"));
        let o = run(&d, &["hear", "-k", s(&key), "--midi", s(&mid)], None);
        ok(&o);
        let names: Vec<String> = String::from_utf8(o.stdout).unwrap().split_whitespace().map(String::from).collect();
        assert_eq!(names.len(), 16);
        let m = std::fs::read(&mid).unwrap();
        let p = parse(&m);
        assert_eq!(p.program, Some(0), "piano by default");
        assert_eq!(p.tempo, Some(500_000));
        assert_eq!(p.notes.len(), 16);
        let eighth = p.ppq as u32 / 2;
        for (n, &(key, dur)) in names.iter().zip(&p.notes) {
            let (nm, long) = match n.strip_suffix('-') {
                Some(x) => (x, true),
                None => (n.as_str(), false),
            };
            assert_eq!(key, name_to_midi(nm), "{n}");
            assert_eq!(dur, if long { 2 * eighth } else { eighth }, "{n}");
        }
        assert_eq!(std::fs::metadata(&mid).unwrap().permissions().mode() & 0o777, 0o600);
    }
}

#[test]
fn midi_is_deterministic_per_key_and_program_selectable() {
    let d = scratch("midi-det");
    let mut rng = Rng(42);
    let k1 = write_key(&d, "1.key", &good_seed(&mut rng));
    let k2 = write_key(&d, "2.key", &good_seed(&mut rng));
    let get = |k: &Path, name: &str, extra: &[&str]| {
        let p = d.join(name);
        let mut a = vec!["hear", "-k", s(k), "--midi", s(&p)];
        a.extend_from_slice(extra);
        ok(&run(&d, &a, None));
        std::fs::read(&p).unwrap()
    };
    let a = get(&k1, "a.mid", &[]);
    let b = get(&k1, "b.mid", &[]);
    let c = get(&k2, "c.mid", &[]);
    assert_eq!(a, b, "same key -> identical MIDI bytes");
    assert_ne!(a, c, "different key -> different MIDI");
    let v = get(&k1, "v.mid", &["--program", "40"]);
    let (pa, pv) = (parse(&a), parse(&v));
    assert_eq!(pv.program, Some(40));
    assert_eq!(pa.notes, pv.notes, "instrument does not change the notes");
    let o = run(&d, &["hear", "-k", s(&k1), "--midi", s(&d.join("x.mid")), "--program", "128"], None);
    assert!(!o.status.success());
}

#[test]
fn midi_and_wav_refuse_overwrite_without_force() {
    let d = scratch("midi-force");
    let mut rng = Rng(43);
    let k1 = write_key(&d, "1.key", &good_seed(&mut rng));
    let k2 = write_key(&d, "2.key", &good_seed(&mut rng));
    for flag in ["--midi", "--wav"] {
        let p = d.join(format!("out{flag}"));
        std::fs::write(&p, b"keep me").unwrap();
        let o = run(&d, &["hear", "-k", s(&k1), flag, s(&p)], None);
        assert!(!o.status.success(), "{flag} must refuse to overwrite");
        assert_eq!(std::fs::read(&p).unwrap(), b"keep me");
        ok(&run(&d, &["hear", "-k", s(&k1), flag, s(&p), "--force"], None));
        let first = std::fs::read(&p).unwrap();
        assert_ne!(first, b"keep me");
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        ok(&run(&d, &["hear", "-k", s(&k2), flag, s(&p), "-f"], None));
        assert_ne!(std::fs::read(&p).unwrap(), first);
    }
    // both at once
    let (w, m) = (d.join("both.wav"), d.join("both.mid"));
    ok(&run(&d, &["hear", "-k", s(&k1), "--wav", s(&w), "--midi", s(&m)], None));
    assert_eq!(&std::fs::read(&w).unwrap()[..4], b"RIFF");
    assert_eq!(&std::fs::read(&m).unwrap()[..4], b"MThd");
    let _ = std::fs::remove_dir_all(&d);
}
