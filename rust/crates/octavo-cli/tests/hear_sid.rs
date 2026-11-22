//! `octavo hear --sid / --sid-wav`: PSID v2 header, the 6502 player run on an independent 6502
//! emulator (tests/common/mos6502.rs), voice 1 == the earworm notes, determinism, WAV validity,
//! and (when installed) a cross-check with sidplayfp.
mod common;
#[path = "common/mos6502.rs"]
mod mos6502;
use common::*;
use mos6502::Mos6502;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}
fn ok(o: &std::process::Output) {
    assert!(o.status.success(), "stderr: {}", String::from_utf8_lossy(&o.stderr));
}
fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

/// Name -> MIDI note number, independent of the CLI's table (C4 = 60).
fn name_to_midi(n: &str) -> u8 {
    let (l, o) = n.split_at(1);
    let pc = match l {
        "C" => 0,
        "D" => 2,
        "E" => 4,
        "G" => 7,
        "A" => 9,
        _ => panic!("note {n} is not C-major pentatonic"),
    };
    (12 * (o.parse::<i32>().unwrap() + 1) + pc) as u8
}
/// PAL SID frequency register for a MIDI note: f * 2^24 / 985248.
fn pal_reg(m: u8) -> u16 {
    (440.0 * 2f64.powf((m as f64 - 69.0) / 12.0) * 16_777_216.0 / 985_248.0).round() as u16
}

/// (midi note, eighths) from the `hear` stdout
fn notes(stdout: &[u8]) -> Vec<(u8, u32)> {
    let v: Vec<(u8, u32)> = String::from_utf8(stdout.to_vec())
        .unwrap()
        .split_whitespace()
        .map(|n| match n.strip_suffix('-') {
            Some(x) => (name_to_midi(x), 2),
            None => (name_to_midi(n), 1),
        })
        .collect();
    assert_eq!(v.len(), 16);
    v
}

struct Psid {
    load: u16,
    init: u16,
    play: u16,
    image: Vec<u8>,
}

/// Strict PSID v2 header parse (fields per the HVSC SID_file_format description).
fn parse_psid(f: &[u8]) -> Psid {
    assert!(f.len() > 0x7C + 2);
    assert_eq!(&f[0..4], b"PSID", "magic");
    assert_eq!(be16(f, 4), 2, "version");
    assert_eq!(be16(f, 6), 0x7C, "dataOffset");
    assert_eq!(be16(f, 8), 0, "loadAddress 0 = taken from the data (HVSC style)");
    let (init, play) = (be16(f, 0x0A), be16(f, 0x0C));
    assert_eq!(be16(f, 0x0E), 1, "songs");
    assert_eq!(be16(f, 0x10), 1, "startSong");
    assert_eq!(u32::from_be_bytes(f[0x12..0x16].try_into().unwrap()), 0, "speed: VBI");
    for (at, want) in [(0x16, "Octavo key earworm"), (0x36, "octavo hear --sid"), (0x56, "2026 homemade, not for secrets")] {
        let fld = &f[at..at + 32];
        let end = fld.iter().position(|&b| b == 0).expect("string field is NUL-terminated");
        assert!(fld[..end].iter().all(|b| (0x20..0x7F).contains(b)));
        assert!(fld[end..].iter().all(|&b| b == 0));
        assert_eq!(std::str::from_utf8(&fld[..end]).unwrap(), want);
    }
    let flags = be16(f, 0x76);
    assert_eq!(flags & 1, 0, "built-in player (not MUS)");
    assert_eq!(flags & 2, 0, "C64 compatible (not PlaySID-specific)");
    assert_eq!((flags >> 2) & 3, 1, "PAL");
    assert_eq!((flags >> 4) & 3, 1, "MOS6581");
    assert_eq!(flags >> 6, 0);
    assert_eq!((f[0x78], f[0x79]), (0, 0), "startPage / pageLength");
    assert_eq!(be16(f, 0x7A), 0, "reserved in v2");
    let load = u16::from_le_bytes([f[0x7C], f[0x7D]]);
    let image = f[0x7E..].to_vec();
    assert!(load >= 0x07E8, "load address must be >= $07E8");
    let end = load as usize + image.len();
    assert!(end <= 0xD000, "image must stay below I/O");
    assert!((load as usize..end).contains(&(init as usize)));
    assert!((load as usize..end).contains(&(play as usize)));
    Psid { load, init, play, image }
}

/// Load into the independent emulator, run init + `frames` play calls.
fn emulate(p: &Psid, frames: u32) -> Mos6502 {
    let mut c = Mos6502::new();
    c.mem[p.load as usize..p.load as usize + p.image.len()].copy_from_slice(&p.image);
    c.call(p.init, 0, 10_000);
    for f in 1..=frames {
        c.frame = f;
        c.call(p.play, 0, 10_000);
    }
    c
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct GateOn {
    frame: u32,
    freq: u16,
    ctrl: u8,
}

/// Replay the recorded writes against a register file; per voice, every gate 0->1 with its freq.
fn gate_ons(c: &Mos6502) -> ([Vec<GateOn>; 3], Vec<(u32, u16)>, [u8; 0x20]) {
    let mut reg = [0u8; 0x20];
    let mut ons: [Vec<GateOn>; 3] = Default::default();
    let mut v3_freqs = vec![];
    for &(frame, r, v) in &c.sid_writes {
        let old = reg[r as usize];
        reg[r as usize] = v;
        if r < 21 && r % 7 == 4 && v & 1 == 1 && old & 1 == 0 {
            let b = (r - 4) as usize;
            ons[b / 7].push(GateOn { frame, freq: u16::from_le_bytes([reg[b], reg[b + 1]]), ctrl: v });
        }
        if r == 15 {
            v3_freqs.push((frame, u16::from_le_bytes([reg[14], reg[15]])));
        }
    }
    (ons, v3_freqs, reg)
}

#[test]
fn psid_header_and_voices_follow_the_earworm() {
    let d = scratch("sid");
    let mut rng = Rng(51);
    for k in 0..4 {
        let key = write_key(&d, &format!("{k}.key"), &good_seed(&mut rng));
        let sid = d.join(format!("{k}.sid"));
        let o = run(&d, &["hear", "-k", s(&key), "--sid", s(&sid)], None);
        ok(&o);
        let tune = notes(&o.stdout);
        let f = std::fs::read(&sid).unwrap();
        assert_eq!(std::fs::metadata(&sid).unwrap().permissions().mode() & 0o777, 0o600);
        let p = parse_psid(&f);
        assert_eq!((p.load, p.init, p.play), (0x1000, 0x1000, 0x1003));

        let pass: u32 = tune.iter().map(|&(_, l)| 12 * l).sum();
        let c = emulate(&p, 2 * pass + 1); // two passes + the first note of the third (the loop)
        let (ons, v3, reg) = gate_ons(&c);
        // init: volume 15, all three voices have an ADSR, pulse widths set for the pulse voices
        assert_eq!(reg[0x18] & 0x0F, 15);
        for v in 0..3 {
            assert!(reg[7 * v + 5] != 0 || reg[7 * v + 6] != 0, "voice {} ADSR", v + 1);
        }
        assert_eq!(u16::from_le_bytes([reg[2], reg[3] & 15]), 0x800, "voice 1 pulse 50 %");
        assert_ne!(u16::from_le_bytes([reg[16], reg[17] & 15]), 0, "voice 3 pulse width");

        // voice 1: the melody, in order, with the right lengths, looping
        let expect: Vec<u16> = tune.iter().chain(tune.iter()).chain(tune.iter().take(1)).map(|&(m, _)| pal_reg(m)).collect();
        let got: Vec<u16> = ons[0].iter().map(|g| g.freq).collect();
        assert_eq!(got, expect, "voice 1 frequencies == earworm notes in order (key {k})");
        let mut frame = 1;
        for (i, g) in ons[0].iter().enumerate() {
            assert_eq!(g.frame, frame, "note {i} starts on its frame");
            assert_eq!(g.ctrl & 0xF0, 0x40, "voice 1 is pulse");
            frame += 12 * tune[i % 16].1;
        }
        // voice 2: bass from the same notes, 2 octaves down on even steps, 1 on odd
        let bass: Vec<u16> = ons[1].iter().take(16).map(|g| g.freq).collect();
        let want: Vec<u16> = (0..16).map(|i| pal_reg(tune[i & !3].0 - if i % 2 == 0 { 24 } else { 12 })).collect();
        assert_eq!(bass, want);
        assert!(ons[1].iter().all(|g| g.ctrl & 0xF0 == 0x20 || g.ctrl & 0xF0 == 0x10), "bass is saw or triangle");
        assert_eq!(ons[1].len(), ons[0].len());
        // voice 3: a new arpeggio note every frame, from notes i, i+1, i+2 of the melody
        assert!(ons[2].iter().all(|g| g.ctrl & 0xF0 == 0x40), "arpeggio is pulse");
        let mut start = 1;
        for i in 0..16 {
            let len = 12 * tune[i].1;
            let pcs: Vec<u8> = (0..3).map(|j| tune[(i + j) % 16].0 % 12).collect();
            let allowed: Vec<u16> = pcs.iter().map(|&pc| pal_reg(72 + pc)).collect();
            let fr: Vec<u16> = v3.iter().filter(|(f, _)| (start..start + len).contains(f)).map(|&(_, x)| x).collect();
            assert_eq!(fr.len() as u32, len, "one arpeggio write per frame");
            assert!(fr.iter().all(|x| allowed.contains(x)), "arpeggio notes come from the melody");
            for w in fr.windows(4) {
                assert_eq!(w[0], w[3], "3-note cycle");
            }
            start += len;
        }
        // gate off 2 frames before each new note (so notes re-attack)
        for w in c.sid_writes.iter().filter(|&&(_, r, _)| r == 4).collect::<Vec<_>>().windows(2) {
            if w[1].2 & 1 == 1 && w[0].0 > 0 {
                assert_eq!(w[0].2 & 1, 0);
                assert_eq!(w[1].0 - w[0].0, 2, "gate off 2 frames before the next note");
            }
        }
    }
    let _ = std::fs::remove_dir_all(&d);
}

/// The player-subset 6502 inside the CLI (used for --sid-wav) produces exactly the register writes
/// the independent emulator sees.
#[test]
fn builtin_player_core_matches_independent_emulator() {
    let mut rng = Rng(52);
    for _ in 0..4 {
        let seed = good_seed(&mut rng);
        let t = octavo_cli::earworm::tune(&seed);
        let p = parse_psid(&octavo_cli::sid::psid(&t));
        let frames = octavo_cli::sid::loop_frames(&t) + 30;
        let mine = octavo_cli::sid::run_player(&t, frames).unwrap();
        let c = emulate(&p, frames);
        for (f, w) in mine.iter().enumerate() {
            let other: Vec<(u8, u8)> = c.sid_writes.iter().filter(|x| x.0 == f as u32).map(|x| (x.1, x.2)).collect();
            assert_eq!(*w, other, "frame {f}");
        }
    }
}

/// Strict RIFF/WAVE parse: returns (rate, samples)
fn parse_wav(w: &[u8]) -> (u32, Vec<i16>) {
    assert_eq!(&w[0..4], b"RIFF");
    assert_eq!(u32::from_le_bytes(w[4..8].try_into().unwrap()) as usize, w.len() - 8);
    assert_eq!(&w[8..16], b"WAVEfmt ");
    assert_eq!(u32::from_le_bytes(w[16..20].try_into().unwrap()), 16);
    let le16 = |a: usize| u16::from_le_bytes([w[a], w[a + 1]]);
    let le32 = |a: usize| u32::from_le_bytes(w[a..a + 4].try_into().unwrap());
    assert_eq!(le16(20), 1, "PCM");
    assert_eq!(le16(22), 1, "mono");
    let rate = le32(24);
    assert_eq!(le32(28), rate * 2, "byte rate");
    assert_eq!(le16(32), 2, "block align");
    assert_eq!(le16(34), 16, "bits");
    assert_eq!(&w[36..40], b"data");
    let n = le32(40) as usize;
    assert_eq!(44 + n, w.len());
    (rate, w[44..].chunks_exact(2).map(|c| i16::from_le_bytes([c[0], c[1]])).collect())
}

#[test]
fn sid_and_sid_wav_deterministic_valid_and_safe() {
    let d = scratch("sid-det");
    let mut rng = Rng(53);
    let k1 = write_key(&d, "1.key", &good_seed(&mut rng));
    let k2 = write_key(&d, "2.key", &good_seed(&mut rng));
    let get = |k: &Path, tag: &str| {
        let (a, b) = (d.join(format!("{tag}.sid")), d.join(format!("{tag}.wav")));
        let o = run(&d, &["hear", "-k", s(k), "--sid", s(&a), "--sid-wav", s(&b)], None);
        ok(&o);
        for p in [&a, &b] {
            assert_eq!(std::fs::metadata(p).unwrap().permissions().mode() & 0o777, 0o600);
        }
        (std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap(), notes(&o.stdout))
    };
    let (s1, w1, t1) = get(&k1, "a");
    let (s1b, w1b, _) = get(&k1, "b");
    let (s2, w2, _) = get(&k2, "c");
    assert_eq!(s1, s1b, "same key -> identical .sid");
    assert_eq!(w1, w1b, "same key -> identical SID WAV");
    assert_ne!(s1, s2);
    assert_ne!(w1, w2);
    assert_eq!(s1[..0x7C], s2[..0x7C], "header does not depend on the key");

    let (rate, pcm) = parse_wav(&w1);
    assert_eq!(rate, 44_100);
    let pass: u32 = t1.iter().map(|&(_, l)| 12 * l).sum();
    let secs = 2.0 * pass as f64 * 19_656.0 / 985_248.0;
    assert!((pcm.len() as f64 - secs * 44_100.0).abs() <= 2.0, "two passes long");
    let peak = pcm.iter().map(|&x| (x as i32).abs()).max().unwrap();
    let clipped = pcm.iter().filter(|&&x| x == i16::MAX || x == i16::MIN).count();
    assert!(peak > 3000 && clipped == 0, "audible, not clipping (peak {peak}, clipped {clipped})");
    // every melody step (first pass) has sound in its middle
    let mut start = 0.0;
    for &(_, l) in &t1 {
        let len = 12.0 * l as f64 * 19_656.0 / 985_248.0;
        let (a, b) = (((start + 0.05) * 44_100.0) as usize, ((start + len - 0.05) * 44_100.0) as usize);
        let rms = (pcm[a..b].iter().map(|&x| (x as f64).powi(2)).sum::<f64>() / (b - a) as f64).sqrt();
        assert!(rms > 1000.0, "step at {start:.2}s is silent");
        start += len;
    }

    // no overwrite without --force, for both outputs
    for flag in ["--sid", "--sid-wav"] {
        let p = d.join(format!("keep{flag}"));
        std::fs::write(&p, b"keep me").unwrap();
        let o = run(&d, &["hear", "-k", s(&k1), flag, s(&p)], None);
        assert!(!o.status.success(), "{flag} must refuse to overwrite");
        assert_eq!(std::fs::read(&p).unwrap(), b"keep me");
        ok(&run(&d, &["hear", "-k", s(&k1), flag, s(&p), "-f"], None));
        assert_ne!(std::fs::read(&p).unwrap(), b"keep me");
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
    }
    let _ = std::fs::remove_dir_all(&d);
}

/// If sidplayfp is installed: it must load and render our .sid, and the melody must be audible in
/// its render and spectrally match ours (tools/check_sid_render.py, python3 -B, numpy). Skips if absent.
#[test]
fn sidplayfp_renders_it_if_installed() {

    if std::process::Command::new("sh").args(["-c", "command -v sidplayfp"]).output().map(|o| !o.status.success()).unwrap_or(true) {
        eprintln!("SKIP: sidplayfp not installed");
        return;
    }
    if !std::process::Command::new("python3").args(["-B", "-c", "import numpy"]).output().map(|o| o.status.success()).unwrap_or(false) {
        eprintln!("SKIP: python3 numpy not available");
        return;
    }
    let d = scratch("sid-fp");
    let key = write_key(&d, "1.key", &good_seed(&mut Rng(54)));
    let (sid, ours, theirs) = (d.join("t.sid"), d.join("ours.wav"), d.join("sidplayfp.wav"));
    let o = run(&d, &["hear", "-k", s(&key), "--sid", s(&sid), "--sid-wav", s(&ours)], None);
    ok(&o);
    let text = String::from_utf8(o.stdout).unwrap();
    let pass: f64 = notes(text.as_bytes()).iter().map(|&(_, l)| 12.0 * l as f64).sum::<f64>() * 19_656.0 / 985_248.0;
    let secs = (2.0 * pass + 1.0).ceil() as u32 + 1; // sidplayfp adds ~1 s of silence first
    let r = std::process::Command::new("timeout")
        .args(["60", "sidplayfp", "-v", &format!("-t{secs}"), &format!("-w{}", s(&theirs)), s(&sid)])
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(r.status.success(), "sidplayfp failed: {}", String::from_utf8_lossy(&r.stderr));
    let log = format!("{}{}", String::from_utf8_lossy(&r.stdout), String::from_utf8_lossy(&r.stderr)).replace('\r', "\n");
    assert!(log.contains("PSID") && log.contains("No errors"), "{log}");
    let c = std::process::Command::new("timeout")
        .args(["60", "python3", "-B", s(&ws().join("tools/check_sid_render.py")), text.trim(), s(&ours), s(&theirs)])
        .output()
        .unwrap();
    let out = String::from_utf8_lossy(&c.stdout);
    eprintln!("{out}");
    assert!(c.status.success(), "check_sid_render failed: {out}{}", String::from_utf8_lossy(&c.stderr));
    let sim: f64 = out.lines().find(|l| l.contains("similarity")).unwrap().split("mean ").nth(1).unwrap().trim().parse().unwrap();
    assert!(sim > 0.85, "spectral similarity to sidplayfp {sim}");
    let _ = std::fs::remove_dir_all(&d);
}
