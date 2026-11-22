//! "Key earworm": a short tune derived one-way from the key, to check a key by ear.
//! The tune is NOT the key and cannot give the key back: it is 16 notes taken from
//! SHA-256("Octavo earworm v1" ‖ key_sig(seed)), about 65 bits of a hash, enough to tell
//! two keys apart, far too few to recover a 1024-bit seed.

use sha2::{Digest, Sha256};

const NAMES: [&str; 10] = ["C4", "D4", "E4", "G4", "A4", "C5", "D5", "E5", "G5", "A5"];
/// MIDI note numbers of the 10 earworm pitches (C4 = 60).
pub const MIDI: [u8; 10] = [60, 62, 64, 67, 69, 72, 74, 76, 79, 81];

/// (note index into the C-major pentatonic over two octaves, length in eighths: 1 or 2)
pub fn tune(seed: &[u8; 128]) -> Vec<(usize, u32)> {
    let sig = octavo_core::formats::key_sig(seed);
    let d = Sha256::new().chain_update(b"Octavo earworm v1").chain_update(sig).finalize();
    d[..16].iter().enumerate().map(|(i, &b)| ((b as usize) % 10, if i % 4 == 3 || (b >> 6) == 3 { 2 } else { 1 })).collect()
}

pub fn notes_text(t: &[(usize, u32)]) -> String {
    t.iter().map(|&(n, l)| if l == 2 { format!("{}-", NAMES[n]) } else { NAMES[n].to_string() }).collect::<Vec<_>>().join(" ")
}

/// 16-bit mono 22050 Hz WAV of the tune (sine with a short fade per note).
pub fn wav(t: &[(usize, u32)]) -> Vec<u8> {
    let sr = 22050u32;
    let eighth = sr / 4; // 120 bpm eighths
    let mut pcm: Vec<i16> = Vec::new();
    for &(n, l) in t {
        let f = 440.0 * 2f64.powf((MIDI[n] as f64 - 69.0) / 12.0);
        let len = eighth * l;
        for i in 0..len {
            let tt = i as f64 / sr as f64;
            let env = (i.min(len - i) as f64 / 400.0).min(1.0);
            pcm.push((env * 0.3 * (2.0 * std::f64::consts::PI * f * tt).sin() * 32767.0) as i16);
        }
    }
    let data_len = (pcm.len() * 2) as u32;
    let mut w = Vec::with_capacity(44 + data_len as usize);
    w.extend_from_slice(b"RIFF");
    w.extend_from_slice(&(36 + data_len).to_le_bytes());
    w.extend_from_slice(b"WAVEfmt ");
    w.extend_from_slice(&16u32.to_le_bytes());
    w.extend_from_slice(&1u16.to_le_bytes());
    w.extend_from_slice(&1u16.to_le_bytes());
    w.extend_from_slice(&sr.to_le_bytes());
    w.extend_from_slice(&(sr * 2).to_le_bytes());
    w.extend_from_slice(&2u16.to_le_bytes());
    w.extend_from_slice(&16u16.to_le_bytes());
    w.extend_from_slice(b"data");
    w.extend_from_slice(&data_len.to_le_bytes());
    for s in pcm {
        w.extend_from_slice(&s.to_le_bytes());
    }
    w
}

/// General MIDI program used by `--midi` unless `--program` says otherwise: 0 = Acoustic Grand Piano.
pub const DEFAULT_PROGRAM: u8 = 0;
/// Ticks per quarter note in the MIDI file; an eighth (the tune's unit) is half of this.
pub const MIDI_PPQ: u16 = 480;

fn vlq(mut v: u32, out: &mut Vec<u8>) {
    let mut buf = [0u8; 5];
    let mut i = buf.len() - 1;
    buf[i] = (v & 0x7f) as u8;
    v >>= 7;
    while v > 0 {
        i -= 1;
        buf[i] = 0x80 | (v & 0x7f) as u8;
        v >>= 7;
    }
    out.extend_from_slice(&buf[i..]);
}

/// Standard MIDI file (format 0, one track, channel 1) of the same 16 notes, pitches and order as
/// `notes_text` / `wav`: 120 bpm, eighth = 240 ticks, long notes ("-") = two eighths, velocity 90.
/// `program` is a General MIDI program number (0..=127; 0 = piano). Deterministic for a given key.
pub fn midi(t: &[(usize, u32)], program: u8) -> Vec<u8> {
    let eighth = (MIDI_PPQ / 2) as u32;
    let mut trk = Vec::new();
    // tempo 500000 us per quarter (120 bpm)
    trk.extend_from_slice(&[0x00, 0xFF, 0x51, 0x03, 0x07, 0xA1, 0x20]);
    // 4/4 time signature
    trk.extend_from_slice(&[0x00, 0xFF, 0x58, 0x04, 0x04, 0x02, 0x18, 0x08]);
    // track name
    let name = b"Octavo key earworm";
    trk.extend_from_slice(&[0x00, 0xFF, 0x03, name.len() as u8]);
    trk.extend_from_slice(name);
    // program change, channel 1
    trk.extend_from_slice(&[0x00, 0xC0, program & 0x7f]);
    for &(n, l) in t {
        let key = MIDI[n];
        trk.extend_from_slice(&[0x00, 0x90, key, 90]);
        vlq(eighth * l, &mut trk);
        trk.extend_from_slice(&[0x80, key, 0]);
    }
    trk.extend_from_slice(&[0x00, 0xFF, 0x2F, 0x00]);
    let mut m = Vec::with_capacity(22 + trk.len());
    m.extend_from_slice(b"MThd");
    m.extend_from_slice(&6u32.to_be_bytes());
    m.extend_from_slice(&0u16.to_be_bytes()); // format 0
    m.extend_from_slice(&1u16.to_be_bytes()); // one track
    m.extend_from_slice(&MIDI_PPQ.to_be_bytes());
    m.extend_from_slice(b"MTrk");
    m.extend_from_slice(&(trk.len() as u32).to_be_bytes());
    m.extend_from_slice(&trk);
    m
}
