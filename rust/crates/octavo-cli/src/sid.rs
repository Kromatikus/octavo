//! C64 SID output for the key earworm: a PSID v2 `.sid` file with a small 6502 player written and
//! assembled here (no third-party C64 code), and a WAV rendered by running that same player on a
//! small 6502 core and feeding its SID register writes to a simple pure-Rust 6581-style synth.
//!
//! Voices (all derived ONLY from the 16 earworm notes, never from the key directly):
//! * voice 1: the melody, pulse wave (50 %), same notes, order and lengths as `notes_text`;
//! * voice 2: bass, sawtooth: in each group of 4 steps the group's first melody note, two octaves
//!   down on even steps and one octave down on odd steps (an octave "bounce");
//! * voice 3: fast arpeggio, pulse (25 %): the pitch classes of melody notes i, i+1, i+2 (mod 16)
//!   placed in the C5 octave, sorted, cycled one note per frame (50 Hz).
//!
//! PAL timing (985 248 Hz, 50 Hz frames, play once per frame), 12 frames per eighth (0.24 s, i.e.
//! 125 bpm), gate off for the last 2 frames of each step, and the tune loops forever.
//!
//! Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.

use crate::earworm::MIDI;
use std::collections::HashMap;

/// PAL C64 CPU clock (Hz).
pub const PAL_CLOCK: f64 = 985_248.0;
/// CPU cycles per PAL frame (312 lines x 63 cycles).
pub const PAL_FRAME_CYCLES: u32 = 312 * 63;
/// Frames per eighth note.
pub const FRAMES_PER_EIGHTH: u8 = 12;
/// Load address of the C64 data (the first two data bytes say so too, as PSID asks).
pub const LOAD: u16 = 0x1000;
pub const INIT: u16 = 0x1000;
pub const PLAY: u16 = 0x1003;
/// Sample rate of `--sid-wav`.
pub const WAV_RATE: u32 = 44_100;

/// SID frequency register value for a MIDI note at the PAL clock: f * 2^24 / clock.
pub fn sid_freq(midi: u8) -> u16 {
    let f = 440.0 * 2f64.powf((midi as f64 - 69.0) / 12.0);
    (f * 16_777_216.0 / PAL_CLOCK).round() as u16
}

/// The three voices' notes per step (MIDI numbers), derived from the 16 melody notes only.
pub struct Parts {
    pub melody: Vec<u8>,
    pub frames: Vec<u8>,
    pub bass: Vec<u8>,
    pub arp: Vec<[u8; 3]>,
}

pub fn parts(t: &[(usize, u32)]) -> Parts {
    let melody: Vec<u8> = t.iter().map(|&(n, _)| MIDI[n]).collect();
    let n = melody.len();
    let frames = t.iter().map(|&(_, l)| FRAMES_PER_EIGHTH * l as u8).collect();
    let bass = (0..n).map(|i| melody[i & !3] - if i % 2 == 0 { 24 } else { 12 }).collect();
    let arp = (0..n)
        .map(|i| {
            let mut c = [0u8; 3];
            for (j, c) in c.iter_mut().enumerate() {
                *c = 72 + melody[(i + j) % n] % 12;
            }
            c.sort_unstable();
            c
        })
        .collect();
    Parts { melody, frames, bass, arp }
}

// ---------------------------------------------------------------- tiny 6502 assembler
enum Fix {
    Abs(usize, &'static str),
    Rel(usize, &'static str),
}
struct Asm {
    org: u16,
    b: Vec<u8>,
    labels: HashMap<&'static str, u16>,
    fixes: Vec<Fix>,
}
impl Asm {
    fn new(org: u16) -> Self {
        Asm { org, b: vec![], labels: HashMap::new(), fixes: vec![] }
    }
    fn pc(&self) -> u16 {
        self.org + self.b.len() as u16
    }
    fn label(&mut self, l: &'static str) {
        assert!(self.labels.insert(l, self.pc()).is_none(), "duplicate label {l}");
    }
    fn imp(&mut self, op: u8) {
        self.b.push(op);
    }
    fn imm(&mut self, op: u8, v: u8) {
        self.b.extend_from_slice(&[op, v]);
    }
    /// absolute (or absolute,X) operand by number
    fn absn(&mut self, op: u8, a: u16) {
        self.b.push(op);
        self.b.extend_from_slice(&a.to_le_bytes());
    }
    /// absolute (or absolute,X) operand by label
    fn abs(&mut self, op: u8, l: &'static str) {
        self.b.push(op);
        self.fixes.push(Fix::Abs(self.b.len(), l));
        self.b.extend_from_slice(&[0, 0]);
    }
    fn br(&mut self, op: u8, l: &'static str) {
        self.b.push(op);
        self.fixes.push(Fix::Rel(self.b.len(), l));
        self.b.push(0);
    }
    fn bytes(&mut self, d: &[u8]) {
        self.b.extend_from_slice(d);
    }
    fn finish(mut self) -> (Vec<u8>, HashMap<&'static str, u16>) {
        for f in std::mem::take(&mut self.fixes) {
            match f {
                Fix::Abs(at, l) => {
                    let a = self.labels[l];
                    self.b[at..at + 2].copy_from_slice(&a.to_le_bytes());
                }
                Fix::Rel(at, l) => {
                    let d = self.labels[l] as i32 - (self.org as i32 + at as i32 + 1);
                    assert!((-128..=127).contains(&d), "branch to {l} out of range");
                    self.b[at] = d as i8 as u8;
                }
            }
        }
        (self.b, self.labels)
    }
}

// opcodes used by the player
const LDA_IMM: u8 = 0xA9;
const LDA_ABS: u8 = 0xAD;
const LDA_ABX: u8 = 0xBD;
const STA_ABS: u8 = 0x8D;
const STA_ABX: u8 = 0x9D;
const LDX_IMM: u8 = 0xA2;
const LDX_ABS: u8 = 0xAE;
const STX_ABS: u8 = 0x8E;
const INX: u8 = 0xE8;
const DEX: u8 = 0xCA;
const CPX_IMM: u8 = 0xE0;
const CMP_IMM: u8 = 0xC9;
const BNE: u8 = 0xD0;
const BPL: u8 = 0x10;
const DEC_ABS: u8 = 0xCE;
const CLC: u8 = 0x18;
const ADC_ABS: u8 = 0x6D;
const TAX: u8 = 0xAA;
const JMP_ABS: u8 = 0x4C;
const RTS: u8 = 0x60;

const SID: u16 = 0xD400;
const PULSE: u8 = 0x40;
const SAW: u8 = 0x20;
const GATE: u8 = 0x01;
/// (AD, SR) per voice: melody A=0 (2 ms) D=9 (750 ms) S=10 R=6 (204 ms); bass A=0 D=8 S=9 R=4;
/// arpeggio A=0 D=0 S=7 R=0 (quieter, clicky).
pub const ADSR: [(u8, u8); 3] = [(0x09, 0xA6), (0x08, 0x94), (0x00, 0x70)];
/// pulse widths (12 bit): voice 1 50 %, voice 3 25 %
pub const PW: [u16; 3] = [0x800, 0, 0x400];
pub const WAVE: [u8; 3] = [PULSE, SAW, PULSE];

/// The C64 program (load image without the 2-byte load-address prefix) for one tune.
pub fn player(t: &[(usize, u32)]) -> Vec<u8> {
    let p = parts(t);
    let n = p.melody.len();
    assert!(n > 0 && n <= 64);
    let mut a = Asm::new(LOAD);
    a.abs(JMP_ABS, "init"); // $1000
    a.abs(JMP_ABS, "play"); // $1003

    // ---- init: silence the SID, set volume / ADSR / pulse widths, reset the sequencer
    a.label("init");
    a.imm(LDX_IMM, 0x18);
    a.imm(LDA_IMM, 0);
    a.label("clr");
    a.absn(STA_ABX, SID);
    a.imp(DEX);
    a.br(BPL, "clr");
    for v in 0..3u16 {
        let base = SID + 7 * v;
        a.imm(LDA_IMM, (PW[v as usize] & 0xFF) as u8);
        a.absn(STA_ABS, base + 2);
        a.imm(LDA_IMM, (PW[v as usize] >> 8) as u8);
        a.absn(STA_ABS, base + 3);
        a.imm(LDA_IMM, ADSR[v as usize].0);
        a.absn(STA_ABS, base + 5);
        a.imm(LDA_IMM, ADSR[v as usize].1);
        a.absn(STA_ABS, base + 6);
    }
    a.imm(LDA_IMM, 0x0F); // volume 15, no filter
    a.absn(STA_ABS, SID + 0x18);
    a.imm(LDA_IMM, 1);
    a.abs(STA_ABS, "counter"); // first play call starts step 0
    a.imm(LDA_IMM, (n - 1) as u8);
    a.abs(STA_ABS, "step");
    a.imm(LDA_IMM, 0);
    a.abs(STA_ABS, "arpbase");
    a.abs(STA_ABS, "arpidx");
    a.imp(RTS);

    // ---- play: once per frame
    a.label("play");
    a.abs(DEC_ABS, "counter");
    a.br(BNE, "held");
    a.abs(LDX_ABS, "step"); // next step, wrapping (the loop)
    a.imp(INX);
    a.imm(CPX_IMM, n as u8);
    a.br(BNE, "s1");
    a.imm(LDX_IMM, 0);
    a.label("s1");
    a.abs(STX_ABS, "step");
    a.abs(LDA_ABX, "dur");
    a.abs(STA_ABS, "counter");
    a.abs(LDA_ABX, "mlo");
    a.absn(STA_ABS, SID);
    a.abs(LDA_ABX, "mhi");
    a.absn(STA_ABS, SID + 1);
    a.abs(LDA_ABX, "blo");
    a.absn(STA_ABS, SID + 7);
    a.abs(LDA_ABX, "bhi");
    a.absn(STA_ABS, SID + 8);
    a.abs(LDA_ABX, "step3");
    a.abs(STA_ABS, "arpbase");
    a.imm(LDA_IMM, 0);
    a.abs(STA_ABS, "arpidx");
    for v in 0..3u16 {
        a.imm(LDA_IMM, WAVE[v as usize] | GATE);
        a.absn(STA_ABS, SID + 7 * v + 4);
    }
    a.abs(JMP_ABS, "arp");
    a.label("held");
    a.abs(LDA_ABS, "counter");
    a.imm(CMP_IMM, 2); // last 2 frames of a step: gate off (release), so the next note re-attacks
    a.br(BNE, "arp");
    for v in 0..3u16 {
        a.imm(LDA_IMM, WAVE[v as usize]);
        a.absn(STA_ABS, SID + 7 * v + 4);
    }
    a.label("arp");
    a.abs(LDA_ABS, "arpbase");
    a.imp(CLC);
    a.abs(ADC_ABS, "arpidx");
    a.imp(TAX);
    a.abs(LDA_ABX, "alo");
    a.absn(STA_ABS, SID + 14);
    a.abs(LDA_ABX, "ahi");
    a.absn(STA_ABS, SID + 15);
    a.abs(LDX_ABS, "arpidx");
    a.imp(INX);
    a.imm(CPX_IMM, 3);
    a.br(BNE, "a1");
    a.imm(LDX_IMM, 0);
    a.label("a1");
    a.abs(STX_ABS, "arpidx");
    a.imp(RTS);

    // ---- data
    let lo = |m: &[u8]| m.iter().map(|&x| (sid_freq(x) & 0xFF) as u8).collect::<Vec<_>>();
    let hi = |m: &[u8]| m.iter().map(|&x| (sid_freq(x) >> 8) as u8).collect::<Vec<_>>();
    let arp_flat: Vec<u8> = p.arp.iter().flatten().copied().collect();
    for (l, d) in [
        ("dur", p.frames.clone()),
        ("mlo", lo(&p.melody)),
        ("mhi", hi(&p.melody)),
        ("blo", lo(&p.bass)),
        ("bhi", hi(&p.bass)),
        ("step3", (0..n).map(|i| (3 * i) as u8).collect()),
        ("alo", lo(&arp_flat)),
        ("ahi", hi(&arp_flat)),
        ("counter", vec![0]),
        ("step", vec![0]),
        ("arpbase", vec![0]),
        ("arpidx", vec![0]),
    ] {
        a.label(l);
        a.bytes(&d);
    }
    a.finish().0
}

fn field(s: &str) -> [u8; 32] {
    let mut f = [0u8; 32];
    let b = s.as_bytes();
    f[..b.len().min(31)].copy_from_slice(&b[..b.len().min(31)]);
    f
}

/// A PSID v2 file: 0x7C-byte header, then the load address (LE) and the player.
/// One song, VBI speed, PAL, 6581, loadAddress 0 (real address in the first two data bytes).
pub fn psid(t: &[(usize, u32)]) -> Vec<u8> {
    let mut h = Vec::with_capacity(0x7C + 600);
    h.extend_from_slice(b"PSID");
    h.extend_from_slice(&2u16.to_be_bytes()); // version
    h.extend_from_slice(&0x7Cu16.to_be_bytes()); // dataOffset
    h.extend_from_slice(&0u16.to_be_bytes()); // loadAddress: in the data
    h.extend_from_slice(&INIT.to_be_bytes());
    h.extend_from_slice(&PLAY.to_be_bytes());
    h.extend_from_slice(&1u16.to_be_bytes()); // songs
    h.extend_from_slice(&1u16.to_be_bytes()); // startSong
    h.extend_from_slice(&0u32.to_be_bytes()); // speed: VBI (50 Hz on PAL)
    h.extend_from_slice(&field("Octavo key earworm"));
    h.extend_from_slice(&field("octavo hear --sid"));
    h.extend_from_slice(&field("2026 homemade, not for secrets"));
    h.extend_from_slice(&0x0014u16.to_be_bytes()); // flags: built-in player, PAL, 6581
    h.extend_from_slice(&[0, 0]); // startPage, pageLength
    h.extend_from_slice(&0u16.to_be_bytes()); // reserved (v2)
    debug_assert_eq!(h.len(), 0x7C);
    h.extend_from_slice(&LOAD.to_le_bytes());
    h.extend_from_slice(&player(t));
    h
}

// ---------------------------------------------------------------- minimal 6502 (player subset)
/// Just enough 6502 to run our own player (the opcodes `player` emits). Writes to $D400-$D41F are
/// passed to `sid`.
struct Cpu {
    a: u8,
    x: u8,
    sp: u8,
    pc: u16,
    n: bool,
    z: bool,
    c: bool,
    mem: Vec<u8>,
}
impl Cpu {
    fn rd16(&self, a: u16) -> u16 {
        u16::from_le_bytes([self.mem[a as usize], self.mem[a.wrapping_add(1) as usize]])
    }
    fn nz(&mut self, v: u8) {
        self.n = v & 0x80 != 0;
        self.z = v == 0;
    }
    fn wr(&mut self, a: u16, v: u8, sid: &mut Sid) {
        self.mem[a as usize] = v;
        if (SID..SID + 0x20).contains(&a) {
            sid.write((a - SID) as u8, v);
        }
    }
    /// JSR to `addr` with A = `a`, run until its RTS.
    fn call(&mut self, addr: u16, a: u8, sid: &mut Sid) -> Result<(), String> {
        self.a = a;
        self.mem[0x100 + self.sp as usize] = 0xFF; // return address $FFFF (pushed as $FFFE)
        self.sp = self.sp.wrapping_sub(1);
        self.mem[0x100 + self.sp as usize] = 0xFE;
        self.sp = self.sp.wrapping_sub(1);
        self.pc = addr;
        for _ in 0..100_000 {
            if self.pc == 0xFFFF {
                return Ok(());
            }
            let op = self.mem[self.pc as usize];
            let o8 = self.mem[self.pc.wrapping_add(1) as usize];
            let o16 = self.rd16(self.pc.wrapping_add(1));
            match op {
                LDA_IMM => { self.a = o8; self.nz(o8); self.pc += 2 }
                LDA_ABS => { self.a = self.mem[o16 as usize]; self.nz(self.a); self.pc += 3 }
                LDA_ABX => { self.a = self.mem[o16.wrapping_add(self.x as u16) as usize]; self.nz(self.a); self.pc += 3 }
                STA_ABS => { self.wr(o16, self.a, sid); self.pc += 3 }
                STA_ABX => { self.wr(o16.wrapping_add(self.x as u16), self.a, sid); self.pc += 3 }
                LDX_IMM => { self.x = o8; self.nz(o8); self.pc += 2 }
                LDX_ABS => { self.x = self.mem[o16 as usize]; self.nz(self.x); self.pc += 3 }
                STX_ABS => { self.wr(o16, self.x, sid); self.pc += 3 }
                INX => { self.x = self.x.wrapping_add(1); self.nz(self.x); self.pc += 1 }
                DEX => { self.x = self.x.wrapping_sub(1); self.nz(self.x); self.pc += 1 }
                CPX_IMM | CMP_IMM => {
                    let r = if op == CPX_IMM { self.x } else { self.a };
                    self.c = r >= o8;
                    self.nz(r.wrapping_sub(o8));
                    self.pc += 2
                }
                BNE | BPL => {
                    let take = if op == BNE { !self.z } else { !self.n };
                    self.pc += 2;
                    if take {
                        self.pc = self.pc.wrapping_add(o8 as i8 as u16);
                    }
                }
                DEC_ABS => { let v = self.mem[o16 as usize].wrapping_sub(1); self.wr(o16, v, sid); self.nz(v); self.pc += 3 }
                CLC => { self.c = false; self.pc += 1 }
                ADC_ABS => {
                    let s = self.a as u16 + self.mem[o16 as usize] as u16 + self.c as u16;
                    self.c = s > 0xFF;
                    self.a = s as u8;
                    self.nz(self.a);
                    self.pc += 3
                }
                TAX => { self.x = self.a; self.nz(self.x); self.pc += 1 }
                JMP_ABS => self.pc = o16,
                RTS => {
                    self.sp = self.sp.wrapping_add(1);
                    let lo = self.mem[0x100 + self.sp as usize];
                    self.sp = self.sp.wrapping_add(1);
                    let hi = self.mem[0x100 + self.sp as usize];
                    self.pc = u16::from_le_bytes([lo, hi]).wrapping_add(1);
                }
                _ => return Err(format!("6502: opcode {op:#04x} at {:#06x} not supported", self.pc)),
            }
        }
        Err("6502: routine did not return".into())
    }
}

// ---------------------------------------------------------------- SID-style synth
/// ADSR rate counter periods in cycles (the SID's documented 2 ms .. 8 s attack times / 256 steps).
const RATE: [u32; 16] = [9, 32, 63, 95, 149, 220, 267, 313, 392, 977, 1954, 3126, 3907, 11720, 19532, 31251];

#[derive(Clone, Copy, PartialEq)]
enum Stage {
    Attack,
    Decay,
    Release,
}

#[derive(Clone, Copy)]
struct Voice {
    freq: u16,
    pw: u16,
    ctrl: u8,
    ad: u8,
    sr: u8,
    acc: u32,
    lfsr: u32,
    env: u8,
    stage: Stage,
    rate_ctr: u32,
    exp_ctr: u32,
}
impl Voice {
    fn new() -> Self {
        Voice { freq: 0, pw: 0, ctrl: 0, ad: 0, sr: 0, acc: 0, lfsr: 0x7F_FFF8, env: 0, stage: Stage::Release, rate_ctr: 0, exp_ctr: 0 }
    }
    fn set_ctrl(&mut self, v: u8) {
        let (was, now) = (self.ctrl & 1, v & 1);
        if now == 1 && was == 0 {
            self.stage = Stage::Attack;
        } else if now == 0 && was == 1 {
            self.stage = Stage::Release;
        }
        self.ctrl = v;
    }
    fn clock(&mut self) {
        if self.ctrl & 0x08 != 0 {
            self.acc = 0; // test bit
        } else {
            let old = self.acc;
            self.acc = (self.acc + self.freq as u32) & 0xFF_FFFF;
            if old & 0x8_0000 == 0 && self.acc & 0x8_0000 != 0 {
                let bit = ((self.lfsr >> 22) ^ (self.lfsr >> 17)) & 1;
                self.lfsr = ((self.lfsr << 1) | bit) & 0x7F_FFFF;
            }
        }
        let nib = match self.stage {
            Stage::Attack => self.ad >> 4,
            Stage::Decay => self.ad & 15,
            Stage::Release => self.sr & 15,
        };
        self.rate_ctr += 1;
        if self.rate_ctr < RATE[nib as usize] {
            return;
        }
        self.rate_ctr = 0;
        if self.stage == Stage::Attack {
            self.env = self.env.saturating_add(1);
            if self.env == 0xFF {
                self.stage = Stage::Decay;
            }
            return;
        }
        // decay / release: the SID's piecewise "exponential" slow-down
        let period = match self.env {
            0..=6 => 30,
            7..=14 => 16,
            15..=26 => 8,
            27..=54 => 4,
            55..=93 => 2,
            _ => 1,
        };
        self.exp_ctr += 1;
        if self.exp_ctr < period {
            return;
        }
        self.exp_ctr = 0;
        let floor = if self.stage == Stage::Decay { (self.sr >> 4) * 17 } else { 0 };
        if self.env > floor {
            self.env -= 1;
        }
    }
    /// 12-bit waveform output (combined waveforms are ANDed, roughly like the chip)
    fn wave(&self, ring_msb: bool) -> Option<u16> {
        let w = self.ctrl >> 4;
        if w == 0 {
            return None;
        }
        let mut out = 0xFFFu16;
        if w & 1 != 0 {
            let msb = (self.acc & 0x80_0000 != 0) ^ (self.ctrl & 0x04 != 0 && ring_msb);
            let t = if msb { !self.acc } else { self.acc };
            out &= ((t >> 11) & 0xFFF) as u16;
        }
        if w & 2 != 0 {
            out &= (self.acc >> 12) as u16;
        }
        if w & 4 != 0 {
            out &= if (self.acc >> 12) as u16 >= self.pw { 0xFFF } else { 0 };
        }
        if w & 8 != 0 {
            let l = self.lfsr;
            let n = ((l >> 20) & 1) << 11 | ((l >> 18) & 1) << 10 | ((l >> 14) & 1) << 9 | ((l >> 11) & 1) << 8
                | ((l >> 9) & 1) << 7 | ((l >> 5) & 1) << 6 | ((l >> 2) & 1) << 5 | (l & 1) << 4;
            out &= n as u16;
        }
        Some(out)
    }
}

/// Three voices + master volume. No filter (the player never enables it).
pub struct Sid {
    v: [Voice; 3],
    vol: u8,
    /// every register write, in order (for tests and debugging)
    pub writes: Vec<(u8, u8)>,
}
impl Default for Sid {
    fn default() -> Self {
        Sid { v: [Voice::new(); 3], vol: 0, writes: vec![] }
    }
}
impl Sid {
    pub fn write(&mut self, r: u8, val: u8) {
        self.writes.push((r, val));
        let (vi, k) = ((r / 7) as usize, r % 7);
        if vi < 3 {
            let v = &mut self.v[vi];
            match k {
                0 => v.freq = (v.freq & 0xFF00) | val as u16,
                1 => v.freq = (v.freq & 0x00FF) | (val as u16) << 8,
                2 => v.pw = (v.pw & 0xF00) | val as u16,
                3 => v.pw = (v.pw & 0x0FF) | ((val as u16 & 15) << 8),
                4 => v.set_ctrl(val),
                5 => v.ad = val,
                _ => v.sr = val,
            }
        } else if r == 0x18 {
            self.vol = val & 15;
        }
    }
    /// one CPU cycle; returns the mixed output (unscaled)
    fn clock(&mut self) -> f64 {
        for v in &mut self.v {
            v.clock();
        }
        let msb = [self.v[2].acc & 0x80_0000 != 0, self.v[0].acc & 0x80_0000 != 0, self.v[1].acc & 0x80_0000 != 0];
        let mut s = 0.0;
        for (i, v) in self.v.iter().enumerate() {
            if let Some(w) = v.wave(msb[i]) {
                s += (w as f64 - 2048.0) * v.env as f64;
            }
        }
        s * self.vol as f64 / 15.0
    }
}

/// Frames in one pass of the tune.
pub fn loop_frames(t: &[(usize, u32)]) -> u32 {
    parts(t).frames.iter().map(|&f| f as u32).sum()
}

/// Run the player: init, then `frames` play calls; returns the register writes of each call
/// (index 0 = init).
pub fn run_player(t: &[(usize, u32)], frames: u32) -> Result<Vec<Vec<(u8, u8)>>, String> {
    let mut sid = Sid::default();
    let mut cpu = load(t);
    let mut out = vec![];
    cpu.call(INIT, 0, &mut sid)?;
    out.push(std::mem::take(&mut sid.writes));
    for _ in 0..frames {
        cpu.call(PLAY, 0, &mut sid)?;
        out.push(std::mem::take(&mut sid.writes));
    }
    Ok(out)
}

fn load(t: &[(usize, u32)]) -> Cpu {
    let mut mem = vec![0u8; 65536];
    let prg = player(t);
    mem[LOAD as usize..LOAD as usize + prg.len()].copy_from_slice(&prg);
    Cpu { a: 0, x: 0, sp: 0xFF, pc: 0, n: false, z: false, c: false, mem }
}

/// Raw mono PCM: `loops` passes of the tune at 44.1 kHz through the SID-style synth, with a short
/// fade-out at the end. The 6581 output stage is approximated by a one-pole low-pass (~12 kHz) and
/// a DC-blocking high-pass (~20 Hz).
pub fn render(t: &[(usize, u32)], loops: u32) -> Result<Vec<i16>, String> {
    let mut sid = Sid::default();
    let mut cpu = load(t);
    cpu.call(INIT, 0, &mut sid)?;
    let frames = loop_frames(t) * loops;
    let cps = PAL_CLOCK / WAV_RATE as f64; // cycles per sample
    let mut pcm = Vec::with_capacity((frames as f64 * PAL_FRAME_CYCLES as f64 / cps) as usize + 2);
    let (mut acc, mut cnt, mut next) = (0.0f64, 0u32, cps);
    let mut cyc = 0.0f64;
    let lp_a = 1.0 - (-2.0 * std::f64::consts::PI * 12_000.0 / WAV_RATE as f64).exp();
    let hp_r = (-2.0 * std::f64::consts::PI * 20.0 / WAV_RATE as f64).exp();
    let (mut lp, mut hp_x, mut hp_y) = (0.0f64, 0.0f64, 0.0f64);
    let full = 3.0 * 2048.0 * 255.0;
    for _ in 0..frames {
        cpu.call(PLAY, 0, &mut sid)?;
        sid.writes.clear();
        for _ in 0..PAL_FRAME_CYCLES {
            acc += sid.clock();
            cnt += 1;
            cyc += 1.0;
            if cyc >= next {
                next += cps;
                let x = acc / cnt as f64 / full;
                acc = 0.0;
                cnt = 0;
                lp += lp_a * (x - lp);
                hp_y = hp_r * (hp_y + lp - hp_x);
                hp_x = lp;
                pcm.push(hp_y);
            }
        }
    }
    let fade = (WAV_RATE as usize / 2).min(pcm.len());
    let len = pcm.len();
    for (i, s) in pcm[len - fade..].iter_mut().enumerate() {
        *s *= 1.0 - i as f64 / fade as f64;
    }
    Ok(pcm.into_iter().map(|s| (s * 0.9 * 32767.0).clamp(-32768.0, 32767.0) as i16).collect())
}

/// 16-bit mono 44.1 kHz WAV of two passes of the SID tune.
pub fn sid_wav(t: &[(usize, u32)]) -> Result<Vec<u8>, String> {
    let pcm = render(t, 2)?;
    let data_len = (pcm.len() * 2) as u32;
    let mut w = Vec::with_capacity(44 + data_len as usize);
    w.extend_from_slice(b"RIFF");
    w.extend_from_slice(&(36 + data_len).to_le_bytes());
    w.extend_from_slice(b"WAVEfmt ");
    w.extend_from_slice(&16u32.to_le_bytes());
    w.extend_from_slice(&1u16.to_le_bytes());
    w.extend_from_slice(&1u16.to_le_bytes());
    w.extend_from_slice(&WAV_RATE.to_le_bytes());
    w.extend_from_slice(&(WAV_RATE * 2).to_le_bytes());
    w.extend_from_slice(&2u16.to_le_bytes());
    w.extend_from_slice(&16u16.to_le_bytes());
    w.extend_from_slice(b"data");
    w.extend_from_slice(&data_len.to_le_bytes());
    for s in pcm {
        w.extend_from_slice(&s.to_le_bytes());
    }
    Ok(w)
}
