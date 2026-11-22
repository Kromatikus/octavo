//! Independent minimal NMOS 6502 for the SID tests (written for the tests, separate from the
//! player-subset core in src/sid.rs). Official opcodes only, binary mode (no decimal), no cycle
//! counting. Writes to $D400-$D41F are recorded as (frame, register, value).

pub struct Mos6502 {
    pub a: u8,
    pub x: u8,
    pub y: u8,
    pub sp: u8,
    pub pc: u16,
    pub p: u8, // N V - B D I Z C
    pub mem: Vec<u8>,
    pub sid_writes: Vec<(u32, u8, u8)>,
    pub frame: u32,
}

const C: u8 = 0x01;
const Z: u8 = 0x02;
const D: u8 = 0x08;
const V: u8 = 0x40;
const N: u8 = 0x80;

#[derive(Clone, Copy)]
enum M {
    Imp,
    Acc,
    Imm,
    Zp,
    Zpx,
    Zpy,
    Abs,
    Abx,
    Aby,
    Ind,
    Izx,
    Izy,
    Rel,
}

impl Mos6502 {
    pub fn new() -> Self {
        Mos6502 { a: 0, x: 0, y: 0, sp: 0xFF, pc: 0, p: 0x24, mem: vec![0; 65536], sid_writes: vec![], frame: 0 }
    }
    fn rd(&self, a: u16) -> u8 {
        self.mem[a as usize]
    }
    fn rd16(&self, a: u16) -> u16 {
        u16::from_le_bytes([self.rd(a), self.rd(a.wrapping_add(1))])
    }
    fn wr(&mut self, a: u16, v: u8) {
        if (0xD400..0xD420).contains(&a) {
            self.sid_writes.push((self.frame, (a - 0xD400) as u8, v));
        }
        self.mem[a as usize] = v;
    }
    fn push(&mut self, v: u8) {
        self.mem[0x100 + self.sp as usize] = v;
        self.sp = self.sp.wrapping_sub(1);
    }
    fn pop(&mut self) -> u8 {
        self.sp = self.sp.wrapping_add(1);
        self.mem[0x100 + self.sp as usize]
    }
    fn set(&mut self, f: u8, on: bool) {
        if on {
            self.p |= f
        } else {
            self.p &= !f
        }
    }
    fn nz(&mut self, v: u8) -> u8 {
        self.set(Z, v == 0);
        self.set(N, v & 0x80 != 0);
        v
    }
    /// effective address and instruction length
    fn ea(&self, m: M) -> (u16, u16) {
        let pc1 = self.pc.wrapping_add(1);
        let b = self.rd(pc1);
        let w = self.rd16(pc1);
        match m {
            M::Imp | M::Acc => (0, 1),
            M::Imm => (pc1, 2),
            M::Zp => (b as u16, 2),
            M::Zpx => (b.wrapping_add(self.x) as u16, 2),
            M::Zpy => (b.wrapping_add(self.y) as u16, 2),
            M::Abs => (w, 3),
            M::Abx => (w.wrapping_add(self.x as u16), 3),
            M::Aby => (w.wrapping_add(self.y as u16), 3),
            M::Ind => {
                // the NMOS page-wrap bug
                let hi = (w & 0xFF00) | (w.wrapping_add(1) & 0x00FF);
                (u16::from_le_bytes([self.rd(w), self.rd(hi)]), 3)
            }
            M::Izx => {
                let z = b.wrapping_add(self.x);
                (u16::from_le_bytes([self.rd(z as u16), self.rd(z.wrapping_add(1) as u16)]), 2)
            }
            M::Izy => {
                let base = u16::from_le_bytes([self.rd(b as u16), self.rd(b.wrapping_add(1) as u16)]);
                (base.wrapping_add(self.y as u16), 2)
            }
            M::Rel => (self.pc.wrapping_add(2).wrapping_add(b as i8 as u16), 2),
        }
    }
    fn adc(&mut self, v: u8) {
        assert!(self.p & D == 0, "decimal mode not emulated");
        let s = self.a as u16 + v as u16 + (self.p & C) as u16;
        let r = s as u8;
        self.set(C, s > 0xFF);
        self.set(V, (!(self.a ^ v) & (self.a ^ r) & 0x80) != 0);
        self.a = self.nz(r);
    }
    fn cmp(&mut self, r: u8, v: u8) {
        self.set(C, r >= v);
        self.nz(r.wrapping_sub(v));
    }

    /// Execute one instruction. Panics on an undocumented opcode.
    pub fn step(&mut self) {
        use M::*;
        let op = self.rd(self.pc);
        // group-decoded addressing modes for the regular "cc=01" ALU group
        let alu_mode = |op: u8| match (op >> 2) & 7 {
            0 => Izx,
            1 => Zp,
            2 => Imm,
            3 => Abs,
            4 => Izy,
            5 => Zpx,
            6 => Aby,
            _ => Abx,
        };
        let m = match op {
            0x01..=0xFF if op & 3 == 1 => alu_mode(op),
            0x0A | 0x2A | 0x4A | 0x6A => Acc,
            0x06 | 0x26 | 0x46 | 0x66 | 0xC6 | 0xE6 | 0x86 | 0xA6 | 0x84 | 0xA4 | 0xC4 | 0xE4 | 0x24 => Zp,
            0x16 | 0x36 | 0x56 | 0x76 | 0xD6 | 0xF6 | 0x94 | 0xB4 => Zpx,
            0x96 | 0xB6 => Zpy,
            0x0E | 0x2E | 0x4E | 0x6E | 0xCE | 0xEE | 0x8E | 0xAE | 0x8C | 0xAC | 0xCC | 0xEC | 0x2C | 0x4C | 0x20 => Abs,
            0x1E | 0x3E | 0x5E | 0x7E | 0xDE | 0xFE | 0xBC => Abx,
            0xBE => Aby,
            0x6C => Ind,
            0xA0 | 0xA2 | 0xC0 | 0xE0 => Imm,
            0x10 | 0x30 | 0x50 | 0x70 | 0x90 | 0xB0 | 0xD0 | 0xF0 => Rel,
            _ => Imp,
        };
        let (ea, len) = self.ea(m);
        let next = self.pc.wrapping_add(len);
        self.pc = next;
        let ld = |s: &Self| s.rd(ea);
        // read-modify-write helper
        macro_rules! rmw {
            ($f:expr) => {{
                let v = if let Acc = m { self.a } else { self.rd(ea) };
                let r: u8 = $f(self, v);
                let r = self.nz(r);
                if let Acc = m {
                    self.a = r
                } else {
                    self.wr(ea, r)
                }
            }};
        }
        match op {
            // ALU group (cc = 01)
            _ if op & 3 == 1 => match op >> 5 {
                0 => { let v = ld(self); self.a = self.nz(self.a | v) }
                1 => { let v = ld(self); self.a = self.nz(self.a & v) }
                2 => { let v = ld(self); self.a = self.nz(self.a ^ v) }
                3 => { let v = ld(self); self.adc(v) }
                4 => { assert!(op != 0x89, "undocumented"); self.wr(ea, self.a) }
                5 => { let v = ld(self); self.a = self.nz(v) }
                6 => { let v = ld(self); self.cmp(self.a, v) }
                _ => { let v = ld(self); self.adc(!v) }
            },
            0x0A | 0x06 | 0x16 | 0x0E | 0x1E => rmw!(|s: &mut Self, v: u8| { s.set(C, v & 0x80 != 0); v << 1 }),
            0x4A | 0x46 | 0x56 | 0x4E | 0x5E => rmw!(|s: &mut Self, v: u8| { s.set(C, v & 1 != 0); v >> 1 }),
            0x2A | 0x26 | 0x36 | 0x2E | 0x3E => rmw!(|s: &mut Self, v: u8| { let c = s.p & C; s.set(C, v & 0x80 != 0); (v << 1) | c }),
            0x6A | 0x66 | 0x76 | 0x6E | 0x7E => rmw!(|s: &mut Self, v: u8| { let c = s.p & C; s.set(C, v & 1 != 0); (v >> 1) | (c << 7) }),
            0xC6 | 0xD6 | 0xCE | 0xDE => rmw!(|_s: &mut Self, v: u8| v.wrapping_sub(1)),
            0xE6 | 0xF6 | 0xEE | 0xFE => rmw!(|_s: &mut Self, v: u8| v.wrapping_add(1)),
            0x86 | 0x96 | 0x8E => self.wr(ea, self.x),
            0x84 | 0x94 | 0x8C => self.wr(ea, self.y),
            0xA2 | 0xA6 | 0xB6 | 0xAE | 0xBE => { let v = ld(self); self.x = self.nz(v) }
            0xA0 | 0xA4 | 0xB4 | 0xAC | 0xBC => { let v = ld(self); self.y = self.nz(v) }
            0xE0 | 0xE4 | 0xEC => { let v = ld(self); self.cmp(self.x, v) }
            0xC0 | 0xC4 | 0xCC => { let v = ld(self); self.cmp(self.y, v) }
            0x24 | 0x2C => {
                let v = ld(self);
                self.set(Z, self.a & v == 0);
                self.set(N, v & 0x80 != 0);
                self.set(V, v & 0x40 != 0);
            }
            0x10 | 0x30 | 0x50 | 0x70 | 0x90 | 0xB0 | 0xD0 | 0xF0 => {
                let (flag, want) = match op >> 6 {
                    0 => (N, op & 0x20 != 0),
                    1 => (V, op & 0x20 != 0),
                    2 => (C, op & 0x20 != 0),
                    _ => (Z, op & 0x20 != 0),
                };
                if (self.p & flag != 0) == want {
                    self.pc = ea;
                }
            }
            0x4C | 0x6C => self.pc = ea,
            0x20 => {
                let r = next.wrapping_sub(1);
                self.push((r >> 8) as u8);
                self.push(r as u8);
                self.pc = ea;
            }
            0x60 => {
                let lo = self.pop();
                let hi = self.pop();
                self.pc = u16::from_le_bytes([lo, hi]).wrapping_add(1);
            }
            0x40 => {
                self.p = self.pop() | 0x20;
                let lo = self.pop();
                let hi = self.pop();
                self.pc = u16::from_le_bytes([lo, hi]);
            }
            0x48 => self.push(self.a),
            0x68 => { let v = self.pop(); self.a = self.nz(v) }
            0x08 => self.push(self.p | 0x30),
            0x28 => self.p = self.pop() | 0x20,
            0xAA => self.x = self.nz(self.a),
            0xA8 => self.y = self.nz(self.a),
            0x8A => self.a = self.nz(self.x),
            0x98 => self.a = self.nz(self.y),
            0xBA => self.x = self.nz(self.sp),
            0x9A => self.sp = self.x,
            0xE8 => self.x = self.nz(self.x.wrapping_add(1)),
            0xC8 => self.y = self.nz(self.y.wrapping_add(1)),
            0xCA => self.x = self.nz(self.x.wrapping_sub(1)),
            0x88 => self.y = self.nz(self.y.wrapping_sub(1)),
            0x18 => self.set(C, false),
            0x38 => self.set(C, true),
            0x58 => self.p &= !0x04,
            0x78 => self.p |= 0x04,
            0xB8 => self.set(V, false),
            0xD8 => self.set(D, false),
            0xF8 => self.set(D, true),
            0xEA => {}
            _ => panic!("undocumented/unsupported opcode {op:#04x} at {:#06x}", self.pc.wrapping_sub(len)),
        }
    }

    /// JSR `addr` with A = `a` from a sentinel and run until the matching RTS (max `limit` steps).
    pub fn call(&mut self, addr: u16, a: u8, limit: usize) {
        self.a = a;
        let sp0 = self.sp;
        self.push(0xFF);
        self.push(0xFE); // returns to $FFFF
        self.pc = addr;
        for _ in 0..limit {
            if self.pc == 0xFFFF {
                assert_eq!(self.sp, sp0, "stack unbalanced");
                return;
            }
            self.step();
        }
        panic!("routine at {addr:#06x} did not return within {limit} instructions");
    }
}
