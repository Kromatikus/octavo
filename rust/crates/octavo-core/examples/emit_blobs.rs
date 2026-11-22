//! Emit Rust-sealed blobs for random inputs so tools/check_rust_blobs.py can open them with the
//! real sneak_n2.py (Rust -> Python direction). Deterministic xorshift RNG; NOT a secure RNG.
use octavo_core::formats::{self, Ctx};

struct X(u64);
impl X {
    fn next(&mut self) -> u8 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 >> 24) as u8
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next()).collect()
    }
}

fn main() {
    let seed_hex = std::env::args().nth(1).expect("usage: emit_blobs <seed-hex-128-bytes>");
    let seed: [u8; 128] = hex::decode(seed_hex).unwrap().try_into().unwrap();
    let ctx = Ctx::live(&seed);
    let mut r = X(0x0c7a_7001_2026_1121);
    let mut out = Vec::new();
    for i in 0..12 {
        let len = r.next() as usize % 128;
        let msg = r.bytes(len);
        let ad = r.bytes([0, 3, 40][i % 3]);
        let pickup: [u8; 16] = r.bytes(16).try_into().unwrap();
        let b = formats::seal_block(&ctx, &msg, &pickup, &ad).unwrap();
        out.push(format!("{{\"mode\":\"v6\",\"msg\":\"{}\",\"ad\":\"{}\",\"blob\":\"{}\"}}", hex::encode(&msg), hex::encode(&ad), hex::encode(&b)));
    }
    for len in [0usize, 127, 128, 500] {
        let msg = r.bytes(len);
        let pickup: [u8; 16] = r.bytes(16).try_into().unwrap();
        let b = formats::seal_movements(&ctx, &msg, &pickup, b"mv").unwrap();
        out.push(format!("{{\"mode\":\"v7\",\"msg\":\"{}\",\"ad\":\"{}\",\"blob\":\"{}\"}}", hex::encode(&msg), hex::encode(b"mv"), hex::encode(&b)));
    }
    for (cs, len) in [(128usize, 300usize), (1024, 2048), (256, 0)] {
        let msg = r.bytes(len);
        let pickup: [u8; 16] = r.bytes(16).try_into().unwrap();
        let nonce: [u8; 16] = r.bytes(16).try_into().unwrap();
        let (b, _) = formats::seal_rehearsal(&seed, &msg, &pickup, &nonce, cs, b"rh").unwrap();
        out.push(format!("{{\"mode\":\"v9\",\"msg\":\"{}\",\"ad\":\"{}\",\"blob\":\"{}\"}}", hex::encode(&msg), hex::encode(b"rh"), hex::encode(&b)));
    }
    // multi-threaded seals (pipelined tag chain); identical bytes to 1 thread, opened by Python too
    for (cs, len, th) in [(1024usize, 6000usize, 8usize), (128, 1000, 3)] {
        let msg = r.bytes(len);
        let pickup: [u8; 16] = r.bytes(16).try_into().unwrap();
        let nonce: [u8; 16] = r.bytes(16).try_into().unwrap();
        let (b, _) = formats::seal_rehearsal_threads(&seed, &msg, &pickup, &nonce, cs, b"rt", th).unwrap();
        let (b1, _) = formats::seal_rehearsal(&seed, &msg, &pickup, &nonce, cs, b"rt").unwrap();
        assert_eq!(b, b1, "thread count changed the bytes");
        out.push(format!("{{\"mode\":\"v9\",\"msg\":\"{}\",\"ad\":\"{}\",\"blob\":\"{}\"}}", hex::encode(&msg), hex::encode(b"rt"), hex::encode(&b)));
    }
    println!("[{}]", out.join(",\n"));
}
