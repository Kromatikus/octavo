//! Per-layer latency of the gfni-simd engine: cargo run --release --example profile
fn main() {
    let seed: [u8; 128] = core::array::from_fn(|i| ((i as u32).wrapping_mul(2654435761) >> 13) as u8);
    let sch = octavo_core::Schedule::new(&seed, &[7u8; 16]);
    let key = octavo_core::simd::SimdKey::new(&sch).expect("gfni-simd unavailable");
    for (n, ns) in octavo_core::simd::profile_layers(&key) {
        println!("{n:>10}: {ns:7.1} ns");
    }
}
