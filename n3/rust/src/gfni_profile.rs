// Lab-only layer profiler for the AVX-512+GFNI backend. Does not change cipher output.
use std::hint::black_box;
use std::time::Instant;

fn cycles() -> u64 {
    unsafe {
        core::arch::x86_64::_mm_mfence();
        core::arch::x86_64::_mm_lfence();
        let t = core::arch::x86_64::_rdtsc();
        core::arch::x86_64::_mm_lfence();
        t
    }
}

pub fn run_layer_profile(key: &GfniKey) {
    unsafe { run_layer_profile_avx(key) }
}

#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn run_layer_profile_avx(key: &GfniKey) {
    let mut block = [0u8; BLOCK_LEN];
    for (i, b) in block.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(3).wrapping_add(0x11);
    }
    let c = &key.c;
    let rk = &key.rounds[0];

    let n1 = 200_000usize;
    println!("\n== per-layer (one 128-byte block, AVX-512+GFNI encrypt_one path, {n1} iters) ==");

    // Shared state, refreshed from a real block so layouts are valid.
    let (z0_0, z1_0) = load_block(&block);
    let faces0 = split_faces(z0_0, z1_0);
    let cols0 = faces_to_cols(&faces0);

    let xor_t = {
        let mut z0 = z0_0;
        let mut z1 = z1_0;
        time_n(n1, || {
            let p = xor_rk(z0, z1, &rk.rk);
            z0 = p.0;
            z1 = p.1;
            black_box((z0, z1));
        })
    };
    record("xor_rk", xor_t, n1);

    let sbox_t = {
        let mut z0 = z0_0;
        let mut z1 = z1_0;
        time_n(n1, || {
            let p = sbox_block(z0, z1, &rk.s);
            z0 = p.0;
            z1 = p.1;
            black_box((z0, z1));
        })
    };
    record("sbox_block", sbox_t, n1);

    let split_t = {
        let mut z0 = z0_0;
        let mut z1 = z1_0;
        time_n(n1, || {
            let f = split_faces(z0, z1);
            let p = join_faces(&f);
            z0 = p.0;
            z1 = p.1;
            black_box((z0, z1));
        })
    };
    record("split+join_faces", split_t, n1);

    let tocols_t = {
        let mut faces = faces0;
        time_n(n1, || {
            let cols = faces_to_cols(&faces);
            faces = cols_to_faces(&cols);
            black_box(&faces);
        })
    };
    record("faces_to/from_cols", tocols_t, n1);

    let staff_t = {
        let mut cols = cols0;
        time_n(n1, || {
            staff_fwd_x(&mut cols);
            black_box(&cols);
        })
    };
    record("staff_fwd (field)", staff_t, n1);

    let staff_i = {
        let mut cols = cols0;
        time_n(n1, || {
            staff_inv_x(&mut cols);
            black_box(&cols);
        })
    };
    record("staff_inv (field)", staff_i, n1);

    let faces_t = {
        let mut faces = faces0;
        time_n(n1, || {
            faces_fwd_x(&mut faces);
            black_box(&faces);
        })
    };
    record("faces_fwd (field)", faces_t, n1);

    let faces_i = {
        let mut faces = faces0;
        time_n(n1, || {
            faces_inv_x(&mut faces);
            black_box(&faces);
        })
    };
    record("faces_inv (field)", faces_i, n1);

    let br_t = {
        let mut z0 = z0_0;
        let mut z1 = z1_0;
        time_n(n1, || {
            let p = bridges(z0, z1, rk, c, false);
            z0 = p.0;
            z1 = p.1;
            black_box((z0, z1));
        })
    };
    record("bridges_fwd (perm)", br_t, n1);

    let br_i = {
        let mut z0 = z0_0;
        let mut z1 = z1_0;
        time_n(n1, || {
            let p = bridges(z0, z1, rk, c, true);
            z0 = p.0;
            z1 = p.1;
            black_box((z0, z1));
        })
    };
    record("bridges_inv (perm)", br_i, n1);

    let trip_t = {
        let mut cols = cols0;
        time_n(n1, || {
            trip_fwd_x(&mut cols);
            black_box(&cols);
        })
    };
    record("trip_fwd", trip_t, n1);

    let trip_i = {
        let mut cols = cols0;
        time_n(n1, || {
            trip_inv_x(&mut cols);
            black_box(&cols);
        })
    };
    record("trip_inv", trip_i, n1);

    let bow_t = {
        let mut cols = cols0;
        time_n(n1, || {
            bow_cols(&mut cols, c, false);
            black_box(&cols);
        })
    };
    record("bow (8-stroke)", bow_t, n1);

    let bow_i = {
        let mut cols = cols0;
        time_n(n1, || {
            bow_cols(&mut cols, c, true);
            black_box(&cols);
        })
    };
    record("unbow (8-stroke)", bow_i, n1);

    let cross_t = {
        let mut faces = faces0;
        time_n(n1, || {
            cross_fwd_x(&mut faces);
            black_box(&faces);
        })
    };
    record("cross_fwd", cross_t, n1);

    let cross_i = {
        let mut faces = faces0;
        time_n(n1, || {
            cross_inv_x(&mut faces);
            black_box(&faces);
        })
    };
    record("cross_inv", cross_i, n1);

    // Full one-block encrypt/decrypt
    let enc1 = {
        let mut b = block;
        time_n(n1, || {
            encrypt_one(key, &mut b);
            black_box(&b);
        })
    };
    let dec1 = {
        let mut b = block;
        encrypt_one(key, &mut b);
        time_n(n1, || {
            decrypt_one(key, &mut b);
            black_box(&b);
        })
    };
    let enc_ns = enc1.0 * 1e9 / n1 as f64;
    let dec_ns = dec1.0 * 1e9 / n1 as f64;
    println!(
        "\n  encrypt_one            {:>8.1} ns  {:>7.0} cyc  {:>6.1} MB/s",
        enc_ns,
        enc1.1 / n1 as f64,
        mbs(enc_ns, 1)
    );
    println!(
        "  decrypt_one            {:>8.1} ns  {:>7.0} cyc  {:>6.1} MB/s",
        dec_ns,
        dec1.1 / n1 as f64,
        mbs(dec_ns, 1)
    );

    // Share of one 16-round encrypt (counts x ns/call)
    // per round: xor, sbox s, split+join (around chord), faces_to/from_cols (around staff),
    // staff, faces, bridges, split+join (around trip/bow), faces_to/from_cols, trip, bow,
    // sbox sm, split+join (around cross), cross, sbox s2; plus final xor.
    // From encrypt_one:
    //   xor_rk: 16 + 1 white
    //   sbox_block: 16*3
    //   split_faces+join: 3 per round (chord, trip/bow, cross) — we timed split+join together
    //   faces_to/from_cols: 2 per round (staff, trip/bow)
    //   staff, faces, bridges, trip, bow, cross: 16 each
    let enc_items: &[(&str, f64, usize)] = &[
        ("xor_rk", ns(xor_t, n1), 17),
        ("sbox_block", ns(sbox_t, n1), 48),
        ("staff_fwd (field)", ns(staff_t, n1), 16),
        ("faces_fwd (field)", ns(faces_t, n1), 16),
        ("bridges_fwd (perm)", ns(br_t, n1), 16),
        ("trip_fwd", ns(trip_t, n1), 16),
        ("bow (8-stroke)", ns(bow_t, n1), 16),
        ("cross_fwd", ns(cross_t, n1), 16),
        ("split+join_faces", ns(split_t, n1), 48),
        ("faces_to/from_cols", ns(tocols_t, n1), 32),
    ];
    println!("\n== layer share of one 16-round 128-byte encrypt (encrypt_one path) ==");
    print_share(enc_items, enc_ns);

    let dec_items: &[(&str, f64, usize)] = &[
        ("xor_rk", ns(xor_t, n1), 17),
        ("sbox_block", ns(sbox_t, n1), 48),
        ("staff_inv (field)", ns(staff_i, n1), 16),
        ("faces_inv (field)", ns(faces_i, n1), 16),
        ("bridges_inv (perm)", ns(br_i, n1), 16),
        ("trip_inv", ns(trip_i, n1), 16),
        ("unbow (8-stroke)", ns(bow_i, n1), 16),
        ("cross_inv", ns(cross_i, n1), 16),
        ("split+join_faces", ns(split_t, n1), 48),
        ("faces_to/from_cols", ns(tocols_t, n1), 32),
    ];
    println!("== layer share of one 16-round 128-byte decrypt (decrypt_one path) ==");
    print_share(dec_items, dec_ns);

    // ---- 64-block sliced path (what AEAD / encrypt_blocks uses) ----
    let mut blocks = vec![[0u8; BLOCK_LEN]; 64];
    for (i, b) in blocks.iter_mut().enumerate() {
        *b = block;
        b[0] = i as u8;
    }
    let mut pos0 = [_mm512_setzero_si512(); 128];
    slice64_load(&blocks, &mut pos0);

    let n64 = 8_000usize;
    println!("\n== per-layer (64-block sliced AVX-512+GFNI path, {n64} group iters; ns per group and per block) ==");

    let xor64 = {
        let mut pos = pos0;
        time_n(n64, || {
            slice64_xor(&mut pos, &rk.rk);
            black_box(&pos);
        })
    };
    rec64("slice64_xor", xor64, n64);

    let s64 = {
        let mut pos = pos0;
        time_n(n64, || {
            slice64_s(&mut pos, &rk.s);
            black_box(&pos);
        })
    };
    rec64("slice64_sbox", s64, n64);

    let staff64 = {
        let mut pos = pos0;
        time_n(n64, || {
            slice64_staff(&mut pos, false);
            black_box(&pos);
        })
    };
    rec64("slice64_staff (field)", staff64, n64);

    let faces64 = {
        let mut pos = pos0;
        time_n(n64, || {
            slice64_faces(&mut pos, false);
            black_box(&pos);
        })
    };
    rec64("slice64_faces (field)", faces64, n64);

    let chord64 = {
        let mut pos = pos0;
        time_n(n64, || {
            slice64_chord(&mut pos, false);
            black_box(&pos);
        })
    };
    rec64("slice64_chord (staff+faces)", chord64, n64);

    let chord64i = {
        let mut pos = pos0;
        time_n(n64, || {
            slice64_chord(&mut pos, true);
            black_box(&pos);
        })
    };
    rec64("slice64_chord_inv", chord64i, n64);

    let benes64 = {
        let mut pos = pos0;
        time_n(n64, || {
            slice64_bridges_benes(&mut pos, rk, c, false);
            black_box(&pos);
        })
    };
    rec64("slice64_bridges_benes", benes64, n64);

    let benes64i = {
        let mut pos = pos0;
        time_n(n64, || {
            slice64_bridges_benes(&mut pos, rk, c, true);
            black_box(&pos);
        })
    };
    rec64("slice64_bridges_benes_inv", benes64i, n64);

    let trip64 = {
        let mut pos = pos0;
        time_n(n64, || {
            slice64_trip_only(&mut pos, false);
            black_box(&pos);
        })
    };
    rec64("slice64_trip", trip64, n64);

    let trip64i = {
        let mut pos = pos0;
        time_n(n64, || {
            slice64_trip_only(&mut pos, true);
            black_box(&pos);
        })
    };
    rec64("slice64_trip_inv", trip64i, n64);

    let bow64 = {
        let mut pos = pos0;
        time_n(n64, || {
            slice64_bow_only(&mut pos, c, false);
            black_box(&pos);
        })
    };
    rec64("slice64_bow (8-stroke)", bow64, n64);

    let bow64i = {
        let mut pos = pos0;
        time_n(n64, || {
            slice64_bow_only(&mut pos, c, true);
            black_box(&pos);
        })
    };
    rec64("slice64_unbow (8-stroke)", bow64i, n64);

    let cross64 = {
        let mut pos = pos0;
        time_n(n64, || {
            slice64_cross(&mut pos, false);
            black_box(&pos);
        })
    };
    rec64("slice64_cross", cross64, n64);

    let cross64i = {
        let mut pos = pos0;
        time_n(n64, || {
            slice64_cross(&mut pos, true);
            black_box(&pos);
        })
    };
    rec64("slice64_cross_inv", cross64i, n64);

    let load64 = {
        let mut pos = pos0;
        time_n(n64, || {
            slice64_load(&blocks, &mut pos);
            black_box(&pos);
        })
    };
    rec64("slice64_load (transpose)", load64, n64);

    let store64 = {
        let mut out = blocks.clone();
        time_n(n64, || {
            slice64_store(&pos0, &mut out);
            black_box(&out);
        })
    };
    rec64("slice64_store (transpose)", store64, n64);

    // Full 64-block crypt
    let nfull = 4_000usize;
    let enc64 = {
        let mut b = blocks.clone();
        time_n(nfull, || {
            crypt_slice64(key, &mut b, true);
            black_box(&b);
        })
    };
    let dec64 = {
        let mut b = blocks.clone();
        crypt_slice64(key, &mut b, true);
        time_n(nfull, || {
            crypt_slice64(key, &mut b, false);
            black_box(&b);
        })
    };
    let enc64_ns_blk = enc64.0 * 1e9 / (nfull * 64) as f64;
    let dec64_ns_blk = dec64.0 * 1e9 / (nfull * 64) as f64;
    println!(
        "\n  crypt_slice64 enc      {:>8.1} ns/block  {:>6.1} MB/s  (64-block group)",
        enc64_ns_blk,
        mbs(enc64_ns_blk, 1)
    );
    println!(
        "  crypt_slice64 dec      {:>8.1} ns/block  {:>6.1} MB/s  (64-block group)",
        dec64_ns_blk,
        mbs(dec64_ns_blk, 1)
    );

    // Per-block ns = group_ns / 64
    let enc64_items: &[(&str, f64, usize)] = &[
        ("slice64_xor", ns(xor64, n64) / 64.0, 17),
        ("slice64_sbox", ns(s64, n64) / 64.0, 48),
        ("slice64_staff (field)", ns(staff64, n64) / 64.0, 16),
        ("slice64_faces (field)", ns(faces64, n64) / 64.0, 16),
        ("slice64_bridges_benes", ns(benes64, n64) / 64.0, 16),
        ("slice64_trip", ns(trip64, n64) / 64.0, 16),
        ("slice64_bow (8-stroke)", ns(bow64, n64) / 64.0, 16),
        ("slice64_cross", ns(cross64, n64) / 64.0, 16),
        ("slice64_load (transpose)", ns(load64, n64) / 64.0, 1),
        ("slice64_store (transpose)", ns(store64, n64) / 64.0, 1),
    ];
    println!("== layer share of 64-block sliced encrypt (per block, 16 rounds) ==");
    print_share(enc64_items, enc64_ns_blk);

    let dec64_items: &[(&str, f64, usize)] = &[
        ("slice64_xor", ns(xor64, n64) / 64.0, 17),
        ("slice64_sbox", ns(s64, n64) / 64.0, 48),
        ("slice64_chord_inv", ns(chord64i, n64) / 64.0, 16),
        ("slice64_bridges_benes_inv", ns(benes64i, n64) / 64.0, 16),
        ("slice64_trip_inv", ns(trip64i, n64) / 64.0, 16),
        ("slice64_unbow (8-stroke)", ns(bow64i, n64) / 64.0, 16),
        ("slice64_cross_inv", ns(cross64i, n64) / 64.0, 16),
        ("slice64_load (transpose)", ns(load64, n64) / 64.0, 1),
        ("slice64_store (transpose)", ns(store64, n64) / 64.0, 1),
    ];
    println!("== layer share of 64-block sliced decrypt (per block, 16 rounds) ==");
    print_share(dec64_items, dec64_ns_blk);

    // Also note chord check
    println!(
        "  (check) slice64_chord fwd {:>8.2} ns/group vs staff+faces {:>8.2}",
        ns(chord64, n64),
        ns(staff64, n64) + ns(faces64, n64)
    );

}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn slice64_trip_only(pos: &mut [__m512i; 128], inv: bool) {
    for f in 0..16 {
        let mut v = [_mm512_setzero_si512(); 8];
        for t in 0..8 {
            v[t] = pos[pidx(f, t)];
        }
        if !inv {
            trip_fwd_z(&mut v);
        } else {
            trip_inv_z(&mut v);
        }
        for t in 0..8 {
            pos[pidx(f, t)] = v[t];
        }
    }
}

#[inline]
#[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,avx2")]
unsafe fn slice64_bow_only(pos: &mut [__m512i; 128], c: &Consts, inv: bool) {
    for f in 0..16 {
        let mut v = [_mm512_setzero_si512(); 8];
        for t in 0..8 {
            v[t] = pos[pidx(f, t)];
        }
        bow_cols512(&mut v, c, inv);
        for t in 0..8 {
            pos[pidx(f, t)] = v[t];
        }
    }
}

fn time_n<F: FnMut()>(n: usize, mut f: F) -> (f64, f64) {
    for _ in 0..64 {
        f();
    }
    let wall = Instant::now();
    let c0 = cycles();
    for _ in 0..n {
        f();
    }
    let c1 = cycles();
    let dt = wall.elapsed().as_secs_f64();
    (dt, c1.wrapping_sub(c0) as f64)
}

fn ns(t: (f64, f64), n: usize) -> f64 {
    t.0 * 1e9 / n as f64
}

fn record(name: &str, t: (f64, f64), n: usize) {
    println!(
        "  {:22} {:>8.2} ns/call  {:>7.1} cyc",
        name,
        ns(t, n),
        t.1 / n as f64
    );
}

fn rec64(name: &str, t: (f64, f64), n: usize) {
    let g = ns(t, n);
    println!(
        "  {:28} {:>8.1} ns/group  {:>6.2} ns/blk  {:>7.1} cyc/group",
        name,
        g,
        g / 64.0,
        t.1 / n as f64
    );
}

fn mbs(ns_per_block: f64, nblocks: usize) -> f64 {
    if ns_per_block <= 0.0 {
        return 0.0;
    }
    (nblocks as f64) * (BLOCK_LEN as f64) / ns_per_block * 1e3
}

fn print_share(items: &[(&str, f64, usize)], measured_ns: f64) {
    let mut acc = 0.0;
    println!("  {:28} times  ns_total   share", "layer");
    for (name, nsc, times) in items {
        let tot = nsc * *times as f64;
        acc += tot;
        let share = if measured_ns > 0.0 {
            100.0 * tot / measured_ns
        } else {
            0.0
        };
        println!("  {name:28} {times:>5}  {tot:>8.1}  {share:>5.1}%");
    }
    let cov = if measured_ns > 0.0 {
        100.0 * acc / measured_ns
    } else {
        0.0
    };
    println!(
        "  accounted {acc:.1} ns vs measured {measured_ns:.1} ns ({cov:.0}% coverage)"
    );
}
