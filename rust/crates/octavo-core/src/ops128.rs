// 128-bit vector ops for simd_layers.rs (one block: 16 faces per register).
pub(super) type V = __m128i;
pub(super) type CV = [V; 8];
type M = __mmask16;
macro_rules! tf { ($($i:item)*) => { $(
    #[inline]
    #[target_feature(enable = "gfni,avx512f,avx512bw,avx512vl,avx512vbmi,ssse3,sse4.1")]
    #[allow(dead_code)]
    $i
)* } }
tf! {
    fn v_xor(a: V, b: V) -> V { _mm_xor_si128(a, b) }
    fn v_and(a: V, b: V) -> V { _mm_and_si128(a, b) }
    fn v_add(a: V, b: V) -> V { _mm_add_epi8(a, b) }
    fn v_sub(a: V, b: V) -> V { _mm_sub_epi8(a, b) }
    fn v_min(a: V, b: V) -> V { _mm_min_epu8(a, b) }
    fn v_zero() -> V { _mm_setzero_si128() }
    fn v_set1(x: i8) -> V { _mm_set1_epi8(x) }
    fn v_set1_16(x: i16) -> V { _mm_set1_epi16(x) }
    fn v_srli16<const S: i32>(a: V) -> V { _mm_srli_epi16::<S>(a) }
    fn v_sllv16(a: V, n: V) -> V { _mm_sllv_epi16(a, n) }
    fn v_shuf(a: V, i: V) -> V { _mm_shuffle_epi8(a, i) }
    fn v_blend(m: M, a: V, b: V) -> V { _mm_mask_blend_epi8(m, a, b) }
    fn v_mask(m: u16) -> M { m }
    fn v_bcast16(b: &[u8; 16]) -> V { unsafe { _mm_loadu_si128(b.as_ptr() as *const _) } }
    fn v_aff(x: V, m: u64) -> V { _mm_gf2p8affine_epi64_epi8::<0>(x, _mm_set1_epi64x(m as i64)) }
    /// lanes with mask bit set: affine(x); others: src
    fn v_mask_aff(src: V, m: M, x: V, a: u64) -> V { _mm_mask_gf2p8affine_epi64_epi8::<0>(src, m, x, _mm_set1_epi64x(a as i64)) }
    fn v_affinv(x: V, m: u64) -> V { _mm_gf2p8affineinv_epi64_epi8::<0>(x, _mm_set1_epi64x(m as i64)) }
}
