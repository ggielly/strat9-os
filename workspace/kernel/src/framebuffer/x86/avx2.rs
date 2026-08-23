use core::arch::x86_64::*;

#[inline]
unsafe fn load_u32_unaligned(src: *const u8) -> i32 {
    core::ptr::read_unaligned(src as *const u32) as i32
}

/// Streaming fill (S2): vmovntdq requires 32-byte-aligned destinations.
/// Callers gate on size and alignment; sfence orders the NT stores.
#[target_feature(enable = "avx2")]
pub unsafe fn fill_avx2_nt(dst: *mut u32, color: u32, count: usize) {
    let color_vec = _mm256_set1_epi32(color as i32);
    let mut i = 0;
    while i < count && dst.add(i) as usize % 32 != 0 {
        *dst.add(i) = color;
        i += 1;
    }
    while i + 8 <= count {
        _mm256_stream_si256(dst.add(i) as *mut __m256i, color_vec);
        i += 8;
    }
    while i + 4 <= count {
        _mm_storeu_si128(dst.add(i) as *mut __m128i, _mm256_castsi256_si128(color_vec));
        i += 4;
    }
    while i < count {
        *dst.add(i) = color;
        i += 1;
    }
    _mm_sfence();
}

/// Streaming blit (S2): regular unaligned source loads, aligned NT stores.
#[target_feature(enable = "avx2")]
pub unsafe fn blit_avx2_nt(dst: *mut u32, src: *const u32, count: usize) {
    let mut i = 0;
    while i < count && dst.add(i) as usize % 32 != 0 {
        *dst.add(i) = *src.add(i);
        i += 1;
    }
    while i + 8 <= count {
        let v = _mm256_loadu_si256(src.add(i) as *const __m256i);
        _mm256_stream_si256(dst.add(i) as *mut __m256i, v);
        i += 8;
    }
    while i < count {
        *dst.add(i) = *src.add(i);
        i += 1;
    }
    _mm_sfence();
}

#[target_feature(enable = "avx2")]
pub unsafe fn blend_avx2(dst: *mut u32, src: *const u32, alpha: u8, count: usize) {
    let alpha_u16 = alpha as u16;
    let inv_alpha = 255 - alpha_u16;

    let alpha_vec = _mm256_set1_epi16(alpha_u16 as i16);
    let inv_alpha_vec = _mm256_set1_epi16(inv_alpha as i16);
    let zero = _mm256_setzero_si256();
    let ones = _mm256_set1_epi16(1);

    let mut i = 0;
    while i + 8 <= count {
        let d = _mm256_loadu_si256(dst.add(i) as *const __m256i);
        let s = _mm256_loadu_si256(src.add(i) as *const __m256i);

        let d_lo = _mm256_unpacklo_epi8(d, zero);
        let d_hi = _mm256_unpackhi_epi8(d, zero);
        let s_lo = _mm256_unpacklo_epi8(s, zero);
        let s_hi = _mm256_unpackhi_epi8(s, zero);

        let res_lo_s = _mm256_mullo_epi16(s_lo, alpha_vec);
        let res_lo_d = _mm256_mullo_epi16(d_lo, inv_alpha_vec);
        let res_lo = _mm256_add_epi16(res_lo_s, res_lo_d);
        // Exact /255: (x + (x>>8) + 1) >> 8  (dav1d formula)
        let lo_div = _mm256_srli_epi16(res_lo, 8);
        let lo_corr = _mm256_add_epi16(res_lo, _mm256_add_epi16(lo_div, ones));
        let res_lo_final = _mm256_srli_epi16(lo_corr, 8);

        let res_hi_s = _mm256_mullo_epi16(s_hi, alpha_vec);
        let res_hi_d = _mm256_mullo_epi16(d_hi, inv_alpha_vec);
        let res_hi = _mm256_add_epi16(res_hi_s, res_hi_d);
        let hi_div = _mm256_srli_epi16(res_hi, 8);
        let hi_corr = _mm256_add_epi16(res_hi, _mm256_add_epi16(hi_div, ones));
        let res_hi_final = _mm256_srli_epi16(hi_corr, 8);

        let res = _mm256_packus_epi16(res_lo_final, res_hi_final);
        _mm256_storeu_si256(dst.add(i) as *mut __m256i, res);
        i += 8;
    }

    if i < count {
        super::sse2::blend_sse2(dst.add(i), src.add(i), alpha, count - i);
    }
}

/// BGR24 => ARGB32 conversion using AVX2 vpshufb (8 pixels/iter)
///
/// Load exactly 24 bytes (8 BGR pixels) without buffer overflow
/// by constructing the YMM from two separately loaded 128-bit lanes.
/// vpshufb operates per 128-bit lane independently, so each lane must have
/// its 4 BGR pixels in the first 12 bytes, followed by zeros.
#[target_feature(enable = "avx2")]
pub unsafe fn convert_bgr_to_argb_avx2(dst: *mut u32, src: *const u8, count: usize) {
    // Masque par lane 128-bit: chaque lane traite 4 pixels BGR -> B G R 0
    // (les index 0-11 réfèrent aux 12 premiers octets de la lane)
    #[rustfmt::skip]
    let per_lane = _mm_set_epi8(
        -1, 11, 10,  9,    // pixel 3: 0, R3, G3, B3
        -1,  8,  7,  6,    // pixel 2: 0, R2, G2, B2
        -1,  5,  4,  3,    // pixel 1: 0, R1, G1, B1
        -1,  2,  1,  0,    // pixel 0: 0, R0, G0, B0
    );
    let shuffle_mask = _mm256_broadcastsi128_si256(per_lane);
    // Alpha mask: sets byte 3,7,11,15,19,23,27,31 to 0xFF
    let alpha_mask = _mm256_set1_epi32(0xFF000000_u32 as i32);

    let mut i = 0;
    while i + 8 <= count {
        // Load 12B low lane  (pixels 0-3)
        let lo8 = _mm_loadl_epi64(src.add(i * 3) as *const __m128i);
        let hi4 = _mm_cvtsi32_si128(load_u32_unaligned(src.add(i * 3 + 8)));
        let lo12 = _mm_unpacklo_epi64(lo8, hi4);
        // Load 12B high lane (pixels 4-7)
        let hi8 = _mm_loadl_epi64(src.add(i * 3 + 12) as *const __m128i);
        let hi4_ = _mm_cvtsi32_si128(load_u32_unaligned(src.add(i * 3 + 20)));
        let hi12 = _mm_unpacklo_epi64(hi8, hi4_);

        let raw = _mm256_set_m128i(hi12, lo12);
        let shuffled = _mm256_shuffle_epi8(raw, shuffle_mask);
        let result = _mm256_or_si256(shuffled, alpha_mask);
        _mm256_storeu_si256(dst.add(i) as *mut __m256i, result);
        i += 8;
    }

    // tail : pixel going through SSE2 -> SSSE3 -> generic -
    if i < count {
        super::sse2::convert_bgr_to_argb_sse2(dst.add(i), src.add(i * 3), count - i);
    }
}
