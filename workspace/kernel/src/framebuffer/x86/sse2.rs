use core::arch::x86_64::*;

#[inline]
unsafe fn load_u32_unaligned(src: *const u8) -> i32 {
    core::ptr::read_unaligned(src as *const u32) as i32
}

#[target_feature(enable = "sse2")]
pub unsafe fn fill_sse2(dst: *mut u32, color: u32, count: usize) {
    let color_vec = _mm_set1_epi32(color as i32);
    let mut i = 0;

    while i + 4 <= count {
        _mm_storeu_si128(dst.add(i) as *mut __m128i, color_vec);
        i += 4;
    }

    while i < count {
        *dst.add(i) = color;
        i += 1;
    }
}

#[target_feature(enable = "sse2")]
pub unsafe fn blit_sse2(dst: *mut u32, src: *const u32, count: usize) {
    let mut i = 0;

    while i + 4 <= count {
        let src_vec = _mm_loadu_si128(src.add(i) as *const __m128i);
        _mm_storeu_si128(dst.add(i) as *mut __m128i, src_vec);
        i += 4;
    }

    while i < count {
        *dst.add(i) = *src.add(i);
        i += 1;
    }
}

// In sse2, we use SSE4.1 blend where possible, but if only sse2 is available,
// we'll implement a basic one. For simplicity, we use SSE2 compatible intrinsics.
#[target_feature(enable = "sse2")]
pub unsafe fn blend_sse2(dst: *mut u32, src: *const u32, alpha: u8, count: usize) {
    // Basic SSE2 implementation for blend
    let alpha_u16 = alpha as u16;
    let inv_alpha = 255 - alpha_u16;

    let alpha_vec = _mm_set1_epi16(alpha_u16 as i16);
    let inv_alpha_vec = _mm_set1_epi16(inv_alpha as i16);
    let zero = _mm_setzero_si128();
    let ones = _mm_set1_epi16(1);

    let mut i = 0;
    while i + 4 <= count {
        let d = _mm_loadu_si128(dst.add(i) as *const __m128i);
        let s = _mm_loadu_si128(src.add(i) as *const __m128i);

        let d_lo = _mm_unpacklo_epi8(d, zero);
        let d_hi = _mm_unpackhi_epi8(d, zero);
        let s_lo = _mm_unpacklo_epi8(s, zero);
        let s_hi = _mm_unpackhi_epi8(s, zero);

        let res_lo_s = _mm_mullo_epi16(s_lo, alpha_vec);
        let res_lo_d = _mm_mullo_epi16(d_lo, inv_alpha_vec);
        let res_lo = _mm_add_epi16(res_lo_s, res_lo_d);
        // Exact /255: (x + (x>>8) + 1) >> 8  (dav1d formula)
        let lo_div = _mm_srli_epi16(res_lo, 8);
        let lo_corr = _mm_add_epi16(res_lo, _mm_add_epi16(lo_div, ones));
        let res_lo_final = _mm_srli_epi16(lo_corr, 8);

        let res_hi_s = _mm_mullo_epi16(s_hi, alpha_vec);
        let res_hi_d = _mm_mullo_epi16(d_hi, inv_alpha_vec);
        let res_hi = _mm_add_epi16(res_hi_s, res_hi_d);
        let hi_div = _mm_srli_epi16(res_hi, 8);
        let hi_corr = _mm_add_epi16(res_hi, _mm_add_epi16(hi_div, ones));
        let res_hi_final = _mm_srli_epi16(hi_corr, 8);

        let res = _mm_packus_epi16(res_lo_final, res_hi_final);
        _mm_storeu_si128(dst.add(i) as *mut __m128i, res);
        i += 4;
    }

    // fallback
    if i < count {
        crate::framebuffer::generic::blend_generic(dst.add(i), src.add(i), alpha, count - i);
    }
}

#[target_feature(enable = "sse2")]
pub unsafe fn convert_bgr_to_argb_sse2(dst: *mut u32, src: *const u8, count: usize) {
    convert_bgr_to_argb_ssse3(dst, src, count);
}

/// BGR24 => ARGB32 conversion using SSSE3 pshufb (4 pixels/iter)
#[target_feature(enable = "ssse3")]
unsafe fn convert_bgr_to_argb_ssse3(dst: *mut u32, src: *const u8, count: usize) {
    // Shuffle mask: rearranges BGR BGR BGR BGR => B G R 0 B G R 0 B G R 0 B G R 0
    // Input bytes:  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
    //             [B0 G0 R0 B1 G1 R1 B2 G2 R2 B3 G3 R3  ?  ?  ?  ?]
    // Output:      [B0 G0 R0  0 B1 G1 R1  0 B2 G2 R2  0 B3 G3 R3  0]
    #[rustfmt::skip]
    let shuffle_mask = _mm_set_epi8(
        -1, 11, 10,  9,     // pixel 3: 0, R3, G3, B3
        -1,  8,  7,  6,     // pixel 2: 0, R2, G2, B2
        -1,  5,  4,  3,     // pixel 1: 0, R1, G1, B1
        -1,  2,  1,  0,     // pixel 0: 0, R0, G0, B0
    );
    // Alpha mask: sets byte 3,7,11,15 to 0xFF
    let alpha_mask = _mm_set1_epi32(0xFF000000_u32 as i32);

    let mut i = 0;
    // Charge exactement 12 octets (4 pixels BGR) sans dépassement de buffer
    while i + 4 <= count {
        // lecture sécurisée: 8 premiers octets (B0..R1) + 4 suivants (B2..R3)
        let lo8 = _mm_loadl_epi64(src.add(i * 3) as *const __m128i);
        let hi4 = _mm_cvtsi32_si128(load_u32_unaligned(src.add(i * 3 + 8)));
        let raw = _mm_unpacklo_epi64(lo8, hi4);
        let shuffled = _mm_shuffle_epi8(raw, shuffle_mask);
        let result = _mm_or_si128(shuffled, alpha_mask);
        _mm_storeu_si128(dst.add(i) as *mut __m128i, result);
        i += 4;
    }

    // tail
    if i < count {
        crate::framebuffer::generic::convert_bgr_to_argb_generic(
            dst.add(i),
            src.add(i * 3),
            count - i,
        );
    }
}
