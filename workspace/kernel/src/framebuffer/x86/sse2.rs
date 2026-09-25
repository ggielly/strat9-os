use core::arch::x86_64::*;

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

#[target_feature(enable = "sse2")]
pub unsafe fn blend_sse2(dst: *mut u32, src: *const u32, alpha: u8, count: usize) {
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

    if i < count {
        crate::framebuffer::generic::blend_generic(dst.add(i), src.add(i), alpha, count - i);
    }
}

#[target_feature(enable = "sse2")]
pub unsafe fn convert_bgr_to_argb_sse2(dst: *mut u32, src: *const u8, count: usize) {
    crate::framebuffer::generic::convert_bgr_to_argb_generic(dst, src, count);
}
