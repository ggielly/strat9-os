use core::arch::x86_64::*;

#[target_feature(enable = "avx512f")]
pub unsafe fn fill_avx512(dst: *mut u32, color: u32, count: usize) {
    let color_vec = _mm512_set1_epi32(color as i32);
    let mut i = 0;

    // S2: streaming stores above the threshold (movntdq requires 64-byte
    // alignment; scalar head/tail handle unaligned edges).
    if count * 4 >= super::stream_threshold() {
        while i < count && dst.add(i) as usize % 64 != 0 {
            *dst.add(i) = color;
            i += 1;
        }
        while i + 16 <= count {
            _mm512_stream_si512(dst.add(i) as *mut __m512i, color_vec);
            i += 16;
        }
        _mm_sfence(); // sfence orders NT stores regardless of vector width
    }

    while i + 16 <= count {
        _mm512_storeu_si512(dst.add(i) as *mut __m512i, color_vec);
        i += 16;
    }

    if i < count {
        crate::framebuffer::generic::fill_generic(dst.add(i), color, count - i);
    }
}

#[target_feature(enable = "avx512f")]
pub unsafe fn blit_avx512(dst: *mut u32, src: *const u32, count: usize) {
    let mut i = 0;

    while i + 16 <= count {
        let src_vec = _mm512_loadu_si512(src.add(i) as *const __m512i);
        _mm512_storeu_si512(dst.add(i) as *mut __m512i, src_vec);
        i += 16;
    }

    if i < count {
        crate::framebuffer::generic::blit_generic(dst.add(i), src.add(i), count - i);
    }
}

#[target_feature(enable = "avx512f")]
pub unsafe fn blend_avx512(dst: *mut u32, src: *const u32, alpha: u8, count: usize) {
    super::avx2::blend_avx2(dst, src, alpha, count);
}

#[target_feature(enable = "avx512f")]
pub unsafe fn convert_bgr_to_argb_avx512(dst: *mut u32, src: *const u8, count: usize) {
    super::avx2::convert_bgr_to_argb_avx2(dst, src, count);
}
