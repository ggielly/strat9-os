pub unsafe fn fill_generic(dst: *mut u32, color: u32, count: usize) {
    for i in 0..count {
        *dst.add(i) = color;
    }
}

pub unsafe fn blit_generic(dst: *mut u32, src: *const u32, count: usize) {
    core::ptr::copy_nonoverlapping(src, dst, count);
}

pub unsafe fn blend_generic(dst: *mut u32, src: *const u32, alpha: u8, count: usize) {
    let alpha_u32 = alpha as u32;
    let inv_alpha = 255 - alpha_u32;

    for i in 0..count {
        let d = *dst.add(i);
        let s = *src.add(i);

        let d_b = d & 0xFF;
        let d_g = (d >> 8) & 0xFF;
        let d_r = (d >> 16) & 0xFF;
        let d_a = (d >> 24) & 0xFF;

        let s_b = s & 0xFF;
        let s_g = (s >> 8) & 0xFF;
        let s_r = (s >> 16) & 0xFF;
        let s_a = (s >> 24) & 0xFF;

        let r_b = ((s_b * alpha_u32 + d_b * inv_alpha) / 255) & 0xFF;
        let r_g = ((s_g * alpha_u32 + d_g * inv_alpha) / 255) & 0xFF;
        let r_r = ((s_r * alpha_u32 + d_r * inv_alpha) / 255) & 0xFF;
        let r_a = ((s_a * alpha_u32 + d_a * inv_alpha) / 255) & 0xFF;

        *dst.add(i) = r_b | (r_g << 8) | (r_r << 16) | (r_a << 24);
    }
}

pub unsafe fn convert_bgr_to_argb_generic(dst: *mut u32, src: *const u8, count: usize) {
    for i in 0..count {
        let b = *src.add(i * 3) as u32;
        let g = *src.add(i * 3 + 1) as u32;
        let r = *src.add(i * 3 + 2) as u32;
        *dst.add(i) = b | (g << 8) | (r << 16) | (0xFF << 24);
    }
}
