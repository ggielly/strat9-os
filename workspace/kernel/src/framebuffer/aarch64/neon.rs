// use core::arch::aarch64::*;

// Placeholder for ARM NEON
// TODO : Implement actual NEON optimized versions of these functions
pub unsafe fn fill_neon(dst: *mut u32, color: u32, count: usize) {
    crate::framebuffer::generic::fill_generic(dst, color, count);
}

pub unsafe fn blit_neon(dst: *mut u32, src: *const u32, count: usize) {
    crate::framebuffer::generic::blit_generic(dst, src, count);
}

pub unsafe fn blend_neon(dst: *mut u32, src: *const u32, alpha: u8, count: usize) {
    crate::framebuffer::generic::blend_generic(dst, src, alpha, count);
}

pub unsafe fn convert_bgr_to_argb_neon(dst: *mut u32, src: *const u8, count: usize) {
    crate::framebuffer::generic::convert_bgr_to_argb_generic(dst, src, count);
}
