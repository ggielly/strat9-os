pub mod generic;
pub mod gpu;

#[cfg(test)]
pub mod tests;

#[cfg(target_arch = "x86_64")]
pub mod x86;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

// Type definitions for our framebuffer operations
pub type FnFill = unsafe fn(dst: *mut u32, color: u32, count: usize);
pub type FnBlit = unsafe fn(dst: *mut u32, src: *const u32, count: usize);
pub type FnBlend = unsafe fn(dst: *mut u32, src: *const u32, alpha: u8, count: usize);
pub type FnConvert = unsafe fn(dst: *mut u32, src: *const u8, count: usize);

#[derive(Clone, Copy)]
pub struct FramebufferOps {
    pub fill: FnFill,
    pub blit: FnBlit,
    pub blend: FnBlend,
    pub convert: FnConvert,
}

impl FramebufferOps {
    pub fn detect() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            return x86::detect_and_init_ops();
        }

        #[cfg(target_arch = "aarch64")]
        {
            // ARM CPUID detection for NEON could be done here,
            // but for now we fallback to generic or neon if compiled with it.
            return aarch64::detect_and_init_ops();
        }

        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            Self {
                fill: generic::fill_generic,
                blit: generic::blit_generic,
                blend: generic::blend_generic,
                convert: generic::convert_bgr_to_argb_generic,
            }
        }
    }
}
