pub mod neon;

use crate::framebuffer::{generic, FramebufferOps};

pub fn detect_and_init_ops() -> FramebufferOps {
    // Basic fallback for now, real CPUID check can go here
    FramebufferOps {
        fill: neon::fill_neon,
        blit: neon::blit_neon,
        blend: neon::blend_neon,
        convert: neon::convert_bgr_to_argb_neon,
    }
}
