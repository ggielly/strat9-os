pub mod sse2;

use crate::framebuffer::{generic, FramebufferOps};
use raw_cpuid::CpuId;

pub fn detect_and_init_ops() -> FramebufferOps {
    let cpuid = CpuId::new();

    let has_sse41 = cpuid
        .get_feature_info()
        .map_or(false, |info| info.has_sse41());

    let has_ssse3 = cpuid
        .get_feature_info()
        .map_or(false, |info| info.has_ssse3());

    let has_sse2 = cpuid
        .get_feature_info()
        .map_or(false, |info| info.has_sse2());

    if has_sse41 || has_sse2 {
        let convert: crate::framebuffer::FnConvert = if has_ssse3 {
            sse2::convert_bgr_to_argb_sse2
        } else {
            generic::convert_bgr_to_argb_generic
        };
        FramebufferOps {
            fill: sse2::fill_sse2,
            blit: sse2::blit_sse2,
            blend: sse2::blend_sse2,
            convert,
        }
    } else {
        FramebufferOps {
            fill: generic::fill_generic,
            blit: generic::blit_generic,
            blend: generic::blend_generic,
            convert: generic::convert_bgr_to_argb_generic,
        }
    }
}
