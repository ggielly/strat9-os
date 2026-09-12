//! SIMD pixel operations for x86_64.
//!
//! Currently exposes the SSE2 (+SSSE3 convert) implementations only.
//!
//! AVX2/AVX512 variants are TEMPORARILY removed: nightly
//! `1.100.0-nightly (c656540d, LLVM 23.1-rust)` mis-compiles the custom
//! `x86_64-unknown-none` target by emitting `+soft-float` into every
//! function's target-features, which makes X86 instruction selection abort
//! on 256-bit intrinsics (`llvm.x86.avx2.pshuf.b`) with:
//!   "Do not know how to split the result of this operator!"
//! Restore `avx2`/`avx512` once the toolchain issue is resolved. The
//! streaming-store paths are disabled too; cached SSE2 remains available.

use crate::framebuffer::{generic, FramebufferOps};
pub mod sse2;

pub fn detect_and_init_ops() -> FramebufferOps {


    let cpuid = raw_cpuid::CpuId::new();

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
        // convert_bgr_to_argb requires SSSE3 (pshufb). Without it, use the scalar path.
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
