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
//! Restore `avx2`/`avx512` once the toolchain issue is resolved. The S2
//! non-temporal store paths remain available through SSE2 (`movntdq`), so
//! large presents still bypass the cache.

use crate::framebuffer::{generic, FramebufferOps};
use core::sync::atomic::{AtomicUsize, Ordering};
use raw_cpuid::CpuId;

/// Non-temporal store threshold in bytes (S2): fill/blit operations writing
/// at least this much use streaming stores so a full-screen present does not
/// evict the working set from cache. Initialized from half the detected L2
/// size, clamped to [256 KiB, 4 MiB]; default 512 KiB until detection runs.
static STREAM_THRESHOLD_BYTES: AtomicUsize = AtomicUsize::new(512 * 1024);

#[inline]
pub fn stream_threshold() -> usize {
    STREAM_THRESHOLD_BYTES.load(Ordering::Relaxed)
}

/// Detect the streaming-store threshold from the L2 cache size (CPUID leaf
/// 0x80000006): threshold = L2 / 2, clamped to sane bounds.
fn detect_stream_threshold() {
    let l2_kib = CpuId::new()
        .get_l2_l3_cache_and_tlb_info()
        .map(|l23| l23.l2cache_size() as usize)
        .filter(|&k| k > 0)
        .unwrap_or(1024);
    let l2_bytes = l2_kib.saturating_mul(1024);
    let threshold = if l2_bytes >= 64 * 1024 {
        (l2_bytes / 2).clamp(256 * 1024, 4 * 1024 * 1024)
    } else {
        // Unknown L2: conservative default (assumes ~1 MiB L2).
        512 * 1024
    };
    STREAM_THRESHOLD_BYTES.store(threshold, Ordering::Relaxed);
}

pub mod sse2;

pub fn detect_and_init_ops() -> FramebufferOps {
    detect_stream_threshold();

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
