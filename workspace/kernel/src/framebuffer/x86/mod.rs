pub mod avx2;
pub mod avx512;
pub mod sse2;

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

#[inline]
fn kernel_can_use_extended_simd() -> bool {
    #[cfg(target_os = "none")]
    {
        if !crate::arch::cpuid::host_uses_xsave() {
            return false;
        }
        // Defensive check: verify AVX is actually enabled in XCR0.
        // If init_cpu_extensions() ever changes which bits it sets,
        // this prevents selecting AVX2/AVX512 routines that would #UD.
        let xcr0 = crate::arch::xgetbv(0);
        (xcr0 & 4) != 0 // XCR0_AVX bit
    }

    #[cfg(not(target_os = "none"))]
    {
        true
    }
}

extern "C" {
    // NASM: cglobal + INIT_YMM avx2 + private_prefix strat9_fb
    //   => symbol strat9_fb_framebuffer_fill_avx2 / _blit_avx2
    pub fn strat9_fb_framebuffer_fill_avx2(dst: *mut u32, color: u32, count: usize);
    pub fn strat9_fb_framebuffer_blit_avx2(dst: *mut u32, src: *const u32, count: usize);
}

/// Wrapper: cast extern "C" NASM fill fn to Rust ABI fn pointer
unsafe fn fill_avx2_asm(dst: *mut u32, color: u32, count: usize) {
    strat9_fb_framebuffer_fill_avx2(dst, color, count);
}

/// Wrapper: cast extern "C" NASM blit fn to Rust ABI fn pointer
unsafe fn blit_avx2_asm(dst: *mut u32, src: *const u32, count: usize) {
    strat9_fb_framebuffer_blit_avx2(dst, src, count);
}

/// Dispatchers (S2): large operations take the streaming-store path,
/// everything else keeps the hand-tuned NASM cached path.
#[target_feature(enable = "avx2")]
pub unsafe fn fill_avx2_dispatch(dst: *mut u32, color: u32, count: usize) {
    if dst as usize % 32 == 0 && count * 4 >= stream_threshold() {
        avx2::fill_avx2_nt(dst, color, count);
    } else {
        fill_avx2_asm(dst, color, count);
    }
}

#[target_feature(enable = "avx2")]
pub unsafe fn blit_avx2_dispatch(dst: *mut u32, src: *const u32, count: usize) {
    if dst as usize % 32 == 0 && count * 4 >= stream_threshold() {
        avx2::blit_avx2_nt(dst, src, count);
    } else {
        blit_avx2_asm(dst, src, count);
    }
}

pub fn detect_and_init_ops() -> FramebufferOps {
    detect_stream_threshold();

    let cpuid = CpuId::new();

    let has_avx512f = kernel_can_use_extended_simd()
        && cpuid
            .get_extended_feature_info()
            .map_or(false, |info| info.has_avx512f());

    let has_avx2 = kernel_can_use_extended_simd()
        && cpuid
            .get_extended_feature_info()
            .map_or(false, |info| info.has_avx2());

    let has_sse41 = cpuid
        .get_feature_info()
        .map_or(false, |info| info.has_sse41());

    let has_ssse3 = cpuid
        .get_feature_info()
        .map_or(false, |info| info.has_ssse3());

    let has_sse2 = cpuid
        .get_feature_info()
        .map_or(false, |info| info.has_sse2());

    if has_avx512f {
        FramebufferOps {
            fill: avx512::fill_avx512,
            blit: avx512::blit_avx512,
            blend: avx512::blend_avx512,
            convert: avx512::convert_bgr_to_argb_avx512,
        }
    } else if has_avx2 {
        FramebufferOps {
            fill: fill_avx2_dispatch,
            blit: blit_avx2_dispatch,
            blend: avx2::blend_avx2,
            convert: avx2::convert_bgr_to_argb_avx2,
        }
    } else if has_sse41 || has_sse2 {
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
