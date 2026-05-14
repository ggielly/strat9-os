#[cfg(test)]
mod test {
    extern crate alloc;
    use crate::framebuffer::*;
    use alloc::{vec, vec::Vec};

    const WIDTH: usize = 1920;
    const HEIGHT: usize = 1080;
    const PIXELS: usize = WIDTH * HEIGHT;

    fn alloc_buffer(n: usize) -> Vec<u32> {
        vec![0u32; n]
    }

    fn make_bgr24(count: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; count * 3];
        for i in 0..count {
            bytes[i * 3] = (i as u8).wrapping_mul(3).wrapping_add(1);
            bytes[i * 3 + 1] = (i as u8).wrapping_mul(5).wrapping_add(2);
            bytes[i * 3 + 2] = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        bytes
    }

    #[test]
    fn test_fill_consistency() {
        let mut buf_generic = alloc_buffer(PIXELS);
        let mut buf_simd = alloc_buffer(PIXELS);
        let color = 0xFFAABBCC_u32;

        unsafe { generic::fill_generic(buf_generic.as_mut_ptr(), color, PIXELS) };

        let ops = FramebufferOps::detect();
        unsafe { (ops.fill)(buf_simd.as_mut_ptr(), color, PIXELS) };

        assert_eq!(
            buf_generic, buf_simd,
            "fill_simd diverge du résultat scalaire"
        );
    }

    #[test]
    fn test_blit_consistency() {
        let mut dst_generic = alloc_buffer(PIXELS);
        let mut dst_simd = alloc_buffer(PIXELS);
        let mut src = alloc_buffer(PIXELS);

        for (i, p) in src.iter_mut().enumerate() {
            *p = (i as u32).wrapping_mul(0x45D9F3B);
        }

        unsafe { generic::blit_generic(dst_generic.as_mut_ptr(), src.as_ptr(), PIXELS) };

        let ops = FramebufferOps::detect();
        unsafe { (ops.blit)(dst_simd.as_mut_ptr(), src.as_ptr(), PIXELS) };

        assert_eq!(
            dst_generic, dst_simd,
            "blit_simd diverge du résultat scalaire"
        );
    }

    #[test]
    fn test_blend_consistency() {
        let mut dst_generic = alloc_buffer(PIXELS);
        let mut dst_simd = alloc_buffer(PIXELS);
        let src = alloc_buffer(PIXELS);

        for (i, p) in dst_generic.iter_mut().enumerate() {
            *p = (i as u32).wrapping_mul(0x9E3779B9);
        }
        dst_simd.copy_from_slice(&dst_generic);

        let alpha = 128u8;

        unsafe { generic::blend_generic(dst_generic.as_mut_ptr(), src.as_ptr(), alpha, PIXELS) };
        let ops = FramebufferOps::detect();
        unsafe { (ops.blend)(dst_simd.as_mut_ptr(), src.as_ptr(), alpha, PIXELS) };

        for (i, (a, b)) in dst_generic.iter().zip(dst_simd.iter()).enumerate() {
            let diff = (*a as i64 - *b as i64).abs();
            assert!(diff <= 1, "blend diverge au pixel {}: {} vs {}", i, a, b);
        }
    }

    #[test]
    fn test_convert_consistency() {
        let src = make_bgr24(PIXELS);
        let mut dst_generic = alloc_buffer(PIXELS);
        let mut dst_simd = alloc_buffer(PIXELS);

        unsafe {
            generic::convert_bgr_to_argb_generic(dst_generic.as_mut_ptr(), src.as_ptr(), PIXELS)
        };

        let ops = FramebufferOps::detect();
        unsafe { (ops.convert)(dst_simd.as_mut_ptr(), src.as_ptr(), PIXELS) };

        assert_eq!(
            dst_generic, dst_simd,
            "convert_simd diverge du résultat scalaire"
        );
    }

    #[cfg(all(target_arch = "x86_64", not(target_os = "none")))]
    #[test]
    fn test_avx2_asm_handles_unaligned_destinations() {
        let cpuid = raw_cpuid::CpuId::new();
        let has_avx2 = cpuid
            .get_extended_feature_info()
            .map_or(false, |info| info.has_avx2());
        if !has_avx2 {
            return;
        }

        let count = 129usize;
        let color = 0xFF12_3456u32;

        let mut fill_reference = alloc_buffer(count + 4);
        let mut fill_test = alloc_buffer(count + 4);
        unsafe {
            generic::fill_generic(fill_reference.as_mut_ptr().add(1), color, count);
            crate::framebuffer::x86::strat9_fb_framebuffer_fill_avx2(
                fill_test.as_mut_ptr().add(1),
                color,
                count,
            );
        }
        assert_eq!(
            fill_reference, fill_test,
            "fill_avx2 asm échoue sur destination non alignée"
        );

        let mut src = alloc_buffer(count + 4);
        let mut blit_reference = alloc_buffer(count + 4);
        let mut blit_test = alloc_buffer(count + 4);
        for (i, p) in src.iter_mut().enumerate() {
            *p = (i as u32).wrapping_mul(0x9E37_79B9);
        }
        unsafe {
            generic::blit_generic(
                blit_reference.as_mut_ptr().add(1),
                src.as_ptr().add(2),
                count,
            );
            crate::framebuffer::x86::strat9_fb_framebuffer_blit_avx2(
                blit_test.as_mut_ptr().add(1),
                src.as_ptr().add(2),
                count,
            );
        }
        assert_eq!(
            blit_reference, blit_test,
            "blit_avx2 asm échoue sur destination non alignée"
        );
    }
}
