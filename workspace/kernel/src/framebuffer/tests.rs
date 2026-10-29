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
            (FramebufferOps::detect().fill)(fill_test.as_mut_ptr().add(1), color, count);
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
            (FramebufferOps::detect().blit)(
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

    /// Build a canvas over a caller-owned backing buffer.
    fn make_canvas(addr: *mut u8, width: usize, height: usize, bpp: u16) -> CanvasBuffer {
        let bytes_pp = (bpp / 8) as usize;
        CanvasBuffer {
            addr,
            width,
            height,
            pitch: width * bytes_pp,
            bpp,
            back_buffer: None,
            draw_to_back: false,
            dirty: DirtyRectSet::empty(),
            track_dirty: false,
            present_pending: false,
            last_present_tick: 0,
            ops: FramebufferOps::detect(),
            wc: false,
            present_row_buf: None,
        }
    }

    #[test]
    fn test_blit_rect_back_buffer_copy_and_clip() {
        let mut hw = vec![0u32; 4 * 3];
        let mut cb = make_canvas(hw.as_mut_ptr() as *mut u8, 4, 3, 32);
        cb.back_buffer = Some(vec![0u32; 4 * 3]);
        cb.draw_to_back = true;
        cb.track_dirty = true;

        let mut src = vec![0u8; 2 * 2 * 4];
        for i in 0..4 {
            let px = 0x100u32 + i as u32;
            src[i * 4..i * 4 + 4].copy_from_slice(&px.to_le_bytes());
        }

        // 2x2 at (1,1) fits exactly.
        assert_eq!(cb.blit_rect(&src, 1, 1, 2, 2), Some((2, 2)));
        {
            let buf = cb.back_buffer.as_ref().unwrap();
            assert_eq!(buf[1 * 4 + 1], 0x100);
            assert_eq!(buf[1 * 4 + 2], 0x101);
            assert_eq!(buf[2 * 4 + 1], 0x102);
            assert_eq!(buf[2 * 4 + 2], 0x103);
            // Nothing outside the destination rectangle was touched.
            assert_eq!(buf[0], 0);
            assert_eq!(buf[1], 0);
        }
        let r = cb.dirty.rects[0];
        assert_eq!((r.x0, r.y0, r.x1, r.y1), (1, 1, 3, 3));
        assert_eq!(hw, vec![0u32; 4 * 3]);

        // 5x5 at (3,2) clips to the single bottom-right pixel.
        let big = vec![0x55u8; 5 * 5 * 4];
        assert_eq!(cb.blit_rect(&big, 3, 2, 5, 5), Some((1, 1)));
        assert_eq!(cb.back_buffer.as_ref().unwrap()[2 * 4 + 3], 0x5555_5555);

        // Empty / off-screen rectangles are rejected.
        assert_eq!(cb.blit_rect(&big, 0, 0, 0, 4), None);
        assert_eq!(cb.blit_rect(&big, 4, 0, 2, 2), None);
        // Too-short source is rejected.
        assert_eq!(cb.blit_rect(&src, 0, 0, 3, 3), None);
    }

    #[test]
    fn test_blit_rect_hw_32bpp() {
        let mut hw = vec![0u32; 4 * 3];
        let mut cb = make_canvas(hw.as_mut_ptr() as *mut u8, 4, 3, 32);

        let mut src = vec![0u8; 2 * 2 * 4];
        for i in 0..4 {
            let px = 0xAA00u32 + i as u32;
            src[i * 4..i * 4 + 4].copy_from_slice(&px.to_le_bytes());
        }

        assert_eq!(cb.blit_rect(&src, 1, 1, 2, 2), Some((2, 2)));
        assert_eq!(hw[1 * 4 + 1], 0xAA00);
        assert_eq!(hw[1 * 4 + 2], 0xAA01);
        assert_eq!(hw[2 * 4 + 1], 0xAA02);
        assert_eq!(hw[2 * 4 + 2], 0xAA03);
        assert_eq!(hw[0], 0);
        assert_eq!(hw[1 * 4 + 3], 0);
    }

    #[test]
    fn test_blit_rect_hw_24bpp_bgr_order() {
        let mut hw = vec![0u8; 4 * 2 * 3];
        let mut cb = make_canvas(hw.as_mut_ptr() as *mut u8, 4, 2, 24);

        // Packed XRGB8888 0x00112233 -> little-endian bytes B,G,R,X.
        let src = vec![0x33u8, 0x22, 0x11, 0x00];
        assert_eq!(cb.blit_rect(&src, 1, 0, 1, 1), Some((1, 1)));

        let off = 3;
        assert_eq!(hw[off], 0x33, "blue byte");
        assert_eq!(hw[off + 1], 0x22, "green byte");
        assert_eq!(hw[off + 2], 0x11, "red byte");
        assert_eq!(hw[12 + off], 0, "next row untouched");
    }

    #[test]
    fn test_fill_rect_then_present_only_dirty() {
        const SENTINEL: u32 = 0xDEAD_BEEF;
        const COLOR: u32 = 0xFF00_FF00;

        let mut hw = vec![SENTINEL; 4 * 2];
        let mut cb = make_canvas(hw.as_mut_ptr() as *mut u8, 4, 2, 32);
        cb.back_buffer = Some(vec![SENTINEL; 4 * 2]);
        cb.draw_to_back = true;
        cb.track_dirty = true;

        cb.fill_rect(1, 0, 2, 1, COLOR);
        cb.present();

        assert_eq!(hw[0], SENTINEL, "pixel left of the dirty rect");
        assert_eq!(hw[1], COLOR);
        assert_eq!(hw[2], COLOR);
        assert_eq!(hw[3], SENTINEL, "pixel right of the dirty rect");
        assert_eq!(hw[4], SENTINEL, "second row is not dirty");
        assert_eq!(hw[7], SENTINEL);
    }
}
