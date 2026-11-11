/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

//! Low-level 32-bit pixel primitives.
//!
//! [`Canvas`](crate::Canvas) is generic over [`PixelOps`], so a kernel build
//! monomorphises to the SSE2/AVX2 backend and a host test instantiates
//! [`ScalarOps`]. There is no `dyn` dispatch on the hot path and no
//! `alloc`-backed trait object.
//!
//! Every public drawing call enters [`PixelOps::guard`] first. The kernel
//! adapter returns an [`FpuGuard`](../strat9_kernel) that preserves the
//! caller's SSE state; the scalar backend returns a zero-sized guard. The
//! invariant therefore lives in the API instead of in the memory of each
//! caller, which is where it used to live (each `fill_rect` opened with
//! `let _fpu = FpuGuard::save();` by convention).

/// Marker for the RAII value returned by [`PixelOps::guard`].
pub trait PixelGuard {}

/// The default no-op guard, used by [`ScalarOps`].
#[derive(Clone, Copy, Debug, Default)]
pub struct NoGuard;

impl PixelGuard for NoGuard {}

/// Raw 32-bit pixel operations.
///
/// # Safety contract
///
/// Implementations may assume, for every method, that:
///
/// - `dst` points to `count` writable `u32` values;
/// - `src` points to `count` readable `u32` values;
/// - the two ranges do not overlap.
///
/// The methods stay `unsafe fn` even though the trait is safe: constructing
/// a bad implementation is harmless as long as every call site upholds the
/// contract, and [`Canvas`](crate::Canvas) is the only caller.
pub trait PixelOps {
    /// RAII state saved around a drawing call (FPU/SSE registers in the
    /// kernel, nothing on the host).
    type Guard: PixelGuard;

    /// Acquire the guard. Kept separate from the operations so the compiler
    /// can drop it at the end of the drawing call.
    fn guard(&self) -> Self::Guard;

    /// Fill `count` pixels with `color`.
    ///
    /// # Safety
    /// See the trait-level contract.
    unsafe fn fill(&self, dst: *mut u32, color: u32, count: usize);

    /// Copy `count` pixels from `src` to `dst`.
    ///
    /// # Safety
    /// See the trait-level contract.
    unsafe fn blit(&self, dst: *mut u32, src: *const u32, count: usize);

    /// Blend `src` over `dst` with a constant `alpha` (0 = keep dst,
    /// 255 = take src), channel by channel including the top byte.
    ///
    /// # Safety
    /// See the trait-level contract.
    unsafe fn blend(&self, dst: *mut u32, src: *const u32, alpha: u8, count: usize);

    /// Non-temporal variant of [`Self::fill`], for write-combining memory.
    ///
    /// # Safety
    /// See the trait-level contract, plus: `dst` must be write-combining
    /// memory, and the caller must issue a fence before the result is read.
    unsafe fn fill_nt(&self, dst: *mut u32, color: u32, count: usize);

    /// Non-temporal variant of [`Self::blit`].
    ///
    /// # Safety
    /// See [`Self::fill_nt`].
    unsafe fn blit_nt(&self, dst: *mut u32, src: *const u32, count: usize);
}

/// Portable scalar backend. This is the reference implementation used by
/// host tests; it is also correct on any architecture.
#[derive(Clone, Copy, Debug, Default)]
pub struct ScalarOps;

impl PixelOps for ScalarOps {
    type Guard = NoGuard;

    #[inline]
    fn guard(&self) -> NoGuard {
        NoGuard
    }

    unsafe fn fill(&self, dst: *mut u32, color: u32, count: usize) {
        for i in 0..count {
            // Unaligned-safe: a 24 bpp surface may hand us a byte-aligned
            // base, and a caller-provided buffer is only 1-byte aligned by
            // type.
            unsafe { dst.add(i).write_unaligned(color) };
        }
    }

    unsafe fn blit(&self, dst: *mut u32, src: *const u32, count: usize) {
        for i in 0..count {
            let px = unsafe { src.add(i).read_unaligned() };
            unsafe { dst.add(i).write_unaligned(px) };
        }
    }

    unsafe fn blend(&self, dst: *mut u32, src: *const u32, alpha: u8, count: usize) {
        let a = alpha as u32;
        let inv = 255 - a;
        for i in 0..count {
            let d = unsafe { dst.add(i).read_unaligned() };
            let s = unsafe { src.add(i).read_unaligned() };
            unsafe { dst.add(i).write_unaligned(blend_word(d, s, a, inv)) };
        }
    }

    unsafe fn fill_nt(&self, dst: *mut u32, color: u32, count: usize) {
        unsafe { self.fill(dst, color, count) }
    }

    unsafe fn blit_nt(&self, dst: *mut u32, src: *const u32, count: usize) {
        unsafe { self.blit(dst, src, count) }
    }
}

/// Blend two packed 32-bit words byte by byte.
///
/// `a` is the source weight (`0..=255`), `inv == 255 - a`. The `/255` is
/// the exact rounding form used by the SSE2 path, so the scalar fallback
/// and the vector path agree on every byte.
#[inline]
pub fn blend_word(d: u32, s: u32, a: u32, inv: u32) -> u32 {
    let mut out = 0u32;
    let mut shift = 0;
    while shift < 32 {
        let db = (d >> shift) & 0xFF;
        let sb = (s >> shift) & 0xFF;
        let x = sb * a + db * inv;
        let byte = (x + (x >> 8) + 1) >> 8;
        out |= (byte & 0xFF) << shift;
        shift += 8;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_and_blit_round_trip() {
        let mut dst = [0u32; 8];
        let src = [1u32, 2, 3, 4];
        unsafe {
            ScalarOps.fill(dst.as_mut_ptr(), 0xABCD_EF01, 4);
            assert_eq!(&dst[..4], &[0xABCD_EF01; 4]);
            ScalarOps.blit(dst.as_mut_ptr(), src.as_ptr(), 4);
        }
        assert_eq!(&dst[..4], &src);
    }

    #[test]
    fn blend_endpoints_are_exact() {
        let d = 0x0011_2233;
        let s = 0xFF44_5566;
        assert_eq!(blend_word(d, s, 0, 255), d);
        // alpha 255 gives src, except the rounding of the exact /255 form:
        // (s*255 + 255) >> 8 is s for every byte.
        assert_eq!(blend_word(d, s, 255, 0), s);
    }

    #[test]
    fn blend_half_way_is_symmetric() {
        let a = 0;
        let b = 0xFF;
        let mid = blend_word(a, b, 127, 128);
        assert_eq!(mid & 0xFF, 127);
        let back = blend_word(b, a, 127, 128);
        assert_eq!(back & 0xFF, 128);
    }

    #[test]
    fn blend_never_exceeds_a_byte() {
        for alpha in 0..=255u32 {
            let out = blend_word(0xFFFF_FFFF, 0xFFFF_FFFF, alpha, 255 - alpha);
            assert_eq!(out, 0xFFFF_FFFF);
        }
    }
}
