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

//! Wide-store helpers for the linear framebuffer.
//!
//! The early boot console (live debug overlay) and the panic screen draw
//! without the `VgaWriter`, so they cannot use its SIMD blit path. They used
//! to write one pixel at a time with `write_volatile`, and to scroll with
//! `core::ptr::copy` (which lowers to `rep movsb`).
//!
//! On real hardware the framebuffer is MMIO behind PCIe: a byte/word store is
//! one bus transaction, so `rep movsb` to uncached memory runs at a few MB/s
//! and the panel visibly repaints from top to bottom. These helpers emit
//! 8-byte stores, which is the widest portable width without target features
//! (the pinned nightly miscompiles `movntdq` on `x86_64-unknown-none`), and
//! keeps the write-combining buffers fed.

/// Bytes per pixel for a supported GOP format (24 or 32).
#[inline]
pub const fn bytes_per_pixel(bpp: u16) -> usize {
    (bpp / 8) as usize
}

/// Fill `pixels` consecutive pixels with `color`.
///
/// # Safety
/// `dst` must point to `pixels * bytes_per_pixel(bpp)` writable bytes inside a
/// mapped framebuffer row.
pub unsafe fn fill_pixels(dst: *mut u8, bpp_bytes: usize, color: u32, pixels: usize) {
    if pixels == 0 {
        return;
    }
    match bpp_bytes {
        4 => {
            let pair = (color as u64) | ((color as u64) << 32);
            let mut i = 0usize;
            while i + 2 <= pixels {
                // SAFETY: two pixels fit before `pixels`; unaligned is fine.
                core::ptr::write_unaligned(dst.add(i * 4) as *mut u64, pair);
                i += 2;
            }
            if i < pixels {
                core::ptr::write_unaligned(dst.add(i * 4) as *mut u32, color);
            }
        }
        3 => {
            // Pack eight 24-bit pixels (24 bytes) per iteration.
            let b = [color as u8, (color >> 8) as u8, (color >> 16) as u8];
            let mut i = 0usize;
            while i + 8 <= pixels {
                let mut chunk = [0u8; 24];
                for px in 0..8 {
                    chunk[px * 3..px * 3 + 3].copy_from_slice(&b);
                }
                core::ptr::copy_nonoverlapping(chunk.as_ptr(), dst.add(i * 3), 24);
                i += 8;
            }
            while i < pixels {
                let p = dst.add(i * 3);
                core::ptr::write_unaligned(p, b[0]);
                core::ptr::write_unaligned(p.add(1), b[1]);
                core::ptr::write_unaligned(p.add(2), b[2]);
                i += 1;
            }
        }
        _ => {}
    }
}

/// Store a row of `colors` (one u32 per pixel) into the framebuffer.
///
/// # Safety
/// `dst` must point to `colors.len() * bytes_per_pixel(bpp)` writable bytes
/// inside a mapped framebuffer row.
pub unsafe fn store_row(dst: *mut u8, bpp_bytes: usize, colors: &[u32]) {
    match bpp_bytes {
        4 => {
            let mut i = 0usize;
            while i + 2 <= colors.len() {
                let pair = (colors[i] as u64) | ((colors[i + 1] as u64) << 32);
                core::ptr::write_unaligned(dst.add(i * 4) as *mut u64, pair);
                i += 2;
            }
            if i < colors.len() {
                core::ptr::write_unaligned(dst.add(i * 4) as *mut u32, colors[i]);
            }
        }
        3 => {
            let mut i = 0usize;
            while i < colors.len() {
                let c = colors[i];
                let p = dst.add(i * 3);
                core::ptr::write_unaligned(p, c as u8);
                core::ptr::write_unaligned(p.add(1), (c >> 8) as u8);
                core::ptr::write_unaligned(p.add(2), (c >> 16) as u8);
                i += 1;
            }
        }
        _ => {}
    }
}

/// Forward copy of `bytes` bytes with 8-byte granularity.
///
/// Use only when `dst < src` (or when the ranges do not overlap): the copy is
/// strictly forward, so an overlapping move-up is safe but a move-down is not.
///
/// # Safety
/// Both ranges must be valid for `bytes` bytes and must not require backward
/// copying.
pub unsafe fn copy_forward(dst: *mut u8, src: *const u8, bytes: usize) {
    let mut i = 0usize;
    while i + 8 <= bytes {
        let v = core::ptr::read_unaligned(src.add(i) as *const u64);
        core::ptr::write_unaligned(dst.add(i) as *mut u64, v);
        i += 8;
    }
    while i < bytes {
        core::ptr::write_unaligned(dst.add(i), core::ptr::read_unaligned(src.add(i)));
        i += 1;
    }
}

/// Backward copy of `bytes` bytes with 8-byte granularity.
///
/// Required when `dst > src` and the ranges overlap (scrolling down): a
/// forward copy would overwrite source bytes before they are read.
///
/// # Safety
/// Both ranges must be valid for `bytes` bytes.
pub unsafe fn copy_backward(dst: *mut u8, src: *const u8, bytes: usize) {
    let mut i = bytes;
    while i >= 8 {
        i -= 8;
        let v = core::ptr::read_unaligned(src.add(i) as *const u64);
        core::ptr::write_unaligned(dst.add(i) as *mut u64, v);
    }
    while i > 0 {
        i -= 1;
        core::ptr::write_unaligned(dst.add(i), core::ptr::read_unaligned(src.add(i)));
    }
}

/// Fence write-combining stores so they become visible on the panel.
#[inline]
pub fn fence() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("sfence", options(nostack, preserves_flags));
    }
}
