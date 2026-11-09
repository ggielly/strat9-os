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

// use core::arch::aarch64::*;

// Placeholder for ARM NEON
// TODO : Implement actual NEON optimized versions of these functions
pub unsafe fn fill_neon(dst: *mut u32, color: u32, count: usize) {
    crate::framebuffer::generic::fill_generic(dst, color, count);
}

pub unsafe fn blit_neon(dst: *mut u32, src: *const u32, count: usize) {
    crate::framebuffer::generic::blit_generic(dst, src, count);
}

pub unsafe fn blend_neon(dst: *mut u32, src: *const u32, alpha: u8, count: usize) {
    crate::framebuffer::generic::blend_generic(dst, src, alpha, count);
}

pub unsafe fn convert_bgr_to_argb_neon(dst: *mut u32, src: *const u8, count: usize) {
    crate::framebuffer::generic::convert_bgr_to_argb_generic(dst, src, count);
}
