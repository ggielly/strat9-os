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

pub mod neon;

use crate::framebuffer::{generic, FramebufferOps};

pub fn detect_and_init_ops() -> FramebufferOps {
    // Basic fallback for now, real CPUID check can go here
    FramebufferOps {
        fill: neon::fill_neon,
        blit: neon::blit_neon,
        blend: neon::blend_neon,
        convert: neon::convert_bgr_to_argb_neon,
        // No non-temporal store path on aarch64 yet: reuse the cached ops.
        fill_nt: neon::fill_neon,
        blit_nt: neon::blit_neon,
    }
}
