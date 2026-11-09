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

use super::GraphicsBackend;

// TODO : Implement actual DRM/KMS backend here, this is just a stub for now

pub struct GpuStub {
    // Stub fields for future DRM/KMS
}

impl GraphicsBackend for GpuStub {
    fn fill_rect(&mut self, _x: u32, _y: u32, _w: u32, _h: u32, _color: u32) {
        // empty stub
    }

    fn blit(&mut self, _dst_x: u32, _dst_y: u32, _src: &[u32], _src_w: u32, _src_h: u32) {
        // empty stub
    }

    fn present(&mut self) {
        // empty stub
    }
}
