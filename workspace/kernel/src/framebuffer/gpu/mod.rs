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

pub trait GraphicsBackend {
    fn fill_rect(&mut self, x: u32, y: u32, w: u32, h: u32, color: u32);
    fn blit(&mut self, dst_x: u32, dst_y: u32, src: &[u32], src_w: u32, src_h: u32);
    fn present(&mut self);
}

pub struct CpuFramebuffer {
    pub buffer: *mut u32,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub ops: super::FramebufferOps,
}

impl GraphicsBackend for CpuFramebuffer {
    fn fill_rect(&mut self, x: u32, y: u32, w: u32, h: u32, color: u32) {
        let end_y = core::cmp::min(y + h, self.height);
        let end_x = core::cmp::min(x + w, self.width);
        let actual_w = end_x.saturating_sub(x);

        for cur_y in y..end_y {
            let offset = (cur_y * self.stride + x) as usize;
            unsafe {
                (self.ops.fill)(self.buffer.add(offset), color, actual_w as usize);
            }
        }
    }

    fn blit(&mut self, dst_x: u32, dst_y: u32, src: &[u32], src_w: u32, src_h: u32) {
        let end_y = core::cmp::min(dst_y + src_h, self.height);
        let end_x = core::cmp::min(dst_x + src_w, self.width);
        let actual_w = end_x.saturating_sub(dst_x);
        let actual_h = end_y.saturating_sub(dst_y);

        for i in 0..actual_h {
            let src_offset = (i * src_w) as usize;
            let dst_offset = ((dst_y + i) * self.stride + dst_x) as usize;
            unsafe {
                (self.ops.blit)(
                    self.buffer.add(dst_offset),
                    src.as_ptr().add(src_offset),
                    actual_w as usize,
                );
            }
        }
    }

    fn present(&mut self) {
        // CPU buffer flush or nothing if directly mapped
    }
}
