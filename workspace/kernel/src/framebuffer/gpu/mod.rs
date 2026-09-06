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
