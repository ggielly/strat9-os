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
