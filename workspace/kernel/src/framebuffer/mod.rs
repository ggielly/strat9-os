use alloc::vec::Vec;

pub mod generic;
pub mod gpu;

#[cfg(test)]
pub mod tests;

#[cfg(target_arch = "x86_64")]
pub mod x86;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

// Shared RgbColor type used by all framebuffer/VGA code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RgbColor {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl RgbColor {
    /// Creates a new instance.
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b }
    }

    pub const BLACK: Self = Self::new(0x00, 0x00, 0x00);
    pub const WHITE: Self = Self::new(0xFF, 0xFF, 0xFF);
    pub const RED: Self = Self::new(0xFF, 0x00, 0x00);
    pub const GREEN: Self = Self::new(0x00, 0xFF, 0x00);
    pub const BLUE: Self = Self::new(0x00, 0x00, 0xFF);
    pub const CYAN: Self = Self::new(0x00, 0xFF, 0xFF);
    pub const MAGENTA: Self = Self::new(0xFF, 0x00, 0xFF);
    pub const YELLOW: Self = Self::new(0xFF, 0xFF, 0x00);
    pub const LIGHT_GREY: Self = Self::new(0xAA, 0xAA, 0xAA);
}

// Shared dirty-rect tracking used by VGA writer and video framebuffer.
#[derive(Clone, Copy, Debug, Default)]
pub struct DirtyRect {
    pub x0: u32,
    pub y0: u32,
    pub x1: u32,
    pub y1: u32,
}

impl DirtyRect {
    pub const fn empty() -> Self {
        Self {
            x0: 0,
            y0: 0,
            x1: 0,
            y1: 0,
        }
    }

    pub fn is_valid(self) -> bool {
        self.x0 < self.x1 && self.y0 < self.y1
    }

    pub fn width(self) -> u32 {
        self.x1.saturating_sub(self.x0)
    }

    pub fn height(self) -> u32 {
        self.y1.saturating_sub(self.y0)
    }

    pub fn include(&mut self, x: u32, y: u32, w: u32, h: u32) {
        if w == 0 || h == 0 {
            return;
        }
        let nx1 = x.saturating_add(w);
        let ny1 = y.saturating_add(h);
        if !self.is_valid() {
            self.x0 = x;
            self.y0 = y;
            self.x1 = nx1;
            self.y1 = ny1;
        } else {
            self.x0 = self.x0.min(x);
            self.y0 = self.y0.min(y);
            self.x1 = self.x1.max(nx1);
            self.y1 = self.y1.max(ny1);
        }
    }

    pub fn overlaps(self, other: DirtyRect) -> bool {
        self.x0 < other.x1 && self.x1 > other.x0 && self.y0 < other.y1 && self.y1 > other.y0
    }
}

pub const MAX_DIRTY_RECTS: usize = 8;

#[derive(Clone, Copy)]
pub struct DirtyRectSet {
    pub rects: [DirtyRect; MAX_DIRTY_RECTS],
    pub len: usize,
}

impl DirtyRectSet {
    pub const fn empty() -> Self {
        Self {
            rects: [DirtyRect::empty(); MAX_DIRTY_RECTS],
            len: 0,
        }
    }

    pub fn clear(&mut self) {
        self.len = 0;
    }

    pub fn include(&mut self, x: u32, y: u32, w: u32, h: u32) {
        if w == 0 || h == 0 {
            return;
        }
        let mut next = DirtyRect::empty();
        next.include(x, y, w, h);

        let mut idx = 0;
        while idx < self.len {
            let cur = self.rects[idx];
            if !cur.is_valid() {
                idx += 1;
                continue;
            }
            if cur.overlaps(next) {
                next.include(cur.x0, cur.y0, cur.width(), cur.height());
                self.rects[idx] = self.rects[self.len - 1];
                self.len -= 1;
                idx = 0;
                continue;
            }
            idx += 1;
        }

        if self.len < MAX_DIRTY_RECTS {
            self.rects[self.len] = next;
            self.len += 1;
            return;
        }
        self.rects[0].include(next.x0, next.y0, next.width(), next.height());
    }

    pub fn iter(&self) -> DirtyRectIter {
        DirtyRectIter { set: self, idx: 0 }
    }
}

pub struct DirtyRectIter<'a> {
    set: &'a DirtyRectSet,
    idx: usize,
}

impl<'a> Iterator for DirtyRectIter<'a> {
    type Item = &'a DirtyRect;

    fn next(&mut self) -> Option<Self::Item> {
        while self.idx < self.set.len {
            let r = &self.set.rects[self.idx];
            self.idx += 1;
            if r.is_valid() {
                return Some(r);
            }
        }
        None
    }
}

// Type definitions for our framebuffer operations
pub type FnFill = unsafe fn(dst: *mut u32, color: u32, count: usize);
pub type FnBlit = unsafe fn(dst: *mut u32, src: *const u32, count: usize);
pub type FnBlend = unsafe fn(dst: *mut u32, src: *const u32, alpha: u8, count: usize);
pub type FnConvert = unsafe fn(dst: *mut u32, src: *const u8, count: usize);

#[derive(Clone, Copy)]
pub struct FramebufferOps {
    pub fill: FnFill,
    pub blit: FnBlit,
    pub blend: FnBlend,
    pub convert: FnConvert,
}

// ---------------------------------------------------------------------------
// CanvasBuffer : shared double-buffered framebuffer canvas
// ---------------------------------------------------------------------------

/// A raw framebuffer canvas with optional double buffering.
///
/// Encapsulates the HW framebuffer pointer, optional back-buffer (always
/// 32bpp), dirty-region tracking, SIMD-accelerated pixel ops, and a
/// `present()` that flushes dirty regions to the real hardware.
///
/// Used by both the VGA text-mode writer (`VgaWriter`) and the raw
/// hardware video driver (`hardware::video::Framebuffer`), eliminating
/// the duplicated `present()` / dirty-tracking logic between them.
pub struct CanvasBuffer {
    /// Pointer to the start of the HW framebuffer (HHDM-mapped virtual).
    pub addr: *mut u8,
    /// Width in pixels.
    pub width: usize,
    /// Height in pixels.
    pub height: usize,
    /// Bytes per row (stride / pitch).
    pub pitch: usize,
    /// Bits per pixel (24 or 32).
    pub bpp: u16,
    /// Optional back-buffer (always 32bpp / `u32` per pixel).
    pub back_buffer: Option<Vec<u32>>,
    /// If `true`, draw operations write to `back_buffer` instead of HW.
    pub draw_to_back: bool,
    /// Set of dirty rectangles pending a `present()`.
    pub dirty: DirtyRectSet,
    /// If `true`, dirty rectangles are tracked.
    pub track_dirty: bool,
    /// Whether a `present()` has been requested.
    pub present_pending: bool,
    /// Tick of the last `present()` (for rate-limiting).
    pub last_present_tick: u64,
    /// SIMD-accelerated pixel ops (fill, blit, blend, convert).
    pub ops: FramebufferOps,
}

unsafe impl Send for CanvasBuffer {}

impl CanvasBuffer {
    /// Enable double-buffering by allocating and syncing a back-buffer.
    pub fn enable_back_buffer(&mut self) -> bool {
        if self.back_buffer.is_some() {
            return true;
        }
        let total = self.width.saturating_mul(self.height);
        if total == 0 || self.addr.is_null() {
            return false;
        }
        let mut buf = alloc::vec![0u32; total];
        // Sync current HW content into back-buffer.
        if self.bpp == 32 {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    self.addr as *const u8,
                    buf.as_mut_ptr() as *mut u8,
                    total * 4,
                );
            }
        } else {
            for y in 0..self.height {
                for x in 0..self.width {
                    buf[y * self.width + x] = self.read_hw_pixel(x, y);
                }
            }
        }
        self.back_buffer = Some(buf);
        self.draw_to_back = true;
        self.track_dirty = true;
        self.dirty.clear();
        true
    }

    /// Disable double-buffering, optionally presenting first.
    pub fn disable_back_buffer(&mut self, do_present: bool) {
        if do_present {
            self.present();
        }
        self.draw_to_back = false;
        self.track_dirty = false;
        self.dirty.clear();
    }

    /// Byte offset in HW memory for pixel `(x, y)`.
    #[inline]
    pub fn pixel_offset(&self, x: usize, y: usize) -> Option<usize> {
        if x >= self.width || y >= self.height {
            return None;
        }
        let bytes_pp = (self.bpp / 8) as usize;
        Some(
            y.checked_mul(self.pitch)?
                .checked_add(x.checked_mul(bytes_pp)?)?,
        )
    }

    /// Read a packed pixel directly from HW memory.
    pub fn read_hw_pixel(&self, x: usize, y: usize) -> u32 {
        let Some(off) = self.pixel_offset(x, y) else {
            return 0;
        };
        unsafe {
            match self.bpp {
                32 => core::ptr::read_volatile(self.addr.add(off) as *const u32),
                24 => {
                    let b0 = core::ptr::read_volatile(self.addr.add(off)) as u32;
                    let b1 = core::ptr::read_volatile(self.addr.add(off + 1)) as u32;
                    let b2 = core::ptr::read_volatile(self.addr.add(off + 2)) as u32;
                    b0 | (b1 << 8) | (b2 << 16)
                }
                _ => 0,
            }
        }
    }

    /// Write a packed pixel to HW memory.
    pub fn write_hw_pixel(&mut self, x: usize, y: usize, color: u32) {
        let Some(off) = self.pixel_offset(x, y) else {
            return;
        };
        unsafe {
            match self.bpp {
                32 => {
                    core::ptr::write_volatile(self.addr.add(off) as *mut u32, color);
                }
                24 => {
                    core::ptr::write_volatile(self.addr.add(off), (color & 0xFF) as u8);
                    core::ptr::write_volatile(self.addr.add(off + 1), ((color >> 8) & 0xFF) as u8);
                    core::ptr::write_volatile(self.addr.add(off + 2), ((color >> 16) & 0xFF) as u8);
                }
                _ => {}
            }
        }
    }

    /// Read pixel `(x, y)` : from back-buffer if available, else HW.
    pub fn read_pixel(&self, x: usize, y: usize) -> u32 {
        if x >= self.width || y >= self.height {
            return 0;
        }
        if self.draw_to_back {
            if let Some(buf) = self.back_buffer.as_ref() {
                return buf[y * self.width + x];
            }
        }
        self.read_hw_pixel(x, y)
    }

    /// Write pixel `(x, y)` : to back-buffer if available, else HW.
    pub fn write_pixel(&mut self, x: usize, y: usize, color: u32) {
        if x >= self.width || y >= self.height {
            return;
        }
        if self.draw_to_back {
            if let Some(buf) = self.back_buffer.as_mut() {
                buf[y * self.width + x] = color;
                self.dirty.include(x as u32, y as u32, 1, 1);
                return;
            }
        }
        self.write_hw_pixel(x, y, color);
    }

    /// Fill a rectangle with a packed colour.
    pub fn fill_rect(&mut self, x: usize, y: usize, w: usize, h: usize, color: u32) {
        if w == 0 || h == 0 {
            return;
        }
        let x_end = core::cmp::min(x.saturating_add(w), self.width);
        let y_end = core::cmp::min(y.saturating_add(h), self.height);
        if x_end <= x || y_end <= y {
            return;
        }
        let fw = self.width;
        let sw = x_end - x;
        let sh = y_end - y;

        if self.draw_to_back {
            if let Some(buf) = self.back_buffer.as_mut() {
                for py in y..y_end {
                    let start = py * fw + x;
                    buf[start..start + sw].fill(color);
                }
                self.dirty.include(x as u32, y as u32, sw as u32, sh as u32);
                return;
            }
        }

        if self.bpp == 32 {
            for py in y..y_end {
                if let Some(off) = py
                    .checked_mul(self.pitch)
                    .and_then(|r| r.checked_add(x * 4))
                {
                    unsafe {
                        let ptr = self.addr.add(off) as *mut u32;
                        (self.ops.fill)(ptr, color, sw);
                    }
                }
            }
        } else {
            for py in y..y_end {
                for px in x..x_end {
                    self.write_hw_pixel(px, py, color);
                }
            }
        }
        if self.track_dirty {
            self.dirty.include(x as u32, y as u32, sw as u32, sh as u32);
        }
    }

    /// Flush dirty back-buffer regions to the hardware framebuffer.
    ///
    /// Uses SIMD-accelerated `ops.blit` when the back-buffer's row stride
    /// matches the frame-buffer's stride, falling back to row-by-row copies.
    pub fn present(&mut self) {
        let Some(buf) = self.back_buffer.as_ref() else {
            return;
        };
        if self.track_dirty && self.dirty.len == 0 {
            return;
        }
        let buf_ptr = buf.as_ptr();
        let pitch = self.pitch;
        let fb_addr = self.addr;

        // Collect regions to present.
        let mut regions: [(u32, u32, u32, u32); MAX_DIRTY_RECTS] = [(0, 0, 0, 0); MAX_DIRTY_RECTS];
        let mut region_count = 0usize;

        if self.track_dirty {
            for r in self.dirty.iter() {
                if region_count < MAX_DIRTY_RECTS {
                    regions[region_count] = (r.x0, r.y0, r.width(), r.height());
                    region_count += 1;
                }
            }
        } else {
            regions[0] = (0, 0, self.width as u32, self.height as u32);
            region_count = 1;
        }

        let stride_pixels_u32 = pitch / 4; // stride in u32 units
        for i in 0..region_count {
            let (rx, ry, rw, rh) = regions[i];
            if rw == 0 || rh == 0 {
                continue;
            }
            let (rx, ry, rw, rh) = (rx as usize, ry as usize, rw as usize, rh as usize);

            // Fast path: row stride matches, blit contiguous block.
            if self.bpp == 32 {
                if self.width == stride_pixels_u32 {
                    let off = ry * self.width + rx;
                    let dst_off = ry * pitch + rx * 4;
                    unsafe {
                        let src = buf_ptr.add(off) as *const u8;
                        (self.ops.blit)(
                            fb_addr.add(dst_off) as *mut u32,
                            src as *const u32,
                            rw * rh,
                        );
                        // (ops.blit) uses copy_nonoverlapping internally
                    }
                } else {
                    for row in 0..rh {
                        let src_off = (ry + row) * self.width + rx;
                        let dst_off = (ry + row) * pitch + rx * 4;
                        unsafe {
                            let src = buf_ptr.add(src_off) as *const u32;
                            (self.ops.blit)(fb_addr.add(dst_off) as *mut u32, src, rw);
                        }
                    }
                }
            } else {
                // 24bpp fallback: convert row-by-row.
                let row_bytes = rw * 3;
                let mut row_buf = alloc::vec![0u8; row_bytes];
                for row in 0..rh {
                    let src_row = (ry + row) * self.width + rx;
                    for x in 0..rw {
                        let packed = unsafe { *buf_ptr.add(src_row + x) };
                        let off = x * 3;
                        row_buf[off] = packed as u8;
                        row_buf[off + 1] = (packed >> 8) as u8;
                        row_buf[off + 2] = (packed >> 16) as u8;
                    }
                    let dst_off = (ry + row) * pitch + rx * 3;
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            row_buf.as_ptr(),
                            fb_addr.add(dst_off),
                            row_bytes,
                        );
                    }
                }
            }
        }

        self.dirty.clear();
        self.present_pending = false;
    }

    /// Request a present (throttled).
    pub fn request_present(&mut self) {
        if !self.draw_to_back {
            return;
        }
        self.present_pending = true;
    }

    /// Present if a request is pending and the throttle delay has elapsed.
    pub fn present_if_due(&mut self, force: bool, now: u64) {
        if !self.present_pending || !self.draw_to_back {
            return;
        }
        if force || now.saturating_sub(self.last_present_tick) >= PRESENT_MIN_TICKS_CB {
            self.last_present_tick = now;
            self.present();
        }
    }
}

/// Local constant for present throttling (matches VgaWriter's PRESENT_MIN_TICKS).
const PRESENT_MIN_TICKS_CB: u64 = 1;

impl FramebufferOps {
    pub fn detect() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            return x86::detect_and_init_ops();
        }

        #[cfg(target_arch = "aarch64")]
        {
            // ARM CPUID detection for NEON could be done here,
            // but for now we fallback to generic or neon if compiled with it.
            return aarch64::detect_and_init_ops();
        }

        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            Self {
                fill: generic::fill_generic,
                blit: generic::blit_generic,
                blend: generic::blend_generic,
                convert: generic::convert_bgr_to_argb_generic,
            }
        }
    }
}
