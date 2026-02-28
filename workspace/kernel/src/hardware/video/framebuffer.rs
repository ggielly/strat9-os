// Framebuffer abstraction layer
//
// Provides a unified framebuffer interface that can use:
// - Limine framebuffer (bootloader-provided)
// - VirtIO GPU framebuffer (native driver)
// - Future: Other GPU drivers (Bochs DRM, etc.)
//
// Features:
// - Resolution switching
// - Double buffering
// - Basic 2D drawing primitives
// - Text rendering support

#![allow(dead_code)]

use crate::{
    hardware::virtio::gpu,
    memory::{get_allocator, phys_to_virt, FrameAllocator},
};
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

/// Maximum supported resolution
const MAX_WIDTH: u32 = 3840;
const MAX_HEIGHT: u32 = 2160;

/// Framebuffer source
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FramebufferSource {
    Limine,
    VirtioGpu,
    None,
}

/// Pixel format
#[derive(Clone, Copy, Debug)]
pub struct PixelFormat {
    pub red_mask: u32,
    pub red_shift: u8,
    pub green_mask: u32,
    pub green_shift: u8,
    pub blue_mask: u32,
    pub blue_shift: u8,
    pub bits_per_pixel: u8,
}

impl Default for PixelFormat {
    fn default() -> Self {
        Self {
            red_mask: 0x00FF0000,
            red_shift: 16,
            green_mask: 0x0000FF00,
            green_shift: 8,
            blue_mask: 0x000000FF,
            blue_shift: 0,
            bits_per_pixel: 32,
        }
    }
}

/// Framebuffer information
#[derive(Clone, Copy, Debug)]
pub struct FramebufferInfo {
    pub base: u64,
    pub base_virt: usize,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub format: PixelFormat,
    pub source: FramebufferSource,
}

unsafe impl Send for FramebufferInfo {}
unsafe impl Sync for FramebufferInfo {}

/// Main framebuffer structure
pub struct Framebuffer {
    info: FramebufferInfo,
    double_buffer: Option<*mut u8>,
    use_double_buffer: bool,
    dirty: DirtyRect,
}

unsafe impl Send for Framebuffer {}
unsafe impl Sync for Framebuffer {}

static FRAMEBUFFER: Mutex<Option<Framebuffer>> = Mutex::new(None);
static FRAMEBUFFER_INITIALIZED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy)]
struct DirtyRect {
    valid: bool,
    x0: u32,
    y0: u32,
    x1: u32,
    y1: u32,
}

impl DirtyRect {
    const fn empty() -> Self {
        Self {
            valid: false,
            x0: 0,
            y0: 0,
            x1: 0,
            y1: 0,
        }
    }

    fn include(&mut self, x: u32, y: u32, width: u32, height: u32) {
        if width == 0 || height == 0 {
            return;
        }
        let x1 = x.saturating_add(width);
        let y1 = y.saturating_add(height);
        if !self.valid {
            self.valid = true;
            self.x0 = x;
            self.y0 = y;
            self.x1 = x1;
            self.y1 = y1;
        } else {
            self.x0 = self.x0.min(x);
            self.y0 = self.y0.min(y);
            self.x1 = self.x1.max(x1);
            self.y1 = self.y1.max(y1);
        }
    }

    fn take(&mut self) -> Option<(u32, u32, u32, u32)> {
        if !self.valid {
            return None;
        }
        let x = self.x0;
        let y = self.y0;
        let width = self.x1.saturating_sub(self.x0);
        let height = self.y1.saturating_sub(self.y0);
        *self = Self::empty();
        Some((x, y, width, height))
    }
}

impl Framebuffer {
    /// Initialize framebuffer with Limine-provided buffer
    pub fn init_limine(
        addr: u64,
        width: u32,
        height: u32,
        stride: u32,
        format: PixelFormat,
    ) -> Result<(), &'static str> {
        if addr == 0 || width == 0 || height == 0 {
            return Err("Invalid framebuffer parameters");
        }

        let base_virt = addr as usize;

        let info = FramebufferInfo {
            base: addr,
            base_virt,
            width,
            height,
            stride,
            format,
            source: FramebufferSource::Limine,
        };

        let fb = Framebuffer {
            info,
            double_buffer: None,
            use_double_buffer: false,
            dirty: DirtyRect::empty(),
        };

        *FRAMEBUFFER.lock() = Some(fb);
        FRAMEBUFFER_INITIALIZED.store(true, Ordering::SeqCst);

        log::info!(
            "[FB] Limine framebuffer: {}x{} @ {}bpp, stride={}",
            width,
            height,
            format.bits_per_pixel,
            stride
        );

        Ok(())
    }

    /// Initialize framebuffer with VirtIO GPU
    pub fn init_virtio_gpu() -> Result<(), &'static str> {
        let gpu_info = gpu::get_framebuffer_info().ok_or("VirtIO GPU not initialized")?;

        let format = PixelFormat {
            red_mask: 0x00FF0000,
            red_shift: 16,
            green_mask: 0x0000FF00,
            green_shift: 8,
            blue_mask: 0x000000FF,
            blue_shift: 0,
            bits_per_pixel: 32,
        };

        let info = FramebufferInfo {
            base: gpu_info.framebuffer_phys,
            base_virt: gpu_info.framebuffer_virt as usize,
            width: gpu_info.width,
            height: gpu_info.height,
            stride: gpu_info.stride,
            format,
            source: FramebufferSource::VirtioGpu,
        };

        // Allocate double buffer for VirtIO GPU
        let db_size = (info.stride as usize) * (info.height as usize);
        if db_size == 0 {
            return Err("Invalid VirtIO framebuffer size");
        }
        let db_pages = (db_size + 4095) / 4096;
        let db_order = db_pages.next_power_of_two().trailing_zeros() as u8;
        let db_frame = {
            let mut alloc_guard = get_allocator().lock();
            let allocator = alloc_guard
                .as_mut()
                .ok_or("Allocator unavailable for double buffer")?;
            allocator
                .alloc(db_order)
                .map_err(|_| "Failed to allocate double buffer")?
        };
        let db_virt = phys_to_virt(db_frame.start_address.as_u64()) as *mut u8;
        unsafe {
            // SAFETY: `db_virt` is a freshly allocated contiguous buffer of at
            // least `db_size` bytes.
            core::ptr::write_bytes(db_virt, 0, db_size);
        }

        let fb = Framebuffer {
            info,
            double_buffer: Some(db_virt),
            use_double_buffer: true,
            dirty: DirtyRect::empty(),
        };

        *FRAMEBUFFER.lock() = Some(fb);
        FRAMEBUFFER_INITIALIZED.store(true, Ordering::SeqCst);

        log::info!(
            "[FB] VirtIO GPU framebuffer: {}x{} @ {}bpp, stride={}",
            info.width,
            info.height,
            info.format.bits_per_pixel,
            info.stride
        );

        Ok(())
    }

    /// Get framebuffer info
    pub fn info() -> Option<FramebufferInfo> {
        FRAMEBUFFER.lock().as_ref().map(|fb| fb.info)
    }

    /// Get framebuffer width
    pub fn width() -> u32 {
        FRAMEBUFFER
            .lock()
            .as_ref()
            .map(|fb| fb.info.width)
            .unwrap_or(0)
    }

    /// Get framebuffer height
    pub fn height() -> u32 {
        FRAMEBUFFER
            .lock()
            .as_ref()
            .map(|fb| fb.info.height)
            .unwrap_or(0)
    }

    /// Get stride (bytes per row)
    pub fn stride() -> u32 {
        FRAMEBUFFER
            .lock()
            .as_ref()
            .map(|fb| fb.info.stride)
            .unwrap_or(0)
    }

    /// Check if framebuffer is initialized
    pub fn is_available() -> bool {
        FRAMEBUFFER_INITIALIZED.load(Ordering::Relaxed)
    }

    /// Get framebuffer source
    pub fn source() -> FramebufferSource {
        FRAMEBUFFER
            .lock()
            .as_ref()
            .map(|fb| fb.info.source)
            .unwrap_or(FramebufferSource::None)
    }

    /// Set a pixel at (x, y) with RGB color
    pub fn set_pixel(x: u32, y: u32, r: u8, g: u8, b: u8) {
        let mut flush_region = None;
        {
            let mut guard = FRAMEBUFFER.lock();
            let fb = match guard.as_mut() {
                Some(f) => f,
                None => return,
            };

            if x >= fb.info.width || y >= fb.info.height {
                return;
            }

            let pixel = ((r as u32) << fb.info.format.red_shift)
                | ((g as u32) << fb.info.format.green_shift)
                | ((b as u32) << fb.info.format.blue_shift);

            let offset = if fb.use_double_buffer {
                fb.double_buffer.unwrap_or(fb.info.base_virt as *mut u8)
            } else {
                fb.info.base_virt as *mut u8
            };

            unsafe {
                let pixel_ptr = offset.add((y * fb.info.stride + x * 4) as usize);
                core::ptr::write(pixel_ptr as *mut u32, pixel);
            }

            fb.dirty.include(x, y, 1, 1);
            if fb.info.source == FramebufferSource::VirtioGpu && !fb.use_double_buffer {
                flush_region = Some((x, y, 1, 1));
            }
        }

        if let Some((fx, fy, fw, fh)) = flush_region {
            if let Some(gpu) = gpu::get_gpu() {
                gpu.flush(fx, fy, fw, fh);
                gpu.flush_now();
            }
        }
    }

    /// Fill rectangle with color
    pub fn fill_rect(x: u32, y: u32, width: u32, height: u32, r: u8, g: u8, b: u8) {
        if width == 0 || height == 0 {
            return;
        }

        let mut flush_region = None;
        {
            let mut guard = FRAMEBUFFER.lock();
            let fb = match guard.as_mut() {
                Some(f) => f,
                None => return,
            };

            if x >= fb.info.width || y >= fb.info.height {
                return;
            }

            let max_w = fb.info.width - x;
            let max_h = fb.info.height - y;
            let width = width.min(max_w);
            let height = height.min(max_h);
            if width == 0 || height == 0 {
                return;
            }

            let pixel = ((r as u32) << fb.info.format.red_shift)
                | ((g as u32) << fb.info.format.green_shift)
                | ((b as u32) << fb.info.format.blue_shift);

            let offset = if fb.use_double_buffer {
                fb.double_buffer.unwrap_or(fb.info.base_virt as *mut u8)
            } else {
                fb.info.base_virt as *mut u8
            };

            let stride = fb.info.stride as usize;
            for dy in 0..height as usize {
                let row_ptr =
                    unsafe { offset.add((y as usize + dy) * stride + x as usize * 4) as *mut u32 };
                for dx in 0..width as usize {
                    unsafe {
                        core::ptr::write(row_ptr.add(dx), pixel);
                    }
                }
            }

            fb.dirty.include(x, y, width, height);
            if fb.info.source == FramebufferSource::VirtioGpu && !fb.use_double_buffer {
                flush_region = Some((x, y, width, height));
            }
        }

        if let Some((fx, fy, fw, fh)) = flush_region {
            if let Some(gpu) = gpu::get_gpu() {
                gpu.flush(fx, fy, fw, fh);
                gpu.flush_now();
            }
        }
    }

    /// Draw a horizontal line
    pub fn draw_hline(x: u32, y: u32, length: u32, r: u8, g: u8, b: u8) {
        Self::fill_rect(x, y, length, 1, r, g, b);
    }

    /// Draw a vertical line
    pub fn draw_vline(x: u32, y: u32, length: u32, r: u8, g: u8, b: u8) {
        Self::fill_rect(x, y, 1, length, r, g, b);
    }

    /// Clear screen to black
    pub fn clear() {
        let info = Self::info();
        if let Some(info) = info {
            Self::fill_rect(0, 0, info.width, info.height, 0, 0, 0);
        }
    }

    /// Swap buffers (for double buffering)
    pub fn swap_buffers() {
        let mut virtio_present = None;
        {
            let mut guard = FRAMEBUFFER.lock();
            let fb = match guard.as_mut() {
                Some(f) => f,
                None => return,
            };

            if !fb.use_double_buffer || fb.double_buffer.is_none() {
                return;
            }

            let db = fb.double_buffer.unwrap();
            let dirty = match fb.dirty.take() {
                Some(d) => d,
                None => return,
            };
            let (x, y, width, height) = dirty;
            if width == 0 || height == 0 {
                return;
            }

            if fb.info.source == FramebufferSource::VirtioGpu {
                virtio_present = Some((db as *const u8, fb.info.stride, x, y, width, height));
            } else {
                let dst = fb.info.base_virt as *mut u8;
                let row_bytes = width as usize * 4;
                let stride = fb.info.stride as usize;
                for row in 0..height as usize {
                    let row_y = y as usize + row;
                    let src_off = row_y * stride + x as usize * 4;
                    let dst_off = src_off;
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            db.add(src_off),
                            dst.add(dst_off),
                            row_bytes,
                        );
                    }
                }
            }
        }

        if let Some((src, src_stride, px, py, pw, ph)) = virtio_present {
            if let Some(gpu) = gpu::get_gpu() {
                let _ = gpu.present_from_linear(src, src_stride, px, py, pw, ph);
            }
        }
    }

    /// Enable/disable double buffering
    pub fn set_double_buffering(enable: bool) {
        let mut fb = FRAMEBUFFER.lock();
        if let Some(ref mut f) = fb.as_mut() {
            f.use_double_buffer = enable && f.double_buffer.is_some();
        }
    }
}

/// RGB color helper
#[derive(Clone, Copy)]
pub struct RgbColor {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl RgbColor {
    pub const BLACK: Self = Self { r: 0, g: 0, b: 0 };
    pub const WHITE: Self = Self {
        r: 255,
        g: 255,
        b: 255,
    };
    pub const RED: Self = Self { r: 255, g: 0, b: 0 };
    pub const GREEN: Self = Self { r: 0, g: 255, b: 0 };
    pub const BLUE: Self = Self { r: 0, g: 0, b: 255 };
    pub const CYAN: Self = Self {
        r: 0,
        g: 255,
        b: 255,
    };
    pub const MAGENTA: Self = Self {
        r: 255,
        g: 0,
        b: 255,
    };
    pub const YELLOW: Self = Self {
        r: 255,
        g: 255,
        b: 0,
    };
}

/// Initialize framebuffer subsystem
pub fn init() {
    log::info!("[FB] Initializing framebuffer subsystem...");

    // Try VirtIO GPU first (native driver)
    if gpu::is_available() {
        if let Err(e) = Framebuffer::init_virtio_gpu() {
            log::warn!("[FB] VirtIO GPU init failed: {}", e);
        } else {
            log::info!("[FB] Using VirtIO GPU framebuffer");
            return;
        }
    }

    // VirtIO GPU not available, Limine framebuffer is already set up in boot
    // The Limine framebuffer is initialized in boot/limine.rs
    if Framebuffer::is_available() {
        log::info!("[FB] Using Limine framebuffer");
    } else {
        log::warn!("[FB] No framebuffer available");
    }
}
