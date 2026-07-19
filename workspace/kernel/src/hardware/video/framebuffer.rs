// Note : _mm512_stream_si512 (NT store) is not available for x86_64-unknown-none;
// Framebuffer abstraction layer
//
// Provides a unified framebuffer interface that can use:
// - Limine framebuffer (bootloader-provided)
// - VirtIO GPU framebuffer (native driver)
// - Future/TODO : other GPU drivers (Bochs DRM, etc.)
//
// Features:
// - Resolution switching
// - Double buffering
// - Basic 2D drawing primitives
// - Text rendering support

#![allow(dead_code)]

use crate::{
    framebuffer::{CanvasBuffer, DirtyRectSet, FramebufferOps, MAX_DIRTY_RECTS},
    hardware::virtio::gpu,
    memory::{self, phys_to_virt},
};
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

/// Maximum supported resolution
const MAX_WIDTH: u32 = 3840;
const MAX_HEIGHT: u32 = 2160;
const PRESENT_MIN_TICKS: u64 = 1;

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
    /// Builds a default instance.
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

#[derive(Clone, Copy, Debug)]
pub struct FramebufferRenderStats {
    pub present_pending: bool,
    pub dirty_region_count: usize,
    pub last_present_tick: u64,
}

unsafe impl Send for FramebufferInfo {}
unsafe impl Sync for FramebufferInfo {}

/// Main framebuffer structure
pub struct Framebuffer {
    info: FramebufferInfo,
    /// Shared double-buffered canvas (dirty tracking, present throttling, SIMD ops)
    pub canvas: CanvasBuffer,
    /// Raw double buffer for VirtIO GPU (physically contiguous)
    double_buffer: Option<*mut u8>,
    /// Whether the raw double buffer should be used
    use_double_buffer: bool,
}

unsafe impl Send for Framebuffer {}
unsafe impl Sync for Framebuffer {}

static FRAMEBUFFER: Mutex<Option<Framebuffer>> = Mutex::new(None);
static FRAMEBUFFER_INITIALIZED: AtomicBool = AtomicBool::new(false);

impl Framebuffer {
    fn request_present(&mut self) {
        self.canvas.present_pending = true;
    }

    fn present_if_due(&mut self, force: bool) {
        if !self.canvas.present_pending {
            return;
        }
        if self.use_double_buffer {
            return;
        }
        let now = crate::process::scheduler::ticks();
        if force || now.saturating_sub(self.canvas.last_present_tick) >= PRESENT_MIN_TICKS {
            self.canvas.present_pending = false;
            self.canvas.last_present_tick = now;
        } else {
            return;
        }

        if self.info.source != FramebufferSource::VirtioGpu {
            self.canvas.dirty.clear();
            return;
        }

        if let Some(gpu) = gpu::get_gpu() {
            let mut idx = 0;
            while idx < self.canvas.dirty.len {
                let rect = self.canvas.dirty.rects[idx];
                if rect.is_valid() {
                    let _ = gpu.present_from_linear(
                        self.info.base_virt as *const u8,
                        self.info.stride,
                        rect.x0,
                        rect.y0,
                        rect.x1.saturating_sub(rect.x0),
                        rect.y1.saturating_sub(rect.y0),
                    );
                }
                idx += 1;
            }
        }
        self.canvas.dirty.clear();
    }

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

        let canvas = CanvasBuffer {
            addr: base_virt as *mut u8,
            width: width as usize,
            height: height as usize,
            pitch: stride as usize,
            bpp: format.bits_per_pixel as u16,
            back_buffer: None,
            draw_to_back: false,
            dirty: DirtyRectSet::empty(),
            track_dirty: false,
            present_pending: false,
            last_present_tick: 0,
            ops: FramebufferOps::detect(),
        };

        let fb = Framebuffer {
            info,
            canvas,
            double_buffer: None,
            use_double_buffer: false,
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
        let db_frame = crate::sync::with_irqs_disabled(|token| {
            memory::allocate_phys_contiguous(token, db_order)
        })
        .map_err(|_| "Failed to allocate double buffer")?;
        let db_virt = phys_to_virt(db_frame.start_address.as_u64()) as *mut u8;
        unsafe {
            // SAFETY: `db_virt` is a freshly allocated contiguous buffer of at
            // least `db_size` bytes.
            core::ptr::write_bytes(db_virt, 0, db_size);
        }

        let canvas = CanvasBuffer {
            addr: info.base_virt as *mut u8,
            width: info.width as usize,
            height: info.height as usize,
            pitch: info.stride as usize,
            bpp: 32,
            back_buffer: None,
            draw_to_back: false,
            dirty: DirtyRectSet::empty(),
            track_dirty: false,
            present_pending: false,
            last_present_tick: 0,
            ops: FramebufferOps::detect(),
        };

        let fb = Framebuffer {
            info,
            canvas,
            double_buffer: Some(db_virt),
            use_double_buffer: true,
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

    /// Initialize framebuffer with AMDGPU
    pub fn init_amd_gpu() -> Result<(), &'static str> {
        let gpu_guard = crate::hardware::amdgpu::get_gpu().ok_or("AMDGPU not available")?;
        let gpu = gpu_guard.as_ref().ok_or("AMDGPU not initialized")?;

        let (phys, width, height, pitch) = gpu.framebuffer_info();

        let format = PixelFormat {
            red_mask: 0x00FF0000,
            red_shift: 16,
            green_mask: 0x0000FF00,
            green_shift: 8,
            blue_mask: 0x000000FF,
            blue_shift: 0,
            bits_per_pixel: 32,
        };

        let hhdm = crate::memory::get_hhdm_offset();
        let base_virt = (phys as u64 + hhdm) as usize;

        let info = FramebufferInfo {
            base: phys as u64,
            base_virt,
            width,
            height,
            stride: pitch,
            format,
            source: FramebufferSource::AmdGpu,
        };

        let fb_size = (pitch as usize) * (height as usize);

        *FRAMEBUFFER.lock() = Some(Framebuffer {
            info,
            back_buffer: None,
            double_buffer: None,
            use_double_buffer: false,
            present_pending: false,
            last_present_tick: 0,
            dirty: Default::default(),
            draw_to_back: false,
            track_dirty: false,
            console_defer_present: false,
            fb_size,
        });

        log::info!(
            "[FB] AMDGPU framebuffer: {}x{} @ {}bpp, {} bytes",
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

    pub fn render_stats() -> Option<FramebufferRenderStats> {
        FRAMEBUFFER
            .lock()
            .as_ref()
            .map(|fb| FramebufferRenderStats {
                present_pending: fb.canvas.present_pending,
                dirty_region_count: fb.canvas.dirty.len,
                last_present_tick: fb.canvas.last_present_tick,
            })
    }

    /// Set a pixel at (x, y) with RGB color.
    ///
    /// Does NOT present to screen. Call `swap_buffers()` or `present()`
    /// after a batch of draw operations.
    pub fn set_pixel(x: u32, y: u32, r: u8, g: u8, b: u8) {
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

            fb.canvas.dirty.include(x, y, 1, 1);
            fb.request_present();
        }
    }

    /// Fill rectangle with color.
    ///
    /// Does NOT present to screen. Call `swap_buffers()` or `present()`
    /// after a batch of draw operations.
    pub fn fill_rect(x: u32, y: u32, width: u32, height: u32, r: u8, g: u8, b: u8) {
        if width == 0 || height == 0 {
            return;
        }

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
            let stride_pixels = fb.info.stride as usize / 4;
            let width_pixels = width as usize;
            if stride_pixels == width_pixels {
                let first = unsafe { offset.add(y as usize * stride + x as usize * 4) as *mut u32 };
                unsafe {
                    (fb.canvas.ops.fill)(first, pixel, width_pixels * height as usize);
                }
            } else {
                for dy in 0..height as usize {
                    let row_ptr = unsafe {
                        offset.add((y as usize + dy) * stride + x as usize * 4) as *mut u32
                    };
                    unsafe {
                        (fb.canvas.ops.fill)(row_ptr, pixel, width_pixels);
                    }
                }
            }

            fb.canvas.dirty.include(x, y, width, height);
            fb.request_present();
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
            if fb.canvas.dirty.len == 0 {
                return;
            }

            if fb.info.source == FramebufferSource::VirtioGpu {
                let mut regions = [(0u32, 0u32, 0u32, 0u32); MAX_DIRTY_RECTS];
                let mut idx = 0;
                while idx < fb.canvas.dirty.len {
                    let rect = fb.canvas.dirty.rects[idx];
                    regions[idx] = (
                        rect.x0,
                        rect.y0,
                        rect.x1.saturating_sub(rect.x0),
                        rect.y1.saturating_sub(rect.y0),
                    );
                    idx += 1;
                }
                virtio_present = Some((
                    db as *const u8,
                    fb.info.stride,
                    regions,
                    fb.canvas.dirty.len,
                ));
            } else {
                let dst = fb.info.base_virt as *mut u32;
                let src_base = db as *const u32;
                let stride_pixels = (fb.info.stride / 4) as usize;
                let mut idx = 0;
                while idx < fb.canvas.dirty.len {
                    let rect = fb.canvas.dirty.rects[idx];
                    let x = rect.x0 as usize;
                    let y = rect.y0 as usize;
                    let width = rect.x1.saturating_sub(rect.x0) as usize;
                    let height = rect.y1.saturating_sub(rect.y0) as usize;
                    // Blit groupé : si stride == width, tout est contigu, un seul appel
                    if stride_pixels == width {
                        let off = y * stride_pixels + x;
                        unsafe {
                            (fb.canvas.ops.blit)(dst.add(off), src_base.add(off), width * height);
                        }
                    } else {
                        for row in 0..height {
                            let row_off = (y + row) * stride_pixels + x;
                            unsafe {
                                (fb.canvas.ops.blit)(
                                    dst.add(row_off),
                                    src_base.add(row_off),
                                    width,
                                );
                            }
                        }
                    }
                    idx += 1;
                }
            }
            fb.canvas.dirty.clear();
            fb.canvas.present_pending = false;
            fb.canvas.last_present_tick = crate::process::scheduler::ticks();
        }

        if let Some((src, src_stride, regions, region_count)) = virtio_present {
            if let Some(gpu) = gpu::get_gpu() {
                let mut idx = 0;
                while idx < region_count {
                    let (px, py, pw, ph) = regions[idx];
                    let _ = gpu.present_from_linear(src, src_stride, px, py, pw, ph);
                    idx += 1;
                }
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

pub use crate::framebuffer::RgbColor;

/// Initialize framebuffer subsystem
pub fn init() {
    log::info!("[FB] Initializing framebuffer subsystem...");

    // Try VirtIO GPU first (native driver)
    if gpu::is_available() {
        if let Err(e) = Framebuffer::init_virtio_gpu() {
            log::warn!("[FB] VirtIO GPU init failed: {}", e);
        } else {
            log::info!("[FB] Using VirtIO GPU framebuffer");
        }
    }

    // Try AMDGPU (real hardware)
    if !Framebuffer::is_available() && crate::hardware::amdgpu::is_available() {
        if let Err(e) = Framebuffer::init_amd_gpu() {
            log::warn!("[FB] AMDGPU init failed: {}", e);
        } else {
            log::info!("[FB] Using AMDGPU framebuffer");
        }
    }

    // VirtIO GPU and AMDGPU not available, Limine framebuffer is already set up in boot
    if Framebuffer::is_available() {
        log::info!("[FB] Using Limine framebuffer");
    } else {
        log::warn!("[FB] No framebuffer available");
    }

    // Register /dev/display/ scheme
    if Framebuffer::is_available() {
        if let Err(e) = super::display_scheme::register_display_scheme() {
            log::warn!("[FB] Failed to register display scheme: {:?}", e);
        }
    }
}
