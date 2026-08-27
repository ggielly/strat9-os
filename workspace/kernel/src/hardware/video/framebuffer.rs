// Framebuffer abstraction layer
//
// Provides a unified framebuffer interface that can use:
// - UEFI bootloader framebuffer (bootloader-provided, WC-mapped via PAT)
// - VirtIO GPU framebuffer (native driver, zero-copy backing)
// - Future/TODO : other GPU drivers (Bochs DRM, etc.)
//
// Features:
// - Resolution switching
// - Double buffering
// - Basic 2D drawing primitives
// - Text rendering support
// - SIMD pixel ops with streaming stores above the L2-derived threshold

#![allow(dead_code)]

use crate::{
    framebuffer::{CanvasBuffer, DirtyRectSet, FramebufferOps, MAX_DIRTY_RECTS, PRESENT_MIN_TICKS},
    hardware::virtio::gpu,
    memory::{self, phys_to_virt},
};
use core::sync::atomic::{AtomicBool, Ordering};
use spin::{Mutex, Once};

/// Maximum supported resolution
const MAX_WIDTH: u32 = 3840;
const MAX_HEIGHT: u32 = 2160;

/// Framebuffer source
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FramebufferSource {
    Bootloader,
    VirtioGpu,
    AmdGpu,
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
    /// Total framebuffer size in bytes
    fb_size: usize,
    /// Whether console deferred present is active
    console_defer_present: bool,
    /// True when the VirtIO backing IS our double buffer (zero-copy present)
    zero_copy_backing: bool,
}

unsafe impl Send for Framebuffer {}
unsafe impl Sync for Framebuffer {}

static FRAMEBUFFER: Mutex<Option<Framebuffer>> = Mutex::new(None);
/// Lockless snapshot of the display geometry, published once at init.
///
/// Getters (`info`/`width`/`height`/`stride`/`source`) read this instead of
/// taking the framebuffer mutex, so hot paths and frequent queries never
/// contend with drawing (G4).
static FB_INFO: Once<FramebufferInfo> = Once::new();
static FRAMEBUFFER_INITIALIZED: AtomicBool = AtomicBool::new(false);

fn publish_info(info: FramebufferInfo) {
    FB_INFO.call_once(|| info);
}

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
                    let _ = unsafe {
                        gpu.present_from_linear(
                            self.info.base_virt as *const u8,
                            self.info.stride,
                            rect.x0,
                            rect.y0,
                            rect.x1.saturating_sub(rect.x0),
                            rect.y1.saturating_sub(rect.y0),
                        )
                    };
                }
                idx += 1;
            }
        }
        self.canvas.dirty.clear();
    }

    /// Initialize framebuffer with bootloader-provided buffer
    pub fn init_bootloader(
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
            source: FramebufferSource::Bootloader,
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
            track_dirty: true,
            present_pending: false,
            last_present_tick: 0,
            ops: FramebufferOps::detect(),
            present_row_buf: None,
        };

        let fb = Framebuffer {
            info,
            canvas,
            double_buffer: None,
            use_double_buffer: false,
            fb_size: (stride as usize) * (height as usize),
            console_defer_present: false,
            zero_copy_backing: false,
        };

        *FRAMEBUFFER.lock() = Some(fb);
        publish_info(info);
        FRAMEBUFFER_INITIALIZED.store(true, Ordering::SeqCst);

        log::info!(
            "[FB] Bootloader framebuffer: {}x{} @ {}bpp, stride={}",
            width,
            height,
            format.bits_per_pixel,
            stride
        );

        Ok(())
    }

    /// Initialize framebuffer with VirtIO GPU
    ///
    /// G3: the double buffer is allocated FIRST and attached as the scanout
    /// resource backing itself, so draws land directly in what
    /// TRANSFER_TO_HOST_2D reads — presentation becomes zero-copy.
    pub fn init_virtio_gpu() -> Result<(), &'static str> {
        let gpu = crate::hardware::virtio::gpu::get_gpu().ok_or("VirtIO GPU not initialized")?;
        let gpu_info = gpu.info();
        if gpu_info.width == 0 || gpu_info.height == 0 {
            return Err("Invalid VirtIO GPU dimensions");
        }

        let format = PixelFormat {
            red_mask: 0x00FF0000,
            red_shift: 16,
            green_mask: 0x0000FF00,
            green_shift: 8,
            blue_mask: 0x000000FF,
            blue_shift: 0,
            bits_per_pixel: 32,
        };

        // Allocate double buffer for VirtIO GPU (physically contiguous).
        let stride = gpu_info.stride;
        let db_size = (stride as usize) * (gpu_info.height as usize);
        if db_size == 0 {
            return Err("Invalid VirtIO framebuffer size");
        }
        let db_pages = (db_size + 4095) / 4096;
        let db_order = db_pages.next_power_of_two().trailing_zeros() as u8;
        let db_frame = crate::sync::with_irqs_disabled(|token| {
            memory::allocate_phys_contiguous(token, db_order)
        })
        .map_err(|_| "Failed to allocate double buffer")?;
        let db_phys = db_frame.start_address.as_u64();
        let db_virt = phys_to_virt(db_phys) as *mut u8;
        unsafe {
            // SAFETY: `db_virt` is a freshly allocated contiguous buffer of at
            // least `db_size` bytes.
            core::ptr::write_bytes(db_virt, 0, db_size);
        }

        // Attach the double buffer AS the resource backing (zero-copy path).
        // On failure we fall back to the legacy bounce-buffer behaviour.
        let zero_copy = match gpu.attach_external_backing(db_phys, db_size) {
            Ok(()) => {
                // Push the zeroed buffer to the scanout for a clean start.
                let _ = gpu.present_scanout_rect(0, 0, gpu_info.width, gpu_info.height);
                true
            }
            Err(e) => {
                log::warn!(
                    "[FB] external backing attach failed ({}): using bounce copy",
                    e
                );
                false
            }
        };

        let info = FramebufferInfo {
            base: db_phys,
            base_virt: db_virt as usize,
            width: gpu_info.width,
            height: gpu_info.height,
            stride: gpu_info.stride,
            format,
            source: FramebufferSource::VirtioGpu,
        };

        let canvas = CanvasBuffer {
            addr: db_virt,
            width: info.width as usize,
            height: info.height as usize,
            pitch: info.stride as usize,
            bpp: 32,
            back_buffer: None,
            draw_to_back: false,
            dirty: DirtyRectSet::empty(),
            track_dirty: true,
            present_pending: false,
            last_present_tick: 0,
            ops: FramebufferOps::detect(),
            present_row_buf: None,
        };

        let fb = Framebuffer {
            info,
            canvas,
            double_buffer: Some(db_virt),
            use_double_buffer: true,
            fb_size: (stride as usize) * (gpu_info.height as usize),
            console_defer_present: false,
            zero_copy_backing: zero_copy,
        };

        *FRAMEBUFFER.lock() = Some(fb);
        publish_info(info);
        FRAMEBUFFER_INITIALIZED.store(true, Ordering::SeqCst);

        log::info!(
            "[FB] VirtIO GPU framebuffer: {}x{} @ {}bpp, stride={} ({})",
            info.width,
            info.height,
            info.format.bits_per_pixel,
            info.stride,
            if zero_copy {
                "zero-copy backing"
            } else {
                "bounce copy"
            }
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

        let hhdm = crate::memory::hhdm_offset();
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

        let canvas = CanvasBuffer {
            addr: base_virt as *mut u8,
            width: width as usize,
            height: height as usize,
            pitch: pitch as usize,
            bpp: 32,
            back_buffer: None,
            draw_to_back: false,
            dirty: DirtyRectSet::empty(),
            track_dirty: true,
            present_pending: false,
            last_present_tick: 0,
            ops: FramebufferOps::detect(),
            present_row_buf: None,
        };

        *FRAMEBUFFER.lock() = Some(Framebuffer {
            info,
            canvas,
            double_buffer: None,
            use_double_buffer: false,
            fb_size: (pitch as usize) * (height as usize),
            console_defer_present: false,
            zero_copy_backing: false,
        });
        publish_info(info);

        log::info!(
            "[FB] AMDGPU framebuffer: {}x{} @ {}bpp, {} bytes",
            info.width,
            info.height,
            info.format.bits_per_pixel,
            info.stride
        );

        Ok(())
    }

    /// Get framebuffer info (lockless: reads the init-time snapshot)
    pub fn info() -> Option<FramebufferInfo> {
        FB_INFO.get().copied()
    }

    /// Get framebuffer width (lockless)
    pub fn width() -> u32 {
        FB_INFO.get().map(|i| i.width).unwrap_or(0)
    }

    /// Get framebuffer height (lockless)
    pub fn height() -> u32 {
        FB_INFO.get().map(|i| i.height).unwrap_or(0)
    }

    /// Get stride in bytes per row (lockless)
    pub fn stride() -> u32 {
        FB_INFO.get().map(|i| i.stride).unwrap_or(0)
    }

    /// Check if framebuffer is initialized
    pub fn is_available() -> bool {
        FRAMEBUFFER_INITIALIZED.load(Ordering::Relaxed)
    }

    /// Get framebuffer source (lockless)
    pub fn source() -> FramebufferSource {
        FB_INFO
            .get()
            .map(|i| i.source)
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
    /// Delegates to [`CanvasBuffer::write_pixel`] (S6: single implementation
    /// of target selection). Takes the framebuffer lock for a single pixel:
    /// fine for sparse dots, but batched drawing MUST go through
    /// [`Self::blit_rect`] instead.
    pub fn set_pixel(x: u32, y: u32, r: u8, g: u8, b: u8) {
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

        fb.canvas.write_pixel(x as usize, y as usize, pixel);
        fb.canvas.dirty.include(x, y, 1, 1);
        fb.request_present();
    }

    /// Fill rectangle with color.
    ///
    /// Delegates to [`CanvasBuffer::fill_rect`] (S6: one implementation of
    /// clipping, SIMD dispatch, target selection and dirty marking). Takes
    /// the framebuffer lock once for the whole rectangle. Does NOT present;
    /// call `swap_buffers()` after a batch of draw operations.
    pub fn fill_rect(x: u32, y: u32, width: u32, height: u32, r: u8, g: u8, b: u8) {
        if width == 0 || height == 0 {
            return;
        }

        let mut guard = FRAMEBUFFER.lock();
        let fb = match guard.as_mut() {
            Some(f) => f,
            None => return,
        };

        if x >= fb.info.width || y >= fb.info.height {
            return;
        }

        let width = width.min(fb.info.width - x);
        let height = height.min(fb.info.height - y);
        if width == 0 || height == 0 {
            return;
        }

        let pixel = ((r as u32) << fb.info.format.red_shift)
            | ((g as u32) << fb.info.format.green_shift)
            | ((b as u32) << fb.info.format.blue_shift);

        fb.canvas.fill_rect(
            x as usize,
            y as usize,
            width as usize,
            height as usize,
            pixel,
        );
        fb.request_present();
    }

    /// Blit a packed 32bpp XRGB rectangle into the current draw target
    /// (double buffer when enabled, else the hardware framebuffer).
    ///
    /// This is the batch primitive: the framebuffer lock is taken exactly
    /// once and a single dirty rectangle is marked, whatever the size.
    /// `src` holds `h` rows of `w` pixels with a tight row stride of `w*4`
    /// bytes; the rect is clipped against screen bounds.
    pub fn blit_rect(src: &[u8], x: u32, y: u32, w: u32, h: u32) {
        if w == 0 || h == 0 || x >= Self::width() || y >= Self::height() {
            return;
        }
        let needed = w as usize * h as usize * 4;
        if src.len() < needed {
            return;
        }

        let mut guard = FRAMEBUFFER.lock();
        let fb = match guard.as_mut() {
            Some(f) => f,
            None => return,
        };

        let max_w = fb.info.width - x;
        let max_h = fb.info.height - y;
        let w = w.min(max_w);
        let h = h.min(max_h);
        if w == 0 || h == 0 {
            return;
        }

        let offset = if fb.use_double_buffer {
            fb.double_buffer.unwrap_or(fb.info.base_virt as *mut u8)
        } else {
            fb.info.base_virt as *mut u8
        };

        let stride = fb.info.stride as usize;
        let stride_pixels = stride / 4;
        let src_row_bytes = w as usize * 4;
        let full_width_contiguous =
            x == 0 && w as usize == fb.info.width as usize && stride_pixels == w as usize;

        unsafe {
            if full_width_contiguous {
                let dst = offset.add(y as usize * stride) as *mut u32;
                let s = src.as_ptr() as *const u32;
                (fb.canvas.ops.blit)(dst, s, w as usize * h as usize);
            } else {
                for dy in 0..h as usize {
                    let dst = offset.add((y as usize + dy) * stride + x as usize * 4) as *mut u32;
                    let s = src.as_ptr().add(dy * src_row_bytes) as *const u32;
                    (fb.canvas.ops.blit)(dst, s, w as usize);
                }
            }
        }

        fb.canvas.dirty.include(x, y, w, h);
        fb.request_present();
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
        enum VirtioPresent {
            ZeroCopy {
                x: u32,
                y: u32,
                w: u32,
                h: u32,
            },
            BounceCopy {
                src: *const u8,
                stride: u32,
                regions: [(u32, u32, u32, u32); MAX_DIRTY_RECTS],
                count: usize,
            },
        }

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
                // G3: coalesce dirty rects into their bounding box, then
                // present. With an attached external backing this is a
                // single TRANSFER+FLUSH pair straight from our draw target
                // (zero copy); otherwise fall back to the bounce-copy path
                // per rect.
                let mut bx0 = u32::MAX;
                let mut by0 = u32::MAX;
                let mut bx1 = 0u32;
                let mut by1 = 0u32;
                let mut idx = 0;
                while idx < fb.canvas.dirty.len {
                    let rect = fb.canvas.dirty.rects[idx];
                    if rect.is_valid() {
                        bx0 = bx0.min(rect.x0);
                        by0 = by0.min(rect.y0);
                        bx1 = bx1.max(rect.x1);
                        by1 = by1.max(rect.y1);
                    }
                    idx += 1;
                }

                virtio_present = if fb.zero_copy_backing && bx1 > bx0 && by1 > by0 {
                    Some(VirtioPresent::ZeroCopy {
                        x: bx0,
                        y: by0,
                        w: bx1 - bx0,
                        h: by1 - by0,
                    })
                } else {
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
                    Some(VirtioPresent::BounceCopy {
                        src: db as *const u8,
                        stride: fb.info.stride,
                        regions,
                        count: fb.canvas.dirty.len,
                    })
                };
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

        match virtio_present {
            Some(VirtioPresent::ZeroCopy { x, y, w, h }) => {
                if let Some(gpu) = gpu::get_gpu() {
                    let _ = gpu.present_scanout_rect(x, y, w, h);
                }
            }
            Some(VirtioPresent::BounceCopy {
                src,
                stride,
                regions,
                count: region_count,
            }) => {
                if let Some(gpu) = gpu::get_gpu() {
                    let mut idx = 0;
                    while idx < region_count {
                        let (px, py, pw, ph) = regions[idx];
                        let _ = unsafe { gpu.present_from_linear(src, stride, px, py, pw, ph) };
                        idx += 1;
                    }
                }
            }
            None => {}
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

    // VirtIO GPU and AMDGPU not available, UEFI bootloader framebuffer is already set up in boot
    if Framebuffer::is_available() {
        log::info!("[FB] Using UEFI bootloader framebuffer");
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
