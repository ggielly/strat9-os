// Framebuffer abstraction layer
//
// Provides a unified framebuffer interface that can use:
// - UEFI bootloader framebuffer (firmware-provided, mapped write-combining)
// - VirtIO GPU framebuffer (native driver, zero-copy backing)
// - AMDGPU framebuffer (native driver, contiguous RAM buffer)
//
// Design rules:
// - One install path (`install`) publishes the lockless geometry snapshot,
//   sets the availability flag, and releases the buffers of the previous
//   source. Adding a new source cannot forget one of the three.
// - Geometry is published through a seqlock so a re-init (driver upgrade,
//   resolution change) cannot leave `width()`/`info()` stale.
// - Draw target selection lives in `CanvasBuffer` (S6), including the
//   optional cached back-buffer used when the scanout memory is uncached.
// - Presentation runs under the framebuffer lock: a concurrent draw must
//   never mutate the buffer the GPU is reading, and a re-init must never
//   free a buffer that is still being presented.
#![allow(dead_code)]

use crate::{
    framebuffer::{CanvasBuffer, DirtyRectSet, FramebufferOps, PRESENT_MIN_TICKS},
    hardware::virtio::gpu,
    memory::{self, phys_to_virt, PhysFrame},
};
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use spin::Mutex;

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

impl PixelFormat {
    const fn zero() -> Self {
        Self {
            red_mask: 0,
            red_shift: 0,
            green_mask: 0,
            green_shift: 0,
            blue_mask: 0,
            blue_shift: 0,
            bits_per_pixel: 0,
        }
    }

    /// True for the common XRGB layout used by UEFI GOP on x86:
    /// red in bits 16..23, green 8..15, blue 0..7 (little-endian bytes
    /// B,G,R,X). This is the layout the SIMD `convert_bgr_to_argb` produces.
    pub fn is_xrgb8888(&self) -> bool {
        self.bits_per_pixel == 32
            && self.red_shift == 16
            && self.green_shift == 8
            && self.blue_shift == 0
    }

    /// Pack an RGB888 triple (wire format) into this framebuffer's native
    /// 32-bit pixel layout. The unused/alpha byte is set opaque.
    pub fn pack_rgb(&self, r: u8, g: u8, b: u8) -> u32 {
        let mut v = ((r as u32) << self.red_shift)
            | ((g as u32) << self.green_shift)
            | ((b as u32) << self.blue_shift);
        if self.bits_per_pixel == 32 {
            v |= 0xFF00_0000;
        }
        v
    }

    /// Whether the draw paths can render this format without conversion.
    ///
    /// `blit_rect` consumes packed XRGB8888, and the pixel/fill paths use the
    /// shifts directly, so only 32/24 bpp with the canonical R-G-B order is
    /// accepted. Anything else is rejected at init instead of being displayed
    /// with swapped channels.
    pub fn is_supported(&self) -> bool {
        matches!(
            (
                self.bits_per_pixel,
                self.red_shift,
                self.green_shift,
                self.blue_shift
            ),
            (32, 16, 8, 0) | (24, 16, 8, 0)
        )
    }
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

impl FramebufferInfo {
    const fn zero() -> Self {
        Self {
            base: 0,
            base_virt: 0,
            width: 0,
            height: 0,
            stride: 0,
            format: PixelFormat::zero(),
            source: FramebufferSource::None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FramebufferRenderStats {
    pub present_pending: bool,
    pub dirty_region_count: usize,
    pub last_present_tick: u64,
}

unsafe impl Send for FramebufferInfo {}
unsafe impl Sync for FramebufferInfo {}

/// A physically contiguous buffer owned by the framebuffer subsystem.
struct OwnedBuffer {
    virt: *mut u8,
    frame: PhysFrame,
    order: u8,
}

/// Main framebuffer structure
pub struct Framebuffer {
    info: FramebufferInfo,
    /// Shared canvas: dirty tracking, present throttling, SIMD ops, and the
    /// single implementation of draw-target selection.
    pub canvas: CanvasBuffer,
    /// Scanout buffer owned by the framebuffer (VirtIO GPU only). `None` means
    /// the hardware framebuffer belongs to firmware or another driver.
    double_buffer: Option<OwnedBuffer>,
    /// Whether draws target `double_buffer`.
    use_double_buffer: bool,
    /// True when the VirtIO backing IS our double buffer (zero-copy present)
    zero_copy_backing: bool,
}

unsafe impl Send for Framebuffer {}
unsafe impl Sync for Framebuffer {}

static FRAMEBUFFER: Mutex<Option<Framebuffer>> = Mutex::new(None);
static FRAMEBUFFER_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Firmware framebuffer described during early boot.
///
/// Kept separately from [`FRAMEBUFFER`] because early boot runs before the
/// global allocator exists (the uncached fallback path may allocate a cached
/// back-buffer), and because a native driver must be allowed to take over
/// before the firmware buffer is published.
#[derive(Clone, Copy)]
struct BootFramebuffer {
    addr_virt: usize,
    width: u32,
    height: u32,
    stride: u32,
    format: PixelFormat,
}
static BOOT_FRAMEBUFFER: Mutex<Option<BootFramebuffer>> = Mutex::new(None);

// ---------------------------------------------------------------------------
// Lockless geometry snapshot (seqlock)
// ---------------------------------------------------------------------------

struct InfoCell(UnsafeCell<FramebufferInfo>);
// SAFETY: all accesses go through `publish_info`/`read_info`, which implement
// the seqlock protocol (odd sequence = write in progress).
unsafe impl Sync for InfoCell {}

static FB_INFO: InfoCell = InfoCell(UnsafeCell::new(FramebufferInfo::zero()));
static FB_INFO_SEQ: AtomicU64 = AtomicU64::new(0);

/// Publish a new geometry snapshot.
///
/// The sequence counter makes the update replaceable: readers retry while a
/// write is in progress, so a driver upgrade or a future `set_mode` cannot
/// leave the lockless getters pointing at the previous source.
fn publish_info(info: FramebufferInfo) {
    let seq = FB_INFO_SEQ.load(Ordering::Relaxed);
    FB_INFO_SEQ.store(seq.wrapping_add(1), Ordering::Release);
    // SAFETY: exclusive writer by protocol (single writer under the FRAMEBUFFER
    // lock); readers only copy while the sequence is even and stable.
    unsafe { FB_INFO.0.get().write(info) };
    FB_INFO_SEQ.store(seq.wrapping_add(2), Ordering::Release);
}

fn read_info() -> Option<FramebufferInfo> {
    if !FRAMEBUFFER_INITIALIZED.load(Ordering::Acquire) {
        return None;
    }
    loop {
        let first = FB_INFO_SEQ.load(Ordering::Acquire);
        if first & 1 != 0 {
            core::hint::spin_loop();
            continue;
        }
        // SAFETY: the sequence is even, so no writer is active. A writer that
        // starts now bumps the sequence to odd and the comparison below fails.
        let info = unsafe { FB_INFO.0.get().read() };
        core::sync::atomic::fence(Ordering::Acquire);
        if FB_INFO_SEQ.load(Ordering::Acquire) == first {
            return Some(info);
        }
    }
}

/// Install a new framebuffer source atomically.
///
/// Every `init_*` goes through this helper so the availability flag, the
/// snapshot and the release of the previous source can never diverge.
fn install(fb: Framebuffer, info: FramebufferInfo) {
    let previous = {
        let mut guard = FRAMEBUFFER.lock();
        let previous = guard.replace(fb);
        publish_info(info);
        FRAMEBUFFER_INITIALIZED.store(true, Ordering::Release);
        previous
    };
    // Drop the lock before returning buffers to the allocator: the old
    // framebuffer is already unreachable, and rendering holds the lock for
    // the whole present, so no in-flight I/O can still reference it.
    if let Some(previous) = previous {
        previous.release_owned_buffers();
    }
}

fn validate_boot_geometry(
    addr_virt: usize,
    width: u32,
    height: u32,
    stride: u32,
    format: &PixelFormat,
) -> Result<(), &'static str> {
    if addr_virt == 0 || width == 0 || height == 0 || stride == 0 {
        return Err("Invalid framebuffer parameters");
    }
    if width > MAX_WIDTH || height > MAX_HEIGHT {
        return Err("Framebuffer resolution exceeds MAX_WIDTH/MAX_HEIGHT");
    }
    if !format.is_supported() {
        return Err("Unsupported pixel format (expected 32/24 bpp R-G-B)");
    }
    Ok(())
}

/// Record the firmware framebuffer without publishing it yet.
///
/// Called from early boot (before the allocator exists). [`init`] installs it
/// as the fallback source if no native driver takes over.
pub fn register_boot_framebuffer(
    addr_virt: usize,
    width: u32,
    height: u32,
    stride: u32,
    format: PixelFormat,
) -> Result<(), &'static str> {
    validate_boot_geometry(addr_virt, width, height, stride, &format)?;
    *BOOT_FRAMEBUFFER.lock() = Some(BootFramebuffer {
        addr_virt,
        width,
        height,
        stride,
        format,
    });
    Ok(())
}

impl Framebuffer {
    fn request_present(&mut self) {
        self.canvas.present_pending = true;
    }

    /// Present the pending dirty regions. Called with the framebuffer lock
    /// already held.
    fn present_locked(&mut self) {
        let dirty_empty = self.canvas.dirty.len == 0;
        if dirty_empty {
            self.canvas.present_pending = false;
            return;
        }

        if self.info.source == FramebufferSource::VirtioGpu {
            if let Some(db) = self.double_buffer.as_ref() {
                if self.zero_copy_backing {
                    // Coalesce the dirty rects into their bounding box, then
                    // present straight from the attached backing.
                    let mut bx0 = u32::MAX;
                    let mut by0 = u32::MAX;
                    let mut bx1 = 0u32;
                    let mut by1 = 0u32;
                    let mut idx = 0;
                    while idx < self.canvas.dirty.len {
                        let rect = self.canvas.dirty.rects[idx];
                        if rect.is_valid() {
                            bx0 = bx0.min(rect.x0);
                            by0 = by0.min(rect.y0);
                            bx1 = bx1.max(rect.x1);
                            by1 = by1.max(rect.y1);
                        }
                        idx += 1;
                    }
                    if bx1 > bx0 && by1 > by0 {
                        if let Some(gpu) = gpu::get_gpu() {
                            let _ = gpu.present_scanout_rect(bx0, by0, bx1 - bx0, by1 - by0);
                        }
                    }
                } else if let Some(gpu) = gpu::get_gpu() {
                    // Bounce path: the GPU copies from our buffer while we
                    // hold the lock, so no other core can draw into it.
                    let mut idx = 0;
                    while idx < self.canvas.dirty.len {
                        let rect = self.canvas.dirty.rects[idx];
                        if rect.is_valid() {
                            let _ = unsafe {
                                gpu.present_from_linear(
                                    db.virt,
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
            }
        } else if self.canvas.draw_to_back {
            // Uncached scanout without PAT/WC support: draws land in the
            // cached canvas and are flushed here.
            self.canvas.present();
        }

        self.canvas.dirty.clear();
        self.canvas.present_pending = false;
        self.canvas.last_present_tick = crate::process::scheduler::ticks();
    }

    fn present_if_due(&mut self, force: bool) {
        if !self.canvas.present_pending {
            return;
        }
        let now = crate::process::scheduler::ticks();
        if force || now.saturating_sub(self.canvas.last_present_tick) >= PRESENT_MIN_TICKS {
            self.present_locked();
        }
    }

    /// Returns the buffers owned by this instance to the allocator.
    fn release_owned_buffers(&self) {
        if let Some(db) = self.double_buffer.as_ref() {
            crate::sync::with_irqs_disabled(|token| {
                memory::free_phys_contiguous(token, db.frame, db.order);
            });
        }
    }

    /// Initialize framebuffer with the bootloader-provided buffer.
    ///
    /// `addr_virt` must be the virtual address of the framebuffer (the HHDM
    /// alias or the bootloader's dedicated UC/WC alias), not the physical
    /// address.
    pub fn init_bootloader(
        addr_virt: usize,
        width: u32,
        height: u32,
        stride: u32,
        format: PixelFormat,
    ) -> Result<(), &'static str> {
        validate_boot_geometry(addr_virt, width, height, stride, &format)?;

        let info = FramebufferInfo {
            base: 0,
            base_virt: addr_virt,
            width,
            height,
            stride,
            format,
            source: FramebufferSource::Bootloader,
        };

        // The kernel maps the firmware framebuffer write-combining when PAT
        // allows it. If it does not, draw into a cached back-buffer and copy
        // dirty rects during `swap_buffers` instead of doing every pixel write
        // on uncached memory.
        let wc = crate::memory::paging::framebuffer_wc_supported();
        let mut canvas = CanvasBuffer {
            addr: addr_virt as *mut u8,
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
            wc,
            present_row_buf: None,
        };
        if !wc {
            canvas.enable_back_buffer();
        }
        let use_double_buffer = canvas.draw_to_back;

        let fb = Framebuffer {
            info,
            canvas,
            double_buffer: None,
            use_double_buffer,
            zero_copy_backing: false,
        };

        install(fb, info);

        log::info!(
            "[FB] Bootloader framebuffer: {}x{} @ {}bpp, stride={}, {}",
            width,
            height,
            format.bits_per_pixel,
            stride,
            if wc {
                "write-combining"
            } else {
                "uncached + back-buffer"
            }
        );

        Ok(())
    }

    /// Initialize framebuffer with VirtIO GPU
    ///
    /// G3: the double buffer is allocated FIRST and attached as the scanout
    /// resource backing itself, so draws land directly in what
    /// TRANSFER_TO_HOST_2D reads : presentation becomes zero-copy.
    pub fn init_virtio_gpu() -> Result<(), &'static str> {
        let gpu = crate::hardware::virtio::gpu::get_gpu().ok_or("VirtIO GPU not initialized")?;
        let gpu_info = gpu.info();
        if gpu_info.width == 0 || gpu_info.height == 0 {
            return Err("Invalid VirtIO GPU dimensions");
        }
        if gpu_info.width > MAX_WIDTH || gpu_info.height > MAX_HEIGHT {
            return Err("VirtIO GPU resolution exceeds MAX_WIDTH/MAX_HEIGHT");
        }

        let format = PixelFormat::default();

        // Allocate double buffer for VirtIO GPU (physically contiguous).
        let stride = gpu_info.stride;
        let db_size = (stride as usize) * (gpu_info.height as usize);
        if db_size == 0 {
            return Err("Invalid VirtIO framebuffer size");
        }
        let db_pages = db_size.div_ceil(4096);
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
            // Scanout memory is cached RAM here: streaming stores would only
            // hurt subsequent reads.
            wc: false,
            present_row_buf: None,
        };

        let fb = Framebuffer {
            info,
            canvas,
            double_buffer: Some(OwnedBuffer {
                virt: db_virt,
                frame: db_frame,
                order: db_order,
            }),
            use_double_buffer: true,
            zero_copy_backing: zero_copy,
        };

        install(fb, info);

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
        let (phys, width, height, pitch, base_virt) = {
            let gpu_guard = crate::hardware::amdgpu::get_gpu().ok_or("AMDGPU not available")?;
            let gpu = gpu_guard.as_ref().ok_or("AMDGPU not initialized")?;
            let (phys, width, height, pitch) = gpu.framebuffer_info();
            (phys, width, height, pitch, gpu.fb_virt())
        };

        if width == 0 || height == 0 || pitch == 0 {
            return Err("Invalid AMDGPU framebuffer geometry");
        }
        if width > MAX_WIDTH || height > MAX_HEIGHT {
            return Err("AMDGPU resolution exceeds MAX_WIDTH/MAX_HEIGHT");
        }

        let format = PixelFormat::default();

        let info = FramebufferInfo {
            base: phys,
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
            // The driver allocates the scanout from coherent RAM, mapped
            // write-back through the HHDM.
            wc: false,
            present_row_buf: None,
        };

        let fb = Framebuffer {
            info,
            canvas,
            double_buffer: None,
            use_double_buffer: false,
            zero_copy_backing: false,
        };

        install(fb, info);

        log::info!(
            "[FB] AMDGPU framebuffer: {}x{} @ {}bpp, stride={} bytes",
            info.width,
            info.height,
            info.format.bits_per_pixel,
            info.stride
        );

        Ok(())
    }

    /// Get framebuffer info (lockless: reads the seqlock snapshot)
    pub fn info() -> Option<FramebufferInfo> {
        read_info()
    }

    /// Get framebuffer width (lockless)
    pub fn width() -> u32 {
        read_info().map(|i| i.width).unwrap_or(0)
    }

    /// Get framebuffer height (lockless)
    pub fn height() -> u32 {
        read_info().map(|i| i.height).unwrap_or(0)
    }

    /// Get stride in bytes per row (lockless)
    pub fn stride() -> u32 {
        read_info().map(|i| i.stride).unwrap_or(0)
    }

    /// Check if framebuffer is initialized
    pub fn is_available() -> bool {
        FRAMEBUFFER_INITIALIZED.load(Ordering::Acquire)
    }

    /// Get framebuffer source (lockless)
    pub fn source() -> FramebufferSource {
        read_info()
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

    /// Set a pixel. Prefer [`Self::blit_rect`] for batches: this takes the
    /// framebuffer lock once per pixel.
    ///
    /// Returns `false` when the pixel is out of bounds or the framebuffer is
    /// unavailable.
    pub fn set_pixel(x: u32, y: u32, r: u8, g: u8, b: u8) -> bool {
        let mut guard = FRAMEBUFFER.lock();
        match guard.as_mut() {
            Some(fb) => fb.set_pixel_impl(x, y, r, g, b),
            None => false,
        }
    }

    /// Lock-free variant of [`Self::set_pixel`] for panic/IRQ paths.
    pub fn try_set_pixel(x: u32, y: u32, r: u8, g: u8, b: u8) -> bool {
        let Some(mut guard) = FRAMEBUFFER.try_lock() else {
            return false;
        };
        match guard.as_mut() {
            Some(fb) => fb.set_pixel_impl(x, y, r, g, b),
            None => false,
        }
    }

    fn set_pixel_impl(&mut self, x: u32, y: u32, r: u8, g: u8, b: u8) -> bool {
        if x >= self.info.width || y >= self.info.height {
            return false;
        }
        let pixel = ((r as u32) << self.info.format.red_shift)
            | ((g as u32) << self.info.format.green_shift)
            | ((b as u32) << self.info.format.blue_shift);
        self.canvas.write_pixel(x as usize, y as usize, pixel);
        self.canvas.dirty.include(x, y, 1, 1);
        self.request_present();
        true
    }

    /// Fill rectangle with color.
    ///
    /// Delegates to [`CanvasBuffer::fill_rect`] (S6: one implementation of
    /// clipping, SIMD dispatch, target selection and dirty marking). Takes
    /// the framebuffer lock once for the whole rectangle. Does NOT present;
    /// call `swap_buffers()` after a batch of draw operations.
    pub fn fill_rect(x: u32, y: u32, width: u32, height: u32, r: u8, g: u8, b: u8) {
        let mut guard = FRAMEBUFFER.lock();
        if let Some(fb) = guard.as_mut() {
            fb.fill_rect_impl(x, y, width, height, r, g, b);
        }
    }

    /// Lock-free variant of [`Self::fill_rect`] for panic/IRQ paths.
    ///
    /// Returns `false` when the framebuffer lock is held by another context:
    /// the caller must drop the frame rather than deadlock.
    pub fn try_fill_rect(x: u32, y: u32, width: u32, height: u32, r: u8, g: u8, b: u8) -> bool {
        let Some(mut guard) = FRAMEBUFFER.try_lock() else {
            return false;
        };
        match guard.as_mut() {
            Some(fb) => fb.fill_rect_impl(x, y, width, height, r, g, b),
            None => false,
        }
    }

    fn fill_rect_impl(
        &mut self,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        r: u8,
        g: u8,
        b: u8,
    ) -> bool {
        if width == 0 || height == 0 || x >= self.info.width || y >= self.info.height {
            return false;
        }
        let width = width.min(self.info.width - x);
        let height = height.min(self.info.height - y);
        if width == 0 || height == 0 {
            return false;
        }
        let pixel = ((r as u32) << self.info.format.red_shift)
            | ((g as u32) << self.info.format.green_shift)
            | ((b as u32) << self.info.format.blue_shift);
        self.canvas.fill_rect(
            x as usize,
            y as usize,
            width as usize,
            height as usize,
            pixel,
        );
        self.request_present();
        true
    }

    /// Blit a packed 32bpp XRGB rectangle into the current draw target.
    ///
    /// `src` holds `h` rows of `w` pixels with a tight row stride of `w*4`
    /// bytes. Clipping, target selection (back buffer vs hardware), bpp
    /// conversion and dirty marking all live in [`CanvasBuffer::blit_rect`].
    pub fn blit_rect(src: &[u8], x: u32, y: u32, w: u32, h: u32) {
        let mut guard = FRAMEBUFFER.lock();
        if let Some(fb) = guard.as_mut() {
            fb.blit_rect_impl(src, x, y, w, h);
        }
    }

    /// Lock-free variant of [`Self::blit_rect`] for panic/IRQ paths.
    pub fn try_blit_rect(src: &[u8], x: u32, y: u32, w: u32, h: u32) -> bool {
        let Some(mut guard) = FRAMEBUFFER.try_lock() else {
            return false;
        };
        match guard.as_mut() {
            Some(fb) => fb.blit_rect_impl(src, x, y, w, h),
            None => false,
        }
    }

    fn blit_rect_impl(&mut self, src: &[u8], x: u32, y: u32, w: u32, h: u32) -> bool {
        if self
            .canvas
            .blit_rect(src, x as usize, y as usize, w as usize, h as usize)
            .is_none()
        {
            return false;
        }
        self.request_present();
        true
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
        let mut guard = FRAMEBUFFER.lock();
        if let Some(fb) = guard.as_mut() {
            fb.clear_impl();
        }
    }

    /// Lock-free variant of [`Self::clear`] for panic/IRQ paths.
    pub fn try_clear() -> bool {
        let Some(mut guard) = FRAMEBUFFER.try_lock() else {
            return false;
        };
        match guard.as_mut() {
            Some(fb) => fb.clear_impl(),
            None => false,
        }
    }

    fn clear_impl(&mut self) -> bool {
        let (width, height) = (self.info.width, self.info.height);
        if width == 0 || height == 0 {
            return false;
        }
        self.canvas
            .fill_rect(0, 0, width as usize, height as usize, 0);
        self.request_present();
        true
    }

    /// Swap buffers (for double buffering)
    ///
    /// The framebuffer lock is held for the whole presentation, including the
    /// GPU transfer. This is what prevents a concurrent draw from mutating the
    /// buffer the GPU is reading/writing, and what makes it safe to free the
    /// previous scanout buffer during a re-init.
    pub fn swap_buffers() {
        let mut guard = FRAMEBUFFER.lock();
        let Some(fb) = guard.as_mut() else {
            return;
        };
        if !fb.use_double_buffer && !fb.canvas.draw_to_back {
            // Direct drawing: the pixels are already in the scanout buffer.
            // Reset the pending dirty state so it cannot leak into a later
            // back-buffered source.
            fb.canvas.dirty.clear();
            fb.canvas.present_pending = false;
            return;
        }
        fb.present_locked();
    }

    /// Enable/disable double buffering
    ///
    /// On VirtIO GPU the draw target is the scanout buffer itself, so
    /// disabling double buffering would silently stop presenting. The request
    /// is ignored for that source.
    pub fn set_double_buffering(enable: bool) {
        let mut guard = FRAMEBUFFER.lock();
        let Some(fb) = guard.as_mut() else {
            return;
        };
        if fb.info.source == FramebufferSource::VirtioGpu {
            log::warn!("[FB] set_double_buffering ignored on VirtIO scanout buffer");
            return;
        }
        if enable {
            fb.canvas.enable_back_buffer();
        } else {
            fb.canvas.disable_back_buffer(true);
        }
        fb.use_double_buffer = fb.canvas.draw_to_back;
    }
}

pub use crate::framebuffer::RgbColor;

/// Initialize framebuffer subsystem
///
/// The bootloader framebuffer is installed earlier (see `init_bootloader`);
/// this pass upgrades to a native driver when one initializes successfully.
/// AMDGPU is attempted even when a firmware framebuffer exists, because the
/// native path is faster and supports different modes.
pub fn init() {
    log::info!("[FB] Initializing framebuffer subsystem...");

    // Try VirtIO GPU first (native driver).
    let mut installed = None;
    if gpu::is_available() {
        match Framebuffer::init_virtio_gpu() {
            Ok(()) => installed = Some(FramebufferSource::VirtioGpu),
            Err(e) => log::warn!("[FB] VirtIO GPU init failed: {}", e),
        }
    }

    // Try AMDGPU (real hardware) when VirtIO did not take over.
    if installed.is_none() && crate::hardware::amdgpu::is_available() {
        match Framebuffer::init_amd_gpu() {
            Ok(()) => installed = Some(FramebufferSource::AmdGpu),
            Err(e) => log::warn!("[FB] AMDGPU init failed: {}", e),
        }
    }

    // Fall back to the firmware framebuffer recorded during early boot.
    if installed.is_none() && !Framebuffer::is_available() {
        let boot = BOOT_FRAMEBUFFER.lock().take();
        if let Some(boot) = boot {
            match Framebuffer::init_bootloader(
                boot.addr_virt,
                boot.width,
                boot.height,
                boot.stride,
                boot.format,
            ) {
                Ok(()) => installed = Some(FramebufferSource::Bootloader),
                Err(e) => log::warn!("[FB] Bootloader framebuffer rejected: {}", e),
            }
        }
    }

    let source = installed.unwrap_or_else(Framebuffer::source);
    match source {
        FramebufferSource::VirtioGpu => log::info!("[FB] Using VirtIO GPU framebuffer"),
        FramebufferSource::AmdGpu => log::info!("[FB] Using AMDGPU framebuffer"),
        FramebufferSource::Bootloader => {
            log::info!("[FB] Using UEFI bootloader framebuffer")
        }
        FramebufferSource::None => log::warn!("[FB] No framebuffer available"),
    }

    // Register /dev/display/ scheme
    if Framebuffer::is_available() {
        if let Err(e) = super::display_scheme::register_display_scheme() {
            log::warn!("[FB] Failed to register display scheme: {:?}", e);
        }
    }
}
