//! Graphics adapter abstraction for multi-display support.
//!
//! Modeled after Redox OS `driver-graphics` crate but adapted for
//! Strat9-OS kernel scheme architecture.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │                GraphicsScheme                   │
//! │  /dev/display/0.0  /dev/display/0.1  ...        │
//! ├─────────────────────────────────────────────────┤
//! │              GraphicsAdapter impl               │
//! │  display_count() => N displays                   │
//! │  display_size(id) => (w, h)                      │
//! │  create_framebuffer(w, h) => DisplayScreen       │
//! │  update_plane(id, screen, damage)               │
//! ├─────────────────────────────────────────────────┤
//! │  DisplayScreen (offscreen buffer)               │
//! │  sync() => copy to onscreen                      │
//! └─────────────────────────────────────────────────┘
//! ```

use alloc::{sync::Arc, vec::Vec};
use core::fmt;
use spin::RwLock;

use crate::{
    capability::CapId,
    memory::{
        self, allocate_mapping_cap_id, ownership_table, release_owned_block, resolve_handle,
        unregister_mapping_identity, OwnerError, PhysFrame,
    },
    sync::with_irqs_disabled,
};

use super::framebuffer::PixelFormat;

/// Dirty region for partial screen updates.
#[derive(Debug, Clone, Copy, Default)]
pub struct Damage {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

impl Damage {
    /// Create a full-screen damage region.
    pub fn full(width: u32, height: u32) -> Self {
        Self {
            x: 0,
            y: 0,
            width,
            height,
        }
    }

    /// Returns true if this damage region has non-zero area.
    pub fn is_valid(&self) -> bool {
        self.width > 0 && self.height > 0
    }

    /// Clip this damage to the given bounds.
    pub fn clip(&self, max_w: u32, max_h: u32) -> Self {
        let x = self.x.min(max_w);
        let y = self.y.min(max_h);
        let w = self.width.min(max_w.saturating_sub(x));
        let h = self.height.min(max_h.saturating_sub(y));
        Self {
            x,
            y,
            width: w,
            height: h,
        }
    }
}

/// Trait for an individual display screen (offscreen buffer).
pub trait DisplayScreen: Send + Sync {
    /// Width in pixels.
    fn width(&self) -> u32;
    /// Height in pixels.
    fn height(&self) -> u32;
    /// Bytes per row (stride).
    fn stride(&self) -> u32;
    /// Bits per pixel.
    fn bpp(&self) -> u8;
    /// Copy `out.len()` bytes starting at byte `offset` of the surface.
    fn read_into(&self, offset: usize, out: &mut [u8]) -> usize;
    /// Copy `src` into the surface at byte `offset`.
    fn write_from(&mut self, offset: usize, src: &[u8]) -> usize;
    /// Fill `len` bytes at `offset` with `value`.
    fn fill_bytes(&mut self, offset: usize, len: usize, value: u8);
    /// Copy one damage rectangle to a physical framebuffer.
    fn copy_rows_to(&self, dst: *mut u8, dst_stride: usize, damage: Damage, bpp_bytes: usize);
}

/// Trait for a graphics adapter managing one or more displays.
pub trait GraphicsAdapter: Send + Sync {
    /// The screen type created by this adapter.
    type Screen: DisplayScreen;

    /// Number of connected displays.
    fn display_count(&self) -> usize;

    /// Resolution of a specific display.
    fn display_size(&self, display_id: usize) -> (u32, u32);

    /// Create an offscreen framebuffer of the given size.
    fn create_framebuffer(&self, width: u32, height: u32) -> Self::Screen;

    /// Present an offscreen buffer to a physical display.
    ///
    /// Only the `damage` region needs to be copied.
    fn update_plane(&self, display_id: usize, screen: &Self::Screen, damage: Damage);

    /// Returns true if the adapter supports hardware cursor planes.
    fn supports_hw_cursor(&self) -> bool {
        false
    }
}

// ============================================================================
// Concrete implementation: UEFI bootloader/VirtIO framebuffer adapter
// ============================================================================

/// An offscreen pixel surface backed by **individual physical frames**.
///
/// Frame backing (instead of a kernel heap `Box`) is what makes
/// `MAP_SHARED` possible: the display scheme can hand the frame list to
/// `sys_mmap`, and a display client writes pixels directly into the mapped
/// pages. The kernel accesses the same frames through the HHDM, page by page,
/// so physical contiguity is not required.
///
/// `size` is the number of meaningful bytes (`stride * height`); the last
/// page may contain padding.
pub struct HeapScreen {
    width: u32,
    height: u32,
    stride: u32,
    bpp: u8,
    /// Native pixel layout of the target framebuffer. Pixels written through
    /// the scheme are packed into this layout, so a GOP with RGB masks is not
    /// displayed with swapped red/blue channels.
    format: PixelFormat,
    pages: Vec<PhysFrame>,
    /// One ownership reference per page, mirroring `/dev/ipc/shm` rings:
    /// a user `MAP_SHARED` unmap drops its mapping ref, but the frame stays
    /// alive until the screen itself is dropped.
    owner_caps: Vec<CapId>,
    size: usize,
}

impl fmt::Debug for HeapScreen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeapScreen")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("stride", &self.stride)
            .field("bpp", &self.bpp)
            .field("format", &self.format)
            .field("pages", &self.pages.len())
            .finish()
    }
}

impl HeapScreen {
    /// Create a new zero-initialized screen using the default XRGB layout.
    pub fn new(width: u32, height: u32, bpp: u8) -> Self {
        Self::new_with_format(width, height, bpp, PixelFormat::default())
    }

    /// Create a new zero-initialized screen with an explicit native pixel
    /// layout (masks/shifts come from the bootloader or GPU driver).
    ///
    /// On frame-allocation failure the screen is left empty (`pages` empty):
    /// all surface operations then become no-ops instead of panicking.
    pub fn new_with_format(width: u32, height: u32, bpp: u8, mut format: PixelFormat) -> Self {
        format.bits_per_pixel = bpp;
        let stride = width.saturating_mul(bpp as u32 / 8);
        let size = stride as usize * height as usize;
        let page_count = (size + 4095) / 4096;

        let mut pages = Vec::with_capacity(page_count);
        let mut owner_caps = Vec::with_capacity(page_count);
        for _ in 0..page_count {
            let frame = match with_irqs_disabled(|token| memory::allocate_frame(token)) {
                Ok(frame) => frame,
                Err(_) => {
                    release_screen_pages(&mut pages, &mut owner_caps);
                    return Self {
                        width,
                        height,
                        stride,
                        bpp,
                        format,
                        pages: Vec::new(),
                        owner_caps: Vec::new(),
                        size: 0,
                    };
                }
            };

            // Take an ownership reference before the page can be mapped
            // shared: unmapping userspace then only drops the mapping ref.
            let owner_cap = allocate_mapping_cap_id();
            let handle = resolve_handle(frame.start_address);
            match ownership_table().ensure_ref(handle, owner_cap) {
                Ok(_) | Err(OwnerError::CapAlreadyPresent) => {}
                Err(_) => {
                    with_irqs_disabled(|token| memory::free_frame(token, frame));
                    release_screen_pages(&mut pages, &mut owner_caps);
                    return Self {
                        width,
                        height,
                        stride,
                        bpp,
                        format,
                        pages: Vec::new(),
                        owner_caps: Vec::new(),
                        size: 0,
                    };
                }
            }

            let va = memory::phys_to_virt(frame.start_address.as_u64());
            unsafe { core::ptr::write_bytes(va as *mut u8, 0, 4096) };
            pages.push(frame);
            owner_caps.push(owner_cap);
        }

        Self {
            width,
            height,
            stride,
            bpp,
            format,
            pages,
            owner_caps,
            size,
        }
    }

    /// Native pixel layout used by this screen.
    pub fn format(&self) -> PixelFormat {
        self.format
    }

    /// Meaningful byte length of the surface.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Physical address of every backing page, for `MAP_SHARED`.
    pub fn frames(&self) -> Vec<u64> {
        self.pages
            .iter()
            .map(|frame| frame.start_address.as_u64())
            .collect()
    }

    fn page_ptr(&self, offset: usize) -> Option<(*const u8, usize)> {
        if offset >= self.size {
            return None;
        }
        let page = offset / 4096;
        let in_page = offset % 4096;
        let frame = self.pages.get(page)?;
        let va = memory::phys_to_virt(frame.start_address.as_u64());
        Some(((va as *const u8).wrapping_add(in_page), in_page))
    }

    /// Copy out of the surface, crossing page boundaries as needed.
    fn copy_out(&self, offset: usize, dst: *mut u8, len: usize) {
        let mut done = 0usize;
        while done < len {
            let Some((src, _)) = self.page_ptr(offset + done) else {
                return;
            };
            let in_page = (offset + done) % 4096;
            let chunk = core::cmp::min(len - done, 4096 - in_page);
            unsafe {
                core::ptr::copy_nonoverlapping(src, dst.add(done), chunk);
            }
            done += chunk;
        }
    }
}

/// Release the ownership refs of a screen's pages.
///
/// The last ownership ref frees the underlying frame; a user `MAP_SHARED`
/// mapping holds a separate mapping ref, so a client unmap never frees a
/// frame the screen still uses.
fn release_screen_pages(pages: &mut Vec<PhysFrame>, owner_caps: &mut Vec<CapId>) {
    for (frame, cap) in pages.drain(..).zip(owner_caps.drain(..)) {
        let handle = resolve_handle(frame.start_address);
        if let Some(block) = unregister_mapping_identity(handle, cap) {
            release_owned_block(block);
        }
    }
}

impl Drop for HeapScreen {
    fn drop(&mut self) {
        release_screen_pages(&mut self.pages, &mut self.owner_caps);
    }
}

impl DisplayScreen for HeapScreen {
    fn width(&self) -> u32 {
        self.width
    }
    fn height(&self) -> u32 {
        self.height
    }
    fn stride(&self) -> u32 {
        self.stride
    }
    fn bpp(&self) -> u8 {
        self.bpp
    }

    fn read_into(&self, offset: usize, out: &mut [u8]) -> usize {
        let n = core::cmp::min(out.len(), self.size.saturating_sub(offset));
        self.copy_out(offset, out.as_mut_ptr(), n);
        n
    }

    fn write_from(&mut self, offset: usize, src: &[u8]) -> usize {
        let n = core::cmp::min(src.len(), self.size.saturating_sub(offset));
        let mut done = 0usize;
        while done < n {
            let Some((_, in_page)) = self.page_ptr(offset + done) else {
                break;
            };
            let page = (offset + done) / 4096;
            let Some(frame) = self.pages.get(page) else {
                break;
            };
            let va = memory::phys_to_virt(frame.start_address.as_u64());
            let chunk = core::cmp::min(n - done, 4096 - in_page);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    src.as_ptr().add(done),
                    (va as *mut u8).wrapping_add(in_page),
                    chunk,
                );
            }
            done += chunk;
        }
        done
    }

    fn fill_bytes(&mut self, offset: usize, len: usize, value: u8) {
        let n = core::cmp::min(len, self.size.saturating_sub(offset));
        let mut done = 0usize;
        while done < n {
            let page = (offset + done) / 4096;
            let in_page = (offset + done) % 4096;
            let Some(frame) = self.pages.get(page) else {
                break;
            };
            let va = memory::phys_to_virt(frame.start_address.as_u64());
            let chunk = core::cmp::min(n - done, 4096 - in_page);
            unsafe {
                core::ptr::write_bytes((va as *mut u8).wrapping_add(in_page), value, chunk);
            }
            done += chunk;
        }
    }

    fn copy_rows_to(&self, dst: *mut u8, dst_stride: usize, damage: Damage, bpp_bytes: usize) {
        if self.pages.is_empty() || bpp_bytes == 0 {
            return;
        }
        let d = damage.clip(self.width, self.height);
        if !d.is_valid() {
            return;
        }
        let row_bytes = d.width as usize * bpp_bytes;
        for row in 0..d.height as usize {
            let src_off = (d.y as usize + row) * self.stride as usize + d.x as usize * bpp_bytes;
            let dst_off = (d.y as usize + row) * dst_stride + d.x as usize * bpp_bytes;
            self.copy_out(src_off, unsafe { dst.add(dst_off) }, row_bytes);
        }
    }
}

/// Adapter backed by a single physical framebuffer (UEFI bootloader or VirtIO).
pub struct SimpleDisplayAdapter {
    /// Physical framebuffer info.
    fb_virt: usize,
    fb_width: u32,
    fb_height: u32,
    fb_stride: u32,
    fb_bpp: u8,
    /// Number of displays (1 for simple adapter).
    display_count: usize,
}

impl SimpleDisplayAdapter {
    /// Create from an existing framebuffer.
    pub fn new(virt: usize, width: u32, height: u32, stride: u32, bpp: u8) -> Self {
        Self {
            fb_virt: virt,
            fb_width: width,
            fb_height: height,
            fb_stride: stride,
            fb_bpp: bpp,
            display_count: 1,
        }
    }

    /// Create from the global Framebuffer if available.
    pub fn from_framebuffer() -> Option<Self> {
        let info = super::framebuffer::Framebuffer::info()?;
        Some(Self::new(
            info.base_virt,
            info.width,
            info.height,
            info.stride,
            info.format.bits_per_pixel,
        ))
    }
}

impl GraphicsAdapter for SimpleDisplayAdapter {
    type Screen = HeapScreen;

    fn display_count(&self) -> usize {
        self.display_count
    }

    fn display_size(&self, display_id: usize) -> (u32, u32) {
        if display_id < self.display_count {
            (self.fb_width, self.fb_height)
        } else {
            (0, 0)
        }
    }

    fn create_framebuffer(&self, width: u32, height: u32) -> HeapScreen {
        let format = super::framebuffer::Framebuffer::info()
            .map(|i| i.format)
            .unwrap_or_default();
        HeapScreen::new_with_format(width, height, self.fb_bpp, format)
    }

    fn update_plane(&self, display_id: usize, screen: &HeapScreen, damage: Damage) {
        if display_id >= self.display_count {
            return;
        }
        if self.fb_virt == 0 {
            return;
        }

        let bpp_bytes = self.fb_bpp as usize / 8;
        if bpp_bytes != 3 && bpp_bytes != 4 {
            return;
        }

        // Frame-backed surface: copy only the damaged rows, page-aware.
        screen.copy_rows_to(
            self.fb_virt as *mut u8,
            self.fb_stride as usize,
            damage,
            bpp_bytes,
        );
    }
}

// ============================================================================
// Global adapter registry
// ============================================================================

/// Global list of registered graphics adapters.
static ADAPTERS: RwLock<Vec<Arc<dyn GraphicsAdapter<Screen = HeapScreen>>>> =
    RwLock::new(Vec::new());

/// Total display count across all adapters.
pub fn total_display_count() -> usize {
    ADAPTERS.read().iter().map(|a| a.display_count()).sum()
}

/// Register a graphics adapter.
pub fn register_adapter(adapter: Arc<dyn GraphicsAdapter<Screen = HeapScreen>>) {
    ADAPTERS.write().push(adapter);
}

/// Get the adapter and local display ID for a global display index.
pub fn get_adapter_for_display(
    global_id: usize,
) -> Option<(Arc<dyn GraphicsAdapter<Screen = HeapScreen>>, usize)> {
    let adapters = ADAPTERS.read();
    let mut remaining = global_id;
    for adapter in adapters.iter() {
        let count = adapter.display_count();
        if remaining < count {
            return Some((adapter.clone(), remaining));
        }
        remaining -= count;
    }
    None
}
