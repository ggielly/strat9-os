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

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::fmt;
use spin::RwLock;

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
    /// Pointer to the raw pixel data.
    fn pixels(&self) -> *const u8;
    /// Mutable pointer to the raw pixel data.
    fn pixels_mut(&mut self) -> *mut u8;
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

/// A heap-allocated offscreen pixel buffer.
#[derive(Clone)]
pub struct HeapScreen {
    width: u32,
    height: u32,
    stride: u32,
    bpp: u8,
    data: Box<[u8]>,
}

impl fmt::Debug for HeapScreen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeapScreen")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("stride", &self.stride)
            .field("bpp", &self.bpp)
            .finish()
    }
}

impl HeapScreen {
    /// Create a new zero-initialized screen.
    pub fn new(width: u32, height: u32, bpp: u8) -> Self {
        let stride = width * (bpp as u32 / 8);
        let size = (stride * height) as usize;
        let data = alloc::vec![0u8; size].into_boxed_slice();
        Self {
            width,
            height,
            stride,
            bpp,
            data,
        }
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
    fn pixels(&self) -> *const u8 {
        self.data.as_ptr()
    }
    fn pixels_mut(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
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
        HeapScreen::new(width, height, self.fb_bpp)
    }

    fn update_plane(&self, display_id: usize, screen: &HeapScreen, damage: Damage) {
        if display_id >= self.display_count {
            return;
        }
        if self.fb_virt == 0 {
            return;
        }

        let damage = damage.clip(screen.width(), screen.height());
        if !damage.is_valid() {
            return;
        }

        let bpp = self.fb_bpp as usize;
        let dst_stride = self.fb_stride as usize;
        let src_stride = screen.stride() as usize;
        let dst = self.fb_virt as *mut u8;
        let src = screen.pixels();

        if bpp == 32 {
            let bytes_per_row = damage.width as usize * 4;
            for row in 0..damage.height as usize {
                let src_off = (damage.y as usize + row) * src_stride + damage.x as usize * 4;
                let dst_off = (damage.y as usize + row) * dst_stride + damage.x as usize * 4;
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        src.add(src_off),
                        dst.add(dst_off),
                        bytes_per_row,
                    );
                }
            }
        } else if bpp == 24 {
            let bytes_per_row = damage.width as usize * 3;
            for row in 0..damage.height as usize {
                let src_off = (damage.y as usize + row) * src_stride + damage.x as usize * 3;
                let dst_off = (damage.y as usize + row) * dst_stride + damage.x as usize * 3;
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        src.add(src_off),
                        dst.add(dst_off),
                        bytes_per_row,
                    );
                }
            }
        }
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
