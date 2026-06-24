//! Video drivers and framebuffer abstraction
//!
//! Provides:
//! - Framebuffer abstraction (Limine or VirtIO GPU)
//! - Basic 2D drawing primitives
//! - Double buffering support
//! - `/dev/display/` VFS scheme (display.vesa)
//! - Graphics adapter trait for multi-display support

pub mod display_scheme;
pub mod framebuffer;
pub mod graphics_adapter;

pub use framebuffer::{Framebuffer, FramebufferInfo, FramebufferSource, RgbColor};
pub use graphics_adapter::{Damage, DisplayScreen, GraphicsAdapter, HeapScreen, SimpleDisplayAdapter};
