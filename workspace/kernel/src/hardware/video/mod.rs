//! Video drivers and framebuffer abstraction
//!
//! Provides:
//! - Framebuffer abstraction (Limine or VirtIO GPU)
//! - Basic 2D drawing primitives
//! - Double buffering support

pub mod framebuffer;

pub use framebuffer::{Framebuffer, FramebufferInfo, FramebufferSource, RgbColor};
