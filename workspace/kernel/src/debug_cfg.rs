//! Centralised debug configuration.
//!
//! All global toggles and knobs that control debug output, diagnostic
//! behaviour, or temporary workarounds live here.  When a debug feature
//! is no longer needed, simply flip the default to `false` : no other
//! code changes required.

use core::sync::atomic::{AtomicBool, Ordering};

// ---------------------------------------------------------------------------
// Quiet mode : disable ALL debug output (serial, VGA, overlay)
// ---------------------------------------------------------------------------

/// Master switch to disable all debug output. When `true`, no serial,
/// VGA, overlay, or status line output is produced. The kernel still
/// runs, but produces zero diagnostic output. Intended for production
/// builds and real hardware bring-up where debug output would slow boot.
pub static QUIET_MODE: AtomicBool = AtomicBool::new(false);

/// Returns `true` if quiet mode is active (all debug output disabled).
pub fn is_quiet() -> bool {
    QUIET_MODE.load(Ordering::Relaxed)
}

/// Enable or disable quiet mode at runtime.
pub fn set_quiet(enabled: bool) {
    QUIET_MODE.store(enabled, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// VGA live debug output
// ---------------------------------------------------------------------------

/// When `true`, every `log::info!` / `log::warn!` / etc. is drawn directly to
/// the VGA framebuffer in real time (pixel by pixel, no buffering).
pub static VGA_DEBUG_LIVE: AtomicBool = AtomicBool::new(true);

pub fn is_vga_debug_live() -> bool {
    !is_quiet() && VGA_DEBUG_LIVE.load(Ordering::Relaxed)
}

pub fn set_vga_debug_live(enabled: bool) {
    VGA_DEBUG_LIVE.store(enabled, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// VGA circular buffer (vgabuf) : async display via status line task
// ---------------------------------------------------------------------------

/// When `true`, log lines are written into the lock-free circular buffer
/// for async display by the status line task.
pub static VGA_DEBUG_BUFFER: AtomicBool = AtomicBool::new(true);

pub fn is_vga_debug_buffer() -> bool {
    !is_quiet() && VGA_DEBUG_BUFFER.load(Ordering::Relaxed)
}

pub fn set_vga_debug_buffer(enabled: bool) {
    VGA_DEBUG_BUFFER.store(enabled, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// Future debug flags : TODO
// ---------------------------------------------------------------------------
