//! Centralised debug configuration.
//!
//! All global toggles and knobs that control debug output, diagnostic
//! behaviour, or temporary workarounds live here.  When a debug feature
//! is no longer needed, simply flip the default to `false` : no other
//! code changes required.
//!
//! # Future additions
//!
//! - `TRACE_SYSCALLS`: log every syscall entry/exit
//! - `TRACE_CONTEXT_SWITCH`: log every task switch
//! - `VGA_DEBUG_LIVE`: real-time VGA framebuffer output (already here)
//! - `PANIC_SCREENSHOT`: dump framebuffer to serial on panic
//! - `LOG_MM`: trace memory allocations

use core::sync::atomic::{AtomicBool, Ordering};

// ---------------------------------------------------------------------------
// VGA live debug output
// ---------------------------------------------------------------------------

/// When `true`, every `log::info!` / `log::warn!` / etc. is drawn directly to
/// the VGA framebuffer **in real time** (pixel by pixel, no buffering).
///
/// This is intentionally linear and synchronous : it slows the boot down but
/// guarantees you see every message, even during a panic.
///
/// Set to `false` (or delete the toggles) once the boot issue is resolved.
pub static VGA_DEBUG_LIVE: AtomicBool = AtomicBool::new(true); // Set to false to disable live VGA output

/// Returns `true` if live VGA debug output is enabled.
pub fn is_vga_debug_live() -> bool {
    VGA_DEBUG_LIVE.load(Ordering::Relaxed)
}

/// Enable or disable live VGA debug output.
pub fn set_vga_debug_live(enabled: bool) {
    VGA_DEBUG_LIVE.store(enabled, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// VGA circular buffer (vgabuf) : async display via status line task
// ---------------------------------------------------------------------------

/// When `true` (default), log lines are also written into the lock-free
/// circular buffer (`vgabuf`) for async display by the status line task.
///
/// Disable this when using `VGA_DEBUG_LIVE` to avoid duplicate output and
/// visual clutter.  Re-enable when live debug is turned off so the status
/// line task keeps the framebuffer terminal up to date.
pub static VGA_DEBUG_BUFFER: AtomicBool = AtomicBool::new(true);

/// Returns `true` if buffered VGA output is enabled.
pub fn is_vga_debug_buffer() -> bool {
    VGA_DEBUG_BUFFER.load(Ordering::Relaxed)
}

/// Enable or disable buffered VGA output.
pub fn set_vga_debug_buffer(enabled: bool) {
    VGA_DEBUG_BUFFER.store(enabled, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// Future debug flags : TODO
// ---------------------------------------------------------------------------
// Example:
//
// pub static TRACE_SYSCALLS: AtomicBool = AtomicBool::new(false);
// pub fn trace_syscalls() -> bool { TRACE_SYSCALLS.load(Ordering::Relaxed) }
