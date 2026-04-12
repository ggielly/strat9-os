//! Shell output formatting and capture.
//!
//! When capture mode is active, `shell_print!` / `shell_println!` write to an
//! internal buffer instead of serial + VGA.  This powers pipe (`|`) and
//! redirection (`>`, `>>`) in the Chevron shell.

use crate::sync::SpinLock;
use alloc::vec::Vec;

// SpinLock over Option<Vec<u8>>: shell-only path, never called from IRQ context
// or the allocator hot path.  Heap growth under this lock is acceptable.
// Tracked as low-priority debt in ticket #49.
static CAPTURE_BUF: SpinLock<Option<Vec<u8>>> = SpinLock::new(None);
static PIPE_INPUT: SpinLock<Option<Vec<u8>>> = SpinLock::new(None);

/// Begin capturing shell output into an internal buffer.
pub fn start_capture() {
    *CAPTURE_BUF.lock() = Some(Vec::new());
}

/// Stop capturing and return the accumulated bytes.
pub fn take_capture() -> Vec<u8> {
    CAPTURE_BUF.lock().take().unwrap_or_default()
}

/// Returns `true` when capture mode is active.
pub fn is_capturing() -> bool {
    CAPTURE_BUF.lock().is_some()
}

/// Append raw bytes to the capture buffer (called by the macros).
pub fn capture_write_bytes(data: &[u8]) {
    if let Some(buf) = CAPTURE_BUF.lock().as_mut() {
        buf.extend_from_slice(data);
    }
}

/// Set pipe input data for the next command in a pipeline.
pub fn set_pipe_input(data: Vec<u8>) {
    *PIPE_INPUT.lock() = Some(data);
}

/// Take and return the current pipe input, if any.
///
/// Commands call this to consume piped data. Returns `None` when
/// the command was not invoked as the right-hand side of a pipe.
pub fn take_pipe_input() -> Option<Vec<u8>> {
    PIPE_INPUT.lock().take()
}

/// Returns `true` when pipe input data is available.
pub fn has_pipe_input() -> bool {
    PIPE_INPUT.lock().is_some()
}

/// Clear any pending pipe input.
pub fn clear_pipe_input() {
    PIPE_INPUT.lock().take();
}

/// Print to both serial and VGA.
#[macro_export]
macro_rules! shell_print {
    ($($arg:tt)*) => {{
        if $crate::shell::output::is_capturing() {
            use core::fmt::Write;
            let mut __tmp = alloc::string::String::new();
            let _ = write!(__tmp, $($arg)*);
            $crate::shell::output::capture_write_bytes(__tmp.as_bytes());
        } else {
            $crate::serial_print!($($arg)*);
            if $crate::arch::x86_64::vga::is_available() {
                use core::fmt::Write;
                let _ = write!($crate::arch::x86_64::vga::VGA_WRITER.lock(), $($arg)*);
            }
        }
    }};
}

/// Print to both serial and VGA with newline.
#[macro_export]
macro_rules! shell_println {
    () => ($crate::shell_print!("\n"));
    ($($arg:tt)*) => {{
        if $crate::shell::output::is_capturing() {
            use core::fmt::Write;
            let mut __tmp = alloc::string::String::new();
            let _ = writeln!(__tmp, $($arg)*);
            $crate::shell::output::capture_write_bytes(__tmp.as_bytes());
        } else {
            $crate::serial_println!($($arg)*);
            if $crate::arch::x86_64::vga::is_available() {
                use core::fmt::Write;
                let _ = writeln!($crate::arch::x86_64::vga::VGA_WRITER.lock(), $($arg)*);
            }
        }
    }};
}

/// Clear the VGA screen.
pub fn clear_screen() {
    if crate::arch::x86_64::vga::is_available() {
        crate::arch::x86_64::vga::VGA_WRITER.lock().clear();
    }
}

/// Print the shell prompt.
pub fn print_prompt() {
    shell_print!(">>> ");
}

/// Print raw text without per-character formatting overhead.
pub fn print_text(text: &str) {
    if crate::arch::x86_64::vga::is_available() {
        crate::arch::x86_64::vga::write_text(text);
    } else {
        crate::serial_print!("{}", text);
    }
}

/// Print a character (no newline).
pub fn print_char(ch: char) {
    crate::arch::x86_64::vga::write_char(ch);
}

/// Format bytes as human-readable size.
pub fn format_bytes(bytes: usize) -> (usize, &'static str) {
    const KB: usize = 1024;
    const MB: usize = KB * 1024;
    const GB: usize = MB * 1024;

    if bytes >= GB {
        (bytes / GB, "GB")
    } else if bytes >= MB {
        (bytes / MB, "MB")
    } else if bytes >= KB {
        (bytes / KB, "KB")
    } else {
        (bytes, "B")
    }
}
