//! Shell output formatting and capture.
//!
//! When capture mode is active, `shell_print!` / `shell_println!` write to an
//! internal buffer instead of serial + VGA.  This powers pipe (`|`) and
//! redirection (`>`, `>>`) in the Chevron shell.

use crate::sync::SpinLock;
use alloc::{string::String, vec::Vec};

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
        } else if !$crate::debug_cfg::is_quiet() {
            $crate::serial_print!($($arg)*);
            if $crate::arch::vga::is_available() {
                use core::fmt::Write;
                let _ = write!($crate::arch::vga::VGA_WRITER.lock(), $($arg)*);
            }
        }
    }};
}

/// Print to both serial and VGA with newline, then flush to screen.
#[macro_export]
macro_rules! shell_println {
    () => ($crate::shell_print!("\n"));
    ($($arg:tt)*) => {{
        if $crate::shell::output::is_capturing() {
            use core::fmt::Write;
            let mut __tmp = alloc::string::String::new();
            let _ = writeln!(__tmp, $($arg)*);
            $crate::shell::output::capture_write_bytes(__tmp.as_bytes());
        } else if !$crate::debug_cfg::is_quiet() {
            $crate::serial_println!($($arg)*);
            if $crate::arch::vga::is_available() {
                use core::fmt::Write;
                let _ = writeln!($crate::arch::vga::VGA_WRITER.lock(), $($arg)*);
                $crate::arch::vga::flush_display();
            }
        }
    }};
}

/// Clear the VGA screen.
pub fn clear_screen() {
    if crate::arch::vga::is_available() {
        crate::arch::vga::VGA_WRITER.lock().clear();
    }
}

/// Print the shell prompt and show the text cursor.
pub fn print_prompt() {
    shell_print!(">>> ");
    // Flush to screen so the prompt is visible immediately.
    if crate::arch::vga::is_available() {
        crate::arch::vga::flush_display();
        let color = crate::arch::vga::RgbColor::new(0x4F, 0xB3, 0xB3);
        crate::arch::vga::draw_text_cursor(color);
    }
}

/// Print raw text without per-character formatting overhead.
pub fn print_text(text: &str) {
    if crate::arch::vga::is_available() {
        crate::arch::vga::write_text(text);
    } else {
        crate::serial_print!("{}", text);
    }
}

/// Print a character (no newline).
pub fn print_char(ch: char) {
    crate::arch::vga::write_char(ch);
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

/// Format a byte count as a ready-to-print string, e.g. `12MB`.
///
/// Single definition shared by every command that reports sizes (`top`, `silo
/// list`, `silo info`, ...) so they cannot drift apart.
pub fn human_bytes(bytes: u64) -> String {
    let (value, unit) = format_bytes(bytes as usize);
    alloc::format!("{}{}", value, unit)
}

/// Format a memory budget, `0` meaning "no upper bound declared".
pub fn human_bytes_or_unlimited(bytes: u64) -> String {
    if bytes == 0 {
        String::from("unlimited")
    } else {
        human_bytes(bytes)
    }
}

/// Task state label, so `ps`, `top` and every listing spell a state the same
/// way instead of each mapping the enum to its own `Debug` spelling.
pub fn task_state_str(state: crate::process::TaskState) -> &'static str {
    match state {
        crate::process::TaskState::Ready => "Ready",
        crate::process::TaskState::Running => "Running",
        crate::process::TaskState::Blocked => "Blocked",
        crate::process::TaskState::Dead => "Dead",
    }
}

/// Splits a tick count into whole seconds and hundredths, using the kernel
/// timer frequency.
///
/// Single definition shared by every command that timestamps an event
/// (`dmesg`, `audit`, `silo logs`, `silo events`): each used to hardcode its own
/// divisor, and `silo logs` was stuck on 100 Hz while the kernel may run at
/// another rate.
pub fn format_ticks(ticks: u64) -> (u64, u32) {
    let hz = crate::arch::timer::TIMER_HZ.max(1);
    (ticks / hz, ((ticks % hz) * 100 / hz) as u32)
}

/// Formats a duration in seconds as `HH:MM:SS`.
pub fn format_uptime(total_secs: u64) -> String {
    alloc::format!(
        "{:02}:{:02}:{:02}",
        total_secs / 3600,
        (total_secs % 3600) / 60,
        total_secs % 60
    )
}

/// Formats a Unix timestamp as `Mon DD HH:MM`.
///
/// The civil-date arithmetic lives in the kernel's RTC module, so leap years are
/// handled once instead of by each caller.
pub fn format_epoch_time(unix_secs: u64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let dt = crate::hardware::timer::rtc::RtcDateTime::from_timestamp(unix_secs);
    let month = MONTHS
        .get((dt.month as usize).saturating_sub(1))
        .copied()
        .unwrap_or("???");
    alloc::format!(
        "{} {:>2} {:02}:{:02}",
        month,
        dt.day,
        dt.hour,
        dt.minute
    )
}

/// Formats a Unix timestamp as a full `YYYY-MM-DD HH:MM:SS UTC` stamp.
pub fn format_epoch_stamp(unix_secs: u64) -> String {
    let dt = crate::hardware::timer::rtc::RtcDateTime::from_timestamp(unix_secs);
    alloc::format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        dt.year,
        dt.month,
        dt.day,
        dt.hour,
        dt.minute,
        dt.second
    )
}
