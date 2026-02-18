//! Shell output formatting
//!
//! Provides utilities for formatted shell output.


/// Print to both serial and VGA
#[macro_export]
macro_rules! shell_print {
    ($($arg:tt)*) => {{
        $crate::serial_print!($($arg)*);
        if $crate::arch::x86_64::vga::is_available() {
            use core::fmt::Write;
            let _ = write!($crate::arch::x86_64::vga::VGA_WRITER.lock(), $($arg)*);
        }
    }};
}

/// Print to both serial and VGA with newline
#[macro_export]
macro_rules! shell_println {
    () => ($crate::shell_print!("\n"));
    ($($arg:tt)*) => {{
        $crate::serial_println!($($arg)*);
        if $crate::arch::x86_64::vga::is_available() {
            use core::fmt::Write;
            let _ = writeln!($crate::arch::x86_64::vga::VGA_WRITER.lock(), $($arg)*);
        }
    }};
}

/// Clear the VGA screen
pub fn clear_screen() {
    if crate::arch::x86_64::vga::is_available() {
        crate::arch::x86_64::vga::VGA_WRITER.lock().clear();
    }
}

/// Print the shell prompt
pub fn print_prompt() {
    shell_print!(">>> ");
}

/// Print a character (no newline)
pub fn print_char(ch: char) {
    shell_print!("{}", ch);
}

/// Format bytes as human-readable size
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
