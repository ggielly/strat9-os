//! Framebuffer text console (Limine framebuffer + PSF font).
//! https://en.wikipedia.org/wiki/PC_Screen_Font
//!
//! Keeps the existing `vga_print!` / `vga_println!` API but renders text into
//! the graphical framebuffer when available. Falls back to serial otherwise.
//!
//! # Module structure
//!
//! - `types`    : Color, RgbColor, UiTheme, layout types, terminal widget
//! - `font`     : PSF font parsing (PSF1/PSF2 + unicode map)
//! - `writer`   : `VgaWriter` struct: glyph rendering, scrollback, cursors,
//!                double-buffering, dirty-rect tracking, present
//! - `canvas`   : `Canvas` convenience drawing API
//! - `api`      : Public free functions, `VGA_WRITER` static, `init()`
//! - `panic_screen` : Lock-free panic framebuffer drawing
//! - `debug_overlay` : Live debug overlay (bypasses VGA_WRITER)
//! - `status_line` : Status bar kthread and rendering

mod api;
mod canvas;
mod cursor;
mod debug_overlay;
mod font;
mod panic_screen;
mod scrollback;
pub(crate) mod status_line;
mod types;
mod writer;

// Re-export everything that was previously public from the old monolithic vga.rs.
pub use api::*;
pub use canvas::Canvas;
pub use types::*;
pub use writer::VgaWriter;

pub use status_line::{
    draw_system_status_line, maybe_refresh_system_status_line, set_status_hostname, set_status_ip,
    status_line_task_main, ui_draw_status_bar,
};

pub use debug_overlay::{vga_debug_init, vga_debug_write, vga_debug_writeln};
pub use panic_screen::{init_panic_fb_globals, panic_draw_direct};

/// Print to framebuffer console (falls back to serial when unavailable).
#[macro_export]
macro_rules! vga_print {
    ($($arg:tt)*) => {
        if !$crate::debug_cfg::is_quiet() {
            $crate::arch::x86_64::vga::_print(format_args!($($arg)*));
        }
    };
}

/// Print line to framebuffer console (falls back to serial when unavailable).
/// Flushes to screen after each line.
#[macro_export]
macro_rules! vga_println {
    () => {
        if !$crate::debug_cfg::is_quiet() {
            $crate::vga_print!("\n");
            $crate::arch::x86_64::vga::flush_display();
        }
    };
    ($($arg:tt)*) => {
        if !$crate::debug_cfg::is_quiet() {
            $crate::vga_print!("{}\n", format_args!($($arg)*));
            $crate::arch::x86_64::vga::flush_display();
        }
    };
}
