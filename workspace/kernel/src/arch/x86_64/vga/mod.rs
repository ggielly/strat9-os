/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

//! Framebuffer text console (UEFI bootloader framebuffer + PSF font).
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
mod console_mode;
mod cursor;
mod debug_overlay;
pub(crate) mod fastfb;
mod font;
mod panic_screen;
mod scrollback;
pub(crate) mod status_line;
mod types;
mod writer;

// Re-export everything that was previously public from the old monolithic vga.rs.
pub use api::*;
pub use canvas::Canvas;
pub use console_mode::{
    current as console_mode, is_lite, is_serial, present_min_ticks,
    select as select_console_mode, ConsoleMode,
};
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
        if !$crate::debug_cfg::is_quiet() && $crate::display_state::kernel_fb_allowed() {
            $crate::arch::x86_64::vga::_print(format_args!($($arg)*));
        }
    };
}

/// Print line to framebuffer console (falls back to serial when unavailable).
/// Flushes to screen after each line.
#[macro_export]
macro_rules! vga_println {
    () => {
        if !$crate::debug_cfg::is_quiet() && $crate::display_state::kernel_fb_allowed() {
            $crate::vga_print!("\n");
            $crate::arch::x86_64::vga::flush_display();
        }
    };
    ($($arg:tt)*) => {
        if !$crate::debug_cfg::is_quiet() && $crate::display_state::kernel_fb_allowed() {
            $crate::vga_print!("{}\n", format_args!($($arg)*));
            $crate::arch::x86_64::vga::flush_display();
        }
    };
}
