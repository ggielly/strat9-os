/// Live debug framebuffer overlay.
///
/// Writes directly to the VGA framebuffer, bypassing VGA_WRITER and all
/// buffers/locks.  Enabled by `debug_cfg::VGA_DEBUG_LIVE`.
use super::panic_screen::{
    panic_pack_rgb, PANIC_FB_ADDR, PANIC_FB_FORMAT, PANIC_FB_PITCH, PANIC_FONT_8X16,
};

// bypassing all buffers and locks.  Enabled by `debug_cfg::VGA_DEBUG_LIVE`.
// =============================================================================

/// Current cursor column for the live debug writer (0-based character column).
static VGA_DEBUG_COL: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
/// Current cursor row for the live debug writer (0-based character row).
static VGA_DEBUG_ROW: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Maximum columns available on the current framebuffer (cached).
static VGA_DEBUG_MAX_COL: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
/// Maximum rows available on the current framebuffer (cached).
static VGA_DEBUG_MAX_ROW: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Initialise or re-initialise the live debug writer's geometry.
/// Called automatically from `vga::init()`.
pub fn vga_debug_init(fb_width: usize, fb_height: usize) {
    let cols = fb_width / 8; // panic_font_8x16 glyph width
    let rows = fb_height / 16; // panic_font_8x16 glyph height
    let status_rows = 1; // reserve 1 row for status bar
    VGA_DEBUG_MAX_COL.store(cols, core::sync::atomic::Ordering::Relaxed);
    VGA_DEBUG_MAX_ROW.store(
        rows.saturating_sub(status_rows),
        core::sync::atomic::Ordering::Relaxed,
    );
    VGA_DEBUG_COL.store(0, core::sync::atomic::Ordering::Relaxed);
    VGA_DEBUG_ROW.store(0, core::sync::atomic::Ordering::Relaxed);
}

/// Scroll the live debug area up by one line.
///
/// Uses a single memmove to shift pixel data, then fills the exposed line
/// with the background colour (same technique as Linux fbcon).
fn vga_debug_scroll() {
    let fb_addr = PANIC_FB_ADDR.load(core::sync::atomic::Ordering::Acquire);
    if fb_addr == 0 {
        return;
    }
    let pitch = PANIC_FB_PITCH.load(core::sync::atomic::Ordering::Relaxed) as usize;
    let max_row = VGA_DEBUG_MAX_ROW.load(core::sync::atomic::Ordering::Relaxed);
    let fmt = PANIC_FB_FORMAT.load(core::sync::atomic::Ordering::Relaxed);
    let bpp = (fmt >> 32) as u16;
    let bpp_bytes = (bpp / 8) as usize;
    if bpp_bytes < 3 || pitch == 0 || max_row <= 1 {
        return;
    }

    let fb = fb_addr as *mut u8;
    let max_col = VGA_DEBUG_MAX_COL.load(core::sync::atomic::Ordering::Relaxed);
    let line_bytes = 16 * pitch; // one text row in bytes
    let total = (max_row - 1) * line_bytes; // all rows except the first
    let bg = panic_pack_rgb(fmt, 0x12, 0x16, 0x1E);

    unsafe {
        // Shift content up by one text line.
        core::ptr::copy(fb.add(line_bytes), fb, total);
        // Fill the newly exposed last line.
        let clear = fb.add((max_row - 1) * line_bytes);
        vga_debug_fill_line(clear, pitch, max_col, bpp_bytes, bg);
    }
}

/// Fill a single text line (16 pixel rows) with a solid colour.
/// `max_col` is the number of character columns (each 8px wide).
unsafe fn vga_debug_fill_line(
    base: *mut u8,
    pitch: usize,
    max_col: usize,
    bpp_bytes: usize,
    color: u32,
) {
    let fill_pixels = max_col * 8; // visible pixel width only
    if bpp_bytes == 4 {
        for row in 0..16 {
            let r = base.add(row * pitch) as *mut u32;
            for p in 0..fill_pixels {
                core::ptr::write_volatile(r.add(p), color);
            }
        }
    } else {
        let fill_bytes = fill_pixels * 3;
        for row in 0..16 {
            let r = base.add(row * pitch);
            for x in (0..fill_bytes).step_by(3) {
                core::ptr::write_volatile(r.add(x), color as u8);
                core::ptr::write_volatile(r.add(x + 1), (color >> 8) as u8);
                core::ptr::write_volatile(r.add(x + 2), (color >> 16) as u8);
            }
        }
    }
}

/// Clear a single 8×16 character cell with the background colour.
unsafe fn vga_debug_clear_cell(
    fb: *mut u8,
    pitch: usize,
    x: usize,
    y: usize,
    bpp_bytes: usize,
    bg: u32,
) {
    if bpp_bytes == 4 {
        let x_off = x * 4;
        for row in 0..16 {
            let r = fb.add((y + row) * pitch + x_off) as *mut u32;
            for c in 0..8 {
                core::ptr::write_volatile(r.add(c), bg);
            }
        }
    } else {
        for row in 0..16 {
            let r = fb.add((y + row) * pitch + x * 3);
            for c in 0..8 {
                let p = r.add(c * 3);
                core::ptr::write_volatile(p, bg as u8);
                core::ptr::write_volatile(p.add(1), (bg >> 8) as u8);
                core::ptr::write_volatile(p.add(2), (bg >> 16) as u8);
            }
        }
    }
}

/// Draw a single 8×16 character from the panic font.
///
/// First clears the entire cell with `bg`, then draws the glyph's foreground
/// pixels.  This guarantees crisp, ghost-free text (like Linux fbcon).
unsafe fn vga_debug_draw_glyph(
    fb: *mut u8,
    pitch: usize,
    x: usize,
    y: usize,
    ch: u8,
    fg: u32,
    bg: u32,
    bpp_bytes: usize,
) {
    // Clear cell first : no ghosting.
    vga_debug_clear_cell(fb, pitch, x, y, bpp_bytes, bg);

    let idx = if ch < 0x20 || ch > 0x7E {
        0usize
    } else {
        (ch - 0x20) as usize
    };
    let gs = idx * 16;

    if bpp_bytes == 4 {
        for row in 0..16 {
            let mask = PANIC_FONT_8X16[gs + row];
            if mask == 0 {
                continue;
            }
            let r = fb.add((y + row) * pitch + x * 4) as *mut u32;
            for col in 0..8 {
                if (mask >> (7 - col)) & 1 != 0 {
                    core::ptr::write_volatile(r.add(col), fg);
                }
            }
        }
    } else {
        for row in 0..16 {
            let mask = PANIC_FONT_8X16[gs + row];
            if mask == 0 {
                continue;
            }
            for col in 0..8 {
                if (mask >> (7 - col)) & 1 != 0 {
                    let p = fb.add((y + row) * pitch + (x + col) * 3);
                    core::ptr::write_volatile(p, fg as u8);
                    core::ptr::write_volatile(p.add(1), (fg >> 8) as u8);
                    core::ptr::write_volatile(p.add(2), (fg >> 16) as u8);
                }
            }
        }
    }
}

/// Write a string directly to the VGA framebuffer in real time.
///
/// Each character cell is cleared before drawing, preventing ghosting from
/// scrolling or rapid updates.  Colours are high-contrast (light grey on
/// dark navy : similar to Linux fbcon and FreeBSD vt(4)).
///
/// Newlines, carriage-returns, and tab stops are handled.  When the cursor
/// reaches the bottom of the debug area, the content scrolls up one line.
pub fn vga_debug_write(s: &str) {
    let fb_addr = PANIC_FB_ADDR.load(core::sync::atomic::Ordering::Acquire);
    if fb_addr == 0 {
        return;
    }

    let pitch = PANIC_FB_PITCH.load(core::sync::atomic::Ordering::Relaxed) as usize;
    let max_col = VGA_DEBUG_MAX_COL.load(core::sync::atomic::Ordering::Relaxed);
    let max_row = VGA_DEBUG_MAX_ROW.load(core::sync::atomic::Ordering::Relaxed);
    let fmt = PANIC_FB_FORMAT.load(core::sync::atomic::Ordering::Relaxed);
    let bpp = (fmt >> 32) as u16;
    let bpp_bytes = (bpp / 8) as usize;
    if max_col == 0 || max_row == 0 || pitch == 0 || bpp_bytes < 3 {
        return;
    }

    let fb = fb_addr as *mut u8;

    // High-contrast colours (Linux vt style: light grey on navy).
    let fg = panic_pack_rgb(fmt, 0xE2, 0xE8, 0xF0);
    let bg = panic_pack_rgb(fmt, 0x12, 0x16, 0x1E);

    let mut col = VGA_DEBUG_COL.load(core::sync::atomic::Ordering::Relaxed);
    let mut row = VGA_DEBUG_ROW.load(core::sync::atomic::Ordering::Relaxed);

    for &byte in s.as_bytes() {
        match byte {
            b'\n' => {
                col = 0;
                row += 1;
                if row >= max_row {
                    vga_debug_scroll();
                    row = max_row - 1;
                }
            }
            b'\r' => {
                col = 0;
            }
            b'\t' => {
                col = (col + 8) & !7;
                if col >= max_col {
                    col = 0;
                    row += 1;
                }
                if row >= max_row {
                    vga_debug_scroll();
                    row = max_row - 1;
                }
            }
            _ => {
                if col >= max_col {
                    col = 0;
                    row += 1;
                    if row >= max_row {
                        vga_debug_scroll();
                        row = max_row - 1;
                    }
                }
                // SAFETY: coordinates are bounded by max_col/max_row, pitch is valid.
                unsafe {
                    vga_debug_draw_glyph(fb, pitch, col * 8, row * 16, byte, fg, bg, bpp_bytes);
                }
                col += 1;
            }
        }
    }

    VGA_DEBUG_COL.store(col, core::sync::atomic::Ordering::Relaxed);
    VGA_DEBUG_ROW.store(row, core::sync::atomic::Ordering::Relaxed);
}

/// Write a newline-terminated line to the live VGA debug output.
pub fn vga_debug_writeln(s: &str) {
    let mut buf: [u8; 512] = [0u8; 512];
    let max = buf.len() - 1;
    let len = if s.len() > max {
        // Truncate at a valid UTF-8 boundary.
        let mut truncated = max;
        let bytes = s.as_bytes();
        while truncated > 0 && (bytes[truncated] & 0xC0) == 0x80 {
            truncated -= 1;
        }
        truncated
    } else {
        s.len()
    };
    buf[..len].copy_from_slice(&s.as_bytes()[..len]);
    buf[len] = b'\n';
    if let Ok(valid) = core::str::from_utf8(&buf[..len + 1]) {
        vga_debug_write(valid);
    }
}
