//! Console renderer: glyph cache, dirty rect tracking, framebuffer present.
//! Uses /dev/display/0.0 for output.

use crate::scrollback::Cell;
use strat9_syscall::call;

const GLYPH_W: usize = 8;
const GLYPH_H: usize = 16;
const MAX_COLS: usize = 256;
const MAX_ROWS: usize = 64;

static FONT_8X16: [[u8; 16]; 95] = include!("font_data.rs");

pub struct Renderer {
    fb_fd: usize,
    fb_width: usize,
    fb_height: usize,
    pub cols: usize,
    pub rows: usize,
    prev_cells: [[Cell; MAX_COLS]; MAX_ROWS],
    prev_initialized: bool,
}

// SAFETY: Renderer contains only an fd (usize, integer type always Send)
// and plain data (arrays of Cell which is Copy). No mutable aliasing across
// threads occurs because only the main event loop accesses the Renderer.
unsafe impl Send for Renderer {}

impl Renderer {
    pub fn open() -> Option<Self> {
        let fd = call::openat(0, "/dev/display/0.0", 0x1, 0).ok()?;
        let info_fd = call::openat(0, "/dev/display/info", 0x1, 0).ok()?;
        let mut info_buf = [0u8; 256];
        let _ = call::read(info_fd, &mut info_buf);
        let _ = call::close(info_fd);

        let info_str = core::str::from_utf8(&info_buf).unwrap_or("display.0=800x600");
        let (w, h) = parse_display_size(info_str).unwrap_or((800, 600));

        let cols = w / GLYPH_W;
        let rows = h / GLYPH_H;
        let blank = Cell::blank(0xE2E8F0, 0x12161E);

        Some(Renderer {
            fb_fd: fd,
            fb_width: w,
            fb_height: h,
            cols: cols.min(MAX_COLS),
            rows: rows.max(1).min(MAX_ROWS),
            prev_cells: [[blank; MAX_COLS]; MAX_ROWS],
            prev_initialized: false,
        })
    }

    pub fn render(
        &mut self,
        cells: &[[Cell; MAX_COLS]; MAX_ROWS],
        cursor_row: usize,
        cursor_col: usize,
        rows: usize,
    ) {
        for row in 0..rows.min(self.rows) {
            for col in 0..self.cols {
                let cell = cells[row][col];
                let prev = if self.prev_initialized {
                    self.prev_cells[row][col]
                } else {
                    Cell::blank(0xE2E8F0, 0x12161E)
                };
                let is_cursor = row == cursor_row && col == cursor_col;
                if !is_cursor && cell.ch == prev.ch && cell.fg == prev.fg && cell.bg == prev.bg {
                    continue;
                }
                self.render_glyph(col, row, &cell, is_cursor);
                self.prev_cells[row][col] = cell;
            }
        }
        self.prev_initialized = true;
        let _ = call::write(self.fb_fd, b"present");
    }

    fn render_glyph(&self, col: usize, row: usize, cell: &Cell, is_cursor: bool) {
        let x = (col * GLYPH_W) as u16;
        let y = (row * GLYPH_H) as u16;
        let (fg, bg) = if is_cursor {
            (cell.bg, cell.fg)
        } else {
            (cell.fg, cell.bg)
        };

        let glyph_idx = (cell.ch as usize).wrapping_sub(0x20);
        let glyph = if glyph_idx < 95 {
            &FONT_8X16[glyph_idx]
        } else {
            &FONT_8X16[0]
        };

        let mut pixel_data = [0u8; 4 + GLYPH_W * GLYPH_H * 3];
        pixel_data[0] = x as u8;
        pixel_data[1] = (x >> 8) as u8;
        pixel_data[2] = y as u8;
        pixel_data[3] = (y >> 8) as u8;

        let mut offset = 4;
        for row_bit in 0..GLYPH_H {
            let row_bits = glyph[row_bit];
            for col_bit in 0..GLYPH_W {
                let bit = (row_bits >> (7 - col_bit)) & 1;
                let color = if bit != 0 { fg } else { bg };
                pixel_data[offset] = (color >> 16) as u8;
                pixel_data[offset + 1] = (color >> 8) as u8;
                pixel_data[offset + 2] = color as u8;
                offset += 3;
            }
        }
        let _ = call::write(self.fb_fd, &pixel_data[..offset]);
    }
}

fn parse_display_size(info: &str) -> Option<(usize, usize)> {
    for line in info.lines() {
        // Accept both "display.0=800x600" and "display/0=800x600" formats.
        if let Some(eq_pos) = line.find('=') {
            let val = &line[eq_pos + 1..];
            // Try 'x' separator first, then 'x' with optional whitespace.
            let x_pos = val.find('x').or_else(|| val.find('×'))?;
            let w: usize = val[..x_pos].trim().parse().ok()?;
            let h: usize = val[x_pos + 1..].trim().parse().ok()?;
            if w > 0 && h > 0 {
                return Some((w, h));
            }
        }
    }
    // Fallback: try to find any two numbers separated by 'x' in the whole string.
    None
}
