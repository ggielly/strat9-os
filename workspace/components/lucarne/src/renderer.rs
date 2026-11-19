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

//! Cell-grid renderer into a Vasistas SHM pixel buffer.
//!
//! Same glyph model as strate-console's renderer (8x16 cells, FONT_8X16,
//! MSB-left bit order, inverse-video cursor), but the target is a
//! client-owned XRGB8888 buffer instead of `/dev/vasistas`: one u32 per
//! pixel, little-endian, at `(col * CELL_W, row * CELL_H)`.

use terminal_core::{font_data::FONT_8X16, Cell, TerminalCore};
use vasistas_client::Buffer;

/// Glyph cell size in pixels.
pub const CELL_W: usize = 8;
pub const CELL_H: usize = 16;
/// Glyphs in the shared font (ASCII 0x20..=0x7E).
const GLYPHS: u32 = 95;

/// Paint the whole visible grid into `buffer`.
pub fn render_screen(buffer: &mut Buffer, term: &TerminalCore, cursor_visible: bool) {
    let stride = buffer.stride as usize;
    let pixels = buffer.pixels_mut();
    for row in 0..term.rows {
        for col in 0..term.cols {
            let cell = term.screen[row][col];
            let cursor = cursor_visible && row == term.cursor_row && col == term.cursor_col;
            draw_cell(pixels, stride, row, col, cell, cursor);
        }
    }
}

/// Paint one cell: the blink tick's cursor-cell repaint.
pub fn render_cell(
    buffer: &mut Buffer,
    term: &TerminalCore,
    row: usize,
    col: usize,
    cursor_visible: bool,
) {
    let stride = buffer.stride as usize;
    let pixels = buffer.pixels_mut();
    draw_cell(pixels, stride, row, col, term.screen[row][col], cursor_visible);
}

/// Draw one 8x16 cell; the cursor cell is inverse video, mirroring
/// strate-console's cursor treatment.
fn draw_cell(
    pixels: &mut [u8],
    stride: usize,
    row: usize,
    col: usize,
    cell: Cell,
    cursor: bool,
) {
    let (fg, bg) = if cursor { (cell.bg, cell.fg) } else { (cell.fg, cell.bg) };
    let bits = glyph_bits(cell.ch);
    let base = row * CELL_H * stride + col * CELL_W * 4;
    for gy in 0..CELL_H {
        let row_bits = bits[gy];
        for gx in 0..CELL_W {
            let color = if (row_bits >> (7 - gx)) & 1 != 0 { fg } else { bg };
            let offset = base + gy * stride + gx * 4;
            pixels[offset..offset + 4].copy_from_slice(&color.to_le_bytes());
        }
    }
}

/// Bitmap rows for `ch`: the shared ASCII font; anything outside its range
/// has no glyph and paints blank (background only).
fn glyph_bits(ch: u32) -> [u8; CELL_H] {
    if (0x20..0x20 + GLYPHS).contains(&ch) {
        FONT_8X16[(ch - 0x20) as usize]
    } else {
        [0; CELL_H]
    }
}
