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

//! Cursor manager for the framebuffer terminal.
//!
//! Owns the mouse-cursor and text-cursor state and provides methods to
//! save/restore/draw the text cursor directly to the hardware framebuffer via
//! [`CanvasBuffer`]. The mouse cursor is a present-time overlay in
//! `writer.rs`; only its state lives here.

use crate::framebuffer::CanvasBuffer;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Mouse-cursor sprite width (pixels).
pub(crate) const CURSOR_W: usize = 12;
/// Mouse-cursor sprite height (pixels).
pub(crate) const CURSOR_H: usize = 16;
/// Maximum text-cursor width or height (pixels).
pub(crate) const TEXT_CURSOR_MAX_DIM: usize = 32;

/// Mouse cursor sprite: 0=transparent, 1=black outline, 2=white fill.
#[rustfmt::skip]
pub(crate) const CURSOR_PIXELS: [u8; CURSOR_W * CURSOR_H] = [
    1,0,0,0,0,0,0,0,0,0,0,0,
    1,1,0,0,0,0,0,0,0,0,0,0,
    1,2,1,0,0,0,0,0,0,0,0,0,
    1,2,2,1,0,0,0,0,0,0,0,0,
    1,2,2,2,1,0,0,0,0,0,0,0,
    1,2,2,2,2,1,0,0,0,0,0,0,
    1,2,2,2,2,2,1,0,0,0,0,0,
    1,2,2,2,2,2,2,1,0,0,0,0,
    1,2,2,2,2,2,2,2,1,0,0,0,
    1,2,2,2,2,2,1,1,0,0,0,0,
    1,2,2,2,1,0,0,0,0,0,0,0,
    1,2,1,1,2,2,1,0,0,0,0,0,
    1,1,0,0,1,2,2,1,0,0,0,0,
    0,0,0,0,0,1,2,1,0,0,0,0,
    0,0,0,0,0,0,1,1,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,
];

// ---------------------------------------------------------------------------
// CursorManager
// ---------------------------------------------------------------------------

/// Holds all cursor-related state for the framebuffer terminal.
///
/// **Mouse cursor** – state only; the sprite is an overlay drawn at present.
/// **Text cursor** – a blinking underline / block that follows the text input
/// position.
pub(crate) struct CursorManager {
    // -- Mouse cursor -------------------------------------------------------
    pub mc_x: i32,
    pub mc_y: i32,
    pub mc_visible: bool,

    // -- Text cursor --------------------------------------------------------
    pub tc_col: usize,
    pub tc_row: usize,
    pub tc_w: usize,
    pub tc_h: usize,
    pub tc_visible: bool,
    pub tc_dirty: bool,
    pub tc_color: u32,
    pub tc_save: [u32; TEXT_CURSOR_MAX_DIM * TEXT_CURSOR_MAX_DIM],
}

impl CursorManager {
    /// Create a new cursor manager with all cursors hidden.
    pub const fn new() -> Self {
        Self {
            mc_x: 0,
            mc_y: 0,
            mc_visible: false,
            tc_col: 0,
            tc_row: 0,
            tc_w: 0,
            tc_h: 0,
            tc_visible: false,
            tc_dirty: false,
            tc_color: 0,
            tc_save: [0u32; TEXT_CURSOR_MAX_DIM * TEXT_CURSOR_MAX_DIM],
        }
    }

    // ========================================================================
    // Text cursor
    // ========================================================================

    /// Calculate the pixel rectangle for the text cursor at `(col, row)`.
    pub fn text_cursor_rect(
        &self,
        col: usize,
        row: usize,
        glyph_w: usize,
        glyph_h: usize,
    ) -> (usize, usize, usize, usize) {
        let tw = glyph_w.min(TEXT_CURSOR_MAX_DIM);
        let th = glyph_h.min(TEXT_CURSOR_MAX_DIM);
        (col * glyph_w, row * glyph_h, tw, th)
    }

    /// Save the pixels under the text cursor.
    pub fn text_cursor_save_hw(
        &mut self,
        col: usize,
        row: usize,
        glyph_w: usize,
        glyph_h: usize,
        canvas: &CanvasBuffer,
    ) {
        let (tx, ty, tw, th) = self.text_cursor_rect(col, row, glyph_w, glyph_h);
        for dy in 0..th {
            for dx in 0..tw {
                let px = tx + dx;
                let py = ty + dy;
                if px < canvas.width && py < canvas.height {
                    self.tc_save[dy * tw + dx] = canvas.read_hw_pixel(px, py);
                }
            }
        }
    }

    /// Draw the text cursor (inverted-colour block) on the hardware framebuffer.
    /// Resets `tc_dirty = false` after drawing.
    pub fn text_cursor_draw_hw(
        &mut self,
        col: usize,
        row: usize,
        glyph_w: usize,
        glyph_h: usize,
        color: u32,
        canvas: &mut CanvasBuffer,
    ) {
        self.tc_dirty = false;
        let (tx, ty, tw, th) = self.text_cursor_rect(col, row, glyph_w, glyph_h);
        for dy in 0..th {
            for dx in 0..tw {
                let px = tx + dx;
                let py = ty + dy;
                if px < canvas.width && py < canvas.height {
                    canvas.write_hw_pixel(px, py, color);
                }
            }
        }
    }

    /// Erase the text cursor by restoring the saved pixels.
    /// Sets `tc_dirty = true` so the next `present()` flushes.
    pub fn text_cursor_erase_hw(
        &mut self,
        col: usize,
        row: usize,
        glyph_w: usize,
        glyph_h: usize,
        canvas: &mut CanvasBuffer,
    ) {
        let (tx, ty, tw, th) = self.text_cursor_rect(col, row, glyph_w, glyph_h);
        for dy in 0..th {
            for dx in 0..tw {
                let px = tx + dx;
                let py = ty + dy;
                if px < canvas.width && py < canvas.height {
                    canvas.write_hw_pixel(px, py, self.tc_save[dy * tw + dx]);
                }
            }
        }
    }

    /// Draw the text cursor as a solid-colour overlay at the given position.
    pub fn draw_text_cursor_overlay(
        &mut self,
        col: usize,
        row: usize,
        glyph_w: usize,
        glyph_h: usize,
        color: u32,
        canvas: &mut CanvasBuffer,
    ) {
        self.text_cursor_draw_hw(col, row, glyph_w, glyph_h, color, canvas);
    }

    /// Hide the text cursor.
    pub fn hide_text_cursor(
        &mut self,
        col: usize,
        row: usize,
        glyph_w: usize,
        glyph_h: usize,
        canvas: &mut CanvasBuffer,
    ) {
        if self.tc_visible {
            self.text_cursor_erase_hw(col, row, glyph_w, glyph_h, canvas);
            self.tc_visible = false;
        }
    }
}
