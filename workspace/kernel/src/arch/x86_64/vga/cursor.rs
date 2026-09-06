//! Cursor manager for the framebuffer terminal.
//!
//! Owns the mouse-cursor and text-cursor state (position, visibility, saved
//! pixels) and provides methods to save/restore/draw them directly to the
//! hardware framebuffer via [`CanvasBuffer`].

use super::types::PixelFormat;
use crate::framebuffer::{CanvasBuffer, RgbColor};

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
/// **Mouse cursor** – a small arrow sprite that can be saved/restored/drawn.
/// **Text cursor** – a blinking underline / block that follows the text input
/// position.
pub(crate) struct CursorManager {
    // -- Mouse cursor -------------------------------------------------------
    pub mc_x: i32,
    pub mc_y: i32,
    pub mc_visible: bool,
    pub mc_dirty: bool,
    pub mc_save: [u32; CURSOR_W * CURSOR_H],

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
            mc_dirty: false,
            mc_save: [0u32; CURSOR_W * CURSOR_H],
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
    // Mouse cursor
    // ========================================================================

    /// Save the pixels under the mouse cursor into `mc_save`.
    /// Sets `mc_dirty = true` so `present()` will redraw.
    pub fn mc_save_hw(&mut self, canvas: &CanvasBuffer) {
        self.mc_dirty = true;
        let x = self.mc_x;
        let y = self.mc_y;
        for cy in 0..CURSOR_H {
            for cx in 0..CURSOR_W {
                let px = x + cx as i32;
                let py = y + cy as i32;
                if px < 0 || py < 0 || px as usize >= canvas.width || py as usize >= canvas.height {
                    self.mc_save[cy * CURSOR_W + cx] = 0;
                    continue;
                }
                self.mc_save[cy * CURSOR_W + cx] = canvas.read_hw_pixel(px as usize, py as usize);
            }
        }
    }

    /// Draw the mouse cursor sprite onto the hardware framebuffer.
    pub fn mc_draw_hw(&mut self, canvas: &mut CanvasBuffer, fmt: &PixelFormat) {
        let x = self.mc_x;
        let y = self.mc_y;
        let black = fmt.pack_rgb(RgbColor::BLACK.r, RgbColor::BLACK.g, RgbColor::BLACK.b);
        let white = fmt.pack_rgb(RgbColor::WHITE.r, RgbColor::WHITE.g, RgbColor::WHITE.b);
        for cy in 0..CURSOR_H {
            for cx in 0..CURSOR_W {
                let p = CURSOR_PIXELS[cy * CURSOR_W + cx];
                if p == 0 {
                    continue;
                }
                let px = x + cx as i32;
                let py = y + cy as i32;
                if px < 0 || py < 0 || px as usize >= canvas.width || py as usize >= canvas.height {
                    continue;
                }
                let color = if p == 1 { black } else { white };
                canvas.write_hw_pixel(px as usize, py as usize, color);
            }
        }
    }

    /// Erase the mouse cursor by restoring the saved pixels.
    /// Sets `mc_dirty = true` so the next `present()` flushes the change.
    pub fn mc_erase_hw(&mut self, canvas: &mut CanvasBuffer) {
        self.mc_dirty = true;
        let x = self.mc_x;
        let y = self.mc_y;
        for cy in 0..CURSOR_H {
            for cx in 0..CURSOR_W {
                if CURSOR_PIXELS[cy * CURSOR_W + cx] == 0 {
                    continue;
                }
                let px = x + cx as i32;
                let py = y + cy as i32;
                if px < 0 || py < 0 || px as usize >= canvas.width || py as usize >= canvas.height {
                    continue;
                }
                canvas.write_hw_pixel(px as usize, py as usize, self.mc_save[cy * CURSOR_W + cx]);
            }
        }
    }

    /// Update mouse cursor position (save old area, redraw at new position).
    pub fn update_mouse_cursor(
        &mut self,
        x: i32,
        y: i32,
        canvas: &mut CanvasBuffer,
        fmt: &PixelFormat,
    ) -> bool {
        let moved = self.mc_visible && (self.mc_x != x || self.mc_y != y);
        let needs_redraw = !self.mc_visible || moved;

        if moved {
            self.mc_erase_hw(canvas);
        }
        if needs_redraw {
            self.mc_x = x;
            self.mc_y = y;
            self.mc_save_hw(canvas);
            self.mc_draw_hw(canvas, fmt);
            self.mc_visible = true;
        }
        needs_redraw
    }

    /// Hide the mouse cursor.
    pub fn hide_mouse_cursor(&mut self, canvas: &mut CanvasBuffer) {
        if self.mc_visible {
            self.mc_erase_hw(canvas);
            self.mc_visible = false;
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
