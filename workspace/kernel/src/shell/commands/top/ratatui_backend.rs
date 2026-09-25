//! Ratatui [`Backend`] on top of the Strat9 VGA framebuffer writer.
//!
//! Drawing is done cell by cell, so the backend resolves the console geometry
//! once per frame and holds the writer lock for the whole frame: going through
//! the `vga::fill_rect` / `vga::draw_text` free functions instead would take
//! and drop the writer lock several times per cell.
//!
//! Presentation is *not* owned here. Both callers (the `top` loop and the
//! one-shot `--gui` tables) bracket their frame with `vga::begin_frame()` and
//! `vga::end_frame()`, so [`Backend::flush`] stays a no-op.

use crate::arch::vga::{self, RgbColor, TextAlign, TextOptions, VgaWriter};
use core::fmt;
use ratatui::{
    backend::{Backend, ClearType, WindowSize},
    buffer::Cell,
    layout::{Position, Size},
    style::Color,
};

/// Caret color used when the TUI asks for a visible cursor.
const CURSOR_COLOR: RgbColor = RgbColor::new(0x4F, 0xB3, 0xB3);

#[derive(Debug, Clone, Copy)]
pub enum BackendError {
    FramebufferUnavailable,
}

impl fmt::Display for BackendError {
    /// Performs the fmt operation.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FramebufferUnavailable => write!(f, "framebuffer unavailable"),
        }
    }
}

impl core::error::Error for BackendError {}

/// Console geometry, resolved once per frame instead of once per cell.
#[derive(Clone, Copy, Default)]
struct Geometry {
    cols: usize,
    rows: usize,
    glyph_w: usize,
    glyph_h: usize,
}

impl Geometry {
    fn resolve() -> Self {
        let (glyph_w, glyph_h) = vga::glyph_size();
        Self {
            cols: vga::text_cols(),
            rows: vga::text_rows(),
            glyph_w,
            glyph_h,
        }
    }

    fn is_usable(&self) -> bool {
        self.glyph_w > 0 && self.glyph_h > 0 && self.cols > 0 && self.rows > 0
    }
}

pub struct Strat9RatatuiBackend {
    cursor: Position,
}

impl Strat9RatatuiBackend {
    /// Creates a new instance.
    pub fn new() -> Result<Self, BackendError> {
        if !vga::is_available() {
            return Err(BackendError::FramebufferUnavailable);
        }
        Ok(Self {
            cursor: Position { x: 0, y: 0 },
        })
    }

    /// Maps fg color.
    fn map_fg_color(color: Color) -> RgbColor {
        match color {
            Color::Reset => RgbColor::LIGHT_GREY,
            Color::Black => RgbColor::new(0x00, 0x00, 0x00),
            Color::Red => RgbColor::new(0x80, 0x00, 0x00),
            Color::Green => RgbColor::new(0x00, 0x80, 0x00),
            Color::Yellow => RgbColor::new(0x80, 0x80, 0x00),
            Color::Blue => RgbColor::new(0x00, 0x00, 0x80),
            Color::Magenta => RgbColor::new(0x80, 0x00, 0x80),
            Color::Cyan => RgbColor::new(0x00, 0x80, 0x80),
            Color::Gray => RgbColor::new(0xAA, 0xAA, 0xAA),
            Color::DarkGray => RgbColor::new(0x55, 0x55, 0x55),
            Color::LightRed => RgbColor::new(0xFF, 0x55, 0x55),
            Color::LightGreen => RgbColor::new(0x55, 0xFF, 0x55),
            Color::LightYellow => RgbColor::new(0xFF, 0xFF, 0x55),
            Color::LightBlue => RgbColor::new(0x55, 0x55, 0xFF),
            Color::LightMagenta => RgbColor::new(0xFF, 0x55, 0xFF),
            Color::LightCyan => RgbColor::new(0x55, 0xFF, 0xFF),
            Color::White => RgbColor::new(0xFF, 0xFF, 0xFF),
            Color::Rgb(r, g, b) => RgbColor::new(r, g, b),
            Color::Indexed(idx) => Self::map_indexed(idx),
        }
    }

    /// Maps bg color.
    fn map_bg_color(color: Color) -> RgbColor {
        match color {
            // For background, Reset should stay dark to match console expectations.
            Color::Reset => RgbColor::BLACK,
            _ => Self::map_fg_color(color),
        }
    }

    /// Maps the 256-color palette onto the framebuffer: the ANSI 16 colors for
    /// the first entries, a gray ramp above them.
    fn map_indexed(idx: u8) -> RgbColor {
        const ANSI_16: [RgbColor; 16] = [
            RgbColor::new(0x00, 0x00, 0x00),
            RgbColor::new(0x80, 0x00, 0x00),
            RgbColor::new(0x00, 0x80, 0x00),
            RgbColor::new(0x80, 0x80, 0x00),
            RgbColor::new(0x00, 0x00, 0x80),
            RgbColor::new(0x80, 0x00, 0x80),
            RgbColor::new(0x00, 0x80, 0x80),
            RgbColor::new(0xAA, 0xAA, 0xAA),
            RgbColor::new(0x55, 0x55, 0x55),
            RgbColor::new(0xFF, 0x55, 0x55),
            RgbColor::new(0x55, 0xFF, 0x55),
            RgbColor::new(0xFF, 0xFF, 0x55),
            RgbColor::new(0x55, 0x55, 0xFF),
            RgbColor::new(0xFF, 0x55, 0xFF),
            RgbColor::new(0x55, 0xFF, 0xFF),
            RgbColor::new(0xFF, 0xFF, 0xFF),
        ];
        match ANSI_16.get(idx as usize) {
            Some(color) => *color,
            None => RgbColor::new(idx, idx, idx),
        }
    }

    /// Performs the normalize symbol operation.
    ///
    /// The console font is ASCII only, so box drawing and block glyphs are
    /// downgraded to their closest printable equivalent.
    fn normalize_symbol(symbol: &str) -> char {
        let ch = symbol.chars().next().unwrap_or(' ');
        match ch {
            // Box drawing fallback
            '│' | '┃' => '|',
            '─' | '━' => '-',
            '┌' | '┐' | '└' | '┘' | '├' | '┤' | '┬' | '┴' | '┼' => '+',
            // Block/shade fallback (used by gauges/progress)
            '█' | '▇' | '▆' | '▅' | '▄' | '▃' | '▂' | '▁' | '░' | '▒' | '▓' => {
                '#'
            }
            // Keep printable ASCII as-is.
            c if c.is_ascii_graphic() || c == ' ' => c,
            _ => '?',
        }
    }

    /// Draws one cell, with the writer already borrowed for the whole frame.
    fn draw_cell(writer: &mut VgaWriter, geo: Geometry, x: u16, y: u16, cell: &Cell) {
        if x as usize >= geo.cols || y as usize >= geo.rows {
            return;
        }

        let px = x as usize * geo.glyph_w;
        let py = y as usize * geo.glyph_h;
        let bg = Self::map_bg_color(cell.bg);
        let fg = Self::map_fg_color(cell.fg);

        writer.fill_rect(px, py, geo.glyph_w, geo.glyph_h, bg);

        #[allow(deprecated)]
        let symbol = if cell.skip { " " } else { cell.symbol() };
        let ch = Self::normalize_symbol(symbol);
        if ch != ' ' {
            let mut one = [0u8; 4];
            let text = ch.encode_utf8(&mut one);
            let _ = writer.draw_text(
                px,
                py,
                text,
                TextOptions {
                    fg,
                    bg,
                    align: TextAlign::Left,
                    wrap: false,
                    max_width: Some(geo.glyph_w),
                },
            );
        }
    }
}

impl Backend for Strat9RatatuiBackend {
    type Error = BackendError;

    /// Performs the draw operation.
    fn draw<'a, I>(&mut self, content: I) -> Result<(), Self::Error>
    where
        I: Iterator<Item = (u16, u16, &'a Cell)>,
    {
        let geo = Geometry::resolve();
        if !geo.is_usable() {
            return Err(BackendError::FramebufferUnavailable);
        }
        vga::with_writer(|writer| {
            for (x, y, cell) in content {
                Self::draw_cell(writer, geo, x, y, cell);
            }
        })
        .ok_or(BackendError::FramebufferUnavailable)
    }

    /// Performs the hide cursor operation.
    fn hide_cursor(&mut self) -> Result<(), Self::Error> {
        // The caret is a framebuffer overlay re-drawn on every present: it has
        // to be hidden on the VGA side, not just tracked here.
        vga::hide_text_cursor();
        Ok(())
    }

    /// Performs the show cursor operation.
    fn show_cursor(&mut self) -> Result<(), Self::Error> {
        vga::draw_text_cursor(CURSOR_COLOR);
        Ok(())
    }

    /// Returns cursor position.
    fn get_cursor_position(&mut self) -> Result<Position, Self::Error> {
        Ok(self.cursor)
    }

    /// Sets cursor position.
    fn set_cursor_position<P: Into<Position>>(&mut self, position: P) -> Result<(), Self::Error> {
        let pos = position.into();
        self.cursor = pos;
        vga::set_text_cursor(pos.x as usize, pos.y as usize);
        Ok(())
    }

    /// Performs the clear operation.
    fn clear(&mut self) -> Result<(), Self::Error> {
        vga::fill_rect(0, 0, vga::width(), vga::height(), RgbColor::BLACK);
        Ok(())
    }

    /// Performs the clear region operation.
    ///
    /// Regions are expressed in character cells, so the clear honors the
    /// console geometry instead of blanking the whole screen.
    fn clear_region(&mut self, clear_type: ClearType) -> Result<(), Self::Error> {
        let geo = Geometry::resolve();
        if !geo.is_usable() {
            return Err(BackendError::FramebufferUnavailable);
        }
        let cx = (self.cursor.x as usize).min(geo.cols - 1);
        let cy = (self.cursor.y as usize).min(geo.rows - 1);

        // (first column, first row, column count, row count), in cells.
        let (x, y, w, h) = match clear_type {
            ClearType::All => return self.clear(),
            ClearType::AfterCursor => (cx, cy, geo.cols - cx, geo.rows - cy),
            ClearType::BeforeCursor => (0, 0, cx + 1, cy + 1),
            ClearType::CurrentLine => (0, cy, geo.cols, 1),
            ClearType::UntilNewLine => (cx, cy, geo.cols - cx, 1),
        };
        if w == 0 || h == 0 {
            return Ok(());
        }
        vga::fill_rect(
            x * geo.glyph_w,
            y * geo.glyph_h,
            w * geo.glyph_w,
            h * geo.glyph_h,
            RgbColor::BLACK,
        );
        Ok(())
    }

    /// Performs the size operation.
    fn size(&self) -> Result<Size, Self::Error> {
        if !vga::is_available() {
            return Err(BackendError::FramebufferUnavailable);
        }
        Ok(Size::new(vga::text_cols() as u16, vga::text_rows() as u16))
    }

    /// Performs the window size operation.
    fn window_size(&mut self) -> Result<WindowSize, Self::Error> {
        if !vga::is_available() {
            return Err(BackendError::FramebufferUnavailable);
        }
        Ok(WindowSize {
            columns_rows: Size::new(vga::text_cols() as u16, vga::text_rows() as u16),
            pixels: Size::new(vga::width() as u16, vga::height() as u16),
        })
    }

    /// Performs the flush operation.
    ///
    /// No-op by design: the caller brackets the frame with `vga::begin_frame()`
    /// and `vga::end_frame()` / `vga::present()`.
    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}
