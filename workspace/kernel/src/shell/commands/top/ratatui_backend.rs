use crate::arch::x86_64::vga::{self, RgbColor, TextAlign, TextOptions};
use core::fmt;
use ratatui::{
    backend::{Backend, ClearType, WindowSize},
    buffer::Cell,
    layout::{Position, Size},
    style::Color,
};

#[derive(Debug, Clone, Copy)]
pub enum BackendError {
    FramebufferUnavailable,
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FramebufferUnavailable => write!(f, "framebuffer unavailable"),
        }
    }
}

impl core::error::Error for BackendError {}

pub struct Strat9RatatuiBackend {
    cursor: Position,
    cursor_visible: bool,
}

impl Strat9RatatuiBackend {
    pub fn new() -> Result<Self, BackendError> {
        if !vga::is_available() {
            return Err(BackendError::FramebufferUnavailable);
        }
        Ok(Self {
            cursor: Position { x: 0, y: 0 },
            cursor_visible: false,
        })
    }

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
            Color::Indexed(idx) => {
                // ANSI 16-color fallback + grayscale for higher indices.
                let basic = match idx & 0x0F {
                    0 => RgbColor::new(0x00, 0x00, 0x00),
                    1 => RgbColor::new(0x80, 0x00, 0x00),
                    2 => RgbColor::new(0x00, 0x80, 0x00),
                    3 => RgbColor::new(0x80, 0x80, 0x00),
                    4 => RgbColor::new(0x00, 0x00, 0x80),
                    5 => RgbColor::new(0x80, 0x00, 0x80),
                    6 => RgbColor::new(0x00, 0x80, 0x80),
                    7 => RgbColor::new(0xAA, 0xAA, 0xAA),
                    8 => RgbColor::new(0x55, 0x55, 0x55),
                    9 => RgbColor::new(0xFF, 0x55, 0x55),
                    10 => RgbColor::new(0x55, 0xFF, 0x55),
                    11 => RgbColor::new(0xFF, 0xFF, 0x55),
                    12 => RgbColor::new(0x55, 0x55, 0xFF),
                    13 => RgbColor::new(0xFF, 0x55, 0xFF),
                    14 => RgbColor::new(0x55, 0xFF, 0xFF),
                    _ => RgbColor::new(0xFF, 0xFF, 0xFF),
                };
                if idx < 16 {
                    basic
                } else {
                    let g = idx;
                    RgbColor::new(g, g, g)
                }
            }
        }
    }

    fn map_bg_color(color: Color) -> RgbColor {
        match color {
            // For background, Reset should stay dark to match console expectations.
            Color::Reset => RgbColor::BLACK,
            _ => Self::map_fg_color(color),
        }
    }

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
            // Keep printable ASCII and Latin-1 letters/numbers as-is.
            c if c.is_ascii_graphic() || c == ' ' => c,
            _ => '?',
        }
    }

    fn draw_cell(&self, x: u16, y: u16, cell: &Cell) {
        if cell.skip {
            return;
        }
        let cols = vga::text_cols();
        let rows = vga::text_rows();
        if x as usize >= cols || y as usize >= rows {
            return;
        }

        let (gw, gh) = vga::glyph_size();
        if gw == 0 || gh == 0 {
            return;
        }
        let px = x as usize * gw;
        let py = y as usize * gh;
        let bg = Self::map_bg_color(cell.bg);
        let fg = Self::map_fg_color(cell.fg);

        vga::fill_rect(px, py, gw, gh, bg);

        let symbol = cell.symbol();
        let ch = Self::normalize_symbol(symbol);
        if ch != ' ' {
            let mut one = [0u8; 4];
            let text = ch.encode_utf8(&mut one);
            let opts = TextOptions {
                fg,
                bg,
                align: TextAlign::Left,
                wrap: false,
                max_width: Some(gw),
            };
            let _ = vga::draw_text(px, py, text, opts);
        }
    }
}

impl Backend for Strat9RatatuiBackend {
    type Error = BackendError;

    fn draw<'a, I>(&mut self, content: I) -> Result<(), Self::Error>
    where
        I: Iterator<Item = (u16, u16, &'a Cell)>,
    {
        if !vga::is_available() {
            return Err(BackendError::FramebufferUnavailable);
        }
        for (x, y, cell) in content {
            self.draw_cell(x, y, cell);
        }
        Ok(())
    }

    fn hide_cursor(&mut self) -> Result<(), Self::Error> {
        self.cursor_visible = false;
        Ok(())
    }

    fn show_cursor(&mut self) -> Result<(), Self::Error> {
        self.cursor_visible = true;
        Ok(())
    }

    fn get_cursor_position(&mut self) -> Result<Position, Self::Error> {
        Ok(self.cursor)
    }

    fn set_cursor_position<P: Into<Position>>(&mut self, position: P) -> Result<(), Self::Error> {
        let pos = position.into();
        self.cursor = pos;
        vga::set_text_cursor(pos.x as usize, pos.y as usize);
        Ok(())
    }

    fn clear(&mut self) -> Result<(), Self::Error> {
        if !vga::is_available() {
            return Err(BackendError::FramebufferUnavailable);
        }
        vga::fill_rect(0, 0, vga::width(), vga::height(), RgbColor::BLACK);
        Ok(())
    }

    fn clear_region(&mut self, clear_type: ClearType) -> Result<(), Self::Error> {
        match clear_type {
            ClearType::All => self.clear(),
            _ => self.clear(),
        }
    }

    fn size(&self) -> Result<Size, Self::Error> {
        if !vga::is_available() {
            return Err(BackendError::FramebufferUnavailable);
        }
        Ok(Size::new(vga::text_cols() as u16, vga::text_rows() as u16))
    }

    fn window_size(&mut self) -> Result<WindowSize, Self::Error> {
        if !vga::is_available() {
            return Err(BackendError::FramebufferUnavailable);
        }
        Ok(WindowSize {
            columns_rows: Size::new(vga::text_cols() as u16, vga::text_rows() as u16),
            pixels: Size::new(vga::width() as u16, vga::height() as u16),
        })
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        if !vga::is_available() {
            return Err(BackendError::FramebufferUnavailable);
        }
        Ok(())
    }
}
