//! VGA color types, UI theme/layout types, and terminal widget types.

pub use crate::framebuffer::RgbColor;
use alloc::{string::String, vec::Vec};

/// VGA colors mapped to RGB for text rendering.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum Color {
    Black = 0x0,
    Blue = 0x1,
    Green = 0x2,
    Cyan = 0x3,
    Red = 0x4,
    Magenta = 0x5,
    Brown = 0x6,
    LightGrey = 0x7,
    DarkGrey = 0x8,
    LightBlue = 0x9,
    LightGreen = 0xA,
    LightCyan = 0xB,
    LightRed = 0xC,
    LightMagenta = 0xD,
    Yellow = 0xE,
    White = 0xF,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextAlign {
    Left,
    Center,
    Right,
}

#[derive(Debug, Clone, Copy)]
pub struct TextOptions {
    pub fg: RgbColor,
    pub bg: RgbColor,
    pub align: TextAlign,
    pub wrap: bool,
    pub max_width: Option<usize>,
}

impl TextOptions {
    /// Creates a new instance.
    pub const fn new(fg: RgbColor, bg: RgbColor) -> Self {
        Self {
            fg,
            bg,
            align: TextAlign::Left,
            wrap: false,
            max_width: None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TextMetrics {
    pub width: usize,
    pub height: usize,
    pub lines: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct SpriteRgba<'a> {
    pub width: usize,
    pub height: usize,
    pub pixels: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
pub struct UiTheme {
    pub background: RgbColor,
    pub panel_bg: RgbColor,
    pub panel_border: RgbColor,
    pub text: RgbColor,
    pub accent: RgbColor,
    pub status_bg: RgbColor,
    pub status_text: RgbColor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiScale {
    Compact = 1,
    Normal = 2,
    Large = 3,
}

impl UiScale {
    /// Performs the factor operation.
    pub const fn factor(self) -> usize {
        self as usize
    }
}

impl UiTheme {
    pub const SLATE: Self = Self {
        background: RgbColor::new(0x12, 0x16, 0x1E),
        panel_bg: RgbColor::new(0x1A, 0x22, 0x2C),
        panel_border: RgbColor::new(0x3D, 0x52, 0x66),
        text: RgbColor::new(0xE2, 0xE8, 0xF0),
        accent: RgbColor::new(0x4F, 0xB3, 0xB3),
        status_bg: RgbColor::new(0x0E, 0x13, 0x1A),
        status_text: RgbColor::new(0xD3, 0xDE, 0xEA),
    };

    pub const SAND: Self = Self {
        background: RgbColor::new(0xFA, 0xF6, 0xEF),
        panel_bg: RgbColor::new(0xF1, 0xE8, 0xD8),
        panel_border: RgbColor::new(0xA6, 0x8F, 0x6A),
        text: RgbColor::new(0x2B, 0x2B, 0x2B),
        accent: RgbColor::new(0x1F, 0x7A, 0x8C),
        status_bg: RgbColor::new(0xE6, 0xD7, 0xBF),
        status_text: RgbColor::new(0x2B, 0x2B, 0x2B),
    };

    pub const OCEAN_STATUS: Self = Self {
        background: RgbColor::new(0x12, 0x16, 0x1E),
        panel_bg: RgbColor::new(0x1A, 0x22, 0x2C),
        panel_border: RgbColor::new(0x3D, 0x52, 0x66),
        text: RgbColor::new(0xE2, 0xE8, 0xF0),
        accent: RgbColor::new(0x4F, 0xB3, 0xB3),
        status_bg: RgbColor::new(0x1B, 0x4D, 0x8A),
        status_text: RgbColor::new(0xF5, 0xFA, 0xFF),
    };
}

#[derive(Debug, Clone, Copy, Default)]
pub struct UiRect {
    pub x: usize,
    pub y: usize,
    pub w: usize,
    pub h: usize,
}

impl UiRect {
    /// Creates a new instance.
    pub const fn new(x: usize, y: usize, w: usize, h: usize) -> Self {
        Self { x, y, w, h }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum DockEdge {
    Top,
    Bottom,
    Left,
    Right,
}

#[derive(Debug, Clone, Copy)]
pub struct UiDockLayout {
    pub(crate) remaining: UiRect,
}

impl UiDockLayout {
    /// Builds this from screen.
    pub fn from_screen() -> Self {
        Self {
            remaining: UiRect::new(0, 0, super::api::width(), super::api::height()),
        }
    }

    /// Builds this from rect.
    pub const fn from_rect(rect: UiRect) -> Self {
        Self { remaining: rect }
    }

    /// Performs the remaining operation.
    pub const fn remaining(&self) -> UiRect {
        self.remaining
    }

    /// Performs the dock operation.
    pub fn dock(&mut self, edge: DockEdge, size: usize) -> UiRect {
        match edge {
            DockEdge::Top => {
                let h = core::cmp::min(size, self.remaining.h);
                let out = UiRect::new(self.remaining.x, self.remaining.y, self.remaining.w, h);
                self.remaining.y = self.remaining.y.saturating_add(h);
                self.remaining.h = self.remaining.h.saturating_sub(h);
                out
            }
            DockEdge::Bottom => {
                let h = core::cmp::min(size, self.remaining.h);
                let y = self
                    .remaining
                    .y
                    .saturating_add(self.remaining.h.saturating_sub(h));
                let out = UiRect::new(self.remaining.x, y, self.remaining.w, h);
                self.remaining.h = self.remaining.h.saturating_sub(h);
                out
            }
            DockEdge::Left => {
                let w = core::cmp::min(size, self.remaining.w);
                let out = UiRect::new(self.remaining.x, self.remaining.y, w, self.remaining.h);
                self.remaining.x = self.remaining.x.saturating_add(w);
                self.remaining.w = self.remaining.w.saturating_sub(w);
                out
            }
            DockEdge::Right => {
                let w = core::cmp::min(size, self.remaining.w);
                let x = self
                    .remaining
                    .x
                    .saturating_add(self.remaining.w.saturating_sub(w));
                let out = UiRect::new(x, self.remaining.y, w, self.remaining.h);
                self.remaining.w = self.remaining.w.saturating_sub(w);
                out
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct UiLabel<'a> {
    pub rect: UiRect,
    pub text: &'a str,
    pub fg: RgbColor,
    pub bg: RgbColor,
    pub align: TextAlign,
}

#[derive(Debug, Clone)]
pub struct UiPanel<'a> {
    pub rect: UiRect,
    pub title: &'a str,
    pub body: &'a str,
    pub theme: UiTheme,
}

#[derive(Debug, Clone, Copy)]
pub struct UiProgressBar {
    pub rect: UiRect,
    pub value: u8, // 0..=100
    pub fg: RgbColor,
    pub bg: RgbColor,
    pub border: RgbColor,
}

#[derive(Debug, Clone)]
pub struct UiTable {
    pub rect: UiRect,
    pub headers: Vec<String>,
    pub rows: Vec<Vec<String>>,
    pub theme: UiTheme,
}

#[derive(Debug, Clone)]
struct TerminalLine {
    text: String,
    fg: RgbColor,
}

#[derive(Debug, Clone)]
pub struct TerminalWidget {
    pub rect: UiRect,
    pub title: String,
    pub fg: RgbColor,
    pub bg: RgbColor,
    pub border: RgbColor,
    pub max_lines: usize,
    lines: Vec<TerminalLine>,
}

impl TerminalWidget {
    /// Creates a new instance.
    pub fn new(rect: UiRect, max_lines: usize) -> Self {
        Self {
            rect,
            title: String::from("Terminal"),
            fg: RgbColor::LIGHT_GREY,
            bg: RgbColor::new(0x0F, 0x14, 0x1B),
            border: RgbColor::new(0x3D, 0x52, 0x66),
            max_lines: core::cmp::max(1, max_lines),
            lines: Vec::new(),
        }
    }

    /// Performs the push line operation.
    pub fn push_line(&mut self, text: &str) {
        self.push_colored_line(text, self.fg);
    }

    /// Performs the push ansi line operation.
    pub fn push_ansi_line(&mut self, text: &str) {
        let (fg, stripped) = parse_ansi_color_prefix(text, self.fg);
        self.push_colored_line(&stripped, fg);
    }

    /// Performs the push colored line operation.
    fn push_colored_line(&mut self, text: &str, fg: RgbColor) {
        if self.lines.len() >= self.max_lines {
            self.lines.remove(0);
        }
        self.lines.push(TerminalLine {
            text: String::from(text),
            fg,
        });
    }

    /// Performs the clear operation.
    pub fn clear(&mut self) {
        self.lines.clear();
    }

    /// Performs the draw operation.
    pub fn draw(&self) {
        let _ = super::api::with_writer(|w| {
            if self.rect.w < 8 || self.rect.h < 8 {
                return;
            }
            let (gw, gh) = w.glyph_size();
            if gw == 0 || gh == 0 {
                return;
            }

            w.fill_rect(self.rect.x, self.rect.y, self.rect.w, self.rect.h, self.bg);
            w.draw_rect(
                self.rect.x,
                self.rect.y,
                self.rect.w,
                self.rect.h,
                self.border,
            );

            let title_h = gh + 2;
            w.fill_rect(
                self.rect.x + 1,
                self.rect.y + 1,
                self.rect.w.saturating_sub(2),
                title_h,
                self.border,
            );
            w.draw_text(
                self.rect.x + 4,
                self.rect.y + 1,
                &self.title,
                TextOptions {
                    fg: RgbColor::WHITE,
                    bg: self.border,
                    align: TextAlign::Left,
                    wrap: false,
                    max_width: Some(self.rect.w.saturating_sub(8)),
                },
            );

            let content_y = self.rect.y + title_h + 2;
            let content_h = self.rect.h.saturating_sub(title_h + 3);
            let rows = core::cmp::max(1, content_h / gh);
            let start = self.lines.len().saturating_sub(rows);

            for (idx, line) in self.lines.iter().skip(start).enumerate() {
                let y = content_y + idx * gh;
                w.draw_text(
                    self.rect.x + 4,
                    y,
                    &line.text,
                    TextOptions {
                        fg: line.fg,
                        bg: self.bg,
                        align: TextAlign::Left,
                        wrap: false,
                        max_width: Some(self.rect.w.saturating_sub(8)),
                    },
                );
            }
        });
    }
}

/// Parses ansi color prefix.
pub(crate) fn parse_ansi_color_prefix(input: &str, default_fg: RgbColor) -> (RgbColor, String) {
    let bytes = input.as_bytes();
    if !bytes.starts_with(b"\x1b[") {
        return (default_fg, String::from(input));
    }
    let Some(mpos) = bytes.iter().position(|b| *b == b'm') else {
        return (default_fg, String::from(input));
    };
    let code = &input[2..mpos];
    let rest = &input[mpos + 1..];
    let fg = match code {
        "30" => RgbColor::BLACK,
        "31" => RgbColor::new(0xFF, 0x55, 0x55),
        "32" => RgbColor::new(0x66, 0xFF, 0x66),
        "33" => RgbColor::new(0xFF, 0xDD, 0x66),
        "34" => RgbColor::new(0x77, 0xAA, 0xFF),
        "35" => RgbColor::new(0xFF, 0x77, 0xFF),
        "36" => RgbColor::new(0x77, 0xFF, 0xFF),
        "37" | "0" => RgbColor::LIGHT_GREY,
        _ => default_fg,
    };
    (fg, String::from(rest))
}

/// Performs the color to rgb operation.
#[inline]
pub(crate) fn color_to_rgb(c: Color) -> (u8, u8, u8) {
    match c {
        Color::Black => (0x00, 0x00, 0x00),
        Color::Blue => (0x00, 0x00, 0xAA),
        Color::Green => (0x00, 0xAA, 0x00),
        Color::Cyan => (0x00, 0xAA, 0xAA),
        Color::Red => (0xAA, 0x00, 0x00),
        Color::Magenta => (0xAA, 0x00, 0xAA),
        Color::Brown => (0xAA, 0x55, 0x00),
        Color::LightGrey => (0xAA, 0xAA, 0xAA),
        Color::DarkGrey => (0x55, 0x55, 0x55),
        Color::LightBlue => (0x55, 0x55, 0xFF),
        Color::LightGreen => (0x55, 0xFF, 0x55),
        Color::LightCyan => (0x55, 0xFF, 0xFF),
        Color::LightRed => (0xFF, 0x55, 0x55),
        Color::LightMagenta => (0xFF, 0x55, 0xFF),
        Color::Yellow => (0xFF, 0xFF, 0x55),
        Color::White => (0xFF, 0xFF, 0xFF),
    }
}

impl From<Color> for RgbColor {
    /// Performs the from operation.
    fn from(value: Color) -> Self {
        let (r, g, b) = color_to_rgb(value);
        Self::new(r, g, b)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct PixelFormat {
    pub(crate) bpp: u16,
    pub(crate) red_size: u8,
    pub(crate) red_shift: u8,
    pub(crate) green_size: u8,
    pub(crate) green_shift: u8,
    pub(crate) blue_size: u8,
    pub(crate) blue_shift: u8,
}

impl PixelFormat {
    pub(crate) fn pack_rgb(&self, r: u8, g: u8, b: u8) -> u32 {
        fn scale(v: u8, bits: u8) -> u32 {
            if bits == 0 {
                0
            } else if bits >= 8 {
                (v as u32) << (bits - 8)
            } else {
                (v as u32) >> (8 - bits)
            }
        }

        (scale(r, self.red_size) << self.red_shift)
            | (scale(g, self.green_size) << self.green_shift)
            | (scale(b, self.blue_size) << self.blue_shift)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FramebufferInfo {
    pub available: bool,
    pub width: usize,
    pub height: usize,
    pub pitch: usize,
    pub bpp: u16,
    pub red_size: u8,
    pub red_shift: u8,
    pub green_size: u8,
    pub green_shift: u8,
    pub blue_size: u8,
    pub blue_shift: u8,
    pub text_cols: usize,
    pub text_rows: usize,
    pub glyph_w: usize,
    pub glyph_h: usize,
    pub double_buffer_mode: bool,
    pub double_buffer_enabled: bool,
    pub ui_scale: UiScale,
}

#[derive(Debug, Clone, Copy)]
pub struct RenderStats {
    pub presented_frames: u64,
    pub estimated_fps: u64,
    pub present_region_count: u64,
    pub present_pixel_count: u64,
}
