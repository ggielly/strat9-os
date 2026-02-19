//! Framebuffer text console (Limine framebuffer + PSF font).
//! https://en.wikipedia.org/wiki/PC_Screen_Font
//!
//! Keeps the existing `vga_print!` / `vga_println!` API but renders text into
//! the graphical framebuffer when available. Falls back to serial otherwise.

use alloc::{collections::VecDeque, format, string::String, vec::Vec};
use core::{
    fmt,
    sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering},
};
use spin::Mutex;

/// Whether framebuffer console is available.
static VGA_AVAILABLE: AtomicBool = AtomicBool::new(false);
static STATUS_LAST_REFRESH_TICK: AtomicU64 = AtomicU64::new(0);
const STATUS_REFRESH_PERIOD_TICKS: u64 = 100; // 100Hz timer => 1s
static PRESENTED_FRAMES: AtomicU64 = AtomicU64::new(0);
static FPS_LAST_TICK: AtomicU64 = AtomicU64::new(0);
static FPS_LAST_FRAME_COUNT: AtomicU64 = AtomicU64::new(0);
static FPS_ESTIMATE: AtomicU64 = AtomicU64::new(0);
static DOUBLE_BUFFER_MODE: AtomicBool = AtomicBool::new(false);
static UI_SCALE: AtomicU8 = AtomicU8::new(1);

const FONT_PSF: &[u8] = include_bytes!("fonts/zap-ext-light20.psf");

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
pub struct RgbColor {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl RgbColor {
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b }
    }

    pub const BLACK: Self = Self::new(0x00, 0x00, 0x00);
    pub const WHITE: Self = Self::new(0xFF, 0xFF, 0xFF);
    pub const RED: Self = Self::new(0xFF, 0x00, 0x00);
    pub const GREEN: Self = Self::new(0x00, 0xFF, 0x00);
    pub const BLUE: Self = Self::new(0x00, 0x00, 0xFF);
    pub const CYAN: Self = Self::new(0x00, 0xFF, 0xFF);
    pub const MAGENTA: Self = Self::new(0xFF, 0x00, 0xFF);
    pub const YELLOW: Self = Self::new(0xFF, 0xFF, 0x00);
    pub const LIGHT_GREY: Self = Self::new(0xAA, 0xAA, 0xAA);
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

#[derive(Debug, Clone)]
struct StatusLineInfo {
    hostname: String,
    ip: String,
}

static STATUS_LINE_INFO: Mutex<Option<StatusLineInfo>> = Mutex::new(None);

#[derive(Debug, Clone, Copy, Default)]
pub struct UiRect {
    pub x: usize,
    pub y: usize,
    pub w: usize,
    pub h: usize,
}

impl UiRect {
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
    remaining: UiRect,
}

impl UiDockLayout {
    pub fn from_screen() -> Self {
        Self {
            remaining: UiRect::new(0, 0, width(), height()),
        }
    }

    pub const fn from_rect(rect: UiRect) -> Self {
        Self { remaining: rect }
    }

    pub const fn remaining(&self) -> UiRect {
        self.remaining
    }

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
    lines: VecDeque<TerminalLine>,
}

impl TerminalWidget {
    pub fn new(rect: UiRect, max_lines: usize) -> Self {
        Self {
            rect,
            title: String::from("Terminal"),
            fg: RgbColor::LIGHT_GREY,
            bg: RgbColor::new(0x0F, 0x14, 0x1B),
            border: RgbColor::new(0x3D, 0x52, 0x66),
            max_lines: core::cmp::max(1, max_lines),
            lines: VecDeque::new(),
        }
    }

    pub fn push_line(&mut self, text: &str) {
        self.push_colored_line(text, self.fg);
    }

    pub fn push_ansi_line(&mut self, text: &str) {
        let (fg, stripped) = parse_ansi_color_prefix(text, self.fg);
        self.push_colored_line(&stripped, fg);
    }

    fn push_colored_line(&mut self, text: &str, fg: RgbColor) {
        if self.lines.len() >= self.max_lines {
            self.lines.pop_front();
        }
        self.lines.push_back(TerminalLine {
            text: String::from(text),
            fg,
        });
    }

    pub fn clear(&mut self) {
        self.lines.clear();
    }

    pub fn draw(&self) {
        let _ = with_writer(|w| {
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

fn parse_ansi_color_prefix(input: &str, default_fg: RgbColor) -> (RgbColor, String) {
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

#[inline]
fn color_to_rgb(c: Color) -> (u8, u8, u8) {
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
    fn from(value: Color) -> Self {
        let (r, g, b) = color_to_rgb(value);
        Self::new(r, g, b)
    }
}

#[derive(Clone, Copy)]
struct PixelFormat {
    bpp: u16,
    red_size: u8,
    red_shift: u8,
    green_size: u8,
    green_shift: u8,
    blue_size: u8,
    blue_shift: u8,
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

impl PixelFormat {
    fn pack_rgb(&self, r: u8, g: u8, b: u8) -> u32 {
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

struct FontInfo {
    glyph_count: usize,
    bytes_per_glyph: usize,
    glyph_w: usize,
    glyph_h: usize,
    data_offset: usize,
    unicode_table_offset: Option<usize>,
}

#[derive(Clone, Copy)]
struct ClipRect {
    x: usize,
    y: usize,
    w: usize,
    h: usize,
}

fn parse_psf(font: &[u8]) -> Option<FontInfo> {
    // PSF1
    if font.len() >= 4 && font[0] == 0x36 && font[1] == 0x04 {
        let mode = font[2];
        let glyph_count = if (mode & 0x01) != 0 { 512 } else { 256 };
        let glyph_h = font[3] as usize;
        let bytes_per_glyph = glyph_h;
        return Some(FontInfo {
            glyph_count,
            bytes_per_glyph,
            glyph_w: 8,
            glyph_h,
            data_offset: 4,
            unicode_table_offset: None,
        });
    }

    // PSF2
    if font.len() >= 32 && font[0] == 0x72 && font[1] == 0xB5 && font[2] == 0x4A && font[3] == 0x86
    {
        let rd_u32 = |off: usize| -> u32 {
            u32::from_le_bytes([font[off], font[off + 1], font[off + 2], font[off + 3]])
        };
        let headersize = rd_u32(8) as usize;
        let flags = rd_u32(12);
        let glyph_count = rd_u32(16) as usize;
        let bytes_per_glyph = rd_u32(20) as usize;
        let glyph_h = rd_u32(24) as usize;
        let glyph_w = rd_u32(28) as usize;
        let glyph_bytes = glyph_count.saturating_mul(bytes_per_glyph);
        let unicode_table_offset = if (flags & 1) != 0 {
            Some(headersize.saturating_add(glyph_bytes))
        } else {
            None
        };
        return Some(FontInfo {
            glyph_count,
            bytes_per_glyph,
            glyph_w,
            glyph_h,
            data_offset: headersize,
            unicode_table_offset,
        });
    }

    None
}

fn decode_utf8_at(bytes: &[u8], pos: usize) -> Option<(u32, usize)> {
    let b0 = *bytes.get(pos)?;
    if b0 < 0x80 {
        return Some((b0 as u32, 1));
    }
    if (b0 & 0xE0) == 0xC0 {
        let b1 = *bytes.get(pos + 1)?;
        if (b1 & 0xC0) != 0x80 {
            return None;
        }
        let cp = (((b0 & 0x1F) as u32) << 6) | ((b1 & 0x3F) as u32);
        return Some((cp, 2));
    }
    if (b0 & 0xF0) == 0xE0 {
        let b1 = *bytes.get(pos + 1)?;
        let b2 = *bytes.get(pos + 2)?;
        if (b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80 {
            return None;
        }
        let cp =
            (((b0 & 0x0F) as u32) << 12) | (((b1 & 0x3F) as u32) << 6) | ((b2 & 0x3F) as u32);
        return Some((cp, 3));
    }
    if (b0 & 0xF8) == 0xF0 {
        let b1 = *bytes.get(pos + 1)?;
        let b2 = *bytes.get(pos + 2)?;
        let b3 = *bytes.get(pos + 3)?;
        if (b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80 || (b3 & 0xC0) != 0x80 {
            return None;
        }
        let cp = (((b0 & 0x07) as u32) << 18)
            | (((b1 & 0x3F) as u32) << 12)
            | (((b2 & 0x3F) as u32) << 6)
            | ((b3 & 0x3F) as u32);
        return Some((cp, 4));
    }
    None
}

fn parse_psf2_unicode_map(font: &[u8], info: &FontInfo) -> Vec<(u32, usize)> {
    let Some(mut i) = info.unicode_table_offset else {
        return Vec::new();
    };
    if i >= font.len() {
        return Vec::new();
    }

    let mut map = Vec::new();
    for glyph in 0..info.glyph_count {
        while i < font.len() {
            let b = font[i];
            if b == 0xFF {
                i += 1;
                break;
            }
            if b == 0xFE {
                // PSF2 sequence marker; skip marker and continue parsing bytes until glyph separator.
                i += 1;
                continue;
            }
            if let Some((cp, adv)) = decode_utf8_at(font, i) {
                if !map.iter().any(|(u, _)| *u == cp) {
                    map.push((cp, glyph));
                }
                i += adv;
            } else {
                i += 1;
            }
        }
    }

    map
}

pub struct VgaWriter {
    enabled: bool,
    fb_addr: *mut u8,
    fb_width: usize,
    fb_height: usize,
    pitch: usize,
    fmt: PixelFormat,

    cols: usize,
    rows: usize,
    col: usize,
    row: usize,

    fg: u32,
    bg: u32,

    font: &'static [u8],
    font_info: FontInfo,
    unicode_map: Vec<(u32, usize)>,
    status_bar_height: usize,
    clip: ClipRect,
    back_buffer: Option<Vec<u32>>,
    draw_to_back: bool,
    dirty_rect: Option<ClipRect>,
    track_dirty: bool,
}

unsafe impl Send for VgaWriter {}

impl VgaWriter {
    pub const fn new() -> Self {
        Self {
            enabled: false,
            fb_addr: core::ptr::null_mut(),
            fb_width: 0,
            fb_height: 0,
            pitch: 0,
            fmt: PixelFormat {
                bpp: 0,
                red_size: 0,
                red_shift: 0,
                green_size: 0,
                green_shift: 0,
                blue_size: 0,
                blue_shift: 0,
            },
            cols: 0,
            rows: 0,
            col: 0,
            row: 0,
            fg: 0,
            bg: 0,
            font: &[],
            font_info: FontInfo {
                glyph_count: 0,
                bytes_per_glyph: 0,
                glyph_w: 8,
                glyph_h: 16,
                data_offset: 0,
                unicode_table_offset: None,
            },
            unicode_map: Vec::new(),
            status_bar_height: 0,
            clip: ClipRect {
                x: 0,
                y: 0,
                w: 0,
                h: 0,
            },
            back_buffer: None,
            draw_to_back: false,
            dirty_rect: None,
            track_dirty: false,
        }
    }

    fn configure(
        &mut self,
        fb_addr: *mut u8,
        fb_width: usize,
        fb_height: usize,
        pitch: usize,
        fmt: PixelFormat,
    ) -> bool {
        let Some(font_info) = parse_psf(FONT_PSF) else {
            return false;
        };
        let status_bar_height = font_info.glyph_h;
        let text_height = fb_height.saturating_sub(status_bar_height);
        let cols = fb_width / font_info.glyph_w;
        let rows = text_height / font_info.glyph_h;
        if cols == 0 || rows == 0 {
            return false;
        }
        let (fr, fg, fb) = color_to_rgb(Color::LightGrey);
        let (br, bg, bb) = color_to_rgb(Color::Black);

        self.enabled = true;
        self.fb_addr = fb_addr;
        self.fb_width = fb_width;
        self.fb_height = fb_height;
        self.pitch = pitch;
        self.fmt = fmt;
        self.cols = cols;
        self.rows = rows;
        self.col = 0;
        self.row = 0;
        self.fg = fmt.pack_rgb(fr, fg, fb);
        self.bg = fmt.pack_rgb(br, bg, bb);
        self.font = FONT_PSF;
        self.font_info = font_info;
        self.unicode_map = parse_psf2_unicode_map(FONT_PSF, &self.font_info);
        self.status_bar_height = status_bar_height;
        self.clip = ClipRect {
            x: 0,
            y: 0,
            w: fb_width,
            h: fb_height,
        };
        self.back_buffer = None;
        self.draw_to_back = false;
        self.dirty_rect = None;
        self.track_dirty = false;
        true
    }

    #[inline]
    fn pack_color(&self, color: RgbColor) -> u32 {
        self.fmt.pack_rgb(color.r, color.g, color.b)
    }

    fn unpack_color(&self, value: u32) -> RgbColor {
        fn unscale(v: u32, bits: u8) -> u8 {
            if bits == 0 {
                return 0;
            }
            let max = (1u32 << bits) - 1;
            ((v * 255) / max) as u8
        }

        let r = unscale(
            (value >> self.fmt.red_shift) & ((1u32 << self.fmt.red_size) - 1),
            self.fmt.red_size,
        );
        let g = unscale(
            (value >> self.fmt.green_shift) & ((1u32 << self.fmt.green_size) - 1),
            self.fmt.green_size,
        );
        let b = unscale(
            (value >> self.fmt.blue_shift) & ((1u32 << self.fmt.blue_size) - 1),
            self.fmt.blue_size,
        );
        RgbColor::new(r, g, b)
    }

    pub fn set_color(&mut self, fg: Color, bg: Color) {
        self.set_rgb_color(fg.into(), bg.into());
    }

    pub fn set_rgb_color(&mut self, fg: RgbColor, bg: RgbColor) {
        self.fg = self.pack_color(fg);
        self.bg = self.pack_color(bg);
    }

    pub fn text_colors(&self) -> (RgbColor, RgbColor) {
        (self.unpack_color(self.fg), self.unpack_color(self.bg))
    }

    pub fn width(&self) -> usize {
        self.fb_width
    }

    pub fn height(&self) -> usize {
        self.fb_height
    }

    pub fn cols(&self) -> usize {
        self.cols
    }

    pub fn rows(&self) -> usize {
        self.rows
    }

    pub fn glyph_size(&self) -> (usize, usize) {
        (self.font_info.glyph_w, self.font_info.glyph_h)
    }

    pub fn set_cursor_cell(&mut self, col: usize, row: usize) {
        if !self.enabled || self.cols == 0 || self.rows == 0 {
            return;
        }
        self.col = core::cmp::min(col, self.cols - 1);
        self.row = core::cmp::min(row, self.rows - 1);
    }

    fn text_area_height(&self) -> usize {
        self.fb_height.saturating_sub(self.status_bar_height)
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn framebuffer_info(&self) -> FramebufferInfo {
        FramebufferInfo {
            available: self.enabled,
            width: self.fb_width,
            height: self.fb_height,
            pitch: self.pitch,
            bpp: self.fmt.bpp,
            red_size: self.fmt.red_size,
            red_shift: self.fmt.red_shift,
            green_size: self.fmt.green_size,
            green_shift: self.fmt.green_shift,
            blue_size: self.fmt.blue_size,
            blue_shift: self.fmt.blue_shift,
            text_cols: self.cols,
            text_rows: self.rows,
            glyph_w: self.font_info.glyph_w,
            glyph_h: self.font_info.glyph_h,
            double_buffer_mode: DOUBLE_BUFFER_MODE.load(Ordering::Relaxed),
            double_buffer_enabled: self.draw_to_back && self.back_buffer.is_some(),
            ui_scale: current_ui_scale(),
        }
    }

    #[inline]
    fn in_clip(&self, x: usize, y: usize) -> bool {
        x >= self.clip.x
            && y >= self.clip.y
            && x < self.clip.x.saturating_add(self.clip.w)
            && y < self.clip.y.saturating_add(self.clip.h)
    }

    fn clipped_rect(
        &self,
        x: usize,
        y: usize,
        width: usize,
        height: usize,
    ) -> Option<(usize, usize, usize, usize)> {
        if width == 0 || height == 0 || !self.enabled {
            return None;
        }
        let src_x2 = core::cmp::min(x.saturating_add(width), self.fb_width);
        let src_y2 = core::cmp::min(y.saturating_add(height), self.fb_height);
        let clip_x2 = self.clip.x.saturating_add(self.clip.w);
        let clip_y2 = self.clip.y.saturating_add(self.clip.h);

        let sx = core::cmp::max(x, self.clip.x);
        let sy = core::cmp::max(y, self.clip.y);
        let ex = core::cmp::min(src_x2, clip_x2);
        let ey = core::cmp::min(src_y2, clip_y2);
        if ex <= sx || ey <= sy {
            return None;
        }
        Some((sx, sy, ex - sx, ey - sy))
    }

    fn clear_dirty(&mut self) {
        self.dirty_rect = None;
    }

    fn mark_dirty_rect(&mut self, x: usize, y: usize, width: usize, height: usize) {
        if !self.track_dirty {
            return;
        }
        let Some((sx, sy, sw, sh)) = self.clipped_rect(x, y, width, height) else {
            return;
        };
        let next = ClipRect {
            x: sx,
            y: sy,
            w: sw,
            h: sh,
        };
        self.dirty_rect = Some(match self.dirty_rect {
            None => next,
            Some(cur) => {
                let x0 = core::cmp::min(cur.x, next.x);
                let y0 = core::cmp::min(cur.y, next.y);
                let x1 = core::cmp::max(cur.x.saturating_add(cur.w), next.x.saturating_add(next.w));
                let y1 = core::cmp::max(cur.y.saturating_add(cur.h), next.y.saturating_add(next.h));
                ClipRect {
                    x: x0,
                    y: y0,
                    w: x1.saturating_sub(x0),
                    h: y1.saturating_sub(y0),
                }
            }
        });
    }

    pub fn set_clip_rect(&mut self, x: usize, y: usize, width: usize, height: usize) {
        let x_end = core::cmp::min(x.saturating_add(width), self.fb_width);
        let y_end = core::cmp::min(y.saturating_add(height), self.fb_height);
        self.clip = ClipRect {
            x,
            y,
            w: x_end.saturating_sub(x),
            h: y_end.saturating_sub(y),
        };
    }

    pub fn reset_clip_rect(&mut self) {
        self.clip = ClipRect {
            x: 0,
            y: 0,
            w: self.fb_width,
            h: self.fb_height,
        };
    }

    fn draw_to_back_buffer(&self) -> bool {
        self.draw_to_back && self.back_buffer.is_some()
    }

    pub fn enable_double_buffer(&mut self) -> bool {
        if !self.enabled {
            return false;
        }
        if self.back_buffer.is_none() {
            let mut buf = Vec::with_capacity(self.fb_width.saturating_mul(self.fb_height));
            for y in 0..self.fb_height {
                for x in 0..self.fb_width {
                    buf.push(self.read_hw_pixel_packed(x, y));
                }
            }
            self.back_buffer = Some(buf);
        }
        self.draw_to_back = true;
        self.track_dirty = true;
        self.clear_dirty();
        true
    }

    pub fn disable_double_buffer(&mut self, present: bool) {
        if present {
            self.present();
        }
        self.draw_to_back = false;
        self.track_dirty = false;
        self.clear_dirty();
    }

    pub fn present(&mut self) {
        if !self.enabled {
            return;
        }
        let Some(buf) = self.back_buffer.as_ref() else {
            return;
        };
        let buf_ptr = buf.as_ptr();
        let (sx, sy, sw, sh) = if self.track_dirty {
            let Some(dirty) = self.dirty_rect else {
                return;
            };
            (dirty.x, dirty.y, dirty.w, dirty.h)
        } else {
            (0, 0, self.fb_width, self.fb_height)
        };

        for y in sy..(sy + sh) {
            for x in sx..(sx + sw) {
                let idx = y * self.fb_width + x;
                let packed = unsafe { *buf_ptr.add(idx) };
                self.write_hw_pixel_packed(x, y, packed);
            }
        }
        PRESENTED_FRAMES.fetch_add(1, Ordering::Relaxed);
        self.clear_dirty();
    }

    pub fn clear_with(&mut self, color: RgbColor) {
        if !self.enabled {
            return;
        }
        let packed = self.pack_color(color);
        for y in 0..self.fb_height {
            for x in 0..self.fb_width {
                self.put_pixel_raw(x, y, packed);
            }
        }
        self.col = 0;
        self.row = 0;
    }

    pub fn clear(&mut self) {
        self.clear_with(self.unpack_color(self.bg));
    }

    #[inline]
    fn pixel_offset(&self, x: usize, y: usize) -> Option<usize> {
        let bytes_pp = self.fmt.bpp as usize / 8;
        let row = y.checked_mul(self.pitch)?;
        let col = x.checked_mul(bytes_pp)?;
        row.checked_add(col)
    }

    fn write_hw_pixel_packed(&mut self, x: usize, y: usize, color: u32) {
        let Some(off) = self.pixel_offset(x, y) else {
            return;
        };
        unsafe {
            match self.fmt.bpp {
                32 => {
                    core::ptr::write_volatile(self.fb_addr.add(off) as *mut u32, color);
                }
                24 => {
                    core::ptr::write_volatile(self.fb_addr.add(off), (color & 0xFF) as u8);
                    core::ptr::write_volatile(
                        self.fb_addr.add(off + 1),
                        ((color >> 8) & 0xFF) as u8,
                    );
                    core::ptr::write_volatile(
                        self.fb_addr.add(off + 2),
                        ((color >> 16) & 0xFF) as u8,
                    );
                }
                _ => {}
            }
        }
    }

    fn read_hw_pixel_packed(&self, x: usize, y: usize) -> u32 {
        let Some(off) = self.pixel_offset(x, y) else {
            return 0;
        };
        unsafe {
            match self.fmt.bpp {
                32 => core::ptr::read_volatile(self.fb_addr.add(off) as *const u32),
                24 => {
                    let b0 = core::ptr::read_volatile(self.fb_addr.add(off)) as u32;
                    let b1 = core::ptr::read_volatile(self.fb_addr.add(off + 1)) as u32;
                    let b2 = core::ptr::read_volatile(self.fb_addr.add(off + 2)) as u32;
                    b0 | (b1 << 8) | (b2 << 16)
                }
                _ => 0,
            }
        }
    }

    fn read_pixel_packed(&self, x: usize, y: usize) -> u32 {
        if self.draw_to_back_buffer() {
            if let Some(buf) = self.back_buffer.as_ref() {
                return buf[y * self.fb_width + x];
            }
        }
        self.read_hw_pixel_packed(x, y)
    }

    fn put_pixel_raw(&mut self, x: usize, y: usize, color: u32) {
        if !self.enabled || x >= self.fb_width || y >= self.fb_height || !self.in_clip(x, y) {
            return;
        }
        if self.draw_to_back_buffer() {
            if let Some(buf) = self.back_buffer.as_mut() {
                buf[y * self.fb_width + x] = color;
                self.mark_dirty_rect(x, y, 1, 1);
                return;
            }
        }
        self.write_hw_pixel_packed(x, y, color);
    }

    pub fn draw_pixel(&mut self, x: usize, y: usize, color: RgbColor) {
        self.put_pixel_raw(x, y, self.pack_color(color));
    }

    pub fn draw_pixel_alpha(&mut self, x: usize, y: usize, color: RgbColor, alpha: u8) {
        if !self.enabled || alpha == 0 || x >= self.fb_width || y >= self.fb_height || !self.in_clip(x, y) {
            return;
        }
        if alpha == 255 {
            self.put_pixel_raw(x, y, self.pack_color(color));
            return;
        }
        let dst = self.unpack_color(self.read_pixel_packed(x, y));
        let inv = (255u16).saturating_sub(alpha as u16);
        let a = alpha as u16;
        let blended = RgbColor::new(
            ((color.r as u16 * a + dst.r as u16 * inv + 127) / 255) as u8,
            ((color.g as u16 * a + dst.g as u16 * inv + 127) / 255) as u8,
            ((color.b as u16 * a + dst.b as u16 * inv + 127) / 255) as u8,
        );
        self.put_pixel_raw(x, y, self.pack_color(blended));
    }

    pub fn draw_line(&mut self, x0: isize, y0: isize, x1: isize, y1: isize, color: RgbColor) {
        let mut x = x0;
        let mut y = y0;
        let dx = (x1 - x0).abs();
        let sx = if x0 < x1 { 1 } else { -1 };
        let dy = -(y1 - y0).abs();
        let sy = if y0 < y1 { 1 } else { -1 };
        let mut err = dx + dy;
        let packed = self.pack_color(color);

        loop {
            if x >= 0 && y >= 0 {
                self.put_pixel_raw(x as usize, y as usize, packed);
            }
            if x == x1 && y == y1 {
                break;
            }
            let e2 = 2 * err;
            if e2 >= dy {
                err += dy;
                x += sx;
            }
            if e2 <= dx {
                err += dx;
                y += sy;
            }
        }
    }

    pub fn draw_rect(&mut self, x: usize, y: usize, width: usize, height: usize, color: RgbColor) {
        if width == 0 || height == 0 {
            return;
        }
        let x2 = x.saturating_add(width - 1);
        let y2 = y.saturating_add(height - 1);
        self.draw_line(x as isize, y as isize, x2 as isize, y as isize, color);
        self.draw_line(x as isize, y as isize, x as isize, y2 as isize, color);
        self.draw_line(x2 as isize, y as isize, x2 as isize, y2 as isize, color);
        self.draw_line(x as isize, y2 as isize, x2 as isize, y2 as isize, color);
    }

    pub fn fill_rect(&mut self, x: usize, y: usize, width: usize, height: usize, color: RgbColor) {
        let Some((sx, sy, sw, sh)) = self.clipped_rect(x, y, width, height) else {
            return;
        };
        let packed = self.pack_color(color);

        if self.draw_to_back_buffer() {
            if let Some(buf) = self.back_buffer.as_mut() {
                for py in sy..(sy + sh) {
                    let row = py * self.fb_width;
                    let start = row + sx;
                    let end = start + sw;
                    buf[start..end].fill(packed);
                }
                self.mark_dirty_rect(sx, sy, sw, sh);
                return;
            }
        }

        if self.fmt.bpp == 32 {
            for py in sy..(sy + sh) {
                let Some(row_off) = py.checked_mul(self.pitch).and_then(|v| v.checked_add(sx * 4)) else {
                    continue;
                };
                let count = sw;
                unsafe {
                    let ptr = self.fb_addr.add(row_off) as *mut u32;
                    for i in 0..count {
                        core::ptr::write_volatile(ptr.add(i), packed);
                    }
                }
            }
            return;
        }

        for py in sy..(sy + sh) {
            for px in sx..(sx + sw) {
                self.write_hw_pixel_packed(px, py, packed);
            }
        }
    }

    pub fn fill_rect_alpha(&mut self, x: usize, y: usize, width: usize, height: usize, color: RgbColor, alpha: u8) {
        if !self.enabled || width == 0 || height == 0 || alpha == 0 {
            return;
        }
        if alpha == 255 {
            self.fill_rect(x, y, width, height, color);
            return;
        }
        let x_end = core::cmp::min(x.saturating_add(width), self.fb_width);
        let y_end = core::cmp::min(y.saturating_add(height), self.fb_height);
        for py in y..y_end {
            for px in x..x_end {
                self.draw_pixel_alpha(px, py, color, alpha);
            }
        }
    }

    pub fn blit_rgb(&mut self, dst_x: usize, dst_y: usize, src_width: usize, src_height: usize, pixels: &[RgbColor]) -> bool {
        let len = src_width.saturating_mul(src_height);
        if !self.enabled || src_width == 0 || src_height == 0 || pixels.len() < len {
            return false;
        }
        let x_end = core::cmp::min(dst_x.saturating_add(src_width), self.fb_width);
        let y_end = core::cmp::min(dst_y.saturating_add(src_height), self.fb_height);
        if x_end <= dst_x || y_end <= dst_y {
            return true;
        }
        let copy_w = x_end - dst_x;
        let copy_h = y_end - dst_y;
        for row in 0..copy_h {
            let src_row = row * src_width;
            for col in 0..copy_w {
                self.draw_pixel(dst_x + col, dst_y + row, pixels[src_row + col]);
            }
        }
        true
    }

    pub fn blit_rgb24(&mut self, dst_x: usize, dst_y: usize, src_width: usize, src_height: usize, bytes: &[u8]) -> bool {
        let needed = src_width.saturating_mul(src_height).saturating_mul(3);
        if !self.enabled || src_width == 0 || src_height == 0 || bytes.len() < needed {
            return false;
        }
        let x_end = core::cmp::min(dst_x.saturating_add(src_width), self.fb_width);
        let y_end = core::cmp::min(dst_y.saturating_add(src_height), self.fb_height);
        if x_end <= dst_x || y_end <= dst_y {
            return true;
        }
        let copy_w = x_end - dst_x;
        let copy_h = y_end - dst_y;
        for row in 0..copy_h {
            for col in 0..copy_w {
                let i = (row * src_width + col) * 3;
                let color = RgbColor::new(bytes[i], bytes[i + 1], bytes[i + 2]);
                self.draw_pixel(dst_x + col, dst_y + row, color);
            }
        }
        true
    }

    pub fn blit_rgba(
        &mut self,
        dst_x: usize,
        dst_y: usize,
        src_width: usize,
        src_height: usize,
        bytes: &[u8],
        global_alpha: u8,
    ) -> bool {
        let needed = src_width.saturating_mul(src_height).saturating_mul(4);
        if !self.enabled || src_width == 0 || src_height == 0 || bytes.len() < needed || global_alpha == 0 {
            return false;
        }

        let Some((sx, sy, sw, sh)) = self.clipped_rect(dst_x, dst_y, src_width, src_height) else {
            return true;
        };
        let src_x0 = sx.saturating_sub(dst_x);
        let src_y0 = sy.saturating_sub(dst_y);

        for row in 0..sh {
            let syi = src_y0 + row;
            for col in 0..sw {
                let sxi = src_x0 + col;
                let i = (syi * src_width + sxi) * 4;
                let r = bytes[i];
                let g = bytes[i + 1];
                let b = bytes[i + 2];
                let sa = bytes[i + 3];
                if sa == 0 {
                    continue;
                }
                let a = ((sa as u16 * global_alpha as u16 + 127) / 255) as u8;
                let dx = sx + col;
                let dy = sy + row;
                if a == 255 {
                    self.put_pixel_raw(dx, dy, self.pack_color(RgbColor::new(r, g, b)));
                } else if a != 0 {
                    self.draw_pixel_alpha(dx, dy, RgbColor::new(r, g, b), a);
                }
            }
        }
        true
    }

    pub fn blit_sprite_rgba(&mut self, dst_x: usize, dst_y: usize, sprite: SpriteRgba<'_>, global_alpha: u8) -> bool {
        self.blit_rgba(
            dst_x,
            dst_y,
            sprite.width,
            sprite.height,
            sprite.pixels,
            global_alpha,
        )
    }

    pub fn draw_text_at(
        &mut self,
        pixel_x: usize,
        pixel_y: usize,
        text: &str,
        fg: RgbColor,
        bg: RgbColor,
    ) {
        if !self.enabled {
            return;
        }

        let saved_col = self.col;
        let saved_row = self.row;
        let saved_fg = self.fg;
        let saved_bg = self.bg;

        self.col = pixel_x / self.font_info.glyph_w;
        self.row = pixel_y / self.font_info.glyph_h;
        self.set_rgb_color(fg, bg);

        for ch in text.chars() {
            self.write_char(ch);
            if self.row >= self.rows {
                break;
            }
        }

        self.col = saved_col;
        self.row = saved_row;
        self.fg = saved_fg;
        self.bg = saved_bg;
    }

    fn glyph_index_for_char(&self, ch: char) -> usize {
        if ch.is_ascii() {
            let idx = ch as usize;
            if idx < self.font_info.glyph_count {
                return idx;
            }
        }
        let cp = ch as u32;
        if let Some((_, glyph)) = self.unicode_map.iter().find(|(u, _)| *u == cp) {
            return *glyph;
        }
        if let Some((_, glyph)) = self.unicode_map.iter().find(|(u, _)| *u == ('?' as u32)) {
            return *glyph;
        }
        if ('?' as usize) < self.font_info.glyph_count {
            return '?' as usize;
        }
        0
    }

    fn draw_glyph_index_at_pixel(
        &mut self,
        pixel_x: usize,
        pixel_y: usize,
        glyph_index: usize,
        fg: u32,
        bg: u32,
    ) {
        if !self.enabled {
            return;
        }
        let glyph_index = core::cmp::min(glyph_index, self.font_info.glyph_count.saturating_sub(1));
        let start = self.font_info.data_offset + glyph_index * self.font_info.bytes_per_glyph;
        if start
            .checked_add(self.font_info.bytes_per_glyph)
            .map_or(true, |end| end > self.font.len())
        {
            return;
        }
        let glyph = &self.font[start..start + self.font_info.bytes_per_glyph];
        let row_bytes = self.font_info.glyph_w.div_ceil(8);

        for gy in 0..self.font_info.glyph_h {
            for gx in 0..self.font_info.glyph_w {
                let byte = glyph[gy * row_bytes + gx / 8];
                let mask = 0x80 >> (gx % 8);
                let color = if (byte & mask) != 0 { fg } else { bg };
                self.put_pixel_raw(pixel_x + gx, pixel_y + gy, color);
            }
        }
    }

    fn draw_glyph_at_pixel(&mut self, pixel_x: usize, pixel_y: usize, ch: char, fg: u32, bg: u32) {
        let glyph_index = self.glyph_index_for_char(ch);
        self.draw_glyph_index_at_pixel(pixel_x, pixel_y, glyph_index, fg, bg);
    }

    fn layout_text_lines(&self, text: &str, wrap: bool, max_cols: Option<usize>) -> Vec<Vec<char>> {
        let mut lines: Vec<Vec<char>> = Vec::new();
        let mut current: Vec<char> = Vec::new();
        let wrap_cols = max_cols.filter(|&c| c > 0);

        for ch in text.chars() {
            if ch == '\n' {
                lines.push(current);
                current = Vec::new();
                continue;
            }

            if wrap {
                if let Some(cols) = wrap_cols {
                    if current.len() >= cols {
                        lines.push(current);
                        current = Vec::new();
                    }
                }
            }

            current.push(ch);
        }

        lines.push(current);
        lines
    }

    pub fn measure_text(&self, text: &str, max_width: Option<usize>, wrap: bool) -> TextMetrics {
        if !self.enabled {
            return TextMetrics {
                width: 0,
                height: 0,
                lines: 0,
            };
        }
        let gw = self.font_info.glyph_w;
        let gh = self.font_info.glyph_h;
        let max_cols = max_width.map(|w| core::cmp::max(1, w / gw));
        let lines = self.layout_text_lines(text, wrap, max_cols);

        let mut max_line_cols = 0usize;
        for line in &lines {
            max_line_cols = core::cmp::max(max_line_cols, line.len());
        }

        TextMetrics {
            width: max_line_cols * gw,
            height: lines.len() * gh,
            lines: lines.len(),
        }
    }

    pub fn draw_text(&mut self, pixel_x: usize, pixel_y: usize, text: &str, opts: TextOptions) -> TextMetrics {
        if !self.enabled {
            return TextMetrics {
                width: 0,
                height: 0,
                lines: 0,
            };
        }

        let gw = self.font_info.glyph_w;
        let gh = self.font_info.glyph_h;
        let max_cols = opts.max_width.map(|w| core::cmp::max(1, w / gw));
        let lines = self.layout_text_lines(text, opts.wrap, max_cols);
        let region_w = opts.max_width.unwrap_or_else(|| {
            let mut max_line_cols = 0usize;
            for line in &lines {
                max_line_cols = core::cmp::max(max_line_cols, line.len());
            }
            max_line_cols * gw
        });

        let fg = self.pack_color(opts.fg);
        let bg = self.pack_color(opts.bg);
        let mut max_line_px = 0usize;

        for (line_idx, line) in lines.iter().enumerate() {
            let line_px = line.len() * gw;
            max_line_px = core::cmp::max(max_line_px, line_px);
            let x = match opts.align {
                TextAlign::Left => pixel_x,
                TextAlign::Center => pixel_x.saturating_add(region_w.saturating_sub(line_px) / 2),
                TextAlign::Right => pixel_x.saturating_add(region_w.saturating_sub(line_px)),
            };
            let y = pixel_y + line_idx * gh;

            for (col, ch) in line.iter().enumerate() {
                self.draw_glyph_at_pixel(x + col * gw, y, *ch, fg, bg);
            }
        }

        TextMetrics {
            width: max_line_px,
            height: lines.len() * gh,
            lines: lines.len(),
        }
    }

    pub fn draw_strata_stack(&mut self, origin_x: usize, origin_y: usize, layer_w: usize, layer_h: usize) {
        if !self.enabled || layer_w == 0 || layer_h == 0 {
            return;
        }

        // Simple "strata" stack: each layer is slightly shifted and tinted.
        let palette = [
            RgbColor::new(0x24, 0x3B, 0x55),
            RgbColor::new(0x2B, 0x54, 0x77),
            RgbColor::new(0x2F, 0x74, 0x93),
            RgbColor::new(0x3A, 0x93, 0xA8),
            RgbColor::new(0x5F, 0xB1, 0xA1),
            RgbColor::new(0xA4, 0xCC, 0x94),
        ];

        let dx = 6usize;
        let dy = 5usize;
        for (i, color) in palette.iter().enumerate() {
            let x = origin_x.saturating_add(i * dx);
            let y = origin_y.saturating_add(i * dy);
            let w = layer_w.saturating_sub(i * dx);
            let h = layer_h.saturating_sub(i * dy);
            if w < 8 || h < 8 {
                break;
            }

            self.fill_rect(x, y, w, h, *color);
            self.draw_rect(x, y, w, h, RgbColor::new(0x10, 0x16, 0x20));
        }
    }

    fn draw_glyph(&mut self, cx: usize, cy: usize, ch: char) {
        let glyph_index = self.glyph_index_for_char(ch);
        self.draw_glyph_index_at_pixel(
            cx * self.font_info.glyph_w,
            cy * self.font_info.glyph_h,
            glyph_index,
            self.fg,
            self.bg,
        );
    }

    fn clear_row(&mut self, row: usize) {
        if !self.enabled {
            return;
        }
        let y_start = row * self.font_info.glyph_h;
        let y_end = y_start + self.font_info.glyph_h;
        for y in y_start..y_end {
            for x in 0..self.fb_width {
                self.put_pixel_raw(x, y, self.bg);
            }
        }
    }

    fn scroll(&mut self) {
        if !self.enabled {
            return;
        }
        let dy = self.font_info.glyph_h;
        let text_h = self.text_area_height();
        if dy >= text_h {
            self.clear();
            return;
        }

        let move_rows = text_h - dy;
        if self.draw_to_back_buffer() {
            if let Some(buf) = self.back_buffer.as_mut() {
                let src_start = dy * self.fb_width;
                let src_end = text_h * self.fb_width;
                buf.copy_within(src_start..src_end, 0);
                self.mark_dirty_rect(0, 0, self.fb_width, text_h);
            }
        } else {
            let bytes_per_row = self.pitch;
            unsafe {
                core::ptr::copy(
                    self.fb_addr.add(dy * bytes_per_row),
                    self.fb_addr,
                    move_rows * bytes_per_row,
                );
            }
        }

        self.fill_rect(0, move_rows, self.fb_width, dy, self.unpack_color(self.bg));
        self.row = self.rows - 1;
    }

    fn write_char(&mut self, c: char) {
        if !self.enabled {
            return;
        }
        let c = normalize_console_char(c);
        match c {
            '\n' => {
                self.col = 0;
                self.row += 1;
            }
            '\r' => self.col = 0,
            '\t' => self.col = (self.col + 4) & !3,
            '\u{8}' => {
                if self.col > 0 {
                    self.col -= 1;
                    self.draw_glyph(self.col, self.row, ' ');
                }
            }
            '\0' => {}
            ch => {
                self.draw_glyph(self.col, self.row, ch);
                self.col += 1;
            }
        }

        if self.col >= self.cols {
            self.col = 0;
            self.row += 1;
        }

        if self.row >= self.rows {
            self.scroll();
            self.clear_row(self.row);
        }
    }

    fn write_bytes(&mut self, s: &str) {
        // Skip basic ANSI escape sequences to avoid rendering control garbage.
        let mut chars = s.chars();
        while let Some(ch) = chars.next() {
            if ch == '\u{1b}' {
                if matches!(chars.clone().next(), Some('[')) {
                    let _ = chars.next();
                    for c in chars.by_ref() {
                        if ('@'..='~').contains(&c) {
                            break;
                        }
                    }
                }
                continue;
            }
            self.write_char(ch);
        }
    }
}

fn normalize_console_char(ch: char) -> char {
    match ch {
        '\n' | '\r' | '\t' | '\u{8}' => ch,
        c if c.is_control() => '\0',
        // Graceful fallback when font lacks box-drawing coverage.
        '\u{2500}' | '\u{2501}' | '\u{2504}' | '\u{2505}' | '\u{2013}' | '\u{2014}' => '-',
        '\u{2502}' | '\u{2503}' => '|',
        '\u{250c}' | '\u{2510}' | '\u{2514}' | '\u{2518}' | '\u{251c}' | '\u{2524}'
        | '\u{252c}' | '\u{2534}' | '\u{253c}' => '+',
        '\u{00a0}' => ' ',
        _ => ch,
    }
}

impl fmt::Write for VgaWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if self.enabled {
            self.write_bytes(s);
        } else {
            crate::arch::x86_64::serial::_print(format_args!("{}", s));
        }
        Ok(())
    }
}

pub static VGA_WRITER: Mutex<VgaWriter> = Mutex::new(VgaWriter::new());

#[inline]
pub fn is_available() -> bool {
    VGA_AVAILABLE.load(Ordering::Relaxed)
}

pub fn with_writer<R>(f: impl FnOnce(&mut VgaWriter) -> R) -> Option<R> {
    if !is_available() {
        return None;
    }
    let mut writer = VGA_WRITER.lock();
    Some(f(&mut writer))
}

fn status_line_info() -> StatusLineInfo {
    let mut guard = STATUS_LINE_INFO.lock();
    if guard.is_none() {
        *guard = Some(StatusLineInfo {
            hostname: String::from("strat9"),
            ip: String::from("n/a"),
        });
    }
    guard.as_ref().cloned().unwrap_or(StatusLineInfo {
        hostname: String::from("strat9"),
        ip: String::from("n/a"),
    })
}

fn format_uptime_from_ticks(ticks: u64) -> String {
    let total_secs = ticks / 100;
    let h = total_secs / 3600;
    let m = (total_secs % 3600) / 60;
    let s = total_secs % 60;
    format!("{:02}:{:02}:{:02}", h, m, s)
}

fn current_fps(tick: u64) -> u64 {
    let last_tick = FPS_LAST_TICK.load(Ordering::Relaxed);
    let frames = PRESENTED_FRAMES.load(Ordering::Relaxed);

    if last_tick == 0 {
        let _ = FPS_LAST_TICK.compare_exchange(0, tick, Ordering::Relaxed, Ordering::Relaxed);
        let _ = FPS_LAST_FRAME_COUNT.compare_exchange(0, frames, Ordering::Relaxed, Ordering::Relaxed);
        return FPS_ESTIMATE.load(Ordering::Relaxed);
    }

    let dt = tick.saturating_sub(last_tick);
    if dt >= STATUS_REFRESH_PERIOD_TICKS
        && FPS_LAST_TICK
            .compare_exchange(last_tick, tick, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        let last_frames = FPS_LAST_FRAME_COUNT.swap(frames, Ordering::Relaxed);
        let df = frames.saturating_sub(last_frames);
        let fps = if dt == 0 { 0 } else { df.saturating_mul(100) / dt };
        FPS_ESTIMATE.store(fps, Ordering::Relaxed);
    }

    FPS_ESTIMATE.load(Ordering::Relaxed)
}

fn current_ui_scale() -> UiScale {
    match UI_SCALE.load(Ordering::Relaxed) {
        1 => UiScale::Compact,
        3 => UiScale::Large,
        _ => UiScale::Normal,
    }
}

pub fn ui_scale() -> UiScale {
    current_ui_scale()
}

pub fn set_ui_scale(scale: UiScale) {
    UI_SCALE.store(scale as u8, Ordering::Relaxed);
}

pub fn ui_scale_px(base: usize) -> usize {
    let factor = current_ui_scale().factor();
    let denom = UiScale::Normal.factor();
    base.saturating_mul(factor) / denom
}

fn format_mem_usage() -> String {
    let lock = crate::memory::buddy::get_allocator();
    let (free, total) = {
        let guard = lock.lock();
        let Some(alloc) = guard.as_ref() else {
            return String::from("n/a");
        };
        let (total_pages, allocated_pages) = alloc.page_totals();
        let page_size = 4096usize;
        let total = total_pages.saturating_mul(page_size);
        let used = allocated_pages.saturating_mul(page_size);
        (total.saturating_sub(used), total)
    };
    format!("{}/{}", format_size(free), format_size(total))
}

fn format_size(bytes: usize) -> String {
    const KB: usize = 1024;
    const MB: usize = 1024 * KB;
    const GB: usize = 1024 * MB;
    if bytes >= GB {
        format!("{}G", bytes / GB)
    } else if bytes >= MB {
        format!("{}M", bytes / MB)
    } else if bytes >= KB {
        format!("{}K", bytes / KB)
    } else {
        format!("{}B", bytes)
    }
}

fn draw_status_bar_inner(w: &mut VgaWriter, left: &str, right: &str, theme: UiTheme) {
    let saved_clip = w.clip;
    w.reset_clip_rect();

    let (gw, gh) = w.glyph_size();
    if gh == 0 || gw == 0 {
        w.clip = saved_clip;
        return;
    }
    let bar_h = gh;
    let y = w.height().saturating_sub(bar_h);
    w.fill_rect(0, y, w.width(), bar_h, theme.status_bg);

    let left_opts = TextOptions {
        fg: theme.status_text,
        bg: theme.status_bg,
        align: TextAlign::Left,
        wrap: false,
        max_width: Some(w.width().saturating_sub(8)),
    };
    w.draw_text(0, y, left, left_opts);

    let right_opts = TextOptions {
        fg: theme.status_text,
        bg: theme.status_bg,
        align: TextAlign::Right,
        wrap: false,
        max_width: Some(w.width()),
    };
    w.draw_text(0, y, right, right_opts);
    w.clip = saved_clip;
}

#[allow(clippy::too_many_arguments)]
pub fn init(
    fb_addr: u64,
    fb_width: u32,
    fb_height: u32,
    pitch: u32,
    bpp: u16,
    red_size: u8,
    red_shift: u8,
    green_size: u8,
    green_shift: u8,
    blue_size: u8,
    blue_shift: u8,
) {
    if fb_addr == 0 || fb_width == 0 || fb_height == 0 || pitch == 0 {
        VGA_AVAILABLE.store(false, Ordering::Relaxed);
        log::info!("Framebuffer console unavailable (no framebuffer)");
        return;
    }

    if bpp != 24 && bpp != 32 {
        VGA_AVAILABLE.store(false, Ordering::Relaxed);
        log::info!("Framebuffer console unavailable (unsupported bpp={})", bpp);
        return;
    }

    let fmt = PixelFormat {
        bpp,
        red_size,
        red_shift,
        green_size,
        green_shift,
        blue_size,
        blue_shift,
    };

    let mut writer = VGA_WRITER.lock();
    if writer.configure(
        fb_addr as *mut u8,
        fb_width as usize,
        fb_height as usize,
        pitch as usize,
        fmt,
    ) {
        writer.set_color(Color::LightCyan, Color::Black);
        writer.clear_with(RgbColor::new(0x12, 0x16, 0x1E));
        // Decorative background mark for Strat9 identity.
        let deco_w = (writer.width() / 3).clamp(120, 300);
        let deco_h = (writer.height() / 4).clamp(90, 220);
        let deco_x = writer.width().saturating_sub(deco_w + 24);
        let deco_y = 24;
        writer.draw_strata_stack(deco_x, deco_y, deco_w, deco_h);
        writer.set_rgb_color(RgbColor::new(0xA7, 0xD8, 0xD8), RgbColor::new(0x12, 0x16, 0x1E));
        writer.write_bytes("Strat9-OS v0.1.0\n");
        writer.set_rgb_color(RgbColor::new(0xE2, 0xE8, 0xF0), RgbColor::new(0x12, 0x16, 0x1E));
        VGA_AVAILABLE.store(true, Ordering::Relaxed);
        log::info!(
            "Framebuffer console enabled: {}x{} {}bpp pitch={}",
            fb_width,
            fb_height,
            bpp,
            pitch
        );
        drop(writer);
        draw_boot_status_line(UiTheme::OCEAN_STATUS);
    } else {
        writer.enabled = false;
        VGA_AVAILABLE.store(false, Ordering::Relaxed);
        log::info!("Framebuffer console unavailable (font parse/init failed)");
    }
}

/// Print to framebuffer console (falls back to serial when unavailable).
#[macro_export]
macro_rules! vga_print {
    ($($arg:tt)*) => {
        $crate::arch::x86_64::vga::_print(format_args!($($arg)*));
    };
}

/// Print line to framebuffer console (falls back to serial when unavailable).
#[macro_export]
macro_rules! vga_println {
    () => ($crate::vga_print!("\n"));
    ($($arg:tt)*) => ($crate::vga_print!("{}\n", format_args!($($arg)*)));
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    use core::fmt::Write;
    if is_available() {
        VGA_WRITER.lock().write_fmt(args).ok();
        return;
    }
    crate::arch::x86_64::serial::_print(args);
}

#[derive(Debug, Clone, Copy)]
pub struct Canvas {
    fg: RgbColor,
    bg: RgbColor,
}

impl Default for Canvas {
    fn default() -> Self {
        Self {
            fg: RgbColor::LIGHT_GREY,
            bg: RgbColor::BLACK,
        }
    }
}

impl Canvas {
    pub const fn new(fg: RgbColor, bg: RgbColor) -> Self {
        Self { fg, bg }
    }

    pub fn set_fg(&mut self, fg: RgbColor) {
        self.fg = fg;
    }

    pub fn set_bg(&mut self, bg: RgbColor) {
        self.bg = bg;
    }

    pub fn set_colors(&mut self, fg: RgbColor, bg: RgbColor) {
        self.fg = fg;
        self.bg = bg;
    }

    pub fn set_clip_rect(&self, x: usize, y: usize, w: usize, h: usize) {
        set_clip_rect(x, y, w, h);
    }

    pub fn reset_clip_rect(&self) {
        reset_clip_rect();
    }

    pub fn clear(&self) {
        fill_rect(0, 0, width(), height(), self.bg);
    }

    pub fn pixel(&self, x: usize, y: usize) {
        draw_pixel(x, y, self.fg);
    }

    pub fn line(&self, x0: isize, y0: isize, x1: isize, y1: isize) {
        draw_line(x0, y0, x1, y1, self.fg);
    }

    pub fn rect(&self, x: usize, y: usize, w: usize, h: usize) {
        draw_rect(x, y, w, h, self.fg);
    }

    pub fn fill_rect(&self, x: usize, y: usize, w: usize, h: usize) {
        fill_rect(x, y, w, h, self.fg);
    }

    pub fn fill_rect_alpha(&self, x: usize, y: usize, w: usize, h: usize, alpha: u8) {
        fill_rect_alpha(x, y, w, h, self.fg, alpha);
    }

    pub fn text(&self, x: usize, y: usize, text: &str) {
        draw_text_at(x, y, text, self.fg, self.bg);
    }

    pub fn text_opts(&self, x: usize, y: usize, text: &str, align: TextAlign, wrap: bool, max_width: Option<usize>) -> TextMetrics {
        draw_text(
            x,
            y,
            text,
            TextOptions {
                fg: self.fg,
                bg: self.bg,
                align,
                wrap,
                max_width,
            },
        )
    }

    pub fn measure_text(&self, text: &str, max_width: Option<usize>, wrap: bool) -> TextMetrics {
        measure_text(text, max_width, wrap)
    }

    pub fn blit_rgb(&self, x: usize, y: usize, w: usize, h: usize, pixels: &[RgbColor]) -> bool {
        blit_rgb(x, y, w, h, pixels)
    }

    pub fn blit_rgb24(&self, x: usize, y: usize, w: usize, h: usize, bytes: &[u8]) -> bool {
        blit_rgb24(x, y, w, h, bytes)
    }

    pub fn blit_rgba(&self, x: usize, y: usize, w: usize, h: usize, bytes: &[u8], global_alpha: u8) -> bool {
        blit_rgba(x, y, w, h, bytes, global_alpha)
    }

    pub fn blit_sprite_rgba(&self, x: usize, y: usize, sprite: SpriteRgba<'_>, global_alpha: u8) -> bool {
        blit_sprite_rgba(x, y, sprite, global_alpha)
    }

    pub fn begin_frame(&self) -> bool {
        begin_frame()
    }

    pub fn end_frame(&self) {
        end_frame();
    }

    pub fn ui_clear(&self, theme: UiTheme) {
        ui_clear(theme);
    }

    pub fn ui_panel(&self, x: usize, y: usize, w: usize, h: usize, title: &str, body: &str, theme: UiTheme) {
        ui_draw_panel(x, y, w, h, title, body, theme);
    }

    pub fn ui_status_bar(&self, left: &str, right: &str, theme: UiTheme) {
        ui_draw_status_bar(left, right, theme);
    }

    pub fn system_status_line(&self, theme: UiTheme) {
        draw_system_status_line(theme);
    }

    pub fn layout_screen(&self) -> UiDockLayout {
        UiDockLayout::from_screen()
    }

    pub fn ui_label(&self, label: &UiLabel<'_>) {
        ui_draw_label(label);
    }

    pub fn ui_progress_bar(&self, bar: UiProgressBar) {
        ui_draw_progress_bar(bar);
    }

    pub fn ui_table(&self, table: &UiTable) {
        ui_draw_table(table);
    }
}

pub fn width() -> usize {
    if !is_available() {
        return 0;
    }
    VGA_WRITER.lock().width()
}

pub fn height() -> usize {
    if !is_available() {
        return 0;
    }
    VGA_WRITER.lock().height()
}

pub fn screen_size() -> (usize, usize) {
    (width(), height())
}

pub fn ui_layout_screen() -> UiDockLayout {
    UiDockLayout::from_screen()
}

pub fn glyph_size() -> (usize, usize) {
    if !is_available() {
        return (0, 0);
    }
    VGA_WRITER.lock().glyph_size()
}

pub fn text_cols() -> usize {
    if !is_available() {
        return 0;
    }
    VGA_WRITER.lock().cols()
}

pub fn text_rows() -> usize {
    if !is_available() {
        return 0;
    }
    VGA_WRITER.lock().rows()
}

pub fn set_text_cursor(col: usize, row: usize) {
    if !is_available() {
        return;
    }
    VGA_WRITER.lock().set_cursor_cell(col, row);
}

pub fn double_buffer_mode() -> bool {
    DOUBLE_BUFFER_MODE.load(Ordering::Relaxed)
}

pub fn set_double_buffer_mode(enabled: bool) {
    DOUBLE_BUFFER_MODE.store(enabled, Ordering::Relaxed);
}

pub fn framebuffer_info() -> FramebufferInfo {
    if !is_available() {
        return FramebufferInfo {
            available: false,
            width: 0,
            height: 0,
            pitch: 0,
            bpp: 0,
            red_size: 0,
            red_shift: 0,
            green_size: 0,
            green_shift: 0,
            blue_size: 0,
            blue_shift: 0,
            text_cols: 0,
            text_rows: 0,
            glyph_w: 0,
            glyph_h: 0,
            double_buffer_mode: false,
            double_buffer_enabled: false,
            ui_scale: UiScale::Normal,
        };
    }
    VGA_WRITER.lock().framebuffer_info()
}

pub fn set_text_color(fg: RgbColor, bg: RgbColor) {
    if !is_available() {
        return;
    }
    VGA_WRITER.lock().set_rgb_color(fg, bg);
}

pub fn set_clip_rect(x: usize, y: usize, width: usize, height: usize) {
    if !is_available() {
        return;
    }
    VGA_WRITER.lock().set_clip_rect(x, y, width, height);
}

pub fn reset_clip_rect() {
    if !is_available() {
        return;
    }
    VGA_WRITER.lock().reset_clip_rect();
}

pub fn begin_frame() -> bool {
    if !is_available() {
        return false;
    }
    if !double_buffer_mode() {
        return false;
    }
    VGA_WRITER.lock().enable_double_buffer()
}

pub fn end_frame() {
    if !is_available() {
        return;
    }
    let mut writer = VGA_WRITER.lock();
    writer.present();
    writer.disable_double_buffer(false);
}

pub fn present() {
    if !is_available() {
        return;
    }
    VGA_WRITER.lock().present();
}

pub fn draw_pixel(x: usize, y: usize, color: RgbColor) {
    if !is_available() {
        return;
    }
    VGA_WRITER.lock().draw_pixel(x, y, color);
}

pub fn draw_pixel_alpha(x: usize, y: usize, color: RgbColor, alpha: u8) {
    if !is_available() {
        return;
    }
    VGA_WRITER.lock().draw_pixel_alpha(x, y, color, alpha);
}

pub fn draw_line(x0: isize, y0: isize, x1: isize, y1: isize, color: RgbColor) {
    if !is_available() {
        return;
    }
    VGA_WRITER.lock().draw_line(x0, y0, x1, y1, color);
}

pub fn draw_rect(x: usize, y: usize, width: usize, height: usize, color: RgbColor) {
    if !is_available() {
        return;
    }
    VGA_WRITER.lock().draw_rect(x, y, width, height, color);
}

pub fn fill_rect(x: usize, y: usize, width: usize, height: usize, color: RgbColor) {
    if !is_available() {
        return;
    }
    VGA_WRITER.lock().fill_rect(x, y, width, height, color);
}

pub fn fill_rect_alpha(x: usize, y: usize, width: usize, height: usize, color: RgbColor, alpha: u8) {
    if !is_available() {
        return;
    }
    VGA_WRITER.lock().fill_rect_alpha(x, y, width, height, color, alpha);
}

pub fn blit_rgb(dst_x: usize, dst_y: usize, src_width: usize, src_height: usize, pixels: &[RgbColor]) -> bool {
    if !is_available() {
        return false;
    }
    VGA_WRITER
        .lock()
        .blit_rgb(dst_x, dst_y, src_width, src_height, pixels)
}

pub fn blit_rgb24(dst_x: usize, dst_y: usize, src_width: usize, src_height: usize, bytes: &[u8]) -> bool {
    if !is_available() {
        return false;
    }
    VGA_WRITER
        .lock()
        .blit_rgb24(dst_x, dst_y, src_width, src_height, bytes)
}

pub fn blit_rgba(
    dst_x: usize,
    dst_y: usize,
    src_width: usize,
    src_height: usize,
    bytes: &[u8],
    global_alpha: u8,
) -> bool {
    if !is_available() {
        return false;
    }
    VGA_WRITER
        .lock()
        .blit_rgba(dst_x, dst_y, src_width, src_height, bytes, global_alpha)
}

pub fn blit_sprite_rgba(dst_x: usize, dst_y: usize, sprite: SpriteRgba<'_>, global_alpha: u8) -> bool {
    if !is_available() {
        return false;
    }
    VGA_WRITER
        .lock()
        .blit_sprite_rgba(dst_x, dst_y, sprite, global_alpha)
}

pub fn draw_text_at(pixel_x: usize, pixel_y: usize, text: &str, fg: RgbColor, bg: RgbColor) {
    if !is_available() {
        return;
    }
    VGA_WRITER
        .lock()
        .draw_text_at(pixel_x, pixel_y, text, fg, bg);
}

pub fn draw_text(pixel_x: usize, pixel_y: usize, text: &str, opts: TextOptions) -> TextMetrics {
    if !is_available() {
        return TextMetrics {
            width: 0,
            height: 0,
            lines: 0,
        };
    }
    VGA_WRITER.lock().draw_text(pixel_x, pixel_y, text, opts)
}

pub fn measure_text(text: &str, max_width: Option<usize>, wrap: bool) -> TextMetrics {
    if !is_available() {
        return TextMetrics {
            width: 0,
            height: 0,
            lines: 0,
        };
    }
    VGA_WRITER.lock().measure_text(text, max_width, wrap)
}

pub fn ui_clear(theme: UiTheme) {
    let _ = with_writer(|w| w.clear_with(theme.background));
}

pub fn ui_draw_panel(
    x: usize,
    y: usize,
    width: usize,
    height: usize,
    title: &str,
    body: &str,
    theme: UiTheme,
) {
    let _ = with_writer(|w| {
        if width < 8 || height < 8 {
            return;
        }
        let (gw, gh) = w.glyph_size();
        w.fill_rect(x, y, width, height, theme.panel_bg);
        w.draw_rect(x, y, width, height, theme.panel_border);

        let title_h = gh + 6;
        w.fill_rect(
            x.saturating_add(1),
            y.saturating_add(1),
            width.saturating_sub(2),
            title_h,
            theme.accent,
        );
        let title_opts = TextOptions {
            fg: theme.text,
            bg: theme.accent,
            align: TextAlign::Left,
            wrap: false,
            max_width: Some(width.saturating_sub(10)),
        };
        w.draw_text(x.saturating_add(6), y.saturating_add(3), title, title_opts);

        let body_opts = TextOptions {
            fg: theme.text,
            bg: theme.panel_bg,
            align: TextAlign::Left,
            wrap: true,
            max_width: Some(width.saturating_sub(10)),
        };
        w.draw_text(
            x.saturating_add(6),
            y.saturating_add(title_h + 4),
            body,
            body_opts,
        );

        // Visual separator.
        w.fill_rect(
            x.saturating_add(1),
            y.saturating_add(title_h + 1),
            width.saturating_sub(2),
            1,
            theme.panel_border,
        );
        // Keep an implicit reference to glyph width to avoid dead code warning for gw in tiny fonts.
        let _ = gw;
    });
}

pub fn ui_draw_panel_widget(panel: &UiPanel<'_>) {
    ui_draw_panel(
        panel.rect.x,
        panel.rect.y,
        panel.rect.w,
        panel.rect.h,
        panel.title,
        panel.body,
        panel.theme,
    );
}

pub fn ui_draw_label(label: &UiLabel<'_>) {
    let _ = with_writer(|w| {
        w.draw_text(
            label.rect.x,
            label.rect.y,
            label.text,
            TextOptions {
                fg: label.fg,
                bg: label.bg,
                align: label.align,
                wrap: false,
                max_width: Some(label.rect.w),
            },
        );
    });
}

pub fn ui_draw_progress_bar(bar: UiProgressBar) {
    let _ = with_writer(|w| {
        if bar.rect.w < 3 || bar.rect.h < 3 {
            return;
        }
        let value = core::cmp::min(bar.value, 100) as usize;
        w.fill_rect(bar.rect.x, bar.rect.y, bar.rect.w, bar.rect.h, bar.bg);
        w.draw_rect(bar.rect.x, bar.rect.y, bar.rect.w, bar.rect.h, bar.border);
        let inner_w = bar.rect.w.saturating_sub(2);
        let fill_w = inner_w.saturating_mul(value) / 100;
        if fill_w > 0 {
            w.fill_rect(
                bar.rect.x + 1,
                bar.rect.y + 1,
                fill_w,
                bar.rect.h.saturating_sub(2),
                bar.fg,
            );
        }
    });
}

pub fn ui_draw_table(table: &UiTable) {
    let _ = with_writer(|w| {
        if table.rect.w < 8 || table.rect.h < 8 {
            return;
        }
        let (_gw, gh) = w.glyph_size();
        if gh == 0 {
            return;
        }

        w.fill_rect(
            table.rect.x,
            table.rect.y,
            table.rect.w,
            table.rect.h,
            table.theme.panel_bg,
        );
        w.draw_rect(
            table.rect.x,
            table.rect.y,
            table.rect.w,
            table.rect.h,
            table.theme.panel_border,
        );

        let cols = core::cmp::max(1, table.headers.len());
        let col_w = table.rect.w / cols;
        let header_h = gh + 2;
        w.fill_rect(
            table.rect.x + 1,
            table.rect.y + 1,
            table.rect.w.saturating_sub(2),
            header_h,
            table.theme.accent,
        );

        for (i, h) in table.headers.iter().enumerate() {
            let x = table.rect.x + i * col_w + 2;
            w.draw_text(
                x,
                table.rect.y + 1,
                h,
                TextOptions {
                    fg: table.theme.text,
                    bg: table.theme.accent,
                    align: TextAlign::Left,
                    wrap: false,
                    max_width: Some(col_w.saturating_sub(4)),
                },
            );
        }

        let mut y = table.rect.y + header_h + 2;
        for row in &table.rows {
            if y + gh > table.rect.y + table.rect.h {
                break;
            }
            for c in 0..cols {
                if c >= row.len() {
                    continue;
                }
                let x = table.rect.x + c * col_w + 2;
                w.draw_text(
                    x,
                    y,
                    &row[c],
                    TextOptions {
                        fg: table.theme.text,
                        bg: table.theme.panel_bg,
                        align: TextAlign::Left,
                        wrap: false,
                        max_width: Some(col_w.saturating_sub(4)),
                    },
                );
            }
            y += gh;
        }
    });
}

pub fn ui_draw_status_bar(left: &str, right: &str, theme: UiTheme) {
    let _ = with_writer(|w| {
        draw_status_bar_inner(w, left, right, theme);
    });
}

pub fn set_status_hostname(hostname: &str) {
    let mut guard = STATUS_LINE_INFO.lock();
    if guard.is_none() {
        *guard = Some(StatusLineInfo {
            hostname: String::new(),
            ip: String::from("n/a"),
        });
    }
    if let Some(info) = guard.as_mut() {
        info.hostname.clear();
        info.hostname.push_str(hostname);
    }
}

pub fn set_status_ip(ip: &str) {
    let mut guard = STATUS_LINE_INFO.lock();
    if guard.is_none() {
        *guard = Some(StatusLineInfo {
            hostname: String::from("strat9"),
            ip: String::new(),
        });
    }
    if let Some(info) = guard.as_mut() {
        info.ip.clear();
        info.ip.push_str(ip);
    }
}

pub fn draw_system_status_line(theme: UiTheme) {
    let info = status_line_info();
    let version = env!("CARGO_PKG_VERSION");
    let tick = crate::process::scheduler::ticks();
    let uptime = format_uptime_from_ticks(tick);
    let mem = format_mem_usage();
    let fps = current_fps(tick);
    let left = format!(" {} ", info.hostname);
    let right = format!(
        "ip:{}  ver:{}  up:{}  fps:{}  load:n/a  mem:{} ",
        info.ip, version, uptime, fps, mem
    );
    ui_draw_status_bar(&left, &right, theme);
}

fn draw_boot_status_line(theme: UiTheme) {
    let _ = with_writer(|w| {
        draw_status_bar_inner(
            w,
            " strat9 ",
            "ip:n/a  ver:boot  up:00:00:00  load:n/a  mem:n/a ",
            theme,
        );
    });
}

pub fn maybe_refresh_system_status_line(theme: UiTheme) {
    if !is_available() {
        return;
    }

    let tick = crate::process::scheduler::ticks();
    let last = STATUS_LAST_REFRESH_TICK.load(Ordering::Relaxed);
    if tick.saturating_sub(last) < STATUS_REFRESH_PERIOD_TICKS {
        return;
    }
    if STATUS_LAST_REFRESH_TICK
        .compare_exchange(last, tick, Ordering::Relaxed, Ordering::Relaxed)
        .is_err()
    {
        return;
    }

    let info = if let Some(guard) = STATUS_LINE_INFO.try_lock() {
        guard.as_ref().cloned().unwrap_or(StatusLineInfo {
            hostname: String::from("strat9"),
            ip: String::from("n/a"),
        })
    } else {
        return;
    };

    let version = env!("CARGO_PKG_VERSION");
    let uptime = format_uptime_from_ticks(tick);
    let mem = format_mem_usage();
    let fps = current_fps(tick);
    let left = format!(" {} ", info.hostname);
    let right = format!(
        "ip:{}  ver:{}  up:{}  fps:{}  load:n/a  mem:{} ",
        info.ip, version, uptime, fps, mem
    );

    if let Some(mut writer) = VGA_WRITER.try_lock() {
        draw_status_bar_inner(&mut writer, &left, &right, theme);
    }
}

pub extern "C" fn status_line_task_main() -> ! {
    let mut last_tick = 0u64;
    loop {
        let tick = crate::process::scheduler::ticks();
        if tick != last_tick {
            last_tick = tick;
            maybe_refresh_system_status_line(UiTheme::OCEAN_STATUS);
        }
        crate::process::yield_task();
    }
}

pub fn draw_strata_stack(origin_x: usize, origin_y: usize, layer_w: usize, layer_h: usize) {
    if !is_available() {
        return;
    }
    VGA_WRITER
        .lock()
        .draw_strata_stack(origin_x, origin_y, layer_w, layer_h);
}
