//! Framebuffer text console (Limine framebuffer + PSF font).
//! https://en.wikipedia.org/wiki/PC_Screen_Font
//!
//! Keeps the existing `vga_print!` / `vga_println!` API but renders text into
//! the graphical framebuffer when available. Falls back to serial otherwise.

use alloc::vec::Vec;
use core::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
};
use spin::Mutex;

/// Whether framebuffer console is available.
static VGA_AVAILABLE: AtomicBool = AtomicBool::new(false);

const FONT_PSF: &[u8] = include_bytes!("fonts/zap-ext-vga16.psf");

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
pub struct UiTheme {
    pub background: RgbColor,
    pub panel_bg: RgbColor,
    pub panel_border: RgbColor,
    pub text: RgbColor,
    pub accent: RgbColor,
    pub status_bg: RgbColor,
    pub status_text: RgbColor,
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
        });
    }

    // PSF2
    if font.len() >= 32 && font[0] == 0x72 && font[1] == 0xB5 && font[2] == 0x4A && font[3] == 0x86
    {
        let rd_u32 = |off: usize| -> u32 {
            u32::from_le_bytes([font[off], font[off + 1], font[off + 2], font[off + 3]])
        };
        let headersize = rd_u32(8) as usize;
        let glyph_count = rd_u32(16) as usize;
        let bytes_per_glyph = rd_u32(20) as usize;
        let glyph_h = rd_u32(24) as usize;
        let glyph_w = rd_u32(28) as usize;
        return Some(FontInfo {
            glyph_count,
            bytes_per_glyph,
            glyph_w,
            glyph_h,
            data_offset: headersize,
        });
    }

    None
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
    clip: ClipRect,
    back_buffer: Option<Vec<u32>>,
    draw_to_back: bool,
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
            },
            clip: ClipRect {
                x: 0,
                y: 0,
                w: 0,
                h: 0,
            },
            back_buffer: None,
            draw_to_back: false,
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
        let cols = fb_width / font_info.glyph_w;
        let rows = fb_height / font_info.glyph_h;
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
        self.clip = ClipRect {
            x: 0,
            y: 0,
            w: fb_width,
            h: fb_height,
        };
        self.back_buffer = None;
        self.draw_to_back = false;
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

    pub fn enabled(&self) -> bool {
        self.enabled
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
        true
    }

    pub fn disable_double_buffer(&mut self, present: bool) {
        if present {
            self.present();
        }
        self.draw_to_back = false;
    }

    pub fn present(&mut self) {
        if !self.enabled {
            return;
        }
        let Some(buf) = self.back_buffer.as_ref() else {
            return;
        };
        let buf_ptr = buf.as_ptr();
        for y in 0..self.fb_height {
            for x in 0..self.fb_width {
                let idx = y * self.fb_width + x;
                let packed = unsafe { *buf_ptr.add(idx) };
                self.write_hw_pixel_packed(x, y, packed);
            }
        }
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

    fn write_hw_pixel_packed(&mut self, x: usize, y: usize, color: u32) {
        let off = y * self.pitch + x * (self.fmt.bpp as usize / 8);
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
        let off = y * self.pitch + x * (self.fmt.bpp as usize / 8);
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
                return;
            }
        }

        if self.fmt.bpp == 32 {
            for py in sy..(sy + sh) {
                let row_off = py * self.pitch + sx * 4;
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
            if ch.is_ascii() {
                self.write_char(ch as u8);
            } else {
                self.write_char(b'?');
            }
            if self.row >= self.rows {
                break;
            }
        }

        self.col = saved_col;
        self.row = saved_row;
        self.fg = saved_fg;
        self.bg = saved_bg;
    }

    fn draw_glyph_at_pixel(&mut self, pixel_x: usize, pixel_y: usize, ch: u8, fg: u32, bg: u32) {
        if !self.enabled {
            return;
        }
        let glyph_index = if (ch as usize) < self.font_info.glyph_count {
            ch as usize
        } else {
            b'?' as usize
        };
        let start = self.font_info.data_offset + glyph_index * self.font_info.bytes_per_glyph;
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

    fn layout_text_lines(&self, text: &str, wrap: bool, max_cols: Option<usize>) -> Vec<Vec<u8>> {
        let mut lines: Vec<Vec<u8>> = Vec::new();
        let mut current: Vec<u8> = Vec::new();
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

            if ch.is_ascii() {
                current.push(ch as u8);
            } else {
                current.push(b'?');
            }
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

    fn draw_glyph(&mut self, cx: usize, cy: usize, ch: u8) {
        if !self.enabled {
            return;
        }
        let glyph_index = if (ch as usize) < self.font_info.glyph_count {
            ch as usize
        } else {
            b'?' as usize
        };
        let start = self.font_info.data_offset + glyph_index * self.font_info.bytes_per_glyph;
        let glyph = &self.font[start..start + self.font_info.bytes_per_glyph];
        let row_bytes = self.font_info.glyph_w.div_ceil(8);

        for gy in 0..self.font_info.glyph_h {
            for gx in 0..self.font_info.glyph_w {
                let byte = glyph[gy * row_bytes + gx / 8];
                let mask = 0x80 >> (gx % 8);
                let px = cx * self.font_info.glyph_w + gx;
                let py = cy * self.font_info.glyph_h + gy;
                let color = if (byte & mask) != 0 { self.fg } else { self.bg };
                self.put_pixel_raw(px, py, color);
            }
        }
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
        if dy >= self.fb_height {
            self.clear();
            return;
        }

        let move_rows = self.fb_height - dy;
        if self.draw_to_back_buffer() {
            if let Some(buf) = self.back_buffer.as_mut() {
                let src_start = dy * self.fb_width;
                let src_end = self.fb_height * self.fb_width;
                buf.copy_within(src_start..src_end, 0);
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

    fn write_char(&mut self, c: u8) {
        if !self.enabled {
            return;
        }
        match c {
            b'\n' => {
                self.col = 0;
                self.row += 1;
            }
            b'\r' => self.col = 0,
            b'\t' => self.col = (self.col + 4) & !3,
            0x08 => {
                if self.col > 0 {
                    self.col -= 1;
                    self.draw_glyph(self.col, self.row, b' ');
                }
            }
            byte => {
                self.draw_glyph(self.col, self.row, byte);
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
        for ch in s.chars() {
            if ch.is_ascii() {
                self.write_char(ch as u8);
            } else {
                self.write_char(b'?');
            }
        }
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
        writer.clear();
        // Decorative background mark for Strat9 identity.
        let deco_w = (writer.width() / 3).clamp(120, 300);
        let deco_h = (writer.height() / 4).clamp(90, 220);
        let deco_x = writer.width().saturating_sub(deco_w + 24);
        let deco_y = 24;
        writer.draw_strata_stack(deco_x, deco_y, deco_w, deco_h);
        writer.write_bytes("Strat9-OS v0.1.0\n");
        writer.set_color(Color::LightGrey, Color::Black);
        VGA_AVAILABLE.store(true, Ordering::Relaxed);
        log::info!(
            "Framebuffer console enabled: {}x{} {}bpp pitch={}",
            fb_width,
            fb_height,
            bpp,
            pitch
        );
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

pub fn glyph_size() -> (usize, usize) {
    if !is_available() {
        return (0, 0);
    }
    VGA_WRITER.lock().glyph_size()
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

pub fn ui_draw_status_bar(left: &str, right: &str, theme: UiTheme) {
    let _ = with_writer(|w| {
        let (gw, gh) = w.glyph_size();
        if gh == 0 || gw == 0 {
            return;
        }
        let bar_h = gh + 4;
        let y = w.height().saturating_sub(bar_h);
        w.fill_rect(0, y, w.width(), bar_h, theme.status_bg);

        let left_opts = TextOptions {
            fg: theme.status_text,
            bg: theme.status_bg,
            align: TextAlign::Left,
            wrap: false,
            max_width: Some(w.width().saturating_sub(8)),
        };
        w.draw_text(4, y + 2, left, left_opts);

        let right_opts = TextOptions {
            fg: theme.status_text,
            bg: theme.status_bg,
            align: TextAlign::Right,
            wrap: false,
            max_width: Some(w.width().saturating_sub(8)),
        };
        w.draw_text(4, y + 2, right, right_opts);
    });
}

pub fn draw_strata_stack(origin_x: usize, origin_y: usize, layer_w: usize, layer_h: usize) {
    if !is_available() {
        return;
    }
    VGA_WRITER
        .lock()
        .draw_strata_stack(origin_x, origin_y, layer_w, layer_h);
}
