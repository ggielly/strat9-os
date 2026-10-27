//! Console renderer: glyph cache/atlas, per-row damage batching, present.
//!
//! Output goes to `/dev/display/0.0`; presentation is requested through
//! `/dev/display/damage` with the binary `DMG2` protocol (a list of
//! rectangles), so a frame costs at most one present syscall.
//!
//! Text is rendered in RAM into 8x16 tiles cached per (codepoint, fg, bg) and
//! sent as one rectangle per changed row run. Non-ASCII Latin-1 letters are
//! synthesised from their base ASCII glyph plus an accent; a few common
//! symbols are drawn procedurally; anything else falls back to '?'.

use alloc::vec::Vec;

use crate::scrollback::Cell;
use strat9_syscall::{call, number, syscall6};

const GLYPH_W: usize = 8;
const GLYPH_H: usize = 16;
const MAX_COLS: usize = 256;
const MAX_ROWS: usize = 64;

/// Maximum cells composed into one scheme write (bounds `row_buf`).
const MAX_RUN_CELLS: usize = 32;
/// Maximum distinct damage rectangles per frame before merging to a bbox.
const MAX_DAMAGE_RECTS: usize = 8;
/// Number of cached coloured glyph tiles (atlas).
const GLYPH_CACHE: usize = 32;

static FONT_8X16: [[u8; 16]; 95] = include!("font_data.rs");

pub struct Renderer {
    fb_fd: usize,
    /// /dev/display/damage : binary DMG2 present commands.
    dmg_fd: usize,
    _fb_width: usize,
    _fb_height: usize,
    pub cols: usize,
    pub rows: usize,
    prev_cells: [[Cell; MAX_COLS]; MAX_ROWS],
    prev_initialized: bool,
    prev_cursor_row: usize,
    prev_cursor_col: usize,
    prev_cursor_visible: bool,
    glyphs: GlyphCache,
    /// `MAP_SHARED` view of the display surface, when available. With it,
    /// pixels are written directly and only damage messages go to the kernel.
    surface: Option<SurfaceMap>,
    /// Reused rectangle packet for one row run (fallback write path).
    row_buf: Vec<u8>,
    damage: [(usize, usize, usize, usize); MAX_DAMAGE_RECTS],
    damage_len: usize,
}

// SAFETY: Renderer contains fds (usize) and plain data; only the main event
// loop accesses it, so no cross-thread aliasing occurs.
unsafe impl Send for Renderer {}

#[derive(Clone, Copy)]
struct GlyphTile {
    ch: u32,
    fg: u32,
    bg: u32,
    pixels: [u32; GLYPH_W * GLYPH_H],
}

struct GlyphCache {
    entries: [Option<GlyphTile>; GLYPH_CACHE],
    next: usize,
}

/// Direct mapping of the display surface (native pixel format).
#[derive(Clone, Copy)]
struct SurfaceMap {
    addr: *mut u8,
    stride: usize,
    bpp: u8,
    red_shift: u8,
    green_shift: u8,
    blue_shift: u8,
}

impl SurfaceMap {
    fn pack(&self, color: u32) -> u32 {
        let r = (color >> 16) & 0xFF;
        let g = (color >> 8) & 0xFF;
        let b = color & 0xFF;
        let mut packed = (r << self.red_shift) | (g << self.green_shift) | (b << self.blue_shift);
        if self.bpp == 32 {
            packed |= 0xFF00_0000;
        }
        packed
    }
}

impl GlyphCache {
    const fn new() -> Self {
        Self {
            entries: [None; GLYPH_CACHE],
            next: 0,
        }
    }
}

impl Renderer {
    pub fn open() -> Option<Self> {
        // 0x2 = OpenFlags::WRITE (Strat9 native flags, not POSIX).
        let fd = call::openat(0, "/dev/display/0.0", 0x2, 0).ok()?;
        let dmg_fd = match call::openat(0, "/dev/display/damage", 0x2, 0) {
            Ok(fd) => fd,
            Err(_) => {
                let _ = call::debug_log(b"[console] FATAL: cannot open /dev/display/damage\n");
                return None;
            }
        };
        let info_fd = call::openat(0, "/dev/display/info", 0x1, 0).ok()?;
        let mut info_buf = [0u8; 256];
        let _ = call::read(info_fd, &mut info_buf);
        let _ = call::close(info_fd);

        let info_str = core::str::from_utf8(&info_buf).unwrap_or("display.0=800x600");
        let (w, h) = parse_display_size(info_str).unwrap_or((800, 600));

        // Zero-copy path: map the frame-backed surface writable. On any
        // failure, fall back to the rectangle write protocol.
        let surface = map_surface(fd, info_str, w, h);

        let cols = w / GLYPH_W;
        let rows = h / GLYPH_H;
        let blank = Cell::blank(0xE2E8F0, 0x12161E);

        Some(Renderer {
            fb_fd: fd,
            dmg_fd,
            _fb_width: w,
            _fb_height: h,
            cols: cols.min(MAX_COLS),
            rows: rows.max(1).min(MAX_ROWS),
            prev_cells: [[blank; MAX_COLS]; MAX_ROWS],
            prev_initialized: false,
            prev_cursor_row: usize::MAX,
            prev_cursor_col: usize::MAX,
            prev_cursor_visible: false,
            glyphs: GlyphCache::new(),
            surface,
            row_buf: Vec::with_capacity(6 + MAX_RUN_CELLS * GLYPH_W * GLYPH_H * 3),
            damage: [(0, 0, 0, 0); MAX_DAMAGE_RECTS],
            damage_len: 0,
        })
    }

    pub fn render(
        &mut self,
        cells: &[[Cell; MAX_COLS]; MAX_ROWS],
        cursor_row: usize,
        cursor_col: usize,
        rows: usize,
        cursor_visible: bool,
    ) {
        self.damage_len = 0;

        for row in 0..rows.min(self.rows) {
            // Redraw the whole span between the first and last changed cell:
            // one rectangle per row run, unchanged cells in between included.
            let mut first: Option<usize> = None;
            let mut last = 0usize;
            for col in 0..self.cols {
                if self.cell_needs_redraw(cells, row, col, cursor_row, cursor_col, cursor_visible) {
                    if first.is_none() {
                        first = Some(col);
                    }
                    last = col;
                }
            }

            if let Some(start) = first {
                self.render_row(
                    cells,
                    row,
                    start,
                    last,
                    cursor_row,
                    cursor_col,
                    cursor_visible,
                );
                self.add_damage(
                    start * GLYPH_W,
                    row * GLYPH_H,
                    (last - start + 1) * GLYPH_W,
                    GLYPH_H,
                );
            }
        }

        self.prev_initialized = true;
        self.prev_cursor_row = cursor_row;
        self.prev_cursor_col = cursor_col;
        self.prev_cursor_visible = cursor_visible;

        if self.damage_len > 0 {
            self.submit_damage();
        }
    }

    fn cell_needs_redraw(
        &self,
        cells: &[[Cell; MAX_COLS]; MAX_ROWS],
        row: usize,
        col: usize,
        cursor_row: usize,
        cursor_col: usize,
        cursor_visible: bool,
    ) -> bool {
        if !self.prev_initialized {
            return true;
        }
        let cell = cells[row][col];
        let prev = self.prev_cells[row][col];
        let is_cursor = cursor_visible && row == cursor_row && col == cursor_col;
        let was_cursor =
            self.prev_cursor_visible && row == self.prev_cursor_row && col == self.prev_cursor_col;
        cell.ch != prev.ch || cell.fg != prev.fg || cell.bg != prev.bg || is_cursor != was_cursor
    }

    /// Compose one row span into `MAX_RUN_CELLS`-sized rectangles and write
    /// each with a single scheme write.
    fn render_row(
        &mut self,
        cells: &[[Cell; MAX_COLS]; MAX_ROWS],
        row: usize,
        start: usize,
        end: usize,
        cursor_row: usize,
        cursor_col: usize,
        cursor_visible: bool,
    ) {
        let surface = self.surface;
        let bytes_pp = surface.map(|s| s.bpp as usize / 8).unwrap_or(0);

        let mut chunk_start = start;
        while chunk_start <= end {
            let chunk_end = (chunk_start + MAX_RUN_CELLS - 1).min(end);
            let width_cells = chunk_end - chunk_start + 1;

            if let Some(s) = surface {
                // Zero-copy: compose straight into the mapped surface in its
                // native pixel layout. No write syscall at all.
                for gy in 0..GLYPH_H {
                    for col in chunk_start..=chunk_end {
                        let cell = cells[row][col];
                        let is_cursor = cursor_visible && row == cursor_row && col == cursor_col;
                        let (fg, bg) = if is_cursor {
                            (cell.bg, cell.fg)
                        } else {
                            (cell.fg, cell.bg)
                        };
                        let tile = self.glyph_tile(cell.ch, fg, bg);
                        for gx in 0..GLYPH_W {
                            let packed = s.pack(tile[gy * GLYPH_W + gx]);
                            let off = row * s.stride + (col * GLYPH_W + gx) * bytes_pp;
                            unsafe {
                                if s.bpp == 32 {
                                    core::ptr::write_unaligned(s.addr.add(off) as *mut u32, packed);
                                } else {
                                    *s.addr.add(off) = packed as u8;
                                    *s.addr.add(off + 1) = (packed >> 8) as u8;
                                    *s.addr.add(off + 2) = (packed >> 16) as u8;
                                }
                            }
                        }
                    }
                }
            } else {
                self.row_buf.clear();
                let x = (chunk_start * GLYPH_W) as u16;
                let y = (row * GLYPH_H) as u16;
                let w = (width_cells * GLYPH_W) as u16;
                self.row_buf.extend_from_slice(&x.to_le_bytes());
                self.row_buf.extend_from_slice(&y.to_le_bytes());
                self.row_buf.extend_from_slice(&w.to_le_bytes());

                for gy in 0..GLYPH_H {
                    for col in chunk_start..=chunk_end {
                        let cell = cells[row][col];
                        let is_cursor = cursor_visible && row == cursor_row && col == cursor_col;
                        let (fg, bg) = if is_cursor {
                            (cell.bg, cell.fg)
                        } else {
                            (cell.fg, cell.bg)
                        };
                        let tile = self.glyph_tile(cell.ch, fg, bg);
                        for gx in 0..GLYPH_W {
                            let color = tile[gy * GLYPH_W + gx];
                            // Wire format is BGR888.
                            self.row_buf.push(color as u8);
                            self.row_buf.push((color >> 8) as u8);
                            self.row_buf.push((color >> 16) as u8);
                        }
                    }
                }

                let _ = call::write(self.fb_fd, &self.row_buf);
            }

            for col in chunk_start..=chunk_end {
                self.prev_cells[row][col] = cells[row][col];
            }
            chunk_start = chunk_end + 1;
        }
    }

    /// Return the coloured 8x16 tile for `(ch, fg, bg)`, building and caching
    /// it on first use. The tile is returned by value (512 bytes) so callers
    /// can keep mutating `self.row_buf` without borrow conflicts.
    fn glyph_tile(&mut self, ch: u32, fg: u32, bg: u32) -> [u32; GLYPH_W * GLYPH_H] {
        for entry in self.glyphs.entries.iter().flatten() {
            if entry.ch == ch && entry.fg == fg && entry.bg == bg {
                return entry.pixels;
            }
        }

        let bits = glyph_bits(ch);
        let mut pixels = [bg; GLYPH_W * GLYPH_H];
        for gy in 0..GLYPH_H {
            let row_bits = bits[gy];
            for gx in 0..GLYPH_W {
                if (row_bits >> (7 - gx)) & 1 != 0 {
                    pixels[gy * GLYPH_W + gx] = fg;
                }
            }
        }

        let tile = GlyphTile { ch, fg, bg, pixels };
        let slot = self.glyphs.next % GLYPH_CACHE;
        self.glyphs.entries[slot] = Some(tile);
        self.glyphs.next = self.glyphs.next.wrapping_add(1);
        pixels
    }

    fn add_damage(&mut self, x: usize, y: usize, w: usize, h: usize) {
        if w == 0 || h == 0 {
            return;
        }
        if self.damage_len < MAX_DAMAGE_RECTS {
            self.damage[self.damage_len] = (x, y, w, h);
            self.damage_len += 1;
            return;
        }

        // Rect list full: collapse everything (including the new rect) into
        // its bounding box. Correct, at the cost of extra copied pixels.
        let mut x0 = x;
        let mut y0 = y;
        let mut x1 = x + w;
        let mut y1 = y + h;
        for &(rx, ry, rw, rh) in &self.damage[..self.damage_len] {
            x0 = x0.min(rx);
            y0 = y0.min(ry);
            x1 = x1.max(rx + rw);
            y1 = y1.max(ry + rh);
        }
        self.damage[0] = (x0, y0, x1 - x0, y1 - y0);
        self.damage_len = 1;
    }

    /// Send the frame damage using the binary protocol:
    /// `"DMG2" | count u16le | display u16le | (x,y,w,h) u16le * count`.
    fn submit_damage(&self) {
        let count = self.damage_len;
        let mut msg = Vec::with_capacity(8 + count * 8);
        msg.extend_from_slice(b"DMG2");
        msg.extend_from_slice(&(count as u16).to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes()); // display 0
        for &(x, y, w, h) in &self.damage[..count] {
            msg.extend_from_slice(&(x as u16).to_le_bytes());
            msg.extend_from_slice(&(y as u16).to_le_bytes());
            msg.extend_from_slice(&(w as u16).to_le_bytes());
            msg.extend_from_slice(&(h as u16).to_le_bytes());
        }
        let _ = call::write(self.dmg_fd, &msg);
    }
}

// ---------------------------------------------------------------------------
// Glyph sources: ASCII font, Latin-1 synthesis, small procedural symbols.
// ---------------------------------------------------------------------------

fn glyph_bits(ch: u32) -> [u8; 16] {
    if (0x20..=0x7E).contains(&ch) {
        return FONT_8X16[(ch - 0x20) as usize];
    }
    if let Some((base, accent)) = latin_accent(ch) {
        let mut glyph = FONT_8X16[(base - 0x20) as usize];
        overlay_accent(&mut glyph, accent);
        return glyph;
    }
    if let Some(glyph) = symbol_glyph(ch) {
        return glyph;
    }
    FONT_8X16[(b'?' as u32 - 0x20) as usize]
}

const ACCENT_ACUTE: u8 = 1;
const ACCENT_GRAVE: u8 = 2;
const ACCENT_CIRCUMFLEX: u8 = 3;
const ACCENT_DIAERESIS: u8 = 4;
const ACCENT_TILDE: u8 = 5;
const ACCENT_RING: u8 = 6;
const ACCENT_CEDILLA: u8 = 7;

/// Map common Latin-1 letters to `(base ASCII letter, accent)`.
fn latin_accent(ch: u32) -> Option<(u8, u8)> {
    Some(match ch {
        0xC0 => (b'A', ACCENT_GRAVE),
        0xC1 => (b'A', ACCENT_ACUTE),
        0xC2 => (b'A', ACCENT_CIRCUMFLEX),
        0xC3 => (b'A', ACCENT_TILDE),
        0xC4 => (b'A', ACCENT_DIAERESIS),
        0xC5 => (b'A', ACCENT_RING),
        0xC7 => (b'C', ACCENT_CEDILLA),
        0xC8 => (b'E', ACCENT_GRAVE),
        0xC9 => (b'E', ACCENT_ACUTE),
        0xCA => (b'E', ACCENT_CIRCUMFLEX),
        0xCB => (b'E', ACCENT_DIAERESIS),
        0xCC => (b'I', ACCENT_GRAVE),
        0xCD => (b'I', ACCENT_ACUTE),
        0xCE => (b'I', ACCENT_CIRCUMFLEX),
        0xCF => (b'I', ACCENT_DIAERESIS),
        0xD1 => (b'N', ACCENT_TILDE),
        0xD2 => (b'O', ACCENT_GRAVE),
        0xD3 => (b'O', ACCENT_ACUTE),
        0xD4 => (b'O', ACCENT_CIRCUMFLEX),
        0xD5 => (b'O', ACCENT_TILDE),
        0xD6 => (b'O', ACCENT_DIAERESIS),
        0xD9 => (b'U', ACCENT_GRAVE),
        0xDA => (b'U', ACCENT_ACUTE),
        0xDB => (b'U', ACCENT_CIRCUMFLEX),
        0xDC => (b'U', ACCENT_DIAERESIS),
        0xDD => (b'Y', ACCENT_ACUTE),
        0xE0 => (b'a', ACCENT_GRAVE),
        0xE1 => (b'a', ACCENT_ACUTE),
        0xE2 => (b'a', ACCENT_CIRCUMFLEX),
        0xE3 => (b'a', ACCENT_TILDE),
        0xE4 => (b'a', ACCENT_DIAERESIS),
        0xE5 => (b'a', ACCENT_RING),
        0xE7 => (b'c', ACCENT_CEDILLA),
        0xE8 => (b'e', ACCENT_GRAVE),
        0xE9 => (b'e', ACCENT_ACUTE),
        0xEA => (b'e', ACCENT_CIRCUMFLEX),
        0xEB => (b'e', ACCENT_DIAERESIS),
        0xEC => (b'i', ACCENT_GRAVE),
        0xED => (b'i', ACCENT_ACUTE),
        0xEE => (b'i', ACCENT_CIRCUMFLEX),
        0xEF => (b'i', ACCENT_DIAERESIS),
        0xF1 => (b'n', ACCENT_TILDE),
        0xF2 => (b'o', ACCENT_GRAVE),
        0xF3 => (b'o', ACCENT_ACUTE),
        0xF4 => (b'o', ACCENT_CIRCUMFLEX),
        0xF5 => (b'o', ACCENT_TILDE),
        0xF6 => (b'o', ACCENT_DIAERESIS),
        0xF9 => (b'u', ACCENT_GRAVE),
        0xFA => (b'u', ACCENT_ACUTE),
        0xFB => (b'u', ACCENT_CIRCUMFLEX),
        0xFC => (b'u', ACCENT_DIAERESIS),
        0xFD => (b'y', ACCENT_ACUTE),
        0xFF => (b'y', ACCENT_DIAERESIS),
        _ => return None,
    })
}

fn overlay_accent(glyph: &mut [u8; 16], accent: u8) {
    match accent {
        ACCENT_ACUTE => {
            set(glyph, 5, 0);
            set(glyph, 4, 1);
            set(glyph, 3, 2);
        }
        ACCENT_GRAVE => {
            set(glyph, 3, 0);
            set(glyph, 4, 1);
            set(glyph, 5, 2);
        }
        ACCENT_CIRCUMFLEX => {
            set(glyph, 4, 0);
            set(glyph, 3, 1);
            set(glyph, 5, 1);
            set(glyph, 2, 2);
            set(glyph, 6, 2);
        }
        ACCENT_DIAERESIS => {
            set(glyph, 3, 1);
            set(glyph, 5, 1);
        }
        ACCENT_TILDE => {
            set(glyph, 2, 1);
            set(glyph, 3, 0);
            set(glyph, 4, 1);
            set(glyph, 5, 2);
            set(glyph, 6, 1);
        }
        ACCENT_RING => {
            set(glyph, 4, 0);
            set(glyph, 3, 1);
            set(glyph, 5, 1);
            set(glyph, 4, 2);
        }
        ACCENT_CEDILLA => {
            set(glyph, 4, 14);
            set(glyph, 3, 15);
            set(glyph, 4, 15);
        }
        _ => {}
    }
}

fn symbol_glyph(ch: u32) -> Option<[u8; 16]> {
    let mut g = [0u8; 16];
    match ch {
        // →
        0x2192 => {
            hline(&mut g, 8, 1, 7);
            set(&mut g, 5, 6);
            set(&mut g, 6, 7);
            set(&mut g, 5, 8);
        }
        // ←
        0x2190 => {
            hline(&mut g, 8, 1, 7);
            set(&mut g, 2, 6);
            set(&mut g, 1, 7);
            set(&mut g, 2, 8);
        }
        // ↑
        0x2191 => {
            vline(&mut g, 4, 2, 14);
            set(&mut g, 3, 3);
            set(&mut g, 2, 4);
            set(&mut g, 5, 3);
            set(&mut g, 6, 4);
        }
        // ↓
        0x2193 => {
            vline(&mut g, 4, 2, 14);
            set(&mut g, 3, 12);
            set(&mut g, 2, 11);
            set(&mut g, 5, 12);
            set(&mut g, 6, 11);
        }
        // •
        0x2022 => {
            for y in 7..10 {
                hline(&mut g, y, 3, 4);
            }
        }
        // ≈
        0x2248 => {
            hline(&mut g, 6, 2, 4);
            hline(&mut g, 7, 4, 6);
            hline(&mut g, 9, 2, 4);
            hline(&mut g, 10, 4, 6);
        }
        // ≤
        0x2264 => {
            set(&mut g, 5, 6);
            set(&mut g, 4, 7);
            set(&mut g, 3, 8);
            set(&mut g, 4, 9);
            set(&mut g, 5, 10);
            hline(&mut g, 12, 2, 6);
        }
        // ≥
        0x2265 => {
            set(&mut g, 2, 6);
            set(&mut g, 3, 7);
            set(&mut g, 4, 8);
            set(&mut g, 3, 9);
            set(&mut g, 2, 10);
            hline(&mut g, 12, 2, 6);
        }
        // ±
        0x00B1 => {
            hline(&mut g, 8, 2, 6);
            vline(&mut g, 4, 5, 11);
            hline(&mut g, 13, 2, 6);
        }
        // ×
        0x00D7 => {
            set(&mut g, 3, 6);
            set(&mut g, 4, 7);
            set(&mut g, 5, 8);
            set(&mut g, 4, 9);
            set(&mut g, 3, 10);
            set(&mut g, 5, 6);
            set(&mut g, 6, 7);
            set(&mut g, 6, 9);
            set(&mut g, 5, 10);
        }
        // ÷
        0x00F7 => {
            hline(&mut g, 8, 2, 6);
            set(&mut g, 4, 6);
            set(&mut g, 4, 10);
        }
        // °
        0x00B0 => {
            set(&mut g, 4, 1);
            set(&mut g, 3, 2);
            set(&mut g, 5, 2);
            set(&mut g, 4, 3);
        }
        // µ
        0x00B5 => {
            vline(&mut g, 2, 6, 12);
            vline(&mut g, 5, 6, 12);
            hline(&mut g, 12, 2, 5);
            vline(&mut g, 5, 12, 14);
        }
        // «
        0x00AB => {
            set(&mut g, 4, 6);
            set(&mut g, 3, 7);
            set(&mut g, 2, 8);
            set(&mut g, 3, 9);
            set(&mut g, 4, 10);
            set(&mut g, 6, 6);
            set(&mut g, 5, 7);
            set(&mut g, 4, 8);
            set(&mut g, 5, 9);
            set(&mut g, 6, 10);
        }
        // »
        0x00BB => {
            set(&mut g, 2, 6);
            set(&mut g, 3, 7);
            set(&mut g, 4, 8);
            set(&mut g, 3, 9);
            set(&mut g, 2, 10);
            set(&mut g, 4, 6);
            set(&mut g, 5, 7);
            set(&mut g, 6, 8);
            set(&mut g, 5, 9);
            set(&mut g, 4, 10);
        }
        // …
        0x2026 => {
            set(&mut g, 2, 12);
            set(&mut g, 4, 12);
            set(&mut g, 6, 12);
        }
        _ => return None,
    }
    Some(g)
}

fn set(glyph: &mut [u8; 16], x: usize, y: usize) {
    if x < GLYPH_W && y < GLYPH_H {
        glyph[y] |= 0x80 >> x;
    }
}

fn hline(glyph: &mut [u8; 16], y: usize, x0: usize, x1: usize) {
    for x in x0..=x1.min(GLYPH_W - 1) {
        set(glyph, x, y);
    }
}

fn vline(glyph: &mut [u8; 16], x: usize, y0: usize, y1: usize) {
    for y in y0..=y1.min(GLYPH_H - 1) {
        set(glyph, x, y);
    }
}

fn parse_usize_field(info: &str, key: &str) -> Option<usize> {
    for line in info.lines() {
        if let Some(value) = line.strip_prefix(key) {
            return value.trim().parse().ok();
        }
    }
    None
}

/// Map the display surface writable (`MAP_SHARED`) for zero-copy rendering.
fn map_surface(fd: usize, info: &str, w: usize, h: usize) -> Option<SurfaceMap> {
    let stride = parse_usize_field(info, "stride=").unwrap_or(w * 4);
    let bpp = parse_usize_field(info, "bpp=").unwrap_or(32) as u8;
    if bpp != 24 && bpp != 32 {
        return None;
    }
    let red_shift = parse_usize_field(info, "red_shift=").unwrap_or(16) as u8;
    let green_shift = parse_usize_field(info, "green_shift=").unwrap_or(8) as u8;
    let blue_shift = parse_usize_field(info, "blue_shift=").unwrap_or(0) as u8;

    let len = stride.checked_mul(h)?;
    if len == 0 {
        return None;
    }

    const PROT_READ_WRITE: usize = 3;
    const MAP_SHARED: usize = 1;
    let addr =
        unsafe { syscall6(number::SYS_MMAP, 0, len, PROT_READ_WRITE, MAP_SHARED, fd, 0) }.ok()?;
    if addr == 0 {
        return None;
    }

    Some(SurfaceMap {
        addr: addr as *mut u8,
        stride,
        bpp,
        red_shift,
        green_shift,
        blue_shift,
    })
}

fn parse_display_size(info: &str) -> Option<(usize, usize)> {
    let mut width = None;
    let mut height = None;
    for line in info.lines() {
        if let Some(value) = line.strip_prefix("width=") {
            width = value.trim().parse().ok();
            continue;
        }
        if let Some(value) = line.strip_prefix("height=") {
            height = value.trim().parse().ok();
            continue;
        }
        // Accept both "display.0=800x600" and "display/0=800x600" formats.
        if let Some(eq_pos) = line.find('=') {
            let val = &line[eq_pos + 1..];
            if let Some(x_pos) = val.find('x').or_else(|| val.find('×')) {
                let w: Option<usize> = val[..x_pos].trim().parse().ok();
                let h: Option<usize> = val[x_pos + 1..].trim().parse().ok();
                if let (Some(w), Some(h)) = (w, h) {
                    if w > 0 && h > 0 {
                        return Some((w, h));
                    }
                }
            }
        }
    }
    match (width, height) {
        (Some(w), Some(h)) if w > 0 && h > 0 => Some((w, h)),
        _ => None,
    }
}
