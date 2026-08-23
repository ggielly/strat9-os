//! Display Server for strat9-os (strate-graphical)
//!
//! A Haiku-like Window Server that runs in a silo.
//! Manages windows with decorations, composites to framebuffer via
//! the /dev/display/ kernel scheme, and routes input.

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use alloc::{format, vec, vec::Vec};
use core::{alloc::Layout, panic::PanicInfo};
use strat9_syscall::call;

// ---------------------------------------------------------------------------
// Global allocator (bump + brk)
// ---------------------------------------------------------------------------

alloc_freelist::define_freelist_brk_allocator!(
    pub struct BumpAllocator;
    brk = strat9_syscall::call::brk;
    heap_max = 32 * 1024 * 1024;
);

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    let _ = call::debug_log(b"[display-server] OOM\n");
    loop {
        core::hint::spin_loop();
    }
}

// ============================================================================
// Color
// ============================================================================

#[derive(Clone, Copy, PartialEq, Eq)]
struct Color {
    r: u8,
    g: u8,
    b: u8,
}

impl Color {
    const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b }
    }
    const BLACK: Self = Self::new(0, 0, 0);
    const WHITE: Self = Self::new(255, 255, 255);
    const GRAY: Self = Self::new(180, 180, 180);
    const DARK_GRAY: Self = Self::new(80, 80, 80);
    const LIGHT_GRAY: Self = Self::new(220, 220, 220);
    const BLUE: Self = Self::new(50, 120, 220);
    const DARK_BLUE: Self = Self::new(30, 60, 140);
    const TITLE_BG: Self = Self::new(45, 50, 65);
    const TITLE_ACTIVE: Self = Self::new(50, 100, 200);
    const CLOSE_RED: Self = Self::new(200, 60, 60);
    const CLOSE_HOVER: Self = Self::new(230, 80, 80);
}

// ============================================================================
// Offscreen buffer : composites here, then flushes to /dev/display/0.0
// ============================================================================

struct Buffer {
    w: u32,
    h: u32,
    stride: u32,
    bpp: u8,
    ptr: *mut u8,
}

impl Buffer {
    fn fill(&self, x: u32, y: u32, rw: u32, rh: u32, c: Color) {
        let b = self.bpp as u32 / 8;
        let x2 = x.min(self.w);
        let y2 = y.min(self.h);
        let rw = rw.min(self.w.saturating_sub(x2));
        let rh = rh.min(self.h.saturating_sub(y2));
        for row in y2..y2 + rh {
            for col in x2..x2 + rw {
                let o = (row * self.stride + col * b) as usize;
                unsafe {
                    *self.ptr.add(o) = c.b;
                    *self.ptr.add(o + 1) = c.g;
                    *self.ptr.add(o + 2) = c.r;
                }
            }
        }
    }
    fn hline(&self, x: u32, y: u32, w: u32, c: Color) {
        self.fill(x, y, w, 1, c);
    }
    fn vline(&self, x: u32, y: u32, h: u32, c: Color) {
        self.fill(x, y, 1, h, c);
    }
    fn outline(&self, x: u32, y: u32, w: u32, h: u32, c: Color) {
        self.hline(x, y, w, c);
        self.hline(x, y + h - 1, w, c);
        self.vline(x, y, h, c);
        self.vline(x + w - 1, y, h, c);
    }
    fn pixel(&self, x: i32, y: i32, c: Color) {
        if x < 0 || y < 0 || x >= self.w as i32 || y >= self.h as i32 {
            return;
        }
        let b = self.bpp as u32 / 8;
        let o = (y as u32 * self.stride + x as u32 * b) as usize;
        unsafe {
            *self.ptr.add(o) = c.b;
            *self.ptr.add(o + 1) = c.g;
            *self.ptr.add(o + 2) = c.r;
        }
    }
}

// ============================================================================
// Constants
// ============================================================================

const TITLE_BAR_H: u32 = 22;
const BORDER_W: u32 = 2;
const CLOSE_BTN_SIZE: u32 = 14;
const CLOSE_BTN_PAD: u32 = 4;

// ============================================================================
// Window
// ============================================================================

#[derive(Clone, Copy, PartialEq, Eq)]
struct WId(u32);

struct Win {
    id: WId,
    x: i32,
    y: i32,
    w: u32,
    h: u32,
    title: [u8; 32],
    tlen: u8,
    bg: Color,
    focused: bool,
    visible: bool,
}

impl Win {
    fn new(id: WId, x: i32, y: i32, w: u32, h: u32, t: &str, bg: Color) -> Self {
        let mut buf = [0u8; 32];
        let l = t.len().min(31) as u8;
        buf[..l as usize].copy_from_slice(&t.as_bytes()[..l as usize]);
        Self {
            id,
            x,
            y,
            w,
            h,
            title: buf,
            tlen: l,
            bg,
            focused: true,
            visible: true,
        }
    }
    fn title(&self) -> &str {
        core::str::from_utf8(&self.title[..self.tlen as usize]).unwrap_or("")
    }

    /// Hit-test: does (px,py) land inside the window frame (including decorations)?
    fn hit(&self, px: i32, py: i32) -> bool {
        self.visible
            && px >= self.x
            && px < self.x + self.w as i32
            && py >= self.y
            && py < self.y + self.h as i32
    }

    /// Is (px,py) on the close button?
    fn hit_close(&self, px: i32, py: i32) -> bool {
        let bx = self.x + self.w as i32 - CLOSE_BTN_SIZE as i32 - CLOSE_BTN_PAD as i32;
        let by = self.y + CLOSE_BTN_PAD as i32;
        px >= bx && px < bx + CLOSE_BTN_SIZE as i32 && py >= by && py < by + CLOSE_BTN_SIZE as i32
    }

    /// Is (px,py) on the title bar (for dragging)?
    fn hit_titlebar(&self, px: i32, py: i32) -> bool {
        px >= self.x
            && px < self.x + self.w as i32
            && py >= self.y
            && py < self.y + TITLE_BAR_H as i32
    }

    /// Is (px,py) on the resize grip (bottom-right corner)?
    fn hit_resize(&self, px: i32, py: i32) -> bool {
        let gx = self.x + self.w as i32 - 8;
        let gy = self.y + self.h as i32 - 8;
        px >= gx && px < self.x + self.w as i32 && py >= gy && py < self.y + self.h as i32
    }

    /// Draw the window frame with decorations on the offscreen buffer.
    fn draw(&self, buf: &Buffer) {
        let x = self.x as u32;
        let y = self.y as u32;

        // Drop shadow
        buf.fill(x + 4, y + 4, self.w, self.h, Color::new(0, 0, 0));

        // Window body
        buf.fill(x, y, self.w, self.h, self.bg);

        // Border
        let border = if self.focused {
            Color::BLUE
        } else {
            Color::DARK_GRAY
        };
        buf.outline(x, y, self.w, self.h, border);

        // Title bar
        let title_color = if self.focused {
            Color::TITLE_ACTIVE
        } else {
            Color::TITLE_BG
        };
        buf.fill(x + 1, y + 1, self.w - 2, TITLE_BAR_H, title_color);

        // Title text
        let title = self.title();
        let mut tx = x + 6;
        for &b in title.as_bytes() {
            if b == 0 || tx + 8 > x + self.w - CLOSE_BTN_SIZE - CLOSE_BTN_PAD * 2 {
                break;
            }
            draw_glyph(buf, tx as i32, (y + 5) as i32, b, Color::WHITE);
            tx += 8;
        }

        // Close button
        let cbx = x + self.w - CLOSE_BTN_SIZE - CLOSE_BTN_PAD;
        let cby = y + CLOSE_BTN_PAD;
        buf.fill(cbx, cby, CLOSE_BTN_SIZE, CLOSE_BTN_SIZE, Color::CLOSE_RED);
        buf.outline(
            cbx,
            cby,
            CLOSE_BTN_SIZE,
            CLOSE_BTN_SIZE,
            Color::new(160, 40, 40),
        );
        for i in 2..CLOSE_BTN_SIZE - 2 {
            buf.fill(cbx + i, cby + i, 1, 1, Color::WHITE);
            buf.fill(cbx + CLOSE_BTN_SIZE - 1 - i, cby + i, 1, 1, Color::WHITE);
        }

        // Resize grip
        let gx = x + self.w - 8;
        let gy = y + self.h - 8;
        for i in 0..4u32 {
            buf.fill(gx + i * 2, gy + i * 2, 2, 2, border);
        }
    }
}

// ============================================================================
// Desktop
// ============================================================================

const DESKTOP_BG: Color = Color::new(25, 30, 40);

fn draw_desktop(buf: &Buffer, w: u32, h: u32) {
    // Solid dark background
    buf.fill(0, 0, w, h, DESKTOP_BG);

    // Subtle grid pattern
    for gx in (0..w).step_by(32) {
        buf.vline(gx, 0, h, Color::new(30, 35, 48));
    }
    for gy in (0..h).step_by(32) {
        buf.hline(0, gy, w, Color::new(30, 35, 48));
    }
}

// ============================================================================
// Cursor
// ============================================================================

struct Cursor {
    x: i32,
    y: i32,
}

impl Cursor {
    fn new(sw: u32, sh: u32) -> Self {
        Self {
            x: sw as i32 / 2,
            y: sh as i32 / 2,
        }
    }

    fn draw(&self, buf: &Buffer) {
        let x = self.x;
        let y = self.y;
        // Arrow cursor
        buf.fill(x as u32, y as u32, 2, 12, Color::WHITE);
        buf.fill(x as u32, y as u32, 8, 2, Color::WHITE);
        buf.fill(x as u32, (y + 1) as u32, 1, 1, Color::BLACK);
        buf.fill((x + 1) as u32, (y + 2) as u32, 1, 1, Color::BLACK);
        buf.fill((x + 2) as u32, (y + 3) as u32, 1, 1, Color::BLACK);
        buf.fill((x + 3) as u32, (y + 4) as u32, 1, 1, Color::BLACK);
        buf.fill((x + 1) as u32, (y + 1) as u32, 1, 1, Color::WHITE);
        buf.fill((x + 2) as u32, (y + 2) as u32, 1, 1, Color::WHITE);
        buf.fill((x + 3) as u32, (y + 3) as u32, 1, 1, Color::WHITE);
        buf.fill((x + 4) as u32, (y + 4) as u32, 1, 1, Color::WHITE);
    }
}

// ============================================================================
// Display Server
// ============================================================================

struct Server {
    buf: Buffer,
    wins: Vec<Win>,
    nid: u32,
    cursor: Cursor,
    btns: u8,
    drag_win: Option<WId>,
    drag_off_x: i32,
    drag_off_y: i32,
    resizing: Option<WId>,
    sw: u32,
    sh: u32,
}

impl Server {
    fn new(buf: Buffer, w: u32, h: u32) -> Self {
        Self {
            buf,
            wins: Vec::new(),
            nid: 1,
            cursor: Cursor::new(w, h),
            btns: 0,
            drag_win: None,
            drag_off_x: 0,
            drag_off_y: 0,
            resizing: None,
            sw: w,
            sh: h,
        }
    }

    fn create_win(&mut self, x: i32, y: i32, w: u32, h: u32, t: &str, bg: Color) -> WId {
        let id = WId(self.nid);
        self.nid += 1;
        self.wins.push(Win::new(id, x, y, w, h, t, bg));
        self.focus(id);
        id
    }

    fn remove_win(&mut self, id: WId) {
        self.wins.retain(|w| w.id != id);
    }

    fn focus(&mut self, id: WId) {
        for w in &mut self.wins {
            w.focused = w.id == id;
        }
    }

    fn win_at(&self, px: i32, py: i32) -> Option<WId> {
        self.wins.iter().rev().find(|w| w.hit(px, py)).map(|w| w.id)
    }

    fn mouse_move(&mut self, dx: i16, dy: i16) {
        self.cursor.x = (self.cursor.x + dx as i32).max(0).min(self.sw as i32 - 1);
        self.cursor.y = (self.cursor.y + dy as i32).max(0).min(self.sh as i32 - 1);

        // Dragging a window
        if self.btns & 1 != 0 {
            if let Some(id) = self.drag_win {
                for w in &mut self.wins {
                    if w.id == id {
                        w.x += dx as i32;
                        w.y += dy as i32;
                    }
                }
            }
            // Resizing
            if let Some(id) = self.resizing {
                for w in &mut self.wins {
                    if w.id == id {
                        w.w = (w.w as i32 + dx as i32).max(80) as u32;
                        w.h = (w.h as i32 + dy as i32).max(60) as u32;
                    }
                }
            }
        }
    }

    fn mouse_btn(&mut self, button: u8, down: bool) {
        if down {
            self.btns |= 1 << button;
            if button == 0 {
                let px = self.cursor.x;
                let py = self.cursor.y;

                // Check windows in reverse Z-order (topmost first)
                if let Some(id) = self.win_at(px, py) {
                    self.focus(id);

                    // Check close button
                    if let Some(win) = self.wins.iter().find(|w| w.id == id) {
                        if win.hit_close(px, py) {
                            self.remove_win(id);
                            return;
                        }
                        if win.hit_titlebar(px, py) {
                            self.drag_win = Some(id);
                            self.drag_off_x = px - win.x;
                            self.drag_off_y = py - win.y;
                            return;
                        }
                        if win.hit_resize(px, py) {
                            self.resizing = Some(id);
                            return;
                        }
                    }
                }
            }
        } else {
            self.btns &= !(1 << button);
            if button == 0 {
                self.drag_win = None;
                self.resizing = None;
            }
        }
    }

    fn composite(&self) {
        let buf = &self.buf;

        // Desktop background
        draw_desktop(buf, self.sw, self.sh);

        // Draw windows (Z-order: first = bottommost)
        for win in &self.wins {
            if win.visible {
                win.draw(buf);
            }
        }

        // Cursor
        self.cursor.draw(buf);
    }
}

// ============================================================================
// Font (8x8 bitmap)
// ============================================================================

fn draw_glyph(buf: &Buffer, x: i32, y: i32, ch: u8, c: Color) {
    let g: [u8; 8] = match ch {
        b'A' => [0x3C, 0x66, 0x66, 0x7E, 0x66, 0x66, 0x66, 0x00],
        b'B' => [0x7C, 0x66, 0x66, 0x7C, 0x66, 0x66, 0x7C, 0x00],
        b'C' => [0x3C, 0x66, 0x60, 0x60, 0x60, 0x66, 0x3C, 0x00],
        b'D' => [0x78, 0x6C, 0x66, 0x66, 0x66, 0x6C, 0x78, 0x00],
        b'E' => [0x7E, 0x60, 0x60, 0x78, 0x60, 0x60, 0x7E, 0x00],
        b'F' => [0x7E, 0x60, 0x60, 0x78, 0x60, 0x60, 0x60, 0x00],
        b'G' => [0x3C, 0x66, 0x60, 0x6E, 0x66, 0x66, 0x3C, 0x00],
        b'H' => [0x66, 0x66, 0x66, 0x7E, 0x66, 0x66, 0x66, 0x00],
        b'I' => [0x3C, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00],
        b'J' => [0x1E, 0x0C, 0x0C, 0x0C, 0x0C, 0x6C, 0x38, 0x00],
        b'K' => [0x66, 0x6C, 0x78, 0x70, 0x78, 0x6C, 0x66, 0x00],
        b'L' => [0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x7E, 0x00],
        b'M' => [0x63, 0x77, 0x7F, 0x6B, 0x63, 0x63, 0x63, 0x00],
        b'N' => [0x66, 0x76, 0x7E, 0x7E, 0x6E, 0x66, 0x66, 0x00],
        b'O' => [0x3C, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00],
        b'P' => [0x7C, 0x66, 0x66, 0x7C, 0x60, 0x60, 0x60, 0x00],
        b'Q' => [0x3C, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x0E, 0x00],
        b'R' => [0x7C, 0x66, 0x66, 0x7C, 0x78, 0x6C, 0x66, 0x00],
        b'S' => [0x3C, 0x66, 0x60, 0x3C, 0x06, 0x66, 0x3C, 0x00],
        b'T' => [0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00],
        b'U' => [0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00],
        b'V' => [0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x18, 0x00],
        b'W' => [0x63, 0x63, 0x63, 0x6B, 0x7F, 0x77, 0x63, 0x00],
        b'X' => [0x66, 0x66, 0x3C, 0x18, 0x3C, 0x66, 0x66, 0x00],
        b'Y' => [0x66, 0x66, 0x66, 0x3C, 0x18, 0x18, 0x18, 0x00],
        b'Z' => [0x7E, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x7E, 0x00],
        b'0' => [0x3C, 0x66, 0x6E, 0x76, 0x66, 0x66, 0x3C, 0x00],
        b'1' => [0x18, 0x38, 0x18, 0x18, 0x18, 0x18, 0x7E, 0x00],
        b'2' => [0x3C, 0x66, 0x06, 0x1C, 0x30, 0x60, 0x7E, 0x00],
        b'3' => [0x3C, 0x66, 0x06, 0x1C, 0x06, 0x66, 0x3C, 0x00],
        b'4' => [0x0C, 0x1C, 0x3C, 0x6C, 0x7E, 0x0C, 0x0C, 0x00],
        b'5' => [0x7E, 0x60, 0x7C, 0x06, 0x06, 0x66, 0x3C, 0x00],
        b'6' => [0x1C, 0x30, 0x60, 0x7C, 0x66, 0x66, 0x3C, 0x00],
        b'7' => [0x7E, 0x06, 0x0C, 0x18, 0x18, 0x18, 0x18, 0x00],
        b'8' => [0x3C, 0x66, 0x66, 0x3C, 0x66, 0x66, 0x3C, 0x00],
        b'9' => [0x3C, 0x66, 0x66, 0x3E, 0x06, 0x0C, 0x38, 0x00],
        b' ' => [0; 8],
        b'.' => [0, 0, 0, 0, 0, 0, 0x18, 0x18],
        b',' => [0, 0, 0, 0, 0, 0x18, 0x30, 0x00],
        b':' => [0, 0x18, 0x18, 0, 0x18, 0x18, 0, 0],
        b';' => [0, 0, 0x18, 0, 0, 0x18, 0x30, 0x00],
        b'-' => [0, 0, 0, 0x7E, 0, 0, 0, 0],
        b'+' => [0, 0x18, 0x18, 0x7E, 0x18, 0x18, 0, 0],
        b'=' => [0, 0, 0, 0x7E, 0, 0x7E, 0, 0],
        b'(' => [0x0C, 0x18, 0x30, 0x30, 0x30, 0x18, 0x0C, 0x00],
        b')' => [0x30, 0x18, 0x0C, 0x0C, 0x0C, 0x18, 0x30, 0x00],
        b'/' => [0x02, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x40, 0x00],
        b'\\' => [0x40, 0x60, 0x30, 0x18, 0x0C, 0x06, 0x02, 0x00],
        b'[' => [0x3C, 0x30, 0x30, 0x30, 0x30, 0x30, 0x3C, 0x00],
        b']' => [0x3C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x3C, 0x00],
        b'<' => [0x0C, 0x18, 0x30, 0x60, 0x30, 0x18, 0x0C, 0x00],
        b'>' => [0x30, 0x18, 0x0C, 0x06, 0x0C, 0x18, 0x30, 0x00],
        _ => [0x3C, 0x66, 0x66, 0x7E, 0x66, 0x66, 0x66, 0x00], // fallback
    };
    for (r, &bits) in g.iter().enumerate() {
        for col in 0..8u32 {
            if bits & (0x80 >> col) != 0 {
                buf.pixel(x + col as i32, y + r as i32, c);
            }
        }
    }
}

// ============================================================================
// Display scheme integration
// ============================================================================

/// Present the full offscreen buffer to the display via the kernel scheme.
///
/// Full-width single write is safe: the kernel Screen handler restarts each
/// row at column x, so with x=0 and w==screen width the linear pixel stream
/// maps row after row correctly.
fn present_full(dfd: u32, dmg_fd: u32, buf: &Buffer) {
    let total = buf.stride as usize * buf.h as usize;
    let _ = call::write(dfd as usize, unsafe {
        core::slice::from_raw_parts(buf.ptr, total)
    });
    send_damage(dmg_fd, 0, 0, buf.w, buf.h);
}

/// Send a partial damage command ("x,y,w,h") so the kernel blits only the
/// changed rectangle from its offscreen HeapScreen to the hardware.
fn send_damage(dmg_fd: u32, x: u32, y: u32, w: u32, h: u32) {
    if w == 0 || h == 0 {
        return;
    }
    let s = format!("{},{},{},{}", x, y, w, h);
    let _ = call::write(dmg_fd as usize, s.as_bytes());
}

/// Write the pixels of one damaged row to the screen handle.
///
/// The kernel Screen handler has no explicit width field: it consumes pixels
/// from column x up to the right edge or buffer end. Supplying exactly one
/// row of `w` pixels therefore fills columns [x, x+w) of that row only.
fn write_row_packet(dfd: u32, buf: &Buffer, x: u32, y: u32, w: u32) -> bool {
    let b = buf.bpp as usize / 8;
    let mut packet: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(4 + w as usize * b);
    packet.push((x & 0xFF) as u8);
    packet.push((x >> 8) as u8);
    packet.push((y & 0xFF) as u8);
    packet.push((y >> 8) as u8);
    let row_off = y as usize * buf.stride as usize + x as usize * b;
    let row_bytes = w as usize * b;
    packet.extend_from_slice(unsafe {
        core::slice::from_raw_parts(buf.ptr.add(row_off), row_bytes)
    });
    matches!(call::write(dfd as usize, &packet), Ok(_))
}

/// Present only the given rectangle: one write per row, then a partial
/// damage command. Returns the number of rows actually sent.
fn present_rect(dfd: u32, dmg_fd: u32, buf: &Buffer, x: u32, y: u32, w: u32, h: u32) -> usize {
    let mut sent = 0usize;
    for row in y..y.saturating_add(h) {
        if write_row_packet(dfd, buf, x, row, w) {
            sent += 1;
        }
    }
    send_damage(dmg_fd, x, y, w, h);
    sent
}

/// Compare the freshly composited frame against the previously presented one
/// and return the bounding box of differing pixels (or None if identical).
///
/// Rows are compared in u64 chunks; only changed rows are scanned byte-wise
/// for the exact horizontal extent. Cost is ~one RAM pass over unchanged
/// frames (~3 MB memcmp), far below the syscall+blit it avoids.
fn damage_bbox(
    prev: &[u8],
    cur: &[u8],
    stride: usize,
    height: usize,
    bpp_bytes: usize,
) -> Option<(u32, u32, u32, u32)> {
    if prev.len() != cur.len() || prev.len() < stride * height {
        return Some((0, 0, u32::MAX, u32::MAX)); // size mismatch: force full
    }

    let mut min_row: usize = usize::MAX;
    let mut max_row: usize = 0;
    let mut min_col: usize = usize::MAX;
    let mut max_col: usize = 0;

    for row in 0..height {
        let start = row * stride;
        let end = start + stride;
        let a = &prev[start..end];
        let c = &cur[start..end];

        // Fast reject: identical rows cost 8 bytes per step.
        let mut changed = false;
        let mut i = 0usize;
        while i + 8 <= stride {
            if a[i..i + 8] != c[i..i + 8] {
                changed = true;
                break;
            }
            i += 8;
        }
        if !changed {
            while i < stride {
                if a[i] != c[i] {
                    changed = true;
                    break;
                }
                i += 1;
            }
        }
        if !changed {
            continue;
        }

        // Locate exact extent on this row.
        let mut rmin = stride;
        let mut rmax = 0usize;
        for col in 0..stride {
            if a[col] != c[col] {
                if col < rmin {
                    rmin = col;
                }
                rmax = col;
            }
        }
        if rmin > rmax {
            continue;
        }
        if row < min_row {
            min_row = row;
        }
        if row > max_row {
            max_row = row;
        }
        let pmin = rmin / bpp_bytes;
        let pmax = rmax / bpp_bytes;
        if pmin < min_col {
            min_col = pmin;
        }
        if pmax > max_col {
            max_col = pmax;
        }
    }

    if min_row == usize::MAX {
        return None;
    }
    Some((
        min_col as u32,
        min_row as u32,
        (max_col - min_col + 1) as u32,
        (max_row - min_row + 1) as u32,
    ))
}

/// Copy one rect worth of rows from `cur` into `prev` after presentation.
fn sync_prev_rect(prev: &mut [u8], cur: &[u8], stride: usize, y: u32, h: u32) {
    let y = y as usize;
    let h = h as usize;
    let start = y * stride;
    let end = (y + h) * stride;
    prev[start..end].copy_from_slice(&cur[start..end]);
}

// ============================================================================
// Main
// ============================================================================

fn log(s: &str) {
    let _ = call::write(2, s.as_bytes());
    let _ = call::write(2, b"\n");
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("========================================");
    log("[display-server] strate-graphical v0.1.0");
    log("========================================");

    // Step 1: Read screen info
    log("[display-server] step 1: reading /dev/display/info...");
    let mut w = 800u32;
    let mut h = 600u32;
    let mut bpp = 32u8;
    match call::open("/dev/display/info", 0) {
        Ok(fd) => {
            log(&format!("[display-server]   opened info fd={}", fd));
            let mut ibuf = [0u8; 256];
            match call::read(fd, &mut ibuf) {
                Ok(n) => {
                    let info = core::str::from_utf8(&ibuf[..n]).unwrap_or("");
                    log(&format!("[display-server]   info: \"{}\"", info));
                    for p in info.split_whitespace() {
                        if let Some(v) = p.strip_prefix("width=") {
                            w = v.parse().unwrap_or(800);
                        } else if let Some(v) = p.strip_prefix("height=") {
                            h = v.parse().unwrap_or(600);
                        } else if let Some(v) = p.strip_prefix("bpp=") {
                            bpp = v.parse().unwrap_or(32);
                        }
                    }
                }
                Err(e) => log(&format!("[display-server]   read info failed: {:?}", e)),
            }
            let _ = call::close(fd);
        }
        Err(e) => log(&format!(
            "[display-server]   open info failed: {:?} (using defaults)",
            e
        )),
    }
    log(&format!("[display-server] screen: {}x{} bpp={}", w, h, bpp));

    // Step 2: Clear display
    log("[display-server] step 2: clearing display...");
    match call::open("/dev/display/clear", 2) {
        Ok(fd) => {
            let _ = call::write(fd, b"clear");
            let _ = call::close(fd);
            log("[display-server]   display cleared");
        }
        Err(e) => log(&format!("[display-server]   clear failed: {:?}", e)),
    }

    // Step 3: Open display framebuffer
    log("[display-server] step 3: opening /dev/display/0.0...");
    let dfd = match call::open("/dev/display/0.0", 2) {
        Ok(fd) => {
            log(&format!("[display-server]   display fd={}", fd));
            fd
        }
        Err(e) => {
            log(&format!(
                "[display-server] FATAL: cannot open /dev/display/0.0: {:?}",
                e
            ));
            log("[display-server]   Is the display scheme mounted?");
            log("[display-server]   Check: ls /dev/display/");
            loop {
                core::hint::spin_loop();
            }
        }
    };

    // Step 4: Open input devices
    log("[display-server] step 4: opening input devices...");
    let kfd = match call::open("/dev/input/kbd", 0) {
        Ok(fd) => {
            log(&format!("[display-server]   kbd fd={}", fd));
            fd
        }
        Err(e) => {
            log(&format!("[display-server]   kbd not available: {:?}", e));
            0
        }
    };
    let mfd = match call::open("/dev/input/mouse", 0) {
        Ok(fd) => {
            log(&format!("[display-server]   mouse fd={}", fd));
            fd
        }
        Err(e) => {
            log(&format!("[display-server]   mouse not available: {:?}", e));
            0
        }
    };

    // Step 5: Allocate offscreen buffer
    log("[display-server] step 5: allocating framebuffer...");
    let bpp_b = bpp as usize / 8;
    let fb_sz = w as usize * h as usize * bpp_b;
    let mut fb = vec![0u8; fb_sz];
    log(&format!(
        "[display-server]   allocated {} bytes ({}x{}x{})",
        fb_sz, w, h, bpp_b
    ));

    // Step 5b: open the damage handle (the screen fd only accepts pixels;
    // "present"/"x,y,w,h" commands go through /dev/display/damage).
    let dmg_fd = match call::open("/dev/display/damage", 0) {
        Ok(fd) => {
            log(&format!("[display-server]   damage fd={}", fd));
            fd
        }
        Err(e) => {
            log(&format!(
                "[display-server] FATAL: cannot open /dev/display/damage: {:?}",
                e
            ));
            loop {
                core::hint::spin_loop();
            }
        }
    };

    // Step 5c: previous-frame copy for damage computation.
    let mut prev_frame: alloc::vec::Vec<u8> = vec![0u8; fb_sz];

    let buf = Buffer {
        w,
        h,
        stride: w * bpp_b as u32,
        bpp,
        ptr: fb.as_mut_ptr(),
    };
    let mut srv = Server::new(buf, w, h);

    // Step 6: Create demo windows
    log("[display-server] step 6: creating demo windows...");
    srv.create_win(60, 60, 350, 220, "File Manager", Color::new(240, 240, 245));
    srv.create_win(140, 140, 300, 200, "Terminal", Color::new(20, 20, 30));
    srv.create_win(220, 220, 320, 240, "Strat9-OS", Color::new(235, 235, 240));
    log(&format!(
        "[display-server]   {} windows created",
        srv.wins.len()
    ));

    // Step 7: First composite and present
    log("[display-server] step 7: initial composite...");
    srv.composite();
    present_full(dfd as u32, dmg_fd as u32, &srv.buf);
    prev_frame.copy_from_slice(unsafe {
        core::slice::from_raw_parts(srv.buf.ptr, fb_sz)
    });
    log("[display-server]   initial frame presented");

    log("[display-server] === entering main loop ===");
    log(&format!(
        "[display-server] kbd={} mouse={} display={}",
        kfd, mfd, dfd
    ));

    // Input buffers
    let mut kb = [0u8; 64];
    let mut mb = [0u8; 56];
    let mut frame_count: u64 = 0;
    let mut skipped_frames: u64 = 0;
    // Event-driven redraw: only composite + present when something changed.
    // (Raw keyboard scancodes do not alter the display today; mouse events
    // and window operations do.)
    let mut need_redraw = false;

    // Main loop
    loop {
        let mut had_mouse = false;

        // Read keyboard
        if kfd != 0 {
            if let Ok(n) = call::read(kfd, &mut kb) {
                for &sc in &kb[..n] {
                    let _ = sc;
                }
            }
        }

        // Read mouse
        if mfd != 0 {
            if let Ok(n) = call::read(mfd, &mut mb) {
                let mut i = 0;
                while i + 7 <= n {
                    had_mouse = true;
                    let dx = mb[i] as i16 | ((mb[i + 1] as i16) << 8);
                    let dy = mb[i + 2] as i16 | ((mb[i + 3] as i16) << 8);
                    let new_btns = mb[i + 5];
                    let changed = new_btns ^ srv.btns;
                    srv.mouse_move(dx, dy);
                    for b in 0..3u8 {
                        if changed & (1 << b) != 0 {
                            srv.mouse_btn(b, new_btns & (1 << b) != 0);
                        }
                    }
                    i += 7;
                }
            }
        }

        if had_mouse {
            need_redraw = true;
        }

        // Nothing changed: skip compositing AND presenting entirely. The
        // diff below would find no damage anyway, but skipping composite
        // also saves the full offscreen redraw.
        if !need_redraw {
            skipped_frames += 1;
            let _ = call::sched_yield();
            continue;
        }

        // Composite into the offscreen buffer, then present only the
        // rectangle that actually differs from the last presented frame.
        srv.composite();

        let bpp_bytes = (srv.buf.bpp / 8) as usize;
        let cur = unsafe { core::slice::from_raw_parts(srv.buf.ptr, fb_sz) };
        match damage_bbox(&prev_frame, cur, srv.buf.stride as usize, srv.buf.h as usize, bpp_bytes)
        {
            None => {}
            Some((x, y, w, h)) => {
                let sent = present_rect(dfd as u32, dmg_fd as u32, &srv.buf, x, y, w, h);
                sync_prev_rect(
                    &mut prev_frame,
                    cur,
                    srv.buf.stride as usize,
                    y,
                    h,
                );
                let _ = sent;
            }
        }

        need_redraw = false;
        frame_count += 1;
        if frame_count % 500 == 0 {
            log(&format!(
                "[display-server] frames={} idle-skips={}",
                frame_count, skipped_frames
            ));
        }

        // Yield
        let _ = call::sched_yield();
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    strat9_syscall::call::handle_panic("strate-graphical", info)
}
