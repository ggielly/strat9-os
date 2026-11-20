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

//! Display Server for strat9-os (strate-graphical)
//!
//! A Haiku-like Window Server that runs in a silo.
//! Manages windows with decorations, composites to framebuffer via
//! the /dev/vasistas/ kernel scheme, and routes input.

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use alloc::{format, vec, vec::Vec};
use core::{alloc::Layout, panic::PanicInfo};
use fbsurface::{Rect as FbRect, RectSet as FbRectSet};
use input_client::{Client, Poll};
use input_protocol::{
    INPUT_EVENT_POINTER_AXIS, INPUT_EVENT_POINTER_BUTTON, INPUT_EVENT_POINTER_MOTION,
};
use strat9_syscall::{
    call,
    data::{TimeSpec, WaitSource, WAIT_EVENT_READABLE, WAIT_SOURCE_HANDLE},
    number, syscall6,
};

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
    let _ = call::debug_log(b"[graphical-server] OOM\n");
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
// Offscreen buffer : composites here, then flushes to /dev/vasistas/0.0
// ============================================================================

struct Buffer {
    w: u32,
    h: u32,
    stride: u32,
    bpp: u8,
    /// Native pixel layout of the surface.
    red_shift: u8,
    green_shift: u8,
    blue_shift: u8,
    /// True when `ptr` is a `MAP_SHARED` view of the display surface: no
    /// pixel writes through the scheme are needed, only damage messages.
    mapped: bool,
    ptr: *mut u8,
}

impl Buffer {
    fn fill(&self, x: u32, y: u32, rw: u32, rh: u32, c: Color) {
        let b = self.bpp as u32 / 8;
        let x2 = x.min(self.w);
        let y2 = y.min(self.h);
        let rw = rw.min(self.w.saturating_sub(x2));
        let rh = rh.min(self.h.saturating_sub(y2));
        if rw == 0 || rh == 0 {
            return;
        }
        let packed = self.pack(c);
        if b == 4 {
            // Whole-pixel 32-bit stores: one branch per row instead of one
            // per pixel, which lets LLVM vectorise the inner loop.
            for row in y2..y2 + rh {
                let offset = (row * self.stride + x2 * 4) as usize;
                let line = unsafe { self.ptr.add(offset) as *mut u32 };
                for col in 0..rw as usize {
                    // SAFETY: the row is inside the validated buffer and the
                    // store is unaligned by construction.
                    unsafe {
                        core::ptr::write_unaligned(line.add(col), packed);
                    }
                }
            }
            return;
        }
        // 24 bpp: write the three-byte pattern per pixel.
        let pattern = [packed as u8, (packed >> 8) as u8, (packed >> 16) as u8];
        for row in y2..y2 + rh {
            let offset = (row * self.stride + x2 * b) as usize;
            let line = unsafe { self.ptr.add(offset) };
            for col in 0..rw as usize {
                // SAFETY: the pixel is inside the validated buffer.
                unsafe {
                    core::ptr::copy_nonoverlapping(pattern.as_ptr(), line.add(col * 3), 3);
                }
            }
        }
    }

    fn pack(&self, c: Color) -> u32 {
        let mut packed = ((c.r as u32) << self.red_shift)
            | ((c.g as u32) << self.green_shift)
            | ((c.b as u32) << self.blue_shift);
        if self.bpp == 32 {
            packed |= 0xFF00_0000;
        }
        packed
    }

    fn store(&self, off: usize, c: Color) {
        let packed = self.pack(c);
        unsafe {
            if self.bpp == 32 {
                core::ptr::write_unaligned(self.ptr.add(off) as *mut u32, packed);
            } else {
                *self.ptr.add(off) = packed as u8;
                *self.ptr.add(off + 1) = (packed >> 8) as u8;
                *self.ptr.add(off + 2) = (packed >> 16) as u8;
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
        self.store(o, c);
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
fn present_full(dfd: u32, dmg_fd: u32, buf: &Buffer, scratch: &mut Vec<u8>) {
    if !buf.mapped {
        write_rect_packet(dfd, buf, scratch, 0, 0, buf.w, buf.h);
    }
    send_damage(dmg_fd, 0, 0, buf.w, buf.h);
}

/// Send a partial damage command ("x,y,w,h") so the kernel blits only the
/// changed rectangle from its offscreen HeapScreen to the hardware.
fn send_damage(dmg_fd: u32, x: u32, y: u32, w: u32, h: u32) {
    if w == 0 || h == 0 {
        return;
    }
    // Binary DMG2 protocol: magic, rect count, display id, then one rect.
    let mut msg = [0u8; 16];
    msg[0..4].copy_from_slice(b"DMG2");
    msg[4..6].copy_from_slice(&1u16.to_le_bytes());
    msg[6..8].copy_from_slice(&0u16.to_le_bytes());
    msg[8..10].copy_from_slice(&(x as u16).to_le_bytes());
    msg[10..12].copy_from_slice(&(y as u16).to_le_bytes());
    msg[12..14].copy_from_slice(&(w as u16).to_le_bytes());
    msg[14..16].copy_from_slice(&(h as u16).to_le_bytes());
    let _ = call::write(dmg_fd as usize, &msg);
}

/// Write one rectangle of pixels in a SINGLE scheme write using wire
/// format v2: [x u16le][y u16le][w u16le][RGB888 w*h pixels]. The kernel
/// consumes exactly w pixels per row, so arbitrary sub-rectangles work
/// without per-row syscalls.
///
/// `scratch` must be pre-sized to at least 6 + w*h*bpp bytes; it is reused
/// across frames to avoid per-present allocations.
fn write_rect_packet(
    dfd: u32,
    buf: &Buffer,
    scratch: &mut Vec<u8>,
    x: u32,
    y: u32,
    w: u32,
    h: u32,
) -> bool {
    if w == 0 || h == 0 {
        return false;
    }
    let b = buf.bpp as usize / 8;

    // Gather rows into the scratch packet, converting native pixels back to
    // the scheme's BGR888 wire format (rows are contiguous only when the
    // rect spans the full width).
    let needed = 6 + w as usize * h as usize * 3;
    scratch.clear();
    scratch.reserve(needed.saturating_sub(scratch.capacity()));

    scratch.push((x & 0xFF) as u8);
    scratch.push((x >> 8) as u8);
    scratch.push((y & 0xFF) as u8);
    scratch.push((y >> 8) as u8);
    scratch.push((w & 0xFF) as u8);
    scratch.push((w >> 8) as u8);

    for row in y..y.saturating_add(h) {
        let row_off = row as usize * buf.stride as usize + x as usize * b;
        for col in 0..w as usize {
            let off = row_off + col * b;
            let packed = unsafe {
                if b == 4 {
                    core::ptr::read_unaligned(buf.ptr.add(off) as *const u32)
                } else {
                    let p = buf.ptr.add(off);
                    (*p as u32) | ((*p.add(1) as u32) << 8) | ((*p.add(2) as u32) << 16)
                }
            };
            let r = (packed >> buf.red_shift) & 0xFF;
            let g = (packed >> buf.green_shift) & 0xFF;
            let blue = (packed >> buf.blue_shift) & 0xFF;
            scratch.push(blue as u8);
            scratch.push(g as u8);
            scratch.push(r as u8);
        }
    }

    matches!(call::write(dfd as usize, scratch), Ok(_))
}

/// Maximum damage rectangles coalesced per presented frame. The kernel accepts
/// up to 1024; 32 is plenty for a drag (two bands) plus the cursor.
const MAX_DAMAGE_RECTS: usize = 32;

/// Compare the freshly composited frame against the previously presented one
/// and return every changed span, coalesced.
///
/// Rows are compared in u64 chunks; changed rows are scanned byte-wise for the
/// exact horizontal extent and inserted as one-pixel-high rectangles. The
/// [`RectSet`] merges vertically adjacent spans with the same extent, so a
/// diagonal drag yields a handful of rectangles instead of one screen-sized
/// bounding box. When the set fills, it merges the least-growing entry: the
/// result can cover clean pixels (overdraw) but never omit a dirty one.
fn damage_rects(
    prev: &[u8],
    cur: &[u8],
    stride: usize,
    width: u32,
    height: usize,
    bpp_bytes: usize,
) -> FbRectSet<MAX_DAMAGE_RECTS> {
    let mut damage = FbRectSet::<MAX_DAMAGE_RECTS>::empty();
    if bpp_bytes == 0 || stride % bpp_bytes != 0 || width == 0 {
        return damage;
    }
    if prev.len() != cur.len() || prev.len() < stride * height {
        damage.include(FbRect::new(0, 0, width, height as u32));
        return damage;
    }

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

        // Locate the exact extent on this row, in whole pixels.
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
        let pmin = (rmin / bpp_bytes) as u32;
        let pmax = ((rmax / bpp_bytes) as u32).min(width - 1);
        if pmin > pmax {
            continue;
        }
        damage.include(FbRect::new(pmin, row as u32, pmax - pmin + 1, 1));
    }
    damage
}

/// Send every rectangle of `damage` in a single `DMG2` message.
fn send_damage_multi(dmg_fd: u32, damage: &FbRectSet<MAX_DAMAGE_RECTS>) {
    if damage.is_empty() {
        return;
    }
    let count = damage.len().min(MAX_DAMAGE_RECTS);
    let mut msg = [0u8; 8 + MAX_DAMAGE_RECTS * 8];
    msg[0..4].copy_from_slice(b"DMG2");
    msg[4..6].copy_from_slice(&(count as u16).to_le_bytes());
    msg[6..8].copy_from_slice(&0u16.to_le_bytes());
    for (index, rect) in damage.iter().take(count).enumerate() {
        let off = 8 + index * 8;
        msg[off..off + 2].copy_from_slice(&(rect.x as u16).to_le_bytes());
        msg[off + 2..off + 4].copy_from_slice(&(rect.y as u16).to_le_bytes());
        msg[off + 4..off + 6].copy_from_slice(&(rect.w as u16).to_le_bytes());
        msg[off + 6..off + 8].copy_from_slice(&(rect.h as u16).to_le_bytes());
    }
    let len = 8 + count * 8;
    let _ = call::write(dmg_fd as usize, &msg[..len]);
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
    log("[graphical-server] strate-graphical v0.1.0");
    log("========================================");

    // Step 1: Read screen info
    log("[graphical-server] step 1: reading /dev/vasistas/info...");
    let mut w = 800u32;
    let mut h = 600u32;
    let mut bpp = 32u8;
    let mut stride = 0usize;
    let mut red_shift = 16u8;
    let mut green_shift = 8u8;
    let mut blue_shift = 0u8;
    match call::open("/dev/vasistas/info", 0) {
        Ok(fd) => {
            log(&format!("[graphical-server]   opened info fd={}", fd));
            let mut ibuf = [0u8; 256];
            match call::read(fd, &mut ibuf) {
                Ok(n) => {
                    let info = core::str::from_utf8(&ibuf[..n]).unwrap_or("");
                    log(&format!("[graphical-server]   info: \"{}\"", info));
                    for p in info.split_whitespace() {
                        if let Some(v) = p.strip_prefix("width=") {
                            w = v.parse().unwrap_or(800);
                        } else if let Some(v) = p.strip_prefix("height=") {
                            h = v.parse().unwrap_or(600);
                        } else if let Some(v) = p.strip_prefix("bpp=") {
                            bpp = v.parse().unwrap_or(32);
                        } else if let Some(v) = p.strip_prefix("stride=") {
                            stride = v.parse().unwrap_or(0);
                        } else if let Some(v) = p.strip_prefix("red_shift=") {
                            red_shift = v.parse().unwrap_or(16);
                        } else if let Some(v) = p.strip_prefix("green_shift=") {
                            green_shift = v.parse().unwrap_or(8);
                        } else if let Some(v) = p.strip_prefix("blue_shift=") {
                            blue_shift = v.parse().unwrap_or(0);
                        }
                    }
                }
                Err(e) => log(&format!("[graphical-server]   read info failed: {:?}", e)),
            }
            let _ = call::close(fd);
        }
        Err(e) => log(&format!(
            "[graphical-server]   open info failed: {:?} (using defaults)",
            e
        )),
    }
    log(&format!(
        "[graphical-server] screen: {}x{} bpp={}",
        w, h, bpp
    ));

    // Step 2: Open display framebuffer. This takes framebuffer ownership, so
    // it must happen before clear/damage writes are permitted.
    log("[graphical-server] step 2: opening /dev/vasistas/0.0...");
    let dfd = match call::open("/dev/vasistas/0.0", 2) {
        Ok(fd) => {
            log(&format!("[graphical-server]   display fd={}", fd));
            fd
        }
        Err(e) => {
            log(&format!(
                "[graphical-server] FATAL: cannot open /dev/vasistas/0.0: {:?}",
                e
            ));
            log("[graphical-server]   Is the display scheme mounted?");
            log("[graphical-server]   Check: ls /dev/vasistas/");
            loop {
                core::hint::spin_loop();
            }
        }
    };

    // Step 3: Clear display (now that this process owns the framebuffer)
    log("[graphical-server] step 3: clearing display...");
    match call::open("/dev/vasistas/clear", 2) {
        Ok(fd) => {
            let _ = call::write(fd, b"clear");
            let _ = call::close(fd);
            log("[graphical-server]   display cleared");
        }
        Err(e) => log(&format!("[graphical-server]   clear failed: {:?}", e)),
    }

    // Step 4: Subscribe to inputd. Retry because the input server may start
    // after the display server; only the client path is used, never
    // /dev/input/*.
    log("[graphical-server] step 4: subscribing to inputd...");
    let mut input = {
        let mut logged = false;
        loop {
            if let Some(client) = Client::open(1) {
                break client;
            }
            if !logged {
                log("[graphical-server]   waiting for inputd (/srv/input)...");
                logged = true;
            }
            let req = TimeSpec {
                tv_sec: 0,
                tv_nsec: 20_000_000,
            };
            let mut rem = TimeSpec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let _ = call::nanosleep(&req, &mut rem);
        }
    };
    input.request_focus();
    log("[graphical-server]   inputd subscription ready");

    // Step 5: map the display surface (zero-copy) or fall back to an
    // offscreen buffer written through the scheme.
    log("[graphical-server] step 5: mapping framebuffer...");
    let bpp_b = bpp as usize / 8;
    if stride == 0 {
        stride = w as usize * bpp_b;
    }
    let fb_sz = stride * h as usize;
    const PROT_READ_WRITE: usize = 3;
    const MAP_SHARED: usize = 1;
    let mapped = unsafe {
        syscall6(
            number::SYS_MMAP,
            0,
            fb_sz,
            PROT_READ_WRITE,
            MAP_SHARED,
            dfd,
            0,
        )
    }
    .ok()
    .filter(|addr| *addr != 0);
    let mut fb_fallback: Vec<u8> = Vec::new();
    let (fb_ptr, is_mapped) = match mapped {
        Some(addr) => {
            log(&format!(
                "[graphical-server]   mapped {} bytes at {:#x}",
                fb_sz, addr
            ));
            (addr as *mut u8, true)
        }
        None => {
            fb_fallback = vec![0u8; fb_sz];
            log(&format!(
                "[graphical-server]   mmap unavailable, fallback {} bytes ({}x{}x{})",
                fb_sz, w, h, bpp_b
            ));
            (fb_fallback.as_mut_ptr(), false)
        }
    };

    // Step 5b: open the damage handle (the screen fd only accepts pixels;
    // "present"/"x,y,w,h" commands go through /dev/vasistas/damage).
    let dmg_fd = match call::open("/dev/vasistas/damage", 2) {
        Ok(fd) => {
            log(&format!("[graphical-server]   damage fd={}", fd));
            fd
        }
        Err(e) => {
            log(&format!(
                "[graphical-server] FATAL: cannot open /dev/vasistas/damage: {:?}",
                e
            ));
            loop {
                core::hint::spin_loop();
            }
        }
    };

    // Step 5c: previous-frame copy for damage computation + reusable packet
    // scratch (sized for a full-screen rect, worst case).
    let mut prev_frame: alloc::vec::Vec<u8> = vec![0u8; fb_sz];
    let mut packet_scratch: alloc::vec::Vec<u8> = Vec::with_capacity(fb_sz);

    let buf = Buffer {
        w,
        h,
        stride: stride as u32,
        bpp,
        red_shift,
        green_shift,
        blue_shift,
        mapped: is_mapped,
        ptr: fb_ptr,
    };
    let mut srv = Server::new(buf, w, h);

    // Step 6: Create demo windows
    log("[graphical-server] step 6: creating demo windows...");
    srv.create_win(60, 60, 350, 220, "File Manager", Color::new(240, 240, 245));
    srv.create_win(140, 140, 300, 200, "Terminal", Color::new(20, 20, 30));
    srv.create_win(220, 220, 320, 240, "Strat9-OS", Color::new(235, 235, 240));
    log(&format!(
        "[graphical-server]   {} windows created",
        srv.wins.len()
    ));

    // Step 7: First composite and present
    log("[graphical-server] step 7: initial composite...");
    srv.composite();
    present_full(dfd as u32, dmg_fd as u32, &srv.buf, &mut packet_scratch);
    prev_frame.copy_from_slice(unsafe { core::slice::from_raw_parts(srv.buf.ptr, fb_sz) });
    log("[graphical-server]   initial frame presented");

    log("[graphical-server] === entering main loop ===");
    log(&format!("[graphical-server] inputd=ready display={}", dfd));

    let mut frame_count: u64 = 0;
    let mut skipped_frames: u64 = 0;
    // Event-driven redraw: only composite + present when something changed.
    // (KEY/TEXT records do not alter the display today; pointer events and
    // window operations do.)
    let mut need_redraw = false;

    // Main loop
    loop {
        let mut had_input = false;

        // Drain inputd batches. Only pointer records drive the compositor.
        loop {
            match input.poll() {
                Poll::Batch(batch) => {
                    for record in batch.records() {
                        let event = record.event;
                        match event.event_type {
                            INPUT_EVENT_POINTER_MOTION => {
                                had_input = true;
                                // value = dx, code = dy (as i16).
                                srv.mouse_move(event.value as i16, event.code as i16);
                            }
                            INPUT_EVENT_POINTER_BUTTON => {
                                had_input = true;
                                srv.mouse_btn(event.code as u8, event.value != 0);
                            }
                            // The server has no scroll path yet: vertical
                            // wheel deltas are acknowledged and ignored.
                            INPUT_EVENT_POINTER_AXIS => {}
                            // KEY/TEXT/ENTER/LEAVE/FOCUS: ignored here.
                            _ => {}
                        }
                    }
                }
                Poll::Reset { .. } => break,
                Poll::Empty | Poll::Error => break,
            }
        }

        if had_input {
            need_redraw = true;
        }

        // Nothing changed: skip compositing AND presenting entirely. The
        // diff below would find no damage anyway, but skipping composite
        // also saves the full offscreen redraw. Block on the input port
        // instead of spinning: a batch/reset wakes the loop, and the
        // timeout is only a housekeeping deadline.
        if !need_redraw {
            skipped_frames += 1;
            // Block on the input port instead of spinning. The wait does not
            // consume the message: the next iteration's `poll` drains it.
            let mut source = [WaitSource {
                kind: WAIT_SOURCE_HANDLE,
                events: WAIT_EVENT_READABLE,
                id: input.port_handle() as u64,
                revents: 0,
            }];
            let _ = call::handle_wait_many(&mut source, 16_000_000);
            continue;
        }

        // Composite into the offscreen buffer, then present every rectangle
        // that actually differs from the last presented frame.
        srv.composite();

        let bpp_bytes = (srv.buf.bpp / 8) as usize;
        let cur = unsafe { core::slice::from_raw_parts(srv.buf.ptr, fb_sz) };
        let damage = damage_rects(
            &prev_frame,
            cur,
            srv.buf.stride as usize,
            srv.buf.w,
            srv.buf.h as usize,
            bpp_bytes,
        );
        if !damage.is_empty() {
            // With a mapped surface the pixels are already in the display
            // frame; only the damage notification is needed. Otherwise upload
            // each changed rectangle through the scheme first.
            let mut uploaded = true;
            if !srv.buf.mapped {
                for rect in damage.iter() {
                    if !write_rect_packet(
                        dfd as u32,
                        &srv.buf,
                        &mut packet_scratch,
                        rect.x,
                        rect.y,
                        rect.w,
                        rect.h,
                    ) {
                        uploaded = false;
                        break;
                    }
                }
            }
            if uploaded {
                // One DMG2 for the whole frame instead of one per rect.
                send_damage_multi(dmg_fd as u32, &damage);
                for rect in damage.iter() {
                    sync_prev_rect(
                        &mut prev_frame,
                        cur,
                        srv.buf.stride as usize,
                        rect.y,
                        rect.h,
                    );
                }
            }
        }

        need_redraw = false;
        frame_count += 1;
        if frame_count % 500 == 0 {
            log(&format!(
                "[graphical-server] frames={} idle-skips={}",
                frame_count, skipped_frames
            ));
        }
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    strat9_syscall::call::handle_panic("strate-graphical", info)
}
