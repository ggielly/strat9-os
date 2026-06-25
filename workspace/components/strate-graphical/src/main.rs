//! Display Server for strat9-os (strate-graphical)
//!
//! A minimal Haiku-like Window Server that runs in a silo.

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;
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
    loop { core::hint::spin_loop(); }
}

// ============================================================================
// Color
// ============================================================================

#[derive(Clone, Copy, PartialEq, Eq)]
struct Color { r: u8, g: u8, b: u8, a: u8 }

impl Color {
    const fn new(r: u8, g: u8, b: u8) -> Self { Self { r, g, b, a: 255 } }
    const BLACK: Self = Self::new(0, 0, 0);
    const WHITE: Self = Self::new(255, 255, 255);
    const DARK_GRAY: Self = Self::new(64, 64, 64);
    const BLUE: Self = Self::new(50, 100, 200);
    const DARK_BLUE: Self = Self::new(30, 60, 120);
}

// ============================================================================
// Screen buffer
// ============================================================================

struct Screen {
    w: u32, h: u32, stride: u32, bpp: u8, ptr: *mut u8,
}

impl Screen {
    fn fill_rect(&self, x: u32, y: u32, rw: u32, rh: u32, c: Color) {
        let b = self.bpp as u32 / 8;
        let x2 = x.min(self.w); let y2 = y.min(self.h);
        let rw = rw.min(self.w.saturating_sub(x2));
        let rh = rh.min(self.h.saturating_sub(y2));
        for row in y2..y2 + rh {
            for col in x2..x2 + rw {
                let o = (row * self.stride + col * b) as usize;
                unsafe { *self.ptr.add(o) = c.b; *self.ptr.add(o+1) = c.g; *self.ptr.add(o+2) = c.r; if b==4 { *self.ptr.add(o+3) = c.a; } }
            }
        }
    }
    fn outline(&self, x: u32, y: u32, w: u32, h: u32, c: Color) {
        self.fill_rect(x, y, w, 2, c); self.fill_rect(x, y+h-2, w, 2, c);
        self.fill_rect(x, y, 2, h, c); self.fill_rect(x+w-2, y, 2, h, c);
    }
    fn pixel(&self, x: i32, y: i32, c: Color) {
        if x < 0 || y < 0 || x >= self.w as i32 || y >= self.h as i32 { return; }
        let b = self.bpp as u32 / 8;
        let o = (y as u32 * self.stride + x as u32 * b) as usize;
        unsafe { *self.ptr.add(o) = c.b; *self.ptr.add(o+1) = c.g; *self.ptr.add(o+2) = c.r; if b==4 { *self.ptr.add(o+3) = c.a; } }
    }
}

// ============================================================================
// Window
// ============================================================================

#[derive(Clone, Copy, PartialEq, Eq)]
struct WId(u32);

struct Win { id: WId, x: i32, y: i32, w: u32, h: u32, title: [u8; 32], tlen: u8, bg: Color, focused: bool }

impl Win {
    fn new(id: WId, x: i32, y: i32, w: u32, h: u32, t: &str, bg: Color) -> Self {
        let mut buf = [0u8; 32]; let l = t.len().min(31) as u8;
        buf[..l as usize].copy_from_slice(&t.as_bytes()[..l as usize]);
        Self { id, x, y, w, h, title: buf, tlen: l, bg, focused: false }
    }
    fn title(&self) -> &str { core::str::from_utf8(&self.title[..self.tlen as usize]).unwrap_or("") }
    fn hit(&self, px: i32, py: i32) -> bool { px >= self.x && px < self.x + self.w as i32 && py >= self.y && py < self.y + self.h as i32 }
}

// ============================================================================
// Server state
// ============================================================================

struct Server {
    scr: Screen, wins: Vec<Win>, nid: u32,
    cx: i32, cy: i32, btns: u8, drag: Option<WId>,
    sw: u32, sh: u32,
}

impl Server {
    fn new(scr: Screen, w: u32, h: u32) -> Self {
        Self { scr, wins: Vec::new(), nid: 1, cx: w as i32 / 2, cy: h as i32 / 2, btns: 0, drag: None, sw: w, sh: h }
    }
    fn add_win(&mut self, x: i32, y: i32, w: u32, h: u32, t: &str, bg: Color) -> WId {
        let id = WId(self.nid); self.nid += 1;
        self.wins.push(Win::new(id, x, y, w, h, t, bg)); id
    }
    fn focus(&mut self, id: WId) { for w in &mut self.wins { w.focused = w.id == id; } }
    fn win_at(&self, px: i32, py: i32) -> Option<WId> { self.wins.iter().rev().find(|w| w.hit(px, py)).map(|w| w.id) }
    fn mouse_move(&mut self, dx: i16, dy: i16) {
        self.cx = (self.cx + dx as i32).max(0).min(self.sw as i32 - 1);
        self.cy = (self.cy + dy as i32).max(0).min(self.sh as i32 - 1);
        if self.btns & 1 != 0 {
            if let Some(id) = self.drag {
                for w in &mut self.wins { if w.id == id { w.x += dx as i32; w.y += dy as i32; } }
            } else if let Some(id) = self.win_at(self.cx, self.cy) { self.drag = Some(id); }
        } else { self.drag = None; }
    }
    fn mouse_btn(&mut self, b: u8, down: bool) {
        if down { self.btns |= 1 << b; if b == 0 { if let Some(id) = self.win_at(self.cx, self.cy) { self.focus(id); } } }
        else { self.btns &= !(1 << b); if b == 0 { self.drag = None; } }
    }
    fn composite(&self) {
        let s = &self.scr;
        for y in 0..s.h { let sh = (y * 40 / s.h) as u8; s.fill_rect(0, y, s.w, 1, Color::new(sh, sh, sh+20)); }
        for win in &self.wins {
            s.fill_rect(win.x as u32, win.y as u32, win.w, win.h, win.bg);
            s.outline(win.x as u32, win.y as u32, win.w, win.h, if win.focused { Color::BLUE } else { Color::DARK_GRAY });
            s.fill_rect(win.x as u32, win.y as u32, win.w, 20, Color::new(30, 60, 120));
            let t = win.title(); let mut cx = win.x + 4;
            for &b in t.as_bytes() { if b == 0 || cx >= win.x + win.w as i32 - 4 { break; } draw_glyph(s, cx, win.y + 6, b, Color::WHITE); cx += 8; }
        }
        // Cursor crosshair
        s.fill_rect(self.cx - 4, self.cy, 9, 2, Color::WHITE);
        s.fill_rect(self.cx, self.cy - 4, 2, 9, Color::WHITE);
    }
}

// ============================================================================
// 8x8 font
// ============================================================================

fn draw_glyph(s: &Screen, x: i32, y: i32, ch: u8, c: Color) {
    let g: [u8; 8] = match ch {
        b'A'..=b'Z'|b'a'..=b'z' => [0x3C,0x66,0x66,0x7E,0x66,0x66,0x66,0x00],
        b'0'..=b'9' => [0x3C,0x66,0x6E,0x76,0x66,0x66,0x3C,0x00],
        b' ' => [0; 8],
        b'.' => [0,0,0,0,0,0,0x18,0x18],
        b':' => [0,0x18,0x18,0,0x18,0x18,0,0],
        b'-' => [0,0,0,0x7E,0,0,0,0],
        _ => [0x3C,0x66,0x66,0x7E,0x66,0x66,0x66,0x00],
    };
    for (r,&bits) in g.iter().enumerate() { for col in 0..8 { if bits & (0x80>>col) != 0 { s.pixel(x+col as i32, y+r as i32, c); } } }
}

// ============================================================================
// Main
// ============================================================================

fn log(s: &str) { let _ = call::write(2, s.as_bytes()); let _ = call::write(2, b"\n"); }

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("[display-server] starting");

    // Read screen info
    let mut w = 800u32; let mut h = 600u32; let mut bpp = 32u8;
    if let Ok(fd) = call::open("/dev/display/info", 0) {
        let mut buf = [0u8; 256];
        if let Ok(n) = call::read(fd, &mut buf) {
            let info = core::str::from_utf8(&buf[..n]).unwrap_or("");
            for p in info.split_whitespace() {
                if let Some(v) = p.strip_prefix("width=") { w = v.parse().unwrap_or(800); }
                else if let Some(v) = p.strip_prefix("height=") { h = v.parse().unwrap_or(600); }
                else if let Some(v) = p.strip_prefix("bpp=") { bpp = v.parse().unwrap_or(32); }
            }
        }
        let _ = call::close(fd);
    }
    log(&format!("[display-server] screen: {}x{} bpp={}", w, h, bpp));

    let dfd = call::open("/dev/display/0.0", 2).unwrap_or_else(|e| { log(&format!("FATAL: display: {:?}", e)); loop {} });
    let kfd = call::open("/dev/input/kbd", 0).unwrap_or(0);
    let mfd = call::open("/dev/input/mouse", 0).unwrap_or(0);

    let bpp_b = bpp as usize / 8;
    let fb_sz = w as usize * h as usize * bpp_b;
    let mut fb = vec![0u8; fb_sz];

    let scr = Screen { w, h, stride: w * bpp_b as u32, bpp, ptr: fb.as_mut_ptr() };
    let mut srv = Server::new(scr, w, h);
    srv.add_win(50, 50, 300, 200, "Window 1", Color::new(40, 40, 60));
    srv.add_win(150, 120, 250, 180, "Window 2", Color::new(50, 40, 40));
    srv.add_win(100, 200, 280, 160, "Strat9-OS", Color::new(40, 50, 40));
    log(&format!("[display-server] {} windows, loop", srv.wins.len()));

    let mut kb = [0u8; 64]; let mut mb = [0u8; 56];
    loop {
        if kfd != 0 { if let Ok(n) = call::read(kfd, &mut kb) { let _ = &kb[..n]; } }
        if mfd != 0 { if let Ok(n) = call::read(mfd, &mut mb) {
            let mut i = 0;
            while i + 7 <= n {
                let dx = mb[i] as i16 | ((mb[i+1] as i16) << 8);
                let dy = mb[i+2] as i16 | ((mb[i+3] as i16) << 8);
                let btns = mb[i+5]; let ch = btns ^ srv.btns;
                srv.mouse_move(dx, dy);
                for b in 0..3u8 { if ch & (1<<b) != 0 { srv.mouse_btn(b, btns & (1<<b) != 0); } }
                i += 7;
            }
        }}
        srv.composite();
        let _ = call::write(dfd, &fb);
        let _ = call::sched_yield();
    }
}

#[panic_handler] fn panic(_: &PanicInfo) -> ! { loop { core::hint::spin_loop(); } }
