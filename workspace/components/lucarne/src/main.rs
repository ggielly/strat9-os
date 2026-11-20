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

//! Lucarne: the Lucarne desktop's first application, a GUI terminal running
//! on a Vasistas surface (Jalon 5).
//!
//! The loop is strate-console's (TerminalCore state, 8x16 glyph grid, cursor
//! blink) with the transport swapped for Vasistas: one 80x25 surface of
//! 640x400 XRGB8888 pixels, one FULL_DAMAGE commit per text change and one
//! cursor-cell damage rect per blink flip. Like the vasistas demo, drawing
//! ping-pongs two buffers: the server holds the current buffer, so only the
//! buffer it released may be the next commit.

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use core::{alloc::Layout, cell::UnsafeCell, mem::MaybeUninit, panic::PanicInfo};

use input_protocol::{
    INPUT_EVENT_FOCUS_GAINED, INPUT_EVENT_FOCUS_LOST, INPUT_EVENT_TEXT, INPUT_TEXT_LEN,
};
use strat9_syscall::{call, data::TimeSpec};
use terminal_core::TerminalCore;
use vasistas_client::{Buffer, Client, Event};
use vasistas_protocol::Rect;

mod renderer;

use renderer::{CELL_H, CELL_W};

/// Terminal grid size in cells.
const COLS: usize = 80;
const ROWS: usize = 25;
/// Surface size in pixels: `COLS * CELL_W` x `ROWS * CELL_H`.
const WIDTH: u32 = (COLS * CELL_W) as u32;
const HEIGHT: u32 = (ROWS * CELL_H) as u32;
/// Tight XRGB8888 stride.
const STRIDE: u32 = WIDTH * 4;

const DEFAULT_FG: u32 = 0xE2E8F0;
const DEFAULT_BG: u32 = 0x12161E;

/// One full blink period (cursor on + off) spans two recv timeouts.
const CURSOR_BLINK_MS: u64 = 500;
/// recv wait per loop iteration: half a blink period.
const BLINK_TICK_NS: u64 = CURSOR_BLINK_MS / 2 * 1_000_000;
/// Connect timeout per attempt.
const CONNECT_TIMEOUT_NS: u64 = 100_000_000;
/// Delay between connect attempts.
const CONNECT_RETRY_MS: u64 = 50;

/// TEXT bytes buffered across one batch's records (16 records x 16 bytes).
const PENDING_MAX: usize = 16 * INPUT_TEXT_LEN;

alloc_freelist::define_freelist_brk_allocator!(
    pub struct BumpAllocator;
    brk = strat9_syscall::call::brk;
    heap_max = 16 * 1024 * 1024;
);

#[global_allocator]
static GLOBAL_ALLOCATOR: BumpAllocator = BumpAllocator;

#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    let _ = call::debug_log(b"[lucarne] OOM\n");
    loop {
        let _ = call::sched_yield();
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    call::handle_panic("lucarne", info);
}

/// `TerminalCore` embeds the visible grid and a 1000-line scrollback ring
/// (~3.3 MiB). The kernel user stack is 64 KiB, so it must live in `.bss`:
/// a stack local makes `_start`'s prologue probe megabytes below the stack
/// and fault before the first pixel is drawn.
struct StaticCell<T>(UnsafeCell<T>);

// SAFETY: `lucarne` is single-threaded; this cell is only touched by `_start`.
unsafe impl<T> Sync for StaticCell<T> {}

impl<T> StaticCell<T> {
    const fn new(value: T) -> Self {
        Self(UnsafeCell::new(value))
    }

    fn as_ptr(&self) -> *mut T {
        self.0.get()
    }
}

static TERM: StaticCell<MaybeUninit<TerminalCore>> = StaticCell::new(MaybeUninit::uninit());

/// The two ping-pong buffers plus the commit bookkeeping the server tracks.
struct Stage {
    /// Buffer currently committed (the server's image).
    front: Buffer,
    /// Draw target: the buffer the server released.
    back: Buffer,
    /// Last known serial, acknowledged by every commit.
    serial: u64,
    /// Monotonic commit id.
    commit_id: u64,
    /// True once a commit failed: the presented image may lag the grid.
    stale: bool,
}

impl Stage {
    /// Commit `back` (`full` damage or `damage` rects), then swap when the
    /// server releases the old image. Returns false on rejection.
    fn present(&mut self, client: &mut Client, surface: u64, damage: &[Rect], full: bool) -> bool {
        self.commit_id += 1;
        let buffer = self.back.id;
        match client.commit(surface, buffer, damage, full, self.serial, self.commit_id) {
            Some(result) => {
                if let Some(frame) = result.frame {
                    self.serial = frame.serial;
                }
                if result.released.is_some() {
                    core::mem::swap(&mut self.front, &mut self.back);
                }
                self.stale = false;
                true
            }
            None => {
                self.stale = true;
                false
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log(b"[lucarne] waiting for /srv/vasistas\n");
    let mut client = loop {
        match Client::connect(b"/srv/vasistas", CONNECT_TIMEOUT_NS) {
            Some(client) => break client,
            None => sleep_ms(CONNECT_RETRY_MS),
        }
    };
    log(b"[lucarne] connected\n");

    let surface = match create_surface(&mut client) {
        Some(surface) => surface,
        None => fatal(b"[lucarne] create_surface failed\n"),
    };
    let mut front = match alloc_buffer(&mut client, surface) {
        Some(buffer) => buffer,
        None => fatal(b"[lucarne] alloc_buffer failed\n"),
    };
    let back = match alloc_buffer(&mut client, surface) {
        Some(buffer) => buffer,
        None => fatal(b"[lucarne] second alloc_buffer failed\n"),
    };

    // SAFETY: single-threaded process; `TERM` is initialised exactly once,
    // here, before `term` is used, and never aliased elsewhere.
    let term: &mut TerminalCore = unsafe {
        let slot = TERM.as_ptr() as *mut TerminalCore;
        TerminalCore::init_in_place(slot, COLS, ROWS, DEFAULT_FG, DEFAULT_BG);
        &mut *slot
    };
    let banner = b"\n\
        \x1b[1;36m========================================\x1b[0m\n\
        \x1b[1;36m  lucarne terminal\x1b[0m\n\
        \x1b[1;36m========================================\x1b[0m\n\
        \x1b[90mType 'help' for commands.\x1b[0m\n\n";
    term.process_bytes(banner);
    renderer::render_screen(&mut front, term, true);

    // First frame: full damage, nothing acknowledged yet (serial 0).
    let mut serial = 0u64;
    match client.commit(surface, front.id, &[], true, 0, 1) {
        Some(result) => {
            if let Some(frame) = result.frame {
                serial = frame.serial;
            }
        }
        None => fatal(b"[lucarne] first commit failed\n"),
    }
    log(b"[lucarne] first frame presented\n");

    let mut stage = Stage {
        front,
        back,
        serial,
        commit_id: 1,
        stale: false,
    };
    let mut focused = false;
    let mut focus_logged: Option<bool> = None;
    let mut cursor_visible = true;
    let mut pending = [0u8; PENDING_MAX];
    let mut pending_len = 0usize;

    loop {
        match client.recv(BLINK_TICK_NS) {
            Some(event) => match event {
                Event::InputBatch { batch, .. } => {
                    let mut focus_line: Option<&'static [u8]> = None;
                    for record in batch.records() {
                        match record.event_type {
                            INPUT_EVENT_TEXT => {
                                let len = (record.value.max(0) as usize).min(INPUT_TEXT_LEN);
                                for &byte in &record.text[..len] {
                                    if pending_len < PENDING_MAX {
                                        pending[pending_len] = byte;
                                        pending_len += 1;
                                    }
                                }
                            }
                            INPUT_EVENT_FOCUS_GAINED | INPUT_EVENT_FOCUS_LOST => {
                                let gained = record.event_type == INPUT_EVENT_FOCUS_GAINED;
                                if focus_logged != Some(gained) {
                                    focus_logged = Some(gained);
                                    focus_line = Some(if gained {
                                        b"[lucarne] focus gained\n"
                                    } else {
                                        b"[lucarne] focus lost\n"
                                    });
                                }
                                focused = gained;
                            }
                            _ => {}
                        }
                    }
                    if let Some(line) = focus_line {
                        log(line);
                    }
                    if pending_len > 0 {
                        let dirty = term.process_bytes(&pending[..pending_len]);
                        pending_len = 0;
                        if dirty {
                            renderer::render_screen(&mut stage.back, term, cursor_visible);
                            stage.present(&mut client, surface, &[], true);
                        }
                    }
                }
                Event::Configure { serial: configure_serial, .. } => {
                    // v1 keeps a fixed 80x25 grid: the geometry is ignored,
                    // but the next commit must still ack the configure serial.
                    log(b"[lucarne] configure ignored\n");
                    stage.serial = configure_serial;
                    stage.stale = true;
                }
                Event::CloseRequest { .. } => {
                    log(b"[lucarne] close requested\n");
                    client.close();
                    call::exit(0);
                }
                Event::Error { .. } => {
                    log(b"[lucarne] server error event\n");
                }
                _ => {}
            },
            None => {
                // recv timeout: one blink tick. The cursor blinks only while
                // focused and flips on each tick, so it is drawn every other
                // tick (one blink period = two ticks).
                if !focused {
                    continue;
                }
                cursor_visible = !cursor_visible;
                if stage.stale {
                    // A commit failed earlier: resynchronize with a whole-grid
                    // repaint instead of trusting the cursor-cell rect.
                    renderer::render_screen(&mut stage.back, term, cursor_visible);
                    stage.present(&mut client, surface, &[], true);
                } else {
                    let row = term.cursor_row;
                    let col = term.cursor_col;
                    renderer::render_cell(&mut stage.back, term, row, col, cursor_visible);
                    let damage = [Rect {
                        x: (col * CELL_W) as i32,
                        y: (row * CELL_H) as i32,
                        w: CELL_W as u32,
                        h: CELL_H as u32,
                    }];
                    stage.present(&mut client, surface, &damage, false);
                }
            }
        }
    }
}

fn create_surface(client: &mut Client) -> Option<u64> {
    for _ in 0..100 {
        if let Some(surface) = client.create_surface(WIDTH, HEIGHT, b"lucarne terminal") {
            return Some(surface);
        }
        sleep_ms(10);
    }
    None
}

fn alloc_buffer(client: &mut Client, surface: u64) -> Option<Buffer> {
    for _ in 0..100 {
        if let Some(buffer) = client.alloc_buffer(surface, WIDTH, HEIGHT, STRIDE) {
            return Some(buffer);
        }
        sleep_ms(10);
    }
    None
}

fn sleep_ms(ms: u64) {
    let req = TimeSpec {
        tv_sec: (ms / 1000) as i64,
        tv_nsec: ((ms % 1000) * 1_000_000) as i64,
    };
    let mut rem = TimeSpec::zero();
    let _ = call::nanosleep(&req, &mut rem);
}

fn fatal(message: &[u8]) -> ! {
    log(message);
    call::exit(1)
}

fn log(text: &[u8]) {
    let _ = call::write(2, text);
}
