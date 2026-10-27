#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use core::{alloc::Layout, panic::PanicInfo};
use strat9_syscall::{call, data::TimeSpec};

mod ansi;
mod input;
mod renderer;
mod scrollback;
mod terminal;

use input::InputHandler;
use renderer::Renderer;
use terminal::TerminalCore;

const DEFAULT_FG: u32 = 0xE2E8F0;
const DEFAULT_BG: u32 = 0x12161E;

/// Cursor blink period. Blinking is the only periodic redraw source.
const CURSOR_BLINK_MS: u64 = 500;
/// Idle sleep when no input is pending (5 ms).
const IDLE_SLEEP_NS: i64 = 5_000_000;

alloc_freelist::define_freelist_brk_allocator!(
    pub struct BumpAllocator;
    brk = strat9_syscall::call::brk;
    heap_max = 16 * 1024 * 1024;
);

#[global_allocator]
static GLOBAL_ALLOCATOR: BumpAllocator = BumpAllocator;

#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    let _ = call::debug_log(b"[console] OOM\n");
    loop {
        let _ = call::sched_yield();
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    call::handle_panic("strate-console", info);
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let _ = call::debug_log(b"[console] strate-console starting\n");

    let mut rend = match Renderer::open() {
        Some(r) => r,
        None => {
            let _ = call::debug_log(b"[console] FATAL: cannot open /dev/display/0.0\n");
            loop {
                let _ = call::sched_yield();
            }
        }
    };

    let mut kbd = match InputHandler::open() {
        Some(k) => k,
        None => {
            let _ = call::debug_log(b"[console] FATAL: cannot open /dev/input/kbd\n");
            loop {
                let _ = call::sched_yield();
            }
        }
    };

    let mut term = TerminalCore::new(rend.cols, rend.rows, DEFAULT_FG, DEFAULT_BG);

    let banner = b"\n\
        \x1b[1;36m========================================\x1b[0m\n\
        \x1b[1;36m  strat9-os console (ring 3)\x1b[0m\n\
        \x1b[1;36m========================================\x1b[0m\n\
        \x1b[90mType 'help' for commands.\x1b[0m\n\n";
    term.process_bytes(banner);

    rend.render(
        &term.screen,
        term.cursor_row,
        term.cursor_col,
        term.rows,
        true,
    );

    let mut cursor_visible = true;
    let mut next_blink_ms = now_ms() + CURSOR_BLINK_MS;
    let mut raw = [0u8; 64];
    let mut input = [0u8; 64];

    loop {
        let mut dirty = false;

        // One syscall per scancode burst, then translate the whole batch.
        // `read_raw` is non-blocking, so an empty read means idle.
        let raw_n = kbd.read_raw(&mut raw);
        let text_n = kbd.translate(&raw[..raw_n], &mut input);
        if text_n > 0 && term.process_bytes(&input[..text_n]) {
            dirty = true;
        }

        // Cursor blink is the only periodic redraw source.
        let now = now_ms();
        if now >= next_blink_ms {
            cursor_visible = !cursor_visible;
            while next_blink_ms <= now {
                next_blink_ms += CURSOR_BLINK_MS;
            }
            dirty = true;
        }

        if dirty {
            rend.render(
                &term.screen,
                term.cursor_row,
                term.cursor_col,
                term.rows,
                cursor_visible,
            );
            let _ = call::sched_yield();
        } else {
            // No blocking poll() on /dev/input/kbd is exposed yet, so sleep
            // briefly instead of spinning; rendering stays damage-driven.
            let req = TimeSpec {
                tv_sec: 0,
                tv_nsec: IDLE_SLEEP_NS,
            };
            let mut rem = TimeSpec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let _ = call::nanosleep(&req, &mut rem);
        }
    }
}

/// Monotonic time in milliseconds, used for cursor blinking only.
fn now_ms() -> u64 {
    let mut ts = TimeSpec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if call::clock_gettime(strat9_syscall::CLOCK_MONOTONIC, &mut ts).is_ok() {
        (ts.tv_sec.max(0) as u64) * 1000 + (ts.tv_nsec.max(0) as u64) / 1_000_000
    } else {
        0
    }
}
