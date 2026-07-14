#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use core::{alloc::Layout, panic::PanicInfo};
use strat9_syscall::call;

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
    for &b in banner {
        term.process_byte(b);
    }

    let mut cells = [[scrollback::Cell::blank(DEFAULT_FG, DEFAULT_BG); 256]; 64];
    render_terminal(&term, &mut cells);
    rend.render(&cells, term.cursor_row, term.cursor_col, term.rows);

    loop {
        if let Some(byte) = kbd.read_byte() {
            term.process_byte(byte);
        }

        render_terminal(&term, &mut cells);
        rend.render(&cells, term.cursor_row, term.cursor_col, term.rows);

        let _ = call::sched_yield();
    }
}

fn render_terminal(term: &TerminalCore, cells: &mut [[scrollback::Cell; 256]; 64]) {
    let visible_rows = term.rows.min(64);
    for row in 0..visible_rows {
        for col in 0..term.cols.min(256) {
            cells[row][col] = term.screen[row][col];
        }
    }
}
