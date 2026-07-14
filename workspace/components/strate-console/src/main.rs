//! Console Silo for strat9-os
//!
//! Terminal emulator, ANSI parser, glyph renderer, and shell — all running
//! in userspace via syscalls to /dev/input/kbd and /dev/display/0.0.
//!
//! This is the ring-3 replacement for the kernel ConsoleScheme. The kernel
//! VgaWriter is retained for boot-only messages.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use strat9_syscall::call;

fn log(s: &str) {
    let _ = call::write(2, s.as_bytes());
    let _ = call::write(2, b"\n");
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("[console] strate-console v0.1.0");
    log("[console] entering main loop");

    loop {
        let _ = call::sched_yield();
    }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
