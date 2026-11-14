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

//! Input Server for strat9-os
//!
//! Reads raw PS/2 scancodes from /dev/input/kbd and mouse events from
//! /dev/input/mouse. Translates scancodes to UTF-8 with the shared
//! `strat9-keymap` decoder (AZERTY/QWERTY). Distributes processed events to clients.
//!
//! Architecture:
//!   Hardware => PS/2 IRQ => kernel ring buffer => /dev/input/kbd => THIS SERVER
//!   => layout translation => processed chars => clients (console, shell, apps)
//!
//! This moves keyboard layout logic out of the kernel, following the Haiku
//! Input Server / Fuchsia Input Reader pattern.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use strat9_keymap::{Decoder, Layout};
use strat9_syscall::call;

// ============================================================================
// Main loop
// ============================================================================

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Open keyboard device
    let kbd_fd = match call::open("/dev/input/kbd", 0 /* O_RDONLY */) {
        Ok(fd) => fd,
        Err(e) => {
            let _ = e;
            log_open_failure("kbd");
            loop {
                core::hint::spin_loop();
            }
        }
    };

    // Open mouse device
    let mouse_fd = match call::open("/dev/input/mouse", 0) {
        Ok(fd) => fd,
        Err(e) => {
            let _ = e;
            log_open_failure("mouse");
            loop {
                core::hint::spin_loop();
            }
        }
    };

    serial_println("[input-server] started");

    let mut decoder = Decoder::new(Layout::Azerty);
    let mut kbd_buf = [0u8; 64];
    let mut mouse_buf = [0u8; 56]; // 8 events × 7 bytes

    loop {
        // Read keyboard scancodes
        if let Ok(n) = call::read(kbd_fd, &mut kbd_buf) {
            for &sc in &kbd_buf[..n] {
                let keys = decoder.feed(sc);
                if !keys.is_empty() {
                    // Write the UTF-8 bytes of the translated key to stdout
                    let _ = call::write(1, keys.as_bytes());
                }
            }
        }

        // Read mouse events (just consume for now : display server will use them)
        let _ = call::read(mouse_fd, &mut mouse_buf);

        // Yield to other processes
        let _ = call::sched_yield();
    }
}

fn serial_println(s: &str) {
    let _ = call::write(2, s.as_bytes());
    let _ = call::write(2, b"\n");
}

/// Log an open failure to stderr without alloc:
/// `[input-server] failed to open /dev/input/<dev>`.
fn log_open_failure(dev: &str) {
    const PREFIX: &[u8] = b"[input-server] failed to open /dev/input/";
    let _ = call::write(2, PREFIX);
    let _ = call::write(2, dev.as_bytes());
    let _ = call::write(2, b"\n");
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    strat9_syscall::call::handle_panic("strate-input", info)
}
