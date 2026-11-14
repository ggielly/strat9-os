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

//! Keyboard input handler for the console.
//! Reads from /dev/input/kbd and decodes scancodes with the shared
//! `strat9-keymap` decoder (same code as the kernel and the input server).

use strat9_keymap::{Decoder, Layout};
use strat9_syscall::call;

pub struct InputHandler {
    kbd_fd: usize,
    decoder: Decoder,
}

impl InputHandler {
    pub fn open() -> Option<Self> {
        let kbd_fd = call::openat(0, "/dev/input/kbd", 0x1, 0).ok()?;
        Some(InputHandler {
            kbd_fd,
            decoder: Decoder::new(Layout::Azerty),
        })
    }

    /// Read up to `out.len()` raw scancodes in a single syscall.
    ///
    /// Non-blocking: returns 0 when nothing is pending.
    pub fn read_raw(&mut self, out: &mut [u8]) -> usize {
        match call::read(self.kbd_fd, out) {
            Ok(n) => n.min(out.len()),
            Err(_) => 0,
        }
    }

    /// Translate a batch of raw scancodes into UTF-8 bytes.
    ///
    /// Decoder state (modifiers, 0xE0 prefix, dead key) persists across
    /// calls, so a scancode burst can be split anywhere.
    pub fn translate(&mut self, raw: &[u8], out: &mut [u8]) -> usize {
        let mut n = 0;
        for &scancode in raw {
            let keys = self.decoder.feed(scancode);
            let bytes = keys.as_bytes();
            if n + bytes.len() > out.len() {
                break;
            }
            out[n..n + bytes.len()].copy_from_slice(bytes);
            n += bytes.len();
        }
        n
    }
}
