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

//! Formatting utilities for the init process (no heap allocation).

use crate::log;

/// Format a u32 as decimal digits and write it via `log()`.
///
/// Handles up to 10 digits (max 4 294 967 295).  
/// Zero-padded bytes in the buffer may be read by `from_utf8_unchecked` but are never written to `log` (the slice is trimmed).
pub fn log_u32(mut value: u32) {
    let mut buf = [0u8; 10];

    if value == 0 {
        log("0");
        return;
    }

    let mut i = buf.len();

    while value > 0 {
        i -= 1;
        buf[i] = b'0' + (value % 10) as u8;
        value /= 10;
    }

    let s = unsafe { core::str::from_utf8_unchecked(&buf[i..]) };

    log(s);
}

/// Format up to a handful of bytes as `0xNN NN ...` (uppercase hex) and write
/// the result via `log()`.
///
/// Used for binary headers: printing four magic bytes as a decimal
/// concatenation (`127697670`) hides the actual signature.
pub fn log_hex_bytes(bytes: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";

    log("0x");
    for (index, byte) in bytes.iter().enumerate() {
        if index != 0 {
            log(" ");
        }
        let pair = [DIGITS[(byte >> 4) as usize], DIGITS[(byte & 0x0F) as usize]];
        // SAFETY: both bytes come from the ASCII digit table above.
        log(unsafe { core::str::from_utf8_unchecked(&pair) });
    }
}
