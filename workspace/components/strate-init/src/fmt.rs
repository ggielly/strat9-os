//! Formatting utilities for the init process (no heap allocation).

use crate::log;

/// Format a u32 as decimal digits and write it via `log()`.
///
/// Handles up to 10 digits (max 4 294 967 295).  
/// Zero-padded bytes in the buffer may be read by `from_utf8_unchecked` but are
/// never written to `log` (the slice is trimmed).
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
