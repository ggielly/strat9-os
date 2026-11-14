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

//! 8042 keyboard controller model (ports `0x60`/`0x64`).
//!
//! A DOS-class guest talks to the keyboard controller directly before (and
//! independently of) the BIOS keyboard service: it polls the status port for
//! "output buffer full", sends controller commands to port `0x64`, keyboard
//! commands to port `0x60`, and reads acknowledgements from the data port.
//!
//! The model answers the controller self-test (`0xAA` → `0x55`), the keyboard
//! interface test (`0xAB` → `0x00`), and acknowledges every keyboard command
//! (`0xFA`); a keyboard reset (`0xFF`) returns the ACK followed by the
//! self-test success byte (`0xAA`). Without those responses PC firmware (and
//! externally SeaBIOS) spends seconds in its timeout loops before deciding the
//! keyboard is absent.
//!
//! The host can also type into the guest: [`KeyboardController::push_scancode`]
//! queues set-1 scancodes exactly as a PS/2 keyboard would send them, the
//! status port reports "output buffer full" while the queue is not empty, and
//! the runner raises `IRQ1` while bytes are waiting. [`text_to_scancodes`]
//! translates host text (ASCII) into that make/break stream, so a DOS guest
//! with its own `INT 9` handler sees a real keyboard instead of only the BIOS
//! `INT 16h` polling path.

/// Keyboard data port (read: controller output, write: keyboard command/data).
pub const DATA_PORT: u16 = 0x60;
/// Keyboard controller status/command port.
pub const STATUS_PORT: u16 = 0x64;

/// Status byte: output buffer empty, input buffer empty, system flag set,
/// keyboard enabled.
const IDLE_STATUS: u8 = 0x14;
/// Status bit 0: output buffer full.
const STATUS_OUTPUT_FULL: u8 = 0x01;
/// Keyboard acknowledgement byte.
const PS2_ACK: u8 = 0xFA;
/// Keyboard self-test success byte.
const PS2_SELFTEST_OK: u8 = 0xAA;
/// Keyboard ID bytes for `0xF2` (MF2 keyboard, translated).
const PS2_ID: [u8; 2] = [0xAB, 0x83];

/// Controller command: read configuration byte.
const CTL_READ_CONFIG: u8 = 0x20;
/// Controller command: write configuration byte (next data byte).
const CTL_WRITE_CONFIG: u8 = 0x60;
/// Controller command: write output port (next data byte goes there).
const CTL_WRITE_OUTPUT_PORT: u8 = 0xD1;
/// Controller command: write auxiliary device (next data byte).
const CTL_WRITE_AUX: u8 = 0xD4;
/// Controller command: controller self-test.
const CTL_SELFTEST: u8 = 0xAA;
/// Controller command: keyboard interface test.
const CTL_KBD_TEST: u8 = 0xAB;
/// Keyboard command: read ID.
const KBD_READ_ID: u8 = 0xF2;
/// Keyboard command: reset and self-test.
const KBD_RESET: u8 = 0xFF;

/// Capacity of the controller output queue.
const OUTPUT_CAPACITY: usize = 8;
/// Capacity of the host-to-guest scancode queue.
pub const INPUT_CAPACITY: usize = 32;

/// PS/2 set-1 scancodes used by [`text_to_scancodes`].
const SCANCODE_ESCAPE: u8 = 0x01;
const SCANCODE_BACKSPACE: u8 = 0x0E;
const SCANCODE_TAB: u8 = 0x0F;
const SCANCODE_ENTER: u8 = 0x1C;
const SCANCODE_LEFT_SHIFT: u8 = 0x2A;
const SCANCODE_RIGHT_SHIFT: u8 = 0x36;
const SCANCODE_SPACE: u8 = 0x39;
const SCANCODE_BREAK: u8 = 0x80;

/// True if the port belongs to the 8042.
pub const fn handles_port(port: u16) -> bool {
    port == DATA_PORT || port == STATUS_PORT
}

/// Minimal 8042 state with a small controller-to-host output queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyboardController {
    /// Bytes waiting for the host on the data port (controller replies).
    output: [u8; OUTPUT_CAPACITY],
    /// Number of valid bytes in `output` (at the front).
    output_len: u8,
    /// Scancodes typed by the host and not read by the guest yet.
    input: [u8; INPUT_CAPACITY],
    /// Number of valid scancodes in `input` (at the front).
    input_len: u8,
    /// Last command written to port `0x64`.
    last_command: u8,
    /// Number of data-port reads the guest performed (diagnostics only).
    ///
    /// A guest that queues scancodes but never reads `0x60` is the difference
    /// between "the interrupt never arrived" and "the handler read the port".
    data_reads: u32,
    /// Reads of `0x60` answered from the controller reply queue (diagnostics).
    reply_reads: u32,
    /// Reads of `0x60` answered from the host scancode queue (diagnostics).
    scancode_reads: u32,
    /// Next data-port write goes to the controller output port, not the
    /// keyboard (set by command `0xD1`).
    output_port_write: bool,
    /// Next data-port write is a controller parameter (config/aux), not a
    /// keyboard command, so it must not produce a keyboard ACK.
    controller_data: bool,
}

impl KeyboardController {
    /// Creates an idle controller.
    pub const fn new() -> Self {
        Self {
            output: [0; OUTPUT_CAPACITY],
            output_len: 0,
            input: [0; INPUT_CAPACITY],
            input_len: 0,
            last_command: 0,
            data_reads: 0,
            reply_reads: 0,
            scancode_reads: 0,
            output_port_write: false,
            controller_data: false,
        }
    }

    /// Queues one set-1 scancode as if the PS/2 keyboard sent it.
    ///
    /// Returns `false` when the queue is full: the caller keeps the remaining
    /// bytes and retries after the guest has read some.
    pub fn push_scancode(&mut self, code: u8) -> bool {
        let len = usize::from(self.input_len);
        if len >= INPUT_CAPACITY {
            return false;
        }
        self.input[len] = code;
        self.input_len += 1;
        true
    }

    /// True while the guest has not read every queued scancode.
    pub const fn has_scancode(&self) -> bool {
        self.input_len != 0
    }

    /// Number of scancodes waiting to be read by the guest.
    pub const fn pending_scancodes(&self) -> u8 {
        self.input_len
    }

    /// Reads one port.
    pub fn read(&mut self, port: u16) -> Option<u8> {
        match port {
            DATA_PORT => {
                self.data_reads = self.data_reads.saturating_add(1);
                if self.output_len != 0 {
                    let value = self.output[0];
                    self.reply_reads = self.reply_reads.saturating_add(1);
                    self.pop_front();
                    Some(value)
                } else if self.input_len != 0 {
                    self.scancode_reads = self.scancode_reads.saturating_add(1);
                    // The host reuses the same output buffer for scancodes: a
                    // real controller only has one byte path to the guest.
                    let value = self.input[0];
                    self.pop_input_front();
                    Some(value)
                } else {
                    Some(0)
                }
            }
            STATUS_PORT => Some(self.status()),
            _ => None,
        }
    }

    /// Writes one port.
    pub fn write(&mut self, port: u16, value: u8) {
        match port {
            DATA_PORT => self.write_data(value),
            STATUS_PORT => self.write_command(value),
            _ => {}
        }
    }

    /// Number of data-port reads observed so far (diagnostics only).
    pub const fn data_reads(&self) -> u32 {
        self.data_reads
    }

    /// Reads of `0x60` answered from the controller reply queue.
    pub const fn reply_reads(&self) -> u32 {
        self.reply_reads
    }

    /// Reads of `0x60` answered from the host scancode queue.
    pub const fn scancode_reads(&self) -> u32 {
        self.scancode_reads
    }

    /// Last command written to the status port (diagnostics).
    pub const fn last_command(&self) -> u8 {
        self.last_command
    }

    /// Current status byte.
    pub fn status(&self) -> u8 {
        let mut status = IDLE_STATUS;
        if self.output_len != 0 || self.input_len != 0 {
            status |= STATUS_OUTPUT_FULL;
        }
        status
    }

    /// Handles a data-port write (keyboard command or parameter).
    fn write_data(&mut self, value: u8) {
        if self.output_port_write {
            // `0xD1` selected the controller output port (A20/gate control,
            // not modeled); consume the byte without a keyboard reply.
            self.output_port_write = false;
            return;
        }
        if self.controller_data {
            // Configuration byte or auxiliary-device byte: no keyboard ACK.
            self.controller_data = false;
            return;
        }
        self.push(PS2_ACK);
        match value {
            KBD_RESET => self.push(PS2_SELFTEST_OK),
            KBD_READ_ID => {
                self.push(PS2_ID[0]);
                self.push(PS2_ID[1]);
            }
            _ => {}
        }
    }

    /// Handles a status-port write (controller command).
    fn write_command(&mut self, value: u8) {
        self.last_command = value;
        self.output_port_write = value == CTL_WRITE_OUTPUT_PORT;
        self.controller_data = matches!(value, CTL_WRITE_CONFIG | CTL_WRITE_AUX);
        match value {
            CTL_SELFTEST => self.push(0x55),
            CTL_KBD_TEST => self.push(0x00),
            CTL_READ_CONFIG => self.push(IDLE_STATUS),
            _ => {}
        }
    }

    /// Appends one byte to the output queue when there is room.
    fn push(&mut self, value: u8) {
        let len = usize::from(self.output_len);
        if len < OUTPUT_CAPACITY {
            self.output[len] = value;
            self.output_len += 1;
        }
    }

    /// Drops the front byte of the output queue.
    fn pop_front(&mut self) {
        if self.output_len == 0 {
            return;
        }
        let len = usize::from(self.output_len);
        for index in 1..len {
            self.output[index - 1] = self.output[index];
        }
        self.output_len -= 1;
    }

    /// Drops the front scancode of the input queue.
    fn pop_input_front(&mut self) {
        if self.input_len == 0 {
            return;
        }
        let len = usize::from(self.input_len);
        for index in 1..len {
            self.input[index - 1] = self.input[index];
        }
        self.input_len -= 1;
    }
}

/// One scancode of a key press, with the shift state it needs.
///
/// `shift` selects the shifted row of a US layout, so an uppercase letter or a
/// symbol (`!`, `"`, `?`, ...) is reported with the shift key held while its
/// make code is sent. The break code (make | `0x80`) always follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyStroke {
    /// Set-1 make code of the key.
    pub scancode: u8,
    /// True when the shift key must be down for this character.
    pub shift: bool,
}

/// Maps one ASCII byte to a US-layout key stroke.
///
/// Returns `None` for characters a PC keyboard cannot type directly (control
/// bytes other than the named ones, non-ASCII). [`text_to_scancodes`] skips
/// them so a caller can pass a raw line of text.
pub fn ascii_keystroke(byte: u8) -> Option<KeyStroke> {
    let (scancode, shift) = match byte {
        b'\x1b' => (SCANCODE_ESCAPE, false),
        b'\x08' => (SCANCODE_BACKSPACE, false),
        b'\t' => (SCANCODE_TAB, false),
        b'\r' => (SCANCODE_ENTER, false),
        b'\n' => (SCANCODE_ENTER, false),
        b' ' => (SCANCODE_SPACE, false),
        b'1'..=b'9' => (0x02 + (byte - b'1'), false),
        b'0' => (0x0B, false),
        b'-' => (0x0C, false),
        b'=' => (0x0D, false),
        b'!' => (0x02, true),
        b'@' => (0x03, true),
        b'#' => (0x04, true),
        b'$' => (0x05, true),
        b'%' => (0x06, true),
        b'^' => (0x07, true),
        b'&' => (0x08, true),
        b'*' => (0x09, true),
        b'(' => (0x0A, true),
        b')' => (0x0B, true),
        b'_' => (0x0C, true),
        b'+' => (0x0D, true),
        b'q' | b'Q' => (0x10, byte == b'Q'),
        b'w' | b'W' => (0x11, byte == b'W'),
        b'e' | b'E' => (0x12, byte == b'E'),
        b'r' | b'R' => (0x13, byte == b'R'),
        b't' | b'T' => (0x14, byte == b'T'),
        b'y' | b'Y' => (0x15, byte == b'Y'),
        b'u' | b'U' => (0x16, byte == b'U'),
        b'i' | b'I' => (0x17, byte == b'I'),
        b'o' | b'O' => (0x18, byte == b'O'),
        b'p' | b'P' => (0x19, byte == b'P'),
        b'[' | b'{' => (0x1A, byte == b'{'),
        b']' | b'}' => (0x1B, byte == b'}'),
        b'a' | b'A' => (0x1E, byte == b'A'),
        b's' | b'S' => (0x1F, byte == b'S'),
        b'd' | b'D' => (0x20, byte == b'D'),
        b'f' | b'F' => (0x21, byte == b'F'),
        b'g' | b'G' => (0x22, byte == b'G'),
        b'h' | b'H' => (0x23, byte == b'H'),
        b'j' | b'J' => (0x24, byte == b'J'),
        b'k' | b'K' => (0x25, byte == b'K'),
        b'l' | b'L' => (0x26, byte == b'L'),
        b';' | b':' => (0x27, byte == b':'),
        b'\'' | b'"' => (0x28, byte == b'"'),
        b'`' | b'~' => (0x29, byte == b'~'),
        b'\\' | b'|' => (0x2B, byte == b'|'),
        b'z' | b'Z' => (0x2C, byte == b'Z'),
        b'x' | b'X' => (0x2D, byte == b'X'),
        b'c' | b'C' => (0x2E, byte == b'C'),
        b'v' | b'V' => (0x2F, byte == b'V'),
        b'b' | b'B' => (0x30, byte == b'B'),
        b'n' | b'N' => (0x31, byte == b'N'),
        b'm' | b'M' => (0x32, byte == b'M'),
        b',' | b'<' => (0x33, byte == b'<'),
        b'.' | b'>' => (0x34, byte == b'>'),
        b'/' | b'?' => (0x35, byte == b'?'),
        _ => return None,
    };
    Some(KeyStroke { scancode, shift })
}

/// Appends the make/break scancodes that type `text` on a US keyboard.
///
/// A shifted key is bracketed by a shift press and release, so every character
/// is self-contained: the guest's `INT 9` handler decodes the same key the host
/// typed without any cross-character state.
pub fn text_to_scancodes(text: &[u8], out: &mut alloc::vec::Vec<u8>) {
    for &byte in text {
        let Some(stroke) = ascii_keystroke(byte) else {
            continue;
        };
        if stroke.shift {
            out.push(SCANCODE_LEFT_SHIFT);
        }
        out.push(stroke.scancode);
        out.push(stroke.scancode | SCANCODE_BREAK);
        if stroke.shift {
            out.push(SCANCODE_LEFT_SHIFT | SCANCODE_BREAK);
        }
    }
}

/// Prefix of an extended PS/2 set-1 scan code (arrows, Home/End, keypad).
pub const SCANCODE_EXTENDED: u8 = 0xE0;

/// Extended scan code of one key the rest of the system reports above `0x7F`.
///
/// The kernel keyboard driver yields single bytes for the special keys (see
/// `strat9_keymap::{KEY_UP, …}`). A PC sends those as `0xE0` followed
/// by the code below, and a DOS `INT 9` handler stores them in the keyboard
/// buffer with a zero ASCII byte, which is how `INT 16h` reports an arrow.
pub const fn extended_scan(key: u8) -> Option<u8> {
    match key {
        strat9_keymap::KEY_UP => Some(0x48), // up
        strat9_keymap::KEY_DOWN => Some(0x50), // down
        strat9_keymap::KEY_LEFT => Some(0x4B), // left
        strat9_keymap::KEY_RIGHT => Some(0x4D), // right
        strat9_keymap::KEY_HOME => Some(0x47), // home
        strat9_keymap::KEY_END => Some(0x4F), // end
        _ => None,
    }
}

/// Appends the scancodes that type one byte, and returns the firmware-buffer
/// entry it produces.
///
/// Printable and named ASCII bytes get the same sequence [`text_to_scancodes`]
/// produces. The special keys above `0x7F` get an `0xE0`-prefixed make/break
/// pair and a buffer entry with a zero ASCII byte. `None` means the byte cannot
/// be typed on a PC keyboard.
pub fn keystroke_for(byte: u8, out: &mut alloc::vec::Vec<u8>) -> Option<(u8, u8)> {
    if let Some(scan) = extended_scan(byte) {
        out.push(SCANCODE_EXTENDED);
        out.push(scan);
        out.push(SCANCODE_EXTENDED);
        out.push(scan | SCANCODE_BREAK);
        return Some((scan, 0));
    }
    let stroke = ascii_keystroke(byte)?;
    if stroke.shift {
        out.push(SCANCODE_LEFT_SHIFT);
    }
    out.push(stroke.scancode);
    out.push(stroke.scancode | SCANCODE_BREAK);
    if stroke.shift {
        out.push(SCANCODE_LEFT_SHIFT | SCANCODE_BREAK);
    }
    // Line feeds never reach DOS: `INT 16h` reports Enter as CR.
    Some((0, if byte == b'\n' { b'\r' } else { byte }))
}

impl Default for KeyboardController {
    fn default() -> Self {
        Self::new()
    }
}
