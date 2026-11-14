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
//! There is no real PS/2 device behind the controller: no scancodes are
//! produced, and `INT 16h` remains the path that delivers keys.

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
/// Controller command: write output port (next data byte goes there).
const CTL_WRITE_OUTPUT_PORT: u8 = 0xD1;
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

/// True if the port belongs to the 8042.
pub const fn handles_port(port: u16) -> bool {
    port == DATA_PORT || port == STATUS_PORT
}

/// Minimal 8042 state with a small controller-to-host output queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyboardController {
    /// Bytes waiting for the host on the data port.
    output: [u8; OUTPUT_CAPACITY],
    /// Number of valid bytes in `output` (at the front).
    output_len: u8,
    /// Last command written to port `0x64`.
    last_command: u8,
    /// Next data-port write goes to the controller output port, not the
    /// keyboard (set by command `0xD1`).
    output_port_write: bool,
}

impl KeyboardController {
    /// Creates an idle controller.
    pub const fn new() -> Self {
        Self {
            output: [0; OUTPUT_CAPACITY],
            output_len: 0,
            last_command: 0,
            output_port_write: false,
        }
    }

    /// Reads one port.
    pub fn read(&mut self, port: u16) -> Option<u8> {
        match port {
            DATA_PORT => {
                if self.output_len != 0 {
                    let value = self.output[0];
                    self.pop_front();
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

    /// Last command written to the status port (diagnostics).
    pub const fn last_command(&self) -> u8 {
        self.last_command
    }

    /// Current status byte.
    pub fn status(&self) -> u8 {
        let mut status = IDLE_STATUS;
        if self.output_len != 0 {
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
}

impl Default for KeyboardController {
    fn default() -> Self {
        Self::new()
    }
}
