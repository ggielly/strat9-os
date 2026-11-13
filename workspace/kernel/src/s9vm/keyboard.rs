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
//! independently of) the BIOS keyboard service: the kernel polls the status
//! port for "input buffer full" and "output buffer full", sends commands to
//! port `0x64` and reads scancodes from port `0x60`. Leaving those ports
//! unmodeled makes the poll reads return stale values and the guest spins.
//!
//! The model exposes the *idle* controller: output buffer empty, input buffer
//! empty, system flag set, keyboard enabled. A guest that polls for a key
//! therefore sees "no key" instead of a stuck status bit, and the BIOS
//! keyboard service (`INT 16h`) remains the path that delivers keys.

/// Keyboard data port (read: scancode, write: command/data byte).
pub const DATA_PORT: u16 = 0x60;
/// Keyboard controller status/command port.
pub const STATUS_PORT: u16 = 0x64;

/// Status byte: output buffer empty, input buffer empty, system flag set,
/// keyboard enabled. Bit 2 (system flag) and bit 4 (keyboard enabled) are the
/// bits DOS tests after its controller self-test.
const IDLE_STATUS: u8 = 0x14;

/// True if the port belongs to the 8042.
pub const fn handles_port(port: u16) -> bool {
    port == DATA_PORT || port == STATUS_PORT
}

/// Minimal 8042 state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyboardController {
    /// Last status value observed by the guest (kept for diagnostics).
    status: u8,
    /// Last command written to port `0x64`.
    last_command: u8,
}

impl KeyboardController {
    /// Creates an idle controller.
    pub const fn new() -> Self {
        Self {
            status: IDLE_STATUS,
            last_command: 0,
        }
    }

    /// Reads one port.
    pub fn read(&mut self, port: u16) -> Option<u8> {
        match port {
            // No scancode is queued: the BIOS service owns the key path.
            DATA_PORT => Some(0),
            STATUS_PORT => Some(self.status),
            _ => None,
        }
    }

    /// Writes one port.
    pub fn write(&mut self, port: u16, value: u8) {
        match port {
            DATA_PORT => {
                // A data byte sent to the controller is acknowledged and
                // discarded: there is no PS/2 device behind the model.
            }
            STATUS_PORT => {
                self.last_command = value;
                // Commands never leave the controller in a busy state.
                self.status = IDLE_STATUS;
            }
            _ => {}
        }
    }

    /// Last command written to the status port (diagnostics).
    pub const fn last_command(&self) -> u8 {
        self.last_command
    }

    /// Current status byte.
    pub const fn status(&self) -> u8 {
        self.status
    }
}

impl Default for KeyboardController {
    fn default() -> Self {
        Self::new()
    }
}
