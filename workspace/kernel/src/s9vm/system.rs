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

//! Chipset system-control ports (`0x92` and `0xCF9`).
//!
//! PC firmware toggles the A20 gate through port `0x92` before it enters
//! protected mode, and resets the machine through the same port or through the
//! PCI reset control register `0xCF9`. A guest that does not see the A20 bit it
//! wrote assumes the gate stayed closed and falls back to the keyboard
//! controller (which the 8042 model does not implement), so the bit must read
//! back.
//!
//! The model is deliberately small: A20 state and reset requests. Reset is
//! recorded and reported to the runner, which turns it into a clean guest
//! abort instead of restarting the world underneath the firmware.

/// System control port A (A20 gate and fast reset).
pub const PORT_A: u16 = 0x92;
/// PCI reset control register.
pub const PORT_RESET: u16 = 0xCF9;

/// `0x92` bit 1: A20 gate enabled.
pub const A20_ENABLE: u8 = 0x02;
/// `0x92` bit 0: fast reset request.
pub const FAST_RESET: u8 = 0x01;

/// True if `port` belongs to the system-control model.
pub const fn handles_port(port: u16) -> bool {
    port == PORT_A || port == PORT_RESET
}

/// State of the system-control ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemControl {
    a20: bool,
    reset: bool,
}

impl SystemControl {
    /// Creates the model with A20 enabled, as firmware leaves it for a boot.
    pub const fn new() -> Self {
        Self {
            a20: true,
            reset: false,
        }
    }

    /// Reads one port.
    pub fn read(&mut self, port: u16) -> Option<u8> {
        match port {
            PORT_A => Some(if self.a20 { A20_ENABLE } else { 0 }),
            PORT_RESET => Some(0),
            _ => None,
        }
    }

    /// Writes one port.
    pub fn write(&mut self, port: u16, value: u8) {
        match port {
            PORT_A => {
                self.a20 = value & A20_ENABLE != 0;
                if value & FAST_RESET != 0 {
                    self.reset = true;
                }
            }
            PORT_RESET => {
                // Bits 1 and 0 both set request a hard reset.
                if value & 0x06 == 0x06 {
                    self.reset = true;
                }
            }
            _ => {}
        }
    }

    /// True if the guest asked for a machine reset.
    pub const fn reset_requested(&self) -> bool {
        self.reset
    }

    /// Takes a pending reset request.
    pub fn take_reset(&mut self) -> bool {
        let pending = self.reset;
        self.reset = false;
        pending
    }

    /// Current A20 state.
    pub const fn a20(&self) -> bool {
        self.a20
    }
}

impl Default for SystemControl {
    fn default() -> Self {
        Self::new()
    }
}
