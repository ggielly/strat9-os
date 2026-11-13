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

//! 8237 DMA controller stub (master and slave register files).
//!
//! Legacy devices (floppy, parallel port, Sound Blaster-era hardware) program
//! the 8237 through ports `0x00..=0x0F` and `0x80..=0x8F`, and the 16-bit
//! cascade through `0xC0..=0xDF`. A DOS-class guest probes those registers even
//! when it ends up using a BIOS disk service: unmapped reads return stale
//! values and the probe can loop.
//!
//! The model keeps the programmed bytes and reports idle status (no terminal
//! count, no request). It does not move data: transfers still have to go
//! through the device that owns the channel.

/// Master DMA register file: `0x00..=0x0F`.
pub const MASTER_BASE: u16 = 0x00;
/// Master DMA page registers: `0x80..=0x8F` (`0x80` itself is the POST port and
/// is served by the platform model, not here).
pub const MASTER_PAGE_BASE: u16 = 0x81;
/// Slave (16-bit) DMA register file: `0xC0..=0xDF`.
pub const SLAVE_BASE: u16 = 0xC0;
/// Last port of the slave file.
pub const SLAVE_END: u16 = 0xDF;

/// Number of channel registers tracked per controller.
const CHANNELS: usize = 4;

/// True if the port belongs to either 8237 register file.
pub fn handles_port(port: u16) -> bool {
    (MASTER_BASE..=0x0F).contains(&port)
        || (MASTER_PAGE_BASE..=0x8F).contains(&port)
        || (SLAVE_BASE..=SLAVE_END).contains(&port)
}

/// Minimal 8237 state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dma {
    master: [u8; 16],
    page: [u8; 16],
    slave: [u8; 32],
}

impl Dma {
    /// Creates an idle controller pair.
    pub const fn new() -> Self {
        Self {
            master: [0; 16],
            page: [0; 16],
            slave: [0; 32],
        }
    }

    /// Reads one port.
    pub fn read(&mut self, port: u16) -> Option<u8> {
        match port {
            0x00..=0x0F => Some(self.master[usize::from(port)]),
            // `0x80` is the platform POST port; the 8237 page registers are
            // `0x81..=0x8F`.
            0x81..=0x8F => Some(self.page[usize::from(port - MASTER_PAGE_BASE)]),
            0xC0..=0xDF => Some(self.slave[usize::from(port - SLAVE_BASE)]),
            _ => None,
        }
    }

    /// Writes one port.
    pub fn write(&mut self, port: u16, value: u8) {
        match port {
            0x00..=0x0F => self.master[usize::from(port)] = value,
            0x81..=0x8F => self.page[usize::from(port - MASTER_PAGE_BASE)] = value,
            0xC0..=0xDF => self.slave[usize::from(port - SLAVE_BASE)] = value,
            _ => {}
        }
    }

    /// Channel count of the master controller (diagnostics).
    pub const fn channels(&self) -> usize {
        CHANNELS
    }
}

impl Default for Dma {
    fn default() -> Self {
        Self::new()
    }
}
