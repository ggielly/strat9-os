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

//! 8237 DMA controller (master and slave register files).
//!
//! Legacy devices (floppy, parallel port, Sound Blaster-era hardware) program
//! the 8237 through ports `0x00..=0x0F` and `0x80..=0x8F`, and the 16-bit
//! cascade through `0xC0..=0xDF`. A DOS-class guest probes those registers even
//! when it ends up using a BIOS disk service; a real firmware such as SeaBIOS
//! additionally uses **channel 2** for every floppy transfer.
//!
//! The model keeps the raw register file (so probes read back what they wrote)
//! and decodes the channel state the floppy controller needs: address, count,
//! page, mode and mask. It never moves data itself: [`FloppyController`] names
//! the transfer, the exit handler performs it through its physical-memory
//! view, and [`Dma::complete`] advances the channel registers.
//!
//! [`FloppyController`]: crate::s9vm::fdc::FloppyController

/// Master DMA register file: `0x00..=0x0F`.
pub const MASTER_BASE: u16 = 0x00;
/// Master DMA page registers: `0x81..=0x8F` (`0x80` itself is the POST port and
/// is served by the platform model, not here).
pub const MASTER_PAGE_BASE: u16 = 0x81;
/// Slave (16-bit) DMA register file: `0xC0..=0xDF`.
pub const SLAVE_BASE: u16 = 0xC0;
/// Last port of the slave file.
pub const SLAVE_END: u16 = 0xDF;

/// Number of channels per controller.
const CHANNELS: usize = 4;
/// Floppy transfer channel.
pub const FLOPPY_CHANNEL: usize = 2;

/// True if the port belongs to either 8237 register file.
pub fn handles_port(port: u16) -> bool {
    (MASTER_BASE..=0x0F).contains(&port)
        || (MASTER_PAGE_BASE..=0x8F).contains(&port)
        || (SLAVE_BASE..=SLAVE_END).contains(&port)
}

/// Decoded state of one DMA channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmaChannel {
    /// Current 16-bit address counter.
    pub address: u16,
    /// Current 16-bit transfer count (number of bytes minus one).
    pub count: u16,
    /// Page register (`A16..A23`).
    pub page: u8,
    /// Mode register byte.
    pub mode: u8,
    /// True while the channel is masked.
    pub masked: bool,
}

impl DmaChannel {
    /// 24-bit physical address currently programmed.
    pub const fn physical_address(&self) -> u32 {
        (self.page as u32) << 16 | self.address as u32
    }

    /// Number of bytes left in the transfer (`count + 1`).
    pub const fn remaining(&self) -> u32 {
        self.count as u32 + 1
    }

    /// True when the mode register selected a memory-to-device transfer.
    pub const fn is_write(&self) -> bool {
        (self.mode >> 2) & 0x03 == 0x02
    }
}

/// Minimal 8237 state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dma {
    master: [u8; 16],
    page: [u8; 16],
    slave: [u8; 32],
    /// Shared low/high byte flip-flop of each controller (0 = master).
    flip_flop: [bool; 2],
    address: [[u16; CHANNELS]; 2],
    count: [[u16; CHANNELS]; 2],
    mode: [u8; 8],
    masked: [bool; 8],
    channel_page: [u8; 8],
}

impl Dma {
    /// Creates an idle controller pair.
    pub const fn new() -> Self {
        Self {
            master: [0; 16],
            page: [0; 16],
            slave: [0; 32],
            flip_flop: [false; 2],
            address: [[0; CHANNELS]; 2],
            count: [[0; CHANNELS]; 2],
            mode: [0; 8],
            masked: [true; 8],
            channel_page: [0; 8],
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
            0x00..=0x0F => {
                self.master[usize::from(port)] = value;
                self.write_master_register(port, value);
            }
            0x81..=0x8F => {
                self.page[usize::from(port - MASTER_PAGE_BASE)] = value;
                if let Some(channel) = page_channel(port) {
                    self.channel_page[usize::from(channel)] = value;
                }
            }
            0xC0..=0xDF => self.slave[usize::from(port - SLAVE_BASE)] = value,
            _ => {}
        }
    }

    /// Decodes the state of one channel (0..=7).
    pub fn channel(&self, index: usize) -> Option<DmaChannel> {
        if index >= 8 {
            return None;
        }
        let controller = if index < CHANNELS { 0 } else { 1 };
        let slot = index % CHANNELS;
        Some(DmaChannel {
            address: self.address[controller][slot],
            count: self.count[controller][slot],
            page: self.channel_page[index],
            mode: self.mode[index],
            masked: self.masked[index],
        })
    }

    /// Advances a channel after `transferred` bytes moved.
    ///
    /// The 8237 increments the address and decrements the count; the model
    /// wraps both like the 16-bit hardware registers.
    pub fn complete(&mut self, index: usize, transferred: u32) {
        if index >= 8 {
            return;
        }
        let controller = if index < CHANNELS { 0 } else { 1 };
        let slot = index % CHANNELS;
        let address = self.address[controller][slot];
        self.address[controller][slot] =
            (u32::from(address).wrapping_add(transferred) & 0xFFFF) as u16;
        let count = self.count[controller][slot];
        let remaining = u32::from(count).saturating_sub(transferred);
        self.count[controller][slot] = if transferred > u32::from(count) {
            0
        } else {
            remaining as u16
        };
    }

    /// Channel count of the master controller (diagnostics).
    pub const fn channels(&self) -> usize {
        CHANNELS
    }

    /// Applies the master register file writes that carry channel semantics.
    fn write_master_register(&mut self, port: u16, value: u8) {
        match port {
            // Address (even) and count (odd) registers, two bytes each.
            0x00..=0x07 => {
                let channel = usize::from((port - 0x00) >> 1);
                let is_count = port & 1 != 0;
                let high = self.flip_flop[0];
                let register = if is_count {
                    &mut self.count[0][channel]
                } else {
                    &mut self.address[0][channel]
                };
                if high {
                    *register = (*register & 0x00FF) | (u16::from(value) << 8);
                } else {
                    *register = (*register & 0xFF00) | u16::from(value);
                }
                self.flip_flop[0] = !high;
            }
            // Clear flip-flop.
            0x0C => self.flip_flop[0] = false,
            // Master clear: same as a hardware reset of the controller.
            0x0D => {
                self.master = [0; 16];
                self.address[0] = [0; CHANNELS];
                self.count[0] = [0; CHANNELS];
                self.mode[..CHANNELS].fill(0);
                self.masked[..CHANNELS].fill(true);
                self.flip_flop[0] = false;
            }
            // Single-channel mask.
            0x0A => {
                let channel = usize::from(value & 0x03);
                self.masked[channel] = value & 0x04 != 0;
            }
            // Mode register.
            0x0B => {
                let channel = usize::from(value & 0x03);
                self.mode[channel] = value;
            }
            _ => {}
        }
    }
}

impl Default for Dma {
    fn default() -> Self {
        Self::new()
    }
}

/// Channel a page register belongs to.
const fn page_channel(port: u16) -> Option<u8> {
    match port {
        0x87 => Some(0),
        0x83 => Some(1),
        0x81 => Some(2),
        0x82 => Some(3),
        0x8B => Some(5),
        0x89 => Some(6),
        0x8A => Some(7),
        _ => None,
    }
}
