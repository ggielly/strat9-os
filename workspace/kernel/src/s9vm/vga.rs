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

//! Minimal VGA register model (CRTC, sequencer, graphics, attribute, status).
//!
//! A DOS-class guest programs the VGA plane directly: after the BIOS sets the
//! mode it may reload the CRTC (ports `0x3D4`/`0x3D5`), read the status port
//! `0x3DA` to synchronise with the display, and touch the sequencer/graphics
//! registers while writing text. An unmodeled `0x3DA` is the classic hang: the
//! retrace poll never sees the bit flip and the guest spins forever.
//!
//! The model stores the register bytes and makes the status port report a
//! display-enabled/vertical-retrace pattern that alternates on every read, so
//! a retrace poll always terminates.

/// First port of the mono CRTC block (`0x3B0..=0x3BF`).
pub const MONO_BASE: u16 = 0x3B0;
/// First port of the colour VGA block (`0x3C0..=0x3DF`).
pub const COLOUR_BASE: u16 = 0x3C0;
/// Last port of the colour VGA block.
pub const COLOUR_END: u16 = 0x3DF;
/// CRTC index port (colour).
pub const CRTC_INDEX_PORT: u16 = 0x3D4;
/// CRTC data port (colour).
pub const CRTC_DATA_PORT: u16 = 0x3D5;
/// Input status register 1 (display enable / vertical retrace).
pub const STATUS_PORT: u16 = 0x3DA;

/// Index counts of the register files.
const ATTRIBUTE_REGS: usize = 32;
const SEQUENCER_REGS: usize = 8;
const GRAPHICS_REGS: usize = 16;
const CRTC_REGS: usize = 32;

/// True if the port belongs to the VGA register file.
pub fn handles_port(port: u16) -> bool {
    (MONO_BASE..=0x3BF).contains(&port) || (COLOUR_BASE..=COLOUR_END).contains(&port)
}

/// Minimal VGA register state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vga {
    attribute: [u8; ATTRIBUTE_REGS],
    sequencer: [u8; SEQUENCER_REGS],
    graphics: [u8; GRAPHICS_REGS],
    crtc: [u8; CRTC_REGS],
    attribute_index: u8,
    sequencer_index: u8,
    graphics_index: u8,
    crtc_index: u8,
    /// Alternates on every status read: `false` = display enabled, `true` =
    /// vertical retrace.
    status_flip: bool,
}

impl Vga {
    /// Creates a text-mode register state.
    pub const fn new() -> Self {
        Self {
            attribute: [0; ATTRIBUTE_REGS],
            sequencer: [0; SEQUENCER_REGS],
            graphics: [0; GRAPHICS_REGS],
            crtc: [0; CRTC_REGS],
            attribute_index: 0,
            sequencer_index: 0,
            graphics_index: 0,
            crtc_index: 0,
            status_flip: false,
        }
    }

    /// Reads one port. `None` means "not a modelled register".
    pub fn read(&mut self, port: u16) -> Option<u8> {
        let value = match port {
            // Input status register 1: alternate a display-enabled phase and a
            // vertical-retrace phase so a polling loop always makes progress.
            0x3DA | 0x3BA => {
                self.status_flip = !self.status_flip;
                if self.status_flip {
                    0x00
                } else {
                    // Bit 3 (vertical retrace) + bit 0 (display enable).
                    0x09
                }
            }
            0x3C2 => 0,
            // CRTC (colour and mono aliases).
            0x3D4 | 0x3B4 => self.crtc_index,
            0x3D5 | 0x3B5 => self.crtc[(self.crtc_index as usize) % CRTC_REGS],
            // Sequencer.
            0x3C4 => self.sequencer_index,
            0x3C5 => self.sequencer[(self.sequencer_index as usize) % SEQUENCER_REGS],
            // Attribute controller.
            0x3C0 | 0x3C1 => self.attribute[(self.attribute_index as usize) % ATTRIBUTE_REGS],
            // Graphics controller.
            0x3CE => self.graphics_index,
            0x3CF => self.graphics[(self.graphics_index as usize) % GRAPHICS_REGS],
            // DAC palette: mask register and read-index latch.
            0x3C6 => 0xFF,
            0x3C7 | 0x3C8 => self.attribute_index,
            0x3C9 => {
                self.attribute_index = self.attribute_index.wrapping_add(1);
                0
            }
            // Other registers in the two VGA windows read as zero.
            p if (MONO_BASE..=0x3BF).contains(&p) || (COLOUR_BASE..=COLOUR_END).contains(&p) => 0,
            _ => return None,
        };
        Some(value)
    }

    /// Writes one port.
    pub fn write(&mut self, port: u16, value: u8) {
        match port {
            // CRTC (colour and mono aliases).
            0x3D4 | 0x3B4 => self.crtc_index = value,
            0x3D5 | 0x3B5 => {
                self.crtc[(self.crtc_index as usize) % CRTC_REGS] = value;
            }
            // Attribute controller: the high bit selects index vs data, as on
            // the real chip.
            0x3C0 => {
                if value & 0x20 != 0 {
                    self.attribute_index = value & 0x1F;
                } else {
                    self.attribute[(self.attribute_index as usize) % ATTRIBUTE_REGS] = value;
                    self.attribute_index = (self.attribute_index.wrapping_add(1)) & 0x1F;
                }
            }
            0x3C1 => self.attribute[(self.attribute_index as usize) % ATTRIBUTE_REGS] = value,
            // Sequencer.
            0x3C4 => self.sequencer_index = value,
            0x3C5 => self.sequencer[(self.sequencer_index as usize) % SEQUENCER_REGS] = value,
            // Graphics controller.
            0x3CE => self.graphics_index = value,
            0x3CF => self.graphics[(self.graphics_index as usize) % GRAPHICS_REGS] = value,
            // Palette write path: accept the bytes, track the index.
            0x3C8 => self.attribute_index = value,
            0x3C9 => self.attribute_index = self.attribute_index.wrapping_add(1),
            _ => {}
        }
    }

    /// Current CRTC index (diagnostics).
    pub const fn crtc_index(&self) -> u8 {
        self.crtc_index
    }

    /// Current attribute index (diagnostics).
    pub const fn attribute_index(&self) -> u8 {
        self.attribute_index
    }
}

impl Default for Vga {
    fn default() -> Self {
        Self::new()
    }
}
