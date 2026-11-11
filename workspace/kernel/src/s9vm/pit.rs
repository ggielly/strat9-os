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

//! s9vm — pure model of the Intel 8254/8253 programmable interval timer.
//!
//! This module models the minimal architectural state of the three PIT
//! channels and their mode/command register. It **touches no hardware**: the
//! kernel layer forwards guest I/O port accesses to [`Pit::read`] /
//! [`Pit::write`] and calls [`Pit::advance`] with the elapsed bus ticks to
//! learn whether channel 0 raised IRQ0.
//!
//! The encodings come from the Intel documentation (8254 datasheet: command
//! register format, six counting modes, latch command). No constant specific
//! to a particular hypervisor is used.
//!
//! ## Ports
//!
//! ```text
//! 0x40  channel 0 data (system timer, wired to IRQ0)
//! 0x41  channel 1 data (legacy RAM refresh)
//! 0x42  channel 2 data (PC speaker)
//! 0x43  mode/command register (write-only)
//! ```
//!
//! ## Time base
//!
//! Counts are expressed in PIT bus ticks, nominally [`FREQUENCY_HZ`]
//! (1.193182 MHz). The model is pure, so it cannot read the bus clock: the
//! caller passes the elapsed ticks to [`Pit::advance`].
//!
//! ## Output and IRQ0
//!
//! [`Pit::advance`] returns `true` when channel 0 expired during the call, and
//! [`Pit::irq_level`] reports the pulse until the next call to `advance`. In
//! modes 2 (rate generator) and 3 (square wave) the counter reloads and pulses
//! again every period; in the one-shot modes (0, 1, 4, 5) it stops after the
//! first expiry, exactly as the hardware does.
//!
//! ## Binary / BCD
//!
//! Counts programmed with the BCD bit set are decoded from decimal digits
//! (nibbles greater than 9 are rejected: the programming is ignored and the
//! channel keeps its previous state). Counts read back are re-encoded in BCD.
//! A count of zero means 65536 in binary mode and 10000 in BCD mode.

/// Base I/O port of the PIT.
pub const BASE_PORT: u16 = 0x40;
/// Number of I/O ports exposed by the PIT (three data ports + command).
pub const PORT_COUNT: u16 = 4;
/// ISA IRQ line driven by channel 0 output.
pub const IRQ_LINE: u8 = 0;
/// Nominal PIT input frequency, in Hz (1.193182 MHz).
pub const FREQUENCY_HZ: u32 = 1_193_182;

/// Number of independent channels.
const CHANNELS: usize = 3;
/// Maximum binary count (0 programs 65536).
const MAX_BINARY_COUNT: u32 = 65_536;
/// Maximum BCD count (0 programs 10000).
const MAX_BCD_COUNT: u32 = 10_000;

/// Returns `true` when `port` belongs to the PIT.
pub fn handles_port(port: u16) -> bool {
    port >= BASE_PORT && port < BASE_PORT + PORT_COUNT
}

/// Access mode programmed in bits 5:4 of the command register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Access {
    /// Latch command (bits 5:4 = 00): capture the current count.
    Latch,
    /// Low byte only.
    LoByte,
    /// High byte only.
    HiByte,
    /// Low byte, then high byte.
    LoHi,
}

impl Access {
    /// Decodes bits 5:4 of the command register.
    const fn from_bits(bits: u8) -> Self {
        match bits & 0x3 {
            0 => Self::Latch,
            1 => Self::LoByte,
            2 => Self::HiByte,
            _ => Self::LoHi,
        }
    }
}

/// Counting mode programmed in bits 3:1 of the command register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Mode 0: interrupt on terminal count (one shot).
    Zero,
    /// Mode 1: hardware-triggered one shot.
    One,
    /// Mode 2: rate generator (periodic).
    Two,
    /// Mode 3: square wave (periodic).
    Three,
    /// Mode 4: software-triggered strobe (one shot).
    Four,
    /// Mode 5: hardware-triggered strobe (one shot).
    Five,
}

impl Mode {
    /// Decodes bits 3:1 of the command register.
    ///
    /// Modes 6 and 7 are aliases of modes 2 and 3 on real hardware.
    const fn from_bits(bits: u8) -> Self {
        match bits & 0x7 {
            0 => Self::Zero,
            1 => Self::One,
            2 => Self::Two,
            3 => Self::Three,
            4 => Self::Four,
            5 => Self::Five,
            6 => Self::Two,
            _ => Self::Three,
        }
    }

    /// `true` when the mode reloads and fires periodically.
    const fn is_periodic(self) -> bool {
        matches!(self, Self::Two | Self::Three)
    }
}

/// Architectural state of one PIT channel.
#[derive(Debug, Clone, Copy)]
struct Channel {
    /// Access mode of the last count programming.
    access: Access,
    /// Counting mode.
    mode: Mode,
    /// BCD count mode.
    bcd: bool,
    /// A count has been programmed: the channel is running or stopped.
    programmed: bool,
    /// Reload value in binary (1..=65536).
    reload: u32,
    /// Current down-counter in binary (0 when a one-shot has expired).
    count: u32,
    /// `false` after a one-shot expired; periodic channels stay `true`.
    running: bool,
    /// First byte of a two-byte count write.
    write_low: u8,
    /// `true` when the next data write is the high byte.
    write_high: bool,
    /// `true` when the next read is the high byte (access 3).
    read_high: bool,
    /// Count captured by a latch command, if any.
    latched: Option<u16>,
    /// `true` when the next latched read is the high byte.
    latch_high: bool,
}

impl Channel {
    /// Empty channel: unprogrammed, no output.
    const fn new() -> Self {
        Self {
            access: Access::LoHi,
            mode: Mode::Three,
            bcd: false,
            programmed: false,
            reload: 0,
            count: 0,
            running: false,
            write_low: 0,
            write_high: false,
            read_high: false,
            latched: None,
            latch_high: false,
        }
    }

    /// Captures the current count for a later latch read.
    fn latch(&mut self) {
        self.latched = Some(encode_count(self.count, self.bcd));
        self.latch_high = false;
    }

    /// Programs a complete count from the raw bytes and starts the channel.
    fn program(&mut self, raw: u16) {
        let Some(value) = decode_count(raw, self.bcd) else {
            // Invalid BCD digits: reject the programming safely.
            self.write_high = false;
            self.write_low = 0;
            return;
        };
        self.reload = value;
        self.count = value;
        self.programmed = true;
        self.running = true;
        self.write_high = false;
        self.write_low = 0;
        self.read_high = false;
        self.latched = None;
        self.latch_high = false;
    }

    /// Next byte of the current count, according to the access mode.
    fn read_current(&mut self) -> u8 {
        if let Some(raw) = self.latched {
            let byte = match self.access {
                Access::Latch | Access::LoByte => raw as u8,
                Access::HiByte => (raw >> 8) as u8,
                Access::LoHi => {
                    let byte = if self.latch_high {
                        (raw >> 8) as u8
                    } else {
                        raw as u8
                    };
                    self.latch_high = !self.latch_high;
                    if !self.latch_high {
                        self.latched = None;
                    }
                    return byte;
                }
            };
            self.latched = None;
            return byte;
        }
        if !self.programmed {
            return 0;
        }
        let raw = encode_count(self.count, self.bcd);
        match self.access {
            Access::Latch | Access::LoByte => raw as u8,
            Access::HiByte => (raw >> 8) as u8,
            Access::LoHi => {
                let byte = if self.read_high {
                    (raw >> 8) as u8
                } else {
                    raw as u8
                };
                self.read_high = !self.read_high;
                byte
            }
        }
    }

    /// Handles one data-port write according to the access mode.
    fn write_data(&mut self, value: u8) {
        match self.access {
            Access::Latch => {
                // The command register is write-only: no data write is
                // accepted in latch mode.
            }
            Access::LoByte => self.program(value as u16),
            Access::HiByte => self.program((value as u16) << 8),
            Access::LoHi => {
                if self.write_high {
                    let raw = (self.write_low as u16) | ((value as u16) << 8);
                    self.program(raw);
                } else {
                    self.write_low = value;
                    self.write_high = true;
                }
            }
        }
    }
}

/// Model of the 8254/8253 programmable interval timer.
#[derive(Debug, Clone, Copy)]
pub struct Pit {
    channels: [Channel; CHANNELS],
    /// IRQ0 pulse raised by the last [`Pit::advance`] call.
    irq: bool,
}

impl Pit {
    /// Creates an unprogrammed PIT: every channel reads 0 and never fires.
    pub fn new() -> Self {
        Self {
            channels: [Channel::new(); CHANNELS],
            irq: false,
        }
    }

    /// Reads one PIT register. `offset` is `port - BASE_PORT`.
    ///
    /// Offsets 0..2 read a channel data port (latched count when a latch
    /// command was issued, current counter otherwise); offset 3 is the
    /// write-only command register and reads 0.
    pub fn read(&mut self, offset: u32) -> u8 {
        match offset {
            0..=2 => self.channels[offset as usize].read_current(),
            _ => 0,
        }
    }

    /// Writes one PIT register. `offset` is `port - BASE_PORT`.
    ///
    /// Offsets 0..2 write a channel count (two-phase access state machine);
    /// offset 3 writes the mode/command register, including the latch command
    /// and the read-back command.
    pub fn write(&mut self, offset: u32, value: u8) {
        match offset {
            0..=2 => self.channels[offset as usize].write_data(value),
            3 => self.write_command(value),
            _ => {}
        }
    }

    /// Decodes and applies one mode/command register write.
    fn write_command(&mut self, value: u8) {
        let channel = value >> 6;
        let access = Access::from_bits((value >> 4) & 0x3);

        if channel == 3 {
            // Read-back command: bits 3:1 select channels, bit 5 latches the
            // count and bit 4 latches the status. Status latching is not
            // modeled (it carries no timing state), count latching is.
            let select = (value >> 1) & 0x7;
            let latch_count = value & 0x20 != 0;
            if latch_count {
                for (index, chan) in self.channels.iter_mut().enumerate() {
                    if select & (1 << index) != 0 {
                        chan.latch();
                    }
                }
            }
            return;
        }

        let chan = &mut self.channels[channel as usize];
        if access == Access::Latch {
            // Latch command: capture the count, keep mode/BCD unchanged.
            chan.latch();
            return;
        }
        chan.access = access;
        chan.mode = Mode::from_bits((value >> 1) & 0x7);
        chan.bcd = value & 0x1 != 0;
        // A new count is expected: the channel is unprogrammed until the
        // access-mode write sequence completes.
        chan.programmed = false;
        chan.running = false;
        chan.latched = None;
        chan.write_high = false;
        chan.write_low = 0;
        chan.read_high = false;
        chan.latch_high = false;
    }

    /// Advances every running channel by `bus_ticks` PIT input ticks.
    ///
    /// Returns `true` when channel 0 raised IRQ0 during the call; in periodic
    /// modes a pulse is produced at every period expiry. [`Pit::irq_level`]
    /// keeps the pulse visible until the next call.
    pub fn advance(&mut self, bus_ticks: u64) -> bool {
        self.irq = false;
        for (index, chan) in self.channels.iter_mut().enumerate() {
            if !chan.programmed || !chan.running || chan.count == 0 {
                continue;
            }
            let fired = chan.advance(bus_ticks);
            if index == 0 && fired != 0 {
                self.irq = true;
            }
        }
        self.irq
    }

    /// IRQ0 level: `true` while a pulse from the last [`Pit::advance`] call is
    /// pending. The level drops at the next `advance`.
    pub fn irq_level(&self) -> bool {
        self.irq
    }
}

impl Default for Pit {
    fn default() -> Self {
        Self::new()
    }
}

impl Channel {
    /// Runs the down-counter; returns the number of expiries during `ticks`.
    fn advance(&mut self, ticks: u64) -> u64 {
        if self.mode.is_periodic() {
            let period = self.reload as u64;
            if period == 0 {
                return 0;
            }
            let mut remaining = ticks;
            let mut fired = 0u64;
            loop {
                if remaining < self.count as u64 {
                    self.count -= remaining as u32;
                    break;
                }
                remaining -= self.count as u64;
                fired += 1;
                self.count = self.reload;
                // Do not consume the reload tick twice when the call ends
                // exactly on a period boundary.
                if remaining == 0 {
                    break;
                }
            }
            fired
        } else {
            // One-shot modes (0, 1, 4, 5): a terminal count stops the channel.
            if ticks < self.count as u64 {
                self.count -= ticks as u32;
                0
            } else {
                self.count = 0;
                self.running = false;
                1
            }
        }
    }
}

/// Decodes a raw count into a binary 1..=65536 value.
///
/// Returns `None` for invalid BCD digits, so the caller can reject the
/// programming instead of running a nonsensical period.
fn decode_count(raw: u16, bcd: bool) -> Option<u32> {
    if !bcd {
        let value = raw as u32;
        return Some(if value == 0 { MAX_BINARY_COUNT } else { value });
    }
    let digits = [
        (raw & 0xF) as u32,
        ((raw >> 4) & 0xF) as u32,
        ((raw >> 8) & 0xF) as u32,
        ((raw >> 12) & 0xF) as u32,
    ];
    if digits.iter().any(|digit| *digit > 9) {
        return None;
    }
    let value = digits[0] + digits[1] * 10 + digits[2] * 100 + digits[3] * 1000;
    Some(if value == 0 { MAX_BCD_COUNT } else { value })
}

/// Encodes a binary count (1..=65536) into the raw bytes read back.
fn encode_count(value: u32, bcd: bool) -> u16 {
    if !bcd {
        return (value & 0xFFFF) as u16;
    }
    let decimal = value % MAX_BCD_COUNT;
    let d0 = decimal % 10;
    let d1 = (decimal / 10) % 10;
    let d2 = (decimal / 100) % 10;
    let d3 = (decimal / 1000) % 10;
    ((d3 << 12) | (d2 << 8) | (d1 << 4) | d0) as u16
}
