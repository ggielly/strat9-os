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

//! 82077AA-compatible floppy disk controller and 1.44 MiB drive model.
//!
//! The s9vm stub firmware services `INT 13h` from the host, so a guest never
//! talks to the controller. A **real firmware** (SeaBIOS) implements `INT 13h`
//! in its own 16-bit code and drives the FDC directly: DOR reset, command and
//! parameter bytes through the FIFO, an IRQ 6 completion, and a DMA transfer
//! through channel 2. This module models that command-level interface.
//!
//! # Modelled command set
//!
//! Only the commands SeaBIOS issues are implemented: `SPECIFY`,
//! `RECALIBRATE`, `SENSE INTERRUPT`, `SEEK`, `READ ID`, `READ DATA`, `WRITE
//! DATA` and `FORMAT TRACK` (accepted, but formatting a read-only test image
//! does not mutate it). Unknown commands complete immediately with the invalid
//! opcode status `0x80`, so a probe cannot hang.
//!
//! # DMA
//!
//! The controller does not touch memory. [`FloppyController::write`] returns an
//! [`FdcEvent`]; a transfer event names the starting LBA and sector count, and
//! the caller performs the channel-2 DMA through its own physical-memory view.
//! The controller already queued the seven result bytes and raised its IRQ
//! flag, so the completion is visible to the guest as soon as the transfer is
//! done.
//!
//! # Geometry
//!
//! The image is a standard 80 x 2 x 18 x 512 floppy: 1 474 560 bytes and 2 880
//! sectors. A CHS access outside that geometry returns a "sector not found"
//! result instead of wrapping.

/// Size of one floppy sector.
pub const SECTOR_SIZE: usize = 512;

use alloc::{vec, vec::Vec};

/// Base of the floppy controller register window.
pub const BASE_PORT: u16 = 0x3F0;
/// Digital output register (motor, DMA/IRQ enable, reset, drive select).
pub const DOR_PORT: u16 = 0x3F2;
/// Main status register (read-only).
pub const MSR_PORT: u16 = 0x3F4;
/// FIFO data register (command, parameters and results).
pub const DATA_PORT: u16 = 0x3F5;
/// Configuration control register / digital input register.
pub const DIR_PORT: u16 = 0x3F7;
/// ISA interrupt line of the controller.
pub const IRQ_LINE: u8 = 6;

/// DOR bit 2: controller reset (0 = held in reset).
pub const DOR_RESET: u8 = 0x04;
/// DOR bit 3: DMA and interrupt enable.
pub const DOR_IRQ_DMA: u8 = 0x08;
/// Main status register: ready for a byte.
pub const MSR_RQM: u8 = 0x80;
/// Main status register: data direction (1 = controller to host).
pub const MSR_DIO: u8 = 0x40;

/// `SPECIFY`: 2 parameter bytes.
pub const CMD_SPECIFY: u8 = 0x03;
/// `RECALIBRATE`: 1 parameter byte.
pub const CMD_RECALIBRATE: u8 = 0x07;
/// `SENSE INTERRUPT STATUS`: no parameter, 2 result bytes.
pub const CMD_SENSE_INTERRUPT: u8 = 0x08;
/// `SEEK`: 2 parameter bytes.
pub const CMD_SEEK: u8 = 0x0F;
/// `READ ID`: 1 parameter, 7 result bytes.
pub const CMD_READ_ID: u8 = 0x4A;
/// `FORMAT TRACK`: 5 parameter bytes.
pub const CMD_FORMAT_TRACK: u8 = 0x4D;
/// `WRITE DATA`: 8 parameter bytes.
pub const CMD_WRITE_DATA: u8 = 0xC5;
/// `READ DATA`: 8 parameter bytes.
pub const CMD_READ_DATA: u8 = 0xE6;

/// Floppy geometry: cylinders.
pub const CYLINDERS: u8 = 80;
/// Floppy geometry: heads.
pub const HEADS: u8 = 2;
/// Floppy geometry: sectors per track.
pub const SECTORS_PER_TRACK: u8 = 18;
/// Total sectors of a 1.44 MiB image.
pub const TOTAL_SECTORS: u64 = 2880;
/// Data-transfer size code for 512-byte sectors.
pub const SIZE_CODE_512: u8 = 2;

/// A DMA transfer requested by a completed read or write command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FdcTransfer {
    /// True for a guest-to-controller (write) transfer.
    pub write: bool,
    /// First linear block address.
    pub lba: u64,
    /// Number of 512-byte sectors.
    pub sectors: u16,
}

/// Outcome of a port write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdcEvent {
    /// Nothing observable happened.
    None,
    /// A command completed and raised IRQ 6.
    Irq,
    /// A command completed, raised IRQ 6 and needs a DMA transfer.
    Transfer(FdcTransfer),
}

/// True if `port` belongs to the controller window.
pub const fn handles_port(port: u16) -> bool {
    matches!(port, BASE_PORT..=DATA_PORT | DIR_PORT)
}

/// State of the modelled controller and drive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FloppyController {
    /// Image bytes (empty when no disk is present).
    image: Vec<u8>,
    /// Digital output register.
    dor: u8,
    /// Current cylinder of the selected drive.
    cylinder: u8,
    /// Command and parameter collection.
    command: u8,
    params: [u8; 8],
    needed: u8,
    received: u8,
    /// Result FIFO.
    result: [u8; 8],
    result_len: u8,
    result_pos: u8,
    /// Pending IRQ 6.
    irq: bool,
    /// Data rate programmed through the DIR port.
    data_rate: u8,
    /// Last requested transfer (diagnostics).
    last_transfer: Option<FdcTransfer>,
}

impl FloppyController {
    /// Creates a controller with no media.
    pub const fn new() -> Self {
        Self {
            image: Vec::new(),
            dor: 0,
            cylinder: 0,
            command: 0,
            params: [0; 8],
            needed: 0,
            received: 0,
            result: [0; 8],
            result_len: 0,
            result_pos: 0,
            irq: false,
            data_rate: 0,
            last_transfer: None,
        }
    }

    /// Installs the floppy image. The image is copied: the controller owns it.
    pub fn load_image(&mut self, image: &[u8]) {
        self.image = image.to_vec();
        self.reset();
    }

    /// True when no image is loaded.
    pub fn is_empty(&self) -> bool {
        self.image.is_empty()
    }

    /// Capacity of the loaded image, in 512-byte sectors.
    pub fn sectors(&self) -> u64 {
        (self.image.len() / SECTOR_SIZE) as u64
    }

    /// True if `port` belongs to the controller window.
    pub const fn handles_port(port: u16) -> bool {
        matches!(port, BASE_PORT..=DATA_PORT | DIR_PORT)
    }

    /// Current main status register.
    pub fn status(&self) -> u8 {
        let mut status = MSR_RQM | (self.dor & 0x03);
        if self.result_pos < self.result_len {
            status |= MSR_DIO;
        }
        status
    }

    /// Reads one controller port.
    pub fn read(&mut self, port: u16) -> Option<u8> {
        match port {
            0x3F0 | 0x3F1 | 0x3F3 => Some(0xFF),
            DOR_PORT => Some(self.dor),
            MSR_PORT => Some(self.status()),
            DATA_PORT => {
                if self.result_pos < self.result_len {
                    let value = self.result[self.result_pos as usize];
                    self.result_pos += 1;
                    Some(value)
                } else {
                    Some(0)
                }
            }
            DIR_PORT => Some(if self.image.is_empty() { 0x00 } else { 0x80 }),
            _ => None,
        }
    }

    /// Writes one controller port.
    pub fn write(&mut self, port: u16, value: u8) -> FdcEvent {
        match port {
            DOR_PORT => self.write_dor(value),
            DATA_PORT => self.push_byte(value),
            DIR_PORT => {
                self.data_rate = value & 0x03;
                FdcEvent::None
            }
            // The FDC has no writable register at 0x3F0/0x3F1/0x3F3; the
            // write is accepted and discarded so a probe cannot spin.
            _ => FdcEvent::None,
        }
    }

    /// Takes the pending IRQ-6 request.
    pub fn take_irq(&mut self) -> bool {
        let pending = self.irq;
        self.irq = false;
        pending
    }

    /// Last transfer requested by the controller.
    pub const fn last_transfer(&self) -> Option<FdcTransfer> {
        self.last_transfer
    }

    /// Reads one sector into `out`. Returns false for an out-of-range LBA.
    pub fn read_sector(&self, lba: u64, out: &mut [u8; SECTOR_SIZE]) -> bool {
        let Some(start) = (lba as usize).checked_mul(SECTOR_SIZE) else {
            return false;
        };
        let Some(end) = start.checked_add(SECTOR_SIZE) else {
            return false;
        };
        let Some(bytes) = self.image.get(start..end) else {
            return false;
        };
        out.copy_from_slice(bytes);
        true
    }

    /// Writes one sector. Returns false for an out-of-range LBA.
    pub fn write_sector(&mut self, lba: u64, bytes: &[u8; SECTOR_SIZE]) -> bool {
        let Some(start) = (lba as usize).checked_mul(SECTOR_SIZE) else {
            return false;
        };
        let Some(end) = start.checked_add(SECTOR_SIZE) else {
            return false;
        };
        let Some(slot) = self.image.get_mut(start..end) else {
            return false;
        };
        slot.copy_from_slice(bytes);
        true
    }

    /// Clears the command and result state (not the media).
    fn reset(&mut self) {
        self.cylinder = 0;
        self.command = 0;
        self.needed = 0;
        self.received = 0;
        self.result_len = 0;
        self.result_pos = 0;
        self.last_transfer = None;
        self.irq = false;
    }

    /// Handles a DOR write, including the reset transition.
    fn write_dor(&mut self, value: u8) -> FdcEvent {
        let was_reset = self.dor & DOR_RESET == 0;
        self.dor = value;
        if value & DOR_RESET == 0 {
            self.reset();
            return FdcEvent::None;
        }
        if was_reset {
            // Releasing reset completes controller initialisation: the real
            // chip raises IRQ 6 once, and SeaBIOS waits for it before sending
            // the four SENSE INTERRUPT polls.
            self.reset();
            self.irq = true;
            return FdcEvent::Irq;
        }
        FdcEvent::None
    }

    /// Consumes one FIFO byte: the command byte first, then its parameters.
    fn push_byte(&mut self, value: u8) -> FdcEvent {
        // A new command is accepted only when no result is waiting and no
        // parameter is outstanding: the guest always drains results first.
        if self.needed == 0 && self.received == 0 && self.result_pos >= self.result_len {
            self.command = value;
            self.needed = parameter_count(value);
            self.received = 0;
            self.result_len = 0;
            self.result_pos = 0;
            if self.needed == 0 {
                return self.execute();
            }
            return FdcEvent::None;
        }
        if self.received < self.needed && (self.received as usize) < self.params.len() {
            self.params[self.received as usize] = value;
            self.received += 1;
            if self.received == self.needed {
                return self.execute();
            }
        }
        FdcEvent::None
    }

    /// Runs the collected command and queues its results.
    fn execute(&mut self) -> FdcEvent {
        let command = self.command;
        let params = self.params;
        self.command = 0;
        self.needed = 0;
        self.received = 0;
        self.result_len = 0;
        self.result_pos = 0;
        let mut event = FdcEvent::None;

        match command {
            CMD_SPECIFY => {}
            CMD_SENSE_INTERRUPT => {
                self.queue(&[0x20, self.cylinder]);
            }
            CMD_RECALIBRATE => {
                self.cylinder = 0;
                self.irq = true;
                event = FdcEvent::Irq;
            }
            CMD_SEEK => {
                self.cylinder = params[1];
                self.irq = true;
                event = FdcEvent::Irq;
            }
            CMD_READ_ID => {
                let head = (params[0] >> 2) & 0x01;
                let drive = params[0] & 0x03;
                self.queue(&[
                    0x20 | (head << 2) | drive,
                    0,
                    0,
                    self.cylinder,
                    head,
                    1,
                    SIZE_CODE_512,
                ]);
                self.irq = true;
                event = FdcEvent::Irq;
            }
            CMD_READ_DATA | CMD_WRITE_DATA => {
                let transfer = self.data_transfer(command, &params);
                match transfer {
                    Some((request, result)) => {
                        self.queue(&result);
                        self.last_transfer = Some(request);
                        self.irq = true;
                        event = FdcEvent::Transfer(request);
                    }
                    None => {
                        // ST0 = abnormal termination, ST1 = no data / no
                        // address mark: reported as a normal command failure.
                        self.queue(&[0x40, 0x04, 0x00, params[1], params[2], params[3], 2]);
                        self.irq = true;
                        event = FdcEvent::Irq;
                    }
                }
            }
            CMD_FORMAT_TRACK => {
                self.queue(&[
                    0x20 | (params[0] & 0x07),
                    0,
                    0,
                    self.cylinder,
                    (params[0] >> 2) & 1,
                    params[2],
                    SIZE_CODE_512,
                ]);
                self.irq = true;
                event = FdcEvent::Irq;
            }
            _ => {
                // Invalid opcode: status 0x80, no transfer.
                self.queue(&[0x80]);
                self.irq = true;
                event = FdcEvent::Irq;
            }
        }
        event
    }

    /// Decodes a READ/WRITE parameter block into a transfer and result bytes.
    fn data_transfer(&self, command: u8, params: &[u8; 8]) -> Option<(FdcTransfer, [u8; 7])> {
        let drive = params[0] & 0x03;
        let head = params[2] & (HEADS - 1);
        let cylinder = params[1];
        let sector = params[3];
        let eot = params[5];
        if cylinder >= CYLINDERS
            || sector == 0
            || sector > SECTORS_PER_TRACK
            || eot < sector
            || eot > SECTORS_PER_TRACK
        {
            return None;
        }
        let count = u16::from(eot - sector + 1);
        let lba = u64::from(cylinder) * u64::from(HEADS) * u64::from(SECTORS_PER_TRACK)
            + u64::from(head) * u64::from(SECTORS_PER_TRACK)
            + u64::from(sector - 1);
        if lba + u64::from(count) > self.sectors() {
            return None;
        }
        let transfer = FdcTransfer {
            write: command == CMD_WRITE_DATA,
            lba,
            sectors: count,
        };
        let result = [
            0x20 | (head << 2) | drive,
            0,
            0,
            cylinder,
            head,
            sector,
            SIZE_CODE_512,
        ];
        Some((transfer, result))
    }

    /// Appends bytes to the result FIFO.
    fn queue(&mut self, bytes: &[u8]) {
        self.result_len = bytes.len().min(self.result.len()) as u8;
        self.result[..self.result_len as usize].copy_from_slice(&bytes[..self.result_len as usize]);
        self.result_pos = 0;
    }
}

impl Default for FloppyController {
    fn default() -> Self {
        Self::new()
    }
}

/// Number of parameter bytes that follow `command`.
pub const fn parameter_count(command: u8) -> u8 {
    match command {
        CMD_SPECIFY => 2,
        CMD_RECALIBRATE => 1,
        CMD_SENSE_INTERRUPT => 0,
        CMD_SEEK => 2,
        CMD_READ_ID => 1,
        CMD_FORMAT_TRACK => 5,
        CMD_WRITE_DATA | CMD_READ_DATA => 8,
        _ => 0,
    }
}

/// Builds a deterministic, zero-filled 1.44 MiB floppy image.
///
/// Host-test helper; the kernel embeds the FreeDOS image instead.
pub fn blank_image() -> Vec<u8> {
    vec![0u8; TOTAL_SECTORS as usize * SECTOR_SIZE]
}
