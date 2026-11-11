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

//! s9vm — 16550A-compatible UART device (pure model, COM1).
//!
//! The guest sees the eight-byte register window of a COM1 16550A at
//! [`BASE_PORT`]. The kernel bridges the model onto the host: bytes written to
//! the transmit holding register are collected by [`Uart::drain_output`] (the
//! kernel logs them), and host input is queued with [`Uart::push_input`] for
//! the guest to read from the receive buffer. [`Uart::irq_asserted`] drives the
//! UART interrupt line [`IRQ_LINE`].
//!
//! The model implements the register semantics a booting guest relies on:
//! divisor latch access through `LCR.DLAB`, the IIR priority chain (line
//! status, receive data, transmitter empty, modem status), IER masking,
//! loopback mode through `MCR`, scratch register and the LSR/MSR status bits.
//! It is transport-agnostic and host-tested; the only extra dependency is the
//! `alloc` vector holding output and input bytes.

use alloc::{collections::VecDeque, vec::Vec};

/// Base I/O port of COM1.
pub const BASE_PORT: u16 = 0x3F8;
/// Number of consecutive I/O ports used by the UART.
pub const PORT_COUNT: u16 = 8;
/// IRQ line driven by the COM1 UART.
pub const IRQ_LINE: u8 = 4;
/// Receive FIFO capacity (bytes pushed by the kernel but not yet read).
pub const INPUT_CAPACITY: usize = 16;

/// Register offsets, relative to [`BASE_PORT`].
///
/// Offsets 0 and 1 are banked: when `LCR.DLAB` is set they address the divisor
/// latch low/high bytes (DLL/DLM) instead of RBR/THR and IER.
pub mod reg {
    /// Receive buffer (read) / transmit holding register (write).
    pub const RBR_THR: u32 = 0;
    /// Interrupt enable register (write), or DLM when `LCR.DLAB` is set.
    pub const IER: u32 = 1;
    /// Interrupt identification (read) / FIFO control (write).
    pub const IIR_FCR: u32 = 2;
    /// Line control register (`DLAB` is bit 7).
    pub const LCR: u32 = 3;
    /// Modem control register (`LOOPBACK` is bit 4).
    pub const MCR: u32 = 4;
    /// Line status register (read-only).
    pub const LSR: u32 = 5;
    /// Modem status register (read-only, delta bits clear on read).
    pub const MSR: u32 = 6;
    /// Scratch register (plain read/write byte).
    pub const SCR: u32 = 7;
}

/// Interrupt enable bits in [`reg::IER`].
pub mod ier {
    /// Received data available.
    pub const RX_DATA: u8 = 1 << 0;
    /// Transmitter holding register empty.
    pub const THR_EMPTY: u8 = 1 << 1;
    /// Receiver line status (overrun, parity, framing, break).
    pub const LINE_STATUS: u8 = 1 << 2;
    /// Modem status change.
    pub const MODEM_STATUS: u8 = 1 << 3;
}

/// Interrupt identification values returned by [`reg::IIR_FCR`] reads.
pub mod iir {
    /// No interrupt pending.
    pub const NONE: u8 = 0x01;
    /// Transmitter holding register empty (priority 3).
    pub const THR_EMPTY: u8 = 0x02;
    /// Received data available (priority 2).
    pub const RX_DATA: u8 = 0x04;
    /// Receiver line status (priority 1, highest).
    pub const LINE_STATUS: u8 = 0x06;
    /// Modem status change (priority 4, lowest).
    pub const MODEM_STATUS: u8 = 0x0C;
}

/// Bits of the line status register.
pub mod lsr {
    /// Data ready: the receive FIFO is not empty.
    pub const DATA_READY: u8 = 1 << 0;
    /// Transmitter holding register empty.
    pub const THR_EMPTY: u8 = 1 << 5;
    /// Transmitter empty (shift register also empty).
    pub const TRANSMITTER_EMPTY: u8 = 1 << 6;
    /// Break indicator (set while `LCR` bit 6 forces a break).
    pub const BREAK: u8 = 1 << 4;
}

/// Bits of the modem control register.
pub mod mcr {
    /// Data terminal ready.
    pub const DTR: u8 = 1 << 0;
    /// Request to send.
    pub const RTS: u8 = 1 << 1;
    /// Auxiliary output 1.
    pub const OUT1: u8 = 1 << 2;
    /// Auxiliary output 2.
    pub const OUT2: u8 = 1 << 3;
    /// Loopback mode: transmitted bytes feed the receive FIFO.
    pub const LOOPBACK: u8 = 1 << 4;
}

/// Bits of the modem status register.
pub mod msr {
    /// Delta clear to send.
    pub const DELTA_CTS: u8 = 1 << 0;
    /// Delta data set ready.
    pub const DELTA_DSR: u8 = 1 << 1;
    /// Trailing edge ring indicator.
    pub const DELTA_RI: u8 = 1 << 2;
    /// Delta data carrier detect.
    pub const DELTA_DCD: u8 = 1 << 3;
    /// Clear to send.
    pub const CTS: u8 = 1 << 4;
    /// Data set ready.
    pub const DSR: u8 = 1 << 5;
    /// Ring indicator.
    pub const RI: u8 = 1 << 6;
    /// Data carrier detect.
    pub const DCD: u8 = 1 << 7;
}

/// Value of [`reg::LSR`] at reset: transmitter holding register empty and
/// transmitter empty. The data-ready bit depends on the receive FIFO.
const LSR_IDLE: u8 = lsr::THR_EMPTY | lsr::TRANSMITTER_EMPTY;
/// Value of [`reg::MSR`] at reset: CTS, DSR and DCD asserted (the host is
/// considered connected), no delta bit pending.
const MSR_IDLE: u8 = msr::CTS | msr::DSR | msr::DCD;

/// True when `port` belongs to the COM1 register window.
pub const fn handles_port(port: u16) -> bool {
    port >= BASE_PORT && port < BASE_PORT + PORT_COUNT
}

/// Software model of the COM1 16550A UART.
#[derive(Debug)]
pub struct Uart {
    /// Interrupt enable register (bits 0..3 defined).
    ier: u8,
    /// Line control register; bit 7 is `DLAB`.
    lcr: u8,
    /// Modem control register; bit 4 is loopback.
    mcr: u8,
    /// Modem status register (input bits 4..7, delta bits 0..3).
    msr: u8,
    /// FIFO control register (write-only on hardware; kept for diagnostics).
    #[allow(dead_code)]
    fcr: u8,
    /// Scratch register.
    scr: u8,
    /// Divisor latch low byte (DLAB mode).
    dll: u8,
    /// Divisor latch high byte (DLAB mode).
    dlm: u8,
    /// Bytes the guest transmitted, waiting for the host to drain them.
    output: Vec<u8>,
    /// Bytes the host queued for the guest to receive.
    input: VecDeque<u8>,
    /// A "transmitter empty" interrupt source is pending.
    ///
    /// It is raised by a THR write and cleared by an IIR read, matching the
    /// 16550 behaviour where reading IIR acknowledges the THRE interrupt.
    thre_pending: bool,
}

impl Uart {
    /// Creates a UART in its reset state (IIR none, LSR idle, MSR idle).
    pub const fn new() -> Self {
        Self {
            ier: 0,
            lcr: 0,
            mcr: 0,
            msr: MSR_IDLE,
            fcr: 0,
            scr: 0,
            dll: 0,
            dlm: 0,
            output: Vec::new(),
            input: VecDeque::new(),
            thre_pending: false,
        }
    }

    /// True when `LCR.DLAB` selects the divisor latch at offsets 0 and 1.
    const fn dlab(&self) -> bool {
        self.lcr & 0x80 != 0
    }

    /// Current line status register value.
    fn line_status(&self) -> u8 {
        let mut value = LSR_IDLE;
        if !self.input.is_empty() {
            value |= lsr::DATA_READY;
        }
        if self.lcr & 0x40 != 0 {
            // LCR.SET_BREAK forces a break, reported through LSR.BI and through
            // the highest-priority line-status interrupt source.
            value |= lsr::BREAK;
        }
        value
    }

    /// Highest-priority pending interrupt source, considering IER masks.
    fn pending_source(&self) -> Option<u8> {
        if self.ier & ier::LINE_STATUS != 0 && self.line_status() & 0x1E != 0 {
            return Some(iir::LINE_STATUS);
        }
        if self.ier & ier::RX_DATA != 0 && !self.input.is_empty() {
            return Some(iir::RX_DATA);
        }
        if self.ier & ier::THR_EMPTY != 0 && self.thre_pending {
            return Some(iir::THR_EMPTY);
        }
        if self.ier & ier::MODEM_STATUS != 0 && self.msr & 0x0F != 0 {
            return Some(iir::MODEM_STATUS);
        }
        None
    }

    /// True when an unmasked interrupt source is pending (drives [`IRQ_LINE`]).
    pub fn irq_asserted(&self) -> bool {
        self.pending_source().is_some()
    }

    /// Reads one register of the window.
    ///
    /// Reading IIR acknowledges the transmitter-empty interrupt; reading RBR
    /// pops one received byte; reading MSR clears the modem delta bits. Reads
    /// of unknown offsets return 0.
    pub fn read(&mut self, offset: u32) -> u8 {
        match offset {
            reg::RBR_THR => {
                if self.dlab() {
                    self.dll
                } else {
                    // A read of an empty receive buffer returns 0 and leaves
                    // the data-ready bit clear.
                    self.input.pop_front().unwrap_or(0)
                }
            }
            reg::IER => {
                if self.dlab() {
                    self.dlm
                } else {
                    self.ier
                }
            }
            reg::IIR_FCR => {
                let pending = self.pending_source().unwrap_or(iir::NONE);
                // Reading IIR acknowledges the THRE source (16550 semantics);
                // the other sources are cleared by their own register access.
                self.thre_pending = false;
                pending
            }
            reg::LCR => self.lcr,
            reg::MCR => self.mcr,
            reg::LSR => self.line_status(),
            reg::MSR => {
                let value = self.msr;
                // Delta bits are cleared by reading MSR.
                self.msr &= 0xF0;
                value
            }
            reg::SCR => self.scr,
            _ => 0,
        }
    }

    /// Writes one register of the window.
    ///
    /// Writes of read-only registers (LSR/MSR) and unknown offsets are
    /// ignored.
    pub fn write(&mut self, offset: u32, value: u8) {
        match offset {
            reg::RBR_THR => {
                if self.dlab() {
                    self.dll = value;
                } else {
                    // Transmitter always accepts the byte (the model has no
                    // baud-rate timing): publishing it sets THRE/TEMT and
                    // raises the transmitter-empty source.
                    self.thre_pending = true;
                    if self.mcr & mcr::LOOPBACK != 0 {
                        self.push_loopback(value);
                    } else {
                        self.output.push(value);
                    }
                }
            }
            reg::IER => {
                if self.dlab() {
                    self.dlm = value;
                } else {
                    self.ier = value & 0x0F;
                }
            }
            reg::IIR_FCR => {
                self.fcr = value;
                // FCR bit 1 clears the receive FIFO; bit 2 would clear the
                // transmit FIFO, but bytes already published to the host are
                // kept (the host log is not a transmit FIFO).
                if value & 0x02 != 0 {
                    self.input.clear();
                }
            }
            reg::LCR => self.lcr = value,
            reg::MCR => {
                self.mcr = value & 0x1F;
                self.update_modem_inputs();
            }
            reg::LSR | reg::MSR => {}
            reg::SCR => self.scr = value,
            _ => {}
        }
    }

    /// Queues bytes for the guest receive FIFO.
    ///
    /// Returns the number of bytes accepted; bytes beyond [`INPUT_CAPACITY`]
    /// are dropped (the hardware FIFO would overrun).
    pub fn push_input(&mut self, bytes: &[u8]) -> usize {
        let mut accepted = 0;
        for byte in bytes {
            if self.input.len() >= INPUT_CAPACITY {
                break;
            }
            self.input.push_back(*byte);
            accepted += 1;
        }
        accepted
    }

    /// Takes the bytes the guest has transmitted since the previous drain.
    pub fn drain_output(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.output)
    }

    /// Loopback: the transmitted byte is delivered to the receive FIFO.
    fn push_loopback(&mut self, value: u8) {
        if self.input.len() < INPUT_CAPACITY {
            self.input.push_back(value);
        }
    }

    /// Recomputes the modem-status inputs and latches the delta bits.
    ///
    /// In loopback mode `MCR` drives the modem inputs (`RTS`→`CTS`,
    /// `DTR`→`DSR`, `OUT1`→`RI`, `OUT2`→`DCD`); otherwise the host is
    /// modelled as connected ([`MSR_IDLE`]). A changed input sets the matching
    /// delta bit.
    fn update_modem_inputs(&mut self) {
        let inputs = if self.mcr & mcr::LOOPBACK != 0 {
            let mut value = 0u8;
            if self.mcr & mcr::RTS != 0 {
                value |= msr::CTS;
            }
            if self.mcr & mcr::DTR != 0 {
                value |= msr::DSR;
            }
            if self.mcr & mcr::OUT1 != 0 {
                value |= msr::RI;
            }
            if self.mcr & mcr::OUT2 != 0 {
                value |= msr::DCD;
            }
            value
        } else {
            MSR_IDLE
        };
        let previous = self.msr & 0xF0;
        let mut deltas = self.msr & 0x0F;
        if (previous ^ inputs) & msr::CTS != 0 {
            deltas |= msr::DELTA_CTS;
        }
        if (previous ^ inputs) & msr::DSR != 0 {
            deltas |= msr::DELTA_DSR;
        }
        if (previous ^ inputs) & msr::RI != 0 {
            deltas |= msr::DELTA_RI;
        }
        if (previous ^ inputs) & msr::DCD != 0 {
            deltas |= msr::DELTA_DCD;
        }
        self.msr = inputs | deltas;
    }
}

impl Default for Uart {
    fn default() -> Self {
        Self::new()
    }
}
