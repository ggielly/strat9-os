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

//! s9vm — MC146818-compatible CMOS real-time clock model for guests.
//!
//! A PC-compatible guest reads the wall clock through two I/O ports: the
//! **index port** (`0x70`) selects one of 128 CMOS registers (bit 7 gates the
//! NMI), and the **data port** (`0x71`) reads or writes the selected register.
//! This module models the MC146818 (and its CMOS RAM) as pure state: the kernel
//! calls [`CmosRtc::write_index`] / [`CmosRtc::read_data`] /
//! [`CmosRtc::write_data`] when it emulates those ports, and never touches
//! hardware.
//!
//! # Time is computed, never stored per field
//!
//! Only a UNIX timestamp is kept. The calendar registers (`sec`, `min`,
//! `hour`, `weekday`, `day`, `month`, `year`, `century`) are **computed on
//! read** from that timestamp, so the clock cannot drift between the fields and
//! never needs a periodic update: the kernel advances it explicitly with
//! [`CmosRtc::advance`] (for instance with the time elapsed between two vCPU
//! runs). [`CmosRtc::new`] starts at the UNIX epoch, `1970-01-01T00:00:00Z`,
//! which is a valid calendar date, and leap years are handled by the civil
//! date conversion.
//!
//! Register semantics, following the chip:
//!
//! | Index | Register | Model behaviour |
//! |---|---|---|
//! | `0x00` | seconds | computed |
//! | `0x01` | seconds alarm | writable RAM |
//! | `0x02` | minutes | computed |
//! | `0x03` | minutes alarm | writable RAM |
//! | `0x04` | hours | computed |
//! | `0x05` | hours alarm | writable RAM |
//! | `0x06` | weekday (`1` = Sunday .. `7` = Saturday) | computed |
//! | `0x07` | day of month | computed |
//! | `0x08` | month | computed |
//! | `0x09` | year (two digits) | computed |
//! | `0x0A` | status A | divider field writable, UIP always `0` |
//! | `0x0B` | status B | writable; bit 2 = binary, bit 1 = 24 h, bit 7 = SET |
//! | `0x0C` | status C | interrupt flags; reading clears them |
//! | `0x0D` | status D | reads `0x80` (valid RAM and time) |
//! | `0x0E..=0x7F` | CMOS RAM | writable, default `0` (except `0x32`) |
//! | `0x32` | century | computed |
//!
//! # Invariants
//!
//! - UIP (status A, bit 7) always reads as zero: the model is instantaneous, a
//!   driver may read the fields in any order;
//! - status C flags are cleared by the read that returns them;
//! - while status B SET is asserted, the computed time is frozen at the moment
//!   SET was written (the host may then program the clock), and clearing SET
//!   makes the computed registers follow the current timestamp again;
//! - writes to the computed time registers are accepted (they land in CMOS RAM
//!   bytes) but do not change the clock: a driver must use an external time
//!   source, which is the documented behaviour of this model;
//! - `new` reports a valid calendar in BCD, 24-hour mode.
//!
//! This module is pure `core` code and is host-tested by `s9vm-tests`.

use crate::rtc_math;

/// I/O port selecting a CMOS register (and gating the NMI with bit 7).
pub const INDEX_PORT: u16 = 0x70;
/// I/O port reading or writing the selected CMOS register.
pub const DATA_PORT: u16 = 0x71;
/// Bit of the index port that disables the NMI when set.
pub const NMI_PORT_MASK: u8 = 0x80;
/// I/O APIC line wired to the RTC periodic interrupt.
pub const IRQ_LINE: u8 = 8;

/// Number of CMOS registers addressable by the index port.
pub const REGISTER_COUNT: usize = 128;

/// Seconds register.
pub const REG_SECONDS: u8 = 0x00;
/// Seconds alarm register.
pub const REG_SECONDS_ALARM: u8 = 0x01;
/// Minutes register.
pub const REG_MINUTES: u8 = 0x02;
/// Minutes alarm register.
pub const REG_MINUTES_ALARM: u8 = 0x03;
/// Hours register.
pub const REG_HOURS: u8 = 0x04;
/// Hours alarm register.
pub const REG_HOURS_ALARM: u8 = 0x05;
/// Weekday register (`1` = Sunday .. `7` = Saturday).
pub const REG_WEEKDAY: u8 = 0x06;
/// Day-of-month register.
pub const REG_DAY: u8 = 0x07;
/// Month register.
pub const REG_MONTH: u8 = 0x08;
/// Two-digit year register.
pub const REG_YEAR: u8 = 0x09;
/// Status register A.
pub const REG_STATUS_A: u8 = 0x0A;
/// Status register B.
pub const REG_STATUS_B: u8 = 0x0B;
/// Status register C.
pub const REG_STATUS_C: u8 = 0x0C;
/// Status register D.
pub const REG_STATUS_D: u8 = 0x0D;
/// Century register.
pub const REG_CENTURY: u8 = 0x32;

/// Bits of status register A.
pub mod status_a {
    /// Update-in-progress; always reads as `0` in this model.
    pub const UIP: u8 = 0x80;
    /// Divider and rate-select bits (bits 6:0).
    pub const DIVIDER_MASK: u8 = 0x7F;
    /// Default value: 32.768 kHz divider, 1024 Hz periodic rate.
    pub const DEFAULT: u8 = 0x26;
}

/// Bits of status register B.
pub mod status_b {
    /// `1` = the clock is frozen and may be programmed.
    pub const SET: u8 = 0x80;
    /// `1` = binary register format, `0` = BCD.
    pub const BINARY: u8 = 0x04;
    /// `1` = 24-hour mode, `0` = 12-hour mode (bit 7 of hours = PM).
    pub const HOURS_24: u8 = 0x02;
    /// Default value: BCD, 24-hour mode.
    pub const DEFAULT: u8 = HOURS_24;
}

/// Bits of status register C.
pub mod status_c {
    /// Periodic-interrupt flag (injected by the caller).
    pub const PERIODIC: u8 = 0x40;
    /// Alarm-interrupt flag (injected by the caller).
    pub const ALARM: u8 = 0x20;
    /// Update-ended-interrupt flag (injected by the caller).
    pub const UPDATED: u8 = 0x10;
}

/// Bits of status register D.
pub mod status_d {
    /// The CMOS RAM and the time are valid.
    pub const VALID: u8 = 0x80;
}

/// True when `port` belongs to the modelled CMOS RTC (`0x70` or `0x71`).
pub const fn handles_port(port: u16) -> bool {
    port == INDEX_PORT || port == DATA_PORT
}

/// Model of an MC146818-compatible CMOS RTC and its CMOS RAM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CmosRtc {
    /// Currently selected register (`0..=127`).
    index: u8,
    /// NMI disabled by the last index-port write (bit 7 of the index byte).
    nmi_disabled: bool,
    /// Current UNIX timestamp, in seconds.
    unix_time: u64,
    /// Timestamp captured when status B SET was written.
    frozen: Option<u64>,
    /// Status register A (UIP excluded when read).
    status_a: u8,
    /// Status register B.
    status_b: u8,
    /// Status register C flags, cleared on read.
    status_c: u8,
    /// CMOS RAM bytes; the computed registers are only mirrors of the clock.
    ram: [u8; REGISTER_COUNT],
}

impl CmosRtc {
    /// Creates a clock at the UNIX epoch, BCD, 24-hour, with a valid calendar.
    pub fn new() -> Self {
        Self {
            index: 0,
            nmi_disabled: false,
            unix_time: 0,
            frozen: None,
            status_a: status_a::DEFAULT,
            status_b: status_b::DEFAULT,
            status_c: 0,
            ram: [0; REGISTER_COUNT],
        }
    }

    /// Sets the clock to `seconds` since the UNIX epoch.
    ///
    /// If status B SET is asserted, the frozen snapshot is updated too, so the
    /// guest sees the newly programmed time.
    pub fn set_unix_time(&mut self, seconds: u64) {
        self.unix_time = seconds;
        if self.frozen.is_some() {
            self.frozen = Some(seconds);
        }
    }

    /// Current UNIX timestamp, in seconds.
    ///
    /// This is the host-side time: it keeps advancing even while status B SET
    /// freezes the **guest-visible** calendar registers.
    pub const fn unix_time(&self) -> u64 {
        self.unix_time
    }

    /// Advances the clock by `seconds` (saturating at [`u64::MAX`]).
    pub fn advance(&mut self, seconds: u64) {
        self.unix_time = self.unix_time.saturating_add(seconds);
    }

    /// Writes the index port.
    ///
    /// Bit 7 disables the NMI; bits 6:0 select the CMOS register. The selected
    /// register is what the next data-port access reads or writes.
    pub fn write_index(&mut self, value: u8) {
        self.nmi_disabled = value & NMI_PORT_MASK != 0;
        self.index = value & !NMI_PORT_MASK;
    }

    /// Currently selected register index (`0..=127`).
    pub const fn index(&self) -> u8 {
        self.index
    }

    /// True when the last index-port write disabled the NMI.
    pub const fn nmi_disabled(&self) -> bool {
        self.nmi_disabled
    }

    /// Reads the data port for the selected register.
    pub fn read_data(&mut self) -> u8 {
        match self.index {
            REG_SECONDS => self.encode(self.seconds()),
            REG_MINUTES => self.encode(self.minutes()),
            REG_HOURS => self.encode_hours(),
            REG_WEEKDAY => self.encode(self.weekday()),
            REG_DAY => self.encode(self.day()),
            REG_MONTH => self.encode(self.month()),
            REG_YEAR => self.encode(self.year() % 100),
            REG_CENTURY => self.encode(self.year() / 100),
            REG_STATUS_A => self.status_a & status_a::DIVIDER_MASK,
            REG_STATUS_B => self.status_b,
            REG_STATUS_C => core::mem::take(&mut self.status_c),
            REG_STATUS_D => status_d::VALID,
            _ => self.ram[usize::from(self.index)],
        }
    }

    /// Writes the data port for the selected register.
    ///
    /// Computed time registers are accepted and kept as CMOS RAM bytes but do
    /// not move the clock (see the module documentation). Status C and D are
    /// read-only; writes to them are ignored.
    pub fn write_data(&mut self, value: u8) {
        match self.index {
            REG_STATUS_A => self.status_a = value & status_a::DIVIDER_MASK,
            REG_STATUS_B => self.write_status_b(value),
            REG_STATUS_C | REG_STATUS_D => {}
            _ => self.ram[usize::from(self.index)] = value,
        }
    }

    /// Raises interrupt flags in status register C.
    ///
    /// The device model calls this when a periodic, alarm or update-ended
    /// event occurs; the guest observes the bits once, then the read that
    /// returns them clears them.
    pub fn raise_status_c(&mut self, flags: u8) {
        self.status_c |= flags;
    }

    /// Writes status register B, capturing or releasing the SET freeze.
    fn write_status_b(&mut self, value: u8) {
        let was_set = self.status_b & status_b::SET != 0;
        let is_set = value & status_b::SET != 0;
        match (was_set, is_set) {
            (false, true) => self.frozen = Some(self.unix_time),
            (true, false) => self.frozen = None,
            _ => {}
        }
        self.status_b = value;
    }

    /// Timestamp the computed registers are derived from.
    fn clock(&self) -> u64 {
        self.frozen.unwrap_or(self.unix_time)
    }

    /// Seconds (`0..=59`).
    fn seconds(&self) -> u64 {
        self.clock() % 60
    }

    /// Minutes (`0..=59`).
    fn minutes(&self) -> u64 {
        (self.clock() / 60) % 60
    }

    /// Hours in 24-hour form (`0..=23`).
    fn hours(&self) -> u64 {
        (self.clock() / 3600) % 24
    }

    /// Day of week, `1` = Sunday .. `7` = Saturday.
    fn weekday(&self) -> u64 {
        let days = self.clock() / 86_400;
        // The UNIX epoch (day 0) was a Thursday: Sunday-based numbering makes
        // Thursday the fifth day of the week.
        (days + 4) % 7 + 1
    }

    /// Day of the month (`1..=31`).
    fn day(&self) -> u64 {
        u64::from(rtc_math::civil_from_days(self.days()).2)
    }

    /// Month (`1..=12`).
    fn month(&self) -> u64 {
        u64::from(rtc_math::civil_from_days(self.days()).1)
    }

    /// Full Gregorian year.
    fn year(&self) -> u64 {
        rtc_math::civil_from_days(self.days()).0
    }

    /// Whole days since the UNIX epoch.
    fn days(&self) -> u64 {
        self.clock() / 86_400
    }

    /// Encodes a value in the format selected by status B (binary or BCD).
    fn encode(&self, value: u64) -> u8 {
        if self.status_b & status_b::BINARY != 0 {
            value as u8
        } else {
            rtc_math::binary_to_bcd(value as u8)
        }
    }

    /// Encodes the hours register, honouring the 12/24-hour mode.
    fn encode_hours(&self) -> u8 {
        let hours = self.hours();
        if self.status_b & status_b::HOURS_24 != 0 {
            return self.encode(hours);
        }
        let hour12 = if hours % 12 == 0 { 12 } else { hours % 12 };
        let mut value = self.encode(hour12);
        if hours >= 12 {
            value |= 0x80;
        }
        value
    }
}

impl Default for CmosRtc {
    fn default() -> Self {
        Self::new()
    }
}

