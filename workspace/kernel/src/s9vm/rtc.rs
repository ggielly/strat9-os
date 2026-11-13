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

//! s9vm : MC146818-compatible CMOS real-time clock model for guests.
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
//! runs) or [`CmosRtc::advance_events`] when it also wants the interrupt
//! events. [`CmosRtc::new`] starts at the UNIX epoch, `1970-01-01T00:00:00Z`,
//! which is a valid calendar date, and leap years are handled by the civil
//! date conversion.
//!
//! # Interrupt model
//!
//! The chip's three interrupt sources are modelled from a **32.768 kHz
//! reference clock** ([`REFERENCE_HZ`]), the divider input of status register A:
//!
//! - **periodic**: the rate-select field `RS3:0` (status A bits `3:0`) selects a
//!   periodic frequency `REFERENCE_HZ >> (RS - 1)` for `RS in 3..=15`; `RS < 3`
//!   disables the periodic interrupt. The counter is a phase accumulator, so a
//!   slow poller does not lose phase: the events of a whole interval collapse
//!   into one observed event, but the next event keeps the exact rate.
//! - **update-ended**: one event at every second boundary of the host clock.
//! - **alarm**: the alarm bytes (`0x01` seconds, `0x03` minutes, `0x05` hours,
//!   and `0x31` day of month in this model) are compared with the guest-visible
//!   time at the new second boundary. A byte in `0xC0..=0xFF` means **don't
//!   care**, as on the chip: the top two bits at `11` are never produced by BCD
//!   or 12-hour encoding, so the convention is unambiguous. The chip itself has
//!   no day-of-month alarm register, so the model keeps that byte in spare CMOS
//!   RAM at [`REG_DAY_ALARM`]; the weekday alarm byte is not compared.
//!
//! Events set the status-C flags (`PF`, `AF`, `UF`) **whether or not the
//! matching enable bit in status B is set**, as on the hardware; the enable
//! bits (`PIE`, `AIE`, `UIE`) only gate the interrupt request. The summary bit
//! `IRQF` (status C bit 7) is not stored: it is computed on read as the OR of
//! the enabled event flags. Reading status C returns the flags and clears them,
//! exactly once.
//!
//! A single [`CmosRtc::advance_events`] call reports at most **one event of
//! each kind** because [`RtcEvents`] uses booleans: a caller that advances by
//! several periods still sees `periodic = true` once, and one status-C flag.
//! This is the documented granularity; poll more often to observe each period.
//!
//! Register semantics, following the chip:
//!
//! | Index | Register | Model behaviour |
//! |---|---|---|
//! | `0x00` | seconds | computed |
//! | `0x01` | seconds alarm | writable RAM, compared (don't-care bytes) |
//! | `0x02` | minutes | computed |
//! | `0x03` | minutes alarm | writable RAM, compared (don't-care bytes) |
//! | `0x04` | hours | computed |
//! | `0x05` | hours alarm | writable RAM, compared (don't-care bytes) |
//! | `0x06` | weekday (`1` = Sunday .. `7` = Saturday) | computed |
//! | `0x07` | day of month | computed |
//! | `0x08` | month | computed |
//! | `0x09` | year (two digits) | computed |
//! | `0x0A` | status A | divider/rate writable, UIP always `0` |
//! | `0x0B` | status B | writable; enables, formats and SET |
//! | `0x0C` | status C | event flags + computed `IRQF`; reading clears |
//! | `0x0D` | status D | reads `0x80` (valid RAM and time) |
//! | `0x0E..=0x7F` | CMOS RAM | writable, default `0` (except `0x31`, `0x32`) |
//! | `0x31` | day-of-month alarm (model extension) | writable RAM, compared (don't-care bytes) |
//! | `0x32` | century | computed |
//!
//! # Invariants
//!
//! - UIP (status A, bit 7) always reads as zero: the model is instantaneous, a
//!   driver may read the fields in any order;
//! - status C flags are generated by events (or by [`CmosRtc::raise_status_c`]
//!   for the caller) and cleared by the read that returns them; the guest can
//!   never set them by writing status C;
//! - while status B SET is asserted, the computed time is frozen at the moment
//!   SET was written (the host may then program the clock), and clearing SET
//!   makes the computed registers follow the current timestamp again; events
//!   keep being generated from the host clock, and the alarm compares the
//!   frozen guest-visible time;
//! - writes to the computed time registers are accepted (they land in CMOS RAM
//!   bytes) but do not change the clock: a driver must use an external time
//!   source, which is the documented behaviour of this model;
//! - `new` reports a valid calendar in BCD, 24-hour mode, with every interrupt
//!   disabled.
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
/// Frequency of the RTC reference clock (the divider input), in hertz.
pub const REFERENCE_HZ: u32 = 32_768;
/// Top two bits of an alarm byte meaning "don't care".
pub const ALARM_DONT_CARE_MASK: u8 = 0xC0;

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
/// Day-of-month alarm register.
///
/// The chip has no day-of-month alarm register (its alarm covers seconds,
/// minutes and hours only). The model needs one to honour the guest-requested
/// alarm, so it uses a spare CMOS RAM byte, next to the century register, with
/// the same "don't care" convention as the standard alarm bytes.
pub const REG_DAY_ALARM: u8 = 0x31;
/// Century register.
pub const REG_CENTURY: u8 = 0x32;

/// Bits of status register A.
pub mod status_a {
    /// Update-in-progress; always reads as `0` in this model.
    pub const UIP: u8 = 0x80;
    /// Divider and rate-select bits (bits 6:0).
    pub const DIVIDER_MASK: u8 = 0x7F;
    /// Rate-select field (bits 3:0): periodic interrupt frequency.
    pub const RATE_SELECT_MASK: u8 = 0x0F;
    /// Lowest rate-select value that enables the periodic interrupt.
    pub const MIN_RATE_SELECT: u8 = 3;
    /// Default value: 32.768 kHz divider input, `RS = 6`, 1024 Hz periodic rate.
    pub const DEFAULT: u8 = 0x26;
}

/// Bits of status register B.
pub mod status_b {
    /// `1` = the clock is frozen and may be programmed.
    pub const SET: u8 = 0x80;
    /// `1` = periodic interrupt enabled.
    pub const PERIODIC_INTERRUPT: u8 = 0x40;
    /// `1` = alarm interrupt enabled.
    pub const ALARM_INTERRUPT: u8 = 0x20;
    /// `1` = update-ended interrupt enabled.
    pub const UPDATE_ENDED_INTERRUPT: u8 = 0x10;
    /// `1` = binary register format, `0` = BCD.
    pub const BINARY: u8 = 0x04;
    /// `1` = 24-hour mode, `0` = 12-hour mode (bit 7 of hours = PM).
    pub const HOURS_24: u8 = 0x02;
    /// `1` = daylight-saving time enabled (formatting hint only).
    pub const DAYLIGHT_SAVING: u8 = 0x01;
    /// Default value: BCD, 24-hour mode, every interrupt disabled.
    pub const DEFAULT: u8 = HOURS_24;
}

/// Bits of status register C.
pub mod status_c {
    /// Interrupt request summary: OR of the enabled event flags.
    ///
    /// Computed on read, never stored.
    pub const IRQF: u8 = 0x80;
    /// Periodic-interrupt flag.
    pub const PERIODIC: u8 = 0x40;
    /// Alarm-interrupt flag.
    pub const ALARM: u8 = 0x20;
    /// Update-ended-interrupt flag.
    pub const UPDATED: u8 = 0x10;
    /// Mask of the event flags (the part that is stored and cleared on read).
    pub const EVENT_FLAGS: u8 = PERIODIC | ALARM | UPDATED;
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

/// True when an alarm byte carries the "don't care" convention.
///
/// The top two bits at `11` (`0xC0..=0xFF`) mean "ignore this field"; no value
/// produced by BCD or by the 12-hour encoding sets both bits.
pub const fn alarm_dont_care(value: u8) -> bool {
    value & ALARM_DONT_CARE_MASK == ALARM_DONT_CARE_MASK
}

/// Events produced by one [`CmosRtc::advance_events`] call.
///
/// Each field is a boolean: an interval that spans several periods or several
/// seconds still reports one event per kind, and latches one status-C flag.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RtcEvents {
    /// At least one periodic interrupt period elapsed.
    pub periodic: bool,
    /// At least one second boundary was crossed (update-ended).
    pub update_ended: bool,
    /// The alarm matched at the new second boundary.
    pub alarm: bool,
}

impl RtcEvents {
    /// No event occurred.
    pub const NONE: Self = Self {
        periodic: false,
        update_ended: false,
        alarm: false,
    };

    /// True if at least one event occurred.
    pub const fn any(self) -> bool {
        self.periodic || self.update_ended || self.alarm
    }
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
    /// Sub-second remainder of the 32.768 kHz reference clock.
    sub_second_remainder: u64,
    /// Phase of the periodic interrupt, in reference-clock ticks.
    periodic_accumulator: u64,
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
            sub_second_remainder: 0,
            periodic_accumulator: 0,
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
    ///
    /// This is the historical helper used by the device model: it advances the
    /// time, generates the same interrupt events as
    /// [`Self::advance_events`] (so status C and [`Self::irq_asserted`] stay
    /// coherent) and discards the returned events.
    pub fn advance(&mut self, seconds: u64) {
        let _ = self.advance_events(seconds, 0);
    }

    /// Advances the clock and reports the interrupt events of the interval.
    ///
    /// `seconds` is whole host seconds; `sub_second_ticks` is an additional
    /// fraction expressed in **32.768 kHz reference-clock ticks**
    /// ([`REFERENCE_HZ`]) : typically `elapsed_ticks / 32768` remainders passed
    /// by a caller that only has a finer-grained clock. The two are added and
    /// the sub-second remainder is carried across calls, so repeated calls with
    /// small tick counts do not drift.
    ///
    /// The returned [`RtcEvents`] carries at most one event of each kind:
    ///
    /// - `periodic`: at least one periodic period elapsed. The phase
    ///   accumulator is maintained modulo the programmed period, so the *rate*
    ///   stays exact even when a poll covers several periods;
    /// - `update_ended`: at least one second boundary was crossed (the model
    ///   has no update cycle to interrupt, so this is the advertised
    ///   update-ended event);
    /// - `alarm`: the alarm bytes matched at the new second boundary. A single
    ///   large jump evaluates the alarm once, on the final second; poll more
    ///   often if an intermediate alarm instant must not be missed.
    ///
    /// Events always latch the matching status-C flag (`PF`, `AF`, `UF`), as on
    /// the hardware; the status-B enables only decide whether `IRQF` is
    /// asserted. Reading status C clears the flags.
    ///
    /// The clock saturates at [`u64::MAX`]; events are then computed from the
    /// ticks that actually elapsed.
    pub fn advance_events(&mut self, seconds: u64, sub_second_ticks: u64) -> RtcEvents {
        // Saturating u128 arithmetic: a hostile caller cannot overflow the
        // second/tick product, and the divisions have a non-zero divisor.
        // `elapsed_ticks` is what the periodic phase consumes; `total_ticks`
        // adds the fraction carried from the previous call, which matters only
        // for whole-second (update-ended) detection.
        let elapsed_ticks = u128::from(seconds)
            .saturating_mul(u128::from(REFERENCE_HZ))
            .saturating_add(u128::from(sub_second_ticks));
        let total_ticks = elapsed_ticks.saturating_add(u128::from(self.sub_second_remainder));
        let whole_seconds_128 = total_ticks / u128::from(REFERENCE_HZ);
        self.sub_second_remainder = (total_ticks % u128::from(REFERENCE_HZ)) as u64;

        let previous = self.unix_time;
        let whole_seconds = if whole_seconds_128 > u128::from(u64::MAX) {
            u64::MAX
        } else {
            whole_seconds_128 as u64
        };
        self.unix_time = self.unix_time.saturating_add(whole_seconds);
        let elapsed_seconds = self.unix_time.saturating_sub(previous);

        let mut events = RtcEvents::NONE;
        if let Some(rate) = self.periodic_rate_hz() {
            // The rate is always a power of two, so the period divides the
            // reference frequency exactly and the shift never truncates.
            let period_ticks = u128::from(REFERENCE_HZ / rate);
            let accumulated = u128::from(self.periodic_accumulator) + elapsed_ticks;
            events.periodic = accumulated >= period_ticks;
            self.periodic_accumulator = (accumulated % period_ticks) as u64;
        } else {
            self.periodic_accumulator = 0;
        }

        if elapsed_seconds > 0 {
            events.update_ended = true;
            events.alarm = self.alarm_matches();
        }

        let mut flags = 0;
        if events.periodic {
            flags |= status_c::PERIODIC;
        }
        if events.alarm {
            flags |= status_c::ALARM;
        }
        if events.update_ended {
            flags |= status_c::UPDATED;
        }
        self.status_c |= flags;
        events
    }

    /// Periodic interrupt frequency in hertz, or `None` when disabled.
    ///
    /// The rate-select field `RS3:0` follows the chip encoding:
    /// `rate = 32768 >> (RS - 1)` for `RS in 3..=15`; `RS` below 3 disables the
    /// periodic interrupt. The default status A (`0x26`) selects `RS = 6`, that
    /// is 1024 Hz.
    pub fn periodic_rate_hz(&self) -> Option<u32> {
        let rate_select = self.status_a & status_a::RATE_SELECT_MASK;
        if rate_select < status_a::MIN_RATE_SELECT {
            None
        } else {
            Some(REFERENCE_HZ >> (rate_select - 1))
        }
    }

    /// True while the interrupt request line is asserted.
    ///
    /// Computed, not stored: the OR of the event flags whose enable bit is set
    /// in status B : exactly the `IRQF` bit that a status-C read returns.
    pub const fn irq_asserted(&self) -> bool {
        let enabled = self.status_b;
        (self.status_c & status_c::PERIODIC != 0 && enabled & status_b::PERIODIC_INTERRUPT != 0)
            || (self.status_c & status_c::ALARM != 0 && enabled & status_b::ALARM_INTERRUPT != 0)
            || (self.status_c & status_c::UPDATED != 0
                && enabled & status_b::UPDATE_ENDED_INTERRUPT != 0)
    }

    /// True when the periodic interrupt is enabled in status B.
    pub const fn periodic_interrupt_enabled(&self) -> bool {
        self.status_b & status_b::PERIODIC_INTERRUPT != 0
    }

    /// True when the alarm interrupt is enabled in status B.
    pub const fn alarm_interrupt_enabled(&self) -> bool {
        self.status_b & status_b::ALARM_INTERRUPT != 0
    }

    /// True when the update-ended interrupt is enabled in status B.
    pub const fn update_ended_interrupt_enabled(&self) -> bool {
        self.status_b & status_b::UPDATE_ENDED_INTERRUPT != 0
    }

    /// True in 24-hour mode (status B bit 1).
    pub const fn hours_24_mode(&self) -> bool {
        self.status_b & status_b::HOURS_24 != 0
    }

    /// True in binary data mode (status B bit 2).
    pub const fn binary_mode(&self) -> bool {
        self.status_b & status_b::BINARY != 0
    }

    /// True when the daylight-saving hint is set (status B bit 0).
    ///
    /// The model does not shift the clock: the bit is exposed for drivers that
    /// report or program it, and has no effect on the computed time.
    pub const fn daylight_saving_enabled(&self) -> bool {
        self.status_b & status_b::DAYLIGHT_SAVING != 0
    }

    /// True while status B SET freezes the guest-visible calendar.
    pub const fn clock_frozen(&self) -> bool {
        self.status_b & status_b::SET != 0
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
            REG_STATUS_C => {
                // The event flags are returned once and cleared; the summary
                // bit is computed from the enables and never stored.
                let mut value = self.status_c & status_c::EVENT_FLAGS;
                if self.irq_asserted() {
                    value |= status_c::IRQF;
                }
                self.status_c = 0;
                value
            }
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
            REG_STATUS_A => {
                self.status_a = value & status_a::DIVIDER_MASK;
                // Changing the rate restarts the periodic phase, as the
                // divider chain does on the chip.
                self.periodic_accumulator = 0;
            }
            REG_STATUS_B => self.write_status_b(value),
            REG_STATUS_C | REG_STATUS_D => {}
            _ => self.ram[usize::from(self.index)] = value,
        }
    }

    /// Raises interrupt flags in status register C.
    ///
    /// The device model calls this when an external event must be latched; the
    /// guest observes the bits once, then the read that returns them clears
    /// them. Only the event flags are accepted: `IRQF` is computed by the model
    /// and a caller cannot force it.
    pub fn raise_status_c(&mut self, flags: u8) {
        self.status_c |= flags & status_c::EVENT_FLAGS;
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
        self.encode_hours_value(self.hours())
    }

    /// Encodes a 24-hour value into the guest-visible hours byte.
    fn encode_hours_value(&self, hours: u64) -> u8 {
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

    /// True when the guest-visible time matches the programmed alarm.
    ///
    /// Seconds, minutes, hours and the model's day-of-month byte are compared;
    /// a byte in `0xC0..=0xFF` is a wildcard. The comparison uses the current
    /// display encoding, so a guest must program the alarm bytes in the same
    /// BCD/binary and 12/24-hour mode as the time registers.
    fn alarm_matches(&self) -> bool {
        let clock = self.clock();
        let seconds = clock % 60;
        let minutes = (clock / 60) % 60;
        let hours = (clock / 3600) % 24;
        let day = self.day();
        alarm_byte_matches(
            self.ram[usize::from(REG_SECONDS_ALARM)],
            self.encode(seconds),
        ) && alarm_byte_matches(
            self.ram[usize::from(REG_MINUTES_ALARM)],
            self.encode(minutes),
        ) && alarm_byte_matches(
            self.ram[usize::from(REG_HOURS_ALARM)],
            self.encode_hours_value(hours),
        ) && alarm_byte_matches(self.ram[usize::from(REG_DAY_ALARM)], self.encode(day))
    }
}

/// Compares one alarm byte with the encoded current value.
///
/// A "don't care" byte always matches; otherwise the bytes must be identical.
fn alarm_byte_matches(alarm: u8, current: u8) -> bool {
    alarm_dont_care(alarm) || alarm == current
}

impl Default for CmosRtc {
    fn default() -> Self {
        Self::new()
    }
}
