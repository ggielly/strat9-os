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

//! s9vm : pure model of the guest High Precision Event Timer (HPET).
//!
//! This module models the architectural state of one HPET block: the
//! capabilities/ID register, the main counter, the configuration and status
//! registers and three comparator timers with their configuration registers.
//! It **touches no hardware**: the kernel layer forwards guest MMIO accesses
//! to [`Hpet::read`] / [`Hpet::write`] and calls [`Hpet::advance_ticks`] (or
//! [`Hpet::advance_femtoseconds`]) with the elapsed time.
//!
//! The encodings come from the Intel documentation (IA-PC HPET specification
//! and ACPI "HPET Description Table"). No constant specific to a particular
//! hypervisor is used.
//!
//! ## Register window
//!
//! ```text
//! 0x000  general capabilities and ID (64-bit, read-only; 0x004 reads the
//!        period in femtoseconds, the high double word of the register)
//! 0x010  general configuration (enable, legacy route)
//! 0x020  general interrupt status (write 1 to clear)
//! 0x0F0  main counter (64-bit, read-only; 0x0F4 reads the high double word)
//! 0x100  timer 0 configuration, 0x108 timer 0 comparator
//! 0x120  timer 1 configuration, 0x128 timer 1 comparator
//! 0x140  timer 2 configuration, 0x148 timer 2 comparator
//! ```
//!
//! ## Access policy
//!
//! Only naturally aligned 4-byte and 8-byte accesses are accepted; any other
//! width or alignment is rejected (`None` from [`Hpet::read`], `false` from
//! [`Hpet::write`]). Writes to read-only registers are ignored and reported as
//! rejected.
//!
//! ## Interrupts
//!
//! A comparator match sets its bit in the interrupt status register whether or
//! not the timer interrupt is enabled, exactly like the hardware. The IRQ line
//! is level-sensitive: [`Hpet::irq_asserted`] is true while a status bit of an
//! **interrupt-enabled** timer is set; software clears it by writing 1 to the
//! status register.
//!
//! ## ACPI table
//!
//! [`table_bytes`] builds the 56-byte ACPI HPET description table (36-byte
//! header, 12-byte address structure, HPET number, minimum tick, page
//! protection and reserved padding) with a valid checksum. The integrator can
//! copy it into the guest firmware tables.

/// Guest physical base address of the HPET MMIO window.
pub const BASE_GPA: u64 = 0xFED0_0000;
/// Size of the HPET MMIO window, in bytes.
pub const MMIO_SIZE: u32 = 0x400;
/// General capabilities and ID register.
pub const CAPS_ID: u16 = 0x000;
/// Counter clock period, in femtoseconds (high double word of `CAPS_ID`).
pub const PERIOD: u16 = 0x004;
/// General configuration register.
pub const CONFIG: u16 = 0x010;
/// General interrupt status register.
pub const ISR: u16 = 0x020;
/// Main counter register.
pub const COUNTER: u16 = 0x0F0;
/// First timer configuration register.
pub const COMPARATOR_BASE: u16 = 0x100;
/// Distance between two timer blocks.
pub const COMPARATOR_STRIDE: u16 = 0x20;
/// Number of comparator timers modeled.
pub const TIMER_COUNT: usize = 3;
/// Interrupt line advertised for the HPET block (GSI 2 on PC firmware).
pub const IRQ_LINE: u8 = 2;
/// Nominal HPET clock frequency, in Hz (14.31818 MHz).
pub const FREQUENCY_HZ: u64 = 14_318_180;
/// Nominal counter clock period, in femtoseconds (1e15 / FREQUENCY_HZ).
///
/// The exact ratio is 69.841278... fs; the value is rounded to the nearest
/// femtosecond, which is the precision of the architectural register.
pub const PERIOD_FS: u32 = 69_841_278;
/// Revision encoded in `CAPS_ID` bits 7:0.
pub const REVISION: u8 = 1;
/// Counter size encoded in `CAPS_ID` bit 13 (1 = 64-bit counter).
pub const COUNTER_SIZE: u8 = 64;
/// Vendor identifier encoded in `CAPS_ID` bits 31:16.
///
/// Data constant chosen to identify this model ("SG"), not a vendor claim.
pub const VENDOR_ID: u16 = 0x5347;
/// Legacy replacement capability (IRQ0/IRQ8 routing), `CAPS_ID` bit 15.
pub const LEGACY_REPLACEMENT_CAPABLE: bool = true;
/// Counter clock period in 100 ns units, derived from [`PERIOD_FS`].
///
/// This is the mathematical minimum periodic interval expressible in the
/// ACPI units (one 100 ns unit covers more than one HPET clock). The table
/// advertises the architectural firmware convention instead (see
/// [`TABLE_MINIMUM_TICK`]).
pub const fn minimum_tick_from_period() -> u16 {
    let units = (PERIOD_FS as u64 + 99_999_999) / 100_000_000;
    if units == 0 {
        1
    } else if units > u16::MAX as u64 {
        u16::MAX
    } else {
        units as u16
    }
}

// ---------------------------------------------------------------------------
// Register bit fields
// ---------------------------------------------------------------------------

/// Global configuration: main counter enable.
pub const CONFIG_ENABLE: u32 = 1 << 0;
/// Global configuration: legacy IRQ routing replacement.
pub const CONFIG_LEGACY_ROUTE: u32 = 1 << 1;
/// Generic timer configuration: interrupt type (0 = edge, 1 = level).
pub const TIMER_INT_TYPE: u32 = 1 << 1;
/// Generic timer configuration: interrupt enable.
pub const TIMER_INT_ENABLE: u32 = 1 << 2;
/// Generic timer configuration: periodic mode capable (read-only, always 1).
pub const TIMER_PERIODIC_CAPABLE: u32 = 1 << 3;
/// Generic timer configuration: periodic mode enable.
pub const TIMER_PERIODIC: u32 = 1 << 4;
/// Generic timer configuration: 64-bit counter capable (read-only, always 1).
pub const TIMER_64BIT_CAPABLE: u32 = 1 << 5;
/// Generic timer configuration: 64-bit counter mode.
pub const TIMER_64BIT_MODE: u32 = 1 << 6;
/// Generic timer configuration: interrupt route mask (bits 13:9).
pub const TIMER_ROUTE_MASK: u32 = 0x3F << 9;
/// Writable bits of a timer configuration register.
const TIMER_WRITABLE: u32 =
    TIMER_INT_TYPE | TIMER_INT_ENABLE | TIMER_PERIODIC | TIMER_64BIT_MODE | TIMER_ROUTE_MASK;

/// Decoded `CAPS_ID` register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapsId {
    /// Architecture revision (bits 7:0).
    pub revision: u8,
    /// Number of comparator timers (bits 12:8 encode count minus one).
    pub timer_count: u8,
    /// 64-bit counter capable (bit 13).
    pub counter_64: bool,
    /// Legacy replacement capable (bit 15).
    pub legacy_capable: bool,
    /// Vendor identifier (bits 31:16).
    pub vendor_id: u16,
    /// Counter clock period in femtoseconds (bits 63:32).
    pub period_fs: u32,
}

impl CapsId {
    /// Decodes the 64-bit `CAPS_ID` value.
    pub const fn decode(raw: u64) -> Self {
        Self {
            revision: (raw & 0xFF) as u8,
            timer_count: (((raw >> 8) & 0x1F) as u8).saturating_add(1),
            counter_64: raw & (1 << 13) != 0,
            legacy_capable: raw & (1 << 15) != 0,
            vendor_id: ((raw >> 16) & 0xFFFF) as u16,
            period_fs: (raw >> 32) as u32,
        }
    }

    /// Encodes the value back into the register format.
    pub const fn encode(self) -> u64 {
        let mut value = self.revision as u64;
        value |= ((self.timer_count.saturating_sub(1)) as u64 & 0x1F) << 8;
        if self.counter_64 {
            value |= 1 << 13;
        }
        if self.legacy_capable {
            value |= 1 << 15;
        }
        value |= (self.vendor_id as u64) << 16;
        value |= (self.period_fs as u64) << 32;
        value
    }
}

/// One comparator timer.
#[derive(Debug, Clone, Copy)]
struct Timer {
    /// Configuration register (only the writable bits plus the read-only
    /// capability bits are stored).
    config: u32,
    /// Comparator value.
    comparator: u64,
    /// Reload period, in main-counter ticks (periodic mode).
    period: u64,
    /// A comparator was written since the last reset/expiry: the timer is
    /// armed. An unarmed timer must not fire, even though its comparator and
    /// the main counter are both zero at reset (distance 0 would otherwise
    /// match on the first advance).
    armed: bool,
    /// The one-shot timer already expired; a comparator write re-arms it.
    expired: bool,
}

impl Timer {
    /// Reset state: no interrupt, one-shot mode, capability bits set.
    const fn new() -> Self {
        Self {
            config: TIMER_PERIODIC_CAPABLE | TIMER_64BIT_CAPABLE,
            comparator: 0,
            period: 0,
            armed: false,
            expired: false,
        }
    }

    /// Configuration value as read by the guest (read-only bits included).
    const fn read_config(&self) -> u32 {
        (self.config & TIMER_WRITABLE) | TIMER_PERIODIC_CAPABLE | TIMER_64BIT_CAPABLE
    }
}

/// Timers that fired during the last advance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HpetEvents {
    /// Bit `n` set when timer `n` matched its comparator.
    pub fired: u32,
}

impl HpetEvents {
    /// No timer fired.
    pub const fn empty() -> Self {
        Self { fired: 0 }
    }

    /// `true` when at least one timer fired.
    pub const fn is_empty(self) -> bool {
        self.fired == 0
    }

    /// `true` when the given timer fired.
    pub const fn contains(self, timer: usize) -> bool {
        timer < TIMER_COUNT && self.fired & (1 << timer) != 0
    }
}

/// Model of one HPET block.
#[derive(Debug, Clone, Copy)]
pub struct Hpet {
    counter: u64,
    frac_fs: u64,
    config: u32,
    isr: u32,
    timers: [Timer; TIMER_COUNT],
}

impl Hpet {
    /// Creates a reset HPET: counter 0, globally disabled, no pending IRQ.
    pub const fn new() -> Self {
        Self {
            counter: 0,
            frac_fs: 0,
            config: 0,
            isr: 0,
            timers: [Timer::new(); TIMER_COUNT],
        }
    }

    /// `true` when the guest programmed the main counter enable bit.
    pub const fn enabled(&self) -> bool {
        self.config & CONFIG_ENABLE != 0
    }

    /// `true` when the legacy replacement route bit is set.
    pub const fn legacy_route(&self) -> bool {
        self.config & CONFIG_LEGACY_ROUTE != 0
    }

    /// Current main counter value.
    pub const fn counter(&self) -> u64 {
        self.counter
    }

    /// Current global configuration register.
    pub const fn config(&self) -> u32 {
        self.config
    }

    /// Current interrupt status register.
    pub const fn isr(&self) -> u32 {
        self.isr
    }

    /// Current comparator value of a timer.
    pub fn comparator(&self, timer: usize) -> Option<u64> {
        self.timers.get(timer).map(|timer| timer.comparator)
    }

    /// Current configuration value of a timer (read-only bits included).
    pub fn timer_config(&self, timer: usize) -> Option<u32> {
        self.timers.get(timer).map(|timer| timer.read_config())
    }

    /// Reload period of a timer, in main-counter ticks.
    pub fn timer_period(&self, timer: usize) -> Option<u64> {
        self.timers.get(timer).map(|timer| timer.period)
    }

    /// Decoded capabilities.
    pub const fn caps(&self) -> CapsId {
        CapsId::decode(self.caps_raw())
    }

    /// Returns `true` when `gpa` falls in the HPET MMIO page.
    pub fn handles_gpa(gpa: u64) -> bool {
        gpa >= BASE_GPA && gpa < BASE_GPA + MMIO_SIZE as u64
    }

    /// Reads a register; `offset` is relative to [`BASE_GPA`].
    ///
    /// Only naturally aligned 4-byte and 8-byte accesses are accepted.
    pub fn read(&self, offset: u16, size: u8) -> Option<u64> {
        let size = size as u16;
        if size != 4 && size != 8 {
            return None;
        }
        if offset as u32 >= MMIO_SIZE || offset % size != 0 {
            return None;
        }

        if size == 8 {
            return match offset {
                CAPS_ID => Some(self.caps_raw()),
                COUNTER => Some(self.counter),
                _ => self
                    .timer_for_comparator(offset)
                    .map(|timer| timer.comparator),
            };
        }

        match offset {
            CAPS_ID => Some(self.caps_raw() & 0xFFFF_FFFF),
            PERIOD => Some(PERIOD_FS as u64),
            CONFIG => Some(self.config as u64),
            ISR => Some(self.isr as u64),
            COUNTER => Some(self.counter & 0xFFFF_FFFF),
            // High double word of the 64-bit counter.
            0x0F4 => Some(self.counter >> 32),
            _ => {
                if let Some(timer) = self.timer_for_config(offset) {
                    return Some(timer.read_config() as u64);
                }
                if let Some(timer) = self.timer_for_comparator_low(offset) {
                    return Some(timer.comparator & 0xFFFF_FFFF);
                }
                if let Some(timer) = self.timer_for_comparator_high(offset) {
                    return Some(timer.comparator >> 32);
                }
                None
            }
        }
    }

    /// Writes a register; returns `false` for read-only, out-of-range or
    /// wrongly sized accesses.
    pub fn write(&mut self, offset: u16, size: u8, value: u64) -> bool {
        let size = size as u16;
        if size != 4 && size != 8 {
            return false;
        }
        if offset as u32 >= MMIO_SIZE || offset % size != 0 {
            return false;
        }

        if size == 8 {
            if let Some(timer) = self.timer_for_comparator_index(offset) {
                self.write_comparator(timer, value);
                return true;
            }
            // CAPS_ID, PERIOD and COUNTER are read-only.
            return false;
        }

        match offset {
            CONFIG => {
                // Only the enable and legacy route bits are writable.
                self.config = value as u32 & (CONFIG_ENABLE | CONFIG_LEGACY_ROUTE);
                true
            }
            ISR => {
                // Write 1 to clear the pending bits.
                self.isr &= !(value as u32);
                true
            }
            _ => {
                if let Some(timer) = self.timer_for_config_index(offset) {
                    self.write_timer_config(timer, value as u32);
                    return true;
                }
                if let Some(timer) = self.timer_for_comparator_low_index(offset) {
                    let low = value as u32 as u64;
                    let comparator = (self.timers[timer].comparator & !0xFFFF_FFFF) | low;
                    self.write_comparator(timer, comparator);
                    return true;
                }
                if let Some(timer) = self.timer_for_comparator_high_index(offset) {
                    let high = value as u32 as u64;
                    let comparator = (self.timers[timer].comparator & 0xFFFF_FFFF) | (high << 32);
                    self.write_comparator(timer, comparator);
                    return true;
                }
                // Read-only registers (CAPS_ID, PERIOD, COUNTER) and holes.
                false
            }
        }
    }

    /// Advances the main counter by a number of counter ticks.
    ///
    /// The main counter and the timers only run while the global enable bit is
    /// set. Returns the timers that matched their comparator during the call.
    pub fn advance_ticks(&mut self, ticks: u64) -> HpetEvents {
        if !self.enabled() || ticks == 0 {
            return HpetEvents::empty();
        }
        let previous = self.counter;
        self.counter = self.counter.wrapping_add(ticks);
        let mut fired = 0u32;

        for index in 0..TIMER_COUNT {
            let timer = &mut self.timers[index];
            if timer.expired || !timer.armed {
                continue;
            }
            let distance = timer.comparator.wrapping_sub(previous);
            let matched = if distance == 0 {
                true
            } else {
                distance <= ticks
            };
            if !matched {
                continue;
            }

            fired |= 1 << index;
            self.isr |= 1 << index;

            if timer.config & TIMER_PERIODIC != 0 {
                let period = timer.period.max(1);
                let extra = if distance == 0 {
                    ticks / period
                } else {
                    (ticks - distance) / period
                };
                let expirations = extra.saturating_add(1);
                timer.comparator = timer
                    .comparator
                    .wrapping_add(expirations.wrapping_mul(period));
            } else {
                // One-shot: stops until the comparator is written again.
                timer.expired = true;
            }
        }

        HpetEvents { fired }
    }

    /// Advances the main counter by a duration expressed in femtoseconds.
    ///
    /// The fractional part is accumulated so no clock is lost between calls.
    pub fn advance_femtoseconds(&mut self, femtoseconds: u64) -> HpetEvents {
        if !self.enabled() {
            return HpetEvents::empty();
        }
        let period = PERIOD_FS as u128;
        let total = self.frac_fs as u128 + femtoseconds as u128;
        let ticks = (total / period) as u64;
        self.frac_fs = (total % period) as u64;
        self.advance_ticks(ticks)
    }

    /// Level state of the HPET IRQ line.
    ///
    /// True while a status bit of an interrupt-enabled timer is pending;
    /// cleared by writing 1 to the corresponding [`ISR`] bit.
    pub fn irq_asserted(&self) -> bool {
        let mut mask = 0u32;
        for (index, timer) in self.timers.iter().enumerate() {
            if timer.config & TIMER_INT_ENABLE != 0 {
                mask |= 1 << index;
            }
        }
        self.isr & mask != 0
    }

    /// Encodes the 64-bit capabilities/ID register.
    const fn caps_raw(&self) -> u64 {
        CapsId {
            revision: REVISION,
            timer_count: TIMER_COUNT as u8,
            counter_64: COUNTER_SIZE == 64,
            legacy_capable: LEGACY_REPLACEMENT_CAPABLE,
            vendor_id: VENDOR_ID,
            period_fs: PERIOD_FS,
        }
        .encode()
    }

    /// Applies a comparator write and re-arms the timer.
    fn write_comparator(&mut self, index: usize, comparator: u64) {
        let mut timer = self.timers[index];
        timer.comparator = comparator;
        timer.armed = true;
        timer.expired = false;
        if timer.config & TIMER_PERIODIC != 0 {
            // Periodic reload: the distance to the comparator at the time of
            // the write is the period added at every expiration.
            let period = comparator.wrapping_sub(self.counter);
            timer.period = period.max(1);
        }
        self.timers[index] = timer;
    }

    /// Applies a timer configuration write.
    fn write_timer_config(&mut self, index: usize, value: u32) {
        let mut timer = self.timers[index];
        let was_periodic = timer.config & TIMER_PERIODIC != 0;
        timer.config = (timer.config & !TIMER_WRITABLE) | (value & TIMER_WRITABLE);
        let is_periodic = timer.config & TIMER_PERIODIC != 0;
        if is_periodic && !was_periodic {
            // Periodic mode just enabled: derive the reload period from the
            // comparator written by the guest.
            let period = timer.comparator.wrapping_sub(self.counter);
            timer.period = period.max(1);
            timer.expired = false;
            timer.armed = true;
        } else if !is_periodic {
            timer.expired = false;
        }
        self.timers[index] = timer;
    }

    /// Timer index of a configuration register offset.
    fn timer_config_index(&self, offset: u16) -> Option<usize> {
        let base = offset.checked_sub(COMPARATOR_BASE)?;
        if base % COMPARATOR_STRIDE != 0 {
            return None;
        }
        let index = (base / COMPARATOR_STRIDE) as usize;
        (index < TIMER_COUNT).then_some(index)
    }

    fn timer_for_config(&self, offset: u16) -> Option<&Timer> {
        self.timer_config_index(offset)
            .and_then(|index| self.timers.get(index))
    }

    fn timer_for_config_index(&self, offset: u16) -> Option<usize> {
        self.timer_config_index(offset)
    }

    /// Timer index of a comparator register offset (`base + 0x08`).
    fn comparator_index(&self, offset: u16) -> Option<usize> {
        let base = offset.checked_sub(COMPARATOR_BASE + 0x08)?;
        if base % COMPARATOR_STRIDE != 0 {
            return None;
        }
        let index = (base / COMPARATOR_STRIDE) as usize;
        (index < TIMER_COUNT).then_some(index)
    }

    fn timer_for_comparator(&self, offset: u16) -> Option<&Timer> {
        self.comparator_index(offset)
            .and_then(|index| self.timers.get(index))
    }

    fn timer_for_comparator_index(&self, offset: u16) -> Option<usize> {
        self.comparator_index(offset)
    }

    /// Timer index of a comparator low-double-word read (`base + 0x08`).
    fn comparator_low_index(&self, offset: u16) -> Option<usize> {
        self.comparator_index(offset)
    }

    fn timer_for_comparator_low(&self, offset: u16) -> Option<&Timer> {
        self.comparator_low_index(offset)
            .and_then(|index| self.timers.get(index))
    }

    fn timer_for_comparator_low_index(&self, offset: u16) -> Option<usize> {
        self.comparator_low_index(offset)
    }

    /// Timer index of a comparator high-double-word read (`base + 0x0C`).
    fn comparator_high_index(&self, offset: u16) -> Option<usize> {
        let base = offset.checked_sub(COMPARATOR_BASE + 0x0C)?;
        if base % COMPARATOR_STRIDE != 0 {
            return None;
        }
        let index = (base / COMPARATOR_STRIDE) as usize;
        (index < TIMER_COUNT).then_some(index)
    }

    fn timer_for_comparator_high(&self, offset: u16) -> Option<&Timer> {
        self.comparator_high_index(offset)
            .and_then(|index| self.timers.get(index))
    }

    fn timer_for_comparator_high_index(&self, offset: u16) -> Option<usize> {
        self.comparator_high_index(offset)
    }
}

impl Default for Hpet {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ACPI HPET description table
// ---------------------------------------------------------------------------

/// ACPI signature of the HPET description table.
pub const TABLE_SIGNATURE: [u8; 4] = *b"HPET";
/// ACPI revision written in the HPET table header.
pub const TABLE_REVISION: u8 = 1;
/// Length of the emitted HPET description table, in bytes.
///
/// 36-byte header + 12-byte address structure + 2-byte HPET number +
/// 2-byte minimum tick + 1-byte page protection + 3 reserved bytes.
pub const TABLE_LEN: usize = 56;
/// OEM identifier of the emitted table.
pub const TABLE_OEM_ID: [u8; 6] = *b"S9VM  ";
/// OEM table identifier of the emitted table.
pub const TABLE_OEM_TABLE_ID: [u8; 8] = *b"S9VMHPET";
/// OEM revision of the emitted table.
pub const TABLE_OEM_REVISION: u32 = 1;
/// Creator identifier of the emitted table.
pub const TABLE_CREATOR_ID: [u8; 4] = *b"S9VM";
/// Creator revision of the emitted table.
pub const TABLE_CREATOR_REVISION: u32 = 1;
/// Address structure: address space id 0 (system memory).
pub const GAS_ADDRESS_SPACE_ID: u8 = 0;
/// Address structure: register bit width (64-bit registers).
pub const GAS_REGISTER_BIT_WIDTH: u8 = 64;
/// Address structure: register bit offset.
pub const GAS_REGISTER_BIT_OFFSET: u8 = 0;
/// Address structure: access size 0 (undefined / any).
pub const GAS_ACCESS_SIZE: u8 = 0;
/// HPET number field of the table.
pub const TABLE_HPET_NUMBER: u16 = 0;
/// Minimum tick field of the table, in 100 ns units.
///
/// 0x0055 (85 x 100 ns = 8.5 us) is the architectural value PC-compatible
/// firmware advertises as the minimum periodic interval. It is comfortably
/// above one HPET clock period ([`PERIOD_FS`] ~= 69.8 ns), so a periodic
/// comparator programmed with it can fire; see
/// [`minimum_tick_from_period`] for the mathematical lower bound in the same
/// units.
pub const TABLE_MINIMUM_TICK: u16 = 0x0055;
/// Page protection field of the table (0 = none).
pub const TABLE_PAGE_PROTECTION: u8 = 0;

/// Writes a little-endian 16-bit value.
fn put_u16(buffer: &mut [u8], offset: usize, value: u16) {
    let bytes = value.to_le_bytes();
    buffer[offset] = bytes[0];
    buffer[offset + 1] = bytes[1];
}

/// Writes a little-endian 32-bit value.
fn put_u32(buffer: &mut [u8], offset: usize, value: u32) {
    let bytes = value.to_le_bytes();
    buffer[offset..offset + 4].copy_from_slice(&bytes);
}

/// Writes a little-endian 64-bit value.
fn put_u64(buffer: &mut [u8], offset: usize, value: u64) {
    let bytes = value.to_le_bytes();
    buffer[offset..offset + 8].copy_from_slice(&bytes);
}

/// Computes the ACPI checksum that makes the table sum to zero modulo 256.
fn checksum(table: &[u8]) -> u8 {
    let mut sum = 0u8;
    for byte in table {
        sum = sum.wrapping_add(*byte);
    }
    0u8.wrapping_sub(sum)
}

/// Builds the ACPI HPET description table.
///
/// The returned bytes are the exact table contents: header, address
/// structure, HPET number, minimum tick, page protection and reserved
/// padding, with a checksum making the byte sum zero.
pub fn table_bytes() -> [u8; TABLE_LEN] {
    let mut table = [0u8; TABLE_LEN];

    // Standard ACPI table header (36 bytes).
    table[0..4].copy_from_slice(&TABLE_SIGNATURE);
    put_u32(&mut table, 4, TABLE_LEN as u32);
    table[8] = TABLE_REVISION;
    table[9] = 0; // checksum computed last
    table[10..16].copy_from_slice(&TABLE_OEM_ID);
    table[16..24].copy_from_slice(&TABLE_OEM_TABLE_ID);
    put_u32(&mut table, 24, TABLE_OEM_REVISION);
    table[28..32].copy_from_slice(&TABLE_CREATOR_ID);
    put_u32(&mut table, 32, TABLE_CREATOR_REVISION);

    // Generic address structure (12 bytes) at offset 36.
    table[36] = GAS_ADDRESS_SPACE_ID;
    table[37] = GAS_REGISTER_BIT_WIDTH;
    table[38] = GAS_REGISTER_BIT_OFFSET;
    table[39] = GAS_ACCESS_SIZE;
    put_u64(&mut table, 40, BASE_GPA);

    // HPET-specific fields.
    put_u16(&mut table, 48, TABLE_HPET_NUMBER);
    put_u16(&mut table, 50, TABLE_MINIMUM_TICK);
    table[52] = TABLE_PAGE_PROTECTION;
    // Bytes 53..56 are reserved padding and already zero.

    table[9] = checksum(&table);
    table
}
