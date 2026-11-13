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

//! s9vm : pure model of the guest local APIC (xAPIC / x2APIC).
//!
//! This module models the minimal architectural state of a local APIC: MMIO
//! registers (4 KiB page), x2APIC registers (MSRs), IRR/ISR, priority (TPR/PPR),
//! EOI and IPI. It **touches no hardware**: the kernel layer reads/writes
//! the registers to emulate guest accesses and decide injections.
//!
//! The encodings come from the Intel documentation (SDM vol. 3A, chapter
//! "Advanced Programmable Interrupt Controller"). No constant specific to
//! a particular hypervisor is used.
//!
//! ## Injection policy
//!
//! The model is deliberately kept separate from the control block's interrupt
//! windows: it answers "which interrupt is deliverable?" via
//! [`LocalApic::pending_vector`], and the caller decides when (RFLAGS.IF,
//! interrupt window, etc.). Architectural priority is honored:
//! the smallest priority class strictly greater than the PPR, then the
//! smallest vector of that class.
//!
//! ## Local vector timer
//!
//! The local APIC timer is modeled with the architectural registers: the LVT
//! timer entry (`0x320`, vector/mask/mode), the initial count (`0x380`), the
//! read-only current count (`0x390`) and the divide configuration (`0x3E0`).
//! Counts are expressed in **APIC timer units**: one unit is one tick of the
//! APIC bus clock after the divide configuration has been applied. The model
//! is pure, so it cannot read the bus clock. Two helpers exist:
//!
//! - [`LocalApic::advance`] is the raw model helper: the caller passes elapsed
//!   time already expressed in APIC timer input units (bus ticks before the
//!   divide) and the model TSC advances by the same value;
//! - [`LocalApic::advance_tsc`] is the host-facing helper: the caller passes
//!   host TSC cycles and the TSC frequency, and the model converts them to
//!   APIC input ticks with the configured nominal bus frequency
//!   ([`DEFAULT_APIC_BUS_HZ`], overridable with
//!   [`LocalApic::set_apic_bus_hz`]) before applying the divide. The model TSC
//!   used by TSC-deadline mode always advances by the raw TSC cycles.
//!
//! Conversion formula: `bus_ticks = tsc_cycles * bus_hz / tsc_hz`, computed
//! with a remainder carried across calls so that a slow bus clock does not
//! lose ticks; the count-based timer then divides `bus_ticks` by the
//! architectural divide value. Arithmetic saturates, and a zero `tsc_hz` or a
//! zero bus frequency disables the count conversion instead of dividing by
//! zero.
//!
//! The real APIC bus clock is not discoverable from the model, so the guest
//! timer period remains **approximate**: it is correct to the extent that the
//! nominal bus frequency matches the host. This limitation is what
//! [`DEFAULT_APIC_BUS_HZ`] documents; a caller that knows the host bus clock
//! must configure it explicitly.
//!
//! Supported modes:
//!
//! - one-shot: expires once, raises the LVT vector, then stays stopped;
//! - periodic: reloads the initial count at every expiry and raises the
//!   LVT vector again;
//! - TSC-deadline: the `IA32_TSC_DEADLINE` MSR (`0x6E0`) sets an absolute
//!   deadline in model-TSC units. The model TSC is advanced by
//!   [`LocalApic::advance`] and can be aligned once with
//!   [`LocalApic::set_tsc`] if the caller knows the guest TSC epoch.
//!
//! A masked LVT entry keeps counting (and keeps reloading in periodic mode)
//! but does not raise a vector. Writing an initial count of zero disables the
//! timer. All arithmetic saturates; the divide configuration is decoded with
//! the architectural encoding and never divides by zero.

/// Size of the local APIC MMIO page.
pub const PAGE_SIZE: usize = 0x1000;

/// Offsets of the xAPIC MMIO registers.
pub mod reg {
    pub const ID: usize = 0x020;
    pub const VERSION: usize = 0x030;
    pub const TPR: usize = 0x080;
    pub const PPR: usize = 0x0A0;
    pub const EOI: usize = 0x0B0;
    pub const LDR: usize = 0x0D0;
    pub const DFR: usize = 0x0E0;
    pub const SVR: usize = 0x0F0;
    pub const ISR: usize = 0x100;
    pub const TMR: usize = 0x180;
    pub const IRR: usize = 0x200;
    pub const ESR: usize = 0x280;
    pub const ICR_LOW: usize = 0x300;
    pub const ICR_HIGH: usize = 0x310;
    pub const LVT_TIMER: usize = 0x320;
    pub const LVT_THERMAL: usize = 0x330;
    pub const LVT_PERF: usize = 0x340;
    pub const LVT_LINT0: usize = 0x350;
    pub const LVT_LINT1: usize = 0x360;
    pub const LVT_ERROR: usize = 0x370;
    pub const INITIAL_COUNT: usize = 0x380;
    pub const CURRENT_COUNT: usize = 0x390;
    pub const DIVIDE_CONFIG: usize = 0x3E0;
    pub const SELF_IPI: usize = 0x3F0;
}

/// x2APIC registers exposed by `RDMSR`/`WRMSR`.
pub mod x2apic {
    pub const ID: u32 = 0x802;
    pub const VERSION: u32 = 0x803;
    pub const TPR: u32 = 0x808;
    pub const PPR: u32 = 0x80A;
    pub const EOI: u32 = 0x80B;
    pub const LDR: u32 = 0x80D;
    pub const DFR: u32 = 0x80E;
    pub const SVR: u32 = 0x80F;
    pub const ISR: u32 = 0x810;
    pub const IRR: u32 = 0x820;
    pub const ESR: u32 = 0x828;
    pub const ICR: u32 = 0x830;
    pub const LVT_TIMER: u32 = 0x832;
    pub const INITIAL_COUNT: u32 = 0x838;
    pub const CURRENT_COUNT: u32 = 0x839;
    pub const DIVIDE_CONFIG: u32 = 0x83E;
    pub const SELF_IPI: u32 = 0x83F;
}

/// Advertised hardware version (integrated xAPIC family, 6 LVTs).
pub const VERSION_VALUE: u32 = 0x0005_0014;
/// Spurious register: enabled, vector 0xFF.
pub const SVR_DEFAULT: u32 = 0x0000_01FF;
/// Vector of the spurious register.
pub const SPURIOUS_VECTOR: u8 = 0xFF;
/// Enable bit of the spurious register.
pub const SVR_ENABLE: u32 = 1 << 8;
/// `IA32_TSC_DEADLINE` MSR used by the LVT TSC-deadline timer mode.
pub const TSC_DEADLINE_MSR: u32 = 0x6E0;

/// Default nominal APIC timer bus frequency, in hertz.
///
/// The architectural APIC bus clock is not discoverable from the pure model,
/// so s9vm uses a documented nominal policy: 100 MHz, the common PC-chipset
/// APIC bus frequency. The guest timer period is exact only to the extent that
/// this nominal value matches the host; a caller that knows the real bus clock
/// overrides it with [`LocalApic::set_apic_bus_hz`].
pub const DEFAULT_APIC_BUS_HZ: u64 = 100_000_000;

/// LVT timer mask bit (bit 16 of the LVT timer entry).
pub const LVT_MASK: u32 = 1 << 16;
/// LVT timer mode field (bits 18:17).
pub const LVT_MODE_SHIFT: u32 = 17;
/// LVT timer mode field mask.
pub const LVT_MODE_MASK: u32 = 0x3 << LVT_MODE_SHIFT;

/// Operating mode of the local vector timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerMode {
    /// One-shot: the count expires once and the timer stops.
    OneShot,
    /// Periodic: the initial count is reloaded at every expiry.
    Periodic,
    /// TSC-deadline: an absolute model-TSC deadline drives the expiry.
    TscDeadline,
    /// Reserved encoding: the timer does not count and raises nothing.
    Reserved,
}

/// Delivery mode in the ICR register (bits 10:8).
pub mod delivery {
    pub const FIXED: u32 = 0;
    pub const LOWEST: u32 = 1;
    pub const SMI: u32 = 2;
    pub const NMI: u32 = 4;
    pub const INIT: u32 = 5;
    pub const STARTUP: u32 = 6;
}

/// Shorthand destination in the ICR register (bits 19:18).
pub mod shorthand {
    pub const NO_SHORTHAND: u32 = 0;
    pub const SELF: u32 = 1;
    pub const ALL_INCLUDING_SELF: u32 = 2;
    pub const ALL_EXCLUDING_SELF: u32 = 3;
}

/// Complete state of a guest local APIC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalApic {
    /// APIC identifier (ID register, 8 significant bits in field 31:24).
    id: u32,
    /// Task priority (TPR), bits 7:0 significant.
    tpr: u8,
    /// Spurious register (SVR).
    svr: u32,
    /// Error status register.
    esr: u32,
    /// In-Service registers (8 x 32 bits = 256 vectors).
    isr: [u32; 8],
    /// In-Request registers (8 x 32 bits = 256 vectors).
    irr: [u32; 8],
    /// LVT: timer, thermal, perf, LINT0, LINT1, error.
    lvt: [u32; 6],
    /// ICR low/high.
    icr_low: u32,
    icr_high: u32,
    /// Initial and current timer count.
    initial_count: u32,
    current_count: u32,
    /// Timer divider.
    divide_config: u32,
    /// True while a one-shot/periodic count is running.
    timer_armed: bool,
    /// Sub-tick remainder of the divide scaling, in APIC timer input units.
    timer_fraction: u64,
    /// Nominal APIC timer bus frequency used by [`LocalApic::advance_tsc`].
    apic_bus_hz: u64,
    /// Remainder of the TSC-to-bus-tick conversion, in TSC cycles.
    tsc_fraction: u64,
    /// Monotonic model TSC, advanced by [`LocalApic::advance`].
    tsc: u64,
    /// Absolute TSC-deadline value written to `IA32_TSC_DEADLINE`.
    tsc_deadline: u64,
    /// True while the TSC-deadline timer is armed.
    tsc_deadline_armed: bool,
}

impl LocalApic {
    /// Creates a local APIC for `apic_id`, LVTs masked, SVR enabled.
    pub const fn new(apic_id: u32) -> Self {
        Self {
            id: (apic_id & 0xFF) << 24,
            tpr: 0,
            svr: SVR_DEFAULT,
            esr: 0,
            isr: [0; 8],
            irr: [0; 8],
            lvt: [0x0001_0000; 6],
            icr_low: 0,
            icr_high: 0,
            initial_count: 0,
            current_count: 0,
            divide_config: 0,
            timer_armed: false,
            timer_fraction: 0,
            apic_bus_hz: DEFAULT_APIC_BUS_HZ,
            tsc_fraction: 0,
            tsc: 0,
            tsc_deadline: 0,
            tsc_deadline_armed: false,
        }
    }

    /// APIC identifier (8-bit value, not shifted).
    pub const fn apic_id(&self) -> u32 {
        self.id >> 24
    }

    /// Current task priority.
    pub const fn tpr(&self) -> u8 {
        self.tpr
    }

    /// Processor priority (TPR and ISR combined), on 8 bits.
    pub fn ppr(&self) -> u8 {
        let mut ppr = self.tpr;
        for index in (0..8).rev() {
            if self.isr[index] != 0 {
                // The PPR is a class priority: the low nibble of the
                // highest in-service vector is ignored.
                ppr = ppr.max(highest_vector(index, self.isr[index]) & 0xF0);
                break;
            }
        }
        ppr
    }

    /// True if the spurious register enables interrupts.
    pub const fn enabled(&self) -> bool {
        self.svr & SVR_ENABLE != 0
    }

    /// True if at least one vector is pending.
    pub fn has_pending(&self) -> bool {
        self.irr.iter().any(|word| *word != 0)
    }

    /// Injects a vector into the IRR (idempotent).
    pub fn inject(&mut self, vector: u8) {
        self.irr[(vector as usize) >> 5] |= 1 << (vector & 31);
    }

    /// Highest-priority deliverable vector, without modifying the state.
    pub fn pending_vector(&self) -> Option<u8> {
        if !self.enabled() {
            return None;
        }
        let ppr = self.ppr();
        let ppr_class = priority_class(u32::from(ppr));
        let mut best: Option<u8> = None;
        for index in 0..8u8 {
            let mut word = self.irr[index as usize];
            while word != 0 {
                let bit = word.trailing_zeros() as u8;
                let vector = index * 32 + bit;
                word &= word - 1;
                if vector < 16 {
                    continue;
                }
                let class = priority_class(u32::from(vector));
                // Priority strictly greater than the PPR: the class must be
                // greater (vectors of the same class are blocked,
                // as required by the architecture).
                if class > ppr_class {
                    best = Some(match best {
                        Some(current) => current.min(vector),
                        None => vector,
                    });
                }
            }
        }
        best
    }

    /// Moves the deliverable vector from the IRR to the ISR and returns it.
    pub fn service(&mut self) -> Option<u8> {
        let vector = self.pending_vector()?;
        self.irr[(vector as usize) >> 5] &= !(1 << (vector & 31));
        self.isr[(vector as usize) >> 5] |= 1 << (vector & 31);
        Some(vector)
    }

    /// Records an EOI: removes the highest-priority vector from the ISR.
    pub fn eoi(&mut self) {
        for index in (0..8).rev() {
            let word = self.isr[index];
            if word != 0 {
                let bit = 31 - word.leading_zeros() as usize;
                self.isr[index] &= !(1u32 << bit);
                return;
            }
        }
    }

    /// True if a vector is in service.
    pub fn in_service(&self) -> bool {
        self.isr.iter().any(|word| *word != 0)
    }

    /// Vector programmed in the LVT timer entry.
    pub const fn timer_vector(&self) -> u8 {
        (self.lvt[0] & 0xFF) as u8
    }

    /// True if the LVT timer entry is masked.
    pub const fn timer_masked(&self) -> bool {
        self.lvt[0] & LVT_MASK != 0
    }

    /// Operating mode of the timer, decoded from the LVT entry.
    pub const fn timer_mode(&self) -> TimerMode {
        match (self.lvt[0] & LVT_MODE_MASK) >> LVT_MODE_SHIFT {
            0 => TimerMode::OneShot,
            1 => TimerMode::Periodic,
            2 => TimerMode::TscDeadline,
            _ => TimerMode::Reserved,
        }
    }

    /// Current divide value decoded from the divide configuration register.
    pub const fn timer_divide(&self) -> u32 {
        divide_value(self.divide_config)
    }

    /// True while either count-based or TSC-deadline timer is running.
    pub const fn timer_armed(&self) -> bool {
        self.timer_armed || self.tsc_deadline_armed
    }

    /// Current timer count (`0` once a one-shot timer has expired).
    pub const fn current_count(&self) -> u32 {
        self.current_count
    }

    /// Last value written to the initial-count register.
    pub const fn initial_count(&self) -> u32 {
        self.initial_count
    }

    /// Absolute TSC-deadline value last written to `IA32_TSC_DEADLINE`.
    pub const fn tsc_deadline(&self) -> u64 {
        self.tsc_deadline
    }

    /// Programs the timer with `initial_count` (`0` disables it).
    ///
    /// In one-shot and periodic modes this loads the current count and starts
    /// counting. In TSC-deadline and reserved modes the register is stored but
    /// the count-based timer stays stopped, matching the architectural rule
    /// that the initial count is ignored in TSC-deadline mode.
    pub fn arm(&mut self, initial_count: u32) {
        self.initial_count = initial_count;
        self.timer_fraction = 0;
        match self.timer_mode() {
            TimerMode::OneShot | TimerMode::Periodic => {
                self.current_count = initial_count;
                self.timer_armed = initial_count != 0;
            }
            TimerMode::TscDeadline | TimerMode::Reserved => {
                self.current_count = 0;
                self.timer_armed = false;
            }
        }
    }

    /// Writes the `IA32_TSC_DEADLINE` MSR.
    ///
    /// A zero value disables the deadline. The value is absolute in model-TSC
    /// units; a deadline already in the past raises the LVT vector immediately
    /// (unless masked). Writes are ignored for the timer state unless the LVT
    /// entry is in TSC-deadline mode.
    pub fn set_tsc_deadline(&mut self, deadline: u64) {
        self.tsc_deadline = deadline;
        self.tsc_deadline_armed = false;
        if deadline == 0 || self.timer_mode() != TimerMode::TscDeadline {
            return;
        }
        self.tsc_deadline_armed = true;
        if self.tsc >= deadline {
            self.expire_tsc_deadline();
        }
    }

    /// Aligns the model TSC with a caller-known absolute value.
    ///
    /// The model starts at zero and is normally advanced by
    /// [`Self::advance`]; this hook lets a caller that knows the guest TSC
    /// epoch seed it once, so absolute `IA32_TSC_DEADLINE` values can be
    /// interpreted.
    pub fn set_tsc(&mut self, tsc: u64) {
        self.tsc = tsc;
        if self.tsc_deadline_armed && self.tsc >= self.tsc_deadline {
            self.expire_tsc_deadline();
        }
    }

    /// Advances the timer by `cycles` APIC timer input units.
    ///
    /// The caller passes the elapsed time already expressed in APIC timer
    /// input units (bus ticks before the divide). Count-based modes divide it
    /// by the configured divide value and decrement the current count;
    /// TSC-deadline mode compares the model TSC with the programmed deadline.
    /// Expiry raises the LVT vector through the IRR, except when the LVT entry
    /// is masked.
    ///
    /// This is the raw model helper, kept for tests and for callers that
    /// already work in bus ticks. A caller holding host TSC cycles and a TSC
    /// frequency must use [`Self::advance_tsc`], which performs the
    /// conversion.
    pub fn advance(&mut self, cycles: u64) {
        self.tsc = self.tsc.saturating_add(cycles);
        if self.tsc_deadline_armed && self.tsc >= self.tsc_deadline {
            self.expire_tsc_deadline();
        }
        if !self.timer_armed {
            return;
        }
        match self.timer_mode() {
            TimerMode::OneShot | TimerMode::Periodic => self.advance_count(cycles),
            TimerMode::TscDeadline | TimerMode::Reserved => self.timer_armed = false,
        }
    }

    /// Nominal APIC timer bus frequency, in hertz.
    pub const fn apic_bus_hz(&self) -> u64 {
        self.apic_bus_hz
    }

    /// Changes the nominal APIC timer bus frequency.
    ///
    /// The conversion remainder is reset because its unit depends on the bus
    /// frequency. A zero value disables the count-based conversion of
    /// [`Self::advance_tsc`] (the model TSC still advances).
    pub fn set_apic_bus_hz(&mut self, bus_hz: u64) {
        self.apic_bus_hz = bus_hz;
        self.tsc_fraction = 0;
    }

    /// Advances the model by host TSC `cycles`, converting to APIC ticks.
    ///
    /// `tsc_hz` is the host TSC frequency in hertz. The count-based timer is
    /// decremented by:
    ///
    /// `bus_ticks = (cycles * apic_bus_hz + remainder) / tsc_hz`
    ///
    /// where `remainder` is carried across calls so that the average
    /// conversion rate stays exact even when a call spans less than one bus
    /// tick. The model TSC used by TSC-deadline mode advances by the raw
    /// `cycles`, without conversion: a deadline is an absolute TSC value.
    ///
    /// A zero `tsc_hz` or a zero bus frequency disables the count conversion
    /// (the model TSC still advances and deadlines are still detected), so a
    /// caller without a detected frequency degrades gracefully instead of
    /// dividing by zero. Arithmetic saturates.
    pub fn advance_tsc(&mut self, cycles: u64, tsc_hz: u64) {
        self.tsc = self.tsc.saturating_add(cycles);
        if self.tsc_deadline_armed && self.tsc >= self.tsc_deadline {
            self.expire_tsc_deadline();
        }
        if !self.timer_armed {
            return;
        }
        match self.timer_mode() {
            TimerMode::OneShot | TimerMode::Periodic => {
                if tsc_hz == 0 || self.apic_bus_hz == 0 {
                    return;
                }
                let numerator = u128::from(cycles)
                    .saturating_mul(u128::from(self.apic_bus_hz))
                    .saturating_add(u128::from(self.tsc_fraction));
                let bus_ticks = numerator / u128::from(tsc_hz);
                self.tsc_fraction = (numerator % u128::from(tsc_hz)) as u64;
                let bus_ticks = if bus_ticks > u128::from(u64::MAX) {
                    u64::MAX
                } else {
                    bus_ticks as u64
                };
                self.advance_count(bus_ticks);
            }
            TimerMode::TscDeadline | TimerMode::Reserved => {}
        }
    }

    /// Decrements the count-based timer by the divided elapsed cycles.
    fn advance_count(&mut self, cycles: u64) {
        let divide = u64::from(self.timer_divide());
        let total = cycles.saturating_add(self.timer_fraction);
        let ticks = total / divide;
        self.timer_fraction = total % divide;
        if ticks == 0 {
            return;
        }

        match self.timer_mode() {
            TimerMode::OneShot => {
                let current = u64::from(self.current_count);
                if ticks >= current {
                    self.current_count = 0;
                    self.timer_armed = false;
                    self.raise_timer_vector();
                } else {
                    self.current_count = (current - ticks) as u32;
                }
            }
            TimerMode::Periodic => {
                let reload = self.initial_count;
                if reload == 0 {
                    self.current_count = 0;
                    self.timer_armed = false;
                    return;
                }
                let current = u64::from(self.current_count);
                if ticks < current {
                    self.current_count = (current - ticks) as u32;
                    return;
                }
                // One expiry at `current`, then one every `reload` ticks.
                let after_first = ticks - current;
                let remainder = after_first % u64::from(reload);
                self.current_count = reload - remainder as u32;
                self.timer_armed = true;
                self.raise_timer_vector();
            }
            TimerMode::TscDeadline | TimerMode::Reserved => self.timer_armed = false,
        }
    }

    /// Raises the LVT vector unless the entry is masked.
    fn raise_timer_vector(&mut self) {
        if !self.timer_masked() {
            let vector = self.timer_vector();
            self.inject(vector);
        }
    }

    /// Completes a TSC-deadline expiry.
    fn expire_tsc_deadline(&mut self) {
        self.tsc_deadline_armed = false;
        self.raise_timer_vector();
    }

    /// Applies a write to the LVT timer entry, keeping the timer state
    /// consistent with the newly selected mode.
    fn write_lvt_timer(&mut self, value: u32) {
        self.lvt[0] = value;
        match self.timer_mode() {
            TimerMode::TscDeadline => {
                self.timer_armed = false;
                // A deadline written before the mode was selected still
                // applies once the entry is switched to TSC-deadline mode.
                if self.tsc_deadline != 0 {
                    self.tsc_deadline_armed = true;
                    if self.tsc >= self.tsc_deadline {
                        self.expire_tsc_deadline();
                    }
                }
            }
            TimerMode::OneShot | TimerMode::Periodic => self.tsc_deadline_armed = false,
            TimerMode::Reserved => {
                self.timer_armed = false;
                self.tsc_deadline_armed = false;
            }
        }
    }

    /// Reads an MMIO register (address relative to the APIC page).
    ///
    /// Unimplemented offsets return 0 (guest access tolerated).
    pub fn mmio_read(&self, offset: usize) -> u32 {
        if let Some(index) = isr_index(offset, reg::ISR) {
            return self.isr[index];
        }
        if let Some(index) = isr_index(offset, reg::IRR) {
            return self.irr[index];
        }
        match offset {
            reg::ID => self.id,
            reg::VERSION => VERSION_VALUE,
            reg::TPR => u32::from(self.tpr),
            reg::PPR => u32::from(self.ppr()),
            reg::SVR => self.svr,
            reg::ESR => self.esr,
            reg::ICR_LOW => self.icr_low,
            reg::ICR_HIGH => self.icr_high,
            reg::INITIAL_COUNT => self.initial_count,
            reg::CURRENT_COUNT => self.current_count,
            reg::DIVIDE_CONFIG => self.divide_config,
            reg::LVT_TIMER => self.lvt[0],
            reg::LVT_THERMAL => self.lvt[1],
            reg::LVT_PERF => self.lvt[2],
            reg::LVT_LINT0 => self.lvt[3],
            reg::LVT_LINT1 => self.lvt[4],
            reg::LVT_ERROR => self.lvt[5],
            _ => 0,
        }
    }

    /// Writes an MMIO register. Unimplemented offsets are ignored.
    pub fn mmio_write(&mut self, offset: usize, value: u32) {
        match offset {
            reg::TPR => self.tpr = (value & 0xFF) as u8,
            reg::EOI => self.eoi(),
            reg::SVR => self.svr = value & 0x0000_01FF,
            reg::ESR => self.esr = value,
            reg::ICR_LOW => self.write_icr_low(value),
            reg::ICR_HIGH => self.icr_high = value & 0xFF00_0000,
            reg::INITIAL_COUNT => self.arm(value),
            reg::DIVIDE_CONFIG => self.divide_config = value & 0xB,
            reg::LVT_TIMER => self.write_lvt_timer(value),
            reg::LVT_THERMAL => self.lvt[1] = value,
            reg::LVT_PERF => self.lvt[2] = value,
            reg::LVT_LINT0 => self.lvt[3] = value,
            reg::LVT_LINT1 => self.lvt[4] = value,
            reg::LVT_ERROR => self.lvt[5] = value,
            reg::SELF_IPI => self.inject((value & 0xFF) as u8),
            _ => {}
        }
    }

    /// Handles an ICR-low write: fixed IPI to self or NMI.
    fn write_icr_low(&mut self, value: u32) {
        self.icr_low = value;
        let delivery_mode = (value >> 8) & 0x7;
        let destination = (value >> 18) & 0x3;
        let vector = (value & 0xFF) as u8;
        match (delivery_mode, destination) {
            (delivery::FIXED, shorthand::SELF) | (delivery::LOWEST, shorthand::SELF) => {
                self.inject(vector);
            }
            (delivery::NMI, _) | (delivery::INIT, _) | (delivery::STARTUP, _) => {
                // Handled outside the APIC (dedicated injection / reset): we
                // accept the write so that the guest can continue.
            }
            _ => {
                // External destination not modeled in P1 (a single guest CPU).
            }
        }
    }

    /// Reads an x2APIC MSR. Returns `None` outside the `0x800..=0x8FF` range.
    pub fn x2apic_read(&self, msr: u32) -> Option<u64> {
        if let Some(index) = isr_msr_index(msr, x2apic::ISR) {
            return Some(u64::from(self.isr[index]));
        }
        if let Some(index) = isr_msr_index(msr, x2apic::IRR) {
            return Some(u64::from(self.irr[index]));
        }
        let value: u64 = match msr {
            x2apic::ID => u64::from(self.id),
            x2apic::VERSION => u64::from(VERSION_VALUE),
            x2apic::TPR => u64::from(self.tpr),
            x2apic::PPR => u64::from(self.ppr()),
            x2apic::EOI => 0,
            x2apic::LDR => (u64::from(self.apic_id()) << 24) | 0x01_0000,
            x2apic::DFR => 0x0000_00FF,
            x2apic::SVR => u64::from(self.svr),
            x2apic::ESR => u64::from(self.esr),
            x2apic::ICR => ((self.icr_high as u64) << 32) | u64::from(self.icr_low),
            x2apic::LVT_TIMER => u64::from(self.lvt[0]),
            x2apic::INITIAL_COUNT => u64::from(self.initial_count),
            x2apic::CURRENT_COUNT => u64::from(self.current_count),
            x2apic::DIVIDE_CONFIG => u64::from(self.divide_config),
            _ => return None,
        };
        Some(value)
    }

    /// Writes an x2APIC MSR. Returns `false` if the MSR is not modeled.
    pub fn x2apic_write(&mut self, msr: u32, value: u64) -> bool {
        match msr {
            x2apic::TPR => self.tpr = (value & 0xFF) as u8,
            x2apic::EOI => self.eoi(),
            x2apic::SVR => self.svr = (value as u32) & 0x0000_01FF,
            x2apic::ESR => self.esr = value as u32,
            x2apic::ICR => {
                self.icr_high = (value >> 32) as u32;
                self.write_icr_low(value as u32);
            }
            x2apic::LVT_TIMER => self.write_lvt_timer(value as u32),
            x2apic::INITIAL_COUNT => self.arm(value as u32),
            x2apic::DIVIDE_CONFIG => self.divide_config = (value as u32) & 0xB,
            x2apic::SELF_IPI => self.inject((value & 0xFF) as u8),
            _ => return false,
        }
        true
    }
}

/// Highest vector of an ISR/IRR word (`index` = word 0..7).
fn highest_vector(index: usize, word: u32) -> u8 {
    (index as u8) * 32 + (31 - word.leading_zeros() as u8)
}

/// Index of an ISR/IRR register in MMIO (16-byte stride, 8 registers).
fn isr_index(offset: usize, base: usize) -> Option<usize> {
    if offset < base || offset >= base + 8 * 16 {
        return None;
    }
    let delta = offset - base;
    if delta % 16 != 0 {
        return None;
    }
    Some(delta / 16)
}

/// Index of an ISR/IRR register in x2APIC (8 consecutive MSRs).
fn isr_msr_index(msr: u32, base: u32) -> Option<usize> {
    if msr < base || msr >= base + 8 {
        return None;
    }
    Some((msr - base) as usize)
}

/// Priority class of a vector (bits 7:4).
pub const fn priority_class(vector: u32) -> u8 {
    ((vector >> 4) & 0xF) as u8
}

/// Decodes the divide configuration register into a divisor (never zero).
///
/// Architectural encoding (`bits 3, 1, 0`): `000` divides by 2, `001` by 4,
/// `010` by 8, `011` by 16, `100` by 32, `101` by 64, `110` by 128 and `111`
/// by 1. Bit 2 is reserved and ignored. Any unexpected value falls back to
/// the reset encoding (divide by 2), so this function is total.
pub const fn divide_value(config: u32) -> u32 {
    match config & 0xB {
        0 => 2,
        1 => 4,
        2 => 8,
        3 => 16,
        8 => 32,
        9 => 64,
        10 => 128,
        _ => 1,
    }
}
