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

//! s9vm : time-stamp counter frequency model.
//!
//! The s9vm timing aggregates are expressed in time-stamp counter (TSC)
//! cycles. Converting them to nanoseconds requires the TSC frequency, which is
//! a property of the **host CPU**: it is the same on every CPU of a host and,
//! when the TSC is invariant, it does not depend on the current P-state or on
//! deep C-states.
//!
//! # Sources, in priority order
//!
//! 1. CPUID leaf `0x15` (*Time Stamp Counter and Core Crystal Clock
//!    Information*): `TSC = crystal_hz * EBX / EAX`, when `EAX != 0`,
//!    `EBX != 0` and `ECX` (the core-crystal frequency in Hz) is non-zero.
//! 2. CPUID leaf `0x16` (*Processor Frequency Information*): `EAX` is the
//!    nominal base frequency in MHz. This is the documented fallback when the
//!    core-crystal frequency is not reported; it is a nominal value (no turbo,
//!    no downclocking) and is acceptable because an invariant TSC ticks at the
//!    base frequency.
//! 3. Otherwise the frequency is unknown: callers must keep displaying raw
//!    cycles.
//!
//! # Plausibility bounds
//!
//! A candidate outside [`MIN_HZ`]`..=`[`MAX_HZ`] is **ignored** (not clamped):
//! an implausible value almost always means a broken or emulated CPUID
//! response, and printing wrong nanoseconds is worse than printing none. The
//! accepted range, 100 MHz to 10 GHz, covers every x86-64 host this kernel
//! targets. If the leaf `0x15` candidate is implausible, leaf `0x16` is still
//! tried; if no candidate is plausible the result is `None`.
//!
//! # Cache
//!
//! The frequency is detected once : by the platform initialisation, or lazily
//! by the first diagnostic read when no value was published yet : and stored
//! with [`set`]; diagnostics then use [`get`] or [`cycles_to_ns`] and never
//! execute CPUID again. The cache is **write-once** (the first `set` wins): the
//! TSC frequency cannot change while the kernel runs, and a concurrent second
//! detection must not overwrite the first result.
//!
//! Everything in this module is pure arithmetic, with the single exception of
//! the global atomic cache: it has no hardware dependency and is host-testable.

use core::sync::atomic::{AtomicU64, Ordering};

// --- Constants -------------------------------------------------------------

/// Lowest plausible TSC frequency (100 MHz).
pub const MIN_HZ: u64 = 100_000_000;

/// Highest plausible TSC frequency (10 GHz).
pub const MAX_HZ: u64 = 10_000_000_000;

/// Bit 8 of CPUID leaf `0x8000_0007` EDX: the TSC is invariant.
pub const INVARIANT_TSC_BIT: u32 = 1 << 8;

/// Nanoseconds per second, as `u128` (intermediate products overflow `u64`).
const NS_PER_S: u128 = 1_000_000_000;

/// Hertz per megahertz.
const HZ_PER_MHZ: u64 = 1_000_000;

/// Sentinel of the global cache: zero means "not detected yet".
static FREQUENCY_HZ: AtomicU64 = AtomicU64::new(0);

// --- Frequency model -------------------------------------------------------

/// TSC frequency of the host, in hertz.
///
/// The constructor validates the value against [`MIN_HZ`]`..=`[`MAX_HZ`]; a
/// value obtained from this type is therefore always usable as a divisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TscFrequency {
    hz: u64,
}

impl TscFrequency {
    /// Builds a frequency from a hertz value, rejecting implausible values.
    pub const fn from_hz(hz: u64) -> Option<Self> {
        if hz < MIN_HZ || hz > MAX_HZ {
            None
        } else {
            Some(Self { hz })
        }
    }

    /// Detects the frequency from CPUID leaves `0x15` and `0x16`.
    ///
    /// The arguments are the four `u32` registers of each leaf in
    /// `[EAX, EBX, ECX, EDX]` order, so this function stays pure and testable
    /// on the host. Priority and validation are described at module level.
    /// Returns `None` when neither leaf yields a plausible frequency; it never
    /// panics, whatever the inputs.
    pub fn from_cpuid(leaf15: [u32; 4], leaf16: [u32; 4]) -> Option<Self> {
        if let Some(hz) = ratio_hz(leaf15) {
            if let Some(frequency) = Self::from_hz(hz) {
                return Some(frequency);
            }
        }
        let base_mhz = leaf16[0] as u64;
        if base_mhz != 0 {
            if let Some(hz) = base_mhz.checked_mul(HZ_PER_MHZ) {
                if let Some(frequency) = Self::from_hz(hz) {
                    return Some(frequency);
                }
            }
        }
        None
    }

    /// Frequency in hertz.
    pub const fn hz(self) -> u64 {
        self.hz
    }

    /// Frequency in megahertz, truncated towards zero.
    ///
    /// The truncation is documented because the value is only used for
    /// human-readable diagnostics; the exact value is [`Self::hz`].
    pub const fn mhz(self) -> u64 {
        self.hz / HZ_PER_MHZ
    }

    /// Converts a cycle count to nanoseconds, rounded to the nearest integer.
    ///
    /// Rounds half up (`+ hz/2` before the division). Saturates at
    /// [`u64::MAX`] instead of overflowing; never divides by zero (the
    /// constructor guarantees a non-zero frequency).
    pub fn nanoseconds(self, cycles: u64) -> u64 {
        let numerator = (cycles as u128).saturating_mul(NS_PER_S);
        let rounded = numerator.saturating_add((self.hz as u128) / 2);
        let nanoseconds = rounded / (self.hz as u128);
        if nanoseconds > u64::MAX as u128 {
            u64::MAX
        } else {
            nanoseconds as u64
        }
    }

    /// Converts a duration in nanoseconds to a cycle count, rounded to the
    /// nearest integer.
    ///
    /// Rounds half up (`+ 5e8` before the division). Saturates at
    /// [`u64::MAX`] instead of overflowing. This is the inverse of
    /// [`Self::nanoseconds`] up to integer rounding.
    pub fn cycles(self, nanoseconds: u64) -> u64 {
        let numerator = (nanoseconds as u128).saturating_mul(self.hz as u128);
        let rounded = numerator.saturating_add(NS_PER_S / 2);
        let cycles = rounded / NS_PER_S;
        if cycles > u64::MAX as u128 {
            u64::MAX
        } else {
            cycles as u64
        }
    }
}

/// CPUID leaves that publish a [`TscFrequency`] to a guest.
///
/// These are the raw register values a CPUID replay returns:
///
/// | Field | Register | Meaning |
/// |---|---|---|
/// | [`ratio_denominator`](Self::ratio_denominator) | `0x15:EAX` | denominator of the TSC/crystal ratio |
/// | [`ratio_numerator`](Self::ratio_numerator) | `0x15:EBX` | numerator of the TSC/crystal ratio |
/// | [`crystal_hz`](Self::crystal_hz) | `0x15:ECX` | core-crystal frequency, in Hz |
/// | [`base_mhz`](Self::base_mhz) | `0x16:EAX` | nominal base frequency, in MHz |
///
/// A guest computes `TSC_HZ = crystal_hz * ratio_numerator / ratio_denominator`
/// and, when leaf `0x15` is unusable, falls back to `base_mhz * 1_000_000`.
/// A zeroed value therefore means "not published"; it is the default of
/// [`crate::s9vm::cpuid::CpuidPolicy`] and is replaced either by an explicit
/// policy or by the host frequency cache.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CpuidTscLeaves {
    /// `CPUID.0x15:EAX` : ratio denominator (never zero in a valid value).
    pub ratio_denominator: u32,
    /// `CPUID.0x15:EBX` : ratio numerator (never zero in a valid value).
    pub ratio_numerator: u32,
    /// `CPUID.0x15:ECX` : core-crystal frequency, in hertz.
    pub crystal_hz: u32,
    /// `CPUID.0x16:EAX` : nominal base frequency, in megahertz.
    pub base_mhz: u32,
}

/// Crystal frequency used to build an exact ratio, in hertz.
///
/// One gigahertz fits in a `u32` and, being `2^9 * 5^9`, reduces most TSC
/// frequencies (which are usually multiples of 100 MHz) to a small exact
/// numerator. The guest computes `crystal_hz * numerator / denominator`, so an
/// exact reduction gives the exact frequency.
pub const CPUID_CRYSTAL_HZ: u32 = 1_000_000_000;

/// Crystal frequency of the approximate fallback representation, in hertz.
///
/// Used only when the exact 1 GHz representation does not fit the 32-bit
/// numerator (frequencies above about 4.29 GHz whose value is coprime with
/// 1 GHz). The published frequency is then truncated to the nearest lower
/// megahertz, an error below 1 MHz.
pub const CPUID_FALLBACK_CRYSTAL_HZ: u32 = 1_000_000;

impl TscFrequency {
    /// Derives the CPUID leaves that publish this frequency to a guest.
    ///
    /// The representation is exact whenever `hz / gcd(hz, 1 GHz)` fits in 32
    /// bits, which covers every frequency up to about 4.29 GHz and many higher
    /// ones (for example 10 GHz reduces to `10/1`). Otherwise the frequency is
    /// published with a 1 MHz crystal and a numerator truncated to the lower
    /// megahertz: the guest then computes a frequency off by less than 1 MHz,
    /// that is less than 0.001 % at 3 GHz.
    ///
    /// `base_mhz` is always the truncated megahertz value, as leaf `0x16`
    /// specifies an integer number of megahertz. A guest that has both leaves
    /// can cross-check them.
    pub fn cpuid_leaves(self) -> CpuidTscLeaves {
        let crystal = u64::from(CPUID_CRYSTAL_HZ);
        let divisor = greatest_common_divisor(self.hz, crystal);
        let numerator = self.hz / divisor;
        let denominator = crystal / divisor;
        let base_mhz = self.mhz();
        if numerator <= u64::from(u32::MAX) && denominator <= u64::from(u32::MAX) {
            CpuidTscLeaves {
                ratio_denominator: denominator as u32,
                ratio_numerator: numerator as u32,
                crystal_hz: CPUID_CRYSTAL_HZ,
                base_mhz: base_mhz.min(u64::from(u32::MAX)) as u32,
            }
        } else {
            let megahertz = base_mhz.min(u64::from(u32::MAX)) as u32;
            CpuidTscLeaves {
                ratio_denominator: 1,
                ratio_numerator: megahertz,
                crystal_hz: CPUID_FALLBACK_CRYSTAL_HZ,
                base_mhz: megahertz,
            }
        }
    }
}

/// Greatest common divisor of two non-zero values (Euclid).
fn greatest_common_divisor(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    if left == 0 {
        1
    } else {
        left
    }
}

/// Computes the frequency from CPUID leaf `0x15`, if the crystal is reported.
///
/// Returns `None` when the ratio is absent (`EAX == 0` or `EBX == 0`) or when
/// the core-crystal frequency (`ECX`) is zero; in both cases the caller falls
/// back to leaf `0x16`. The multiplication is done in `u128` so that a
/// hostile CPUID response cannot overflow; a result larger than `u64::MAX`
/// saturates and is then rejected by the plausibility bounds.
fn ratio_hz(leaf15: [u32; 4]) -> Option<u64> {
    let denominator = leaf15[0] as u64;
    let numerator = leaf15[1] as u64;
    let crystal_hz = leaf15[2] as u64;
    if denominator == 0 || numerator == 0 || crystal_hz == 0 {
        return None;
    }
    let scaled = (crystal_hz as u128).checked_mul(numerator as u128)?;
    let hz = scaled / denominator as u128;
    if hz > u64::MAX as u128 {
        Some(u64::MAX)
    } else {
        Some(hz as u64)
    }
}

/// True when CPUID leaf `0x8000_0007` EDX reports an invariant TSC.
///
/// The flag is informational: the frequency model does not need it, but
/// diagnostics use it to warn when cycle-to-nanosecond conversions may drift
/// with the P-state or deep C-states.
pub const fn is_invariant(extended_edx: u32) -> bool {
    extended_edx & INVARIANT_TSC_BIT != 0
}

// --- Global cache ----------------------------------------------------------

/// Detects the frequency from the two CPUID leaves without touching the cache.
///
/// Thin wrapper over [`TscFrequency::from_cpuid`] for platform code that reads
/// the leaves itself; kept separate so that detection and storage have
/// distinct call sites.
pub fn detect(leaf15: [u32; 4], leaf16: [u32; 4]) -> Option<TscFrequency> {
    TscFrequency::from_cpuid(leaf15, leaf16)
}

/// Stores the detected frequency in the global cache.
///
/// Write-once: if a value is already present, the call is ignored. This keeps
/// concurrent detections deterministic (the first writer wins) and guarantees
/// that a diagnostic reader never observes a frequency changing under it.
pub fn set(frequency: TscFrequency) {
    let _ = FREQUENCY_HZ.compare_exchange(0, frequency.hz(), Ordering::AcqRel, Ordering::Acquire);
}

/// Returns the cached host TSC frequency, or `None` when it was never set.
pub fn get() -> Option<TscFrequency> {
    let hz = FREQUENCY_HZ.load(Ordering::Acquire);
    if hz == 0 {
        None
    } else {
        TscFrequency::from_hz(hz)
    }
}

/// Converts TSC cycles to nanoseconds using the cached frequency.
///
/// Returns `None` when the frequency is unknown, so that callers can fall back
/// to displaying raw cycles instead of inventing a conversion.
pub fn cycles_to_ns(cycles: u64) -> Option<u64> {
    get().map(|frequency| frequency.nanoseconds(cycles))
}
