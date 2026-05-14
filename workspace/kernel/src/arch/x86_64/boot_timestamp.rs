//! Boot timestamp : TSC-based elapsed time from kernel entry.
//!
//! Captures `rdtsc()` at the very start of `kernel_main` and exposes
//! `elapsed_ms()` / `elapsed_us()` for boot milestone logging.
//!
//! Before APIC timer calibration the TSC frequency is unknown, so we
//! use a conservative default (2 GHz).  Call `calibrate()` once the
//! real frequency is known to get accurate readings.

use core::sync::atomic::{AtomicU64, Ordering};

/// TSC value captured at kernel entry.
static BOOT_TSC: AtomicU64 = AtomicU64::new(0);

/// TSC frequency in KHz.  Default 2_000_000 KHz (= 2 GHz) until calibrated.
static TSC_KHZ: AtomicU64 = AtomicU64::new(2_000_000);

/// Capture the boot TSC.  Must be called once, as early as possible.
pub fn init() {
    BOOT_TSC.store(super::rdtsc(), Ordering::Relaxed);
}

/// Refine TSC frequency after timer calibration.
///
/// `known_interval_ns` : duration of the reference interval in nanoseconds.
/// `tsc_delta`          : TSC ticks measured over that interval.
///
/// Example: if the APIC timer calibration measured 10 ms (10_000_000 ns)
/// and `tsc_delta` = 20_000_000 cycles  →  TSC runs at 2 GHz.
pub fn calibrate(known_interval_ns: u64, tsc_delta: u64) {
    if known_interval_ns == 0 || tsc_delta == 0 {
        return;
    }
    let khz = tsc_delta.saturating_mul(1_000_000) / known_interval_ns;
    calibrate_khz(khz);
}

/// Set TSC frequency directly (used for CPUID leaf 0x15 calibration).
pub fn calibrate_khz(khz: u64) {
    // Sanity check: reject absurdly low frequencies (< 100 MHz).
    const MIN_SANE_KHZ: u64 = 100_000;
    if khz >= MIN_SANE_KHZ {
        TSC_KHZ.store(khz, Ordering::Relaxed);
    }
}

/// TSC ticks elapsed since `init()`.
#[inline]
fn elapsed_tsc() -> u64 {
    let boot = BOOT_TSC.load(Ordering::Relaxed);
    if boot == 0 {
        return 0;
    }
    super::rdtsc().wrapping_sub(boot)
}

/// Milliseconds elapsed since kernel entry.
#[inline]
pub fn elapsed_ms() -> u64 {
    let khz = TSC_KHZ.load(Ordering::Relaxed);
    if khz == 0 {
        return 0;
    }
    elapsed_tsc() / khz
}

/// Microseconds elapsed since kernel entry.
#[inline]
pub fn elapsed_us() -> u64 {
    let khz = TSC_KHZ.load(Ordering::Relaxed);
    if khz == 0 {
        return 0;
    }
    // tsc / (khz / 1000) = tsc * 1000 / khz
    elapsed_tsc().saturating_mul(1_000) / khz
}

/// Current TSC frequency in KHz (for external conversions).
#[inline]
pub fn tsc_khz() -> u64 {
    TSC_KHZ.load(Ordering::Relaxed)
}
