// Timer subsystem
//
// Provides:
// - HPET (High Precision Event Timer)
// - RTC (Real Time Clock)
// - PIT (Programmable Interval Timer) - legacy

pub mod hpet;
pub mod rtc;

use core::sync::atomic::{AtomicBool, Ordering};

/// `hardware::init()` and the component graph both run the hardware stage.
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Performs the init operation.
///
/// Idempotent: the component `timer_init` runs after `hardware::init()` has
/// already probed HPET and RTC.
pub fn init() {
    if INITIALIZED.swap(true, Ordering::AcqRel) {
        return;
    }
    log::info!("[TIMER] Initializing timers...");

    // Initialize HPET first (high precision)
    if let Err(e) = hpet::init() {
        log::warn!("[TIMER] HPET init failed: {}", e);
    }

    // Initialize RTC (real-time clock)
    if let Err(e) = rtc::init() {
        log::warn!("[TIMER] RTC init failed: {}", e);
    }

    log::info!("[TIMER] Timer subsystem initialized");
}
