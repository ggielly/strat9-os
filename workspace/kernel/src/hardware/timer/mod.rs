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
