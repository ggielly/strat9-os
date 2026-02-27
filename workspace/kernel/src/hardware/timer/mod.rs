// Timer subsystem
//
// Provides:
// - HPET (High Precision Event Timer)
// - RTC (Real Time Clock)
// - PIT (Programmable Interval Timer) - legacy

pub mod hpet;
pub mod rtc;

pub fn init() {
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
