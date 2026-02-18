//! Timer Implementation
//!
//! Provides timer functionality for the kernel:
//! - PIT (Programmable Interval Timer) for legacy fallback
//! - APIC Timer for modern systems (calibrated via PIT channel 2)

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use x86_64::instructions::port::Port;

/// Programmable Interval Timer (PIT) constants
const PIT_CHANNEL0_PORT: u16 = 0x40;
const PIT_COMMAND_PORT: u16 = 0x43;
const PIT_FREQUENCY: u32 = 1193182; // Hz

/// Whether the APIC timer is currently active
static APIC_TIMER_ACTIVE: AtomicBool = AtomicBool::new(false);
/// Cached APIC ticks per 10ms from calibration (used by APs)
static APIC_TICKS_PER_10MS: AtomicU32 = AtomicU32::new(0);

/// Initialize the Programmable Interval Timer (PIT)
pub fn init_pit(frequency_hz: u32) {
    let divisor = PIT_FREQUENCY / frequency_hz;

    // Send command byte to configure PIT
    let mut cmd_port = Port::new(PIT_COMMAND_PORT);
    unsafe {
        cmd_port.write(0x36u8); // Channel 0, low/high byte, rate generator
    }

    // Send divisor (low byte, then high byte)
    let mut ch0_port = Port::new(PIT_CHANNEL0_PORT);
    unsafe {
        ch0_port.write((divisor & 0xFF) as u8); // Low byte
        ch0_port.write(((divisor >> 8) & 0xFF) as u8); // High byte
    }
}

/// Check if the APIC timer is active
pub fn is_apic_timer_active() -> bool {
    APIC_TIMER_ACTIVE.load(Ordering::Relaxed)
}

/// Calibrate the APIC timer using PIT channel 2 as a reference.
///
/// Uses PIT channel 2 in one-shot mode (~10ms) to measure how many
/// APIC timer ticks elapse. Interrupts should be disabled during calibration.
///
/// Returns the number of APIC timer ticks per 10ms, or 0 on failure.
pub fn calibrate_apic_timer() -> u32 {
    use super::{
        apic,
        io::{inb, outb},
    };

    // PIT channel 2 count for ~10ms: 1193182 / 100 = 11932
    const PIT_10MS_COUNT: u16 = 11932;
    // Maximum poll iterations to prevent infinite loop
    const MAX_POLL_ITERATIONS: u32 = 10_000_000;

    // Set APIC timer divide to 16
    // Divide configuration: 0x03 = divide by 16
    // SAFETY: APIC is initialized
    unsafe {
        apic::write_reg(apic::REG_TIMER_DIVIDE, 0x03);
    }

    // Step 1: Enable PIT channel 2 gate
    // Port 0x61: bit 0 = gate, bit 1 = speaker enable
    unsafe {
        let val = inb(0x61);
        outb(0x61, (val & 0xFD) | 0x01); // Enable gate, disable speaker
    }

    // Step 2: Program PIT channel 2 in mode 0 (one-shot)
    // Command: 0xB0 = channel 2, lobyte/hibyte, mode 0, binary
    unsafe {
        outb(0x43, 0xB0);
        outb(0x42, (PIT_10MS_COUNT & 0xFF) as u8); // Low byte
        outb(0x42, ((PIT_10MS_COUNT >> 8) & 0xFF) as u8); // High byte
    }

    // Step 3: Set APIC timer initial count to maximum
    // SAFETY: APIC is initialized
    unsafe {
        apic::write_reg(apic::REG_TIMER_INIT, 0xFFFF_FFFF);
    }

    // Step 4: Restart PIT channel 2 by toggling the gate
    unsafe {
        let val = inb(0x61);
        outb(0x61, val & 0xFE); // Gate low
        outb(0x61, val | 0x01); // Gate high — starts counting
    }

    // Step 5: Poll PIT channel 2 output (bit 5 of port 0x61)
    // When the count reaches 0, bit 5 goes high
    let mut iterations: u32 = 0;
    loop {
        // SAFETY: reading port 0x61 is safe
        let status = unsafe { inb(0x61) };
        if status & 0x20 != 0 {
            break; // PIT output went high — 10ms elapsed
        }
        iterations += 1;
        if iterations >= MAX_POLL_ITERATIONS {
            log::warn!("APIC timer calibration: PIT poll timeout");
            // SAFETY: APIC is initialized
            unsafe {
                apic::write_reg(apic::REG_TIMER_INIT, 0);
            }
            return 0;
        }
    }

    // Step 6: Read APIC timer current count
    // SAFETY: APIC is initialized
    let current = unsafe { apic::read_reg(apic::REG_TIMER_CURRENT) };
    let elapsed = 0xFFFF_FFFFu32.wrapping_sub(current);

    // Stop the APIC timer
    // SAFETY: APIC is initialized
    unsafe {
        apic::write_reg(apic::REG_TIMER_INIT, 0);
    }

    if elapsed == 0 {
        log::warn!("APIC timer calibration: zero ticks measured");
        return 0;
    }

    log::info!(
        "APIC timer calibration: {} ticks per 10ms (div=16)",
        elapsed
    );

    APIC_TICKS_PER_10MS.store(elapsed, Ordering::Release);

    elapsed
}

/// Start the APIC timer in periodic mode.
///
/// `ticks_per_10ms` is the calibrated tick count from `calibrate_apic_timer()`.
/// The timer fires at vector 0x20 (same as PIT timer), 100Hz.
pub fn start_apic_timer(ticks_per_10ms: u32) {
    use super::apic;

    if ticks_per_10ms == 0 {
        log::warn!("APIC timer: cannot start with 0 ticks");
        return;
    }

    // SAFETY: APIC is initialized
    unsafe {
        // Set divide to 16 (same as calibration)
        apic::write_reg(apic::REG_TIMER_DIVIDE, 0x03);

        // Configure LVT Timer: periodic mode, vector 0x20
        apic::write_reg(apic::REG_LVT_TIMER, apic::LVT_TIMER_PERIODIC | 0x20);

        // Set initial count (fires every ~10ms = 100Hz)
        apic::write_reg(apic::REG_TIMER_INIT, ticks_per_10ms);
    }

    APIC_TIMER_ACTIVE.store(true, Ordering::Relaxed);

    log::info!(
        "APIC timer: started periodic mode, vector=0x20, count={} (~100Hz)",
        ticks_per_10ms
    );
}

/// Return the cached calibration value (ticks per 10ms).
pub fn apic_ticks_per_10ms() -> u32 {
    APIC_TICKS_PER_10MS.load(Ordering::Acquire)
}

/// Start the APIC timer using the cached calibration value.
pub fn start_apic_timer_cached() {
    let ticks = apic_ticks_per_10ms();
    start_apic_timer(ticks);
}
