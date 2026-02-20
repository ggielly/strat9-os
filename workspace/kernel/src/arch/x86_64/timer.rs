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
///
/// Configures PIT channel 0 to generate interrupts at the specified frequency.
/// Used as a fallback when APIC timer calibration fails.
pub fn init_pit(frequency_hz: u32) {
    log::info!("========================================");
    log::info!("PIT INITIALIZATION (fallback mode)");
    log::info!("========================================");
    log::info!("Target frequency: {} Hz", frequency_hz);
    log::info!("PIT base frequency: {} Hz", PIT_FREQUENCY);

    let divisor = PIT_FREQUENCY / frequency_hz;
    log::info!("Calculated divisor: {} (0x{:04X})", divisor, divisor);

    // Expected actual frequency
    let actual_freq = PIT_FREQUENCY / divisor;
    log::info!(
        "Expected actual frequency: {} Hz (error: {} Hz)",
        actual_freq,
        if actual_freq > frequency_hz {
            actual_freq - frequency_hz
        } else {
            frequency_hz - actual_freq
        }
    );

    // Send command byte to configure PIT
    let mut cmd_port = Port::new(PIT_COMMAND_PORT);
    unsafe {
        cmd_port.write(0x36u8); // Channel 0, low/high byte, rate generator
    }
    log::info!(
        "PIT command port (0x{:X}) wrote: 0x{:02X}",
        PIT_COMMAND_PORT,
        0x36u8
    );
    log::info!("  Channel: 0");
    log::info!("  Access: low byte then high byte");
    log::info!("  Mode: 3 (square wave generator / rate generator)");

    // Send divisor (low byte, then high byte)
    let mut ch0_port = Port::new(PIT_CHANNEL0_PORT);
    let low_byte = (divisor & 0xFF) as u8;
    let high_byte = ((divisor >> 8) & 0xFF) as u8;

    unsafe {
        ch0_port.write(low_byte); // Low byte
        ch0_port.write(high_byte); // High byte
    }

    log::info!("PIT channel 0 port (0x{:X}) wrote:", PIT_CHANNEL0_PORT);
    log::info!("  Low byte:  0x{:02X} ({})", low_byte, low_byte);
    log::info!("  High byte: 0x{:02X} ({})", high_byte, high_byte);

    log::info!("========================================");
    log::info!("PIT INITIALIZED SUCCESSFULLY");
    log::info!("  Frequency: {} Hz", frequency_hz);
    log::info!("  Interval: {} ms", 1000 / frequency_hz);
    log::info!("========================================");
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

    // ========================================================================
    // DEBUG: Verbose logging for timer calibration
    // ========================================================================
    log::info!("========================================");
    log::info!("APIC TIMER CALIBRATION (verbose debug)");
    log::info!("========================================");

    // PIT channel 2 count for ~10ms: 1193182 / 100 = 11932
    const PIT_10MS_COUNT: u16 = 11932;
    // Maximum poll iterations to prevent infinite loop
    const MAX_POLL_ITERATIONS: u32 = 10_000_000;

    log::info!("PIT frequency: {} Hz", PIT_FREQUENCY);
    log::info!("PIT 10ms count: {}", PIT_10MS_COUNT);
    log::info!("Target wait time: ~10ms");

    // Set APIC timer divide to 16
    // Divide configuration: 0x03 = divide by 16
    // SAFETY: APIC is initialized
    unsafe {
        apic::write_reg(apic::REG_TIMER_DIVIDE, 0x03);
    }
    log::info!("APIC timer divide set to 16 (0x03)");

    // ========================================================================
    // CRITICAL TIMING SECTION — no log messages between gate-up and poll end
    // ========================================================================
    // The PIT channel 2 gate must be LOW while programming the counter.
    // In mode 0, counting starts as soon as the count is loaded AND gate is
    // HIGH. If gate is already HIGH when we load the count, the 10 ms window
    // begins before we can start the APIC timer → measurement is wrong.
    //
    // Correct sequence:
    //   1. Gate LOW  — prevent counting while we program the PIT
    //   2. Program PIT channel 2 (mode 0, one-shot, count = PIT_10MS_COUNT)
    //   3. Set APIC timer initial count to 0xFFFF_FFFF
    //   4. Gate HIGH — PIT starts counting NOW, APIC is already counting
    //   5. Poll bit 5 of port 0x61 until PIT output goes HIGH (10 ms elapsed)
    //   6. Read APIC timer current count
    // ========================================================================

    // Step 1: Disable PIT channel 2 gate (prevent counting during setup)
    // Port 0x61: bit 0 = gate, bit 1 = speaker enable
    unsafe {
        let val = inb(0x61);
        log::info!("Port 0x61 initial value: 0x{:02X}", val);
        outb(0x61, val & 0xFC); // Clear bit 0 (gate) and bit 1 (speaker)
    }
    log::info!("PIT channel 2 gate DISABLED for setup");

    // Step 2: Program PIT channel 2 in mode 0 (one-shot)
    // Command: 0xB0 = channel 2, lobyte/hibyte, mode 0, binary
    // Writing the command sets output LOW. Count is loaded but gate is LOW
    // so counting does NOT start yet.
    unsafe {
        outb(0x43, 0xB0);
        outb(0x42, (PIT_10MS_COUNT & 0xFF) as u8); // Low byte
        outb(0x42, ((PIT_10MS_COUNT >> 8) & 0xFF) as u8); // High byte
    }
    log::info!(
        "PIT channel 2 programmed: mode 0 (one-shot), count={}",
        PIT_10MS_COUNT
    );
    log::info!("  Low byte:  0x{:02X}", (PIT_10MS_COUNT & 0xFF) as u8);
    log::info!(
        "  High byte: 0x{:02X}",
        ((PIT_10MS_COUNT >> 8) & 0xFF) as u8
    );

    // Step 3: Set APIC timer initial count to maximum
    // SAFETY: APIC is initialized
    unsafe {
        apic::write_reg(apic::REG_TIMER_INIT, 0xFFFF_FFFF);
    }
    log::info!("APIC timer initial count set to MAX (0xFFFFFFFF)");
    log::info!("Enabling PIT gate NOW — measurement starts...");

    // Step 4: Enable PIT channel 2 gate — starts PIT counting
    // APIC timer is already counting from step 3, so the measurement
    // window begins precisely here.  NO LOG MESSAGES until poll completes.
    unsafe {
        let val = inb(0x61);
        outb(0x61, (val | 0x01) & 0xFD); // Set bit 0 (gate), clear bit 1 (speaker)
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
            log::warn!(
                "APIC timer calibration: PIT poll timeout after {} iterations",
                iterations
            );
            log::warn!("  This may indicate a hardware issue or incorrect PIT configuration");
            // SAFETY: APIC is initialized
            unsafe {
                apic::write_reg(apic::REG_TIMER_INIT, 0);
            }
            return 0;
        }
    }

    // Step 6: Read APIC timer current count — end of critical section
    // SAFETY: APIC is initialized
    let current = unsafe { apic::read_reg(apic::REG_TIMER_CURRENT) };
    let elapsed = 0xFFFF_FFFFu32.wrapping_sub(current);

    // Stop the APIC timer
    // SAFETY: APIC is initialized
    unsafe {
        apic::write_reg(apic::REG_TIMER_INIT, 0);
    }

    // ========================================================================
    // END CRITICAL TIMING SECTION — safe to log again
    // ========================================================================
    log::info!("PIT poll completed after {} iterations", iterations);
    log::info!("APIC timer current count: 0x{:08X}", current);
    log::info!("APIC timer elapsed ticks: {} (0x{:08X})", elapsed, elapsed);

    // Validate calibration result
    if elapsed == 0 {
        log::error!("APIC timer calibration: ZERO ticks measured!");
        log::error!("  This indicates a serious problem with the APIC timer");
        return 0;
    }

    // Check for suspicious values
    // With div=16, ticks_10ms = APIC_bus_freq / 16 / 100.
    // QEMU default APIC frequency is ~1 GHz → ~625,000 ticks/10ms.
    // Real hardware with a 200 MHz bus → ~125,000 ticks/10ms.
    // Use wide bounds to support both real hardware and emulators.
    const MIN_EXPECTED_TICKS: u32 = 1_000; // extremely slow / throttled
    const MAX_EXPECTED_TICKS: u32 = 5_000_000; // very fast host or low divider

    if elapsed < MIN_EXPECTED_TICKS {
        log::warn!(
            "APIC calibration SUSPICIOUS: {} ticks/10ms is TOO LOW",
            elapsed
        );
        log::warn!(
            "  Expected range: {} - {} ticks/10ms",
            MIN_EXPECTED_TICKS,
            MAX_EXPECTED_TICKS
        );
        log::warn!("  Possible causes:");
        log::warn!("    - APIC divide configured incorrectly");
        log::warn!("    - PIT frequency mismatch");
        log::warn!("    - hardware issue");
        log::warn!("  Forcing fallback to PIT timer");
        return 0;
    }

    if elapsed > MAX_EXPECTED_TICKS {
        log::warn!(
            "APIC calibration SUSPICIOUS: {} ticks/10ms is TOO HIGH",
            elapsed
        );
        log::warn!(
            "  Expected range: {} - {} ticks/10ms",
            MIN_EXPECTED_TICKS,
            MAX_EXPECTED_TICKS
        );
        log::warn!("  Possible causes:");
        log::warn!("    - PIT poll completed too early");
        log::warn!("    - APIC timer running at wrong frequency");
        log::warn!("    - hardware issue");
        log::warn!("  Forcing fallback to PIT timer");
        return 0;
    }

    // Calculate estimated CPU frequency
    // CPU_freq = elapsed_ticks * div * 100
    let estimated_cpu_freq_mhz = (elapsed as u64) * 16 * 100 / 1_000_000;
    log::info!(
        "Estimated CPU frequency: {} MHz (based on APIC ticks)",
        estimated_cpu_freq_mhz
    );

    // Store calibration result
    APIC_TICKS_PER_10MS.store(elapsed, Ordering::Release);

    log::info!("========================================");
    log::info!("APIC TIMER CALIBRATION COMPLETE");
    log::info!("  Ticks per 10ms: {}", elapsed);
    log::info!("  Expected frequency: ~100Hz");
    log::info!("  Estimated CPU: {} MHz", estimated_cpu_freq_mhz);
    log::info!("========================================");

    elapsed
}

/// Start the APIC timer in periodic mode.
///
/// `ticks_per_10ms` is the calibrated tick count from `calibrate_apic_timer()`.
/// The timer fires at vector 0x20 (same as PIT timer), 100Hz.
pub fn start_apic_timer(ticks_per_10ms: u32) {
    use super::apic;

    log::info!("========================================");
    log::info!("APIC TIMER START");
    log::info!("========================================");

    if ticks_per_10ms == 0 {
        log::warn!("APIC timer: cannot start with 0 ticks");
        return;
    }

    log::info!("Ticks per 10ms: {}", ticks_per_10ms);
    log::info!("Target frequency: 100Hz (10ms interval)");

    // SAFETY: APIC is initialized
    unsafe {
        // Set divide to 16 (same as calibration)
        let divide_val = apic::read_reg(apic::REG_TIMER_DIVIDE);
        log::info!("APIC timer divide register before: 0x{:08X}", divide_val);
        apic::write_reg(apic::REG_TIMER_DIVIDE, 0x03);
        let divide_val_after = apic::read_reg(apic::REG_TIMER_DIVIDE);
        log::info!(
            "APIC timer divide register after: 0x{:08X}",
            divide_val_after
        );

        // Configure LVT Timer: periodic mode, vector 0x20
        let lvt_before = apic::read_reg(apic::REG_LVT_TIMER);
        log::info!("LVT Timer register before: 0x{:08X}", lvt_before);

        let lvt_config = apic::LVT_TIMER_PERIODIC | 0x20;
        log::info!(
            "LVT Timer config: 0x{:08X} (periodic + vector 0x20)",
            lvt_config
        );
        apic::write_reg(apic::REG_LVT_TIMER, lvt_config);

        let lvt_after = apic::read_reg(apic::REG_LVT_TIMER);
        log::info!("LVT Timer register after: 0x{:08X}", lvt_after);

        // Set initial count (fires every ~10ms = 100Hz)
        log::info!(
            "Setting timer initial count to: {} (0x{:08X})",
            ticks_per_10ms,
            ticks_per_10ms
        );
        apic::write_reg(apic::REG_TIMER_INIT, ticks_per_10ms);

        let init_verify = apic::read_reg(apic::REG_TIMER_INIT);
        log::info!(
            "Timer initial count verified: {} (0x{:08X})",
            init_verify,
            init_verify
        );
    }

    APIC_TIMER_ACTIVE.store(true, Ordering::Relaxed);

    log::info!(
        "APIC timer: started periodic mode, vector=0x20, count={} (~100Hz)",
        ticks_per_10ms
    );
    log::info!("========================================");
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

// ============================================================================
// DEBUG UTILITIES
// ============================================================================

/// Debug function to measure elapsed real time vs kernel ticks
///
/// Call this from shell to verify timer accuracy.
/// Should block for approximately `seconds` real seconds.
pub fn debug_measure_time(seconds: u32) {
    use core::arch::x86_64::_rdtsc;

    log::info!("========================================");
    log::info!("TIMER DEBUG: Measuring {} seconds...", seconds);
    log::info!("========================================");

    let start_tick = crate::process::scheduler::ticks();
    let start_tsc = unsafe { _rdtsc() };

    log::info!("Start: tick={}, TSC={}", start_tick, start_tsc);

    // Wait for the specified number of ticks (100 ticks = 1 second at 100Hz)
    let target_ticks = start_tick + (seconds as u64 * 100);

    while crate::process::scheduler::ticks() < target_ticks {
        core::hint::spin_loop();
    }

    let end_tick = crate::process::scheduler::ticks();
    let end_tsc = unsafe { _rdtsc() };

    let elapsed_ticks = end_tick - start_tick;
    let elapsed_tsc = end_tsc - start_tsc;

    log::info!("End: tick={}, TSC={}", end_tick, end_tsc);
    log::info!("Elapsed ticks: {}", elapsed_ticks);
    log::info!("Elapsed TSC: {}", elapsed_tsc);

    // Calculate expected TSC (assuming constant CPU frequency)
    let expected_tsc = (elapsed_ticks as u64) * (apic_ticks_per_10ms() as u64) * 16;
    log::info!("Expected TSC (approx): {}", expected_tsc);

    // Calculate estimated CPU frequency
    // CPU_freq = TSC_elapsed / time_seconds
    let estimated_cpu_mhz = (elapsed_tsc / seconds as u64) / 1_000_000;
    log::info!("Estimated CPU frequency: {} MHz", estimated_cpu_mhz);

    // Calculate actual tick frequency
    // If we waited 100 ticks expecting 1 second, but it was actually different
    let expected_ticks = seconds as u64 * 100;
    if elapsed_ticks != expected_ticks {
        log::warn!(
            "TICK MISMATCH: expected {} ticks, got {} ticks",
            expected_ticks,
            elapsed_ticks
        );
    }

    log::info!("========================================");
    log::info!(
        "If this message appeared after ~{} real seconds, timer is CORRECT",
        seconds
    );
    log::info!("If it was faster/slower, timer calibration may be WRONG");
    log::info!("========================================");
}
