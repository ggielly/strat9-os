//! Timer debug commands
//!
//! Provides shell commands for debugging and verifying timer accuracy.

use crate::{arch::timer::TIMER_HZ, shell::ShellError, shell_println};
use alloc::string::String;

/// Timer debug command
///
/// Usage: `timer info`
///
/// Reports the tick source the kernel actually programmed. The two timer
/// backends used to print the same command with different quantities under
/// matching labels: the APIC branch printed "Ticks per 10ms" (the LAPIC
/// counter's own rate) while the fallback branch printed "Frequency" in Hz
/// (the tick rate), so the two could not be compared. Both now report the
/// tick rate, and the APIC counter rate is labelled as what it is.
pub fn cmd_timer(args: &[String]) -> Result<(), ShellError> {
    let subcommand = match args.first() {
        Some(arg) => arg.as_str(),
        None => {
            print_usage();
            // A bare `timer` is a usage error, not a successful no-op: it used
            // to return `Ok(())`, so scripts saw `$?` = 0 for a command that
            // had printed its own usage.
            return Err(ShellError::InvalidArguments);
        }
    };

    match subcommand {
        // The measurement path was removed as unstable. It used to print a
        // "disabled" notice and return `Ok(())`, so `timer test` looked like it
        // had run and set `$?` = 0. Kept as an explicit rejection rather than
        // folded into the unknown-subcommand arm: the old spelling is in
        // people's notes, and "unknown subcommand" would claim it never
        // existed.
        "test" => {
            shell_println!(
                "timer: 'test' was removed with the unstable debug path; use 'timer info'."
            );
            Err(ShellError::InvalidArguments)
        }
        "info" => {
            print_timer_info();
            Ok(())
        }
        other => {
            print_usage();
            shell_println!("timer: unknown subcommand '{}'", other);
            Err(ShellError::InvalidArguments)
        }
    }
}

/// Prints what the kernel knows about its tick source.
///
/// Every line is either a configured constant or a measured value. The APIC
/// branch used to end with `ticks * 16 * 100 / 1_000_000` labelled
/// "Estimated CPU": the LAPIC counter is fed by the *APIC bus* through a
/// divide-by-16 prescaler, so that figure is the bus clock in MHz and was
/// wrong as a CPU frequency by the bus/core ratio. The CPU line now comes
/// from the measured TSC rate.
fn print_timer_info() {
    shell_println!("=== Timer information ===");
    shell_println!("Arch: {}", crate::arch::ARCH_NAME);

    let ticks = crate::process::scheduler::ticks();
    let (secs, cs) = crate::shell::output::format_ticks(ticks);
    shell_println!("Scheduler ticks: {} ({}.{:02} s)", ticks, secs, cs);
    // The rate the kernel programs the tick source to, whichever source that
    // is: the LAPIC timer is loaded with a count for TIMER_HZ, and the PIT
    // fallback is programmed with the same TIMER_HZ divisor.
    shell_println!("Tick rate: {} Hz", TIMER_HZ);

    if crate::arch::timer::is_apic_timer_active() {
        shell_println!("Timer mode: APIC (LAPIC timer, divide-by-16 counter)");
        // Only meaningful for the LAPIC counter, so it is scoped to that mode
        // instead of standing in for the tick rate the other branch prints.
        let ticks_per_10ms = crate::arch::timer::apic_ticks_per_10ms();
        if ticks_per_10ms == 0 {
            shell_println!("APIC counter ticks per 10ms: unavailable (not calibrated)");
        } else {
            shell_println!("APIC counter ticks per 10ms: {}", ticks_per_10ms);
        }
    } else {
        // riscv64 also reports the APIC timer as inactive, but it never
        // programs a PIT: it arms stimecmp through SBI or SSTC.
        #[cfg(target_arch = "x86_64")]
        shell_println!("Timer mode: PIT (fallback)");
        #[cfg(target_arch = "riscv64")]
        shell_println!("Timer mode: SBI/SSTC timer (no LAPIC timer on this arch)");
        #[cfg(not(any(target_arch = "x86_64", target_arch = "riscv64")))]
        shell_println!("Timer mode: platform timer (no LAPIC timer)");
    }

    // `tsc_khz` is a real measurement on x86_64 (CPUID leaf 0x15, or the
    // PIT-gated rdtsc window in `calibrate_apic_timer`). riscv64's is a
    // hardcoded QEMU timebase constant, so it is not dressed up as a CPU
    // frequency there.
    #[cfg(target_arch = "x86_64")]
    {
        let tsc_khz = crate::arch::boot_timestamp::tsc_khz();
        if tsc_khz == 0 {
            shell_println!("CPU (TSC): not calibrated");
        } else {
            shell_println!(
                "CPU (TSC): {}.{:03} GHz",
                tsc_khz / 1_000_000,
                (tsc_khz % 1_000_000) / 1_000
            );
        }
    }
}

/// Performs the print usage operation.
fn print_usage() {
    shell_println!("Timer debug commands:");
    shell_println!("  timer info          - Show timer configuration");
    shell_println!("");
    shell_println!("Example:");
    shell_println!("  timer info          - Show current timer info");
}
