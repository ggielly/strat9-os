//! Timer debug commands
//!
//! Provides shell commands for debugging and verifying timer accuracy.

use crate::shell_println;
use crate::shell::ShellError;
use alloc::string::String;

/// Timer debug command
///
/// Usage: timer test <seconds>
///
/// Measures elapsed real time vs kernel ticks.
pub fn cmd_timer(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() {
        print_usage();
        return Ok(());
    }

    match args[0].as_str() {
        "test" => {
            let seconds = if args.len() > 1 {
                args[1].parse::<u32>().unwrap_or(1)
            } else {
                1 // Default: 1 second
            };

            shell_println!("Testing timer accuracy for {} seconds...", seconds);
            shell_println!("Please compare with a real clock/stopwatch.");
            shell_println!("Serial output will show detailed timing info.");

            // Call the debug function
            crate::arch::x86_64::timer::debug_measure_time(seconds);

            Ok(())
        }
        "info" => {
            shell_println!("=== Timer Information ===");
            shell_println!("Scheduler ticks: {}", crate::process::scheduler::ticks());

            if crate::arch::x86_64::timer::is_apic_timer_active() {
                let ticks_per_10ms = crate::arch::x86_64::timer::apic_ticks_per_10ms();
                shell_println!("Timer mode: APIC");
                shell_println!("Ticks per 10ms: {}", ticks_per_10ms);
                shell_println!(
                    "Estimated CPU: {} MHz",
                    (ticks_per_10ms as u64) * 16 * 100 / 1_000_000
                );
            } else {
                shell_println!("Timer mode: PIT (fallback)");
                shell_println!("Frequency: 100 Hz");
            }

            Ok(())
        }
        _ => {
            print_usage();
            Ok(())
        }
    }
}

fn print_usage() {
    shell_println!("Timer debug commands:");
    shell_println!("  timer test [seconds]  - Measure timer accuracy (default: 1s)");
    shell_println!("  timer info            - Show timer configuration");
    shell_println!("");
    shell_println!("Examples:");
    shell_println!("  timer test          - Test for 1 second");
    shell_println!("  timer test 5        - Test for 5 seconds");
    shell_println!("  timer info          - Show current timer info");
}
