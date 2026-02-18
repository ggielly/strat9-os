//! Built-in shell commands
//!
//! Implements the core commands for the Chevron shell.

use super::{output::format_bytes, ShellError};
use alloc::string::String;

// Import the shell output macros
use crate::shell_println;

/// Display help information
pub fn cmd_help(_args: &[String]) -> Result<(), ShellError> {
    shell_println!("Strat9-OS shell (Chevron) - available commands:");
    shell_println!("");
    shell_println!("  help              - Display this help message");
    shell_println!("  version           - Display kernel version");
    shell_println!("  clear             - Clear the screen");
    shell_println!("  mem               - Display memory status");
    shell_println!("  mem zones         - Display detailed zone information");
    shell_println!("  ps                - List all tasks");
    shell_println!("  silo ls           - List all silos (to be implemented)");
    shell_println!("  scheme ls         - List mounted schemes");
    shell_println!("  cpuinfo           - Display CPU information");
    shell_println!("  reboot            - Reboot the system");
    shell_println!("");
    Ok(())
}

/// Display kernel version
pub fn cmd_version(_args: &[String]) -> Result<(), ShellError> {
    shell_println!("Strat9-OS v0.1.0 (Bedrock)");
    shell_println!("Build: x86_64-unknown-none");
    shell_println!("Features: SMP, APIC, VirtIO, IPC, Schemes");
    Ok(())
}

/// Clear the screen
pub fn cmd_clear(_args: &[String]) -> Result<(), ShellError> {
    super::output::clear_screen();
    Ok(())
}

/// Display memory status
pub fn cmd_mem(args: &[String]) -> Result<(), ShellError> {
    if args.len() > 0 && args[0] == "zones" {
        return cmd_mem_zones();
    }

    shell_println!("Memory status:");

    // Get buddy allocator stats
    let allocator_guard = crate::memory::buddy::get_allocator().lock();
    if let Some(ref allocator) = *allocator_guard {
        let stats = allocator.get_stats();

        let total_bytes = stats.total_pages * 4096;
        let used_bytes = stats.allocated_pages * 4096;
        let free_bytes = total_bytes - used_bytes;

        let (total_val, total_unit) = format_bytes(total_bytes);
        let (used_val, used_unit) = format_bytes(used_bytes);
        let (free_val, free_unit) = format_bytes(free_bytes);

        shell_println!(
            "  Total:     {} {} ({} pages)",
            total_val,
            total_unit,
            stats.total_pages
        );
        shell_println!(
            "  Used:      {} {} ({} pages)",
            used_val,
            used_unit,
            stats.allocated_pages
        );
        shell_println!(
            "  Free:      {} {} ({} pages)",
            free_val,
            free_unit,
            stats.total_pages - stats.allocated_pages
        );
        shell_println!("");
    } else {
        shell_println!("  Memory allocator not initialized");
    }

    Ok(())
}

/// Display detailed memory zone information
fn cmd_mem_zones() -> Result<(), ShellError> {
    shell_println!("Memory zones:");

    let allocator_guard = crate::memory::buddy::get_allocator().lock();
    if let Some(ref allocator) = *allocator_guard {
        let stats = allocator.get_stats();

        for zone_stat in &stats.zones {
            let total_bytes = zone_stat.page_count * 4096;
            let used_bytes = zone_stat.allocated * 4096;
            let free_bytes = total_bytes - used_bytes;

            let (total_val, total_unit) = format_bytes(total_bytes);
            let (free_val, free_unit) = format_bytes(free_bytes);

            shell_println!("  Zone {:?}:", zone_stat.zone_type);
            shell_println!("    Base:      0x{:016x}", zone_stat.base);
            shell_println!(
                "    Total:     {} {} ({} pages)",
                total_val,
                total_unit,
                zone_stat.page_count
            );
            shell_println!(
                "    Free:      {} {} ({} pages)",
                free_val,
                free_unit,
                zone_stat.page_count - zone_stat.allocated
            );
            shell_println!("    Used:      {} pages", zone_stat.allocated);
            shell_println!("");
        }
    } else {
        shell_println!("  Memory allocator not initialized");
    }

    Ok(())
}

/// List all tasks
pub fn cmd_ps(_args: &[String]) -> Result<(), ShellError> {
    shell_println!("PID    Name              State      Priority");
    shell_println!("────────────────────────────────────────────────");

    if let Some(tasks) = crate::process::get_all_tasks() {
        for task in tasks {
            let state = unsafe { *task.state.get() };
            let state_str = match state {
                crate::process::TaskState::Ready => "Ready",
                crate::process::TaskState::Running => "Running",
                crate::process::TaskState::Blocked => "Blocked",
                crate::process::TaskState::Dead => "Dead",
            };

            let priority_str = match task.priority {
                crate::process::TaskPriority::Idle => "Idle",
                crate::process::TaskPriority::Low => "Low",
                crate::process::TaskPriority::Normal => "Normal",
                crate::process::TaskPriority::High => "High",
                crate::process::TaskPriority::Realtime => "Realtime",
            };

            shell_println!(
                "{:<6} {:<17} {:<10} {}",
                task.id.as_u64(),
                task.name,
                state_str,
                priority_str
            );
        }
    } else {
        shell_println!("  No tasks available");
    }

    shell_println!("");
    Ok(())
}

/// List mounted schemes
pub fn cmd_scheme(args: &[String]) -> Result<(), ShellError> {
    if args.len() == 0 || args[0] != "ls" {
        shell_println!("Usage: scheme ls");
        return Ok(());
    }

    shell_println!("Mounted Schemes:");
    shell_println!("Path         Type");
    shell_println!("────────────────────────────────────");

    let schemes = crate::vfs::list_schemes();
    for scheme in schemes {
        shell_println!("  {:<12} {}", scheme, "Kernel");
    }

    shell_println!("");
    Ok(())
}

/// Display CPU information
pub fn cmd_cpuinfo(_args: &[String]) -> Result<(), ShellError> {
    shell_println!("CPU information:");

    // Check if APIC is initialized
    if crate::arch::x86_64::apic::is_initialized() {
        let lapic_id = crate::arch::x86_64::apic::lapic_id();
        let cpu_count = crate::arch::x86_64::percpu::cpu_count();
        shell_println!("  Current LAPIC ID:  {}", lapic_id);
        shell_println!("  CPU count:         {}", cpu_count);
        shell_println!("  APIC:              Active");
    } else {
        shell_println!("  APIC:              Not initialized");
        shell_println!("  Mode:              Legacy PIC");
    }

    shell_println!("");
    Ok(())
}

/// Reboot the system
pub fn cmd_reboot(_args: &[String]) -> Result<(), ShellError> {
    shell_println!("Rebooting system...");

    // Triple fault method (most reliable on x86_64)
    unsafe {
        // Disable interrupts
        crate::arch::x86_64::cli();

        // Try keyboard controller reset (0x64 port, command 0xFE)
        crate::arch::x86_64::io::outb(0x64, 0xFE);

        // If that fails, try ACPI reset (requires FADT parsing - not implemented yet)
        // For now, just halt
        loop {
            crate::arch::x86_64::hlt();
        }
    }
}

/// Silo management commands
pub fn cmd_silo(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() {
        shell_println!("Usage: silo <ls|info|create|kill> [args]");
        return Ok(());
    }

    match args[0].as_str() {
        "ls" => cmd_silo_ls(&args[1..]),
        "info" => {
            if args.len() < 2 {
                shell_println!("Usage: silo info <id>");
                Ok(())
            } else {
                cmd_silo_info(&args[1..])
            }
        }
        _ => {
            shell_println!("Unknown silo subcommand: {}", args[0]);
            shell_println!("Available: ls, info");
            Ok(())
        }
    }
}

/// List all silos
/// TODO: implement actual silo management and replace this stub with real functionality
fn cmd_silo_ls(_args: &[String]) -> Result<(), ShellError> {
    shell_println!("Silo management not yet fully implemented.");
    shell_println!("Coming in v2: silo ls, silo info, silo create, silo kill");
    Ok(())
}

/// Display silo information
/// TODO: implement actual silo management and replace this stub with real functionality
fn cmd_silo_info(_args: &[String]) -> Result<(), ShellError> {
    shell_println!("Silo info not yet implemented.");
    Ok(())
}
