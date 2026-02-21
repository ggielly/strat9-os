//! System management commands
use crate::{
    process::{
        log_scheduler_state, scheduler_class_table, scheduler_verbose_enabled, set_scheduler_verbose,
    },
    shell::{output::clear_screen, ShellError},
    shell_println,
};
use alloc::string::String;

/// Display kernel version
pub fn cmd_version(_args: &[String]) -> Result<(), ShellError> {
    shell_println!("Strat9-OS v0.1.0 (Bedrock)");
    shell_println!("Build: x86_64-unknown-none");
    shell_println!("Features: SMP, APIC, VirtIO, IPC, Schemes");
    Ok(())
}

/// Clear the screen
pub fn cmd_clear(_args: &[String]) -> Result<(), ShellError> {
    clear_screen();
    Ok(())
}

/// Display CPU information
pub fn cmd_cpuinfo(_args: &[String]) -> Result<(), ShellError> {
    shell_println!("CPU information:");

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
    unsafe {
        crate::arch::x86_64::cli();
        crate::arch::x86_64::io::outb(0x64, 0xFE);
        loop {
            crate::arch::x86_64::hlt();
        }
    }
}

/// scheduler debug on|off|dump
pub fn cmd_scheduler(args: &[String]) -> Result<(), ShellError> {
    if args.len() != 2 || args[0].as_str() != "debug" {
        shell_println!("Usage: scheduler debug on|off|dump");
        return Err(ShellError::InvalidArguments);
    }

    match args[1].as_str() {
        "on" => {
            set_scheduler_verbose(true);
            shell_println!("scheduler debug: on");
            Ok(())
        }
        "off" => {
            set_scheduler_verbose(false);
            shell_println!("scheduler debug: off");
            Ok(())
        }
        "dump" => {
            let table = scheduler_class_table();
            let pick = table.pick_order();
            let steal = table.steal_order();
            shell_println!(
                "scheduler debug: {}",
                if scheduler_verbose_enabled() { "on" } else { "off" }
            );
            shell_println!(
                "class table: pick=[{},{},{}] steal=[{},{}]",
                pick[0].as_str(),
                pick[1].as_str(),
                pick[2].as_str(),
                steal[0].as_str(),
                steal[1].as_str()
            );
            log_scheduler_state("shell");
            Ok(())
        }
        _ => {
            shell_println!("Usage: scheduler debug on|off|dump");
            Err(ShellError::InvalidArguments)
        }
    }
}
