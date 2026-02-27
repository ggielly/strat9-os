//! System management commands
use crate::{
    process::{
        elf::load_and_run_elf, log_scheduler_state, scheduler_class_table,
        scheduler_verbose_enabled, set_scheduler_verbose,
    },
    silo,
    shell::{output::clear_screen, ShellError},
    shell_println, vfs,
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
                if scheduler_verbose_enabled() {
                    "on"
                } else {
                    "off"
                }
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

/// trace mem on|off|dump [n]|clear|serial on|off|mask
pub fn cmd_trace(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() || args[0].as_str() != "mem" {
        shell_println!("Usage: trace mem on|off|dump [n]|clear|serial on|off|mask");
        return Err(ShellError::InvalidArguments);
    }

    if args.len() < 2 {
        shell_println!("Usage: trace mem on|off|dump [n]|clear|serial on|off|mask");
        return Err(ShellError::InvalidArguments);
    }

    match args[1].as_str() {
        "on" => {
            crate::trace::enable(crate::trace::category::MEM_ALL);
            shell_println!(
                "trace mem: on (mask={:#x}, mode={})",
                crate::trace::mask(),
                crate::trace::mask_human(crate::trace::mask())
            );
            Ok(())
        }
        "off" => {
            crate::trace::disable(crate::trace::category::MEM_ALL);
            shell_println!(
                "trace mem: off (mask={:#x}, mode={})",
                crate::trace::mask(),
                crate::trace::mask_human(crate::trace::mask())
            );
            Ok(())
        }
        "mask" => {
            let stats = crate::trace::stats();
            shell_println!(
                "trace mem: mask={:#x} mode={} serial={} stored={} dropped={}",
                crate::trace::mask(),
                crate::trace::mask_human(crate::trace::mask()),
                if crate::trace::serial_echo() {
                    "on"
                } else {
                    "off"
                },
                stats.stored,
                stats.dropped
            );
            Ok(())
        }
        "clear" => {
            crate::trace::clear_all();
            shell_println!("trace mem: buffers cleared");
            Ok(())
        }
        "serial" => {
            if args.len() != 3 {
                shell_println!("Usage: trace mem serial on|off");
                return Err(ShellError::InvalidArguments);
            }
            match args[2].as_str() {
                "on" => {
                    crate::trace::set_serial_echo(true);
                    shell_println!("trace mem serial: on");
                    Ok(())
                }
                "off" => {
                    crate::trace::set_serial_echo(false);
                    shell_println!("trace mem serial: off");
                    Ok(())
                }
                _ => {
                    shell_println!("Usage: trace mem serial on|off");
                    Err(ShellError::InvalidArguments)
                }
            }
        }
        "dump" => {
            let limit = if args.len() >= 3 {
                args[2].parse::<usize>().unwrap_or(64)
            } else {
                64
            };
            let events = crate::trace::snapshot_all(limit);
            let stats = crate::trace::stats();
            shell_println!(
                "trace mem dump: events={} stored={} dropped={}",
                events.len(),
                stats.stored,
                stats.dropped
            );
            for e in events.iter() {
                shell_println!(
                    "  seq={} t={} cpu={} kind={} pid={} tid={} cr3={:#x} rip={:#x} vaddr={:#x} fl={:#x} a0={:#x} a1={:#x}",
                    e.seq,
                    e.ticks,
                    e.cpu,
                    crate::trace::kind_name(e.kind),
                    e.pid,
                    e.tid,
                    e.cr3,
                    e.rip,
                    e.vaddr,
                    e.flags,
                    e.arg0,
                    e.arg1
                );
            }
            Ok(())
        }
        _ => {
            shell_println!("Usage: trace mem on|off|dump [n]|clear|serial on|off|mask");
            Err(ShellError::InvalidArguments)
        }
    }
}

/// Launch the userspace PID test binary from initfs.
pub fn cmd_test_pid(_args: &[String]) -> Result<(), ShellError> {
    let path = "/initfs/test_pid";
    shell_println!("Launching {} ...", path);

    let fd = match vfs::open(path, vfs::OpenFlags::READ) {
        Ok(fd) => fd,
        Err(e) => {
            shell_println!("open failed: {:?}", e);
            return Err(ShellError::ExecutionFailed);
        }
    };

    let data = match vfs::read_all(fd) {
        Ok(d) => d,
        Err(e) => {
            let _ = vfs::close(fd);
            shell_println!("read failed: {:?}", e);
            return Err(ShellError::ExecutionFailed);
        }
    };
    let _ = vfs::close(fd);

    shell_println!("ELF size: {} bytes", data.len());
    shell_println!("Launching with task name 'init' to inherit bootstrap console/admin caps");
    match load_and_run_elf(&data, "init") {
        Ok(task_id) => {
            shell_println!("test_pid started (task id={})", task_id);
            Ok(())
        }
        Err(e) => {
            shell_println!("load_and_run_elf failed: {}", e);
            Err(ShellError::ExecutionFailed)
        }
    }
}

/// Launch the userspace memory test binary from initfs.
pub fn cmd_test_mem(_args: &[String]) -> Result<(), ShellError> {
    let path = "/initfs/test_mem";
    shell_println!("Launching {} ...", path);

    let fd = match vfs::open(path, vfs::OpenFlags::READ) {
        Ok(fd) => fd,
        Err(e) => {
            shell_println!("open failed: {:?}", e);
            return Err(ShellError::ExecutionFailed);
        }
    };

    let data = match vfs::read_all(fd) {
        Ok(d) => d,
        Err(e) => {
            let _ = vfs::close(fd);
            shell_println!("read failed: {:?}", e);
            return Err(ShellError::ExecutionFailed);
        }
    };
    let _ = vfs::close(fd);

    shell_println!("ELF size: {} bytes", data.len());
    shell_println!("Launching with task name 'init' to inherit bootstrap console/admin caps");
    match load_and_run_elf(&data, "init") {
        Ok(task_id) => {
            shell_println!("test_mem started (task id={})", task_id);
            Ok(())
        }
        Err(e) => {
            shell_println!("load_and_run_elf failed: {}", e);
            Err(ShellError::ExecutionFailed)
        }
    }
}

/// Launch the userspace stressed memory test binary from initfs.
pub fn cmd_test_mem_stressed(_args: &[String]) -> Result<(), ShellError> {
    let path = "/initfs/test_mem_stressed";
    shell_println!("Launching {} ...", path);

    let fd = match vfs::open(path, vfs::OpenFlags::READ) {
        Ok(fd) => fd,
        Err(e) => {
            shell_println!("open failed: {:?}", e);
            return Err(ShellError::ExecutionFailed);
        }
    };

    let data = match vfs::read_all(fd) {
        Ok(d) => d,
        Err(e) => {
            let _ = vfs::close(fd);
            shell_println!("read failed: {:?}", e);
            return Err(ShellError::ExecutionFailed);
        }
    };
    let _ = vfs::close(fd);

    shell_println!("ELF size: {} bytes", data.len());
    shell_println!("Launching with task name 'init' to inherit bootstrap console/admin caps");
    match load_and_run_elf(&data, "init") {
        Ok(task_id) => {
            shell_println!("test_mem_stressed started (task id={})", task_id);
            Ok(())
        }
        Err(e) => {
            shell_println!("load_and_run_elf failed: {}", e);
            Err(ShellError::ExecutionFailed)
        }
    }
}

/// strate ls
pub fn cmd_strate(args: &[String]) -> Result<(), ShellError> {
    if args.len() != 1 || args[0].as_str() != "ls" {
        shell_println!("Usage: strate ls");
        return Err(ShellError::InvalidArguments);
    }

    let mut silos = silo::list_silos_snapshot();
    silos.sort_by_key(|s| s.id);

    shell_println!(
        "{:<6} {:<12} {:<10} {:<7} {}",
        "ID",
        "Name",
        "State",
        "Tasks",
        "Label"
    );
    shell_println!("────────────────────────────────────────────────────────────");
    for s in silos {
        let label = s.strate_label.unwrap_or_else(|| String::from("-"));
        shell_println!(
            "{:<6} {:<12} {:<10?} {:<7} {}",
            s.id,
            s.name,
            s.state,
            s.task_count,
            label
        );
    }
    Ok(())
}
