use super::*;

/// Graceful shutdown: stop strates in reverse order, then power off.
///
/// QEMU/KVM ACPI shutdown uses I/O port 0x604 (Bochs/QEMU) or 0xB004 (older).
pub fn cmd_shutdown(_args: &[String]) -> Result<(), ShellError> {
    shell_println!("[shutdown] Stopping silos...");

    let mut silos = crate::silo::list_silos_snapshot();
    silos.sort_by(|a, b| b.id.cmp(&a.id));

    for s in &silos {
        shell_println!("  stopping silo {} ({})", s.id, s.name);
        let _ = crate::silo::kernel_suspend_silo(&alloc::format!("{}", s.id));
    }

    shell_println!("[shutdown] Killing remaining tasks...");
    let current_tid = crate::process::current_task_clone().map(|t| t.id);
    if let Some(tasks) = crate::process::get_all_tasks() {
        for t in tasks.iter().rev() {
            let tid = t.id;
            if tid.as_u64() <= 1 || current_tid == Some(tid) {
                continue;
            }
            crate::process::kill_task(tid);
        }
    }

    for _ in 0..500 {
        crate::process::yield_task();
    }

    shell_println!("[shutdown] Power off...");
    unsafe {
        crate::arch::x86_64::cli();
        // QEMU/Bochs ACPI shutdown
        crate::arch::x86_64::io::outw(0x604, 0x2000);
        // Fallback: older QEMU
        crate::arch::x86_64::io::outw(0xB004, 0x2000);
        loop {
            crate::arch::x86_64::hlt();
        }
    }
}
