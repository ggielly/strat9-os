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

    shell_println!("[shutdown] Powering off...");
    unsafe {
        crate::arch::cli();
        // QEMU/Bochs ACPI shutdown
        crate::arch::io::outw(0x604, 0x2000);
        // Fallback: older QEMU
        crate::arch::io::outw(0xB004, 0x2000);
        loop {
            crate::arch::hlt();
        }
    }
}
