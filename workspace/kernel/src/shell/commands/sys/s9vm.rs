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

const S9VM_USAGE: &str = "Usage: s9vm <status|capabilities|list|selftest>";

/// Show or exercise the s9vm virtualization engine.
pub fn cmd_s9vm(args: &[String]) -> Result<(), ShellError> {
    let sub = args.first().map(|value| value.as_str()).unwrap_or("status");
    match sub {
        "status" => cmd_status(),
        "capabilities" | "caps" => cmd_capabilities(),
        "list" => cmd_list(),
        "selftest" => cmd_selftest(),
        "help" | "-h" | "--help" => {
            shell_println!("{}", S9VM_USAGE);
            Ok(())
        }
        _ => {
            shell_println!("{}", S9VM_USAGE);
            Err(ShellError::InvalidArguments)
        }
    }
}

fn cmd_status() -> Result<(), ShellError> {
    let detected = crate::s9vm::detected();
    let active = crate::s9vm::active_cpu_count();
    let worlds = crate::s9vm::vm::count();
    shell_println!("s9vm: {}", if detected { "detected" } else { "unavailable" });
    if !detected {
        shell_println!("  reason: {}", crate::s9vm::unavailable_reason());
    }
    shell_println!("active cpus: {}", active);
    shell_println!("worlds: {}", worlds);
    if detected {
        if let Some(caps) = crate::s9vm::detect() {
            shell_println!(
                "second level: ept={} 2M={} 1G={} ad={} vpid={}",
                caps.ept,
                caps.ept_2mb,
                caps.ept_1gb,
                caps.ept_ad,
                caps.vpid
            );
            shell_println!(
                "interrupts: apicv={} posted={} x2apic={}",
                caps.apic_register_virt && caps.virtual_interrupt_delivery,
                caps.posted_interrupts,
                caps.virtualize_x2apic
            );
        }
    }
    Ok(())
}

fn cmd_capabilities() -> Result<(), ShellError> {
    let Some(caps) = crate::s9vm::detect() else {
        shell_println!("s9vm: VT-x unavailable on this CPU");
        return Ok(());
    };
    shell_println!("s9vm capabilities: {}", caps.summary());
    shell_println!("can run (ept+4 levels): {}", caps.can_run());
    Ok(())
}

fn cmd_list() -> Result<(), ShellError> {
    let worlds = crate::s9vm::vm::list();
    if worlds.is_empty() {
        shell_println!("no virtual world");
        return Ok(());
    }
    shell_println!("id   name                             vcpus pages state");
    for world in worlds {
        let name = core::str::from_utf8(world.name_slice()).unwrap_or("<invalid>");
        shell_println!(
            "{:<4} {:<32} {:>5} {:>5} {}",
            world.id,
            name,
            world.vcpu_count,
            world.mapped_pages,
            world.state
        );
    }
    Ok(())
}

fn cmd_selftest() -> Result<(), ShellError> {
    let Some(caps) = crate::s9vm::detect() else {
        shell_println!("s9vm: VT-x unavailable, selftest skipped");
        return Ok(());
    };
    if crate::s9vm::active_cpu_count() == 0 {
        shell_println!("s9vm: engine not activated on any CPU, selftest skipped");
        return Ok(());
    }
    match crate::s9vm::selftest::run(&caps) {
        Ok(report) => {
            shell_println!(
                "s9vm selftest: PASS (exits={}, io={}, hlt={})",
                report.total_exits,
                report.io_exits,
                report.halt_exits
            );
            Ok(())
        }
        Err(error) => {
            shell_println!("s9vm selftest: FAIL ({:?})", error);
            Err(ShellError::ExecutionFailed)
        }
    }
}
