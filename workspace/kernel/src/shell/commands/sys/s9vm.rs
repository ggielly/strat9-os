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

const S9VM_USAGE: &str = "Usage: s9vm <status|capabilities|list|timing|selftest|phase <name>>";

/// Show or exercise the s9vm virtualization engine.
pub fn cmd_s9vm(args: &[String]) -> Result<(), ShellError> {
    let sub = args.first().map(|value| value.as_str()).unwrap_or("status");
    match sub {
        "status" => cmd_status(),
        "capabilities" | "caps" => cmd_capabilities(),
        "list" => cmd_list(),
        "timing" => cmd_timing(),
        "selftest" => cmd_selftest(),
        "phase" | "demo" => cmd_phase(args.get(1).map(|value| value.as_str())),
        "help" | "-h" | "--help" => {
            shell_println!("{}", S9VM_USAGE);
            shell_println!("  phase <device|irq|console|blk|net|loader|acpi|smp>");
            shell_println!("  timing   per-world exit latency/rate aggregates");
            Ok(())
        }
        _ => {
            shell_println!("{}", S9VM_USAGE);
            Err(ShellError::InvalidArguments)
        }
    }
}

/// Runs one hardware phase on demand (the same code as the boot selftest).
///
/// This is the interactive counterpart of `s9vm.selftest=<phase>`: it lets an
/// operator re-run a single phase after boot, with the report printed on the
/// shell instead of the serial log.
fn cmd_phase(name: Option<&str>) -> Result<(), ShellError> {
    use crate::s9vm::selftest;
    let Some(caps) = crate::s9vm::detect() else {
        shell_println!("s9vm: hardware virtualization unavailable");
        return Ok(());
    };
    if !caps.can_run() {
        shell_println!("s9vm: the platform cannot run a guest");
        return Ok(());
    }
    let phase = name.unwrap_or("loader");
    let outcome: Result<(), selftest::SelftestError> = match phase {
        "device" | "1" => selftest::run(&caps).map(|report| {
            shell_println!(
                "device PASS: exits={} io={} hlt={} emulated={} pic={:?} byte={:?}",
                report.total_exits,
                report.io_exits,
                report.halt_exits,
                report.emulated_exits,
                report.pic_readback,
                report.observed_byte
            );
        }),
        "irq" => selftest::run_interrupt(&caps).map(|report| {
            shell_println!(
                "irq PASS: exits={} io={} hlt={}",
                report.total_exits,
                report.io_exits,
                report.halt_exits
            );
        }),
        "console" => selftest::run_console(&caps).map(|report| {
            shell_println!(
                "console PASS: exits={} emulated={} io={} hlt={} marker={:?}",
                report.total_exits,
                report.emulated_exits,
                report.io_exits,
                report.halt_exits,
                report.marker
            );
        }),
        "blk" | "block" => selftest::run_blk(&caps).map(|report| {
            shell_println!(
                "block PASS: exits={} emulated={} io={} hlt={} marker={:?}",
                report.total_exits,
                report.emulated_exits,
                report.io_exits,
                report.halt_exits,
                report.marker
            );
        }),
        "net" => selftest::run_net(&caps).map(|report| {
            shell_println!(
                "net PASS: exits={} emulated={} hlt={} marker={:?} transmitted={}",
                report.total_exits,
                report.emulated_exits,
                report.halt_exits,
                report.marker,
                report.transmitted
            );
        }),
        "loader" => selftest::run_loader(&caps).map(|report| {
            shell_println!(
                "loader PASS: entry={:#x} base={:#x} pages={} exits={} io={} hlt={} marker={:?}",
                report.entry,
                report.image_base,
                report.pages,
                report.total_exits,
                report.io_exits,
                report.halt_exits,
                report.marker
            );
        }),
        "acpi" => selftest::run_acpi(&caps).map(|report| {
            shell_println!(
                "acpi PASS: rsdp={:#x} madt_apics={} expected={} exits={} io={} hlt={} marker={:?}",
                report.rsdp,
                report.madt_apics,
                report.expected_apics,
                report.total_exits,
                report.io_exits,
                report.halt_exits,
                report.marker
            );
        }),
        "smp" => selftest::run_smp(&caps).map(|report| {
            shell_println!(
                "smp PASS: vcpus={} exits={} hlt={} runs={}",
                report.vcpus,
                report.exits,
                report.hlt,
                report.runs
            );
        }),
        other => {
            shell_println!("s9vm: unknown phase `{}`", other);
            shell_println!("{}", S9VM_USAGE);
            return Err(ShellError::InvalidArguments);
        }
    };
    if let Err(error) = outcome {
        shell_println!("s9vm: phase `{}` FAILED: {:?}", phase, error);
        return Err(ShellError::ExecutionFailed);
    }
    Ok(())
}

/// Prints the cumulative timing aggregates of every world.
fn cmd_timing() -> Result<(), ShellError> {
    let worlds = crate::s9vm::vm::list();
    if worlds.is_empty() {
        shell_println!("s9vm: no world");
        return Ok(());
    }
    for world in worlds {
        let name = core::str::from_utf8(world.name_slice()).unwrap_or("<non-utf8>");
        shell_println!("world {} `{}`", world.id, name);
        match crate::s9vm::vm::timing(world.id) {
            Some(timing) => {
                shell_println!(
                    "  exits={} mean={}cy p95={}cy min={}cy max={}cy window={} peak={}",
                    timing.exits,
                    timing.mean_cycles,
                    timing.p95_cycles,
                    timing.min_cycles,
                    timing.max_cycles,
                    timing.window,
                    timing.peak_window
                );
                shell_println!(
                    "  handler: samples={} mean={}cy p95={}cy",
                    timing.handler_samples,
                    timing.handler_mean_cycles,
                    timing.handler_p95_cycles
                );
            }
            None => shell_println!("  timing: unavailable"),
        }
        match crate::s9vm::vm::stats(world.id) {
            Some(stats) => shell_println!(
                "  runs={} policy_exits={} emulated={} (io={} mmio={} msr={}) irq={}",
                stats.runs,
                stats.policy_exits,
                stats.emulated_exits,
                stats.emulated_io,
                stats.emulated_mmio,
                stats.emulated_msr,
                stats.injected_interrupts
            ),
            None => {}
        }
    }
    Ok(())
}

fn cmd_status() -> Result<(), ShellError> {
    let detected = crate::s9vm::detected();
    let active = crate::s9vm::active_cpu_count();
    let worlds = crate::s9vm::vm::count();
    shell_println!(
        "s9vm: {}",
        if detected { "detected" } else { "unavailable" }
    );
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
