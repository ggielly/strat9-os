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

//! `vm` — command-line manager for s9vm worlds.
//!
//! The command is a thin **scheme client**: every operation goes through the
//! `/dev/vmm` VFS scheme, exactly like a userspace component would, instead of
//! calling the engine directly:
//!
//! | Command | Scheme path | Semantics |
//! |---|---|---|
//! | `vm list` | `worlds` (read) | ids, names, state, vCPU/page counters |
//! | `vm info <id>` | `<id>/info`, `<id>/stats`, `<id>/vcpus`, `<id>/timing` | world snapshot |
//! | `vm start <id>` | `control` (write `start <id>`) | resume + post one RUN per vCPU |
//! | `vm stop <id>` | `control` (write `stop <id>`) | pause the world |
//! | `vm pause/resume <id>` | `<id>/control` | the pause/resume transitions |
//! | `vm console <id>` | `<id>/console` (read) | drain the guest console |
//! | `vm send <id> <text>` | `<id>/console` (write) | queue guest console input |
//! | `vm test` | `dosboot` | boot the built-in FreeDOS 1.4 test world |
//!
//! `vm start` cannot create or configure a world: creation remains the job of
//! the `SYS_VMM_*` syscalls and their capability checks (for instance the
//! `s9vm-vmm` policy). It only schedules an existing, configured world, which
//! is what a management front-end needs once the world exists.

use super::ShellError;
use crate::shell_println;
use crate::vfs::{self, OpenFlags};
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

/// Mount point of the engine's diagnostic/control scheme.
const VMM_ROOT: &str = "/dev/vmm";

/// Reads one scheme file completely into a string.
fn read_file(path: &str) -> Result<String, ShellError> {
    let fd = vfs::open(path, OpenFlags::READ).map_err(|_| ShellError::ExecutionFailed)?;
    let mut text = String::new();
    let mut buf = [0u8; 1024];
    loop {
        match vfs::read(fd, &mut buf) {
            Ok(0) => break,
            Ok(n) => text.push_str(core::str::from_utf8(&buf[..n]).unwrap_or("<non-utf8>")),
            Err(_) => {
                let _ = vfs::close(fd);
                return Err(ShellError::ExecutionFailed);
            }
        }
    }
    let _ = vfs::close(fd);
    Ok(text)
}

/// Writes one command to a scheme control file.
fn write_text(path: &str, text: &str) -> Result<usize, ShellError> {
    let fd = vfs::open(path, OpenFlags::WRITE).map_err(|_| ShellError::ExecutionFailed)?;
    let written = vfs::write(fd, text.as_bytes()).map_err(|_| ShellError::ExecutionFailed);
    let _ = vfs::close(fd);
    written
}

/// Parses a world identifier argument.
fn parse_id(text: &str) -> Option<u64> {
    let id = text.parse::<u64>().ok()?;
    if id == 0 {
        None
    } else {
        Some(id)
    }
}

/// Human-readable name of an ABI world state.
fn state_name(state: u32) -> &'static str {
    match state {
        strat9_abi::vmm::state::CREATED => "created",
        strat9_abi::vmm::state::RUNNING => "running",
        strat9_abi::vmm::state::PAUSED => "paused",
        strat9_abi::vmm::state::STOPPED => "stopped",
        strat9_abi::vmm::state::FAILED => "failed",
        _ => "?",
    }
}

/// Extracts `key=value` from one `world …` line.
fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split_ascii_whitespace()
        .find_map(|token| token.strip_prefix(key).and_then(|rest| rest.strip_prefix('=')))
}

/// `vm list` — table of the worlds the kernel registry still owns.
fn cmd_list() -> Result<(), ShellError> {
    let text = read_file(&format!("{VMM_ROOT}/worlds"))?;
    let mut rows = 0usize;
    shell_println!(
        "{:>4}  {:<20} {:<8} {:>4} {:>7} {:>6} {:>7} {:>7} {:>7}  {}",
        "ID",
        "NAME",
        "STATE",
        "VCPU",
        "PAGES",
        "PEND",
        "RUNS",
        "EMUL",
        "POLICY",
        "PAUSED"
    );
    for line in text.lines() {
        let Some(id) = line
            .split_ascii_whitespace()
            .nth(1)
            .filter(|_| line.starts_with("world "))
        else {
            continue;
        };
        let name = field(line, "name").unwrap_or("?");
        let state = field(line, "state")
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(0);
        let paused = field(line, "paused").unwrap_or("false");
        rows += 1;
        shell_println!(
            "{:>4}  {:<20} {:<8} {:>4} {:>7} {:>6} {:>7} {:>7} {:>7}  {}",
            id,
            name,
            state_name(state),
            field(line, "vcpus").unwrap_or("?"),
            field(line, "pages").unwrap_or("?"),
            field(line, "pending_exits").unwrap_or("?"),
            field(line, "runs").unwrap_or("?"),
            field(line, "emulated").unwrap_or("?"),
            field(line, "policy_exits").unwrap_or("?"),
            if paused == "true" { "yes" } else { "no" }
        );
    }
    if rows == 0 {
        shell_println!("vm: no world in the kernel registry (nothing is virtualised).");
        shell_println!(
            "    Start one with the s9vm policy (`s9vm-vmm`) or the FreeDOS test world: `vm test`."
        );
    }
    Ok(())
}

/// `vm info <id>` — snapshot of one world from the scheme.
fn cmd_info(id: u64) -> Result<(), ShellError> {
    for leaf in ["info", "stats", "vcpus", "timing"] {
        shell_println!("--- {}:{}/{} ---", VMM_ROOT, id, leaf);
        match read_file(&format!("{VMM_ROOT}/{id}/{leaf}")) {
            Ok(text) => shell_println!("{}", text.trim_end()),
            Err(_) => shell_println!("(unavailable)"),
        }
    }
    Ok(())
}

/// `vm start <id>` / `vm stop <id>` — root control file.
fn cmd_control(verb: &str, id: u64) -> Result<(), ShellError> {
    match write_text(&format!("{VMM_ROOT}/control"), &format!("{verb} {id}\n")) {
        Ok(_) => {
            shell_println!("vm: {} world {}: ok", verb, id);
            Ok(())
        }
        Err(_) => {
            shell_println!("vm: {} world {}: failed (unknown world or scheme error)", verb, id);
            Err(ShellError::ExecutionFailed)
        }
    }
}

/// `vm pause|resume <id>` — per-world control file.
fn cmd_world_control(verb: &str, id: u64) -> Result<(), ShellError> {
    match write_text(&format!("{VMM_ROOT}/{id}/control"), &format!("{verb}\n")) {
        Ok(_) => {
            shell_println!("vm: world {}: {}", id, verb);
            Ok(())
        }
        Err(_) => {
            shell_println!("vm: world {}: {} failed", id, verb);
            Err(ShellError::ExecutionFailed)
        }
    }
}

/// `vm console <id>` — drain the guest console stream.
fn cmd_console(id: u64) -> Result<(), ShellError> {
    match read_file(&format!("{VMM_ROOT}/{id}/console")) {
        Ok(text) if text.is_empty() => shell_println!("vm: world {}: no console output pending", id),
        Ok(text) => shell_println!("{}", text.trim_end()),
        Err(_) => {
            shell_println!("vm: world {}: console unavailable", id);
            return Err(ShellError::ExecutionFailed);
        }
    }
    Ok(())
}

/// `vm send <id> <text…>` — queue guest console input.
fn cmd_send(id: u64, words: &[String]) -> Result<(), ShellError> {
    let mut text = words.join(" ");
    text.push('\n');
    match write_text(&format!("{VMM_ROOT}/{id}/console"), &text) {
        Ok(accepted) => {
            shell_println!("vm: world {}: {} byte(s) queued", id, accepted);
            Ok(())
        }
        Err(_) => {
            shell_println!("vm: world {}: console input failed", id);
            Err(ShellError::ExecutionFailed)
        }
    }
}

/// `vm test [dry]` — boot the built-in FreeDOS 1.4 test world.
fn cmd_test(args: &[String]) -> Result<(), ShellError> {
    let dry = args.first().map(|arg| arg.as_str()) == Some("dry");
    // Operator-controlled time budget, clamped so a typo cannot freeze the
    // system for an unbounded time. The guest loop keeps interrupts disabled.
    let seconds = if dry {
        0
    } else {
        args.first()
            .and_then(|arg| arg.parse::<u64>().ok())
            .unwrap_or(2)
            .clamp(1, 10)
    };
    // The dry run only installs the image in a world: it works without VT-x,
    // so it must not be skipped when detection reports no hardware support.
    let caps = crate::s9vm::detect().unwrap_or_default();
    if !crate::s9vm::detected() && !dry {
        shell_println!("vm: test VM skipped: hardware virtualization unavailable");
        return Ok(());
    }
    if dry {
        match crate::s9vm::dosboot::run_freedos_dry(&caps) {
            Ok(report) => shell_println!(
                "vm: test VM (dry) PASS: boot={:#x} entry={:#x} sectors={}",
                report.boot_sector_gpa,
                report.entry,
                report.disk_sectors
            ),
            Err(error) => shell_println!("vm: test VM (dry) FAIL: {:?}", error),
        }
        return Ok(());
    }
    if !caps.can_run() {
        shell_println!("vm: test VM skipped: the platform cannot run a guest");
        return Ok(());
    }
    shell_println!(
        "vm: booting the FreeDOS 1.4 test world (VT-x, bounded to {} s: the guest loop runs \
         with interrupts disabled, so the attempt cannot freeze the system)…",
        seconds
    );
    let limits = crate::s9vm::dosboot::RunLimits {
        max_exits: crate::s9vm::dosboot::RunLimits::SHELL.max_exits,
        max_nanoseconds: seconds.saturating_mul(1_000_000_000),
    };
    match crate::s9vm::dosboot::run_freedos_with_limits(&caps, limits) {
        Ok(report) if report.timed_out => {
            shell_println!(
                "vm: test VM INCOMPLETE (bounded run): marker={:?} exits={} bios={} hlt={} \
                 sectors={}",
                report.marker.map(|byte| byte as char),
                report.total_exits,
                report.bios_calls,
                report.halt_exits,
                report.disk_sectors
            );
            shell_println!("vm: the attempt was stopped by its time/exit budget; run `vm test`");
            shell_println!("    again, or `vm test dry` to check the image without VT-x.");
            if !report.text.is_empty() {
                shell_println!("vm: guest text so far:\n{}", report.text.trim_end());
            }
            Ok(())
        }
        Ok(report) => {
            let marker = report.marker.map(|byte| byte as char).unwrap_or('?');
            let booted = report.marker == Some(b'K') && report.text.contains("FreeDOS");
            shell_println!(
                "vm: test VM {}: marker={} exits={} io={} bios={} hlt={} sectors={}",
                if booted { "PASS" } else { "FAIL" },
                marker,
                report.total_exits,
                report.io_exits,
                report.bios_calls,
                report.halt_exits,
                report.disk_sectors
            );
            shell_println!("vm: guest text:\n{}", report.text.trim_end());
            if booted {
                Ok(())
            } else {
                shell_println!("vm: run `vm diag` for the pre-entry checks and capability masks.");
                Err(ShellError::ExecutionFailed)
            }
        }
        Err(crate::s9vm::dosboot::DosError::Unsupported) => {
            shell_println!("vm: test VM skipped: real-mode entry needs VT-x and unrestricted guest");
            Ok(())
        }
        Err(error) => {
            shell_println!("vm: test VM FAIL: {:?}", error);
            shell_println!("vm: run `vm diag` for the pre-entry checks and capability masks.");
            Err(ShellError::ExecutionFailed)
        }
    }
}

/// `vm diag` — everything needed to debug a VM-entry failure.
///
/// A hardware "invalid guest state" does not name the rejected field. This
/// command prints the capability masks the kernel validates against, replays
/// the same pre-entry checks on the real-mode and long-mode boot presets, and
/// reports the rule that fails (the engine itself logs the same check before
/// every entry).
fn cmd_diag() -> Result<(), ShellError> {
    let caps = crate::s9vm::detect().unwrap_or_default();
    shell_println!(
        "engine: detected={} can_run={} unrestricted_guest={} ept={} ept_2mb={} \
         ept_1gb={} vpid={} preemption_timer={}",
        crate::s9vm::detected(),
        caps.can_run(),
        caps.unrestricted_guest,
        caps.ept,
        caps.ept_2mb,
        caps.ept_1gb,
        caps.vpid,
        caps.preemption_timer
    );
    if !crate::s9vm::detected() {
        shell_println!(
            "fixed masks: unavailable (VT-x is not exposed here; the presets cannot be checked \
             against real capability masks)"
        );
        shell_println!("worlds in the registry: {}", crate::s9vm::vm::count());
        return Ok(());
    }
    shell_println!(
        "fixed masks: cr0_0={:#x} cr0_1={:#x} cr4_0={:#x} cr4_1={:#x}",
        caps.cr0_fixed0,
        caps.cr0_fixed1,
        caps.cr4_fixed0,
        caps.cr4_fixed1
    );
    let fixed = crate::s9vm::guest::FixedBits::new(
        caps.cr0_fixed0,
        caps.cr0_fixed1,
        caps.cr4_fixed0,
        caps.cr4_fixed1,
    );
    let presets = [
        (
            "real-mode  (FreeDOS/DOS, rip=0x7c00)",
            crate::s9vm::guest::GuestState::real_mode(0x7c00, 0x7c00),
        ),
        (
            "long-mode  (s9vm guest kernel, rip=0x100000)",
            crate::s9vm::guest::GuestState::long_mode_64(0x100000, 0x200000, 0x1000),
        ),
    ];
    for (label, state) in presets {
        match state.validate(&fixed, caps.unrestricted_guest) {
            Ok(()) => shell_println!("{}: guest state VALID", label),
            Err(error) => shell_println!("{}: guest state INVALID: {:?}", label, error),
        }
        shell_println!(
            "  cr0={:#x} cr4={:#x} efer={:#x} rflags={:#x} tr.ar={:#x} tr.lim={:#x} \
             gdtr.lim={:#x} idtr.lim={:#x}",
            state.cr0,
            state.cr4,
            state.efer,
            state.rflags,
            state.tr.access_rights,
            state.tr.limit,
            state.gdtr_limit,
            state.idtr_limit
        );
    }
    shell_println!("worlds in the registry: {}", crate::s9vm::vm::count());
    Ok(())
}

const VM_USAGE: &str = "Usage: vm <list|info <id>|start <id>|stop <id>|pause <id>|resume <id>|console <id>|send <id> <text>|test [dry|seconds]|diag>";

/// `vm` — manage the s9vm worlds through the `/dev/vmm` scheme.
pub fn cmd_vm(args: &[String]) -> Result<(), ShellError> {
    let sub = args.first().map(|arg| arg.as_str()).unwrap_or("list");
    match sub {
        "list" | "ls" => cmd_list(),
        "info" | "show" => match args.get(1).and_then(|arg| parse_id(arg)) {
            Some(id) => cmd_info(id),
            None => {
                shell_println!("{}", VM_USAGE);
                Err(ShellError::InvalidArguments)
            }
        },
        "start" | "stop" => match args.get(1).and_then(|arg| parse_id(arg)) {
            Some(id) => cmd_control(sub, id),
            None => {
                shell_println!("{}", VM_USAGE);
                Err(ShellError::InvalidArguments)
            }
        },
        "pause" | "resume" => match args.get(1).and_then(|arg| parse_id(arg)) {
            Some(id) => cmd_world_control(sub, id),
            None => {
                shell_println!("{}", VM_USAGE);
                Err(ShellError::InvalidArguments)
            }
        },
        "console" | "log" => match args.get(1).and_then(|arg| parse_id(arg)) {
            Some(id) => cmd_console(id),
            None => {
                shell_println!("{}", VM_USAGE);
                Err(ShellError::InvalidArguments)
            }
        },
        "send" | "input" => match args.get(1).and_then(|arg| parse_id(arg)) {
            Some(id) => cmd_send(id, &args[2..]),
            None => {
                shell_println!("{}", VM_USAGE);
                Err(ShellError::InvalidArguments)
            }
        },
        "test" => cmd_test(&args[1..]),
        "diag" | "debug" => cmd_diag(),
        "help" | "-h" | "--help" => {
            shell_println!("{}", VM_USAGE);
            shell_println!("  The command is a client of the /dev/vmm scheme:");
            shell_println!("    /dev/vmm/worlds, /dev/vmm/<id>/{{info,stats,vcpus,timing,console}}");
            shell_println!("    /dev/vmm/control            (write: start <id> | stop <id>)");
            shell_println!("    /dev/vmm/<id>/control       (write: start | stop | pause | resume)");
            shell_println!(
                "  `vm test [dry|seconds]` boots the bundled FreeDOS 1.4 floppy with a bounded \
                 time budget (VT-x needed; `vm test dry` checks the image without VT-x); \
                 `vm diag` prints the capability masks and replays the pre-entry guest-state \
                 checks."
            );
            Ok(())
        }
        _ => {
            shell_println!("{}", VM_USAGE);
            Err(ShellError::UnknownCommand)
        }
    }
}
