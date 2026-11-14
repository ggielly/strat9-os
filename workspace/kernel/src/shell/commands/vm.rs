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

//! `vm` : command-line manager for s9vm worlds.
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
//! | `vm test [seabios\|hello] [dry\|seconds]` | `dosboot` | boot the FreeDOS test/demo world (stub, SeaBIOS or Hello/DIR image) |
//!
//! `vm start` cannot create or configure a world: creation remains the job of
//! the `SYS_VMM_*` syscalls and their capability checks (for instance the
//! `s9vm-vmm` policy). It only schedules an existing, configured world, which
//! is what a management front-end needs once the world exists.

use super::ShellError;
use crate::{
    shell_println,
    vfs::{self, OpenFlags},
};
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
    line.split_ascii_whitespace().find_map(|token| {
        token
            .strip_prefix(key)
            .and_then(|rest| rest.strip_prefix('='))
    })
}

/// `vm list` : table of the worlds the kernel registry still owns.
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

/// `vm info <id>` : snapshot of one world from the scheme.
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

/// `vm start <id>` / `vm stop <id>` : root control file.
fn cmd_control(verb: &str, id: u64) -> Result<(), ShellError> {
    match write_text(&format!("{VMM_ROOT}/control"), &format!("{verb} {id}\n")) {
        Ok(_) => {
            shell_println!("vm: {} world {}: ok", verb, id);
            Ok(())
        }
        Err(_) => {
            shell_println!(
                "vm: {} world {}: failed (unknown world or scheme error)",
                verb,
                id
            );
            Err(ShellError::ExecutionFailed)
        }
    }
}

/// `vm pause|resume <id>` : per-world control file.
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

/// `vm console <id>` : drain the guest console stream.
fn cmd_console(id: u64) -> Result<(), ShellError> {
    match read_file(&format!("{VMM_ROOT}/{id}/console")) {
        Ok(text) if text.is_empty() => {
            shell_println!("vm: world {}: no console output pending", id)
        }
        Ok(text) => shell_println!("{}", text.trim_end()),
        Err(_) => {
            shell_println!("vm: world {}: console unavailable", id);
            return Err(ShellError::ExecutionFailed);
        }
    }
    Ok(())
}

/// `vm send <id> <text…>` : queue guest console input.
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

/// Expands the escape sequences accepted in `vm test keys=<text>`.
///
/// The shell already splits arguments on spaces, so a caller writes the keys it
/// wants to type with `\r` for Enter, `\t` for Tab, `\e` for Escape and `\\`
/// for a literal backslash.
fn unescape_keys(text: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(text.len());
    let mut chars = text.bytes();
    while let Some(byte) = chars.next() {
        if byte != b'\\' {
            bytes.push(byte);
            continue;
        }
        match chars.next() {
            Some(b'r') | Some(b'n') => bytes.push(b'\r'),
            Some(b't') => bytes.push(b'\t'),
            Some(b'e') => bytes.push(0x1b),
            Some(b'\\') => bytes.push(b'\\'),
            Some(other) => {
                bytes.push(b'\\');
                bytes.push(other);
            }
            None => bytes.push(b'\\'),
        }
    }
    bytes
}

/// `vm test [seabios|hello] [dry|seconds] [keys=<text>]` : boot a FreeDOS test world.
fn cmd_test(args: &[String]) -> Result<(), ShellError> {
    // Accept the switches in any order: `vm test 5`, `vm test seabios 10` and
    // `vm test dry` all work. An unrecognised word is reported instead of being
    // silently dropped, which used to turn `vm test dosbox 5` into a 2 s run.
    let mut seabios = false;
    let mut hello = false;
    let mut dry = false;
    let mut seconds: Option<u64> = None;
    let mut keys: Vec<u8> = Vec::new();
    for arg in args {
        if let Some(text) = arg.strip_prefix("keys=") {
            keys = unescape_keys(text);
            continue;
        }
        match arg.as_str() {
            "seabios" => seabios = true,
            "hello" => hello = true,
            "dry" => dry = true,
            _ => match arg.parse::<u64>() {
                Ok(value) => seconds = Some(value),
                Err(_) => shell_println!(
                    "vm: ignoring unknown argument `{}` (usage: `vm test [seabios|hello] \
                     [dry|seconds] [keys=<text>]`)",
                    arg
                ),
            },
        }
    }
    // Operator-controlled time budget, clamped so a typo cannot freeze the
    // system for an unbounded time. The guest loop keeps interrupts disabled.
    let seconds = if dry {
        0
    } else {
        seconds.unwrap_or(2).clamp(1, 10)
    };
    // The dry run only installs the image in a world: it works without VT-x,
    // so it must not be skipped when detection reports no hardware support.
    let caps = crate::s9vm::detect().unwrap_or_default();
    if !crate::s9vm::detected() && !dry {
        shell_println!("vm: test VM skipped: hardware virtualization unavailable");
        return Ok(());
    }
    if dry {
        let result = if hello {
            crate::s9vm::dosboot::run_freedos_hello_dry(&caps)
        } else if seabios {
            crate::s9vm::dosboot::run_freedos_seabios_dry(&caps)
        } else {
            crate::s9vm::dosboot::run_freedos_dry(&caps)
        };
        match result {
            Ok(report) => shell_println!(
                "vm: test VM (dry{}) PASS: boot/reset={:#x} entry={:#x} sectors={}",
                if hello {
                    ", hello"
                } else if seabios {
                    ", seabios"
                } else {
                    ""
                },
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
        "vm: booting the FreeDOS {} world with {} (VT-x, bounded to {} s: the guest \
         loop runs with interrupts disabled, so the attempt cannot freeze the system)…",
        if hello { "Hello/DIR demo" } else { "1.4 test" },
        if hello || seabios {
            "SeaBIOS"
        } else {
            "the s9vm stub firmware"
        },
        seconds
    );
    let limits = crate::s9vm::dosboot::RunLimits {
        max_exits: crate::s9vm::dosboot::RunLimits::SHELL.max_exits,
        max_nanoseconds: seconds.saturating_mul(1_000_000_000),
        // Typed keys run after the marker: keep the guest alive to the budget.
        stop_at_marker: keys.is_empty(),
    };
    let result = if hello {
        crate::s9vm::dosboot::run_freedos_hello_with_limits(&caps, limits)
    } else if seabios {
        crate::s9vm::dosboot::run_freedos_seabios_with_limits(&caps, limits)
    } else {
        crate::s9vm::dosboot::run_freedos_with_limits_and_keys(&caps, limits, &keys)
    };
    match result {
        Ok(report) => {
            let booted = report.marker == Some(b'K')
                && report.text.contains("FreeDOS")
                && (!hello || report.text.contains("Hello world, from FreeDOS"));
            let marker = report.marker.map(|byte| byte as char);
            if booted {
                shell_println!(
                    "vm: test VM PASS: marker={} exits={} io={} bios={} hlt={} ext={} int={} \
                     irq={} keys={} sectors={}",
                    marker.unwrap_or('?'),
                    report.total_exits,
                    report.io_exits,
                    report.bios_calls,
                    report.halt_exits,
                    report.external_interrupts,
                    report.unhandled_interrupts,
                    report.interrupts_delivered,
                    report.scancodes_typed,
                    report.disk_sectors
                );
                shell_println!("vm: BIOS vectors: {}", report.vector_summary());
                print_dos_performance(&report);
                shell_println!("vm: guest text:\n{}", report.text.trim_end());
                return Ok(());
            }
            // With typed keys the runner continues past the marker to its time
            // budget, so success is the marker plus the boot text.
            if !keys.is_empty() && report.marker == Some(b'K') && report.text.contains("FreeDOS") {
                shell_println!(
                    "vm: test VM PASS (bounded run with typed keys): exits={} io={} bios={} \
                     hlt={} ext={} int={} irq={} keys={} sectors={}",
                    report.total_exits,
                    report.io_exits,
                    report.bios_calls,
                    report.halt_exits,
                    report.external_interrupts,
                    report.unhandled_interrupts,
                    report.interrupts_delivered,
                    report.scancodes_typed,
                    report.disk_sectors
                );
                shell_println!("vm: BIOS vectors: {}", report.vector_summary());
                print_dos_performance(&report);
                shell_println!("vm: guest text:\n{}", report.text.trim_end());
                return Ok(());
            }
            if report.timed_out {
                shell_println!(
                    "vm: test VM INCOMPLETE (bounded run): marker={:?} exits={} io={} bios={} \
                     hlt={} ext={} int={} irq={} keys={} sectors={}",
                    marker,
                    report.total_exits,
                    report.io_exits,
                    report.bios_calls,
                    report.halt_exits,
                    report.external_interrupts,
                    report.unhandled_interrupts,
                    report.interrupts_delivered,
                    report.scancodes_typed,
                    report.disk_sectors
                );
                shell_println!(
                    "vm: the attempt was stopped by its time/exit budget (`vm test <1..10>` \
                     for a longer run); no world is left behind."
                );
                shell_println!("vm: BIOS vectors: {}", report.vector_summary());
                print_dos_performance(&report);
                if !report.text.is_empty() {
                    shell_println!("vm: guest text so far:\n{}", report.text.trim_end());
                }
                return Ok(());
            }
            shell_println!(
                "vm: test VM FAIL: marker={:?} exits={} io={} bios={} hlt={} ext={} int={} \
                 irq={} keys={} sectors={}",
                marker,
                report.total_exits,
                report.io_exits,
                report.bios_calls,
                report.halt_exits,
                report.external_interrupts,
                report.unhandled_interrupts,
                report.interrupts_delivered,
                report.scancodes_typed,
                report.disk_sectors
            );
            shell_println!("vm: guest text:\n{}", report.text.trim_end());
            shell_println!("vm: run `vm diag` for the pre-entry checks and capability masks.");
            Err(ShellError::ExecutionFailed)
        }
        Err(crate::s9vm::dosboot::DosError::Unsupported) => {
            shell_println!(
                "vm: test VM skipped: real-mode entry needs VT-x and unrestricted guest"
            );
            Ok(())
        }
        Err(error) => {
            shell_println!("vm: test VM FAIL: {:?} ({})", error, error.hint());
            shell_println!("vm: run `vm diag` for the pre-entry checks and capability masks.");
            Err(ShellError::ExecutionFailed)
        }
    }
}

/// Writes raw bytes to a scheme device file.
fn write_bytes(path: &str, bytes: &[u8]) -> Result<usize, ShellError> {
    let fd = vfs::open(path, OpenFlags::WRITE).map_err(|_| ShellError::ExecutionFailed)?;
    let written = vfs::write(fd, bytes).map_err(|_| ShellError::ExecutionFailed);
    let _ = vfs::close(fd);
    written
}

/// Prints the exit rate and the most-accessed legacy ports of a DOS run.
///
/// These are the figures the port-dispatch work is measured on: the rate only
/// moves when the per-exit cost moves, and the histogram says which ports the
/// exit cost is spent on (a coalescing change has to aim at the top entries).
fn print_dos_performance(report: &crate::s9vm::dosboot::DosReport) {
    if report.elapsed_nanoseconds != 0 {
        shell_println!(
            "vm: guest ran {} ms at {} exits/s",
            report.elapsed_nanoseconds / 1_000_000,
            report.exits_per_second()
        );
    }
    if !report.port_calls.is_empty() {
        shell_println!("vm: top ports: {}", report.port_summary());
    }
}

/// Prints the lines of `current` that differ from `previous`.
///
/// The DOS screen is a fixed text grid, so comparing line by line keeps the
/// interactive console readable: after a `DIR`, the prompt and the listing are
/// printed instead of the whole 25-line screen.
fn print_screen_changes(previous: &str, current: &str) {
    let mut before = previous.lines();
    for line in current.lines() {
        let old = before.next().unwrap_or("");
        if old == line {
            continue;
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            continue;
        }
        shell_println!("{trimmed}");
    }
}

/// `vm dos <open [seabios]|run [seconds] [keys=<text>]|console|info|state|text|selftest|reset|close>` : live DOS session.
///
/// The DOS world stays mapped between commands: `vm dos console` keeps the
/// guest running in short slices while host keystrokes are typed into it (the
/// interactive path), `vm dos run` enters it for one bounded slice, `vm send
/// <id> <text>` queues keyboard input for the next slice and `vm console <id>`
/// shows the screen the last slice produced.
fn cmd_dos(args: &[String]) -> Result<(), ShellError> {
    use crate::s9vm::dosboot;
    let sub = args.first().map(|arg| arg.as_str()).unwrap_or("run");
    let caps = crate::s9vm::detect().unwrap_or_default();
    match sub {
        "open" | "boot" => {
            if !caps.can_run() {
                shell_println!("vm: DOS session needs VT-x and unrestricted guest");
                return Ok(());
            }
            if args.iter().skip(1).any(|arg| arg == "seabios") {
                shell_println!(
                    "vm: live sessions resume the stub firmware; use `vm test seabios` for the \
                     real-BIOS boot"
                );
                return Err(ShellError::InvalidArguments);
            }
            let firmware = dosboot::FirmwareKind::Stub;
            match dosboot::dos_open(&caps, firmware, dosboot::freedos_image()) {
                Ok(id) => {
                    shell_println!(
                        "vm: DOS session open on world {id}: `vm dos console`, `vm dos run`, \
                         `vm send {id} <text>`, `vm console {id}`, `vm dos close`"
                    );
                    Ok(())
                }
                Err(error) => {
                    shell_println!("vm: cannot open the DOS session: {:?} ({})", error, error.hint());
                    Err(ShellError::ExecutionFailed)
                }
            }
        }
        "run" | "resume" => {
            let Some(id) = dosboot::dos_world_id() else {
                shell_println!("vm: no DOS session: run `vm dos open` first");
                return Err(ShellError::ExecutionFailed);
            };
            let mut seconds = 2u64;
            let mut keys: Vec<u8> = Vec::new();
            for arg in args.iter().skip(1) {
                if let Some(text) = arg.strip_prefix("keys=") {
                    keys = unescape_keys(text);
                } else if let Ok(value) = arg.parse::<u64>() {
                    seconds = value;
                }
            }
            if !keys.is_empty() {
                // Same path as `vm send`: the runner types the queued bytes at
                // the next entry.
                let _ = write_bytes(&format!("{VMM_ROOT}/{id}/console"), &keys);
            }
            let limits = dosboot::RunLimits {
                max_exits: dosboot::RunLimits::SHELL.max_exits,
                max_nanoseconds: seconds.clamp(1, 10).saturating_mul(1_000_000_000),
                stop_at_marker: false,
            };
            match dosboot::dos_run(&caps, limits) {
                Ok(report) => {
                    shell_println!(
                        "vm: DOS slice: exits={} io={} bios={} hlt={} irq={} keys={} marker={:?}",
                        report.total_exits,
                        report.io_exits,
                        report.bios_calls,
                        report.halt_exits,
                        report.interrupts_delivered,
                        report.scancodes_typed,
                        report.marker.map(|byte| byte as char)
                    );
                    // Which firmware services the guest actually called: this
                    // is what distinguishes "the guest never reached INT 16h"
                    // from "it called it and got nothing" when a slice fails on
                    // real hardware.
                    if report.bios_calls != 0 {
                        shell_println!("vm: BIOS vectors: {}", report.vector_summary());
                    }
                    print_dos_performance(&report);
                    if report.unhandled_interrupts != 0 {
                        shell_println!(
                            "vm: {} unserviced interrupt(s): check the kernel log for the \
                             vector that faulted",
                            report.unhandled_interrupts
                        );
                    }
                    if !report.text.is_empty() {
                        shell_println!("vm: screen:\n{}", report.text.trim_end());
                    }
                    Ok(())
                }
                Err(error) => {
                    // A DOS `reboot` is a request, not a fault: honour it by
                    // starting a fresh session for the same firmware and image,
                    // which is what the operator asked the guest to do. The
                    // world and its disk are recreated, so nothing partial from
                    // the interrupted boot survives.
                    if matches!(
                        error,
                        dosboot::DosError::BadExit("guest requested reset")
                            | dosboot::DosError::BadExit("guest requested reboot")
                    ) {
                        let _ = dosboot::dos_close();
                        match dosboot::dos_open(
                            &caps,
                            dosboot::FirmwareKind::Stub,
                            dosboot::freedos_image(),
                        ) {
                            Ok(id) => {
                                shell_println!(
                                    "vm: the guest asked for a reset: DOS session rebooted on \
                                     world {id}"
                                );
                                return Ok(());
                            }
                            Err(error) => {
                                shell_println!(
                                    "vm: the guest asked for a reset but the session could not be \
                                     reopened: {:?} ({})",
                                    error,
                                    error.hint()
                                );
                                return Err(ShellError::ExecutionFailed);
                            }
                        }
                    }
                    shell_println!("vm: DOS slice failed: {:?} ({})", error, error.hint());
                    Err(ShellError::ExecutionFailed)
                }
            }
        }
        "reset" | "reboot" => {
            let had = dosboot::dos_close();
            if !caps.can_run() {
                shell_println!("vm: DOS session needs VT-x and unrestricted guest");
                return Ok(());
            }
            match dosboot::dos_open(&caps, dosboot::FirmwareKind::Stub, dosboot::freedos_image())
            {
                Ok(id) => {
                    shell_println!(
                        "vm: DOS session reset on world {id}{}",
                        if had { "" } else { " (no previous session)" }
                    );
                    Ok(())
                }
                Err(error) => {
                    shell_println!(
                        "vm: cannot reset the DOS session: {:?} ({})",
                        error,
                        error.hint()
                    );
                    Err(ShellError::ExecutionFailed)
                }
            }
        }
        "selftest" | "check" => {
            // One command that proves the interactive path end to end: boot
            // to the prompt, type `dir`, then copy a file and read it back.
            if !caps.can_run() {
                shell_println!(
                    "vm: DOS session selftest needs VT-x and unrestricted guest ({})",
                    crate::s9vm::dosboot::DosError::Unsupported.hint()
                );
                return Ok(());
            }
            let _ = dosboot::dos_close();
            shell_println!(
                "vm: DOS session selftest: boot + typed `dir` + disk round-trip (about 20 s)…"
            );
            match dosboot::run_freedos_session_selftest(&caps) {
                Ok(()) => {
                    shell_println!(
                        "vm: DOS session PASS: prompt reached, keys typed, file copied and read \
                         back"
                    );
                    Ok(())
                }
                Err(error) => {
                    shell_println!(
                        "vm: DOS session FAIL: {:?} ({})",
                        error,
                        error.hint()
                    );
                    Err(ShellError::ExecutionFailed)
                }
            }
        }
        "info" | "status" => match dosboot::dos_status() {
            Some(status) => {
                shell_println!(
                    "vm: DOS session on world {}: slices={} marker={} pending_keys={} \
                     last: exits={} irq={} keys={}",
                    status.world_id,
                    status.slices,
                    status.marker_seen,
                    status.pending_keys,
                    status.last_exits,
                    status.last_irq,
                    status.last_keys
                );
                Ok(())
            }
            None => {
                shell_println!("vm: no DOS session: run `vm dos open` first");
                Err(ShellError::ExecutionFailed)
            }
        },
        "console" | "attach" => {
            // Interactive console: host keystrokes are handed to the guest
            // between short slices and the screen changes are printed as they
            // happen. The shell's line editor is not active here, so the bytes
            // come straight from the task-context keyboard queue.
            let Some(mut id) = dosboot::dos_world_id() else {
                shell_println!("vm: no DOS session: run `vm dos open` first");
                return Err(ShellError::ExecutionFailed);
            };
            shell_println!(
                "vm: DOS console on world {id}: type at the DOS prompt, Ctrl-C returns to the \
                 shell"
            );
            // An optional duration bounds the loop for scripted use; without it
            // the console runs until Ctrl-C.
            let mut seconds = 0u64;
            for arg in args.iter().skip(1) {
                if let Ok(value) = arg.parse::<u64>() {
                    seconds = value;
                }
            }
            let slice_ns = 150_000_000u64;
            let max_slices = if seconds == 0 {
                u64::MAX
            } else {
                seconds.saturating_mul(1_000_000_000) / slice_ns
            };
            let mut slices = 0u64;
            let mut screen = dosboot::dos_text().unwrap_or_default();
            print_screen_changes("", &screen);
            loop {
                if slices >= max_slices {
                    break;
                }
                slices += 1;
                let mut text: Vec<u8> = Vec::new();
                let mut interrupted = false;
                while let Some(byte) = crate::arch::x86_64::keyboard::read_char() {
                    match byte {
                        0x03 => {
                            interrupted = true;
                            break;
                        }
                        b'\r' | b'\n' => text.push(b'\r'),
                        0x08 | 0x7F => text.push(0x08),
                        0x20..=0x7E => text.push(byte),
                        // Arrows/Home/End reach the guest as extended PS/2
                        // scan codes, which is what DOS command editing needs.
                        0x80..=0x85 => text.push(byte),
                        _ => {}
                    }
                }
                if interrupted {
                    break;
                }
                if !text.is_empty() {
                    let _ = write_bytes(&format!("{VMM_ROOT}/{id}/console"), &text);
                }
                let limits = dosboot::RunLimits {
                    max_exits: dosboot::RunLimits::SHELL.max_exits,
                    max_nanoseconds: slice_ns,
                    stop_at_marker: false,
                };
                match dosboot::dos_run(&caps, limits) {
                    Ok(_) => {}
                    Err(dosboot::DosError::BadExit("guest requested reset"))
                    | Err(dosboot::DosError::BadExit("guest requested reboot")) => {
                        // A DOS `reboot` is honoured in place, like the slice
                        // path does: a fresh session for the same image.
                        let _ = dosboot::dos_close();
                        match dosboot::dos_open(
                            &caps,
                            dosboot::FirmwareKind::Stub,
                            dosboot::freedos_image(),
                        ) {
                            Ok(reopened) => {
                                id = reopened;
                                shell_println!("vm: the guest rebooted on world {id}");
                                screen.clear();
                            }
                            Err(error) => {
                                shell_println!(
                                    "vm: the guest rebooted but the session could not be \
                                     reopened: {:?} ({})",
                                    error,
                                    error.hint()
                                );
                                return Err(ShellError::ExecutionFailed);
                            }
                        }
                    }
                    Err(error) => {
                        shell_println!("vm: DOS console stopped: {:?} ({})", error, error.hint());
                        return Err(ShellError::ExecutionFailed);
                    }
                }
                let current = dosboot::dos_text().unwrap_or_default();
                print_screen_changes(&screen, &current);
                screen = current;
            }
            shell_println!(
                "vm: DOS console detached; the session stays open for `vm dos run`"
            );
            Ok(())
        }
        "state" | "diag" => match dosboot::dos_machine_state() {
            Ok(state) => {
                // One read-only snapshot of the machine, so a failing hardware
                // run can be diagnosed without hunting through the kernel log.
                shell_println!(
                    "vm: DOS state on world {}: slices={} marker={} pending_keys={} \
                     (scancodes={} buffer={})",
                    state.world_id,
                    state.slices,
                    state.marker_seen,
                    state.pending_scancodes + state.pending_buffer_keys,
                    state.pending_scancodes,
                    state.pending_buffer_keys
                );
                shell_println!(
                    "vm: guest {:04x}:{:04x}  INT 9 owner={}  INT 16h owner={}",
                    state.cs,
                    state.ip,
                    if state.guest_owns_int9 {
                        "guest"
                    } else {
                        "firmware"
                    },
                    if state.guest_owns_int16 {
                        "guest"
                    } else {
                        "firmware"
                    }
                );
                shell_println!(
                    "vm: 8259 master imr={:#04x} irr={:#04x} isr={:#04x}  slave imr={:#04x}",
                    state.pic_master_imr,
                    state.pic_master_irr,
                    state.pic_master_isr,
                    state.pic_slave_imr
                );
                shell_println!(
                    "vm: 8042 queued={}  PIT IRQ0={}  BDA head={:#06x} tail={:#06x} \
                     cursor=({}, {})",
                    state.controller_scancodes,
                    state.pit_irq_level,
                    state.bda_head,
                    state.bda_tail,
                    state.bda_cursor >> 8,
                    state.bda_cursor & 0xFF
                );
                Ok(())
            }
            Err(error) => {
                shell_println!("vm: DOS state unavailable: {:?} ({})", error, error.hint());
                Err(ShellError::ExecutionFailed)
            }
        },
        "text" | "screen" => match dosboot::dos_text() {
            Some(text) => {
                shell_println!("{}", text.trim_end());
                Ok(())
            }
            None => {
                shell_println!("vm: no DOS session: run `vm dos open` first");
                Err(ShellError::ExecutionFailed)
            }
        },
        "close" | "stop" => {
            if dosboot::dos_close() {
                shell_println!("vm: DOS session closed");
                Ok(())
            } else {
                shell_println!("vm: no DOS session to close");
                Ok(())
            }
        }
        _ => {
            shell_println!(
                "Usage: vm dos <open [seabios]|run [seconds] [keys=<text>]|console|info|state|text|selftest|reset|close>"
            );
            Err(ShellError::InvalidArguments)
        }
    }
}

/// `vm diag` : everything needed to debug a VM-entry failure.
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

const VM_USAGE: &str = "Usage: vm <list|info <id>|start <id>|stop <id>|pause <id>|resume <id>|console <id>|send <id> <text>|test [seabios|hello] [dry|seconds] [keys=<text>]|dos <open|run|text|close>|diag>";

/// `vm` : manage the s9vm worlds through the `/dev/vmm` scheme.
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
        "dos" => cmd_dos(&args[1..]),
        "diag" | "debug" => cmd_diag(),
        "help" | "-h" | "--help" => {
            shell_println!("{}", VM_USAGE);
            shell_println!("  The command is a client of the /dev/vmm scheme:");
            shell_println!(
                "    /dev/vmm/worlds, /dev/vmm/<id>/{{info,stats,vcpus,timing,console}}"
            );
            shell_println!("    /dev/vmm/control            (write: start <id> | stop <id>)");
            shell_println!(
                "    /dev/vmm/<id>/control       (write: start | stop | pause | resume)"
            );
            shell_println!(
                "  `vm test [seabios|hello] [dry|seconds]` boots the bundled FreeDOS floppy with a \
                 bounded time budget: the s9vm stub firmware by default, SeaBIOS/SeaVGABIOS with \
                 `seabios`, or the Hello/DIR demo image with `hello` (VT-x needed; `vm test \
                 [seabios|hello] dry` checks the installation without VT-x); `vm diag` prints \
                 the capability masks and replays the pre-entry guest-state checks."
            );
            Ok(())
        }
        _ => {
            shell_println!("{}", VM_USAGE);
            Err(ShellError::UnknownCommand)
        }
    }
}
