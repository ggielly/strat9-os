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

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

//
// The boot configuration parser, policy validation and SID allocation live in
// the host-testable `init-config` crate. This file only maps the resulting
// `BootPlan` onto the kernel ABI at the execution boundary. Launching lives in
// `launcher.rs` and child supervision in `supervisor.rs`.
//

use alloc::vec::Vec;
use core::{alloc::Layout, panic::PanicInfo};
use init_config::{
    BootPlan, Diagnostic, PlannedKind, SiloDef, build_plan, merge_overlay, parse_config,
};
use strat9_syscall::{call, data::SiloConfig};
pub mod fmt;
mod launcher;
mod supervisor;
use fmt::log_u32;

const EAGAIN: usize = 11;
const MAX_READ_BYTES: usize = 64 * 1024 * 1024;
const MAX_READ_EAGAIN: usize = 256;

// ---------------------------------------------------------------------------
// GLOBAL ALLOCATOR (BUMP + BRK)
// ---------------------------------------------------------------------------

alloc_freelist::define_freelist_brk_allocator!(
    pub struct BumpAllocator;
    brk = strat9_syscall::call::brk;
    heap_max = 64 * 1024 * 1024;
);

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

#[alloc_error_handler]
/// Implements alloc error.
fn alloc_error(_layout: Layout) -> ! {
    let _ = call::debug_log(b"[init] OOM Fatal\n");
    call::exit(12);
}

// ---------------------------------------------------------------------------
// Utils
// ---------------------------------------------------------------------------

/// Writes `msg` to the kernel debug log.
fn log(msg: &str) {
    let _ = call::debug_log(msg.as_bytes());
}

/// Writes a configuration diagnostic, reproducing the historic log line.
fn log_diagnostic(diagnostic: &Diagnostic) {
    log("[init] ");
    log(&diagnostic.message);
}

/// Reads file.
///
/// Returns an error when the file is larger than [`MAX_READ_BYTES`] instead of
/// silently truncating it: a truncated ELF blob must never reach
/// `SYS_MODULE_LOAD`.
fn read_file(path: &str) -> Result<Vec<u8>, &'static str> {
    let fd = call::openat(0, path, 0x1, 0).map_err(|_| "open failed")?;
    let mut out = Vec::new();

    let mut chunk = [0u8; 8192]; // 8 KiB scratch buffer, keeps the stack small

    let mut eagain = 0usize;
    loop {
        match call::read(fd as usize, &mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if out.len() + n > MAX_READ_BYTES {
                    let _ = call::close(fd as usize);
                    log("[init] read_file: file exceeds MAX_READ_BYTES\n");
                    return Err("file too large");
                }
                out.extend_from_slice(&chunk[..n]);
                eagain = 0;
            }
            Err(e) if e.to_errno() == EAGAIN => {
                eagain += 1;
                if eagain > MAX_READ_EAGAIN {
                    let _ = call::close(fd as usize);
                    return Err("read timeout");
                }
                let _ = call::sched_yield();
            }
            Err(_) => {
                let _ = call::close(fd as usize);
                return Err("read failed");
            }
        }
    }
    let _ = call::close(fd as usize);
    Ok(out)
}

// ---------------------------------------------------------------------------
// CONFIGURATION LOADING
// ---------------------------------------------------------------------------

// Keep the fallback identical to the configuration shipped in the UEFI image.
const DEFAULT_SILO_TOML: &str = include_str!("../../../assets/boot/silo.toml");

/// Parses the embedded default silo config.
fn default_silos() -> (Vec<SiloDef>, Vec<Diagnostic>) {
    let parsed = parse_config(DEFAULT_SILO_TOML);
    (parsed.silos, parsed.diagnostics)
}

/// Loads the primary silo config, falling back to the embedded defaults.
fn load_primary_silos() -> (Vec<SiloDef>, Vec<Diagnostic>) {
    log("[init] load_primary_silos: begin\n");
    let parsed = match read_file("/initfs/silo.toml") {
        Ok(data_vec) => match core::str::from_utf8(&data_vec) {
            Ok(data_str) => {
                log("[init] load_primary_silos: parse /initfs/silo.toml\n");
                Some(parse_config(data_str))
            }
            Err(_) => {
                log("[init] Invalid UTF-8 in /initfs/silo.toml, using embedded defaults\n");
                None
            }
        },
        Err(_) => {
            log("[init] Missing /initfs/silo.toml, using embedded defaults\n");
            None
        }
    };

    match parsed {
        Some(parsed) if !parsed.silos.is_empty() => {
            log("[init] load_primary_silos: parsed file count=");
            log_u32(parsed.silos.len() as u32);
            log("\n");
            (parsed.silos, parsed.diagnostics)
        }
        _ => {
            log("[init] Empty or unusable /initfs/silo.toml, using embedded defaults\n");
            let (silos, diagnostics) = default_silos();
            log("[init] load_primary_silos: parsed embedded defaults count=");
            log_u32(silos.len() as u32);
            log("\n");
            (silos, diagnostics)
        }
    }
}

/// Merges `/initfs/wasm-test.toml` silos that are not already declared.
fn merge_wasm_test_overlay(silos: &mut Vec<SiloDef>) -> Vec<Diagnostic> {
    let data = match read_file("/initfs/wasm-test.toml") {
        Ok(data) => data,
        Err(_) => return Vec::new(),
    };
    let text = match core::str::from_utf8(&data) {
        Ok(text) => text,
        Err(_) => {
            log("[init] Invalid UTF-8 in /initfs/wasm-test.toml, skipping overlay\n");
            return Vec::new();
        }
    };
    let parsed = parse_config(text);
    if parsed.silos.is_empty() {
        return parsed.diagnostics;
    }

    let added = merge_overlay(silos, parsed.silos);
    if added > 0 {
        log("[init] Applied wasm-test overlay silos: ");
        log_u32(added as u32);
        log("\n");
    }
    parsed.diagnostics
}

// ---------------------------------------------------------------------------
// EXECUTION LOGIC
// ---------------------------------------------------------------------------

const SILO_FLAG_ADMIN: u64 = 1 << 0;
const SILO_FLAG_GRAPHICS: u64 = 1 << 1;
const SILO_FLAG_WEBRTC_NATIVE: u64 = 1 << 2;
const SILO_FLAG_GRAPHICS_READ_ONLY: u64 = 1 << 3;
const SILO_FLAG_WEBRTC_TURN_FORCE: u64 = 1 << 4;

/// Builds the kernel [`SiloConfig`] for one planned silo.
fn build_silo_config(silo: &init_config::PlannedSilo) -> SiloConfig {
    let mut flags = 0u64;
    // The admin policy was already validated: only SYS may request it.
    if silo.admin {
        flags |= SILO_FLAG_ADMIN;
    }
    if silo.graphics.enabled {
        flags |= SILO_FLAG_GRAPHICS;
        if silo.graphics.mode == "webrtc-native" {
            flags |= SILO_FLAG_WEBRTC_NATIVE;
        }
        if silo.graphics.read_only {
            flags |= SILO_FLAG_GRAPHICS_READ_ONLY;
        }
        if silo.graphics.turn_policy == "force" {
            flags |= SILO_FLAG_WEBRTC_TURN_FORCE;
        }
    }

    let mut config = SiloConfig::zero();
    config.sid = silo.sid;
    config.mode = silo.mode.0;
    config.family = silo.family_id;
    config.flags = flags;
    config.graphics_max_sessions = if silo.graphics.enabled {
        if silo.graphics.max_sessions == 0 {
            1
        } else {
            silo.graphics.max_sessions
        }
    } else {
        0
    };
    config.graphics_session_ttl_sec = if silo.graphics.enabled {
        if silo.graphics.session_ttl_sec == 0 {
            1800
        } else {
            silo.graphics.session_ttl_sec
        }
    } else {
        0
    };
    config.dma_max_domains = silo.dma.max_domains;
    config.dma_max_bytes = silo.dma.max_bytes;
    config.dma_iova_base = silo.dma.iova_base;
    config.dma_iova_limit = silo.dma.iova_limit;
    config.dma_fault_policy = silo.dma.fault_policy.to_u8();
    config
}

/// Implements boot silos.
fn boot_silos(plan: BootPlan, supervised: &mut Vec<supervisor::SupervisedChild>) {
    for s_def in plan.silos {
        log("[init] Creating Silo: ");
        log(&s_def.name);
        log(" (SID=");
        log_u32(s_def.sid);
        log(")\n");

        let config = build_silo_config(&s_def);

        let silo_handle = match call::silo_create((&config as *const SiloConfig) as usize) {
            Ok(h) => h,
            Err(e) => {
                log("[init] silo_create failed: ");
                log(e.name());
                log("\n");
                continue;
            }
        };

        if let Some(ref lbl) = s_def.label {
            if let Err(e) = call::silo_rename(silo_handle, lbl.as_ptr() as usize, lbl.len()) {
                log("[init] silo_rename failed: ");
                log(e.name());
                log("\n");
            }
        }

        let mut active_strates = 0u32;

        if s_def.strates.is_empty() {
            log("[init] No strates declared for silo ");
            log(&s_def.name);
            log("\n");
        }

        for str_def in s_def.strates {
            match str_def.kind {
                PlannedKind::Elf | PlannedKind::WasmRuntime => {
                    log("[init]   -> Strate: ");
                    log(&str_def.name);
                    log("\n");
                    if let Some(launched) =
                        launcher::launch_module(silo_handle, &str_def.name, &str_def.binary)
                    {
                        supervisor::register(
                            supervised,
                            &str_def.name,
                            launched.pid,
                            silo_handle,
                            launched.module_handle,
                            str_def.restart,
                            str_def.critical,
                            str_def.max_restarts,
                        );
                        active_strates += 1;
                    }
                }
                PlannedKind::WasmApp { service_label } => {
                    log("[init]   -> Wasm-App: ");
                    log(&str_def.name);
                    log("\n");
                    // `init-config` already resolved the runtime service label.
                    let service_path = alloc::format!("/srv/strate-wasm/{}", service_label);
                    match launcher::run_wasm_app(&service_path, &str_def.binary) {
                        Ok(()) => {
                            log("[init]     wasm app started: ");
                            log(&str_def.binary);
                            log("\n");
                            active_strates += 1;
                        }
                        Err(code) => {
                            log("[init]     wasm app failed: status=0x");
                            log_u32(code);
                            log(" (service=");
                            log(&service_path);
                            log(", path=");
                            log(&str_def.binary);
                            log(")\n");
                        }
                    }
                }
            }
        }

        // A silo whose strates all failed must not stay open: a task-less
        // `Ready` silo (and the module it still references) would be kept for
        // the rest of the boot. Destroy it, then release our handle.
        if active_strates == 0 {
            log("[init] No active strate in silo ");
            log(&s_def.name);
            log(", destroying it\n");
            if let Err(e) = call::silo_destroy(silo_handle) {
                log("[init] silo_destroy failed: ");
                log(e.name());
                log(", stopping it instead\n");
                let _ = call::silo_stop(silo_handle);
            }
            let _ = call::handle_close(silo_handle);
        }
    }
}

#[unsafe(no_mangle)]
/// Implements start.
pub unsafe extern "C" fn _start() -> ! {
    log("[init] Strat9 hierarchical boot starting\n");
    log("[init] Stage: load primary silos\n");
    let (mut silos, mut diagnostics) = load_primary_silos();
    log("[init] Stage: merge wasm overlay\n");
    diagnostics.extend(merge_wasm_test_overlay(&mut silos));
    log("[init] Stage: ensure required silos\n");
    let plan = build_plan(silos, diagnostics);
    for diagnostic in &plan.diagnostics {
        log_diagnostic(diagnostic);
    }
    log("[init] Stage: boot silos\n");
    let mut supervised = Vec::with_capacity(supervisor::CAPACITY);
    boot_silos(plan, &mut supervised);
    log("[init] Boot complete.\n");
    supervisor::run(supervised);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    call::handle_panic("init", info)
}
