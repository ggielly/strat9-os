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

use alloc::{string::String, vec::Vec};
use core::{alloc::Layout, panic::PanicInfo};
use init_config::{
    BootPlan, Diagnostic, PlannedKind, PlannedSilo, Policy, Selection, SiloDef,
    build_plan_with_policy, build_plan_with_reserved, merge_overlay, parse_config,
};
use strat9_syscall::{
    call,
    data::{
        SILO_GRANT_ACCESS_WRITE, SILO_GRANT_DMA, SILO_GRANT_IRQ, SILO_GRANT_PATH, SILO_GRANT_PCI,
        SiloConfig, SiloGrantDesc,
    },
};
mod control;
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
fn default_silos() -> init_config::ParsedConfig {
    parse_config(DEFAULT_SILO_TOML)
}

/// Loads the primary silo config, falling back to the embedded defaults.
///
/// The parsed `[policy]` section is returned with the silos so the same
/// admin allowlist and target/profile selection drive the plan and later
/// `reload` calls.
fn load_primary_silos() -> (Vec<SiloDef>, Vec<Diagnostic>, Policy) {
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
            (parsed.silos, parsed.diagnostics, parsed.policy)
        }
        _ => {
            log("[init] Empty or unusable /initfs/silo.toml, using embedded defaults\n");
            let parsed = default_silos();
            log("[init] load_primary_silos: parsed embedded defaults count=");
            log_u32(parsed.silos.len() as u32);
            log("\n");
            (parsed.silos, parsed.diagnostics, parsed.policy)
        }
    }
}

/// Applies `/initfs/init.target` over the configured selection.
///
/// The file's first non-empty line is a `Selection` spec; on any error the
/// configured policy is kept unchanged.
fn apply_init_target(policy: &mut Policy) {
    let data = match read_file("/initfs/init.target") {
        Ok(data) => data,
        Err(_) => return,
    };
    let text = match core::str::from_utf8(&data) {
        Ok(text) => text,
        Err(_) => {
            log("[init] CONFIG ERROR: init.target: invalid UTF-8\n");
            return;
        }
    };
    let spec = text
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("")
        .trim();
    match Selection::from_spec(spec) {
        Ok(selection) => {
            policy.selection.profile = selection.profile;
            for name in selection.disabled {
                if !policy.selection.is_disabled(&name) {
                    policy.selection.disabled.push(name);
                }
            }
            log("[init] target=");
            log(policy.selection.profile.as_str());
            log(" disable=");
            log_u32(policy.selection.disabled.len() as u32);
            log("\n");
        }
        Err(e) => {
            log("[init] CONFIG ERROR: init.target: ");
            log(&e);
            log("\n");
        }
    }
}

/// True when the kernel command line explicitly selects a boot profile.
fn cmdline_sets_target(cmdline: &str) -> bool {
    cmdline
        .split(|c: char| c == '\0' || c.is_whitespace())
        .any(|token| token.starts_with("init.target="))
}

/// Applies `init.target=` / `init.disable=` from the kernel command line.
///
/// Runs after `/initfs/init.target` so precedence is kernel cmdline >
/// `/initfs/init.target` > `[policy] target`. A kernel `target` overrides only
/// when explicitly present; `disable` lists are always unioned. Unrelated
/// kernel keys are ignored.
fn apply_kernel_cmdline(policy: &mut Policy) {
    let mut buf = [0u8; 2048];
    let n = match call::getcmdline(&mut buf) {
        Ok(n) => n,
        Err(e) => {
            log("[init] cmdline: read failed: ");
            log(e.name());
            log("\n");
            return;
        }
    };
    let len = n.min(buf.len());
    let cmdline = match core::str::from_utf8(&buf[..len]) {
        Ok(text) => text,
        Err(_) => {
            log("[init] cmdline: invalid UTF-8, ignored\n");
            return;
        }
    };

    let selection = Selection::from_kernel_cmdline(cmdline);
    if !cmdline_sets_target(cmdline) && selection.disabled.is_empty() {
        return;
    }
    if cmdline_sets_target(cmdline) {
        policy.selection.profile = selection.profile;
    }
    for name in selection.disabled {
        if !policy.selection.is_disabled(&name) {
            policy.selection.disabled.push(name);
        }
    }
    log("[init] cmdline target=");
    log(policy.selection.profile.as_str());
    log(" disable=");
    log_u32(policy.selection.disabled.len() as u32);
    log("\n");
}

///
/// `reserved` holds the SIDs of live children so a reload cannot hand one of
/// them to a newly added silo. Shared by `_start` and the `/srv/init` `reload`
/// command so both apply the same parse, overlay merge and policy rules.
pub(crate) fn rebuild_plan(reserved: &[u32]) -> BootPlan {
    let (mut silos, mut diagnostics, policy) = load_primary_silos();
    diagnostics.extend(merge_wasm_test_overlay(&mut silos));
    build_plan_with_reserved(silos, diagnostics, policy, reserved)
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

/// Waits until `path` resolves through `ipc_connect`, with bounded backoff.
///
/// Probes with a closed handle immediately: connecting is the readiness signal,
/// not a handle we intend to keep. Backoff doubles from 10 ms to 250 ms and the
/// total wait is capped at ~10 s.
fn wait_for_service(path: &str) -> bool {
    let mut delay = 10u32;
    let mut waited = 0u32;
    loop {
        if let Ok(handle) = call::ipc_connect(path.as_bytes()) {
            let _ = call::handle_close(handle);
            return true;
        }
        if waited >= 10_000 {
            return false;
        }
        supervisor::sleep_ms(delay);
        waited += delay;
        delay = (delay * 2).min(250);
    }
}

/// Runtime binding of one planned silo, preserved after boot.
pub(crate) struct SiloRuntime {
    pub name: String,
    pub sid: u32,
    pub handle: usize,
    pub desired: PlannedSilo,
}

/// Implements boot silos.
fn boot_silos(
    plan: BootPlan,
    supervised: &mut Vec<supervisor::SupervisedChild>,
    runtimes: &mut Vec<SiloRuntime>,
) {
    for s_def in plan.silos {
        boot_silo(s_def, supervised, runtimes);
    }
}

/// Converts declared grants into wire descriptors.
///
/// Path grants need their bytes to stay alive until the syscall returns, so the
/// caller keeps the returned buffer vector in scope.
fn grant_descriptors(grants: &[init_config::Grant]) -> (Vec<SiloGrantDesc>, Vec<Vec<u8>>) {
    let mut descs = Vec::with_capacity(grants.len());
    let mut buffers: Vec<Vec<u8>> = Vec::new();
    for grant in grants {
        let desc = match &grant.kind {
            init_config::GrantKind::Path { service, write } => {
                let bytes = service.as_str().as_bytes().to_vec();
                let desc = SiloGrantDesc {
                    kind: SILO_GRANT_PATH,
                    access: if *write { SILO_GRANT_ACCESS_WRITE } else { 0 },
                    id: bytes.as_ptr() as u64,
                    len: bytes.len() as u64,
                    _reserved: 0,
                };
                buffers.push(bytes);
                desc
            }
            init_config::GrantKind::Irq(line) => SiloGrantDesc {
                kind: SILO_GRANT_IRQ,
                access: 0,
                id: *line as u64,
                len: 0,
                _reserved: 0,
            },
            init_config::GrantKind::Pci(addr) => SiloGrantDesc {
                kind: SILO_GRANT_PCI,
                access: 0,
                id: ((addr.bus as u64) << 16)
                    | ((addr.device as u64) << 8)
                    | (addr.function as u64),
                len: 0,
                _reserved: 0,
            },
            init_config::GrantKind::Dma(bytes) => SiloGrantDesc {
                kind: SILO_GRANT_DMA,
                access: 0,
                id: *bytes,
                len: 0,
                _reserved: 0,
            },
        };
        descs.push(desc);
    }
    (descs, buffers)
}

/// Applies `grants` to an editable silo.
///
/// The path buffers stay alive until `silo_grant` returns. Returns the kernel
/// error name on failure so the caller can decide whether to keep the silo.
fn apply_grants(silo_handle: usize, grants: &[init_config::Grant]) -> Result<(), &'static str> {
    if grants.is_empty() {
        return Ok(());
    }
    let (descs, _buffers) = grant_descriptors(grants);
    // The syscall returns 0 on success; report the descriptor count.
    call::silo_grant(silo_handle, &descs).map_err(|e| e.name())?;
    log("[init] GRANTS: applied ");
    log_u32(descs.len() as u32);
    log("\n");
    if grants
        .iter()
        .any(|g| matches!(g.kind, init_config::GrantKind::Irq(_)))
    {
        log(
            "[init] NOTE: irq grants are stored by the kernel but no subsystem consumes them yet\n",
        );
    }
    Ok(())
}

/// Starts every strate of `s_def` inside `silo_handle`.
///
/// Returns the number of strates that became active and registers each
/// launched module with the supervisor. Shared by boot and in-place reload.
fn start_strates(
    silo_handle: usize,
    s_def: &PlannedSilo,
    supervised: &mut Vec<supervisor::SupervisedChild>,
) -> u32 {
    let mut active_strates = 0u32;

    if s_def.strates.is_empty() {
        log("[init] No strates declared for silo ");
        log(&s_def.name);
        log("\n");
    }

    for str_def in &s_def.strates {
        match &str_def.kind {
            PlannedKind::Elf | PlannedKind::WasmRuntime => {
                log("[init]   -> Strate: ");
                log(&str_def.name);
                log("\n");
                if let Some(launched) = launcher::launch_module(
                    silo_handle,
                    &str_def.name,
                    &str_def.binary,
                    str_def.sha256,
                ) {
                    supervisor::register(
                        supervised,
                        &str_def.name,
                        launched.pid,
                        silo_handle,
                        launched.module_handle,
                        &s_def.name,
                        s_def.admin,
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

    active_strates
}

/// Creates and starts every strate of one planned silo.
///
/// A silo whose `requires` service is not reachable within the readiness budget
/// is skipped: `init-config` already dropped its dependents from the plan.
/// Returns the silo handle when at least one strate became active, and records
/// the binding in `runtimes` so a later `reload` can reconfigure it in place.
pub(crate) fn boot_silo(
    s_def: PlannedSilo,
    supervised: &mut Vec<supervisor::SupervisedChild>,
    runtimes: &mut Vec<SiloRuntime>,
) -> Option<usize> {
    for path in &s_def.requires {
        if !wait_for_service(path.as_str()) {
            log("[init] DEGRADED: silo ");
            log(&s_def.name);
            log(" missing required service ");
            log(path.as_str());
            log(", skipping\n");
            return None;
        }
    }

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
            return None;
        }
    };

    // Apply declared grants before any strate is attached or started. With the
    // kernel's deny-by-default-when-declared rule, a silo whose grants failed to
    // apply must not run: it would silently run unrestricted.
    if let Err(e) = apply_grants(silo_handle, &s_def.grants) {
        log("[init] silo_grant failed: ");
        log(&s_def.name);
        log(" ");
        log(e);
        log("\n");
        if let Err(e) = call::silo_destroy(silo_handle) {
            log("[init] silo_destroy failed: ");
            log(e.name());
            log(", stopping it instead\n");
            let _ = call::silo_stop(silo_handle);
        }
        let _ = call::handle_close(silo_handle);
        return None;
    }

    if let Some(ref lbl) = s_def.label {
        if let Err(e) = call::silo_rename(silo_handle, lbl.as_ptr() as usize, lbl.len()) {
            log("[init] silo_rename failed: ");
            log(e.name());
            log("\n");
        }
    }

    let active_strates = start_strates(silo_handle, &s_def, supervised);

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
        return None;
    }

    runtimes.push(SiloRuntime {
        name: s_def.name.clone(),
        sid: s_def.sid,
        handle: silo_handle,
        desired: s_def,
    });
    Some(silo_handle)
}

/// Reconfigures an existing (stopped) silo in place and restarts its strates.
///
/// `s_def` must carry the live SID (the reload path forces it). Config and the
/// grant set are replaced on the same handle; no silo is created or destroyed.
/// Returns the number of strates that became active.
pub(crate) fn reconfigure_silo(
    handle: usize,
    s_def: &PlannedSilo,
    supervised: &mut Vec<supervisor::SupervisedChild>,
) -> Result<u32, &'static str> {
    let config = build_silo_config(s_def);
    call::silo_config(handle, (&config as *const SiloConfig) as usize).map_err(|e| e.name())?;
    call::silo_grant_reset(handle).map_err(|e| e.name())?;
    apply_grants(handle, &s_def.grants)?;

    if let Some(ref lbl) = s_def.label {
        if let Err(e) = call::silo_rename(handle, lbl.as_ptr() as usize, lbl.len()) {
            log("[init] silo_rename failed: ");
            log(e.name());
            log("\n");
        }
    }

    Ok(start_strates(handle, s_def, supervised))
}

#[unsafe(no_mangle)]
/// Implements start.
pub unsafe extern "C" fn _start() -> ! {
    log("[init] Strat9 hierarchical boot starting\n");
    log("[init] Stage: load primary silos\n");
    let (mut silos, mut diagnostics, mut policy) = load_primary_silos();
    log("[init] Stage: apply init.target\n");
    apply_init_target(&mut policy);
    log("[init] Stage: apply kernel cmdline\n");
    apply_kernel_cmdline(&mut policy);
    log("[init] Stage: merge wasm overlay\n");
    diagnostics.extend(merge_wasm_test_overlay(&mut silos));
    log("[init] Stage: ensure required silos\n");
    let plan = build_plan_with_policy(silos, diagnostics, policy);
    for diagnostic in &plan.diagnostics {
        log_diagnostic(diagnostic);
    }
    for silo in &plan.silos {
        if !silo.grants.is_empty() {
            log("[init] GRANTS: ");
            log(&silo.name);
            log(" declares ");
            log_u32(silo.grants.len() as u32);
            log(" grant(s)\n");
        }
    }
    log("[init] Stage: boot silos\n");
    let mut supervised = Vec::with_capacity(supervisor::CAPACITY);
    // The plan is already in dependency order: the supervisor reuses it to stop
    // children in reverse order on shutdown.
    let plan_order: Vec<alloc::string::String> =
        plan.silos.iter().map(|s| s.name.clone()).collect();
    let mut runtimes = Vec::new();
    boot_silos(plan, &mut supervised, &mut runtimes);
    log("[init] Boot complete.\n");
    let control_port = control::init_port();
    supervisor::run(supervised, control_port, plan_order, runtimes);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    call::handle_panic("init", info)
}
