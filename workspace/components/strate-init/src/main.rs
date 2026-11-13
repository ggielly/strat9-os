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
// TODO : split this file into multiple modules like the TOML parser, the silo launcher, the wasm runner, etc.
//
// TODO : the deafult main silo.toml file is loaded here. We need to have a fixed silo config inside the filesystem
//

use alloc::{string::String, vec::Vec};
use core::{alloc::Layout, panic::PanicInfo};
use strat9_syscall::{
    call,
    data::{IpcMessage, SiloConfig, SiloMode},
    number,
};
pub mod fmt;
use fmt::{log_hex_bytes, log_u32};

const EAGAIN: usize = 11;
const MAX_READ_BYTES: usize = 64 * 1024 * 1024;
const MAX_READ_EAGAIN: usize = 256;
/// `sid` value the shipped configuration uses to request automatic allocation.
///
/// It is kept as a sentinel (instead of removing the key) so the boot files
/// stay readable and the kernel-visible SID is always allocated by this
/// process.
const SID_AUTO: u32 = 42;
/// First SID handed out to a system-family silo (`SYS`, `DRV`, `FS`, `NET`).
const SID_SYSTEM_FIRST: u32 = 100;
/// First SID handed out to a user-family silo (`WASM`, `USR`).
const SID_USER_FIRST: u32 = 1000;

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

// compile‑time perfect‑hash map (phf)

use phf::phf_map;

/// Static description of a silo family.
///
/// Both values the boot process needs are kept in the same entry: the numeric
/// identifier published in [`SiloConfig::family`], and the maximum
/// [`SiloMode`] a member of the family may request. They used to live in two
/// independent tables, which could silently diverge.
struct FamilyProfile {
    /// Family identifier expected by the kernel ABI.
    id: u8,
    /// Highest operations mode a silo of this family may be granted.
    ceiling: SiloMode,
}

static FAMILY_PROFILES: phf::Map<&'static str, FamilyProfile> = phf_map! {
    "SYS"  => FamilyProfile { id: 0, ceiling: SiloMode(0o777) }, // no restriction
    "DRV"  => FamilyProfile { id: 1, ceiling: SiloMode(0o076) }, // anything except SYS
    "FS"   => FamilyProfile { id: 2, ceiling: SiloMode(0o076) }, // anything except SYS
    "NET"  => FamilyProfile { id: 3, ceiling: SiloMode(0o076) }, // anything except SYS
    "WASM" => FamilyProfile { id: 4, ceiling: SiloMode(0o006) }, // NET and FS only
    "USR"  => FamilyProfile { id: 5, ceiling: SiloMode(0o004) }, // read only
};

/// Returns the profile of `name`, or `None` for an unknown family.
fn get_family_profile(name: &str) -> Option<&'static FamilyProfile> {
    FAMILY_PROFILES.get(name)
}

// ---------------------------------------------------------------------------
// Utils
// ---------------------------------------------------------------------------

/// Writes `msg` to the kernel debug log.
fn log(msg: &str) {
    let _ = call::debug_log(msg.as_bytes());
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
// HIERARCHICAL PARSER
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct StrateDef {
    name: String,
    binary: String,
    stype: String,
    target: String,
}

impl Default for StrateDef {
    fn default() -> Self {
        Self {
            name: String::new(),
            binary: String::new(),
            stype: String::from("elf"),
            target: String::from("default"),
        }
    }
}

/// SID requested by the configuration.
#[derive(Clone, PartialEq, Eq)]
enum SidChoice {
    /// `SID_AUTO`: allocate the next free SID of the family range.
    Auto,
    /// Explicit SID; rejected when it is already taken.
    Fixed(u32),
    /// The configured value is not a number; the silo must be skipped.
    Invalid(String),
}

// silo definition as parsed from config, before validation and transformation into SiloConfig
// This is the structure for the TOML config.
#[derive(Clone)]
struct SiloDef {
    name: String,
    label: Option<String>,
    sid: SidChoice,
    family: String,
    mode: String,
    /// Grants the silo administrator capability (SILO_FLAG_ADMIN).
    ///
    /// Checked by SYS_VMM_CREATE and a few other privileged calls. It is
    /// only granted through the boot configuration, never inferred from
    /// the family or the mode, and only accepted for the `SYS` family.
    admin: bool,
    graphics_enabled: bool,
    graphics_mode: String,
    graphics_read_only: bool,
    graphics_max_sessions: u16,
    graphics_session_ttl_sec: u32,
    graphics_turn_policy: String,
    dma_max_domains: u32,
    dma_max_bytes: u64,
    dma_iova_base: u64,
    dma_iova_limit: u64,
    dma_fault_policy: u8,
    strates: Vec<StrateDef>,
}

impl Default for SiloDef {
    fn default() -> Self {
        Self {
            name: String::new(),
            label: None,
            sid: SidChoice::Auto,
            family: String::from("USR"),
            mode: String::from("000"),
            admin: false,
            graphics_enabled: false,
            graphics_mode: String::new(),
            graphics_read_only: false,
            graphics_max_sessions: 0,
            graphics_session_ttl_sec: 0,
            graphics_turn_policy: String::from("auto"),
            dma_max_domains: 0,
            dma_max_bytes: 0,
            dma_iova_base: 0,
            dma_iova_limit: 0,
            dma_fault_policy: 0,
            strates: Vec::new(),
        }
    }
}

impl SiloDef {
    /// Builds the fallback definition of a mandatory silo.
    ///
    /// The fallback is deliberately identical to the entry the UEFI image
    /// ships, so a missing configuration key cannot change the machine.
    fn fallback(name: &str, family: &str, strate: &str, binary: &str) -> Self {
        Self {
            name: String::from(name),
            family: String::from(family),
            mode: String::from("076"),
            strates: alloc::vec![StrateDef {
                name: String::from(strate),
                binary: String::from(binary),
                ..StrateDef::default()
            }],
            ..Self::default()
        }
    }
}

/// Removes a TOML inline comment, ignoring `#` inside quoted strings.
fn strip_comment(line: &str) -> &str {
    let mut in_basic_string = false;
    let mut in_literal_string = false;
    let mut escaped = false;
    for (index, ch) in line.char_indices() {
        match ch {
            '\\' if in_basic_string => escaped = !escaped,
            '"' if !in_literal_string => {
                if !escaped {
                    in_basic_string = !in_basic_string;
                }
                escaped = false;
            }
            '\'' if !in_basic_string => in_literal_string = !in_literal_string,
            '#' if !in_basic_string && !in_literal_string => return &line[..index],
            _ => escaped = false,
        }
    }
    line
}

/// Extracts the value of a `key = value` line.
///
/// Basic (`"..."`) and literal (`'...'`) strings are unquoted; anything else is
/// taken verbatim. Returns `None` for an unterminated string so the caller can
/// report the mistake instead of using half a value. Escape sequences are not
/// decoded: this configuration only carries identifiers, paths and numbers.
fn parse_value(raw: &str) -> Option<&str> {
    let raw = raw.trim();
    if let Some(rest) = raw.strip_prefix('"') {
        let mut escaped = false;
        for (index, ch) in rest.char_indices() {
            match ch {
                '\\' => escaped = !escaped,
                '"' if !escaped => return Some(&rest[..index]),
                _ => escaped = false,
            }
        }
        None
    } else if let Some(rest) = raw.strip_prefix('\'') {
        rest.find('\'').map(|end| &rest[..end])
    } else {
        Some(raw)
    }
}

/// Parses the silo configuration.
///
/// Supported constructs are `[[silos]]`, `[[silos.strates]]`, `key = value`,
/// inline comments and blank lines. Every `[[silos.strates]]` starts a new
/// strate; keys are only applied to the section that owns them. Unknown
/// sections and misplaced tables are reported and ignored instead of leaking
/// into the current silo.
fn parse_config(data: &str) -> Vec<SiloDef> {
    #[derive(Clone, Copy)]
    enum Section {
        /// Keys belong to the current silo.
        Silo,
        /// Keys belong to the last `[[silos.strates]]` of the current silo.
        Strate,
        /// Keys are ignored (unknown or misplaced section).
        Ignored,
    }

    let mut silos: Vec<SiloDef> = Vec::new();
    let mut current_silo: Option<SiloDef> = None;
    let mut section = Section::Silo;

    for raw_line in data.lines() {
        let line = strip_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }

        if line == "[[silos]]" {
            if let Some(silo) = current_silo.take() {
                silos.push(silo);
            }
            current_silo = Some(SiloDef::default());
            section = Section::Silo;
            continue;
        }

        if line == "[[silos.strates]]" {
            match current_silo.as_mut() {
                Some(silo) => {
                    // One TOML table, one strate: a new table always starts a
                    // new definition instead of overwriting the previous one.
                    silo.strates.push(StrateDef::default());
                    section = Section::Strate;
                }
                None => {
                    log("[init] config: [[silos.strates]] before any [[silos]], ignored\n");
                    section = Section::Ignored;
                }
            }
            continue;
        }

        if line.starts_with('[') {
            log("[init] config: unsupported section '");
            log(line);
            log("', its keys are ignored\n");
            section = Section::Ignored;
            continue;
        }

        let Some(idx) = line.find('=') else {
            continue;
        };
        let key = line[..idx].trim();
        let Some(val) = parse_value(&line[idx + 1..]) else {
            log("[init] config: unterminated string for key '");
            log(key);
            log("', ignored\n");
            continue;
        };

        let Some(silo) = current_silo.as_mut() else {
            log("[init] config: key '");
            log(key);
            log("' outside any [[silos]], ignored\n");
            continue;
        };

        match section {
            Section::Silo => match key {
                "name" => silo.name = String::from(val),
                "label" => silo.label = Some(String::from(val)),
                "sid" => {
                    silo.sid = match val.parse::<u32>() {
                        Ok(SID_AUTO) => SidChoice::Auto,
                        Ok(sid) => SidChoice::Fixed(sid),
                        Err(_) => SidChoice::Invalid(String::from(val)),
                    }
                }
                "family" => silo.family = String::from(val),
                "mode" => silo.mode = String::from(val),
                "admin" => silo.admin = parse_toml_bool(val),
                "graphics_enabled" => silo.graphics_enabled = parse_toml_bool(val),
                "graphics_mode" => silo.graphics_mode = String::from(val),
                "graphics_read_only" => silo.graphics_read_only = parse_toml_bool(val),
                "graphics_max_sessions" => silo.graphics_max_sessions = val.parse().unwrap_or(0),
                "graphics_session_ttl_sec" => {
                    silo.graphics_session_ttl_sec = val.parse().unwrap_or(0)
                }
                "graphics_turn_policy" => silo.graphics_turn_policy = String::from(val),
                "dma_max_domains" => silo.dma_max_domains = val.parse().unwrap_or(0),
                "dma_max_bytes" => silo.dma_max_bytes = parse_u64_auto(val).unwrap_or(0),
                "dma_iova_base" => silo.dma_iova_base = parse_u64_auto(val).unwrap_or(0),
                "dma_iova_limit" => silo.dma_iova_limit = parse_u64_auto(val).unwrap_or(0),
                "dma_fault_policy" => {
                    silo.dma_fault_policy = match val {
                        "log" => 0,
                        "notify" => 1,
                        "kill" => 2,
                        "panic" => 3,
                        _ => val.parse().unwrap_or(0),
                    }
                }
                _ => {}
            },
            Section::Strate => {
                if let Some(strate) = silo.strates.last_mut() {
                    match key {
                        "name" => strate.name = String::from(val),
                        "binary" => strate.binary = String::from(val),
                        "type" => strate.stype = String::from(val),
                        "target_strate" => strate.target = String::from(val),
                        _ => {}
                    }
                }
            }
            Section::Ignored => {}
        }
    }
    if let Some(silo) = current_silo {
        silos.push(silo);
    }
    silos
}

/// Implements ensure required silos.
fn ensure_required_silos(mut silos: Vec<SiloDef>) -> Vec<SiloDef> {
    // Scan once to detect mandatory silos.
    let mut has_bus = false;
    let mut has_network = false;
    let mut has_dhcp = false;
    for s in &silos {
        match s.name.as_str() {
            "bus" => has_bus = true,
            "network" => has_network = true,
            "dhcp-client" => has_dhcp = true,
            _ => {}
        }
    }

    if !has_bus {
        log("[init] Missing mandatory silo 'bus' in config, adding fallback\n");
        silos.push(SiloDef::fallback(
            "bus",
            "DRV",
            "strate-bus",
            "/initfs/strate-bus",
        ));
    }

    if !has_network {
        log("[init] Missing mandatory silo 'network' in config, adding fallback\n");
        silos.push(SiloDef::fallback(
            "network",
            "NET",
            "strate-net",
            "/initfs/strate-net-silo",
        ));
    }

    if !has_dhcp {
        log("[init] Missing mandatory silo 'dhcp-client' in config, adding fallback\n");
        silos.push(SiloDef::fallback(
            "dhcp-client",
            "NET",
            "dhcp-client",
            "/initfs/dhcp-client",
        ));
    }

    silos
}

/// Returns the parsed default silo config.
///
/// The function runs at most once per boot (when `/initfs/silo.toml` is
/// missing or unusable), so it simply parses the embedded copy: there is no
/// cache to synchronise and no leaked allocation.
fn default_silos() -> Vec<SiloDef> {
    parse_config(DEFAULT_SILO_TOML)
}

/// Implements load primary silos.
fn load_primary_silos() -> Vec<SiloDef> {
    log("[init] load_primary_silos: begin\n");
    let parsed = match read_file("/initfs/silo.toml") {
        Ok(data_vec) => match core::str::from_utf8(&data_vec) {
            Ok(data_str) => {
                log("[init] load_primary_silos: parse /initfs/silo.toml\n");
                parse_config(data_str)
            }
            Err(_) => {
                log("[init] Invalid UTF-8 in /initfs/silo.toml, using embedded defaults\n");
                Vec::new()
            }
        },
        Err(_) => {
            log("[init] Missing /initfs/silo.toml, using embedded defaults\n");
            Vec::new()
        }
    };
    if parsed.is_empty() {
        log("[init] Empty or unusable /initfs/silo.toml, using embedded defaults\n");
        let defaults = default_silos();
        log("[init] load_primary_silos: parsed embedded defaults count=");
        log_u32(defaults.len() as u32);
        log("\n");
        defaults
    } else {
        log("[init] load_primary_silos: parsed file count=");
        log_u32(parsed.len() as u32);
        log("\n");
        parsed
    }
}

/// Implements merge wasm test overlay.
fn merge_wasm_test_overlay(silos: &mut Vec<SiloDef>) {
    let data = match read_file("/initfs/wasm-test.toml") {
        Ok(d) => d,
        Err(_) => return,
    };
    let text = match core::str::from_utf8(&data) {
        Ok(t) => t,
        Err(_) => {
            log("[init] Invalid UTF-8 in /initfs/wasm-test.toml, skipping overlay\n");
            return;
        }
    };
    let overlay = parse_config(text);
    if overlay.is_empty() {
        return;
    }

    let mut added = 0u32;
    for o in overlay {
        let exists = silos.iter().any(|s| s.name == o.name);
        if exists {
            continue;
        }
        silos.push(o);
        added += 1;
    }
    if added > 0 {
        log("[init] Applied wasm-test overlay silos: ");
        log_u32(added);
        log("\n");
    }
}

// ---------------------------------------------------------------------------
// EXECUTION LOGIC
// ---------------------------------------------------------------------------

const SILO_FLAG_ADMIN: u64 = 1 << 0;
const SILO_FLAG_GRAPHICS: u64 = 1 << 1;
const SILO_FLAG_WEBRTC_NATIVE: u64 = 1 << 2;
const SILO_FLAG_GRAPHICS_READ_ONLY: u64 = 1 << 3;
const SILO_FLAG_WEBRTC_TURN_FORCE: u64 = 1 << 4;

/// Status reported when the wasm runtime cannot be reached.
const WASM_STATUS_CONNECT: u32 = 0xffff_0000;
/// Status reported when the `load` IPC call itself fails.
const WASM_STATUS_LOAD: u32 = 0xffff_0001;
/// Status reported when the `run` IPC call itself fails.
const WASM_STATUS_RUN: u32 = 0xffff_0002;
/// Status reported when the wasm path does not fit in the IPC framing.
const WASM_STATUS_PATH_TOO_LONG: u32 = 0xffff_0003;

/// Parses mode octal.
fn parse_mode_octal(s: &str) -> Option<u16> {
    let trimmed = if let Some(rest) = s.strip_prefix("0o") {
        rest
    } else {
        s
    };
    u16::from_str_radix(trimmed, 8).ok()
}

fn parse_toml_bool(s: &str) -> bool {
    matches!(s, "true" | "True" | "TRUE" | "1" | "yes" | "on")
}

/// Parse a decimal or `0x`-prefixed hexadecimal u64.
fn parse_u64_auto(s: &str) -> Option<u64> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

/// Implements ipc call status.
fn ipc_call_status(port: usize, msg: &mut IpcMessage) -> Result<u32, &'static str> {
    call::ipc_call(port, msg).map_err(|_| "ipc_call failed")?;
    Ok(u32::from_le_bytes([
        msg.payload[0],
        msg.payload[1],
        msg.payload[2],
        msg.payload[3],
    ]))
}

/// Implements connect wasm service with exponential backoff.
fn connect_wasm_service(path: &str) -> Result<usize, &'static str> {
    let mut delay = 1;
    for _ in 0..12 {
        if let Ok(h) = call::ipc_connect(path.as_bytes()) {
            return Ok(h);
        }
        for _ in 0..delay {
            let _ = call::sched_yield();
        }
        delay = core::cmp::min(delay * 2, 256);
    }
    Err("ipc_connect timeout")
}

/// Closes an IPC port when it goes out of scope.
///
/// A failed `ipc_call` used to `?` out of [`run_wasm_app`] before the explicit
/// `handle_close`, leaking the port for the rest of the boot.
struct PortGuard(usize);

impl Drop for PortGuard {
    fn drop(&mut self) {
        let _ = call::handle_close(self.0);
    }
}

/// Implements run wasm app.
fn run_wasm_app(service_path: &str, wasm_path: &str) -> Result<(), u32> {
    let port = connect_wasm_service(service_path).map_err(|_| WASM_STATUS_CONNECT)?;
    // The port is released on every return path, including the early ones.
    let port = PortGuard(port);

    let bytes = wasm_path.as_bytes();
    // The path length travels in a single byte, so anything longer than 255
    // bytes cannot be framed: report it instead of sending a truncated length.
    if bytes.len() > u8::MAX as usize {
        return Err(WASM_STATUS_PATH_TOO_LONG);
    }
    let mut load = IpcMessage::new(0x100);
    let n = bytes.len();
    load.payload[0] = n as u8;
    if n > 0 {
        load.payload[1..1 + n].copy_from_slice(bytes);
    }
    let load_status = ipc_call_status(port.0, &mut load).map_err(|_| WASM_STATUS_LOAD)?;
    if load_status != 0 {
        return Err(load_status);
    }

    let mut run = IpcMessage::new(0x102);
    let run_status = ipc_call_status(port.0, &mut run).map_err(|_| WASM_STATUS_RUN)?;
    if run_status != 0 {
        return Err(run_status);
    }
    Ok(())
}

/// Loads module bytes into the kernel module registry.
fn load_module(ptr: usize, len: usize) -> Option<usize> {
    match unsafe { strat9_syscall::syscall2(number::SYS_MODULE_LOAD, ptr, len) } {
        Ok(handle) => Some(handle),
        Err(_) => None,
    }
}

/// Attaches `module_handle` to the silo and starts the strate by name.
///
/// Returns the started pid, and logs the reason on failure.
fn attach_and_start(silo_handle: usize, strate: &StrateDef, module_handle: usize) -> Option<usize> {
    if let Err(e) = call::silo_attach_module(silo_handle, module_handle) {
        log("[init] silo_attach_module failed: ");
        log(e.name());
        log("\n");
        return None;
    }
    match call::silo_start_named(silo_handle, &strate.name) {
        Ok(pid) => Some(pid),
        Err(e) => {
            log("[init] silo_start failed: ");
            log(e.name());
            log("\n");
            None
        }
    }
}

/// Loads, attaches and starts one ELF (or wasm runtime) strate.
///
/// Both module sources converge here: a binary under `/initfs` is loaded by
/// path, any other path is read by this process and loaded as a blob. Only
/// the source of the bytes differs. A module that cannot be attached or
/// started is unloaded immediately, so a failed launch does not leak the
/// blob. Returns the module handle and the started pid, both needed by the
/// supervisor to restart this exact strate.
fn start_elf_strate(silo_handle: usize, strate: &StrateDef) -> Option<(usize, usize)> {
    let module_handle = if strate.binary.starts_with("/initfs/") {
        log("[init]     module path ");
        log(&strate.binary);
        log("\n");
        match load_module(strate.binary.as_ptr() as usize, strate.binary.len()) {
            Some(handle) => handle,
            None => {
                log("[init] module_load failed for ");
                log(&strate.binary);
                log("\n");
                return None;
            }
        }
    } else {
        let data = match read_file(&strate.binary) {
            Ok(data) => data,
            Err(_) => {
                log("[init] failed to read binary ");
                log(&strate.binary);
                log("\n");
                return None;
            }
        };
        if data.len() < 4 {
            log("[init]     module too small size=");
            log_u32(data.len() as u32);
            log("\n");
            return None;
        }
        log("[init]     module magic ");
        log_hex_bytes(&data[..4]);
        log(" size=");
        log_u32(data.len() as u32);
        log("\n");
        match load_module(data.as_ptr() as usize, data.len()) {
            Some(handle) => handle,
            None => {
                log("[init] module_load failed for ");
                log(&strate.binary);
                log("\n");
                return None;
            }
        }
    };

    // The blob is loaded from here on: release it if the strate cannot run.
    match attach_and_start(silo_handle, strate, module_handle) {
        Some(pid) => Some((module_handle, pid)),
        None => {
            let _ = call::module_unload(module_handle);
            let _ = call::handle_close(module_handle);
            None
        }
    }
}

/// Claims the SID of one silo definition.
///
/// Automatic allocation walks past every SID the configuration pins explicitly
/// and every SID already handed out, so the kernel never answers
/// `AlreadyExists` for a SID this process could have avoided. Returns `None`
/// when the requested SID is unusable or already taken: the caller then skips
/// the silo with a diagnostic.
fn claim_sid(
    choice: &SidChoice,
    system_range: bool,
    next_system: &mut u32,
    next_user: &mut u32,
    fixed_sids: &[u32],
    used_sids: &mut Vec<u32>,
    name: &str,
) -> Option<u32> {
    match choice {
        SidChoice::Invalid(raw) => {
            log("[init] CONFIG ERROR: invalid sid '");
            log(raw);
            log("' for silo ");
            log(name);
            log(", skipped\n");
            None
        }
        SidChoice::Fixed(sid) => {
            if used_sids.contains(sid) {
                log("[init] CONFIG ERROR: sid ");
                log_u32(*sid);
                log(" is already used, silo ");
                log(name);
                log(" skipped\n");
                return None;
            }
            used_sids.push(*sid);
            Some(*sid)
        }
        SidChoice::Auto => {
            let next = if system_range { next_system } else { next_user };
            let mut sid = *next;
            while used_sids.contains(&sid) || fixed_sids.contains(&sid) {
                sid += 1;
            }
            *next = sid + 1;
            used_sids.push(sid);
            Some(sid)
        }
    }
}

/// Implements boot silos.
fn boot_silos(mut silos: Vec<SiloDef>) {
    let mut next_system_sid = SID_SYSTEM_FIRST;
    let mut next_user_sid = SID_USER_FIRST;
    // SIDs the configuration pins explicitly: automatic allocation must not
    // take one of them, even when the explicit silo is created later in the
    // list.
    let mut fixed_sids: Vec<u32> = Vec::new();
    for silo in &silos {
        if let SidChoice::Fixed(sid) = silo.sid {
            fixed_sids.push(sid);
        }
    }
    // SIDs handed out during this boot, explicit or automatic.
    let mut used_sids: Vec<u32> = Vec::new();

    // Move "bus" to front (must launch first for PCI discovery),
    // preserving relative order of all other silos.
    if let Some(bus_pos) = silos.iter().position(|s| s.name == "bus") {
        if bus_pos != 0 {
            let bus_def = silos.remove(bus_pos);
            silos.insert(0, bus_def);
        }
    }

    for s_def in silos {
        let Some(family) = get_family_profile(&s_def.family) else {
            log("[init] Invalid family '");
            log(&s_def.family);
            log("' for silo ");
            log(&s_def.name);
            log(", skipped\n");
            continue;
        };

        let requested_mode = match parse_mode_octal(&s_def.mode) {
            Some(mode) => mode,
            None => {
                log("[init] CONFIG ERROR: invalid mode '");
                log(&s_def.mode);
                log("' for silo ");
                log(&s_def.name);
                log(", skipped\n");
                continue;
            }
        };

        // Administrator capability: explicit opt-in from the boot config. It
        // is what `SYS_VMM_CREATE` and other privileged calls check; it is
        // never inferred from the family or the mode, and it is only accepted
        // for the SYS family.
        if s_def.admin && s_def.family != "SYS" {
            log("[init] SECURITY VIOLATION: admin requested for non-SYS silo ");
            log(&s_def.name);
            log(", skipped\n");
            continue;
        }

        // Policy Validation
        if !SiloMode(requested_mode).is_subset_of(&family.ceiling) {
            log("[init] SECURITY VIOLATION: silo ");
            log(&s_def.name);
            log(" exceeds family ceiling\n");
            continue;
        }

        // SYS, DRV, FS and NET allocate from the system range; WASM and USR
        // from the user range.
        let Some(final_sid) = claim_sid(
            &s_def.sid,
            family.id <= 3,
            &mut next_system_sid,
            &mut next_user_sid,
            &fixed_sids,
            &mut used_sids,
            &s_def.name,
        ) else {
            continue;
        };

        log("[init] Creating Silo: ");
        log(&s_def.name);
        log(" (SID=");
        log_u32(final_sid);
        log(")\n");

        let mut flags = 0u64;
        // The admin policy check above already restricted the opt-in to the
        // SYS family.
        if s_def.admin {
            flags |= SILO_FLAG_ADMIN;
        }
        let graphics_mode = s_def.graphics_mode.as_str();
        if s_def.graphics_enabled {
            flags |= SILO_FLAG_GRAPHICS;
            if graphics_mode == "webrtc-native" {
                flags |= SILO_FLAG_WEBRTC_NATIVE;
            }
            if s_def.graphics_read_only {
                flags |= SILO_FLAG_GRAPHICS_READ_ONLY;
            }
            if s_def.graphics_turn_policy == "force" {
                flags |= SILO_FLAG_WEBRTC_TURN_FORCE;
            }
        }
        let mut config = SiloConfig::zero();
        config.sid = final_sid;
        config.mode = requested_mode;
        config.family = family.id;
        config.flags = flags;
        config.graphics_max_sessions = if s_def.graphics_enabled {
            if s_def.graphics_max_sessions == 0 {
                1
            } else {
                s_def.graphics_max_sessions
            }
        } else {
            0
        };
        config.graphics_session_ttl_sec = if s_def.graphics_enabled {
            if s_def.graphics_session_ttl_sec == 0 {
                1800
            } else {
                s_def.graphics_session_ttl_sec
            }
        } else {
            0
        };
        config.dma_max_domains = s_def.dma_max_domains;
        config.dma_max_bytes = s_def.dma_max_bytes;
        config.dma_iova_base = s_def.dma_iova_base;
        config.dma_iova_limit = s_def.dma_iova_limit;
        config.dma_fault_policy = s_def.dma_fault_policy;

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

        let mut runtime_targets: Vec<(String, String)> = Vec::new();
        let mut active_strates = 0u32;

        if s_def.strates.is_empty() {
            log("[init] No strates declared for silo ");
            log(&s_def.name);
            log("\n");
        }

        for str_def in s_def.strates {
            match str_def.stype.as_str() {
                "elf" | "wasm-runtime" => {
                    log("[init]   -> Strate: ");
                    log(&str_def.name);
                    log("\n");
                    if let Some((module_handle, pid)) = start_elf_strate(silo_handle, &str_def) {
                        register_supervised(&str_def.name, pid as u64, silo_handle, module_handle);
                        if str_def.stype == "wasm-runtime" {
                            runtime_targets.push((str_def.name.clone(), str_def.target.clone()));
                        }
                        active_strates += 1;
                    }
                }
                "wasm-app" => {
                    log("[init]   -> Wasm-App: ");
                    log(&str_def.name);
                    log("\n");
                    let mut target_label = String::new();
                    if !str_def.target.is_empty() {
                        let mut found = false;
                        for (runtime_name, runtime_label) in runtime_targets.iter() {
                            if runtime_name == &str_def.target {
                                target_label = runtime_label.clone();
                                found = true;
                                break;
                            }
                        }
                        if !found {
                            target_label = str_def.target.clone();
                        }
                    }
                    if target_label.is_empty() {
                        target_label = String::from("default");
                    }

                    let service_path = alloc::format!("/srv/strate-wasm/{}", target_label);
                    match run_wasm_app(&service_path, &str_def.binary) {
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
                other => {
                    log("[init]   -> Strate '");
                    log(&str_def.name);
                    log("': unknown type '");
                    log(other);
                    log("', ignored\n");
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

// Keep the fallback identical to the configuration shipped in the UEFI image.
const DEFAULT_SILO_TOML: &str = include_str!("../../../assets/boot/silo.toml");

#[derive(Clone, Copy, PartialEq, Eq)]
enum StrateHealth {
    Ready,
    Failed,
}

struct SupervisedChild {
    name: [u8; 32],
    name_len: u8,
    pid: u64,
    /// Silo handle, kept so a crashed strate can be restarted in place.
    silo_handle: usize,
    /// Module handle of this strate.
    ///
    /// A silo only stores one `module_id`, and every `silo_attach_module`
    /// overwrites it: without this handle a restart in a silo that hosts
    /// several strates would start the last attached binary instead of the
    /// one that crashed.
    module_handle: usize,
    health: StrateHealth,
    restart_count: u16,
}

impl SupervisedChild {
    fn from_name(name: &str, pid: u64, silo_handle: usize, module_handle: usize) -> Self {
        let mut buf = [0u8; 32];
        // Truncate on a character boundary: cutting in the middle of a
        // multi-byte character would make `name_str` unsound.
        let mut n = core::cmp::min(name.len(), buf.len());
        while n > 0 && !name.is_char_boundary(n) {
            n -= 1;
        }
        buf[..n].copy_from_slice(&name.as_bytes()[..n]);
        Self {
            name: buf,
            name_len: n as u8,
            pid,
            silo_handle,
            module_handle,
            health: StrateHealth::Ready,
            restart_count: 0,
        }
    }

    fn name_str(&self) -> &str {
        // SAFETY: `from_name` only copies a prefix that ends on a UTF-8
        // character boundary of a valid `&str`.
        unsafe { core::str::from_utf8_unchecked(&self.name[..self.name_len as usize]) }
    }
}

/// Number of strates the supervisor can watch.
///
/// The shipped configuration already declares a dozen strates and the wasm
/// test overlay adds more; the table is therefore sized for `silo.toml` plus a
/// comfortable margin instead of silently dropping strates over the old 16.
const SUPERVISED_CAPACITY: usize = 64;

static mut SUPERVISED: [Option<SupervisedChild>; SUPERVISED_CAPACITY] =
    [const { None }; SUPERVISED_CAPACITY];
static mut SUPERVISED_COUNT: usize = 0;

fn register_supervised(name: &str, pid: u64, silo_handle: usize, module_handle: usize) {
    unsafe {
        if SUPERVISED_COUNT < SUPERVISED_CAPACITY {
            let sup = &mut *core::ptr::addr_of_mut!(SUPERVISED);
            sup[SUPERVISED_COUNT] = Some(SupervisedChild::from_name(
                name,
                pid,
                silo_handle,
                module_handle,
            ));
            SUPERVISED_COUNT += 1;
        } else {
            log("[init] WARN: SUPERVISED_CAPACITY exhausted, strate '");
            log(name);
            log("' pid=");
            log_u32(pid as u32);
            log(" not supervised\n");
        }
    }
}

fn supervisor_loop() -> ! {
    log("[init] Supervisor: entering watch loop\n");
    loop {
        let mut wstatus: i32 = 0;
        // Optimal blocking waitpid (0 instead of WNOHANG) : blocks without CPU-spinning or sched_yield.
        match call::waitpid(-1, Some(&mut wstatus), 0) {
            Ok(pid) if pid > 0 => {
                let status = wstatus;
                let mut found = false;
                unsafe {
                    let base =
                        core::ptr::addr_of_mut!(SUPERVISED).cast::<Option<SupervisedChild>>();
                    let count = SUPERVISED_COUNT;
                    for idx in 0..count {
                        let slot = base.add(idx);
                        if let Some(child) = (*slot).as_mut() {
                            if child.pid == pid as u64 {
                                child.health = StrateHealth::Failed;
                                found = true;
                                log("[init] Supervisor: strate '");
                                log(child.name_str());
                                log("' exited (status=");
                                log_u32(status as u32);
                                log(", restarts=");
                                log_u32(child.restart_count as u32);
                                log(")\n");

                                // Hot-restart in place: re-attach *this*
                                // strate's module (a silo keeps a single
                                // `module_id` slot, so the last attach wins)
                                // and start it under its own instance name.
                                // The replacement strate re-binds its
                                // namespace path; the mount takeover in
                                // `ipc_bind_port` makes that atomic.
                                if child.restart_count < 3 {
                                    child.restart_count += 1;
                                    let restarted = match call::silo_attach_module(
                                        child.silo_handle,
                                        child.module_handle,
                                    ) {
                                        Ok(_) => call::silo_start_named(
                                            child.silo_handle,
                                            child.name_str(),
                                        ),
                                        Err(e) => Err(e),
                                    };
                                    match restarted {
                                        Ok(new_pid) => {
                                            child.pid = new_pid as u64;
                                            child.health = StrateHealth::Ready;
                                            log("[init] Supervisor: restarted '");
                                            log(child.name_str());
                                            log("' pid=");
                                            log_u32(new_pid as u32);
                                            log("\n");
                                        }
                                        Err(e) => {
                                            log("[init] Supervisor: restart failed: ");
                                            log(e.name());
                                            log("\n");
                                        }
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
                if !found {
                    log("[init] Supervisor: unknown child pid=");
                    log_u32(pid as u32);
                    log(" exited status=");
                    log_u32(status as u32);
                    log("\n");
                }
            }
            _ => {
                // If waitpid fails or is interrupted, yield briefly to avoid hard lockups but sleep is the default.
                let _ = call::sched_yield();
            }
        }
    }
}

#[unsafe(no_mangle)]
/// Implements start.
pub unsafe extern "C" fn _start() -> ! {
    log("[init] Strat9 hierarchical boot starting\n");
    log("[init] Stage: load primary silos\n");
    let mut silos = load_primary_silos();
    log("[init] Stage: merge wasm overlay\n");
    merge_wasm_test_overlay(&mut silos);
    log("[init] Stage: ensure required silos\n");
    let silos = ensure_required_silos(silos);
    log("[init] Stage: boot silos\n");
    boot_silos(silos);
    log("[init] Boot complete.\n");
    supervisor_loop();
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    call::handle_panic("init", info)
}
