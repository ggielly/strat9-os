#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use alloc::{string::String, vec::Vec};
use core::{alloc::Layout, panic::PanicInfo};
use strat9_syscall::{call, data::IpcMessage, number};

const EAGAIN: usize = 11;
const MAX_READ_BYTES: usize = 64 * 1024 * 1024;
const MAX_READ_ITERS: usize = 32768;
const MAX_READ_EAGAIN: usize = 256;
const SUPERVISOR_POLL_YIELDS: usize = 512;

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
// SECURITY POLICY & PROFILES (From silo_security_model.md)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct OctalMode(u16);

impl OctalMode {
    /// Returns whether subset of.
    fn is_subset_of(&self, other: &OctalMode) -> bool {
        let (s_c, s_h, s_r) = ((self.0 >> 6) & 0o7, (self.0 >> 3) & 0o7, self.0 & 0o7);
        let (o_c, o_h, o_r) = ((other.0 >> 6) & 0o7, (other.0 >> 3) & 0o7, other.0 & 0o7);
        (s_c & !o_c) == 0 && (s_h & !o_h) == 0 && (s_r & !o_r) == 0
    }
}

struct FamilyProfile {
    family: &'static str,
    max_mode: OctalMode,
}

const FAMILY_PROFILES: &[FamilyProfile] = &[
    FamilyProfile {
        family: "SYS",
        max_mode: OctalMode(0o777),
    },
    FamilyProfile {
        family: "DRV",
        max_mode: OctalMode(0o076),
    },
    FamilyProfile {
        family: "FS",
        max_mode: OctalMode(0o076),
    },
    FamilyProfile {
        family: "NET",
        max_mode: OctalMode(0o076),
    },
    FamilyProfile {
        family: "WASM",
        max_mode: OctalMode(0o006),
    },
    FamilyProfile {
        family: "USR",
        max_mode: OctalMode(0o004),
    },
];

/// Returns family profile.
fn get_family_profile(name: &str) -> &'static FamilyProfile {
    for p in FAMILY_PROFILES {
        if p.family == name {
            return p;
        }
    }
    &FAMILY_PROFILES[5] // Default to USR
}

// ---------------------------------------------------------------------------
// UTILS
// ---------------------------------------------------------------------------

/// Implements log.
fn log(msg: &str) {
    let _ = call::debug_log(msg.as_bytes());
}

/// Reads file.
fn read_file(path: &str) -> Result<Vec<u8>, &'static str> {
    let fd = call::openat(0, path, 0x1, 0).map_err(|_| "open failed")?;
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut iters = 0usize;
    let mut eagain = 0usize;
    loop {
        if out.len() >= MAX_READ_BYTES || iters >= MAX_READ_ITERS {
            break;
        }
        iters += 1;
        match call::read(fd as usize, &mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                let remain = MAX_READ_BYTES.saturating_sub(out.len());
                let take = core::cmp::min(n, remain);
                out.extend_from_slice(&chunk[..take]);
                eagain = 0;
                if take < n {
                    log("[init] read_file: truncated at MAX_READ_BYTES\n");
                    break;
                }
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

struct StrateDef {
    name: String,
    binary: String,
    stype: String,
    target: String,
}

struct SiloDef {
    name: String,
    sid: u32,
    family: String,
    mode: String,
    graphics_enabled: bool,
    graphics_mode: String,
    graphics_read_only: bool,
    graphics_max_sessions: u16,
    graphics_session_ttl_sec: u32,
    graphics_turn_policy: String,
    strates: Vec<StrateDef>,
}

/// Parses config.
fn parse_config(data: &str) -> Vec<SiloDef> {
    #[derive(Clone, Copy)]
    enum Section {
        Silo,
        Strate,
    }

    /// Implements push default strate.
    fn push_default_strate(silo: &mut SiloDef) {
        silo.strates.push(StrateDef {
            name: String::new(),
            binary: String::new(),
            stype: String::from("elf"),
            target: String::from("default"),
        });
    }

    let mut silos = Vec::new();
    let mut current_silo: Option<SiloDef> = None;
    let mut section = Section::Silo;

    for raw_line in data.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line == "[[silos]]" {
            if let Some(s) = current_silo.take() {
                silos.push(s);
            }
            current_silo = Some(SiloDef {
                name: String::new(),
                sid: 42,
                family: String::from("USR"),
                mode: String::from("000"),
                graphics_enabled: false,
                graphics_mode: String::new(),
                graphics_read_only: false,
                graphics_max_sessions: 0,
                graphics_session_ttl_sec: 0,
                graphics_turn_policy: String::from("auto"),
                strates: Vec::new(),
            });
            section = Section::Silo;
            continue;
        }

        if line == "[[silos.strates]]" {
            if let Some(ref mut s) = current_silo {
                push_default_strate(s);
            }
            section = Section::Strate;
            continue;
        }

        if let Some(idx) = line.find('=') {
            let key = line[..idx].trim();
            let val = line[idx + 1..].trim().trim_matches('"');

            if let Some(ref mut s) = current_silo {
                match section {
                    Section::Silo => match key {
                        "name" => s.name = String::from(val),
                        "sid" => s.sid = val.parse().unwrap_or(42),
                        "family" => s.family = String::from(val),
                        "mode" => s.mode = String::from(val),
                        "graphics_enabled" => s.graphics_enabled = parse_toml_bool(val),
                        "graphics_mode" => s.graphics_mode = String::from(val),
                        "graphics_read_only" => s.graphics_read_only = parse_toml_bool(val),
                        "graphics_max_sessions" => {
                            s.graphics_max_sessions = val.parse().unwrap_or(0)
                        }
                        "graphics_session_ttl_sec" => {
                            s.graphics_session_ttl_sec = val.parse().unwrap_or(0)
                        }
                        "graphics_turn_policy" => s.graphics_turn_policy = String::from(val),
                        _ => {}
                    },
                    Section::Strate => {
                        if s.strates.is_empty() {
                            push_default_strate(s);
                        }
                        if let Some(strate) = s.strates.last_mut() {
                            match key {
                                "name" => strate.name = String::from(val),
                                "binary" => strate.binary = String::from(val),
                                "type" => strate.stype = String::from(val),
                                "target_strate" => strate.target = String::from(val),
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
    }
    if let Some(s) = current_silo {
        silos.push(s);
    }
    silos
}

/// Implements ensure required silos.
fn ensure_required_silos(mut silos: Vec<SiloDef>) -> Vec<SiloDef> {
    let has_bus = silos.iter().any(|s| s.name == "bus");
    let has_network = silos.iter().any(|s| s.name == "network");
    let has_dhcp = silos.iter().any(|s| s.name == "dhcp-client");

    if !has_bus {
        log("[init] Missing mandatory silo 'bus' in config, adding fallback\n");
        silos.push(SiloDef {
            name: String::from("bus"),
            sid: 42,
            family: String::from("DRV"),
            mode: String::from("076"),
            graphics_enabled: false,
            graphics_mode: String::new(),
            graphics_read_only: false,
            graphics_max_sessions: 0,
            graphics_session_ttl_sec: 0,
            graphics_turn_policy: String::from("auto"),
            strates: alloc::vec![StrateDef {
                name: String::from("strate-bus"),
                binary: String::from("/initfs/strate-bus"),
                stype: String::from("elf"),
                target: String::from("default"),
            }],
        });
    }

    if !has_network {
        log("[init] Missing mandatory silo 'network' in config, adding fallback\n");
        silos.push(SiloDef {
            name: String::from("network"),
            sid: 42,
            family: String::from("NET"),
            mode: String::from("076"),
            graphics_enabled: false,
            graphics_mode: String::new(),
            graphics_read_only: false,
            graphics_max_sessions: 0,
            graphics_session_ttl_sec: 0,
            graphics_turn_policy: String::from("auto"),
            strates: alloc::vec![StrateDef {
                name: String::from("strate-net"),
                binary: String::from("/initfs/strate-net"),
                stype: String::from("elf"),
                target: String::from("default"),
            }],
        });
    }

    if !has_dhcp {
        log("[init] Missing mandatory silo 'dhcp-client' in config, adding fallback\n");
        silos.push(SiloDef {
            name: String::from("dhcp-client"),
            sid: 42,
            family: String::from("NET"),
            mode: String::from("076"),
            graphics_enabled: false,
            graphics_mode: String::new(),
            graphics_read_only: false,
            graphics_max_sessions: 0,
            graphics_session_ttl_sec: 0,
            graphics_turn_policy: String::from("auto"),
            strates: alloc::vec![StrateDef {
                name: String::from("dhcp-client"),
                binary: String::from("/initfs/bin/dhcp-client"),
                stype: String::from("elf"),
                target: String::from("default"),
            }],
        });
    }

    silos
}

/// Implements load primary silos.
fn load_primary_silos() -> Vec<SiloDef> {
    log("[init] load_primary_silos: begin\n");
    match read_file("/initfs/silo.toml") {
        Ok(data_vec) => match core::str::from_utf8(&data_vec) {
            Ok(data_str) => {
                log("[init] load_primary_silos: parse /initfs/silo.toml\n");
                let parsed = parse_config(data_str);
                if parsed.is_empty() {
                    log("[init] Empty /initfs/silo.toml, using embedded defaults\n");
                    log("[init] load_primary_silos: parse embedded defaults\n");
                    let parsed = parse_config(DEFAULT_SILO_TOML);
                    log("[init] load_primary_silos: parsed embedded defaults count=");
                    log_u32(parsed.len() as u32);
                    log("\n");
                    parsed
                } else {
                    log("[init] load_primary_silos: parsed file count=");
                    log_u32(parsed.len() as u32);
                    log("\n");
                    parsed
                }
            }
            Err(_) => {
                log("[init] Invalid UTF-8 in /initfs/silo.toml, using embedded defaults\n");
                log("[init] load_primary_silos: parse embedded defaults\n");
                let parsed = parse_config(DEFAULT_SILO_TOML);
                log("[init] load_primary_silos: parsed embedded defaults count=");
                log_u32(parsed.len() as u32);
                log("\n");
                parsed
            }
        },
        Err(_) => {
            log("[init] Missing /initfs/silo.toml, using embedded defaults\n");
            log("[init] load_primary_silos: parse embedded defaults\n");
            let parsed = parse_config(DEFAULT_SILO_TOML);
            log("[init] load_primary_silos: parsed embedded defaults count=");
            log_u32(parsed.len() as u32);
            log("\n");
            parsed
        }
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

#[repr(C)]
struct SiloConfig {
    mem_min: u64,
    mem_max: u64,
    cpu_shares: u32,
    cpu_quota_us: u64,
    cpu_period_us: u64,
    cpu_affinity_mask: u64,
    max_tasks: u32,
    io_bw_read: u64,
    io_bw_write: u64,
    caps_ptr: u64,
    caps_len: u64,
    flags: u64,
    sid: u32,
    mode: u16,
    family: u8,
    cpu_features_required: u64,
    cpu_features_allowed: u64,
    xcr0_mask: u64,
    graphics_max_sessions: u16,
    graphics_session_ttl_sec: u32,
    graphics_reserved: u16,
}

impl SiloConfig {
    /// Creates a new instance.
    const fn new(sid: u32, mode: u16, family: u8, flags: u64) -> Self {
        Self {
            mem_min: 0,
            mem_max: 0,
            cpu_shares: 0,
            cpu_quota_us: 0,
            cpu_period_us: 0,
            cpu_affinity_mask: 0,
            max_tasks: 0,
            io_bw_read: 0,
            io_bw_write: 0,
            caps_ptr: 0,
            caps_len: 0,
            flags,
            sid,
            mode,
            family,
            cpu_features_required: 0,
            cpu_features_allowed: u64::MAX,
            xcr0_mask: 0,
            graphics_max_sessions: 0,
            graphics_session_ttl_sec: 0,
            graphics_reserved: 0,
        }
    }
}

const SILO_FLAG_GRAPHICS: u64 = 1 << 1;
const SILO_FLAG_WEBRTC_NATIVE: u64 = 1 << 2;
const SILO_FLAG_GRAPHICS_READ_ONLY: u64 = 1 << 3;
const SILO_FLAG_WEBRTC_TURN_FORCE: u64 = 1 << 4;

/// Implements family to id.
fn family_to_id(name: &str) -> Option<u8> {
    match name {
        "SYS" => Some(0),
        "DRV" => Some(1),
        "FS" => Some(2),
        "NET" => Some(3),
        "WASM" => Some(4),
        "USR" => Some(5),
        _ => None,
    }
}

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

/// Implements log u32.
fn log_u32(mut value: u32) {
    let mut buf = [0u8; 10];
    if value == 0 {
        log("0");
        return;
    }
    let mut i = buf.len();
    while value > 0 {
        i -= 1;
        buf[i] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    let s = unsafe { core::str::from_utf8_unchecked(&buf[i..]) };
    log(s);
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

/// Implements connect wasm service.
fn connect_wasm_service(path: &str) -> Result<usize, &'static str> {
    for _ in 0..256 {
        if let Ok(h) = call::ipc_connect(path.as_bytes()) {
            return Ok(h);
        }
        let _ = call::sched_yield();
    }
    Err("ipc_connect timeout")
}

/// Implements run wasm app.
fn run_wasm_app(service_path: &str, wasm_path: &str) -> Result<(), u32> {
    let port = connect_wasm_service(service_path).map_err(|_| 0xffff0000u32)?;

    let mut load = IpcMessage::new(0x100);
    let bytes = wasm_path.as_bytes();
    let n = core::cmp::min(bytes.len(), load.payload.len().saturating_sub(1));
    load.payload[0] = n as u8;
    if n > 0 {
        load.payload[1..1 + n].copy_from_slice(&bytes[..n]);
    }
    let load_status = ipc_call_status(port, &mut load).map_err(|_| 0xffff0001u32)?;
    if load_status != 0 {
        let _ = call::handle_close(port);
        return Err(load_status);
    }

    let mut run = IpcMessage::new(0x102);
    let run_status = ipc_call_status(port, &mut run).map_err(|_| 0xffff0002u32)?;
    let _ = call::handle_close(port);
    if run_status != 0 {
        return Err(run_status);
    }
    Ok(())
}

/// Implements boot silos.
fn boot_silos(silos: Vec<SiloDef>) {
    let mut next_sys_sid = 100u32;
    let mut next_usr_sid = 1000u32;
    let mut silos = silos;

    // Blocking launch order requirement:
    // - "bus" must start first and expose /bus/pci/* before PCI-dependent silos.
    // - other silos keep their relative order.
    silos.sort_by_key(|s| if s.name == "bus" { 0u8 } else { 1u8 });

    for s_def in silos {
        let requested_mode = parse_mode_octal(&s_def.mode).unwrap_or(0);
        let profile = get_family_profile(&s_def.family);

        // Policy Validation
        if !OctalMode(requested_mode).is_subset_of(&profile.max_mode) {
            log("[init] SECURITY VIOLATION: silo ");
            log(&s_def.name);
            log(" exceeds family ceiling\n");
            continue;
        }
        let family_id = match family_to_id(&s_def.family) {
            Some(id) => id,
            None => {
                log("[init] Invalid family for silo ");
                log(&s_def.name);
                log("\n");
                continue;
            }
        };

        let final_sid = if s_def.sid == 42 {
            match family_id {
                0 | 1 | 2 | 3 => {
                    let id = next_sys_sid;
                    next_sys_sid += 1;
                    id
                }
                _ => {
                    let id = next_usr_sid;
                    next_usr_sid += 1;
                    id
                }
            }
        } else {
            s_def.sid
        };

        log(&alloc::format!(
            "[init] Creating Silo: {} (SID={})\n",
            s_def.name,
            final_sid
        ));

        let mut flags = 0u64;
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
        let mut config = SiloConfig::new(final_sid, requested_mode, family_id, flags);
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

        let silo_handle = match call::silo_create((&config as *const SiloConfig) as usize) {
            Ok(h) => h,
            Err(e) => {
                log("[init] silo_create failed: ");
                log(e.name());
                log("\n");
                continue;
            }
        };

        if s_def.strates.is_empty() {
            log("[init] No strates declared for silo ");
            log(&s_def.name);
            log("\n");
            continue;
        }

        let mut runtime_targets: Vec<(String, String)> = Vec::new();

        for str_def in s_def.strates {
            match str_def.stype.as_str() {
                "elf" | "wasm-runtime" => {
                    log(&alloc::format!("[init]   -> Strate: {}\n", str_def.name));
                    if str_def.binary.starts_with("/initfs/") {
                        log(&alloc::format!("[init]     module path {}\n", str_def.binary));
                        let mod_h = match unsafe {
                            strat9_syscall::syscall2(
                                number::SYS_MODULE_LOAD,
                                str_def.binary.as_ptr() as usize,
                                str_def.binary.len(),
                            )
                        } {
                            Ok(h) => h,
                            Err(_) => {
                                log(&alloc::format!(
                                    "[init] module_load failed for {}\n",
                                    str_def.binary
                                ));
                                continue;
                            }
                        };
                        if let Err(e) = call::silo_attach_module(silo_handle, mod_h) {
                            log(&alloc::format!(
                                "[init] silo_attach_module failed: {}\n",
                                e.name()
                            ));
                            continue;
                        }
                        match call::silo_start(silo_handle) {
                            Err(e) => {
                                log(&alloc::format!("[init] silo_start failed: {}\n", e.name()));
                            }
                            Ok(pid) => {
                                register_supervised(&str_def.name, pid as u64);
                                if str_def.stype == "wasm-runtime" {
                                    runtime_targets
                                        .push((str_def.name.clone(), str_def.target.clone()));
                                }
                            }
                        }
                        continue;
                    }
                    if let Ok(data) = read_file(&str_def.binary) {
                        if data.len() >= 4 {
                            log(&alloc::format!(
                                "[init]     module magic {:02x}{:02x}{:02x}{:02x} size={}\n",
                                data[0],
                                data[1],
                                data[2],
                                data[3],
                                data.len()
                            ));
                        } else {
                            log(&alloc::format!(
                                "[init]     module too small size={}\n",
                                data.len()
                            ));
                        }
                        let mod_h = match unsafe {
                            strat9_syscall::syscall2(
                                number::SYS_MODULE_LOAD,
                                data.as_ptr() as usize,
                                data.len(),
                            )
                        } {
                            Ok(h) => h,
                            Err(_) => {
                                log(&alloc::format!(
                                    "[init] module_load failed for {}\n",
                                    str_def.binary
                                ));
                                continue;
                            }
                        };
                        if let Err(e) = call::silo_attach_module(silo_handle, mod_h) {
                            log(&alloc::format!(
                                "[init] silo_attach_module failed: {}\n",
                                e.name()
                            ));
                            continue;
                        }
                        match call::silo_start(silo_handle) {
                            Err(e) => {
                                log(&alloc::format!("[init] silo_start failed: {}\n", e.name()));
                            }
                            Ok(pid) => {
                                register_supervised(&str_def.name, pid as u64);
                                if str_def.stype == "wasm-runtime" {
                                    runtime_targets
                                        .push((str_def.name.clone(), str_def.target.clone()));
                                }
                            }
                        }
                    } else {
                        log(&alloc::format!(
                            "[init] failed to read binary {}\n",
                            str_def.binary
                        ));
                    }
                }
                "wasm-app" => {
                    log(&alloc::format!("[init]   -> Wasm-App: {}\n", str_def.name));
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
                            log(&alloc::format!(
                                "[init]     wasm app started: {}\n",
                                str_def.binary
                            ));
                        }
                        Err(code) => {
                            let line = alloc::format!(
                                "[init]     wasm app failed: status=0x{:08x} (service={}, path={})\n",
                                code,
                                service_path,
                                str_def.binary
                            );
                            log(&line);
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

const DEFAULT_SILO_TOML: &str = r#"
[[silos]]
name = "console-admin"
family = "SYS"
mode = "700"
sid = 42
[[silos.strates]]
name = "console-admin"
binary = "/initfs/console-admin"
type = "elf"

[[silos]]
name = "bus"
family = "DRV"
mode = "076"
sid = 42
[[silos.strates]]
name = "strate-bus"
binary = "/initfs/strate-bus"
type = "elf"
probe_mode = "full"

[[silos]]
name = "network"
family = "NET"
mode = "076"
sid = 42
[[silos.strates]]
name = "strate-net"
binary = "/initfs/strate-net"
type = "elf"

[[silos]]
name = "dhcp-client"
family = "NET"
mode = "076"
sid = 42
[[silos.strates]]
name = "dhcp-client"
binary = "/initfs/bin/dhcp-client"
type = "elf"

[[silos]]
name = "telnet"
family = "NET"
mode = "076"
sid = 42
[[silos.strates]]
name = "telnetd"
binary = "/initfs/bin/telnetd"
type = "elf"

[[silos]]
name = "ssh"
family = "NET"
mode = "076"
sid = 42
[[silos.strates]]
name = "sshd"
binary = "/initfs/bin/sshd"
type = "elf"

[[silos]]
name = "web-admin"
family = "NET"
mode = "076"
sid = 42
graphics_enabled = true
graphics_mode = "webrtc-native"
graphics_max_sessions = 1
graphics_session_ttl_sec = 1800
graphics_turn_policy = "auto"
[[silos.strates]]
name = "web-admin"
binary = "/initfs/bin/web-admin"
type = "elf"

[[silos]]
name = "graphics-webrtc"
family = "NET"
mode = "076"
sid = 42
[[silos.strates]]
name = "strate-webrtc"
binary = "/initfs/strate-webrtc"
type = "elf"
"#;

#[derive(Clone, Copy, PartialEq, Eq)]
enum StrateHealth {
    Ready,
    Failed,
}

struct SupervisedChild {
    name: [u8; 32],
    name_len: u8,
    pid: u64,
    health: StrateHealth,
    restart_count: u16,
}

impl SupervisedChild {
    fn from_name(name: &str, pid: u64) -> Self {
        let mut buf = [0u8; 32];
        let n = core::cmp::min(name.len(), 32);
        buf[..n].copy_from_slice(&name.as_bytes()[..n]);
        Self {
            name: buf,
            name_len: n as u8,
            pid,
            health: StrateHealth::Ready,
            restart_count: 0,
        }
    }

    fn name_str(&self) -> &str {
        unsafe { core::str::from_utf8_unchecked(&self.name[..self.name_len as usize]) }
    }
}

static mut SUPERVISED: [Option<SupervisedChild>; 16] = [
    None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
];
static mut SUPERVISED_COUNT: usize = 0;
const SUPERVISED_CAPACITY: usize = 16;

fn register_supervised(name: &str, pid: u64) {
    unsafe {
        if SUPERVISED_COUNT < SUPERVISED_CAPACITY {
            let base = core::ptr::addr_of_mut!(SUPERVISED).cast::<Option<SupervisedChild>>();
            let slot = base.add(SUPERVISED_COUNT);
            slot.write(Some(SupervisedChild::from_name(name, pid)));
            SUPERVISED_COUNT += 1;
        }
    }
}

fn supervisor_loop() -> ! {
    log("[init] Supervisor: entering watch loop\n");
    loop {
        for _ in 0..SUPERVISOR_POLL_YIELDS {
            let _ = call::sched_yield();
        }

        let mut wstatus: i32 = 0;
        match call::waitpid(-1, Some(&mut wstatus), 1) {
            // WNOHANG = 1
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
            _ => {}
        }
    }
}

#[unsafe(no_mangle)]
/// Implements start.
pub unsafe extern "C" fn _start() -> ! {
    log("[init] Strat9 Hierarchical Boot Starting\n");
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
/// Implements panic.
fn panic(_info: &PanicInfo) -> ! {
    let _ = call::debug_log(b"[init] PANIC!\n");
    call::exit(255)
}
