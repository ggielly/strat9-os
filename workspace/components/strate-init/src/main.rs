#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use alloc::{string::String, vec::Vec};
use core::{
    alloc::Layout,
    panic::PanicInfo,
};
use strat9_syscall::{call, number};

// ---------------------------------------------------------------------------
// GLOBAL ALLOCATOR (BUMP + BRK)
// ---------------------------------------------------------------------------

alloc_freelist::define_freelist_brk_allocator!(
    pub struct BumpAllocator;
    brk = strat9_syscall::call::brk;
    heap_max = 16 * 1024 * 1024;
);

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    let _ = call::write(1, b"[init] OOM Fatal\n");
    call::exit(12);
}

// ---------------------------------------------------------------------------
// SECURITY POLICY & PROFILES (From silo_security_model.md)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct OctalMode(u16);

impl OctalMode {
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

fn log(msg: &str) {
    let _ = call::write(1, msg.as_bytes());
}

fn read_file(path: &str) -> Result<Vec<u8>, &'static str> {
    let fd = call::openat(0, path, 0x1, 0).map_err(|_| "open failed")?;
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match call::read(fd as usize, &mut chunk) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&chunk[..n]),
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
    strates: Vec<StrateDef>,
}

fn parse_config(data: &str) -> Vec<SiloDef> {
    #[derive(Clone, Copy)]
    enum Section {
        Silo,
        Strate,
    }

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

fn ensure_required_silos(mut silos: Vec<SiloDef>) -> Vec<SiloDef> {
    let has_network = silos.iter().any(|s| s.name == "network");
    let has_dhcp = silos.iter().any(|s| s.name == "dhcp-client");

    if !has_network {
        log("[init] Missing mandatory silo 'network' in config, adding fallback\n");
        silos.push(SiloDef {
            name: String::from("network"),
            sid: 42,
            family: String::from("NET"),
            mode: String::from("076"),
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
}

impl SiloConfig {
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
        }
    }
}

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

fn parse_mode_octal(s: &str) -> Option<u16> {
    let trimmed = if let Some(rest) = s.strip_prefix("0o") {
        rest
    } else {
        s
    };
    u16::from_str_radix(trimmed, 8).ok()
}

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

fn log_u8_hex(v: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let b = [HEX[(v >> 4) as usize], HEX[(v & 0x0f) as usize]];
    let s = unsafe { core::str::from_utf8_unchecked(&b) };
    log(s);
}

fn boot_silos(silos: Vec<SiloDef>) {
    let mut next_sys_sid = 100u32;
    let mut next_usr_sid = 1000u32;

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

        log("[init] Creating Silo: ");
        log(&s_def.name);
        log(" (SID=");
        log_u32(final_sid);
        log(")\n");

        let config = SiloConfig::new(final_sid, requested_mode, family_id, 0);

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

        for str_def in s_def.strates {
            match str_def.stype.as_str() {
                "elf" | "wasm-runtime" => {
                    log("[init]   -> Strate: ");
                    log(&str_def.name);
                    log("\n");
                    if let Ok(data) = read_file(&str_def.binary) {
                        if data.len() >= 4 {
                            log("[init]     module magic ");
                            log_u8_hex(data[0]);
                            log_u8_hex(data[1]);
                            log_u8_hex(data[2]);
                            log_u8_hex(data[3]);
                            log(" size=");
                            log_u32(data.len() as u32);
                            log("\n");
                        } else {
                            log("[init]     module too small size=");
                            log_u32(data.len() as u32);
                            log("\n");
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
                                log("[init] module_load failed for ");
                                log(&str_def.binary);
                                log("\n");
                                continue;
                            }
                        };
                        if let Err(e) = call::silo_attach_module(silo_handle, mod_h) {
                            log("[init] silo_attach_module failed: ");
                            log(e.name());
                            log("\n");
                            continue;
                        }
                        if let Err(e) = call::silo_start(silo_handle) {
                            log("[init] silo_start failed: ");
                            log(e.name());
                            log("\n");
                        }
                    } else {
                        log("[init] failed to read binary ");
                        log(&str_def.binary);
                        log("\n");
                    }
                }
                "wasm-app" => {
                    log("[init]   -> Wasm-App: ");
                    log(&str_def.name);
                    log("\n");
                    // Logic to send IPC to strate-wasm...
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
"#;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start() -> ! {
    log("[init] Strat9 Hierarchical Boot Starting\n");
    let silos = match read_file("/initfs/silo.toml") {
        Ok(data_vec) => match core::str::from_utf8(&data_vec) {
            Ok(data_str) => {
                let parsed = parse_config(data_str);
                if parsed.is_empty() {
                    log("[init] Empty /initfs/silo.toml, using embedded defaults\n");
                    parse_config(DEFAULT_SILO_TOML)
                } else {
                    parsed
                }
            }
            Err(_) => {
                log("[init] Invalid UTF-8 in /initfs/silo.toml, using embedded defaults\n");
                parse_config(DEFAULT_SILO_TOML)
            }
        },
        Err(_) => {
            log("[init] Missing /initfs/silo.toml, using embedded defaults\n");
            parse_config(DEFAULT_SILO_TOML)
        }
    };
    let silos = ensure_required_silos(silos);
    boot_silos(silos);
    log("[init] Boot complete.\n");
    loop {
        let _ = call::sched_yield();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    log("[init] PANIC!\n");
    call::exit(255)
}
