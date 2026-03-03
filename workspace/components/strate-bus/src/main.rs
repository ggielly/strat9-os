#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use core::{alloc::Layout, panic::PanicInfo};
use strat9_bus_drivers::{
    probe::{self, ProbeMode},
    scheme::BusSchemeServer,
    simple_pm_bus::SimplePmBus,
    BusDriver,
};
use strat9_syscall::call;

alloc_freelist::define_freelist_brk_allocator!(
    pub struct BumpAllocator;
    brk = strat9_syscall::call::brk;
    heap_max = 4 * 1024 * 1024;
);

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

#[alloc_error_handler]
/// Implements alloc error.
fn alloc_error(_layout: Layout) -> ! {
    let _ = call::debug_log(b"[strate-bus] OOM\n");
    call::exit(12);
}

#[panic_handler]
/// Implements panic.
fn panic(_info: &PanicInfo) -> ! {
    let _ = call::debug_log(b"[strate-bus] PANIC\n");
    call::exit(255);
}

/// Implements u32 to ascii.
fn u32_to_ascii(mut n: u32, buf: &mut [u8; 10]) -> &[u8] {
    if n == 0 {
        buf[9] = b'0';
        return &buf[9..10];
    }
    let mut pos = 10;
    while n > 0 && pos > 0 {
        pos -= 1;
        buf[pos] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    &buf[pos..10]
}

/// Implements log probe counts.
fn log_probe_counts(passed: u32, failed: u32) {
    let mut line = [0u8; 64];
    let prefix = b"[strate-bus] MMIO probe: passed=";
    let mid = b" failed=";
    let suffix = b"\n";
    let mut off = 0usize;

    line[off..off + prefix.len()].copy_from_slice(prefix);
    off += prefix.len();

    let mut tmp = [0u8; 10];
    let digits = u32_to_ascii(passed, &mut tmp);
    line[off..off + digits.len()].copy_from_slice(digits);
    off += digits.len();

    line[off..off + mid.len()].copy_from_slice(mid);
    off += mid.len();

    let digits = u32_to_ascii(failed, &mut tmp);
    line[off..off + digits.len()].copy_from_slice(digits);
    off += digits.len();

    line[off..off + suffix.len()].copy_from_slice(suffix);
    off += suffix.len();

    let _ = call::debug_log(&line[..off]);
}

/// Reads file.
fn read_file(path: &str) -> Option<alloc::vec::Vec<u8>> {
    let fd = call::openat(0, path, 0x1, 0).ok()?;
    let mut out = alloc::vec::Vec::new();
    let mut buf = [0u8; 256];
    loop {
        match call::read(fd as usize, &mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    let _ = call::close(fd as usize);
    Some(out)
}

/// Parses probe mode from silo toml.
fn parse_probe_mode_from_silo_toml(text: &str) -> Option<ProbeMode> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Section {
        Silo,
        Strate,
    }

    let mut section = Section::Silo;
    let mut in_bus_silo = false;
    let mut in_bus_strate = false;

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[silos]]" {
            section = Section::Silo;
            in_bus_silo = false;
            in_bus_strate = false;
            continue;
        }
        if line == "[[silos.strates]]" {
            section = Section::Strate;
            in_bus_strate = false;
            continue;
        }

        let Some(idx) = line.find('=') else {
            continue;
        };
        let key = line[..idx].trim();
        let val = line[idx + 1..].trim().trim_matches('"');

        if section == Section::Silo {
            if key == "name" {
                in_bus_silo = val == "bus";
                in_bus_strate = false;
            }
            continue;
        }

        if !in_bus_silo {
            continue;
        }

        if key == "name" {
            in_bus_strate = val == "strate-bus";
            continue;
        }

        if in_bus_strate && key == "probe_mode" {
            return match val {
                "quick" | "QUICK" => Some(ProbeMode::Quick),
                "full" | "FULL" => Some(ProbeMode::Full),
                _ => None,
            };
        }
    }

    None
}

/// Implements load probe mode.
fn load_probe_mode() -> ProbeMode {
    let Some(data) = read_file("/initfs/silo.toml") else {
        return ProbeMode::Full;
    };
    let Ok(text) = core::str::from_utf8(&data) else {
        return ProbeMode::Full;
    };
    parse_probe_mode_from_silo_toml(text).unwrap_or(ProbeMode::Full)
}

/// Implements startup hardware test.
fn startup_hardware_test(driver: &mut SimplePmBus) -> bool {
    if driver.compatible().is_empty() {
        return false;
    }
    if driver.init(0x1000).is_err() {
        return false;
    }
    driver.shutdown().is_ok()
}

#[unsafe(no_mangle)]
/// Implements start.
pub extern "C" fn _start() -> ! {
    let _ = call::debug_log(b"[strate-bus] Starting\n");
    let port = match call::ipc_create_port(0) {
        Ok(h) => h as u64,
        Err(_) => call::exit(1),
    };
    if call::ipc_bind_port(port as usize, b"/srv/strate-bus/default").is_err() {
        call::exit(2);
    }
    let _ = call::ipc_bind_port(port as usize, b"/bus");

    let probe_mode = load_probe_mode();
    match probe_mode {
        ProbeMode::Quick => {
            let _ = call::debug_log(b"[strate-bus] Probe mode: quick\n");
        }
        ProbeMode::Full => {
            let _ = call::debug_log(b"[strate-bus] Probe mode: full\n");
        }
    }
    let _ = call::debug_log(b"[strate-bus] MMIO probe starting\n");
    let probe_result = probe::run_mmio_probe_with_mode(probe_mode);
    if probe_result.all_passed() {
        let _ = call::debug_log(b"[strate-bus] MMIO probe: ALL PASSED\n");
    } else {
        let _ = call::debug_log(b"[strate-bus] MMIO probe: FAILURES DETECTED\n");
    }
    log_probe_counts(probe_result.passed, probe_result.failed);
    let mut driver = SimplePmBus::new();
    if startup_hardware_test(&mut driver) {
        let _ = call::debug_log(b"[strate-bus] Startup hardware test: OK\n");
    } else {
        let _ = call::debug_log(b"[strate-bus] Startup hardware test: FAILED\n");
    }

    let mut server = BusSchemeServer::new(driver, port);
    server.refresh_pci_cache();
    server.serve();
}
