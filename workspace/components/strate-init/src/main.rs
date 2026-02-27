#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::alloc::Layout;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering};
use strat9_syscall::{call, number};

// ---------------------------------------------------------------------------
// GLOBAL ALLOCATOR (BUMP + BRK)
// ---------------------------------------------------------------------------

struct BumpAllocator;

static HEAP_START: AtomicUsize = AtomicUsize::new(0);
static HEAP_OFFSET: AtomicUsize = AtomicUsize::new(0);
const HEAP_MAX: usize = 16 * 1024 * 1024; // 16 MB heap for init

unsafe impl core::alloc::GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut start = HEAP_START.load(Ordering::Relaxed);
        if start == 0 {
            match call::brk(0) {
                Ok(cur) => {
                    if let Ok(_new) = call::brk(cur + HEAP_MAX) {
                        HEAP_START.store(cur, Ordering::SeqCst);
                        start = cur;
                    } else { return core::ptr::null_mut(); }
                }
                Err(_) => return core::ptr::null_mut(),
            }
        }

        let align = layout.align().max(1);
        let size = layout.size();
        let mut offset = HEAP_OFFSET.load(Ordering::Relaxed);
        loop {
            let aligned = (offset + align - 1) & !(align - 1);
            let next = aligned + size;
            if next > HEAP_MAX { return core::ptr::null_mut(); }
            
            match HEAP_OFFSET.compare_exchange(offset, next, Ordering::SeqCst, Ordering::Relaxed) {
                Ok(_) => return (start + aligned) as *mut u8,
                Err(prev) => offset = prev,
            }
        }
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    let _ = call::write(1, b"[init] OOM Fatal\n");
    call::exit(12);
}

// ---------------------------------------------------------------------------
// UTILS
// ---------------------------------------------------------------------------

fn log(msg: &str) {
    let _ = call::write(1, msg.as_bytes());
}

/// Simple file reader
fn read_file(path: &str) -> Result<Vec<u8>, &'static str> {
    let fd = call::openat(0, path, 0x1, 0).map_err(|_| "open failed")?;
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match call::read(fd as usize, &mut chunk) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&chunk[..n]),
            Err(_) => { let _ = call::close(fd as usize); return Err("read failed"); }
        }
    }
    let _ = call::close(fd as usize);
    Ok(out)
}

// ---------------------------------------------------------------------------
// MANUAL TOML-LIKE PARSER
// ---------------------------------------------------------------------------

struct SiloDef {
    name: String,
    stype: String,
    binary: String,
    admin: bool,
    target: String,
}

impl Default for SiloDef {
    fn default() -> Self {
        Self {
            name: String::from("default"),
            stype: String::from("elf"),
            binary: String::new(),
            admin: false,
            target: String::from("default"),
        }
    }
}

fn parse_config(data: &str) -> Vec<SiloDef> {
    let mut silos = Vec::new();
    let mut current = SiloDef::default();
    let mut in_silo = false;

    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }

        if line == "[[silos]]" {
            if in_silo { silos.push(current); }
            current = SiloDef::default();
            in_silo = true;
            continue;
        }

        if let Some(idx) = line.find('=') {
            let key = line[..idx].trim();
            let val = line[idx+1..].trim().trim_matches('"');
            match key {
                "name" => current.name = String::from(val),
                "type" => current.stype = String::from(val),
                "binary" => current.binary = String::from(val),
                "admin" => current.admin = val == "true",
                "target_strate" => current.target = String::from(val),
                _ => {}
            }
        }
    }
    if in_silo { silos.push(current); }
    silos
}

// ---------------------------------------------------------------------------
// SILO OPERATIONS
// ---------------------------------------------------------------------------

#[repr(C)]
struct SiloConfig {
    mem_min: u64, mem_max: u64, cpu_shares: u32, cpu_quota_us: u64,
    cpu_period_us: u64, cpu_affinity_mask: u64, max_tasks: u32,
    io_bw_read: u64, io_bw_write: u64, caps_ptr: u64, caps_len: u64, flags: u64,
}

fn spawn_elf(path: &str, is_admin: bool) -> Result<usize, &'static str> {
    log("[init] spawning ELF silo: "); log(path); log("\n");
    let data = read_file(path)?;
    
    let mod_handle = unsafe { strat9_syscall::syscall2(number::SYS_MODULE_LOAD, data.as_ptr() as usize, data.len()) }
        .map_err(|_| "module load failed")?;
    
    let silo_handle = call::silo_create(0).map_err(|_| "silo create failed")?;
    
    let mut config = unsafe { core::mem::zeroed::<SiloConfig>() };
    if is_admin { config.flags = 1; } // SILO_FLAG_ADMIN
    call::silo_config(silo_handle, &config as *const _ as usize).map_err(|_| "silo config failed")?;
    
    call::silo_attach_module(silo_handle, mod_handle).map_err(|_| "attach failed")?;
    call::silo_start(silo_handle).map_err(|_| "start failed")?;
    
    Ok(silo_handle)
}

fn wasm_run(strate_label: &str) -> Result<(), &'static str> {
    let service_path = format!("/srv/strate-wasm/{}", strate_label);
    log("[init] wasm-run: waiting for "); log(&service_path); log("\n");

    let mut found = false;
    for _ in 0..100 {
        if let Ok(fd) = call::openat(0, &service_path, 0x1, 0) {
            let _ = call::close(fd as usize);
            found = true; break;
        }
        let _ = call::sched_yield();
    }
    if !found { return Err("strate-wasm timeout"); }

    log("[init] wasm-run: strate ready\n");
    Ok(())
}

// ---------------------------------------------------------------------------
// MAIN
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start() -> ! {
    log("[init] boot sequence starting\n");

    match read_file("/initfs/silo.toml") {
        Ok(data_vec) => {
            if let Ok(data_str) = core::str::from_utf8(&data_vec) {
                let silos = parse_config(data_str);
                for silo in silos {
                    match silo.stype.as_str() {
                        "elf" | "wasm-runtime" => {
                            let _ = spawn_elf(&silo.binary, silo.admin);
                        }
                        "wasm-app" => {
                            let _ = wasm_run(&silo.target);
                        }
                        _ => { log("[init] unknown type\n"); }
                    }
                }
            }
        }
        Err(_) => { log("[init] /initfs/silo.toml not found\n"); }
    }

    log("[init] boot complete, entering idle loop\n");
    loop { let _ = call::sched_yield(); }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    let _ = call::write(1, b"[init] PANIC!\n");
    call::exit(255)
}
