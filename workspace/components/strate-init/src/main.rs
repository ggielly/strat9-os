#![no_std]
#![no_main]

use core::panic::PanicInfo;
use strat9_syscall::{call, number};

fn log(msg: &str) {
    let _ = call::write(1, msg.as_bytes());
}

fn log_u64(mut value: u64) {
    let mut buf = [0u8; 21];
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

/// Read an entire file into a heap-allocated buffer using brk().
/// Returns (ptr, len) on success.
fn read_file_to_heap(path: &str) -> Result<(*const u8, usize), &'static str> {
    let fd = call::openat(0, path, 0x1, 0) // O_READ = 0x1
        .map_err(|_| "open failed")?;

    // Use brk to allocate a read buffer (up to 2MB)
    const MAX_FILE_SIZE: usize = 2 * 1024 * 1024;
    let heap_start = call::brk(0).map_err(|_| "brk query failed")?;
    let heap_end = call::brk(heap_start + MAX_FILE_SIZE).map_err(|_| "brk alloc failed")?;
    if heap_end < heap_start + MAX_FILE_SIZE {
        return Err("brk: not enough memory");
    }

    let buf_ptr = heap_start as *mut u8;
    let mut total = 0usize;

    loop {
        let remaining = MAX_FILE_SIZE - total;
        if remaining == 0 {
            break;
        }
        let chunk_size = if remaining > 4096 { 4096 } else { remaining };
        let chunk = unsafe { core::slice::from_raw_parts_mut(buf_ptr.add(total), chunk_size) };
        match call::read(fd as usize, chunk) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(_) => {
                let _ = call::close(fd as usize);
                return Err("read failed");
            }
        }
    }

    let _ = call::close(fd as usize);

    // Shrink the heap to actual size
    let _ = call::brk(heap_start + total);

    Ok((buf_ptr as *const u8, total))
}

fn create_console_admin_silo() -> Result<(), &'static str> {
    log("[init] Loading /initfs/console-admin...\n");

    let (data_ptr, data_len) = read_file_to_heap("/initfs/console-admin")?;

    // Load as a module blob
    let module_handle =
        unsafe { strat9_syscall::syscall2(number::SYS_MODULE_LOAD, data_ptr as usize, data_len) }
            .map_err(|_| "module_load failed")?;

    log("[init] Module loaded, handle=");
    log_u64(module_handle as u64);
    log("\n");

    // Create the silo
    let silo_handle = call::silo_create(0).map_err(|_| "silo_create failed")?;
    log("[init] Silo created, handle=");
    log_u64(silo_handle as u64);
    log("\n");

    // Attach the module
    call::silo_attach_module(silo_handle, module_handle).map_err(|_| "silo_attach failed")?;

    let config = SiloConfigUser::admin();
    let config_ptr = &config as *const SiloConfigUser as usize;
    call::silo_config(silo_handle, config_ptr).map_err(|_| "silo_config failed")?;

    // Start the silo
    call::silo_start(silo_handle).map_err(|_| "silo_start failed")?;
    log("[init] Console-admin silo started.\n");

    Ok(())
}

fn create_net_silo() -> Result<(), &'static str> {
    log("[init] Loading /initfs/strate-net...\n");

    let (data_ptr, data_len) = read_file_to_heap("/initfs/strate-net")?;

    // Load as a module blob
    let module_handle =
        unsafe { strat9_syscall::syscall2(number::SYS_MODULE_LOAD, data_ptr as usize, data_len) }
            .map_err(|_| "module_load failed")?;

    log("[init] Module loaded, handle=");
    log_u64(module_handle as u64);
    log("\n");

    // Create the silo
    let silo_handle = call::silo_create(0).map_err(|_| "silo_create failed")?;
    log("[init] Silo created, handle=");
    log_u64(silo_handle as u64);
    log("\n");

    // Attach the module
    call::silo_attach_module(silo_handle, module_handle).map_err(|_| "silo_attach failed")?;

    let config = SiloConfigUser::admin(); // Network needs admin privileges for now to access NIC
    let config_ptr = &config as *const SiloConfigUser as usize;
    call::silo_config(silo_handle, config_ptr).map_err(|_| "silo_config failed")?;

    // Start the silo
    call::silo_start(silo_handle).map_err(|_| "silo_start failed")?;
    log("[init] Network silo started.\n");

    Ok(())
}

fn create_dhcp_client_silo() -> Result<(), &'static str> {
    log("[init] Loading /initfs/bin/dhcp-client...\n");

    let (data_ptr, data_len) = read_file_to_heap("/initfs/bin/dhcp-client")?;

    let module_handle =
        unsafe { strat9_syscall::syscall2(number::SYS_MODULE_LOAD, data_ptr as usize, data_len) }
            .map_err(|_| "module_load failed")?;

    log("[init] dhcp-client module loaded, handle=");
    log_u64(module_handle as u64);
    log("\n");

    let silo_handle = call::silo_create(0).map_err(|_| "silo_create failed")?;
    log("[init] dhcp-client silo created, handle=");
    log_u64(silo_handle as u64);
    log("\n");

    call::silo_attach_module(silo_handle, module_handle).map_err(|_| "silo_attach failed")?;

    // dhcp-client only needs read access to /net – no admin privileges needed
    let config = SiloConfigUser::admin(); // TODO: reduce to unprivileged once caps allow reading /net
    let config_ptr = &config as *const SiloConfigUser as usize;
    call::silo_config(silo_handle, config_ptr).map_err(|_| "silo_config failed")?;

    call::silo_start(silo_handle).map_err(|_| "silo_start failed")?;
    log("[init] dhcp-client silo started (polling /net for DHCP).\n");

    Ok(())
}

/// Monitor the console-admin silo and restart it if it crashes.
fn monitor_loop() -> ! {
    log("[init] Entering monitor loop.\n");
    loop {
        // Yield to let other tasks run
        let _ = call::sched_yield();

        // TODO: poll silo_event_next to detect crashes and restart
    }
}

const SILO_FLAG_ADMIN: u64 = 1 << 0;

#[repr(C)]
struct SiloConfigUser {
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
}

impl SiloConfigUser {
    const fn admin() -> Self {
        SiloConfigUser {
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
            flags: SILO_FLAG_ADMIN,
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    log("[init] PANIC! Exiting with code 255.\n");
    call::exit(255)
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("\n");
    log("============================================================\n");
    log("[init] strat9-os init process starting\n");
    log("============================================================\n");

    match create_console_admin_silo() {
        Ok(()) => {
            log("[init] Console-admin silo launched successfully.\n");
        }
        Err(msg) => {
            log("[init] Failed to launch console-admin: ");
            log(msg);
            log("\n");
            log("[init] Falling back to idle loop.\n");
        }
    }

    match create_net_silo() {
        Ok(()) => {
            log("[init] Network silo launched successfully.\n");
        }
        Err(msg) => {
            log("[init] Failed to launch network silo: ");
            log(msg);
            log("\n");
        }
    }

    // Launch dhcp-client after the network stack – it polls /net/ip until DHCP completes
    match create_dhcp_client_silo() {
        Ok(()) => {
            log("[init] dhcp-client launched (will report when DHCP completes).\n");
        }
        Err(msg) => {
            log("[init] Failed to launch dhcp-client: ");
            log(msg);
            log("\n");
        }
    }

    monitor_loop()
}
