#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use core::{alloc::Layout, panic::PanicInfo};
use strat9_bus_drivers::{simple_pm_bus::SimplePmBus, scheme::BusSchemeServer, BusDriver};
use strat9_syscall::call;

alloc_freelist::define_freelist_brk_allocator!(
    pub struct BumpAllocator;
    brk = strat9_syscall::call::brk;
    heap_max = 4 * 1024 * 1024;
);

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    let _ = call::debug_log(b"[strate-bus] OOM\n");
    call::exit(12);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    let _ = call::debug_log(b"[strate-bus] PANIC\n");
    call::exit(255);
}

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

    let mut driver = SimplePmBus::new();
    if startup_hardware_test(&mut driver) {
        let _ = call::debug_log(b"[strate-bus] Startup hardware test: OK\n");
    } else {
        let _ = call::debug_log(b"[strate-bus] Startup hardware test: FAILED\n");
    }

    let mut server = BusSchemeServer::new(driver, port);
    server.serve();
}
