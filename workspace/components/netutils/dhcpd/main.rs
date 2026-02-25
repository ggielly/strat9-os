//! dhcpd – DHCP status monitor for strat9-os
//!
//! This is **not** a full DHCP client.  The actual DHCP exchange is performed
//! by the `strate-net` silo (via smoltcp's DHCPv4 socket).  `dhcpd` simply
//! polls the `/net/ip`, `/net/gateway`, `/net/route` and `/net/dns` scheme files until a
//! valid address is obtained, then prints the result to the console.
//!
//! All I/O is done through Plan 9–style schemes – no BSD sockets.

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use core::{
    alloc::Layout,
    panic::PanicInfo,
    sync::atomic::{AtomicUsize, Ordering},
};
use strat9_syscall::{call, data::TimeSpec, number};

// ---------------------------------------------------------------------------
// Minimal bump allocator (same pattern as other strat9 silos)
// ---------------------------------------------------------------------------

struct BumpAllocator;

const HEAP_SIZE: usize = 64 * 1024; // 64 KiB – dhcpd is tiny
static mut HEAP: [u8; HEAP_SIZE] = [0u8; HEAP_SIZE];
static HEAP_OFFSET: AtomicUsize = AtomicUsize::new(0);

unsafe impl core::alloc::GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align = layout.align().max(1);
        let size = layout.size();
        let mut offset = HEAP_OFFSET.load(Ordering::Relaxed);
        loop {
            let aligned = (offset + align - 1) & !(align - 1);
            let new_offset = match aligned.checked_add(size) {
                Some(v) => v,
                None => return core::ptr::null_mut(),
            };
            if new_offset > HEAP_SIZE {
                return core::ptr::null_mut();
            }
            match HEAP_OFFSET.compare_exchange(
                offset,
                new_offset,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    let heap_ptr = core::ptr::addr_of_mut!(HEAP) as *mut u8;
                    return unsafe { heap_ptr.add(aligned) };
                }
                Err(prev) => offset = prev,
            }
        }
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[global_allocator]
static GLOBAL_ALLOCATOR: BumpAllocator = BumpAllocator;

#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    log("[dhcpd] OOM\n");
    call::exit(12)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    log("[dhcpd] PANIC: ");
    let msg = info.message();
    let mut buf = [0u8; 256];
    use core::fmt::Write;
    let mut cursor = BufWriter {
        buf: &mut buf,
        pos: 0,
    };
    let _ = write!(cursor, "{}", msg);
    let written = cursor.pos;
    if written > 0 {
        if let Ok(s) = core::str::from_utf8(&buf[..written]) {
            log(s);
        }
    }
    log("\n");
    call::exit(255)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn log(msg: &str) {
    let _ = call::write(1, msg.as_bytes());
}

struct BufWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}
impl core::fmt::Write for BufWriter<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let avail = self.buf.len().saturating_sub(self.pos);
        let n = bytes.len().min(avail);
        self.buf[self.pos..self.pos + n].copy_from_slice(&bytes[..n]);
        self.pos += n;
        Ok(())
    }
}

/// Read a scheme file and return how many bytes were read into `buf`.
fn scheme_read(path: &str, buf: &mut [u8]) -> Result<usize, ()> {
    let fd = call::openat(0, path, 0x1, 0).map_err(|_| ())?; // O_READ
    let n = call::read(fd as usize, buf).map_err(|_| {
        let _ = call::close(fd as usize);
    })?;
    let _ = call::close(fd as usize);
    Ok(n)
}

fn sleep_ms(ms: u64) {
    let req = TimeSpec {
        tv_sec: (ms / 1000) as i64,
        tv_nsec: ((ms % 1000) * 1_000_000) as i64,
    };
    let _ = unsafe {
        strat9_syscall::syscall2(number::SYS_NANOSLEEP, &req as *const TimeSpec as usize, 0)
    };
}

fn is_unconfigured(data: &[u8]) -> bool {
    // "169.254.9.9" means DHCP failed successfully
    data.starts_with(b"169.254.9.9")
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

const MAX_RETRIES: usize = 60; // 60 x 500ms = 30 seconds timeout
const POLL_INTERVAL_MS: u64 = 500;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    log("[dhcpd] Waiting for DHCP configuration via /net scheme...\n");

    let mut ip_buf = [0u8; 64];
    let mut gw_buf = [0u8; 64];
    let mut route_buf = [0u8; 64];
    let mut dns_buf = [0u8; 96];
    let mut retries = 0;

    loop {
        // Try to read the IP address from the network strate
        let ip_n = match scheme_read("/net/ip", &mut ip_buf) {
            Ok(n) => n,
            Err(_) => {
                if retries == 0 {
                    log("[dhcpd] /net not available yet, retrying...\n");
                }
                retries += 1;
                if retries >= MAX_RETRIES {
                    log("[dhcpd] Timeout waiting for /net scheme\n");
                    call::exit(1);
                }
                sleep_ms(POLL_INTERVAL_MS);
                continue;
            }
        };

        if ip_n == 0 || is_unconfigured(&ip_buf[..ip_n]) {
            retries += 1;
            if retries >= MAX_RETRIES {
                log("[dhcpd] Timeout: DHCP did not complete within 30s\n");
                call::exit(1);
            }
            sleep_ms(POLL_INTERVAL_MS);
            continue;
        }

        // We have a valid IP - read the rest
        let gw_n = scheme_read("/net/gateway", &mut gw_buf).unwrap_or(0);
        let route_n = scheme_read("/net/route", &mut route_buf).unwrap_or(0);
        let dns_n = scheme_read("/net/dns", &mut dns_buf).unwrap_or(0);

        // Report
        log("[dhcpd] DHCP configuration acquired:\n");
        log("  IP      : ");
        if let Ok(s) = core::str::from_utf8(&ip_buf[..ip_n]) {
            log(s.trim());
        }
        log("\n  Gateway : ");
        if gw_n > 0 {
            if let Ok(s) = core::str::from_utf8(&gw_buf[..gw_n]) {
                log(s.trim());
            }
        } else {
            log("(none)");
        }
        log("\n  Route   : ");
        if route_n > 0 {
            if let Ok(s) = core::str::from_utf8(&route_buf[..route_n]) {
                log(s.trim());
            }
        } else {
            log("(none)");
        }
        log("\n  DNS     : ");
        if dns_n > 0 {
            if let Ok(s) = core::str::from_utf8(&dns_buf[..dns_n]) {
                log(s.trim());
            }
        } else {
            log("(none)");
        }
        log("\n");

        break;
    }

    log("[dhcpd] Done.\n");
    call::exit(0)
}
