//! dhcp-client – DHCP status monitor for strat9-os
//!
//! This is **not** a full DHCP client.  The actual DHCP exchange is performed
//! by the `strate-net` silo (via smoltcp's DHCPv4 socket).  `dhcp-client` simply
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
};
use strat9_syscall::{call, data::TimeSpec, number};

// ---------------------------------------------------------------------------
// Minimal bump allocator (same pattern as other strat9 silos)
// ---------------------------------------------------------------------------

alloc_freelist::define_freelist_allocator!(pub struct BumpAllocator; heap_size = 64 * 1024;);

#[global_allocator]
static GLOBAL_ALLOCATOR: BumpAllocator = BumpAllocator;

#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    log("[dhcp-client] OOM\n");
    call::exit(12)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    log("[dhcp-client] PANIC: ");
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
    data.starts_with(b"0.0.0.0") || data.starts_with(b"169.254.")
}

fn cidr_to_netmask(prefix_str: &str) -> Option<[u8; 20]> {
    let mut out = [0u8; 20];
    let s = prefix_str.trim();
    if s.is_empty() {
        return None;
    }

    let mut prefix: u16 = 0;
    for &b in s.as_bytes() {
        if b < b'0' || b > b'9' {
            return None;
        }
        prefix = prefix
            .checked_mul(10)?
            .checked_add((b - b'0') as u16)?;
    }
    if prefix > 32 {
        return None;
    }

    let prefix = prefix as u8;
    let mask: u32 = if prefix == 32 {
        0xFFFF_FFFF
    } else if prefix == 0 {
        0
    } else {
        !((1u32 << (32 - prefix)) - 1)
    };
    let o = mask.to_be_bytes();
    use core::fmt::Write;
    let mut w = BufWriter {
        buf: &mut out,
        pos: 0,
    };
    let _ = write!(w, "{}.{}.{}.{}", o[0], o[1], o[2], o[3]);
    Some(out)
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

const BOOT_RETRIES: usize = 10;
const POLL_INTERVAL_MS: u64 = 500;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    log("[dhcp-client] Waiting for DHCP configuration via /net scheme...\n");

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
                    log("[dhcp-client] /net not available yet, retrying...\n");
                }
                retries += 1;
                if retries >= BOOT_RETRIES {
                    log("[dhcp-client] /net not ready yet; continuing boot without DHCP\n");
                    call::exit(0);
                }
                sleep_ms(POLL_INTERVAL_MS);
                continue;
            }
        };

        if ip_n == 0 || is_unconfigured(&ip_buf[..ip_n]) {
            retries += 1;
            if retries >= BOOT_RETRIES {
                log("[dhcp-client] DHCP not ready during boot window; leaving background probe\n");
                call::exit(0);
            }
            sleep_ms(POLL_INTERVAL_MS);
            continue;
        }

        let gw_n = scheme_read("/net/gateway", &mut gw_buf).unwrap_or(0);
        let route_n = scheme_read("/net/route", &mut route_buf).unwrap_or(0);
        let dns_n = scheme_read("/net/dns", &mut dns_buf).unwrap_or(0);

        let ip_str = core::str::from_utf8(&ip_buf[..ip_n]).unwrap_or("").trim();

        // Split "a.b.c.d/prefix" into address and netmask
        let (addr, netmask) = if let Some(slash) = ip_str.find('/') {
            let prefix_str = &ip_str[slash + 1..];
            let mask = cidr_to_netmask(prefix_str).unwrap_or([0u8; 20]);
            (&ip_str[..slash], mask)
        } else {
            (ip_str, [0u8; 20])
        };

        log("\n");
        log("============================================================\n");
        log("  Network configuration (DHCP)\n");
        log("------------------------------------------------------------\n");
        log("  Address : ");
        log(addr);
        log("\n  Netmask : ");
        if let Ok(s) = core::str::from_utf8(&netmask) {
            let s = s.trim_end_matches('\0');
            if !s.is_empty() { log(s); } else { log("(none)"); }
        }
        log("\n  Gateway : ");
        if gw_n > 0 {
            if let Ok(s) = core::str::from_utf8(&gw_buf[..gw_n]) { log(s.trim()); }
        } else {
            log("(none)");
        }
        log("\n  Route   : ");
        if route_n > 0 {
            if let Ok(s) = core::str::from_utf8(&route_buf[..route_n]) { log(s.trim()); }
        } else {
            log("(none)");
        }
        log("\n  DNS     : ");
        if dns_n > 0 {
            if let Ok(s) = core::str::from_utf8(&dns_buf[..dns_n]) { log(s.trim()); }
        } else {
            log("(none)");
        }
        log("\n");
        log("============================================================\n");

        break;
    }

    log("[dhcp-client] Done.\n");
    call::exit(0)
}
