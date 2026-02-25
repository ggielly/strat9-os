//! ping – ICMP echo utility for strat9-os
//!
//! Sends ICMP echo requests by writing to `/net/ping/<target_ip>` and reads
//! replies from the same scheme path.  The actual ICMP socket is driven by
//! the `strate-net` silo via smoltcp; this tool is a thin userspace wrapper.
//!
//! Usage:  ping <ipv4-address> [-c count]
//!
//! All I/O is done through Plan 9–style schemes – no BSD sockets.

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use core::{
    alloc::Layout,
    fmt::Write,
    panic::PanicInfo,
    sync::atomic::{AtomicUsize, Ordering},
};
use strat9_syscall::{call, data::TimeSpec, number};

// ---------------------------------------------------------------------------
// Minimal bump allocator
// ---------------------------------------------------------------------------

struct BumpAllocator;

const HEAP_SIZE: usize = 64 * 1024;
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
    log("[ping] OOM\n");
    call::exit(12)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    log("[ping] PANIC: ");
    let msg = info.message();
    let mut buf = [0u8; 256];
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

fn log_u32(val: u32) {
    let mut buf = [0u8; 12];
    let s = u32_to_str(val, &mut buf);
    log(s);
}

fn u32_to_str(mut val: u32, buf: &mut [u8; 12]) -> &str {
    if val == 0 {
        return "0";
    }
    let mut i = buf.len();
    while val > 0 {
        i -= 1;
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
    }
    unsafe { core::str::from_utf8_unchecked(&buf[i..]) }
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

fn clock_ns() -> u64 {
    unsafe { strat9_syscall::syscall0(number::SYS_CLOCK_GETTIME) }
        .map(|v| v as u64)
        .unwrap_or(0)
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

/// Read a scheme file, return bytes read.
fn scheme_read(path: &str, buf: &mut [u8]) -> Result<usize, ()> {
    let fd = call::openat(0, path, 0x1, 0).map_err(|_| ())?; // O_READ
    let n = call::read(fd as usize, buf).map_err(|_| {
        let _ = call::close(fd as usize);
    })?;
    let _ = call::close(fd as usize);
    Ok(n)
}

/// Write to a scheme file, return bytes written.
fn scheme_write(path: &str, data: &[u8]) -> Result<usize, ()> {
    let fd = call::openat(0, path, 0x2, 0).map_err(|_| ())?; // O_WRITE
    let n = call::write(fd as usize, data).map_err(|_| {
        let _ = call::close(fd as usize);
    })?;
    let _ = call::close(fd as usize);
    Ok(n)
}

// ---------------------------------------------------------------------------
//  Minimal argument parsing (no clap – we are no_std)
// ---------------------------------------------------------------------------

struct PingArgs {
    target: [u8; 64],
    target_len: usize,
    count: u32,
}

fn parse_args() -> PingArgs {
    // In strat9-os, command-line args are not yet available via /proc or argc/argv.
    // For now, we hard-code a sensible default.  When the init passes arguments
    // through a scheme, this can be extended.
    //
    // Target: the gateway (read from /net/gateway), or fallback 10.0.2.2 (QEMU default)
    let mut target = [0u8; 64];
    let target_len;

    let mut gw_buf = [0u8; 64];
    if let Ok(n) = scheme_read("/net/gateway", &mut gw_buf) {
        if n > 0 && !gw_buf.starts_with(b"0.0.0.0") {
            // Trim trailing newline
            let end = gw_buf[..n].iter().position(|&b| b == b'\n').unwrap_or(n);
            target[..end].copy_from_slice(&gw_buf[..end]);
            target_len = end;
        } else {
            let default = b"10.0.2.2";
            target[..default.len()].copy_from_slice(default);
            target_len = default.len();
        }
    } else {
        let default = b"10.0.2.2";
        target[..default.len()].copy_from_slice(default);
        target_len = default.len();
    }

    PingArgs {
        target,
        target_len,
        count: 4,
    }
}

// ---------------------------------------------------------------------------
// Ping implementation
// ---------------------------------------------------------------------------

/// ICMP echo request/reply payload passed through the `/net/ping/<ip>` scheme.
///
/// Write: seq(u16 LE) + timestamp_ns(u64 LE) + padding(40 bytes) = 50 bytes
/// Read:  seq(u16 LE) + rtt_us(u64 LE)                           = 10 bytes
#[repr(C)]
struct PingRequest {
    seq: u16,
    timestamp_ns: u64,
    payload: [u8; 40],
}

#[repr(C)]
struct PingReply {
    seq: u16,
    rtt_us: u64,
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let args = parse_args();
    let target = unsafe { core::str::from_utf8_unchecked(&args.target[..args.target_len]) };

    log("PING ");
    log(target);
    log(" - ");
    log_u32(args.count);
    log(" packets\n");

    // Build the scheme path: /net/ping/<ip>
    let mut path_buf = [0u8; 128];
    let mut pw = BufWriter {
        buf: &mut path_buf,
        pos: 0,
    };
    let _ = write!(pw, "/net/ping/{}", target);
    let path_len = pw.pos;
    let path = unsafe { core::str::from_utf8_unchecked(&path_buf[..path_len]) };

    let mut sent: u32 = 0;
    let mut received: u32 = 0;
    let mut min_rtt_us: u64 = u64::MAX;
    let mut max_rtt_us: u64 = 0;
    let mut total_rtt_us: u64 = 0;

    for seq in 0..args.count {
        // Build the request payload
        let ts = clock_ns();
        let req = PingRequest {
            seq: seq as u16,
            timestamp_ns: ts,
            payload: [0xAA; 40],
        };
        let req_bytes = unsafe {
            core::slice::from_raw_parts(
                &req as *const PingRequest as *const u8,
                core::mem::size_of::<PingRequest>(),
            )
        };

        // Send
        if scheme_write(path, req_bytes).is_err() {
            log("  Request timeout (write failed)\n");
            sent += 1;
            sleep_ms(1000);
            continue;
        }
        sent += 1;

        // Wait a bit then read reply
        sleep_ms(100);
        let mut reply_buf = [0u8; 64];
        match scheme_read(path, &mut reply_buf) {
            Ok(n) if n >= 10 => {
                let rtt_us = u64::from_le_bytes([
                    reply_buf[2],
                    reply_buf[3],
                    reply_buf[4],
                    reply_buf[5],
                    reply_buf[6],
                    reply_buf[7],
                    reply_buf[8],
                    reply_buf[9],
                ]);
                let rtt_ms = rtt_us / 1000;
                let rtt_frac = (rtt_us % 1000) / 100;

                log("  Reply from ");
                log(target);
                log(": seq=");
                log_u32(seq);
                log(" time=");
                log_u32(rtt_ms as u32);
                log(".");
                log_u32(rtt_frac as u32);
                log("ms\n");

                received += 1;
                total_rtt_us += rtt_us;
                if rtt_us < min_rtt_us {
                    min_rtt_us = rtt_us;
                }
                if rtt_us > max_rtt_us {
                    max_rtt_us = rtt_us;
                }
            }
            _ => {
                log("  Request timeout: seq=");
                log_u32(seq);
                log("\n");
            }
        }

        if seq + 1 < args.count {
            sleep_ms(900); // ~1s interval
        }
    }

    // Statistics
    log("\n--- ");
    log(target);
    log(" ping statistics ---\n");
    log_u32(sent);
    log(" packets transmitted, ");
    log_u32(received);
    log(" received");
    if sent > 0 {
        let loss = ((sent - received) * 100) / sent;
        log(", ");
        log_u32(loss);
        log("% packet loss");
    }
    log("\n");

    if received > 0 {
        let avg = total_rtt_us / received as u64;
        log("rtt min/avg/max = ");
        log_u32((min_rtt_us / 1000) as u32);
        log("/");
        log_u32((avg / 1000) as u32);
        log("/");
        log_u32((max_rtt_us / 1000) as u32);
        log(" ms\n");
    }

    call::exit(0)
}
