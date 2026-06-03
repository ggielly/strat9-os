//! ping : ICMP echo utility for strat9-os
//!
//! Sends ICMP echo requests by writing to `/net/ping/<target_ip>` and reads
//! replies from the same scheme path.  The actual ICMP socket is driven by
//! the `strate-net` silo via smoltcp; this tool is a thin userspace wrapper.
//!
//! Usage:  ping [-6] [-c count] [ip|hostname] [count]
//!
//! All I/O is done through Plan 9–style schemes (no BSD sockets).

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use core::{alloc::Layout, fmt::Write, panic::PanicInfo};
use strat9_abi::net::{
    is_ipv4_literal_candidate, is_ipv6_literal_candidate, parse_ipv4_literal, parse_ipv6_literal,
};
use strat9_syscall::{call, data::TimeSpec, number};

// ===========================================================================
// Minimal bump allocator
// ===========================================================================

alloc_freelist::define_freelist_allocator!(pub struct BumpAllocator; heap_size = 64 * 1024;);

#[global_allocator]
static GLOBAL_ALLOCATOR: BumpAllocator = BumpAllocator;

#[alloc_error_handler]
/// Implements alloc error.
fn alloc_error(_layout: Layout) -> ! {
    log("[ping] OOM\n");
    call::exit(12)
}

#[panic_handler]
/// Implements panic.
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

// ===========================================================================
// Helpers
// ===========================================================================

/// Implements log.
fn log(msg: &str) {
    let _ = call::write(1, msg.as_bytes());
}

/// Implements log u32.
fn log_u32(val: u32) {
    let mut buf = [0u8; 12];
    let s = u32_to_str(val, &mut buf);
    log(s);
}

/// Implements u32 to str.
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
    /// Writes str.
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let avail = self.buf.len().saturating_sub(self.pos);
        let n = bytes.len().min(avail);
        self.buf[self.pos..self.pos + n].copy_from_slice(&bytes[..n]);
        self.pos += n;
        Ok(())
    }
}

/// Implements clock ns.
fn clock_ns() -> u64 {
    unsafe { strat9_syscall::syscall0(number::SYS_CLOCK_GETTIME) }
        .map(|v| v as u64)
        .unwrap_or(0)
}

/// Implements sleep ms.
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum AddressFamily {
    Ipv4,
    Ipv6,
}

struct ResolvedTarget<'a> {
    addr: &'a str,
    family: AddressFamily,
}

enum ResolveError {
    InvalidLiteral(AddressFamily),
    ResolveFailed,
    FamilyMismatch {
        requested: AddressFamily,
        actual: AddressFamily,
    },
}

fn family_flag(family: AddressFamily) -> &'static str {
    match family {
        AddressFamily::Ipv4 => "-4",
        AddressFamily::Ipv6 => "-6",
    }
}

fn family_name(family: AddressFamily) -> &'static str {
    match family {
        AddressFamily::Ipv4 => "IPv4",
        AddressFamily::Ipv6 => "IPv6",
    }
}

fn apply_family_constraint(
    requested: Option<AddressFamily>,
    actual: AddressFamily,
) -> Result<(), ResolveError> {
    match requested {
        Some(expected) if expected != actual => Err(ResolveError::FamilyMismatch {
            requested: expected,
            actual,
        }),
        _ => Ok(()),
    }
}

fn resolve_target<'a>(
    target: &'a str,
    requested_family: Option<AddressFamily>,
    resolved_buf: &'a mut [u8; 64],
) -> Result<ResolvedTarget<'a>, ResolveError> {
    if parse_ipv4_literal(target).is_some() {
        apply_family_constraint(requested_family, AddressFamily::Ipv4)?;
        return Ok(ResolvedTarget {
            addr: target,
            family: AddressFamily::Ipv4,
        });
    }
    if parse_ipv6_literal(target).is_some() {
        apply_family_constraint(requested_family, AddressFamily::Ipv6)?;
        return Ok(ResolvedTarget {
            addr: target,
            family: AddressFamily::Ipv6,
        });
    }
    if is_ipv4_literal_candidate(target) {
        return Err(ResolveError::InvalidLiteral(AddressFamily::Ipv4));
    }
    if is_ipv6_literal_candidate(target) {
        return Err(ResolveError::InvalidLiteral(AddressFamily::Ipv6));
    }

    let mut path_buf = [0u8; 128];
    let path_len = {
        let mut pw = BufWriter {
            buf: &mut path_buf,
            pos: 0,
        };
        let _ = write!(pw, "/net/resolve/{}", target);
        pw.pos
    };
    let path =
        core::str::from_utf8(&path_buf[..path_len]).map_err(|_| ResolveError::ResolveFailed)?;
    let n = scheme_read(path, resolved_buf).map_err(|_| ResolveError::ResolveFailed)?;
    if n == 0 {
        return Err(ResolveError::ResolveFailed);
    }
    let end = resolved_buf[..n]
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(n);
    if end == 0 {
        return Err(ResolveError::ResolveFailed);
    }
    let resolved =
        core::str::from_utf8(&resolved_buf[..end]).map_err(|_| ResolveError::ResolveFailed)?;
    if parse_ipv4_literal(resolved).is_some() {
        apply_family_constraint(requested_family, AddressFamily::Ipv4)?;
        Ok(ResolvedTarget {
            addr: resolved,
            family: AddressFamily::Ipv4,
        })
    } else if parse_ipv6_literal(resolved).is_some() {
        apply_family_constraint(requested_family, AddressFamily::Ipv6)?;
        Ok(ResolvedTarget {
            addr: resolved,
            family: AddressFamily::Ipv6,
        })
    } else {
        Err(ResolveError::ResolveFailed)
    }
}

fn print_usage() {
    log("Usage: ping [-6] [-c count] [target] [count]\n");
    log("       ping -h | --help\n");
    log("Options:\n");
    log("  -6           Require IPv6\n");
    log("  -c <count>   Send count requests (default: 4)\n");
    log("  -h, --help   Show this help\n");
}

fn copy_target(dst: &mut [u8; 64], value: &str) -> usize {
    let len = value.len().min(dst.len() - 1);
    dst[..len].copy_from_slice(&value.as_bytes()[..len]);
    len
}

fn read_default_target(family: Option<AddressFamily>, target: &mut [u8; 64]) -> Option<usize> {
    let mut gateway_buf = [0u8; 64];
    let path = if family == Some(AddressFamily::Ipv6) {
        "/net/ip6/gateway"
    } else {
        "/net/gateway"
    };
    let n = scheme_read(path, &mut gateway_buf).ok()?;
    if n == 0 {
        return None;
    }

    let end = gateway_buf[..n]
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(n);
    if end == 0 {
        return None;
    }

    let gateway = &gateway_buf[..end];
    if gateway == b"0.0.0.0" || gateway == b"::" {
        return None;
    }

    let gateway_str = core::str::from_utf8(gateway).ok()?;
    Some(copy_target(target, gateway_str))
}

// ===========================================================================
//  Minimal argument parsing
// ===========================================================================

struct PingArgs {
    target: [u8; 64],
    target_len: usize,
    count: u32,
    family: Option<AddressFamily>,
}

/// Convert a null-terminated C string pointer to a `&'static str`.
///
/// # Safety
/// `ptr` must point to a valid null-terminated byte sequence that remains
/// valid for the lifetime of the process (true for argv pointers on the
/// initial user stack).
unsafe fn cstr_to_str(ptr: *const u8) -> &'static str {
    let mut len = 0usize;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    core::str::from_utf8_unchecked(core::slice::from_raw_parts(ptr, len))
}

/// Parse an ASCII decimal string into a `u32`.
fn str_to_u32(s: &str) -> Option<u32> {
    if s.is_empty() {
        return None;
    }
    let mut val: u32 = 0;
    for &b in s.as_bytes() {
        if !b.is_ascii_digit() {
            return None;
        }
        val = val.checked_mul(10)?.checked_add((b - b'0') as u32)?;
    }
    Some(val)
}

/// Build `PingArgs` from the SysV initial user stack.
///
/// Supported forms:
/// - `ping <target> [count]`
/// - `ping -c <count> [target]`
/// - `ping -6 ...`
/// - `ping -h|--help`
fn parse_args_from_stack(argc: usize, argv: *const *const u8) -> PingArgs {
    let mut target = [0u8; 64];
    let mut target_len = 0usize;
    let mut count = 4u32;
    let mut family: Option<AddressFamily> = None;
    let mut positional_count_set = false;

    let mut i = 1usize;
    while i < argc {
        let arg = unsafe { cstr_to_str(*argv.add(i)) };
        match arg {
            "-h" | "--help" => {
                print_usage();
                call::exit(0);
            }
            "-6" => {
                family = Some(AddressFamily::Ipv6);
            }
            "-c" => {
                i += 1;
                if i >= argc {
                    log("ping: missing value for -c\n");
                    print_usage();
                    call::exit(1);
                }
                let count_arg = unsafe { cstr_to_str(*argv.add(i)) };
                let Some(parsed) = str_to_u32(count_arg) else {
                    log("ping: invalid count: ");
                    log(count_arg);
                    log("\n");
                    call::exit(1);
                };
                count = parsed;
            }
            _ if arg.starts_with('-') => {
                log("ping: unknown option: ");
                log(arg);
                log("\n");
                print_usage();
                call::exit(1);
            }
            _ if target_len == 0 => {
                target_len = copy_target(&mut target, arg);
            }
            _ if !positional_count_set => {
                let Some(parsed) = str_to_u32(arg) else {
                    log("ping: unexpected argument: ");
                    log(arg);
                    log("\n");
                    print_usage();
                    call::exit(1);
                };
                count = parsed;
                positional_count_set = true;
            }
            _ => {
                log("ping: unexpected argument: ");
                log(arg);
                log("\n");
                print_usage();
                call::exit(1);
            }
        }

        i += 1;
    }

    if target_len == 0 {
        target_len = match read_default_target(family, &mut target) {
            Some(len) => len,
            None => {
                log("ping: no target specified and no default gateway configured\n");
                print_usage();
                call::exit(1);
            }
        };
    }

    PingArgs {
        target,
        target_len,
        count,
        family,
    }
}

// ===========================================================================
// Ping implementation
// ===========================================================================

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

/// Entry point: captures the initial RSP (= SysV stack pointer) and calls
/// `start_impl`. Using a naked function guarantees that no prologue has
/// modified RSP before we pass it as `rdi`.
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start() -> ! {
    // At entry via iretq: RSP = boot_sp from the ELF loader.
    // SysV layout: [RSP] = argc, [RSP+8] = argv[0] ptr, ...
    core::arch::naked_asm!(
        "mov rdi, rsp",   // pass initial stack pointer as first arg
        "call {f}",
        "ud2",
        f = sym start_impl,
    );
}

/// Main program logic; called from the naked `_start` trampoline.
///
/// `initial_sp` is the SysV stack pointer captured before any prologue code
/// has run, so `*initial_sp` == argc and `*(initial_sp + 1)` == argv[0].
extern "C" fn start_impl(initial_sp: *const u64) -> ! {
    let argc = unsafe { *initial_sp } as usize;
    let argv = unsafe { initial_sp.add(1) as *const *const u8 };
    let args = parse_args_from_stack(argc, argv);
    let raw_target = unsafe { core::str::from_utf8_unchecked(&args.target[..args.target_len]) };
    let mut resolved_buf = [0u8; 64];
    let target = match resolve_target(raw_target, args.family, &mut resolved_buf) {
        Ok(target) => target,
        Err(ResolveError::InvalidLiteral(family)) => {
            log("ping: invalid ");
            log(family_name(family));
            log(" address: ");
            log(raw_target);
            log("\n");
            call::exit(1);
        }
        Err(ResolveError::ResolveFailed) => {
            log("ping: cannot resolve host: ");
            log(raw_target);
            log("\n");
            call::exit(1);
        }
        Err(ResolveError::FamilyMismatch { requested, actual }) => {
            log("ping: ");
            log(family_flag(requested));
            log(" requires an ");
            log(family_name(requested));
            log(" target, but got ");
            log(family_name(actual));
            log("\n");
            call::exit(1);
        }
    };

    log("PING ");
    log(target.addr);
    log(", sending ");
    log_u32(args.count);
    log(" ICMP now\n");

    // Build the scheme path: /net/ping/<ip> or /net/ping6/<ip>
    let mut path_buf = [0u8; 128];
    let mut pw = BufWriter {
        buf: &mut path_buf,
        pos: 0,
    };
    let scheme_name = match target.family {
        AddressFamily::Ipv4 => "ping",
        AddressFamily::Ipv6 => "ping6",
    };
    let _ = write!(pw, "/net/{}/{}", scheme_name, target.addr);
    let path_len = pw.pos;
    let path = unsafe { core::str::from_utf8_unchecked(&path_buf[..path_len]) };

    const PING_TIMEOUT_MS: u64 = 5_000;
    const POLL_INTERVAL_MS: u64 = 100;

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

        let mut wrote = false;
        let write_deadline_ns = clock_ns().saturating_add(PING_TIMEOUT_MS * 1_000_000);
        while clock_ns() < write_deadline_ns {
            if scheme_write(path, req_bytes).is_ok() {
                wrote = true;
                break;
            }

            let mut drain_buf = [0u8; 64];
            let _ = scheme_read(path, &mut drain_buf);
            sleep_ms(POLL_INTERVAL_MS);
        }

        if !wrote {
            log("  Request timeout (write failed): seq=");
            log_u32(seq);
            log("\n");
            sent += 1;
            continue;
        }
        sent += 1;

        let mut got_reply = false;
        let read_deadline_ns = clock_ns().saturating_add(PING_TIMEOUT_MS * 1_000_000);
        while clock_ns() < read_deadline_ns {
            let mut reply_buf = [0u8; 64];
            match scheme_read(path, &mut reply_buf) {
                Ok(n) if n >= 10 => {
                    let recv_ts = clock_ns();
                    let rtt_ns = recv_ts.saturating_sub(ts);
                    let rtt_us = rtt_ns / 1000;
                    let rtt_ms = rtt_us / 1000;
                    let rtt_frac = (rtt_us % 1000) / 100;

                    log("  Reply from ");
                    log(target.addr);
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
                    got_reply = true;
                    break;
                }
                _ => sleep_ms(POLL_INTERVAL_MS),
            }
        }

        if !got_reply {
            log("  Request timeout: seq=");
            log_u32(seq);
            log("\n");
        }

        if seq + 1 < args.count {
            sleep_ms(900); // ~1s interval
        }
    }

    // Statistics
    log("\n--- ");
    log(target.addr);
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
