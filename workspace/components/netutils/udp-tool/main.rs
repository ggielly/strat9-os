//! udp-tool – UDP scheme probe utility for strat9-os
//!
//! This binary exercises the `/net/udp/*` scheme API exposed by `strate-net`.
//! It binds a local UDP endpoint, sends periodic probes, prints incoming
//! datagrams, and echoes received payloads back to their source.
//!
//! Usage: currently no argv wiring; defaults are used.

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use core::{alloc::Layout, fmt::Write, panic::PanicInfo};
use strat9_syscall::{call, data::TimeSpec, number};

alloc_freelist::define_freelist_allocator!(pub struct BumpAllocator; heap_size = 96 * 1024;);

#[global_allocator]
static GLOBAL_ALLOCATOR: BumpAllocator = BumpAllocator;

#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    log("[udp-tool] OOM\n");
    call::exit(12)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    log("[udp-tool] PANIC: ");
    let mut buf = [0u8; 256];
    let n = {
        let mut w = BufWriter {
            buf: &mut buf,
            pos: 0,
        };
        let _ = write!(w, "{}", info.message());
        w.pos
    };
    if let Ok(s) = core::str::from_utf8(&buf[..n]) {
        log(s);
    }
    log("\n");
    call::exit(255)
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

fn log(msg: &str) {
    let _ = call::write(1, msg.as_bytes());
}

fn debug(msg: &str) {
    let _ = call::debug_log(msg.as_bytes());
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

fn clock_ns() -> u64 {
    unsafe { strat9_syscall::syscall0(number::SYS_CLOCK_GETTIME) }
        .map(|v| v as u64)
        .unwrap_or(0)
}

fn open_rw(path: &str) -> Result<usize, i32> {
    call::openat(0, path, 0x2, 0)
        .map(|fd| fd as usize)
        .map_err(|e| e.to_errno() as i32)
}

fn read_text(path: &str, out: &mut [u8]) -> usize {
    let Ok(fd) = call::openat(0, path, 0x0, 0) else {
        return 0;
    };
    let n = call::read(fd as usize, out).unwrap_or(0);
    let _ = call::close(fd as usize);
    n
}

fn parse_ipv4_literal(s: &str) -> Option<[u8; 4]> {
    let mut octets = [0u8; 4];
    let mut idx = 0usize;
    let mut val: u16 = 0;
    let mut has_digit = false;

    for &b in s.as_bytes() {
        if b == b'.' {
            if !has_digit || idx >= 3 || val > 255 {
                return None;
            }
            octets[idx] = val as u8;
            idx += 1;
            val = 0;
            has_digit = false;
            continue;
        }
        if !b.is_ascii_digit() {
            return None;
        }
        val = val * 10 + (b - b'0') as u16;
        has_digit = true;
    }

    if !has_digit || idx != 3 || val > 255 {
        return None;
    }

    octets[3] = val as u8;
    Some(octets)
}

fn parse_first_ipv4_line(path: &str, buf: &mut [u8; 128]) -> Option<[u8; 4]> {
    let n = read_text(path, buf);
    if n == 0 {
        return None;
    }
    let line_end = buf[..n].iter().position(|&b| b == b'\n').unwrap_or(n);
    let mut s = core::str::from_utf8(&buf[..line_end]).ok()?.trim();
    if let Some((head, _tail)) = s.split_once('/') {
        s = head;
    }
    parse_ipv4_literal(s)
}

fn ip_to_path<'a>(dst: &[u8; 4], port: u16, out: &'a mut [u8; 96]) -> &'a str {
    let n = {
        let mut w = BufWriter { buf: out, pos: 0 };
        let _ = write!(
            w,
            "/net/udp/send/{}.{}.{}.{}/{}",
            dst[0], dst[1], dst[2], dst[3], port
        );
        w.pos
    };
    core::str::from_utf8(&out[..n]).unwrap_or("/net/udp/send/0.0.0.0/0")
}

fn format_src<'a>(src: &[u8; 4], port: u16, out: &'a mut [u8; 64]) -> &'a str {
    let n = {
        let mut w = BufWriter { buf: out, pos: 0 };
        let _ = write!(w, "{}.{}.{}.{}:{}", src[0], src[1], src[2], src[3], port);
        w.pos
    };
    core::str::from_utf8(&out[..n]).unwrap_or("0.0.0.0:0")
}

fn dump_payload_ascii<'a>(data: &[u8], out: &'a mut [u8; 96]) -> &'a str {
    let n = data.len().min(out.len());
    for (i, &b) in data.iter().take(n).enumerate() {
        out[i] = if (0x20..=0x7e).contains(&b) { b } else { b'.' };
    }
    core::str::from_utf8(&out[..n]).unwrap_or("")
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    const PORT: u16 = 9999;
    const HEARTBEAT_MS: u64 = 2000;

    log("[udp-tool] starting\n");

    let mut path_buf = [0u8; 96];
    let bind_path = {
        let n = {
            let mut w = BufWriter {
                buf: &mut path_buf,
                pos: 0,
            };
            let _ = write!(w, "/net/udp/bind/{}", PORT);
            w.pos
        };
        core::str::from_utf8(&path_buf[..n]).unwrap_or("/net/udp/bind/9999")
    };

    let bind_fd = loop {
        match open_rw(bind_path) {
            Ok(fd) => break fd,
            Err(_) => {
                debug("[udp-tool] waiting for /net/udp bind\n");
                sleep_ms(200);
            }
        }
    };

    let mut ip_buf = [0u8; 128];
    let local_ip = parse_first_ipv4_line("/net/address", &mut ip_buf);
    let gateway_ip = parse_first_ipv4_line("/net/gateway", &mut ip_buf);
    let default_target = local_ip.or(gateway_ip).unwrap_or([127, 0, 0, 1]);

    let send_path = ip_to_path(&default_target, PORT, &mut path_buf);
    let send_fd = open_rw(send_path).ok();

    log("[udp-tool] bound on /net/udp/bind/9999\n");
    log("[udp-tool] target path: ");
    log(send_path);
    log("\n");

    if let Some(fd) = send_fd {
        let _ = call::write(fd, b"udp-tool: hello\n");
    }

    let mut last_heartbeat = clock_ns();
    let mut rx_buf = [0u8; 512];
    let mut src_txt = [0u8; 64];
    let mut ascii = [0u8; 96];

    loop {
        match call::read(bind_fd, &mut rx_buf) {
            Ok(n) if n >= 6 => {
                let src = [rx_buf[0], rx_buf[1], rx_buf[2], rx_buf[3]];
                let src_port = u16::from_be_bytes([rx_buf[4], rx_buf[5]]);
                let payload = &rx_buf[6..n];

                log("[udp-tool] rx from ");
                log(format_src(&src, src_port, &mut src_txt));
                log(" | ");
                log(dump_payload_ascii(payload, &mut ascii));
                log("\n");

                // Echo payload to sender via scheme path.
                let reply_path = ip_to_path(&src, src_port, &mut path_buf);
                if let Ok(fd) = open_rw(reply_path) {
                    let _ = call::write(fd, payload);
                    let _ = call::close(fd);
                }
            }
            Ok(_) => {
                // Ignore short frame.
            }
            Err(e) => {
                if e.to_errno() != 11 {
                    log("[udp-tool] read error\n");
                }
            }
        }

        let now = clock_ns();
        if now.saturating_sub(last_heartbeat) >= HEARTBEAT_MS * 1_000_000 {
            if let Some(fd) = send_fd {
                let _ = call::write(fd, b"udp-tool: heartbeat\n");
            }
            last_heartbeat = now;
        }

        sleep_ms(50);
    }
}
