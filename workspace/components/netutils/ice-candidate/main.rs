#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use alloc::format;
use core::{alloc::Layout, fmt::Write, panic::PanicInfo};
use strat9_syscall::{call, data::TimeSpec, number};

/// Default STUN host used when /net/stun-config is absent or unreadable.
const DEFAULT_STUN_HOST: &str = "stun.l.google.com";
/// Default STUN port used when /net/stun-config does not specify one.
const DEFAULT_STUN_PORT: u16 = 19302;

alloc_freelist::define_freelist_allocator!(pub struct BumpAllocator; heap_size = 64 * 1024;);

#[global_allocator]
static GLOBAL_ALLOCATOR: BumpAllocator = BumpAllocator;

#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    let _ = call::write(1, b"[ice-candidate] OOM\n");
    call::exit(12)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    let _ = call::write(1, b"[ice-candidate] PANIC: ");
    let mut buf = [0u8; 192];
    let mut w = BufWriter {
        buf: &mut buf,
        pos: 0,
    };
    let _ = write!(w, "{}", info.message());
    if w.pos > 0 {
        let _ = call::write(1, &buf[..w.pos]);
    }
    let _ = call::write(1, b"\n");
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

fn sleep_ms(ms: u64) {
    let req = TimeSpec {
        tv_sec: (ms / 1000) as i64,
        tv_nsec: ((ms % 1000) * 1_000_000) as i64,
    };
    let _ = unsafe {
        strat9_syscall::syscall2(number::SYS_NANOSLEEP, &req as *const TimeSpec as usize, 0)
    };
}

fn scheme_read(path: &str, buf: &mut [u8]) -> Result<usize, ()> {
    let fd = call::openat(0, path, 0x1, 0).map_err(|_| ())?;
    let n = call::read(fd as usize, buf).map_err(|_| {
        let _ = call::close(fd as usize);
    })?;
    let _ = call::close(fd as usize);
    Ok(n)
}

fn scheme_open(path: &str, flags: usize) -> Result<usize, ()> {
    call::openat(0, path, flags, 0).map_err(|_| ())
}

fn parse_ipv4_literal(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let mut dots = 0usize;
    let mut val: u16 = 0;
    let mut has_digit = false;
    for &b in bytes {
        if b == b'.' {
            if !has_digit || val > 255 || dots >= 3 {
                return false;
            }
            dots += 1;
            val = 0;
            has_digit = false;
            continue;
        }
        if !b.is_ascii_digit() {
            return false;
        }
        val = val * 10 + (b - b'0') as u16;
        has_digit = true;
    }
    has_digit && val <= 255 && dots == 3
}

fn resolve_target<'a>(target: &'a str, resolved_buf: &'a mut [u8; 64]) -> Option<&'a str> {
    if parse_ipv4_literal(target) {
        return Some(target);
    }
    let path = format!("/net/resolve/{}", target);
    let n = scheme_read(&path, resolved_buf).ok()?;
    if n == 0 {
        return None;
    }
    let end = resolved_buf[..n]
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(n);
    if end == 0 {
        return None;
    }
    let resolved = core::str::from_utf8(&resolved_buf[..end]).ok()?;
    if parse_ipv4_literal(resolved) {
        Some(resolved)
    } else {
        None
    }
}

fn parse_u16_decimal(s: &[u8]) -> Option<u16> {
    if s.is_empty() {
        return None;
    }
    let mut v: u32 = 0;
    for &b in s {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v * 10 + (b - b'0') as u32;
        if v > 65535 {
            return None;
        }
    }
    Some(v as u16)
}

/// Read STUN configuration from /net/stun-config.
///
/// Accepted formats (newline-terminated):
///   host          — uses DEFAULT_STUN_PORT
///   host:port     — overrides both host and port
///
/// On any parse or I/O error the defaults are returned unchanged.
fn read_stun_config<'a>(host_buf: &'a mut [u8; 253], port_out: &mut u16) -> &'a str {
    let mut raw = [0u8; 260];
    let n = match scheme_read("/net/stun-config", &mut raw) {
        Ok(n) if n > 0 => n,
        _ => return DEFAULT_STUN_HOST,
    };
    // Trim trailing whitespace / newlines.
    let mut end = n;
    while end > 0 && (raw[end - 1] == b'
' || raw[end - 1] == b'
' || raw[end - 1] == b' ') {
        end -= 1;
    }
    let line = &raw[..end];
    // Find the last ':' to split host from optional port.
    let colon = line.iter().rposition(|&b| b == b':');
    let (host_bytes, port_bytes) = if let Some(pos) = colon {
        (&line[..pos], Some(&line[pos + 1..]))
    } else {
        (line, None)
    };
    if host_bytes.is_empty() || host_bytes.len() > 253 {
        return DEFAULT_STUN_HOST;
    }
    if let Some(pb) = port_bytes {
        if let Some(p) = parse_u16_decimal(pb) {
            *port_out = p;
        } else {
            return DEFAULT_STUN_HOST;
        }
    }
    host_buf[..host_bytes.len()].copy_from_slice(host_bytes);
    match core::str::from_utf8(&host_buf[..host_bytes.len()]) {
        Ok(s) => s,
        Err(_) => DEFAULT_STUN_HOST,
    }
}

fn read_local_ip<'a>(out: &'a mut [u8; 64]) -> Option<&'a str> {
    let n = scheme_read("/net/address", out).ok()?;
    if n == 0 {
        return None;
    }
    let mut end = out[..n].iter().position(|&b| b == b'\n').unwrap_or(n);
    if let Some(slash) = out[..end].iter().position(|&b| b == b'/') {
        end = slash;
    }
    if end == 0 {
        return None;
    }
    let ip = core::str::from_utf8(&out[..end]).ok()?;
    if parse_ipv4_literal(ip) {
        Some(ip)
    } else {
        None
    }
}

fn parse_stun_binding(resp: &[u8], txid: &[u8; 12]) -> Option<([u8; 4], u16)> {
    if resp.len() < 20 {
        return None;
    }
    let msg_type = u16::from_be_bytes([resp[0], resp[1]]);
    if msg_type != 0x0101 {
        return None;
    }
    let msg_len = u16::from_be_bytes([resp[2], resp[3]]) as usize;
    if msg_len + 20 > resp.len() {
        return None;
    }
    if resp[4..8] != [0x21, 0x12, 0xA4, 0x42] {
        return None;
    }
    if resp[8..20] != txid[..] {
        return None;
    }
    let mut off = 20usize;
    let end = 20 + msg_len;
    while off + 4 <= end && off + 4 <= resp.len() {
        let attr_ty = u16::from_be_bytes([resp[off], resp[off + 1]]);
        let attr_len = u16::from_be_bytes([resp[off + 2], resp[off + 3]]) as usize;
        let val_off = off + 4;
        let val_end = val_off + attr_len;
        if val_end > end || val_end > resp.len() {
            return None;
        }
        if attr_ty == 0x0020 && attr_len >= 8 {
            if resp[val_off + 1] != 0x01 {
                return None;
            }
            let xport = u16::from_be_bytes([resp[val_off + 2], resp[val_off + 3]]);
            let port = xport ^ 0x2112;
            let ip = [
                resp[val_off + 4] ^ 0x21,
                resp[val_off + 5] ^ 0x12,
                resp[val_off + 6] ^ 0xA4,
                resp[val_off + 7] ^ 0x42,
            ];
            return Some((ip, port));
        }
        if attr_ty == 0x0001 && attr_len >= 8 {
            if resp[val_off + 1] != 0x01 {
                return None;
            }
            let port = u16::from_be_bytes([resp[val_off + 2], resp[val_off + 3]]);
            let ip = [
                resp[val_off + 4],
                resp[val_off + 5],
                resp[val_off + 6],
                resp[val_off + 7],
            ];
            return Some((ip, port));
        }
        let pad = (4 - (attr_len % 4)) % 4;
        off = val_end + pad;
    }
    None
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let mut stun_port: u16 = DEFAULT_STUN_PORT;
    let mut stun_host_buf = [0u8; 253];
    let stun_host = read_stun_config(&mut stun_host_buf, &mut stun_port);
    let mut resolved = [0u8; 64];
    let Some(stun_ip) = resolve_target(stun_host, &mut resolved) else {
        log("[ice-candidate] resolve failed\n");
        call::exit(1);
    };

    let path = format!("/net/udp/connect/{}/{}", stun_ip, stun_port);
    let mut req = [0u8; 20];
    req[0..2].copy_from_slice(&0x0001u16.to_be_bytes());
    req[2..4].copy_from_slice(&0u16.to_be_bytes());
    req[4..8].copy_from_slice(&0x2112A442u32.to_be_bytes());
    let now = unsafe { strat9_syscall::syscall0(number::SYS_CLOCK_GETTIME) }.unwrap_or(0) as u64;
    let tid = now.to_be_bytes();
    req[8..16].copy_from_slice(&tid);
    req[16..20].copy_from_slice(&[0x53, 0x49, 0x4C, 0x4F]);
    let mut txid = [0u8; 12];
    txid.copy_from_slice(&req[8..20]);

    let fd = match scheme_open(&path, 0x3) {
        Ok(fd) => fd,
        Err(_) => {
            log("[ice-candidate] stun open failed\n");
            call::exit(2);
        }
    };

    if call::write(fd as usize, &req).is_err() {
        log("[ice-candidate] stun send failed\n");
        let _ = call::close(fd as usize);
        call::exit(2);
    }

    let mut resp = [0u8; 128];
    let mut mapped: Option<([u8; 4], u16)> = None;
    let mut tries = 0usize;
    while tries < 50 {
        tries += 1;
        if let Ok(n) = call::read(fd as usize, &mut resp) {
            if n > 0 {
                mapped = parse_stun_binding(&resp[..n], &txid);
                if mapped.is_some() {
                    break;
                }
            }
        }
        sleep_ms(20);
    }

    let mut local_ip_buf = [0u8; 64];
    if let Some(local_ip) = read_local_ip(&mut local_ip_buf) {
        let host = format!("candidate:1 1 UDP 2130706431 {} 9 typ host\r\n", local_ip);
        log(&host);
    }

    if let Some((ip, port)) = mapped {
        let srflx = format!(
            "candidate:2 1 UDP 1694498815 {}.{}.{}.{} {} typ srflx raddr 0.0.0.0 rport 9\r\n",
            ip[0], ip[1], ip[2], ip[3], port
        );
        log(&srflx);
        let _ = call::close(fd as usize);
        call::exit(0);
    }

    log("[ice-candidate] no srflx candidate\n");
    let _ = call::close(fd as usize);
    call::exit(3)
}
