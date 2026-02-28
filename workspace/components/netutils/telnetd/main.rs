#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use core::{
    alloc::Layout,
    fmt::Write,
    panic::PanicInfo,
};
use strat9_syscall::{call, data::TimeSpec, number};

alloc_freelist::define_freelist_allocator!(pub struct BumpAllocator; heap_size = 128 * 1024;);

#[global_allocator]
static GLOBAL_ALLOCATOR: BumpAllocator = BumpAllocator;

#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    log("[telnetd] OOM\n");
    call::exit(12)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    log("[telnetd] PANiK: ");
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

fn sleep_ms(ms: u64) {
    let req = TimeSpec {
        tv_sec: (ms / 1000) as i64,
        tv_nsec: ((ms % 1000) * 1_000_000) as i64,
    };
    let _ = unsafe {
        strat9_syscall::syscall2(number::SYS_NANOSLEEP, &req as *const TimeSpec as usize, 0)
    };
}

fn write_all(fd: usize, data: &[u8]) -> bool {
    let mut off = 0usize;
    while off < data.len() {
        match call::write(fd, &data[off..]) {
            Ok(0) => return false,
            Ok(n) => off += n,
            Err(e) => {
                if e.to_errno() == 11 {
                    sleep_ms(10);
                    continue;
                }
                return false;
            }
        }
    }
    true
}

fn read_text_file(path: &str, out: &mut [u8]) -> usize {
    let fd = match call::openat(0, path, 0x0, 0) {
        Ok(fd) => fd as usize,
        Err(_) => return 0,
    };
    let n = call::read(fd, out).unwrap_or(0);
    let _ = call::close(fd);
    n
}

fn open_listener() -> usize {
    loop {
        match call::openat(0, "/net/tcp/listen/23", 0x2, 0) {
            Ok(fd) => return fd as usize,
            Err(_) => sleep_ms(200),
        }
    }
}

enum LineAction {
    Continue,
    Disconnect,
}

struct TelnetSession {
    connected: bool,
    line: [u8; 256],
    line_len: usize,
    iac_skip: u8,
}

impl TelnetSession {
    const fn new() -> Self {
        Self {
            connected: false,
            line: [0u8; 256],
            line_len: 0,
            iac_skip: 0,
        }
    }

    fn reset(&mut self) {
        self.connected = false;
        self.line_len = 0;
        self.iac_skip = 0;
    }
}

fn send_prompt(fd: usize) {
    let _ = write_all(fd, b"\r\nstrat9> ");
}

fn handle_command(fd: usize, line: &str) -> LineAction {
    let cmd = line.trim();
    if cmd.is_empty() {
        send_prompt(fd);
        return LineAction::Continue;
    }

    if cmd == "help" {
        let _ = write_all(
            fd,
            b"\r\nCommands: help, ip, net, echo <text>, clear, quit\r\n",
        );
        send_prompt(fd);
        return LineAction::Continue;
    }

    if cmd == "ip" {
        let mut buf = [0u8; 128];
        let n = read_text_file("/net/address", &mut buf);
        let _ = write_all(fd, b"\r\nIP: ");
        if n > 0 {
            let _ = write_all(fd, &buf[..n]);
        } else {
            let _ = write_all(fd, b"n/a\r\n");
        }
        send_prompt(fd);
        return LineAction::Continue;
    }

    if cmd == "net" {
        let mut ip = [0u8; 128];
        let mut gw = [0u8; 128];
        let mut dns = [0u8; 128];
        let mut route = [0u8; 128];
        let nip = read_text_file("/net/ip", &mut ip);
        let ngw = read_text_file("/net/gateway", &mut gw);
        let ndns = read_text_file("/net/dns", &mut dns);
        let nr = read_text_file("/net/route", &mut route);

        let _ = write_all(fd, b"\r\nIP: ");
        let _ = write_all(fd, if nip > 0 { &ip[..nip] } else { b"n/a\r\n" });
        let _ = write_all(fd, b"GW: ");
        let _ = write_all(fd, if ngw > 0 { &gw[..ngw] } else { b"n/a\r\n" });
        let _ = write_all(fd, b"DNS: ");
        let _ = write_all(fd, if ndns > 0 { &dns[..ndns] } else { b"n/a\r\n" });
        let _ = write_all(fd, b"ROUTE: ");
        let _ = write_all(fd, if nr > 0 { &route[..nr] } else { b"n/a\r\n" });
        send_prompt(fd);
        return LineAction::Continue;
    }

    if let Some(rest) = cmd.strip_prefix("echo ") {
        let _ = write_all(fd, b"\r\n");
        let _ = write_all(fd, rest.as_bytes());
        let _ = write_all(fd, b"\r\n");
        send_prompt(fd);
        return LineAction::Continue;
    }

    if cmd == "clear" {
        let _ = write_all(fd, b"\x1b[2J\x1b[H");
        send_prompt(fd);
        return LineAction::Continue;
    }

    if cmd == "quit" || cmd == "exit" {
        let _ = write_all(fd, b"\r\nBye.\r\n");
        return LineAction::Disconnect;
    }

    let _ = write_all(fd, b"\r\nUnknown command. Type 'help'.\r\n");
    send_prompt(fd);
    LineAction::Continue
}

fn handle_bytes(fd: usize, session: &mut TelnetSession, bytes: &[u8]) -> LineAction {
    for &b in bytes {
        if session.iac_skip > 0 {
            session.iac_skip -= 1;
            continue;
        }
        if b == 255 {
            session.iac_skip = 2;
            continue;
        }
        if b == b'\r' {
            continue;
        }
        if b == b'\n' {
            let line = core::str::from_utf8(&session.line[..session.line_len]).unwrap_or("");
            session.line_len = 0;
            let action = handle_command(fd, line);
            if matches!(action, LineAction::Disconnect) {
                return action;
            }
            continue;
        }
        if session.line_len < session.line.len() {
            session.line[session.line_len] = b;
            session.line_len += 1;
        }
    }
    LineAction::Continue
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    log("[telnetd] Starting telnet server on /net/tcp/listen/23\n");
    let mut fd = open_listener();
    let mut session = TelnetSession::new();
    let mut buf = [0u8; 128];

    loop {
        match call::read(fd, &mut buf) {
            Ok(0) => {
                if session.connected {
                    let _ = call::close(fd);
                    session.reset();
                    fd = open_listener();
                } else {
                    sleep_ms(20);
                }
            }
            Ok(n) => {
                if !session.connected {
                    session.connected = true;
                    let _ = write_all(fd, b"\r\nStrat9 Telnet\r\nType 'help' for commands.\r\n");
                    send_prompt(fd);
                }
                if matches!(handle_bytes(fd, &mut session, &buf[..n]), LineAction::Disconnect) {
                    let _ = call::close(fd);
                    session.reset();
                    fd = open_listener();
                }
            }
            Err(e) => {
                if e.to_errno() == 11 {
                    sleep_ms(10);
                    continue;
                }
                let _ = call::close(fd);
                session.reset();
                sleep_ms(100);
                fd = open_listener();
            }
        }
    }
}
