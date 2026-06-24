#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use core::{alloc::Layout, fmt::Write, panic::PanicInfo};
use strat9_syscall::{call, data::TimeSpec, number};

alloc_freelist::define_freelist_allocator!(pub struct BumpAllocator; heap_size = 128 * 1024;);

#[global_allocator]
static GLOBAL_ALLOCATOR: BumpAllocator = BumpAllocator;

#[alloc_error_handler]
/// Implements alloc error.
fn alloc_error(_layout: Layout) -> ! {
    log("[telnetd] OOM\n");
    call::exit(12)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    call::handle_panic("telnetd", info)
}

/// Implements log.
fn log(msg: &str) {
    let _ = call::debug_log(msg.as_bytes());
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

/// Writes all. Returns false on broken pipe or after 500 retries on EAGAIN.
fn write_all(fd: usize, data: &[u8]) -> bool {
    let mut off = 0usize;
    let mut retries = 0u32;
    while off < data.len() {
        match call::write(fd, &data[off..]) {
            Ok(0) => return false,
            Ok(n) => {
                off += n;
                retries = 0;
            }
            Err(e) => {
                if e.to_errno() == 11 {
                    retries += 1;
                    if retries > 500 {
                        return false;
                    }
                    sleep_ms(10);
                    continue;
                }
                return false;
            }
        }
    }
    true
}

/// Reads text file.
fn read_text_file(path: &str, out: &mut [u8]) -> usize {
    let fd = match call::openat(0, path, 0x0, 0) {
        Ok(fd) => fd as usize,
        Err(_) => return 0,
    };
    let n = call::read(fd, out).unwrap_or(0);
    let _ = call::close(fd);
    n
}

/// Opens listener. Returns 0 on failure after 100 retries.
fn open_listener() -> usize {
    let mut retries = 0u32;
    loop {
        match call::openat(0, "/net/tcp/listen/23", 0x2, 0) {
            Ok(fd) => return fd as usize,
            Err(_) => {
                retries += 1;
                if retries > 100 {
                    log("[telnetd] FATAL: cannot open listener after 100 retries\n");
                    return 0;
                }
                sleep_ms(200);
            }
        }
    }
}

enum LineAction {
    Continue,
    Disconnect,
}

#[derive(Clone, Copy, PartialEq)]
enum IacState {
    Normal,
    SkipOption,
    SubNeg,
}

struct TelnetSession {
    connected: bool,
    line: [u8; 256],
    line_len: usize,
    iac_state: IacState,
}

impl TelnetSession {
    const fn new() -> Self {
        Self {
            connected: false,
            line: [0u8; 256],
            line_len: 0,
            iac_state: IacState::Normal,
        }
    }

    fn reset(&mut self) {
        self.connected = false;
        self.line_len = 0;
        self.iac_state = IacState::Normal;
    }
}

/// Implements send prompt.
fn send_prompt(fd: usize) {
    let _ = write_all(fd, b"\r\nstrat9> ");
}

/// Implements handle command.
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
            let _ = write_all(fd, b"\r\n");
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
        if nip > 0 {
            let _ = write_all(fd, &ip[..nip]);
            let _ = write_all(fd, b"\r\n");
        } else {
            let _ = write_all(fd, b"n/a\r\n");
        }
        let _ = write_all(fd, b"GW: ");
        if ngw > 0 {
            let _ = write_all(fd, &gw[..ngw]);
            let _ = write_all(fd, b"\r\n");
        } else {
            let _ = write_all(fd, b"n/a\r\n");
        }
        let _ = write_all(fd, b"DNS: ");
        if ndns > 0 {
            let _ = write_all(fd, &dns[..ndns]);
            let _ = write_all(fd, b"\r\n");
        } else {
            let _ = write_all(fd, b"n/a\r\n");
        }
        let _ = write_all(fd, b"ROUTE: ");
        if nr > 0 {
            let _ = write_all(fd, &route[..nr]);
            let _ = write_all(fd, b"\r\n");
        } else {
            let _ = write_all(fd, b"n/a\r\n");
        }
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

/// Implements handle bytes.
fn handle_bytes(fd: usize, session: &mut TelnetSession, bytes: &[u8]) -> LineAction {
    for &b in bytes {
        match session.iac_state {
            IacState::SkipOption => {
                session.iac_state = IacState::Normal;
                continue;
            }
            IacState::SubNeg => {
                if b == 240 {
                    session.iac_state = IacState::Normal;
                }
                continue;
            }
            IacState::Normal => {}
        }

        if b == 255 {
            session.iac_state = IacState::SkipOption;
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
/// Implements start.
pub extern "C" fn _start() -> ! {
    log("[telnetd] Starting telnet server on /net/tcp/listen/23\n");
    let mut fd = open_listener();
    if fd == 0 {
        log("[telnetd] Cannot open listener, exiting\n");
        call::exit(1);
    }
    let mut session = TelnetSession::new();
    let mut buf = [0u8; 512];
    let mut idle_ticks: u64 = 0;

    loop {
        match call::read(fd, &mut buf) {
            Ok(0) => {
                if session.connected {
                    log("[telnetd] client disconnected\n");
                    let _ = call::close(fd);
                    session.reset();
                    fd = open_listener();
                    if fd == 0 {
                        call::exit(1);
                    }
                    idle_ticks = 0;
                } else {
                    sleep_ms(20);
                    idle_ticks += 1;
                    if idle_ticks > 750 {
                        log("[telnetd] idle timeout on listener, reopening\n");
                        let _ = call::close(fd);
                        fd = open_listener();
                        if fd == 0 {
                            call::exit(1);
                        }
                        idle_ticks = 0;
                    }
                }
            }
            Ok(n) => {
                idle_ticks = 0;
                if !session.connected {
                    session.connected = true;
                    log("[telnetd] client connected\n");
                    let _ =
                        write_all(fd, b"\r\nStrat9 Telnet\r\nType 'help' for commands.\r\n");
                    send_prompt(fd);
                }
                if matches!(
                    handle_bytes(fd, &mut session, &buf[..n]),
                    LineAction::Disconnect
                ) {
                    log("[telnetd] client quit\n");
                    let _ = call::close(fd);
                    session.reset();
                    fd = open_listener();
                    if fd == 0 {
                        call::exit(1);
                    }
                    idle_ticks = 0;
                }
            }
            Err(e) => {
                if e.to_errno() == 11 {
                    sleep_ms(10);
                    idle_ticks += 1;
                    if session.connected && idle_ticks > 1500 {
                        log("[telnetd] client idle timeout, disconnecting\n");
                        let _ = call::close(fd);
                        session.reset();
                        fd = open_listener();
                        if fd == 0 {
                            call::exit(1);
                        }
                        idle_ticks = 0;
                    }
                    continue;
                }
                log("[telnetd] read error, reconnecting\n");
                let _ = call::close(fd);
                session.reset();
                sleep_ms(100);
                fd = open_listener();
                if fd == 0 {
                    call::exit(1);
                }
                idle_ticks = 0;
            }
        }
    }
}
