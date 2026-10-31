#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use core::{alloc::Layout, panic::PanicInfo};
use strat9_syscall::{call, data::TimeSpec, flag, number};

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
    call::handle_panic("telnetd", info)
}

const EAGAIN: usize = 11;
const ECONNRESET: usize = 104;
const TELNET_PORT_PATH: &str = "/net/tcp/listen/23";
const IP_PATH: &str = "/net/ip";

/// Telnet command bytes.
const IAC: u8 = 255;
const WILL: u8 = 251;
const DO: u8 = 253;
const SB: u8 = 250;
const SE: u8 = 240;
/// Telnet options.
const OPT_ECHO: u8 = 1;
const OPT_SGA: u8 = 3;

/// Client idle timeout: 5 minutes at 10 ms per poll tick.
const CLIENT_IDLE_TICKS: u64 = 30_000;

fn log(msg: &str) {
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
                if e.to_errno() == EAGAIN {
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

fn read_text_file(path: &str, out: &mut [u8]) -> usize {
    let fd = match call::openat(
        0,
        path,
        flag::OpenFlags::RDONLY.bits() as usize,
        0,
    ) {
        Ok(fd) => fd,
        Err(_) => return 0,
    };
    let n = call::read(fd, out).unwrap_or(0);
    let _ = call::close(fd);
    n
}

fn network_configured() -> bool {
    let mut buf = [0u8; 64];
    let n = read_text_file(IP_PATH, &mut buf);
    if n == 0 {
        return false;
    }
    let s = core::str::from_utf8(&buf[..n]).unwrap_or("").trim();
    if s.is_empty() {
        return false;
    }
    if s.starts_with("0.0.0.0") || s.starts_with("169.254.") || s == "(unavailable)" {
        return false;
    }
    true
}

fn wait_for_network() {
    log("[telnetd] waiting for /net IP configuration\n");
    let mut retries = 0u32;
    loop {
        if network_configured() {
            log("[telnetd] network ready\n");
            return;
        }
        retries = retries.saturating_add(1);
        if retries % 25 == 0 {
            log("[telnetd] still waiting for DHCP/static IPv4...\n");
        }
        sleep_ms(200);
    }
}

/// Open the permanent listening fd.  Retries forever with backoff: a daemon
/// that keeps retrying is more useful than a daemon that exits.
fn open_listener() -> usize {
    let mut retries = 0u32;
    loop {
        match call::openat(
            0,
            TELNET_PORT_PATH,
            flag::OpenFlags::RDWR.bits() as usize,
            0,
        ) {
            Ok(fd) => {
                log("[telnetd] listening on :23\n");
                return fd;
            }
            Err(e) => {
                let err = e.to_errno();
                if retries % 25 == 0 {
                    if err == 98 {
                        log("[telnetd] port 23 busy, retrying\n");
                    } else {
                        log("[telnetd] /net/tcp/listen not ready yet\n");
                    }
                }
                retries = retries.saturating_add(1);
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
    Iac,
    Opt,
    Sb,
    SbIac,
    AfterCr,
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

    fn push(&mut self, b: u8) {
        if self.line_len < self.line.len() {
            self.line[self.line_len] = b;
            self.line_len += 1;
        }
    }
}

fn send_negotiation(fd: usize) {
    // Character-at-a-time mode, server echoes, suppress client-side echo and
    // suppress go-ahead.
    let _ = write_all(
        fd,
        &[
            IAC, WILL, OPT_ECHO, IAC, WILL, OPT_SGA, IAC, DO, OPT_SGA,
        ],
    );
}

fn send_prompt(fd: usize) {
    let _ = write_all(fd, b"\r\nstrat9> ");
}

fn send_banner(fd: usize) {
    let _ = write_all(fd, b"\r\nStrat9 Telnet\r\nType 'help' for commands.\r\n");
    send_prompt(fd);
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

fn run_line(fd: usize, session: &mut TelnetSession) -> LineAction {
    let line_len = session.line_len;
    session.line_len = 0;
    let line = core::str::from_utf8(&session.line[..line_len]).unwrap_or("");
    handle_command(fd, line)
}

fn handle_bytes(fd: usize, session: &mut TelnetSession, bytes: &[u8]) -> LineAction {
    for &b in bytes {
        match session.iac_state {
            IacState::Iac => {
                session.iac_state = match b {
                    WILL | 252 | DO | 254 => IacState::Opt, // WILL/WONT/DO/DONT + 1 byte
                    SB => IacState::Sb,
                    255 => {
                        // IAC IAC is a literal 0xFF data byte.
                        session.push(255);
                        IacState::Normal
                    }
                    _ => IacState::Normal,
                };
                continue;
            }
            IacState::Opt => {
                session.iac_state = IacState::Normal;
                continue;
            }
            IacState::Sb => {
                if b == 255 {
                    session.iac_state = IacState::SbIac;
                }
                continue;
            }
            IacState::SbIac => {
                session.iac_state = if b == SE {
                    IacState::Normal
                } else {
                    IacState::Sb
                };
                continue;
            }
            IacState::AfterCr => {
                session.iac_state = IacState::Normal;
                if b == b'\n' || b == 0 {
                    // CRLF or CR NUL: the line was already submitted on CR.
                    continue;
                }
                // CR not followed by LF/NUL: fall through and handle `b`.
            }
            IacState::Normal => {}
        }

        match b {
            255 => session.iac_state = IacState::Iac,
            b'\r' => {
                session.iac_state = IacState::AfterCr;
                if matches!(run_line(fd, session), LineAction::Disconnect) {
                    return LineAction::Disconnect;
                }
            }
            b'\n' => {
                if matches!(run_line(fd, session), LineAction::Disconnect) {
                    return LineAction::Disconnect;
                }
            }
            0x08 | 0x7f => {
                if session.line_len > 0 {
                    session.line_len -= 1;
                    let _ = write_all(fd, b"\x08 \x08");
                }
            }
            0x20..=0x7e => {
                if session.line_len < session.line.len() {
                    session.push(b);
                    let _ = write_all(fd, &[b]);
                }
            }
            _ => {}
        }
    }
    LineAction::Continue
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    log("[telnetd] Starting on /net/tcp/listen/23\n");
    wait_for_network();
    let mut fd = open_listener();
    let mut session = TelnetSession::new();
    let mut buf = [0u8; 512];
    let mut idle_ticks: u64 = 0;

    loop {
        match call::read(fd, &mut buf) {
            Ok(0) => {
                if session.connected {
                    // EOF for the current session.  The listening fd itself
                    // stays open: strate-net has already promoted the next
                    // queued connection (if any) onto the same fid.
                    log("[telnetd] client disconnected\n");
                    session.reset();
                    idle_ticks = 0;
                } else {
                    sleep_ms(20);
                    idle_ticks = idle_ticks.saturating_add(1);
                }
            }
            Ok(n) => {
                idle_ticks = 0;
                if !session.connected {
                    session.connected = true;
                    send_negotiation(fd);
                    send_banner(fd);
                }
                if matches!(
                    handle_bytes(fd, &mut session, &buf[..n]),
                    LineAction::Disconnect
                ) {
                    log("[telnetd] client quit\n");
                    // Explicit quit: flush the session with a graceful close,
                    // then create a fresh listener.  open_listener() never
                    // returns "fatal", so the daemon cannot die here.
                    let _ = call::close(fd);
                    session.reset();
                    sleep_ms(100);
                    fd = open_listener();
                    idle_ticks = 0;
                }
            }
            Err(e) => {
                let err = e.to_errno();
                if err == EAGAIN {
                    sleep_ms(10);
                    idle_ticks = idle_ticks.saturating_add(1);
                    if session.connected && idle_ticks > CLIENT_IDLE_TICKS {
                        log("[telnetd] client idle timeout, disconnecting\n");
                        let _ = call::close(fd);
                        session.reset();
                        fd = open_listener();
                        idle_ticks = 0;
                    }
                    continue;
                }
                if err == ECONNRESET {
                    log("[telnetd] connection reset\n");
                } else {
                    log("[telnetd] read error, reconnecting\n");
                }
                let _ = call::close(fd);
                session.reset();
                sleep_ms(100);
                fd = open_listener();
                idle_ticks = 0;
            }
        }
    }
}
