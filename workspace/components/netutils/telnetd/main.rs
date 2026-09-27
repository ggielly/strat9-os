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
const EADDRINUSE: usize = 98;
const TELNET_PORT_PATH: &str = "/net/tcp/listen/23";
const LISTENERS_PATH: &str = "/net/tcp/listeners";
const IP_PATH: &str = "/net/ip";

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
        retries += 1;
        if retries % 25 == 0 {
            log("[telnetd] still waiting for DHCP/static IPv4...\n");
        }
        sleep_ms(200);
    }
}

fn listener_established() -> bool {
    let mut buf = [0u8; 512];
    let n = read_text_file(LISTENERS_PATH, &mut buf);
    if n == 0 {
        return false;
    }
    let s = core::str::from_utf8(&buf[..n]).unwrap_or("");
    for line in s.lines() {
        let has_port = line.contains("port=23");
        let has_est = line.contains("state=ESTABLISHED");
        if has_port && has_est {
            return true;
        }
    }
    false
}

fn open_listener() -> Option<usize> {
    let mut retries = 0u32;
    loop {
        match call::openat(
            0,
            TELNET_PORT_PATH,
            flag::OpenFlags::RDWR.bits() as usize,
            0,
        ) {
            Ok(fd) => return Some(fd),
            Err(e) => {
                let err = e.to_errno();
                if err == EADDRINUSE {
                    log("[telnetd] port 23 busy, retrying\n");
                } else if retries == 0 {
                    log("[telnetd] /net/tcp/listen not ready yet\n");
                }
                retries += 1;
                if retries > 200 {
                    log("[telnetd] FATAL: cannot open /net/tcp/listen/23\n");
                    return None;
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

fn reopen_listener(session: &mut TelnetSession) -> Option<usize> {
    if let Some(fd) = open_listener() {
        session.reset();
        return Some(fd);
    }
    None
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    log("[telnetd] Starting on /net/tcp/listen/23\n");
    wait_for_network();
    let mut fd = match open_listener() {
        Some(fd) => fd,
        None => {
            log("[telnetd] Cannot open listener, exiting\n");
            call::exit(1);
        }
    };
    let mut session = TelnetSession::new();
    let mut buf = [0u8; 512];
    let mut idle_ticks: u64 = 0;
    let mut announced = false;

    loop {
        if !session.connected && listener_established() {
            session.connected = true;
            announced = false;
            idle_ticks = 0;
            log("[telnetd] client connected\n");
        }

        if session.connected && !announced {
            send_banner(fd);
            announced = true;
        }

        match call::read(fd, &mut buf) {
            Ok(0) => {
                if session.connected {
                    log("[telnetd] client disconnected\n");
                    let _ = call::close(fd);
                    fd = match reopen_listener(&mut session) {
                        Some(fd) => fd,
                        None => {
                            call::exit(1);
                        }
                    };
                    announced = false;
                    idle_ticks = 0;
                } else {
                    sleep_ms(20);
                    idle_ticks += 1;
                    if idle_ticks > 750 {
                        log("[telnetd] idle timeout on listener, reopening\n");
                        let _ = call::close(fd);
                        fd = match reopen_listener(&mut session) {
                            Some(fd) => fd,
                            None => {
                                call::exit(1);
                            }
                        };
                        announced = false;
                        idle_ticks = 0;
                    }
                }
            }
            Ok(n) => {
                idle_ticks = 0;
                if !session.connected && listener_established() {
                    session.connected = true;
                    announced = false;
                    log("[telnetd] client connected\n");
                    if !announced {
                        send_banner(fd);
                        announced = true;
                    }
                }
                if matches!(
                    handle_bytes(fd, &mut session, &buf[..n]),
                    LineAction::Disconnect
                ) {
                    log("[telnetd] client quit\n");
                    let _ = call::close(fd);
                    fd = match reopen_listener(&mut session) {
                        Some(fd) => fd,
                        None => {
                            call::exit(1);
                        }
                    };
                    announced = false;
                    idle_ticks = 0;
                }
            }
            Err(e) => {
                let err = e.to_errno();
                if err == EAGAIN {
                    if session.connected && !listener_established() {
                        log("[telnetd] peer closed, reconnecting\n");
                        let _ = call::close(fd);
                        fd = match reopen_listener(&mut session) {
                            Some(fd) => fd,
                            None => {
                                call::exit(1);
                            }
                        };
                        announced = false;
                        idle_ticks = 0;
                        continue;
                    }
                    sleep_ms(10);
                    idle_ticks += 1;
                    if session.connected && idle_ticks > 1500 {
                        log("[telnetd] client idle timeout, disconnecting\n");
                        let _ = call::close(fd);
                        fd = match reopen_listener(&mut session) {
                            Some(fd) => fd,
                            None => {
                                call::exit(1);
                            }
                        };
                        announced = false;
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
                fd = match open_listener() {
                    Some(fd) => fd,
                    None => {
                        call::exit(1);
                    }
                };
                announced = false;
                idle_ticks = 0;
            }
        }
    }
}
