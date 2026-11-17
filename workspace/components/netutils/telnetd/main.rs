/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

//! Strat9 telnet console: a development/test shell reachable on TCP port 23.
//!
//! * `telnet.rs` - telnet protocol (ECHO/SGA/NAWS/TTYPE) and line editor
//! * `shell.rs`  - command interpreter exposing the VFS (ls, cat, cp, ...)
//! * `out.rs`    - buffered output with ANSI / 256-color styling
//! * `sys.rs`    - syscall wrappers and path helpers

extern crate alloc;

mod out;
mod shell;
mod sys;
mod telnet;

use core::{alloc::Layout, panic::PanicInfo};
use out::Out;
use strat9_syscall::{call, flag};
use sys::{log, sleep_ms, EAGAIN, ECONNRESET};
use telnet::Session;

alloc_freelist::define_freelist_allocator!(pub struct BumpAllocator; heap_size = 512 * 1024;);

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

const TELNET_PORT_PATH: &str = "/net/tcp/listen/23";
const IP_PATH: &str = "/net/ip";

/// Client idle timeout: 5 minutes at ~10 ms per poll tick.
const CLIENT_IDLE_TICKS: u64 = 30_000;

fn network_configured() -> bool {
    let mut buf = [0u8; 64];
    let n = sys::read_text_file(IP_PATH, &mut buf);
    if n == 0 {
        return false;
    }
    let s = core::str::from_utf8(&buf[..n]).unwrap_or("").trim();
    if s.is_empty() {
        return false;
    }
    !(s.starts_with("0.0.0.0") || s.starts_with("169.254.") || s == "(unavailable)")
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
        match call::openat(0, TELNET_PORT_PATH, flag::OpenFlags::RDWR.bits() as usize, 0) {
            Ok(fd) => {
                log("[telnetd] listening on :23\n");
                return fd;
            }
            Err(e) => {
                if retries % 25 == 0 {
                    if e.to_errno() == 98 {
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

/// Drop the current connection (closing the listen fid tears the session
/// down with a proper FIN) and start listening again.
fn restart_listener(fd: usize, sess: &mut Session) -> (usize, Out) {
    let _ = call::close(fd);
    sess.reset();
    sleep_ms(50);
    let new_fd = open_listener();
    (new_fd, Out::new(new_fd))
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    log("[telnetd] Starting on /net/tcp/listen/23\n");
    wait_for_network();
    let mut fd = open_listener();
    let mut sess = Session::new();
    let mut out = Out::new(fd);
    let mut buf = [0u8; 512];
    let mut idle_ticks: u64 = 0;

    loop {
        match call::read(fd, &mut buf) {
            Ok(0) => {
                if sess.connected {
                    // EOF for the current session.  The listening fd stays
                    // open: strate-net promotes the next queued connection
                    // (if any) onto the same fid.
                    log("[telnetd] client disconnected\n");
                    sess.reset();
                    out = Out::new(fd);
                    idle_ticks = 0;
                } else {
                    sleep_ms(20);
                }
            }
            Ok(n) => {
                idle_ticks = 0;
                if !sess.connected {
                    // Client spoke first: greet it now.
                    sess.connected = true;
                    out = Out::new(fd);
                    sess.send_negotiation(&mut out);
                    sess.send_banner(&mut out);
                }
                if !sess.feed(&mut out, &buf[..n]) {
                    log("[telnetd] client quit\n");
                    (fd, out) = restart_listener(fd, &mut sess);
                    idle_ticks = 0;
                }
            }
            Err(e) => {
                let err = e.to_errno();
                if err == EAGAIN {
                    if !sess.connected {
                        // Real telnet clients wait for the server to speak:
                        // a write only succeeds once a session was accepted,
                        // so use it to detect new connections and greet them.
                        if telnet::probe_connect(fd) {
                            log("[telnetd] client connected\n");
                            sess.connected = true;
                            out = Out::new(fd);
                            sess.send_banner(&mut out);
                            idle_ticks = 0;
                        } else {
                            sleep_ms(20);
                        }
                        continue;
                    }
                    sleep_ms(10);
                    idle_ticks = idle_ticks.saturating_add(1);
                    // Keepalive: strate-net does not always report a peer FIN,
                    // so poke the client with IAC NOP; a dead peer answers with
                    // RST, which then surfaces as EOF / ECONNRESET on read.
                    if idle_ticks % 300 == 0 {
                        let _ = call::write(fd, &[255, 241]);
                    }
                    if idle_ticks > CLIENT_IDLE_TICKS {
                        log("[telnetd] client idle timeout, disconnecting\n");
                        out.text("\nidle timeout\n");
                        out.flush();
                        (fd, out) = restart_listener(fd, &mut sess);
                        idle_ticks = 0;
                    }
                    continue;
                }
                if err == ECONNRESET {
                    log("[telnetd] connection reset\n");
                } else {
                    log("[telnetd] read error, reconnecting\n");
                }
                (fd, out) = restart_listener(fd, &mut sess);
                idle_ticks = 0;
            }
        }
    }
}
