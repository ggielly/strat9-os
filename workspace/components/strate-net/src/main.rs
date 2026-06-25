#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

mod config;
mod content;
mod device;
mod icmp;
mod ip;
mod ipc;
mod state;
mod transport;
mod vfs;

use core::{alloc::Layout, panic::PanicInfo};
use smoltcp::{iface::PollResult, socket::tcp, time::Instant};
use state::NetworkStrate;
use strate_net::{syscalls::*, IpcMessage, OPCODE_CLOSE, OPCODE_OPEN, OPCODE_READ, OPCODE_WRITE};

alloc_freelist::define_freelist_brk_allocator!(
    pub struct BumpAllocator;
    brk = strat9_syscall::call::brk;
    heap_max = 16 * 1024 * 1024;
);

#[global_allocator]
static GLOBAL_ALLOCATOR: BumpAllocator = BumpAllocator;

#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    let _ = call::debug_log(b"[strate-net] OOM\n");
    exit(12);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    call::handle_panic("strate-net", info)
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

const NANOS_PER_SEC: u64 = 1_000_000_000;
const NANOS_PER_MICRO: u64 = 1_000;

const IPC_BATCH_SIZE: usize = 16;

fn log_errno(prefix: &str, err: strate_net::syscalls::Error) {
    use core::fmt::Write;

    let mut buf = [0u8; 96];
    let len = {
        let mut w = BufWriter {
            buf: &mut buf,
            pos: 0,
        };
        let _ = writeln!(w, "{}{}", prefix, err.to_errno());
        w.pos
    };
    if let Ok(s) = core::str::from_utf8(&buf[..len]) {
        debug_log(s);
    }
}

fn now_instant() -> Instant {
    match clock_gettime_ns() {
        Ok(ns) => Instant::from_micros((ns / NANOS_PER_MICRO) as i64),
        Err(_) => Instant::from_micros(0),
    }
}

fn sleep_micros(micros: u64) {
    if micros == 0 {
        return;
    }
    let nanos = micros.saturating_mul(NANOS_PER_MICRO);
    let req = TimeSpec {
        tv_sec: (nanos / NANOS_PER_SEC) as i64,
        tv_nsec: (nanos % NANOS_PER_SEC) as i64,
    };
    let _ = nanosleep(&req);
}

impl NetworkStrate {
    fn serve(&mut self, port: u64) -> ! {
        log("[strate-net] Starting DHCP...\n");
        self.enable_dhcp();

        loop {
            let now = now_instant();
            // Stamp pending pings before both polls so they are never
            // seen as "timed out" with send_ts_ns == 0.
            let send_ns = clock_gettime_ns().unwrap_or(0);
            for ping in self.pending_pings.iter_mut() {
                if ping.send_ts_ns == 0 {
                    ping.send_ts_ns = send_ns;
                }
            }
            let poll_result = self
                .interface
                .poll(now, &mut self.device, &mut self.sockets);

            self.process_icmp();

            self.lingering_sockets.retain(|&handle| {
                let socket = self.sockets.get::<tcp::Socket>(handle);
                if socket.state() == tcp::State::Closed {
                    self.sockets.remove(handle);
                    false
                } else {
                    true
                }
            });

            self.process_dhcp();
            self.process_ipv6_slaac();

            let mut msg = IpcMessage::new(0);
            let mut got_ipc = false;
            for _ in 0..IPC_BATCH_SIZE {
                if ipc_try_recv(port, &mut msg).is_err() {
                    break;
                }
                got_ipc = true;
                let reply = match msg.msg_type {
                    OPCODE_OPEN => self.handle_open(&msg),
                    OPCODE_READ => self.handle_read(&msg),
                    OPCODE_WRITE => self.handle_write(&msg),
                    OPCODE_CLOSE => self.handle_close(&msg),
                    _ => IpcMessage::error_reply(msg.sender, -22),
                };
                let _ = call::ipc_reply(&reply);
            }

            if got_ipc {
                let now2 = now_instant();
                // Stamp pings queued during IPC before the poll that sends them.
                let send_ns2 = clock_gettime_ns().unwrap_or(0);
                for ping in self.pending_pings.iter_mut() {
                    if ping.send_ts_ns == 0 {
                        ping.send_ts_ns = send_ns2;
                    }
                }
                let _ = self
                    .interface
                    .poll(now2, &mut self.device, &mut self.sockets);
                self.process_icmp();
                self.process_ipv6_slaac();
            }

            if !got_ipc && poll_result == PollResult::None {
                const MAX_SLEEP_US: u64 = 1_000;
                if let Some(delay) = self.interface.poll_delay(now, &self.sockets) {
                    let micros = delay.total_micros().min(MAX_SLEEP_US);
                    if micros > 0 {
                        sleep_micros(micros);
                    } else {
                        let _ = proc_yield();
                    }
                } else {
                    sleep_micros(MAX_SLEEP_US);
                }
            }
        }
    }
}

fn log(msg: &str) {
    let _ = call::debug_log(msg.as_bytes());
}

fn wait_for_kernel_mac(max_attempts: usize) -> Option<[u8; 6]> {
    let mut mac = [0u8; 6];

    for attempt in 0..max_attempts {
        if net_info(0, &mut mac).is_ok() && mac != [0; 6] {
            if attempt != 0 {
                log("[strate-net] Kernel NIC became available\n");
            }
            return Some(mac);
        }

        if attempt == 0 {
            log("[strate-net] Waiting for kernel NIC registration...\n");
        }

        sleep_micros(1000);
    }

    None
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    log("[strate-net] Starting network silo\n");

    let port = match call::ipc_create_port(0) {
        Ok(p) => p as u64,
        Err(e) => {
            log("[strate-net] Failed to create port: ");
            log_error_code(e);
            log("\n");
            exit(1);
        }
    };

    if let Err(e) = call::ipc_bind_port(port as usize, b"/net") {
        log("[strate-net] Failed to bind to /net: ");
        log_error_code(e);
        log("\n");
        exit(2);
    }

    log("[strate-net] Bound to /net\n");

    let mac = match wait_for_kernel_mac(2048) {
        Some(mac) => {
            log("[strate-net] MAC acquired from kernel\n");
            mac
        }
        None => {
            log("[strate-net] No NIC found after waiting, using fallback MAC\n");
            [0x52, 0x54, 0x00, 0x12, 0x34, 0x56]
        }
    };

    let mut strate = NetworkStrate::new(mac);
    strate.serve(port);
}

fn log_error_code(e: strate_net::syscalls::Error) {
    use core::fmt::Write;

    let mut buf = [0u8; 32];
    let n = {
        let mut w = BufWriter {
            buf: &mut buf,
            pos: 0,
        };
        let _ = write!(w, "{}", e.to_errno());
        w.pos
    };
    if let Ok(s) = core::str::from_utf8(&buf[..n]) {
        log(s);
    }
}
