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
use strat9_abi::net::{NetEvent, NetQueueHeader, NetQueueMap};
use strate_net::{
    syscalls::*, IpcMessage, OPCODE_BULK_SETUP, OPCODE_BULK_TEARDOWN, OPCODE_CLOSE, OPCODE_OPEN,
    OPCODE_READ, OPCODE_WRITE,
};

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
            // Drain hotplug/link events before polling: a removed device must
            // not be touched by the stack.
            let mut device_event = NetEvent::default();
            if call::net_device_event(&mut device_event).is_ok() {
                match device_event.kind {
                    strat9_abi::net::event::DEVICE_REMOVE => {
                        log("[strate-net] device removed, exiting for supervisor restart\n");
                        exit(3);
                    }
                    strat9_abi::net::event::LINK_DOWN => {
                        log("[strate-net] link down\n");
                    }
                    strat9_abi::net::event::LINK_UP => {
                        log("[strate-net] link up\n");
                    }
                    _ => {}
                }
            }

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
            self.device.flush();

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
                    OPCODE_BULK_SETUP => self.handle_bulk_setup(&msg),
                    OPCODE_BULK_TEARDOWN => self.handle_bulk_teardown(&msg),
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
                self.device.flush();
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

    // Acquire the NIC capability once.  Without it every raw network syscall
    // returns EPERM; this is the capability gate introduced in P0.
    let dev_handle = match net_open() {
        Ok(handle) => {
            log("[strate-net] NIC capability acquired\n");
            handle as u64
        }
        Err(e) => {
            log("[strate-net] net_open failed: ");
            log_error_code(e);
            log("\n");
            0
        }
    };

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

    // Register with the NIC subsystem so the IRQ handler can wake us.
    if net_register().is_ok() {
        log("[strate-net] Registered with NIC IRQ dispatch\n");
    } else {
        log("[strate-net] NIC registration failed (will poll)\n");
    }

    // Try to map all shared queue regions.  On success RX/TX are syscall-free
    // and copy-free between the kernel and this stack, and the stack polls
    // every software RSS queue.
    let device = if dev_handle != 0 {
        let mut queue_count: u32 = 0;
        let _ = call::net_info(4, &mut queue_count as *mut u32 as usize);
        let count = core::cmp::min(queue_count, 8) as usize;
        let mut queues = alloc::vec::Vec::with_capacity(count);
        for qid in 0..count {
            let mut map = NetQueueMap::default();
            if call::net_queue_map(dev_handle as usize, qid, &mut map).is_err() || map.base == 0 {
                break;
            }
            let header = map.base as *mut NetQueueHeader;
            // SAFETY: the kernel returned a writable mapping; verify magic.
            if !unsafe { (*header).is_valid() } {
                break;
            }
            queues.push(crate::device::SharedQueue {
                qid: qid as u16,
                header,
                tx_pending: alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false)),
            });
        }
        if queues.is_empty() {
            log("[strate-net] Queue map failed, using copy path\n");
            crate::device::NetDevice::legacy()
        } else {
            log("[strate-net] Shared queues mapped (zero-copy, multi-queue)\n");
            let features = unsafe {
                (*queues[0].header)
                    .features
                    .load(core::sync::atomic::Ordering::Acquire)
            };
            unsafe { crate::device::NetDevice::shared(dev_handle, queues, mac, features) }
        }
    } else {
        crate::device::NetDevice::legacy()
    };

    let mut strate = NetworkStrate::new(mac, device);
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
