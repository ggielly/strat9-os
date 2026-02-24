#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use core::{
    alloc::Layout,
    panic::PanicInfo,
    sync::atomic::{AtomicUsize, Ordering},
};
use strate_net::{syscalls::*, IpcMessage, OPCODE_CLOSE, OPCODE_OPEN, OPCODE_READ, OPCODE_WRITE};

// TODO - implement a proper userspace heap and remove the bump allocator
// ---------------------------------------------------------------------------
// Minimal bump allocator (shared with other silos until userspace heap is ready)
// ---------------------------------------------------------------------------

struct BumpAllocator;

const HEAP_SIZE: usize = 1024 * 1024; // 1 MiB heap for now
static mut HEAP: [u8; HEAP_SIZE] = [0u8; HEAP_SIZE];
static HEAP_OFFSET: AtomicUsize = AtomicUsize::new(0);

unsafe impl core::alloc::GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align = layout.align().max(1);
        let size = layout.size();
        let mut offset = HEAP_OFFSET.load(Ordering::Relaxed);
        loop {
            let aligned = (offset + align - 1) & !(align - 1);
            let new_offset = match aligned.checked_add(size) {
                Some(v) => v,
                None => return core::ptr::null_mut(),
            };
            if new_offset > HEAP_SIZE {
                return core::ptr::null_mut();
            }
            match HEAP_OFFSET.compare_exchange(
                offset,
                new_offset,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    let heap_ptr = core::ptr::addr_of_mut!(HEAP) as *mut u8;
                    return unsafe { heap_ptr.add(aligned) };
                }
                Err(prev) => offset = prev,
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[global_allocator]
static GLOBAL_ALLOCATOR: BumpAllocator = BumpAllocator;

#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    debug_log("[strate-net] OOM\n");
    exit(12);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    debug_log("[strate-net] PANIC!\n");
    if let Some(s) = info.payload().downcast_ref::<&str>() {
        debug_log(s);
    }
    exit(255);
}

// ---------------------------------------------------------------------------
// Network strate logic
// ---------------------------------------------------------------------------

use smoltcp::{
    phy::{self, Device, DeviceCapabilities, Medium},
    time::Instant,
};

const MAX_FRAME_SIZE: usize = 1514;
const NANOS_PER_SEC: u64 = 1_000_000_000;
const NANOS_PER_MICRO: u64 = 1_000;

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

struct Strat9NetDevice;

impl Device for Strat9NetDevice {
    type RxToken<'a> = Strat9RxToken;
    type TxToken<'a> = Strat9TxToken;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let mut buf = [0u8; MAX_FRAME_SIZE];
        match net_recv(&mut buf) {
            Ok(n) if n > 0 => {
                let len = core::cmp::min(n, MAX_FRAME_SIZE);
                Some((Strat9RxToken { buf, len }, Strat9TxToken))
            }
            _ => None,
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(Strat9TxToken)
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = MAX_FRAME_SIZE;
        caps.medium = Medium::Ethernet;
        caps
    }
}

struct Strat9RxToken {
    buf: [u8; MAX_FRAME_SIZE],
    len: usize,
}

impl phy::RxToken for Strat9RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buf[..self.len])
    }
}

struct Strat9TxToken;

impl phy::TxToken for Strat9TxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        if len > MAX_FRAME_SIZE {
            debug_log("[strate-net] TX frame too large\n");
            return f(&mut []);
        }
        let mut buf = [0u8; MAX_FRAME_SIZE];
        let ret = f(&mut buf[..len]);
        let _ = net_send(&buf[..len]);
        ret
    }
}

use smoltcp::{
    iface::{Config, Interface, SocketSet},
    wire::{EthernetAddress, IpCidr},
};

struct NetworkStrate {
    device: Strat9NetDevice,
    interface: Interface,
    sockets: SocketSet<'static>,
}

impl NetworkStrate {
    fn new(mac: [u8; 6]) -> Self {
        let mut device = Strat9NetDevice;
        let config = Config::new(EthernetAddress(mac).into());

        let interface = Interface::new(config, &mut device, Instant::from_micros(0));
        let sockets = SocketSet::new(alloc::vec![]);

        Self {
            device,
            interface,
            sockets,
        }
    }

    fn handle_open(&mut self, msg: &IpcMessage) -> IpcMessage {
        debug_log("[strate-net] Handling OPEN\n");
        // Plan 9 style: /net/tcp/0, /net/udp/0, etc.
        IpcMessage::error_reply(msg.sender, -38) // ENOSYS/ENOTSUP
    }

    fn handle_read(&mut self, msg: &IpcMessage) -> IpcMessage {
        IpcMessage::error_reply(msg.sender, -38)
    }

    fn handle_write(&mut self, msg: &IpcMessage) -> IpcMessage {
        IpcMessage::error_reply(msg.sender, -38)
    }

    fn handle_close(&mut self, msg: &IpcMessage) -> IpcMessage {
        IpcMessage::error_reply(msg.sender, -38)
    }

    fn serve(&mut self, port: u64) -> ! {
        loop {
            // 1. Process network packets
            let now = now_instant();
            let poll_result = self
                .interface
                .poll(now, &mut self.device, &mut self.sockets);

            // 2. Check for IPC messages (non-blocking)
            let mut msg = IpcMessage::new(0);
            let mut got_ipc = false;
            if ipc_try_recv(port, &mut msg).is_ok() {
                got_ipc = true;
                match msg.msg_type {
                    OPCODE_OPEN => {
                        let reply = self.handle_open(&msg);
                        let _ = unsafe {
                            syscall1(number::SYS_IPC_REPLY, &reply as *const IpcMessage as usize)
                        };
                    }
                    OPCODE_READ => {
                        let reply = self.handle_read(&msg);
                        let _ = unsafe {
                            syscall1(number::SYS_IPC_REPLY, &reply as *const IpcMessage as usize)
                        };
                    }
                    OPCODE_WRITE => {
                        let reply = self.handle_write(&msg);
                        let _ = unsafe {
                            syscall1(number::SYS_IPC_REPLY, &reply as *const IpcMessage as usize)
                        };
                    }
                    OPCODE_CLOSE => {
                        let reply = self.handle_close(&msg);
                        let _ = unsafe {
                            syscall1(number::SYS_IPC_REPLY, &reply as *const IpcMessage as usize)
                        };
                    }
                    _ => {
                        let reply = IpcMessage::error_reply(msg.sender, -22); // EINVAL
                        let _ = unsafe {
                            syscall1(number::SYS_IPC_REPLY, &reply as *const IpcMessage as usize)
                        };
                    }
                }
            }

            if !got_ipc && poll_result == smoltcp::iface::PollResult::None {
                if let Some(delay) = self.interface.poll_delay(now, &self.sockets) {
                    let micros = delay.total_micros();
                    if micros > 0 {
                        sleep_micros(micros);
                    } else {
                        let _ = proc_yield();
                    }
                } else {
                    let _ = proc_yield();
                }
            }
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    debug_log("[strate-net] Starting network silo\n");

    // 1. Create IPC port
    let port = match unsafe { syscall1(number::SYS_IPC_CREATE_PORT, 0) } {
        Ok(p) => p as u64,
        Err(_) => {
            debug_log("[strate-net] Failed to create port\n");
            exit(1);
        }
    };

    // 2. Bind port to /net
    let path = b"/net";
    let bind = unsafe {
        syscall3(
            number::SYS_IPC_BIND_PORT,
            port as usize,
            path.as_ptr() as usize,
            path.len(),
        )
    };

    if bind.is_err() {
        debug_log("[strate-net] Failed to bind to /net\n");
        exit(2);
    }

    debug_log("[strate-net] Bound to /net\n");

    // 3. Get MAC address from kernel
    let mut mac = [0u8; 6];
    if net_info(0, &mut mac).is_err() {
        debug_log("[strate-net] Failed to get MAC address, using fallback\n");
        mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    } else {
        debug_log("[strate-net] MAC acquired from kernel\n");
    }

    debug_log("[strate-net] Serving...\n");

    let mut strate = NetworkStrate::new(mac);
    strate.serve(port);
}
