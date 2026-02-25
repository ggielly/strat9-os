#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use alloc::{collections::BTreeMap, string::String};
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
    debug_log("[strate-net] PANIC: ");
    // info.message() is stable since Rust 1.73
    let msg = info.message();
    let mut buf = [0u8; 256];
    use core::fmt::Write;
    let mut cursor = BufWriter {
        buf: &mut buf,
        pos: 0,
    };
    let _ = write!(cursor, "{}", msg);
    let written = cursor.pos;
    if written > 0 {
        if let Ok(s) = core::str::from_utf8(&buf[..written]) {
            debug_log(s);
        }
    }
    debug_log("\n");
    exit(255);
}

/// Minimal fmt::Write adapter over a fixed byte buffer.
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

// ---------------------------------------------------------------------------
// Network strate logic
// ---------------------------------------------------------------------------

use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{self, Device, DeviceCapabilities, Medium},
    socket::dhcpv4,
    time::Instant,
    wire::{EthernetAddress, IpAddress, IpCidr, Ipv4Address},
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

// ---------------------------------------------------------------------------
// IP configuration obtained via DHCP
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct IpConfig {
    /// Assigned address + prefix length (e.g. 192.168.1.100/24)
    address: smoltcp::wire::Ipv4Cidr,
    /// Default gateway (optional)
    gateway: Option<Ipv4Address>,
    /// Up to 3 DNS servers
    dns: [Option<Ipv4Address>; 3],
}

/// Encode an IPv4Cidr as a human-readable string ("a.b.c.d/p\n").
fn ipv4_cidr_to_str(cidr: &smoltcp::wire::Ipv4Cidr, buf: &mut [u8]) -> usize {
    use core::fmt::Write;
    let mut w = BufWriter { buf, pos: 0 };
    let a = cidr.address().as_bytes();
    let _ = write!(
        w,
        "{}.{}.{}.{}/{}\n",
        a[0],
        a[1],
        a[2],
        a[3],
        cidr.prefix_len()
    );
    w.pos
}

/// Encode an Ipv4Address as a human-readable string ("a.b.c.d\n").
fn ipv4_addr_to_str(addr: &Ipv4Address, buf: &mut [u8]) -> usize {
    use core::fmt::Write;
    let mut w = BufWriter { buf, pos: 0 };
    let a = addr.as_bytes();
    let _ = write!(w, "{}.{}.{}.{}\n", a[0], a[1], a[2], a[3]);
    w.pos
}

// ---------------------------------------------------------------------------
// IPC reply builders  (match the layout expected by kernel IpcScheme)
// ---------------------------------------------------------------------------
//
// OPEN success reply  (msg_type = 0x80):
//   payload[0..4]  = status : u32 LE  (0 = OK)
//   payload[4..12] = file_id: u64 LE
//   payload[12..20]= size   : u64 LE  (u64::MAX ⇒ unknown)
//   payload[20..24]= flags  : u32 LE  (FileFlags bits)
//
// READ success reply  (msg_type = 0x80):
//   payload[0..4]  = status     : u32 LE (0 = OK)
//   payload[4..8]  = bytes_read : u32 LE
//   payload[8..48] = data (up to 40 bytes inline)
//
// CLOSE / generic OK reply (msg_type = 0x80):
//   payload[0..4] = status : u32 LE (0 = OK)

fn reply_open(sender: u64, file_id: u64, size: u64, flags: u32) -> IpcMessage {
    let mut msg = IpcMessage::new(0x80);
    msg.sender = sender;
    msg.payload[0..4].copy_from_slice(&0u32.to_le_bytes());
    msg.payload[4..12].copy_from_slice(&file_id.to_le_bytes());
    msg.payload[12..20].copy_from_slice(&size.to_le_bytes());
    msg.payload[20..24].copy_from_slice(&flags.to_le_bytes());
    msg
}

fn reply_read(sender: u64, data: &[u8]) -> IpcMessage {
    let mut msg = IpcMessage::new(0x80);
    msg.sender = sender;
    msg.payload[0..4].copy_from_slice(&0u32.to_le_bytes());
    // Max inline data: 48 - 8 = 40 bytes
    let n = data.len().min(40);
    msg.payload[4..8].copy_from_slice(&(n as u32).to_le_bytes());
    msg.payload[8..8 + n].copy_from_slice(&data[..n]);
    msg
}

fn reply_ok(sender: u64) -> IpcMessage {
    let mut msg = IpcMessage::new(0x80);
    msg.sender = sender;
    msg.payload[0..4].copy_from_slice(&0u32.to_le_bytes());
    msg
}

// ---------------------------------------------------------------------------
// NetworkStrate  – main state machine
// ---------------------------------------------------------------------------

struct NetworkStrate {
    device: Strat9NetDevice,
    interface: Interface,
    sockets: SocketSet<'static>,
    /// Handle to the smoltcp DHCP socket
    dhcp_handle: SocketHandle,
    /// Populated once DHCP handshake completes
    ip_config: Option<IpConfig>,
    /// VFS handles: file_id → virtual path ("ip", "gateway", "dns", "" = root dir)
    open_handles: BTreeMap<u64, String>,
    /// Monotonically-increasing file handle allocator
    next_fid: u64,
}

impl NetworkStrate {
    fn new(mac: [u8; 6]) -> Self {
        let mut device = Strat9NetDevice;
        let config = Config::new(EthernetAddress(mac).into());
        let interface = Interface::new(config, &mut device, Instant::from_micros(0));
        let mut sockets = SocketSet::new(alloc::vec![]);

        // Create the DHCP socket – smoltcp will handle the full DORA sequence
        let dhcp_socket = dhcpv4::Socket::new();
        let dhcp_handle = sockets.add(dhcp_socket);

        Self {
            device,
            interface,
            sockets,
            dhcp_handle,
            ip_config: None,
            open_handles: BTreeMap::new(),
            next_fid: 1,
        }
    }

    // -----------------------------------------------------------------------
    // DHCP event processing
    // -----------------------------------------------------------------------

    fn process_dhcp(&mut self) {
        let event = self
            .sockets
            .get_mut::<dhcpv4::Socket>(self.dhcp_handle)
            .poll();

        match event {
            Some(dhcpv4::Event::Configured(config)) => {
                debug_log("[strate-net] DHCP: address acquired\n");

                // Apply address to the interface
                self.interface.update_ip_addrs(|addrs| {
                    let cidr = IpCidr::new(
                        IpAddress::Ipv4(config.address.address()),
                        config.address.prefix_len(),
                    );
                    if let Some(slot) = addrs.iter_mut().next() {
                        *slot = cidr;
                    } else {
                        // Ignore error: heap alloc failure is a hard stop
                        let _ = addrs.push(cidr);
                    }
                });

                // Apply default route
                if let Some(gw) = config.router {
                    self.interface.routes_mut().add_default_ipv4_route(gw).ok();
                }

                // Collect up to 3 DNS servers
                let mut dns = [None::<Ipv4Address>; 3];
                for (slot, &server) in dns.iter_mut().zip(config.dns_servers.iter()) {
                    *slot = Some(server);
                }

                self.ip_config = Some(IpConfig {
                    address: config.address,
                    gateway: config.router,
                    dns,
                });
            }
            Some(dhcpv4::Event::Deconfigured) => {
                debug_log("[strate-net] DHCP: deconfigured (lease expired?)\n");
                self.ip_config = None;
                // Clear interface addresses
                self.interface.update_ip_addrs(|addrs| addrs.clear());
            }
            None => {}
        }
    }

    // -----------------------------------------------------------------------
    // VFS / IPC handlers  (Plan 9 style, mounted at /net)
    //
    //  /net            — directory: lists available virtual files
    //  /net/ip         — read: "a.b.c.d/prefix\n"  (from DHCP)
    //  /net/gateway    — read: "a.b.c.d\n"          (from DHCP)
    //  /net/dns        — read: "a.b.c.d\n"          (first DNS)
    //  /net/ethX       — read/write: raw Ethernet frames (future)
    // -----------------------------------------------------------------------

    fn handle_open(&mut self, msg: &IpcMessage) -> IpcMessage {
        // Decode path from payload: [flags:u32][path_len:u16][path bytes…]
        let path_len = u16::from_le_bytes([msg.payload[4], msg.payload[5]]) as usize;
        if path_len > 42 {
            return IpcMessage::error_reply(msg.sender, -22); // EINVAL
        }
        let path_bytes = &msg.payload[6..6 + path_len];
        let path = match core::str::from_utf8(path_bytes) {
            Ok(p) => p.trim_start_matches('/'),
            Err(_) => return IpcMessage::error_reply(msg.sender, -22),
        };

        match path {
            // Root directory
            "" => {
                let fid = self.alloc_fid();
                self.open_handles.insert(fid, String::from(""));
                // FileFlags::DIRECTORY = 1
                reply_open(msg.sender, fid, u64::MAX, 1)
            }
            "ip" | "gateway" | "dns" => {
                let fid = self.alloc_fid();
                self.open_handles.insert(fid, String::from(path));
                reply_open(msg.sender, fid, u64::MAX, 0)
            }
            _ => IpcMessage::error_reply(msg.sender, -2), // ENOENT
        }
    }

    fn handle_read(&mut self, msg: &IpcMessage) -> IpcMessage {
        let file_id = u64::from_le_bytes(msg.payload[0..8].try_into().unwrap_or([0u8; 8]));
        let offset = u64::from_le_bytes(msg.payload[8..16].try_into().unwrap_or([0u8; 8]));

        let path = match self.open_handles.get(&file_id) {
            Some(p) => p.clone(),
            None => return IpcMessage::error_reply(msg.sender, -9), // EBADF
        };

        let mut tmp = [0u8; 48];

        match path.as_str() {
            // Root listing
            "" => {
                let listing = b"ip\ngateway\ndns\n";
                let start = (offset as usize).min(listing.len());
                let data = &listing[start..];
                reply_read(msg.sender, data)
            }
            "ip" => {
                if let Some(ref cfg) = self.ip_config {
                    let n = ipv4_cidr_to_str(&cfg.address, &mut tmp);
                    let start = (offset as usize).min(n);
                    reply_read(msg.sender, &tmp[start..n])
                } else {
                    reply_read(msg.sender, b"0.0.0.0/0\n")
                }
            }
            "gateway" => {
                if let Some(ref cfg) = self.ip_config {
                    if let Some(gw) = cfg.gateway {
                        let n = ipv4_addr_to_str(&gw, &mut tmp);
                        let start = (offset as usize).min(n);
                        return reply_read(msg.sender, &tmp[start..n]);
                    }
                }
                reply_read(msg.sender, b"0.0.0.0\n")
            }
            "dns" => {
                if let Some(ref cfg) = self.ip_config {
                    if let Some(dns0) = cfg.dns[0] {
                        let n = ipv4_addr_to_str(&dns0, &mut tmp);
                        let start = (offset as usize).min(n);
                        return reply_read(msg.sender, &tmp[start..n]);
                    }
                }
                reply_read(msg.sender, b"0.0.0.0\n")
            }
            _ => IpcMessage::error_reply(msg.sender, -9), // EBADF
        }
    }

    fn handle_write(&mut self, msg: &IpcMessage) -> IpcMessage {
        // Write not supported on virtual status files
        IpcMessage::error_reply(msg.sender, -1) // EPERM
    }

    fn handle_close(&mut self, msg: &IpcMessage) -> IpcMessage {
        let file_id = u64::from_le_bytes(msg.payload[0..8].try_into().unwrap_or([0u8; 8]));
        self.open_handles.remove(&file_id);
        reply_ok(msg.sender)
    }

    fn alloc_fid(&mut self) -> u64 {
        let id = self.next_fid;
        self.next_fid += 1;
        id
    }

    // -----------------------------------------------------------------------
    // Main event loop
    // -----------------------------------------------------------------------

    fn serve(&mut self, port: u64) -> ! {
        debug_log("[strate-net] Starting DHCP...\n");

        loop {
            // 1. Drive the smoltcp stack (transmits queued packets, processes received ones)
            let now = now_instant();
            let poll_result = self
                .interface
                .poll(now, &mut self.device, &mut self.sockets);

            // 2. Check DHCP state machine for new events
            self.process_dhcp();

            // 3. Handle IPC messages from other strates / VFS callers (non-blocking)
            let mut msg = IpcMessage::new(0);
            let mut got_ipc = false;
            if ipc_try_recv(port, &mut msg).is_ok() {
                got_ipc = true;
                let reply = match msg.msg_type {
                    OPCODE_OPEN => self.handle_open(&msg),
                    OPCODE_READ => self.handle_read(&msg),
                    OPCODE_WRITE => self.handle_write(&msg),
                    OPCODE_CLOSE => self.handle_close(&msg),
                    _ => IpcMessage::error_reply(msg.sender, -22), // EINVAL
                };
                let _ = call::ipc_reply(&reply);
            }

            // 4. Sleep until the next smoltcp deadline if there is nothing to do
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

    let port = match call::ipc_create_port(0) {
        Ok(p) => p as u64,
        Err(_) => {
            debug_log("[strate-net] Failed to create port\n");
            exit(1);
        }
    };

    if call::ipc_bind_port(port as usize, b"/net").is_err() {
        debug_log("[strate-net] Failed to bind to /net\n");
        exit(2);
    }

    debug_log("[strate-net] Bound to /net\n");

    // Get MAC address from kernel (fallback to a QEMU-safe address if unavailable)
    let mut mac = [0u8; 6];
    if net_info(0, &mut mac).is_err() {
        debug_log("[strate-net] Failed to get MAC address, using fallback\n");
        mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    } else {
        debug_log("[strate-net] MAC acquired from kernel\n");
    }

    let mut strate = NetworkStrate::new(mac);
    strate.serve(port);
}
