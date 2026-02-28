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

alloc_freelist::define_freelist_allocator!(pub struct BumpAllocator; heap_size = 1024 * 1024;);

#[global_allocator]
static GLOBAL_ALLOCATOR: BumpAllocator = BumpAllocator;

#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    let _ = call::write(1, b"[strate-net] OOM\n");
    exit(12);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    let _ = call::write(1, b"[strate-net] PANIC: ");
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
        let _ = call::write(1, &buf[..written]);
    }
    let _ = call::write(1, b"\n");
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
    socket::{dhcpv4, dns, icmp, tcp},
    time::Instant,
    wire::{DnsQueryType, EthernetAddress, IpAddress, IpCidr, Ipv4Address},
};

fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

const MAX_FRAME_SIZE: usize = 1514;
const NANOS_PER_SEC: u64 = 1_000_000_000;
const NANOS_PER_MICRO: u64 = 1_000;
static RX_ERR_LOG_BUDGET: AtomicUsize = AtomicUsize::new(16);
static TX_ERR_LOG_BUDGET: AtomicUsize = AtomicUsize::new(16);

fn log_errno(prefix: &str, err: strate_net::syscalls::Error) {
    use core::fmt::Write;
    let mut buf = [0u8; 96];
    let len = {
        let mut w = BufWriter {
            buf: &mut buf,
            pos: 0,
        };
        let _ = write!(w, "{}{}\n", prefix, err.to_errno());
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
            Err(e) => {
                if e.to_errno() != 11 {
                    if RX_ERR_LOG_BUDGET.load(Ordering::Relaxed) > 0 {
                        RX_ERR_LOG_BUDGET.fetch_sub(1, Ordering::Relaxed);
                        log_errno("[strate-net] net_recv errno=", e);
                    }
                }
                None
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
            log("[strate-net] TX frame too large\n");
            return f(&mut []);
        }
        let mut buf = [0u8; MAX_FRAME_SIZE];
        let ret = f(&mut buf[..len]);
        if let Err(e) = net_send(&buf[..len]) {
            if TX_ERR_LOG_BUDGET.load(Ordering::Relaxed) > 0 {
                TX_ERR_LOG_BUDGET.fetch_sub(1, Ordering::Relaxed);
                log_errno("[strate-net] net_send errno=", e);
            }
        }
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
    /// Host address only (e.g. 192.168.1.100)
    host: Ipv4Address,
    /// Prefix length (e.g. 24)
    prefix_len: u8,
    /// Netmask derived from prefix (e.g. 255.255.255.0)
    netmask: Ipv4Address,
    /// Broadcast derived from host+prefix (e.g. 192.168.1.255)
    broadcast: Ipv4Address,
    /// Default gateway (optional)
    gateway: Option<Ipv4Address>,
    /// Up to 3 DNS servers
    dns: [Option<Ipv4Address>; 3],
}

/// Encode an IPv4Cidr as a human-readable string ("a.b.c.d/p\n").
fn ipv4_cidr_to_str(cidr: &smoltcp::wire::Ipv4Cidr, buf: &mut [u8]) -> usize {
    use core::fmt::Write;
    let mut w = BufWriter { buf, pos: 0 };
    let a = cidr.address().octets();
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
    let a = addr.octets();
    let _ = write!(w, "{}.{}.{}.{}\n", a[0], a[1], a[2], a[3]);
    w.pos
}

fn u8_to_str(v: u8, buf: &mut [u8]) -> usize {
    use core::fmt::Write;
    let mut w = BufWriter { buf, pos: 0 };
    let _ = write!(w, "{}\n", v);
    w.pos
}

fn mask_from_prefix(prefix: u8) -> Ipv4Address {
    let mask: u32 = if prefix == 0 {
        0
    } else if prefix >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    };
    let b = mask.to_be_bytes();
    Ipv4Address::new(b[0], b[1], b[2], b[3])
}

fn broadcast_from_host_prefix(host: Ipv4Address, prefix: u8) -> Ipv4Address {
    let h = u32::from_be_bytes(host.octets());
    let m = u32::from_be_bytes(mask_from_prefix(prefix).octets());
    let b = (h & m) | (!m);
    let o = b.to_be_bytes();
    Ipv4Address::new(o[0], o[1], o[2], o[3])
}

fn route_to_str(gateway: &Ipv4Address, buf: &mut [u8]) -> usize {
    use core::fmt::Write;
    let mut w = BufWriter { buf, pos: 0 };
    let a = gateway.octets();
    let _ = write!(w, "default via {}.{}.{}.{}\n", a[0], a[1], a[2], a[3]);
    w.pos
}

fn dns_list_to_str(dns: &[Option<Ipv4Address>; 3], buf: &mut [u8]) -> usize {
    use core::fmt::Write;
    let mut w = BufWriter { buf, pos: 0 };
    let mut wrote_any = false;
    for server in dns.iter().flatten() {
        let a = server.octets();
        let _ = write!(w, "{}.{}.{}.{}\n", a[0], a[1], a[2], a[3]);
        wrote_any = true;
    }
    if !wrote_any {
        let _ = write!(w, "0.0.0.0\n");
    }
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

fn reply_write(sender: u64, n: usize) -> IpcMessage {
    let mut msg = IpcMessage::new(0x80);
    msg.sender = sender;
    msg.payload[0..4].copy_from_slice(&0u32.to_le_bytes());
    msg.payload[4..8].copy_from_slice(&(n as u32).to_le_bytes());
    msg
}

fn reply_ok(sender: u64) -> IpcMessage {
    let mut msg = IpcMessage::new(0x80);
    msg.sender = sender;
    msg.payload[0..4].copy_from_slice(&0u32.to_le_bytes());
    msg
}

fn parse_ipv4(s: &str) -> Option<Ipv4Address> {
    let mut octets = [0u8; 4];
    let mut idx = 0;
    let mut val: u16 = 0;
    let mut has_digit = false;
    for &b in s.as_bytes() {
        if b == b'.' {
            if !has_digit || idx >= 3 {
                return None;
            }
            if val > 255 {
                return None;
            }
            octets[idx] = val as u8;
            idx += 1;
            val = 0;
            has_digit = false;
        } else if b >= b'0' && b <= b'9' {
            val = val * 10 + (b - b'0') as u16;
            has_digit = true;
        } else {
            break;
        }
    }
    if !has_digit || idx != 3 || val > 255 {
        return None;
    }
    octets[3] = val as u8;
    Some(Ipv4Address::new(octets[0], octets[1], octets[2], octets[3]))
}

// ---------------------------------------------------------------------------
// NetworkStrate  – main state machine
// ---------------------------------------------------------------------------

struct PendingPing {
    seq: u16,
    send_ts_ns: u64,
}

#[derive(Clone, Copy)]
struct TcpListenerState {
    socket: SocketHandle,
    port: u16,
}

struct NetworkStrate {
    device: Strat9NetDevice,
    interface: Interface,
    sockets: SocketSet<'static>,
    dhcp_handle: SocketHandle,
    dns_handle: SocketHandle,
    icmp_handle: SocketHandle,
    ip_config: Option<IpConfig>,
    /// VFS handles: file_id → virtual path ("/net/*")
    open_handles: BTreeMap<u64, String>,
    tcp_listeners: BTreeMap<u64, TcpListenerState>,
    next_fid: u64,
    /// Last ping that was sent, waiting for reply
    pending_ping: Option<PendingPing>,
    /// Received reply: (seq, rtt_us)
    ping_reply: Option<(u16, u64)>,
    ping_ident: u16,
}

impl NetworkStrate {
    fn new(mac: [u8; 6]) -> Self {
        let mut device = Strat9NetDevice;
        let config = Config::new(EthernetAddress(mac).into());
        let interface = Interface::new(config, &mut device, Instant::from_micros(0));
        let mut sockets = SocketSet::new(alloc::vec![]);

        let dhcp_socket = dhcpv4::Socket::new();
        let dhcp_handle = sockets.add(dhcp_socket);

        let dns_socket = dns::Socket::new(&[], alloc::vec![]);
        let dns_handle = sockets.add(dns_socket);

        let icmp_rx_buf = icmp::PacketBuffer::new(
            alloc::vec![icmp::PacketMetadata::EMPTY; 4],
            alloc::vec![0u8; 1024],
        );
        let icmp_tx_buf = icmp::PacketBuffer::new(
            alloc::vec![icmp::PacketMetadata::EMPTY; 4],
            alloc::vec![0u8; 1024],
        );
        let icmp_socket = icmp::Socket::new(icmp_rx_buf, icmp_tx_buf);
        let icmp_handle = sockets.add(icmp_socket);

        Self {
            device,
            interface,
            sockets,
            dhcp_handle,
            dns_handle,
            icmp_handle,
            ip_config: None,
            open_handles: BTreeMap::new(),
            tcp_listeners: BTreeMap::new(),
            next_fid: 1,
            pending_ping: None,
            ping_reply: None,
            ping_ident: 0x9001,
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
                log("[strate-net] DHCP: address acquired\n");

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
                let _ = self.interface.routes_mut().remove_default_ipv4_route();
                if let Some(gw) = config.router {
                    self.interface.routes_mut().add_default_ipv4_route(gw).ok();
                }

                // Collect up to 3 DNS servers
                let mut dns = [None::<Ipv4Address>; 3];
                for (slot, &server) in dns.iter_mut().zip(config.dns_servers.iter()) {
                    *slot = Some(server);
                }

                let host = config.address.address();
                let prefix_len = config.address.prefix_len();
                let netmask = mask_from_prefix(prefix_len);
                let broadcast = broadcast_from_host_prefix(host, prefix_len);
                self.ip_config = Some(IpConfig {
                    address: config.address,
                    host,
                    prefix_len,
                    netmask,
                    broadcast,
                    gateway: config.router,
                    dns,
                });
                self.refresh_dns_servers();
            }
            Some(dhcpv4::Event::Deconfigured) => {
                log("[strate-net] DHCP: deconfigured (lease expired?)\n");
                self.ip_config = None;
                // Clear interface addresses
                self.interface.update_ip_addrs(|addrs| addrs.clear());
                let _ = self.interface.routes_mut().remove_default_ipv4_route();
                self.refresh_dns_servers();
            }
            None => {}
        }
    }

    fn refresh_dns_servers(&mut self) {
        let mut servers = [IpAddress::Ipv4(Ipv4Address::new(0, 0, 0, 0)); 3];
        let mut count = 0usize;

        if let Some(ref cfg) = self.ip_config {
            for s in cfg.dns.iter().flatten() {
                if *s != Ipv4Address::new(0, 0, 0, 0) && count < servers.len() {
                    servers[count] = IpAddress::Ipv4(*s);
                    count += 1;
                }
            }
            if count == 0 {
                if let Some(gw) = cfg.gateway {
                    servers[0] = IpAddress::Ipv4(gw);
                    count = 1;
                }
            }
        }

        let socket = self.sockets.get_mut::<dns::Socket>(self.dns_handle);
        socket.update_servers(&servers[..count]);
    }

    fn resolve_hostname_blocking(&mut self, name: &str) -> core::result::Result<Ipv4Address, i32> {
        if let Some(ip) = parse_ipv4(name) {
            return Ok(ip);
        }
        if self.ip_config.is_none() {
            return Err(-11);
        }

        let query = {
            let cx = self.interface.context();
            let socket = self.sockets.get_mut::<dns::Socket>(self.dns_handle);
            match socket.start_query(cx, name, DnsQueryType::A) {
                Ok(q) => q,
                Err(_) => return Err(-22),
            }
        };

        let deadline_ns = clock_gettime_ns().unwrap_or(0).saturating_add(3_000_000_000);
        loop {
            let now = now_instant();
            let _ = self
                .interface
                .poll(now, &mut self.device, &mut self.sockets);
            self.process_dhcp();
            self.process_icmp();

            let res = self
                .sockets
                .get_mut::<dns::Socket>(self.dns_handle)
                .get_query_result(query);
            match res {
                Ok(addrs) => {
                    for addr in addrs {
                        if let IpAddress::Ipv4(v4) = addr {
                            return Ok(v4);
                        }
                    }
                    return Err(-2);
                }
                Err(dns::GetQueryResultError::Failed) => return Err(-2),
                Err(dns::GetQueryResultError::Pending) => {
                    if clock_gettime_ns().unwrap_or(0) >= deadline_ns {
                        return Err(-110);
                    }
                    sleep_micros(10_000);
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // ICMP echo processing
    // -----------------------------------------------------------------------

    fn process_icmp(&mut self) {
        let socket = self.sockets.get_mut::<icmp::Socket>(self.icmp_handle);
        if !socket.can_recv() {
            return;
        }
        let now_ns = clock_gettime_ns().unwrap_or(0);
        while socket.can_recv() {
            let Ok((data, _addr)) = socket.recv() else {
                break;
            };
            // data is the raw ICMP payload after IP header
            if data.len() < 8 {
                continue;
            }
            // ICMP type=0 (echo reply), code=0
            if data[0] != 0 {
                continue;
            }
            let ident = u16::from_be_bytes([data[4], data[5]]);
            let seq = u16::from_be_bytes([data[6], data[7]]);
            if ident != self.ping_ident {
                continue;
            }
            if let Some(ref pending) = self.pending_ping {
                if seq == pending.seq {
                    let rtt_us = now_ns.saturating_sub(pending.send_ts_ns) / 1000;
                    self.ping_reply = Some((seq, rtt_us));
                    self.pending_ping = None;
                }
            }
        }
    }

    fn send_ping(&mut self, target: Ipv4Address, seq: u16) -> bool {
        // One in-flight ping at a time, and don't overwrite unread replies.
        if self.pending_ping.is_some() || self.ping_reply.is_some() {
            return false;
        }
        let socket = self.sockets.get_mut::<icmp::Socket>(self.icmp_handle);
        if !socket.is_open() {
            socket.bind(icmp::Endpoint::Ident(self.ping_ident)).ok();
        }
        if !socket.can_send() {
            return false;
        }
        // Build ICMP echo request manually: type(1)+code(1)+cksum(2)+ident(2)+seq(2)+payload
        let payload_len = 40;
        let icmp_len = 8 + payload_len;
        let Ok(buf) = socket.send(icmp_len, IpAddress::Ipv4(target)) else {
            return false;
        };
        buf[0] = 8; // type = echo request
        buf[1] = 0; // code
        buf[2] = 0; // checksum (filled later)
        buf[3] = 0;
        buf[4..6].copy_from_slice(&self.ping_ident.to_be_bytes());
        buf[6..8].copy_from_slice(&seq.to_be_bytes());
        for i in 8..icmp_len {
            buf[i] = 0xAA;
        }
        // Compute ICMP checksum
        let cksum = icmp_checksum(buf);
        buf[2..4].copy_from_slice(&cksum.to_be_bytes());

        let now_ns = clock_gettime_ns().unwrap_or(0);
        self.pending_ping = Some(PendingPing {
            seq,
            send_ts_ns: now_ns,
        });
        true
    }

    // -----------------------------------------------------------------------
    // VFS / IPC handlers
    // -----------------------------------------------------------------------

    fn handle_open(&mut self, msg: &IpcMessage) -> IpcMessage {
        let path_len = u16::from_le_bytes([msg.payload[4], msg.payload[5]]) as usize;
        if path_len > 42 {
            return IpcMessage::error_reply(msg.sender, -22);
        }
        let path_bytes = &msg.payload[6..6 + path_len];
        let path = match core::str::from_utf8(path_bytes) {
            Ok(p) => p.trim_start_matches('/'),
            Err(_) => return IpcMessage::error_reply(msg.sender, -22),
        };

        match path {
            "" => {
                let fid = self.alloc_fid();
                self.open_handles.insert(fid, String::from(""));
                reply_open(msg.sender, fid, u64::MAX, 1)
            }
            "ip" | "address" | "prefix" | "netmask" | "broadcast" | "gateway" | "route"
            | "dns" | "resolve" | "tcp" => {
                let fid = self.alloc_fid();
                self.open_handles.insert(fid, String::from(path));
                reply_open(msg.sender, fid, u64::MAX, 0)
            }
            p if p.starts_with("resolve/") => {
                if p.len() <= 8 {
                    return IpcMessage::error_reply(msg.sender, -22);
                }
                let fid = self.alloc_fid();
                self.open_handles.insert(fid, String::from(path));
                reply_open(msg.sender, fid, u64::MAX, 0)
            }
            p if p.starts_with("ping/") => {
                let fid = self.alloc_fid();
                self.open_handles.insert(fid, String::from(path));
                reply_open(msg.sender, fid, u64::MAX, 0)
            }
            p if p.starts_with("tcp/listen/") => {
                let port_str = &p[11..];
                let Some(port) = port_str.parse::<u16>().ok() else {
                    return IpcMessage::error_reply(msg.sender, -22);
                };
                if port == 0 {
                    return IpcMessage::error_reply(msg.sender, -22);
                }

                let rx_buf = tcp::SocketBuffer::new(alloc::vec![0u8; 4096]);
                let tx_buf = tcp::SocketBuffer::new(alloc::vec![0u8; 4096]);
                let mut sock = tcp::Socket::new(rx_buf, tx_buf);
                if sock.listen(port).is_err() {
                    return IpcMessage::error_reply(msg.sender, -98);
                }
                let socket = self.sockets.add(sock);

                let fid = self.alloc_fid();
                self.open_handles.insert(fid, String::from(path));
                self.tcp_listeners
                    .insert(fid, TcpListenerState { socket, port });
                reply_open(msg.sender, fid, u64::MAX, 0)
            }
            _ => IpcMessage::error_reply(msg.sender, -2),
        }
    }

    fn handle_tcp_read(&mut self, sender: u64, listener: TcpListenerState) -> IpcMessage {
        let socket = self.sockets.get_mut::<tcp::Socket>(listener.socket);
        if !socket.is_open() || (!socket.is_listening() && !socket.is_active()) {
            let _ = socket.listen(listener.port);
        }

        let mut data = [0u8; 40];
        if socket.can_recv() {
            match socket.recv_slice(&mut data) {
                Ok(n) => return reply_read(sender, &data[..n]),
                Err(_) => return IpcMessage::error_reply(sender, -5),
            }
        }

        if socket.is_open() && !socket.may_recv() && !socket.may_send() {
            socket.abort();
            let _ = socket.listen(listener.port);
        }
        IpcMessage::error_reply(sender, -11)
    }

    fn handle_tcp_write(&mut self, sender: u64, listener: TcpListenerState, msg: &IpcMessage) -> IpcMessage {
        let socket = self.sockets.get_mut::<tcp::Socket>(listener.socket);
        if !socket.is_open() || (!socket.is_listening() && !socket.is_active()) {
            let _ = socket.listen(listener.port);
        }

        let data_len = u16::from_le_bytes([msg.payload[16], msg.payload[17]]) as usize;
        let data_len = core::cmp::min(data_len, msg.payload.len().saturating_sub(18));
        let data = &msg.payload[18..18 + data_len];

        if !socket.can_send() {
            return IpcMessage::error_reply(sender, -11);
        }

        match socket.send_slice(data) {
            Ok(n) => reply_write(sender, n),
            Err(_) => IpcMessage::error_reply(sender, -11),
        }
    }

    fn handle_read(&mut self, msg: &IpcMessage) -> IpcMessage {
        let file_id = u64::from_le_bytes(msg.payload[0..8].try_into().unwrap_or([0u8; 8]));
        let offset = u64::from_le_bytes(msg.payload[8..16].try_into().unwrap_or([0u8; 8]));

        if let Some(listener) = self.tcp_listeners.get(&file_id).copied() {
            return self.handle_tcp_read(msg.sender, listener);
        }

        let path = match self.open_handles.get(&file_id) {
            Some(p) => p.clone(),
            None => return IpcMessage::error_reply(msg.sender, -9),
        };

        let mut tmp = [0u8; 64];

        match path.as_str() {
            "" => {
                let listing =
                    b"ip\naddress\nprefix\nnetmask\nbroadcast\ngateway\nroute\ndns\nresolve\nping\ntcp\n";
                let start = (offset as usize).min(listing.len());
                reply_read(msg.sender, &listing[start..])
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
            "address" => {
                if let Some(ref cfg) = self.ip_config {
                    let n = ipv4_addr_to_str(&cfg.host, &mut tmp);
                    let start = (offset as usize).min(n);
                    reply_read(msg.sender, &tmp[start..n])
                } else {
                    reply_read(msg.sender, b"0.0.0.0\n")
                }
            }
            "prefix" => {
                if let Some(ref cfg) = self.ip_config {
                    let n = u8_to_str(cfg.prefix_len, &mut tmp);
                    let start = (offset as usize).min(n);
                    reply_read(msg.sender, &tmp[start..n])
                } else {
                    reply_read(msg.sender, b"0\n")
                }
            }
            "netmask" => {
                if let Some(ref cfg) = self.ip_config {
                    let n = ipv4_addr_to_str(&cfg.netmask, &mut tmp);
                    let start = (offset as usize).min(n);
                    reply_read(msg.sender, &tmp[start..n])
                } else {
                    reply_read(msg.sender, b"0.0.0.0\n")
                }
            }
            "broadcast" => {
                if let Some(ref cfg) = self.ip_config {
                    let n = ipv4_addr_to_str(&cfg.broadcast, &mut tmp);
                    let start = (offset as usize).min(n);
                    reply_read(msg.sender, &tmp[start..n])
                } else {
                    reply_read(msg.sender, b"0.0.0.0\n")
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
                    let n = dns_list_to_str(&cfg.dns, &mut tmp);
                    let start = (offset as usize).min(n);
                    return reply_read(msg.sender, &tmp[start..n]);
                }
                reply_read(msg.sender, b"0.0.0.0\n")
            }
            "route" => {
                if let Some(ref cfg) = self.ip_config {
                    if let Some(gw) = cfg.gateway {
                        let n = route_to_str(&gw, &mut tmp);
                        let start = (offset as usize).min(n);
                        return reply_read(msg.sender, &tmp[start..n]);
                    }
                }
                reply_read(msg.sender, b"none\n")
            }
            "resolve" => reply_read(msg.sender, b"use /net/resolve/<hostname>\n"),
            "tcp" => reply_read(msg.sender, b"use /net/tcp/listen/<port>\n"),
            p if p.starts_with("resolve/") => {
                let name = &p[8..];
                match self.resolve_hostname_blocking(name) {
                    Ok(addr) => {
                        let n = ipv4_addr_to_str(&addr, &mut tmp);
                        let start = (offset as usize).min(n);
                        reply_read(msg.sender, &tmp[start..n])
                    }
                    Err(e) => IpcMessage::error_reply(msg.sender, e),
                }
            }
            p if p.starts_with("ping/") => {
                if let Some((seq, rtt_us)) = self.ping_reply.take() {
                    let mut buf = [0u8; 10];
                    buf[0..2].copy_from_slice(&seq.to_le_bytes());
                    buf[2..10].copy_from_slice(&rtt_us.to_le_bytes());
                    let start = (offset as usize).min(buf.len());
                    reply_read(msg.sender, &buf[start..])
                } else {
                    reply_read(msg.sender, &[])
                }
            }
            _ => IpcMessage::error_reply(msg.sender, -9),
        }
    }

    fn handle_write(&mut self, msg: &IpcMessage) -> IpcMessage {
        let file_id = u64::from_le_bytes(msg.payload[0..8].try_into().unwrap_or([0u8; 8]));

        if let Some(listener) = self.tcp_listeners.get(&file_id).copied() {
            return self.handle_tcp_write(msg.sender, listener, msg);
        }

        let path = match self.open_handles.get(&file_id) {
            Some(p) => p.clone(),
            None => return IpcMessage::error_reply(msg.sender, -9),
        };

        if path.starts_with("ping/") {
            let ip_str = &path[5..];
            if let Some(target) = parse_ipv4(ip_str) {
                let data_len =
                    u16::from_le_bytes([msg.payload[16], msg.payload[17]]) as usize;
                let seq = if data_len >= 2 {
                    u16::from_le_bytes([msg.payload[18], msg.payload[19]])
                } else {
                    0
                };
                if self.send_ping(target, seq) {
                    return reply_write(msg.sender, data_len);
                }
                return IpcMessage::error_reply(msg.sender, -11); // EAGAIN
            }
            return IpcMessage::error_reply(msg.sender, -22);
        }

        IpcMessage::error_reply(msg.sender, -1) // EPERM
    }

    fn handle_close(&mut self, msg: &IpcMessage) -> IpcMessage {
        let file_id = u64::from_le_bytes(msg.payload[0..8].try_into().unwrap_or([0u8; 8]));
        self.open_handles.remove(&file_id);
        if let Some(listener) = self.tcp_listeners.remove(&file_id) {
            let _ = self.sockets.remove(listener.socket);
        }
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
        log("[strate-net] Starting DHCP...\n");

        loop {
            // 1. Drive the smoltcp stack (transmits queued packets, processes received ones)
            let now = now_instant();
            let poll_result = self
                .interface
                .poll(now, &mut self.device, &mut self.sockets);

            // 2. Check DHCP and ICMP state machines
            self.process_dhcp();
            self.process_icmp();

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

            // 4. Brief sleep when idle — capped to stay responsive to IPC
            if !got_ipc && poll_result == smoltcp::iface::PollResult::None {
                const MAX_SLEEP_US: u64 = 10_000; // 10 ms
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
    let _ = call::write(1, msg.as_bytes());
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

    let mut mac = [0u8; 6];
    if net_info(0, &mut mac).is_err() {
        log("[strate-net] No NIC found, using fallback MAC\n");
        mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    } else {
        log("[strate-net] MAC acquired from kernel\n");
    }

    let mut strate = NetworkStrate::new(mac);
    strate.serve(port);
}

fn log_error_code(e: strate_net::syscalls::Error) {
    use core::fmt::Write;
    let mut buf = [0u8; 32];
    let n = {
        let mut w = BufWriter { buf: &mut buf, pos: 0 };
        let _ = write!(w, "{}", e.to_errno());
        w.pos
    };
    if let Ok(s) = core::str::from_utf8(&buf[..n]) {
        log(s);
    }
}
