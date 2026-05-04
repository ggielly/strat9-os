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

alloc_freelist::define_freelist_brk_allocator!(
    pub struct BumpAllocator;
    brk = strat9_syscall::call::brk;
    heap_max = 16 * 1024 * 1024;
);

#[global_allocator]
static GLOBAL_ALLOCATOR: BumpAllocator = BumpAllocator;

#[alloc_error_handler]
/// Implements alloc error.
fn alloc_error(_layout: Layout) -> ! {
    let _ = call::debug_log(b"[strate-net] OOM\n");
    exit(12);
}

#[panic_handler]
/// Implements panic.
fn panic(info: &PanicInfo) -> ! {
    let _ = call::debug_log(b"[strate-net] PANIC: ");
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
        let _ = call::debug_log(&buf[..written]);
    }
    let _ = call::debug_log(b"\n");
    exit(255);
}

/// Minimal fmt::Write adapter over a fixed byte buffer.
struct BufWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl core::fmt::Write for BufWriter<'_> {
    /// Writes str.
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
    socket::{dhcpv4, dns, icmp, tcp, udp},
    time::Instant,
    wire::{DnsQueryType, EthernetAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address},
};

/// Implements icmp checksum.
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
static TX_SUCCESS_COUNT: AtomicUsize = AtomicUsize::new(0);
const NET_SEND_RETRY_LIMIT: usize = 64;

/// Implements log errno.
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

/// Implements now instant.
fn now_instant() -> Instant {
    match clock_gettime_ns() {
        Ok(ns) => Instant::from_micros((ns / NANOS_PER_MICRO) as i64),
        Err(_) => Instant::from_micros(0),
    }
}

/// Implements sleep micros.
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

    /// Implements receive.
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

    /// Implements transmit.
    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(Strat9TxToken)
    }

    /// Implements capabilities.
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
        let mut last_err = None;
        for attempt in 0..NET_SEND_RETRY_LIMIT {
            match net_send(&buf[..len]) {
                Ok(_) => {
                    TX_SUCCESS_COUNT.fetch_add(1, Ordering::Relaxed);
                    last_err = None;
                    break;
                }
                Err(e @ (Error::Again | Error::QueueFull)) => {
                    last_err = Some(e);
                    sleep_micros(1000);
                }
                Err(e @ Error::IoError) if attempt + 1 < NET_SEND_RETRY_LIMIT => {
                    last_err = Some(e);
                    sleep_micros(500);
                }
                Err(e) => {
                    last_err = Some(e);
                    break;
                }
            }
        }

        if let Some(e) = last_err {
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

/// Implements u8 to str.
fn u8_to_str(v: u8, buf: &mut [u8]) -> usize {
    use core::fmt::Write;
    let mut w = BufWriter { buf, pos: 0 };
    let _ = write!(w, "{}\n", v);
    w.pos
}

/// Implements mask from prefix.
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

/// Implements broadcast from host prefix.
fn broadcast_from_host_prefix(host: Ipv4Address, prefix: u8) -> Ipv4Address {
    let h = u32::from_be_bytes(host.octets());
    let m = u32::from_be_bytes(mask_from_prefix(prefix).octets());
    let b = (h & m) | (!m);
    let o = b.to_be_bytes();
    Ipv4Address::new(o[0], o[1], o[2], o[3])
}

/// Implements route to str.
fn route_to_str(gateway: &Ipv4Address, buf: &mut [u8]) -> usize {
    use core::fmt::Write;
    let mut w = BufWriter { buf, pos: 0 };
    let a = gateway.octets();
    let _ = write!(w, "default via {}.{}.{}.{}\n", a[0], a[1], a[2], a[3]);
    w.pos
}

/// Implements dns list to str.
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

/// Parses ipv4 cidr.
fn parse_ipv4_cidr(s: &str) -> Option<smoltcp::wire::Ipv4Cidr> {
    let slash = s.find('/')?;
    let ip = parse_ipv4(&s[..slash])?;
    let prefix = s[slash + 1..].parse::<u8>().ok()?;
    if prefix > 32 {
        return None;
    }
    Some(smoltcp::wire::Ipv4Cidr::new(ip, prefix))
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

/// Implements reply open.
fn reply_open(sender: u64, file_id: u64, size: u64, flags: u32) -> IpcMessage {
    let mut msg = IpcMessage::new(0x80);
    msg.sender = sender;
    msg.payload[0..4].copy_from_slice(&0u32.to_le_bytes());
    msg.payload[4..12].copy_from_slice(&file_id.to_le_bytes());
    msg.payload[12..20].copy_from_slice(&size.to_le_bytes());
    msg.payload[20..24].copy_from_slice(&flags.to_le_bytes());
    msg
}

/// Implements reply read.
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

/// Implements reply write.
fn reply_write(sender: u64, n: usize) -> IpcMessage {
    let mut msg = IpcMessage::new(0x80);
    msg.sender = sender;
    msg.payload[0..4].copy_from_slice(&0u32.to_le_bytes());
    msg.payload[4..8].copy_from_slice(&(n as u32).to_le_bytes());
    msg
}

/// Implements reply ok.
fn reply_ok(sender: u64) -> IpcMessage {
    let mut msg = IpcMessage::new(0x80);
    msg.sender = sender;
    msg.payload[0..4].copy_from_slice(&0u32.to_le_bytes());
    msg
}

/// Parses ipv4.
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
    auto_relisten: bool,
}

/// State for an outgoing TCP connection (`tcp/connect/<ip>/<port>`).
#[derive(Copy, Clone)]
struct TcpConnState {
    socket: SocketHandle,
    local_port: u16,
    remote: IpEndpoint,
}

/// State for a UDP scheme handle bound on a local port (`udp/bind/<port>`).
#[derive(Copy, Clone)]
struct UdpBoundState {
    socket: SocketHandle,
    local_port: u16,
}

/// State for a UDP scheme handle with a fixed remote endpoint
/// (`udp/connect/<ip>/<port>` or `udp/send/<ip>/<port>`).
#[derive(Copy, Clone)]
struct UdpConnState {
    socket: SocketHandle,
    local_port: u16,
    remote: IpEndpoint,
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
    tcp_connections: BTreeMap<u64, TcpConnState>,
    udp_bound: BTreeMap<u64, UdpBoundState>,
    udp_connections: BTreeMap<u64, UdpConnState>,
    next_fid: u64,
    /// Last ping that was sent, waiting for reply
    pending_ping: Option<PendingPing>,
    /// Received reply: (seq, rtt_us)
    ping_reply: Option<(u16, u64)>,
    ping_ident: u16,
    dhcp_enabled: bool,
}

impl NetworkStrate {
    /// Creates a new instance.
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
            tcp_connections: BTreeMap::new(),
            udp_bound: BTreeMap::new(),
            udp_connections: BTreeMap::new(),
            next_fid: 1,
            pending_ping: None,
            ping_reply: None,
            ping_ident: 0x9001,
            dhcp_enabled: true,
        }
    }

    fn clear_ipv4_runtime_config(&mut self) {
        self.ip_config = None;
        self.interface.update_ip_addrs(|addrs| addrs.clear());
        let _ = self.interface.routes_mut().remove_default_ipv4_route();
        self.refresh_dns_servers();
    }

    fn reset_dhcp_socket(&mut self) {
        self.sockets
            .get_mut::<dhcpv4::Socket>(self.dhcp_handle)
            .reset();
    }

    fn enable_dhcp(&mut self) {
        self.dhcp_enabled = true;
        self.clear_ipv4_runtime_config();
        self.reset_dhcp_socket();
    }

    /// Returns true if a local UDP port is already in use by an opened UDP handle.
    fn udp_port_in_use(&self, port: u16) -> bool {
        self.udp_bound.values().any(|s| s.local_port == port)
            || self.udp_connections.values().any(|s| s.local_port == port)
    }

    /// Allocates an ephemeral UDP local port from the dynamic range.
    fn alloc_udp_ephemeral_port(&self) -> Option<u16> {
        const BASE: u16 = 49_152;
        const COUNT: usize = 16_384;
        let start = (self.next_fid as usize) % COUNT;
        for step in 0..COUNT {
            let port = BASE + ((start + step) % COUNT) as u16;
            if !self.udp_port_in_use(port) {
                return Some(port);
            }
        }
        None
    }

    /// Creates and binds an internal UDP transport endpoint on `local_port`,
    /// then registers it in the smoltcp socket set.
    fn create_udp_socket(&mut self, local_port: u16) -> core::result::Result<SocketHandle, i32> {
        let rx_buf = udp::PacketBuffer::new(
            alloc::vec![udp::PacketMetadata::EMPTY; 16],
            alloc::vec![0u8; 4096],
        );
        let tx_buf = udp::PacketBuffer::new(
            alloc::vec![udp::PacketMetadata::EMPTY; 16],
            alloc::vec![0u8; 4096],
        );
        let mut socket = udp::Socket::new(rx_buf, tx_buf);
        if socket.bind(local_port).is_err() {
            return Err(-98); // EADDRINUSE
        }
        Ok(self.sockets.add(socket))
    }

    /// Returns a textual name for a TCP state.
    fn tcp_state_name(state: tcp::State) -> &'static str {
        match state {
            tcp::State::Closed => "CLOSED",
            tcp::State::Listen => "LISTEN",
            tcp::State::SynSent => "SYN-SENT",
            tcp::State::SynReceived => "SYN-RECEIVED",
            tcp::State::Established => "ESTABLISHED",
            tcp::State::FinWait1 => "FIN-WAIT-1",
            tcp::State::FinWait2 => "FIN-WAIT-2",
            tcp::State::CloseWait => "CLOSE-WAIT",
            tcp::State::Closing => "CLOSING",
            tcp::State::LastAck => "LAST-ACK",
            tcp::State::TimeWait => "TIME-WAIT",
        }
    }

    // -----------------------------------------------------------------------
    // DHCP event processing
    // -----------------------------------------------------------------------

    /// Implements process dhcp.
    fn process_dhcp(&mut self) {
        if !self.dhcp_enabled {
            return;
        }
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
                self.clear_ipv4_runtime_config();
            }
            None => {}
        }
    }

    /// Implements refresh dns servers.
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

    /// Implements apply ipv4 config.
    fn apply_ipv4_config(
        &mut self,
        address: smoltcp::wire::Ipv4Cidr,
        gateway: Option<Ipv4Address>,
        dns: [Option<Ipv4Address>; 3],
    ) {
        let host = address.address();
        let prefix_len = address.prefix_len();
        let netmask = mask_from_prefix(prefix_len);
        let broadcast = broadcast_from_host_prefix(host, prefix_len);

        self.interface.update_ip_addrs(|addrs| {
            let cidr = IpCidr::new(IpAddress::Ipv4(host), prefix_len);
            if let Some(slot) = addrs.iter_mut().next() {
                *slot = cidr;
            } else {
                let _ = addrs.push(cidr);
            }
        });

        let _ = self.interface.routes_mut().remove_default_ipv4_route();
        if let Some(gw) = gateway {
            let _ = self.interface.routes_mut().add_default_ipv4_route(gw);
        }

        self.ip_config = Some(IpConfig {
            address,
            host,
            prefix_len,
            netmask,
            broadcast,
            gateway,
            dns,
        });
        self.refresh_dns_servers();
    }

    /// Implements resolve hostname blocking.
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

        let deadline_ns = clock_gettime_ns()
            .unwrap_or(0)
            .saturating_add(3_000_000_000);
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
                        let IpAddress::Ipv4(v4) = addr;
                        return Ok(v4);
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

    /// Implements process icmp.
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

    /// Implements send ping.
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

    /// Implements handle open.
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
            | "routes" | "dns" | "resolve" | "ping" | "tcp" | "tcp/listeners"
            | "tcp/connections" | "tcp/stats" | "udp" | "dhcp" => {
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
            p if p.starts_with("tcp/connect/") => {
                let rest = &p[12..];
                let parts: alloc::vec::Vec<&str> = rest.split('/').collect();
                if parts.len() < 2 || parts.len() > 3 {
                    return IpcMessage::error_reply(msg.sender, -22);
                }
                let Some(ip) = parse_ipv4(parts[0]) else {
                    return IpcMessage::error_reply(msg.sender, -22);
                };
                let Some(port) = parts[1].parse::<u16>().ok() else {
                    return IpcMessage::error_reply(msg.sender, -22);
                };
                if port == 0 {
                    return IpcMessage::error_reply(msg.sender, -22);
                }

                let rx_buf = tcp::SocketBuffer::new(alloc::vec![0u8; 4096]);
                let tx_buf = tcp::SocketBuffer::new(alloc::vec![0u8; 4096]);
                let sock = tcp::Socket::new(rx_buf, tx_buf);
                let handle = self.sockets.add(sock);

                let local_port = if parts.len() == 3 {
                    let Some(lp) = parts[2].parse::<u16>().ok() else {
                        self.sockets.remove(handle);
                        return IpcMessage::error_reply(msg.sender, -22);
                    };
                    if lp == 0 {
                        self.sockets.remove(handle);
                        return IpcMessage::error_reply(msg.sender, -22);
                    }
                    lp
                } else {
                    49152 + (self.next_fid as u16 % 16384)
                };
                let remote = (smoltcp::wire::IpAddress::Ipv4(ip), port);
                let conn_socket = self.sockets.get_mut::<tcp::Socket>(handle);
                if conn_socket
                    .connect(self.interface.context(), remote, local_port)
                    .is_err()
                {
                    self.sockets.remove(handle);
                    return IpcMessage::error_reply(msg.sender, -111);
                }

                let fid = self.alloc_fid();
                self.open_handles.insert(fid, String::from(path));
                self.tcp_connections.insert(
                    fid,
                    TcpConnState {
                        socket: handle,
                        local_port,
                        remote: IpEndpoint::new(IpAddress::Ipv4(ip), port),
                    },
                );
                reply_open(msg.sender, fid, u64::MAX, 0)
            }
            p if p.starts_with("tcp/listen-once/") => {
                let port_str = &p[16..];
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
                self.tcp_listeners.insert(
                    fid,
                    TcpListenerState {
                        socket,
                        port,
                        auto_relisten: false,
                    },
                );
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
                self.tcp_listeners.insert(
                    fid,
                    TcpListenerState {
                        socket,
                        port,
                        auto_relisten: true,
                    },
                );
                reply_open(msg.sender, fid, u64::MAX, 0)
            }
            p if p.starts_with("udp/bind/") => {
                let port_str = &p[9..];
                let Some(port) = port_str.parse::<u16>().ok() else {
                    return IpcMessage::error_reply(msg.sender, -22);
                };
                if port == 0 || self.udp_port_in_use(port) {
                    return IpcMessage::error_reply(msg.sender, -98);
                }
                let Ok(socket) = self.create_udp_socket(port) else {
                    return IpcMessage::error_reply(msg.sender, -98);
                };

                let fid = self.alloc_fid();
                self.open_handles.insert(fid, String::from(path));
                self.udp_bound.insert(
                    fid,
                    UdpBoundState {
                        socket,
                        local_port: port,
                    },
                );
                reply_open(msg.sender, fid, u64::MAX, 0)
            }
            p if p.starts_with("udp/connect/") => {
                let rest = &p[12..];
                let parts: alloc::vec::Vec<&str> = rest.splitn(2, '/').collect();
                if parts.len() != 2 {
                    return IpcMessage::error_reply(msg.sender, -22);
                }
                let Some(ip) = parse_ipv4(parts[0]) else {
                    return IpcMessage::error_reply(msg.sender, -22);
                };
                let Some(remote_port) = parts[1].parse::<u16>().ok() else {
                    return IpcMessage::error_reply(msg.sender, -22);
                };
                if remote_port == 0 {
                    return IpcMessage::error_reply(msg.sender, -22);
                }

                let Some(local_port) = self.alloc_udp_ephemeral_port() else {
                    return IpcMessage::error_reply(msg.sender, -28); // ENOSPC
                };
                let Ok(socket) = self.create_udp_socket(local_port) else {
                    return IpcMessage::error_reply(msg.sender, -98);
                };

                let fid = self.alloc_fid();
                self.open_handles.insert(fid, String::from(path));
                self.udp_connections.insert(
                    fid,
                    UdpConnState {
                        socket,
                        local_port,
                        remote: IpEndpoint::new(IpAddress::Ipv4(ip), remote_port),
                    },
                );
                reply_open(msg.sender, fid, u64::MAX, 0)
            }
            p if p.starts_with("udp/send/") => {
                let rest = &p[9..];
                let parts: alloc::vec::Vec<&str> = rest.splitn(2, '/').collect();
                if parts.len() != 2 {
                    return IpcMessage::error_reply(msg.sender, -22);
                }
                let Some(ip) = parse_ipv4(parts[0]) else {
                    return IpcMessage::error_reply(msg.sender, -22);
                };
                let Some(remote_port) = parts[1].parse::<u16>().ok() else {
                    return IpcMessage::error_reply(msg.sender, -22);
                };
                if remote_port == 0 {
                    return IpcMessage::error_reply(msg.sender, -22);
                }

                let Some(local_port) = self.alloc_udp_ephemeral_port() else {
                    return IpcMessage::error_reply(msg.sender, -28); // ENOSPC
                };
                let Ok(socket) = self.create_udp_socket(local_port) else {
                    return IpcMessage::error_reply(msg.sender, -98);
                };

                let fid = self.alloc_fid();
                self.open_handles.insert(fid, String::from(path));
                self.udp_connections.insert(
                    fid,
                    UdpConnState {
                        socket,
                        local_port,
                        remote: IpEndpoint::new(IpAddress::Ipv4(ip), remote_port),
                    },
                );
                reply_open(msg.sender, fid, u64::MAX, 0)
            }
            p if p.starts_with("route/add/")
                || p.starts_with("route/del/")
                || p.starts_with("route/default/set/")
                || p == "route/default/clear" =>
            {
                let fid = self.alloc_fid();
                self.open_handles.insert(fid, String::from(path));
                reply_open(msg.sender, fid, u64::MAX, 0)
            }
            p if p.starts_with("ip/set/")
                || p.starts_with("dns/set/")
                || p == "dhcp/enable"
                || p == "dhcp/disable" =>
            {
                let fid = self.alloc_fid();
                self.open_handles.insert(fid, String::from(path));
                reply_open(msg.sender, fid, u64::MAX, 0)
            }
            _ => IpcMessage::error_reply(msg.sender, -2),
        }
    }

    /// Implements handle tcp read.
    fn handle_tcp_read(&mut self, sender: u64, listener: TcpListenerState) -> IpcMessage {
        let socket = self.sockets.get_mut::<tcp::Socket>(listener.socket);
        if !socket.is_open() || (!socket.is_listening() && !socket.is_active()) {
            if listener.auto_relisten {
                let _ = socket.listen(listener.port);
            } else {
                return IpcMessage::error_reply(sender, -104);
            }
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
            if listener.auto_relisten {
                let _ = socket.listen(listener.port);
            } else {
                return IpcMessage::error_reply(sender, -104);
            }
        }
        IpcMessage::error_reply(sender, -11)
    }

    /// Implements handle tcp write.
    fn handle_tcp_write(
        &mut self,
        sender: u64,
        listener: TcpListenerState,
        msg: &IpcMessage,
    ) -> IpcMessage {
        let socket = self.sockets.get_mut::<tcp::Socket>(listener.socket);
        if !socket.is_open() || (!socket.is_listening() && !socket.is_active()) {
            if listener.auto_relisten {
                let _ = socket.listen(listener.port);
            } else {
                return IpcMessage::error_reply(sender, -104);
            }
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

    /// Read from an outgoing TCP connection.
    fn handle_tcp_conn_read(&mut self, sender: u64, conn: TcpConnState) -> IpcMessage {
        let socket = self.sockets.get_mut::<tcp::Socket>(conn.socket);
        if !socket.is_open() {
            return IpcMessage::error_reply(sender, -104); // ECONNRESET
        }
        let state = socket.state();
        if state == tcp::State::SynSent || state == tcp::State::SynReceived {
            return IpcMessage::error_reply(sender, -115); // EINPROGRESS
        }
        let mut data = [0u8; 40];
        if socket.can_recv() {
            match socket.recv_slice(&mut data) {
                Ok(n) => reply_read(sender, &data[..n]),
                Err(_) => IpcMessage::error_reply(sender, -5),
            }
        } else {
            IpcMessage::error_reply(sender, -11) // EAGAIN
        }
    }

    /// Write to an outgoing TCP connection.
    fn handle_tcp_conn_write(
        &mut self,
        sender: u64,
        conn: TcpConnState,
        msg: &IpcMessage,
    ) -> IpcMessage {
        let socket = self.sockets.get_mut::<tcp::Socket>(conn.socket);
        if !socket.is_open() {
            return IpcMessage::error_reply(sender, -104);
        }
        let state = socket.state();
        if state == tcp::State::SynSent || state == tcp::State::SynReceived {
            return IpcMessage::error_reply(sender, -115); // EINPROGRESS
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

    /// Read from a UDP scheme handle bound on a local port.
    ///
    /// Returned bytes are encoded as:
    /// - [0..4]  source IPv4
    /// - [4..6]  source UDP port (big-endian)
    /// - [6..]   datagram payload (truncated to fit inline IPC reply)
    fn handle_udp_bound_read(&mut self, sender: u64, state: UdpBoundState) -> IpcMessage {
        let socket = self.sockets.get_mut::<udp::Socket>(state.socket);
        let Ok((data, meta)) = socket.recv() else {
            return IpcMessage::error_reply(sender, -11); // EAGAIN
        };

        let IpAddress::Ipv4(src_ip) = meta.endpoint.addr;

        // Layout: [src_ip: 4 bytes][src_port: 2 bytes][payload: up to 1472 bytes]
        let mut out = [0u8; 1478];
        out[0..4].copy_from_slice(&src_ip.octets());
        out[4..6].copy_from_slice(&meta.endpoint.port.to_be_bytes());
        let data_n = core::cmp::min(data.len(), out.len().saturating_sub(6));
        out[6..6 + data_n].copy_from_slice(&data[..data_n]);
        reply_read(sender, &out[..6 + data_n])
    }

    /// Write to a bound UDP scheme handle is not supported directly.
    ///
    /// Use `/net/udp/connect/<ip>/<port>` for bidirectional traffic or
    /// `/net/udp/send/<ip>/<port>` for datagram sends with a fixed peer.
    fn handle_udp_bound_write(
        &mut self,
        sender: u64,
        state: UdpBoundState,
        msg: &IpcMessage,
    ) -> IpcMessage {
        let _ = state;
        let _ = msg;
        IpcMessage::error_reply(sender, -95) // EOPNOTSUPP
    }

    /// Read from a connected UDP scheme handle.
    fn handle_udp_conn_read(&mut self, sender: u64, conn: UdpConnState) -> IpcMessage {
        let socket = self.sockets.get_mut::<udp::Socket>(conn.socket);
        while socket.can_recv() {
            let Ok((data, meta)) = socket.recv() else {
                break;
            };
            if meta.endpoint.addr == conn.remote.addr && meta.endpoint.port == conn.remote.port {
                let n = core::cmp::min(data.len(), 1472); // max UDP payload at 1500-byte MTU
                return reply_read(sender, &data[..n]);
            }
        }
        IpcMessage::error_reply(sender, -11) // EAGAIN
    }

    /// Write to a connected UDP scheme handle.
    fn handle_udp_conn_write(
        &mut self,
        sender: u64,
        conn: UdpConnState,
        msg: &IpcMessage,
    ) -> IpcMessage {
        let socket = self.sockets.get_mut::<udp::Socket>(conn.socket);
        let data_len = u16::from_le_bytes([msg.payload[16], msg.payload[17]]) as usize;
        let data_len = core::cmp::min(data_len, msg.payload.len().saturating_sub(18));
        let data = &msg.payload[18..18 + data_len];
        if !socket.can_send() {
            return IpcMessage::error_reply(sender, -11);
        }
        match socket.send_slice(data, conn.remote) {
            Ok(()) => reply_write(sender, data_len),
            Err(udp::SendError::BufferFull) => IpcMessage::error_reply(sender, -11),
            Err(udp::SendError::Unaddressable) => IpcMessage::error_reply(sender, -22),
        }
    }

    /// Implements handle read.
    fn handle_read(&mut self, msg: &IpcMessage) -> IpcMessage {
        let file_id = u64::from_le_bytes(msg.payload[0..8].try_into().unwrap_or([0u8; 8]));
        let offset = u64::from_le_bytes(msg.payload[8..16].try_into().unwrap_or([0u8; 8]));

        if let Some(listener) = self.tcp_listeners.get(&file_id).copied() {
            return self.handle_tcp_read(msg.sender, listener);
        }
        if let Some(conn) = self.tcp_connections.get(&file_id).copied() {
            return self.handle_tcp_conn_read(msg.sender, conn);
        }
        if let Some(state) = self.udp_bound.get(&file_id).copied() {
            return self.handle_udp_bound_read(msg.sender, state);
        }
        if let Some(conn) = self.udp_connections.get(&file_id).copied() {
            return self.handle_udp_conn_read(msg.sender, conn);
        }

        let path = match self.open_handles.get(&file_id) {
            Some(p) => p.clone(),
            None => return IpcMessage::error_reply(msg.sender, -9),
        };

        let mut tmp = [0u8; 64];

        match path.as_str() {
            "" => {
                let listing =
                    b"ip\naddress\nprefix\nnetmask\nbroadcast\ngateway\nroute\nroutes\ndns\ndhcp\nresolve\nping\ntcp\nudp\n";
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
            "dhcp" => {
                if self.dhcp_enabled {
                    reply_read(msg.sender, b"on\n")
                } else {
                    reply_read(msg.sender, b"off\n")
                }
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
            "routes" => {
                use core::fmt::Write;
                let mut out = [0u8; 256];
                let n = {
                    let mut w = BufWriter {
                        buf: &mut out,
                        pos: 0,
                    };
                    let mut any = false;
                    self.interface.routes_mut().update(|table| {
                        for r in table.iter() {
                            let (IpCidr::Ipv4(c), IpAddress::Ipv4(gw)) = (r.cidr, r.via_router);
                            let ca = c.address().octets();
                            let ga = gw.octets();
                            let _ = write!(
                                w,
                                "{}.{}.{}.{}/{} via {}.{}.{}.{}\n",
                                ca[0],
                                ca[1],
                                ca[2],
                                ca[3],
                                c.prefix_len(),
                                ga[0],
                                ga[1],
                                ga[2],
                                ga[3]
                            );
                            any = true;
                        }
                    });
                    if !any {
                        let _ = write!(w, "none\n");
                    }
                    w.pos
                };
                let start = (offset as usize).min(n);
                reply_read(msg.sender, &out[start..n])
            }
            "resolve" => reply_read(msg.sender, b"use /net/resolve/<hostname>\n"),
            "tcp" => reply_read(
                msg.sender,
                b"use /net/tcp/listen/<port>, /net/tcp/listen-once/<port>, /net/tcp/connect/<ip>/<port>[/<local_port>], /net/tcp/listeners, /net/tcp/connections, /net/tcp/stats\n",
            ),
            "tcp/listeners" => {
                use core::fmt::Write;
                let mut out = [0u8; 512];
                let n = {
                    let mut w = BufWriter {
                        buf: &mut out,
                        pos: 0,
                    };
                    if self.tcp_listeners.is_empty() {
                        let _ = write!(w, "none\n");
                    } else {
                        for (fid, listener) in self.tcp_listeners.iter() {
                            let socket = self.sockets.get::<tcp::Socket>(listener.socket);
                            let mode = if listener.auto_relisten { "auto" } else { "once" };
                            let _ = write!(
                                w,
                                "fid={} port={} state={} mode={}\n",
                                fid,
                                listener.port,
                                Self::tcp_state_name(socket.state()),
                                mode
                            );
                        }
                    }
                    w.pos
                };
                let start = (offset as usize).min(n);
                reply_read(msg.sender, &out[start..n])
            }
            "tcp/connections" => {
                use core::fmt::Write;
                let mut out = [0u8; 768];
                let n = {
                    let mut w = BufWriter {
                        buf: &mut out,
                        pos: 0,
                    };
                    if self.tcp_connections.is_empty() {
                        let _ = write!(w, "none\n");
                    } else {
                        for (fid, conn) in self.tcp_connections.iter() {
                            let socket = self.sockets.get::<tcp::Socket>(conn.socket);
                            let local = socket.local_endpoint();
                            let remote = socket.remote_endpoint();
                            match (local, remote) {
                                (Some(l), Some(r)) => {
                                    let _ = write!(
                                        w,
                                        "fid={} local={} remote={} state={}\n",
                                        fid,
                                        l,
                                        r,
                                        Self::tcp_state_name(socket.state())
                                    );
                                }
                                _ => {
                                    let _ = write!(
                                        w,
                                        "fid={} local_port={} remote={} state={}\n",
                                        fid,
                                        conn.local_port,
                                        conn.remote,
                                        Self::tcp_state_name(socket.state())
                                    );
                                }
                            }
                        }
                    }
                    w.pos
                };
                let start = (offset as usize).min(n);
                reply_read(msg.sender, &out[start..n])
            }
            "tcp/stats" => {
                use core::fmt::Write;
                let mut out = [0u8; 256];
                let n = {
                    let mut w = BufWriter {
                        buf: &mut out,
                        pos: 0,
                    };
                    let listeners = self.tcp_listeners.len();
                    let connections = self.tcp_connections.len();
                    let mut established = 0usize;
                    let mut connecting = 0usize;
                    let mut closing = 0usize;
                    for conn in self.tcp_connections.values() {
                        let socket = self.sockets.get::<tcp::Socket>(conn.socket);
                        match socket.state() {
                            tcp::State::Established => established += 1,
                            tcp::State::SynSent | tcp::State::SynReceived => connecting += 1,
                            tcp::State::Closed => {}
                            _ => closing += 1,
                        }
                    }
                    let _ = write!(
                        w,
                        "listeners={}\nconnections={}\nestablished={}\nconnecting={}\nclosing={}\n",
                        listeners,
                        connections,
                        established,
                        connecting,
                        closing
                    );
                    w.pos
                };
                let start = (offset as usize).min(n);
                reply_read(msg.sender, &out[start..n])
            }
            "udp" => reply_read(
                msg.sender,
                b"use /net/udp/bind/<port>, /net/udp/connect/<ip>/<port> or /net/udp/send/<ip>/<port>\n",
            ),
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

    /// Implements handle write.
    fn handle_write(&mut self, msg: &IpcMessage) -> IpcMessage {
        let file_id = u64::from_le_bytes(msg.payload[0..8].try_into().unwrap_or([0u8; 8]));

        if let Some(listener) = self.tcp_listeners.get(&file_id).copied() {
            return self.handle_tcp_write(msg.sender, listener, msg);
        }
        if let Some(conn) = self.tcp_connections.get(&file_id).copied() {
            return self.handle_tcp_conn_write(msg.sender, conn, msg);
        }
        if let Some(state) = self.udp_bound.get(&file_id).copied() {
            return self.handle_udp_bound_write(msg.sender, state, msg);
        }
        if let Some(conn) = self.udp_connections.get(&file_id).copied() {
            return self.handle_udp_conn_write(msg.sender, conn, msg);
        }

        let path = match self.open_handles.get(&file_id) {
            Some(p) => p.clone(),
            None => return IpcMessage::error_reply(msg.sender, -9),
        };

        if path.starts_with("ping/") {
            let ip_str = &path[5..];
            if let Some(target) = parse_ipv4(ip_str) {
                let data_len = u16::from_le_bytes([msg.payload[16], msg.payload[17]]) as usize;
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

        if let Some(cidr_s) = path.strip_prefix("ip/set/") {
            let Some(cidr) = parse_ipv4_cidr(cidr_s) else {
                return IpcMessage::error_reply(msg.sender, -22);
            };
            self.dhcp_enabled = false;
            let (gateway, dns) = if let Some(ref cfg) = self.ip_config {
                (cfg.gateway, cfg.dns)
            } else {
                (None, [None; 3])
            };
            self.apply_ipv4_config(cidr, gateway, dns);
            let data_len = u16::from_le_bytes([msg.payload[16], msg.payload[17]]) as usize;
            return reply_write(msg.sender, data_len);
        }

        if let Some(rest) = path.strip_prefix("dns/set/") {
            let mut parts = rest.split('/');
            let Some(idx_s) = parts.next() else {
                return IpcMessage::error_reply(msg.sender, -22);
            };
            let Some(ip_s) = parts.next() else {
                return IpcMessage::error_reply(msg.sender, -22);
            };
            if parts.next().is_some() {
                return IpcMessage::error_reply(msg.sender, -22);
            }
            let Some(idx) = idx_s.parse::<usize>().ok() else {
                return IpcMessage::error_reply(msg.sender, -22);
            };
            if idx >= 3 {
                return IpcMessage::error_reply(msg.sender, -22);
            }
            let Some(ip) = parse_ipv4(ip_s) else {
                return IpcMessage::error_reply(msg.sender, -22);
            };
            let Some(ref mut cfg) = self.ip_config else {
                return IpcMessage::error_reply(msg.sender, -11);
            };
            self.dhcp_enabled = false;
            cfg.dns[idx] = if ip == Ipv4Address::new(0, 0, 0, 0) {
                None
            } else {
                Some(ip)
            };
            self.refresh_dns_servers();
            let data_len = u16::from_le_bytes([msg.payload[16], msg.payload[17]]) as usize;
            return reply_write(msg.sender, data_len);
        }

        if path == "dhcp/enable" {
            self.enable_dhcp();
            let data_len = u16::from_le_bytes([msg.payload[16], msg.payload[17]]) as usize;
            return reply_write(msg.sender, data_len);
        }

        if path == "dhcp/disable" {
            self.dhcp_enabled = false;
            let data_len = u16::from_le_bytes([msg.payload[16], msg.payload[17]]) as usize;
            return reply_write(msg.sender, data_len);
        }

        if let Some(rest) = path.strip_prefix("route/add/") {
            let mut parts = rest.split('/');
            let Some(cidr_s) = parts.next() else {
                return IpcMessage::error_reply(msg.sender, -22);
            };
            let Some(gw_s) = parts.next() else {
                return IpcMessage::error_reply(msg.sender, -22);
            };
            if parts.next().is_some() {
                return IpcMessage::error_reply(msg.sender, -22);
            }
            let Some(cidr) = parse_ipv4_cidr(cidr_s) else {
                return IpcMessage::error_reply(msg.sender, -22);
            };
            let Some(gw) = parse_ipv4(gw_s) else {
                return IpcMessage::error_reply(msg.sender, -22);
            };
            let mut full = false;
            self.interface.routes_mut().update(|table| {
                if let Some((idx, _)) = table
                    .iter()
                    .enumerate()
                    .find(|(_, r)| r.cidr == IpCidr::Ipv4(cidr))
                {
                    let _ = table.remove(idx);
                }
                if table
                    .push(smoltcp::iface::Route {
                        cidr: IpCidr::Ipv4(cidr),
                        via_router: IpAddress::Ipv4(gw),
                        preferred_until: None,
                        expires_at: None,
                    })
                    .is_err()
                {
                    full = true;
                }
            });
            if full {
                return IpcMessage::error_reply(msg.sender, -28);
            }
            let data_len = u16::from_le_bytes([msg.payload[16], msg.payload[17]]) as usize;
            return reply_write(msg.sender, data_len);
        }

        if let Some(rest) = path.strip_prefix("route/del/") {
            let Some(cidr) = parse_ipv4_cidr(rest) else {
                return IpcMessage::error_reply(msg.sender, -22);
            };
            let mut removed = false;
            self.interface.routes_mut().update(|table| {
                if let Some((idx, _)) = table
                    .iter()
                    .enumerate()
                    .find(|(_, r)| r.cidr == IpCidr::Ipv4(cidr))
                {
                    let _ = table.remove(idx);
                    removed = true;
                }
            });
            if !removed {
                return IpcMessage::error_reply(msg.sender, -2);
            }
            let data_len = u16::from_le_bytes([msg.payload[16], msg.payload[17]]) as usize;
            return reply_write(msg.sender, data_len);
        }

        if let Some(gw_s) = path.strip_prefix("route/default/set/") {
            let Some(gw) = parse_ipv4(gw_s) else {
                return IpcMessage::error_reply(msg.sender, -22);
            };
            if self
                .interface
                .routes_mut()
                .add_default_ipv4_route(gw)
                .is_err()
            {
                return IpcMessage::error_reply(msg.sender, -28);
            }
            if let Some(ref mut cfg) = self.ip_config {
                cfg.gateway = Some(gw);
            }
            let data_len = u16::from_le_bytes([msg.payload[16], msg.payload[17]]) as usize;
            return reply_write(msg.sender, data_len);
        }

        if path == "route/default/clear" {
            let _ = self.interface.routes_mut().remove_default_ipv4_route();
            if let Some(ref mut cfg) = self.ip_config {
                cfg.gateway = None;
            }
            let data_len = u16::from_le_bytes([msg.payload[16], msg.payload[17]]) as usize;
            return reply_write(msg.sender, data_len);
        }

        IpcMessage::error_reply(msg.sender, -1) // EPERM
    }

    /// Implements handle close.
    fn handle_close(&mut self, msg: &IpcMessage) -> IpcMessage {
        let file_id = u64::from_le_bytes(msg.payload[0..8].try_into().unwrap_or([0u8; 8]));
        self.open_handles.remove(&file_id);
        if let Some(listener) = self.tcp_listeners.remove(&file_id) {
            let _ = self.sockets.remove(listener.socket);
        }
        if let Some(conn) = self.tcp_connections.remove(&file_id) {
            let sock = self.sockets.get_mut::<tcp::Socket>(conn.socket);
            sock.close();
            self.sockets.remove(conn.socket);
        }
        if let Some(state) = self.udp_bound.remove(&file_id) {
            let sock = self.sockets.get_mut::<udp::Socket>(state.socket);
            sock.close();
            self.sockets.remove(state.socket);
        }
        if let Some(conn) = self.udp_connections.remove(&file_id) {
            let sock = self.sockets.get_mut::<udp::Socket>(conn.socket);
            sock.close();
            self.sockets.remove(conn.socket);
        }
        reply_ok(msg.sender)
    }

    /// Implements alloc fid.
    fn alloc_fid(&mut self) -> u64 {
        let id = self.next_fid;
        self.next_fid += 1;
        id
    }

    // -----------------------------------------------------------------------
    // Main event loop
    // -----------------------------------------------------------------------

    /// Implements serve.
    fn serve(&mut self, port: u64) -> ! {
        log("[strate-net] Starting DHCP...\n");
        self.enable_dhcp();

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

            // 4. Brief sleep when idle : capped to stay responsive to IPC
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

/// Implements log.
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
/// Implements start.
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

/// Implements log error code.
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
