use alloc::{collections::BTreeMap, string::String};

use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    socket::{dhcpv4, dns, icmp, tcp, udp},
    time::Instant,
    wire::{EthernetAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address, Ipv6Address},
};
use strate_net::IpcMessage;

use crate::{
    device::Strat9NetDevice,
    ip::{link_local_from_mac, IpConfig, Ipv6Config},
    ipc::reply_read,
};

pub(crate) const PING_TIMEOUT_NS: u64 = 5_000_000_000;

pub(crate) struct PendingPing {
    pub(crate) seq: u16,
    pub(crate) token: u64,
    pub(crate) send_ts_ns: u64,
    pub(crate) is_v6: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct TcpListenerState {
    pub(crate) socket: SocketHandle,
    pub(crate) port: u16,
    pub(crate) auto_relisten: bool,
}

#[derive(Copy, Clone)]
pub(crate) struct TcpConnState {
    pub(crate) socket: SocketHandle,
    pub(crate) local_port: u16,
    pub(crate) remote: IpEndpoint,
}

#[derive(Copy, Clone)]
pub(crate) struct UdpBoundState {
    pub(crate) socket: SocketHandle,
    pub(crate) local_port: u16,
    pub(crate) last_peer: Option<IpEndpoint>,
}

#[derive(Copy, Clone)]
pub(crate) struct UdpConnState {
    pub(crate) socket: SocketHandle,
    pub(crate) local_port: u16,
    pub(crate) remote: IpEndpoint,
}

pub(crate) struct OpenedFile {
    pub(crate) path: String,
    pub(crate) cached_content: Option<alloc::vec::Vec<u8>>,
    pub(crate) read_spill: Option<alloc::vec::Vec<u8>>,
}

impl OpenedFile {
    pub(crate) fn new(path: &str) -> Self {
        Self {
            path: String::from(path),
            cached_content: None,
            read_spill: None,
        }
    }
}

pub(crate) struct NetworkStrate {
    pub(crate) device: Strat9NetDevice,
    pub(crate) interface: Interface,
    pub(crate) sockets: SocketSet<'static>,
    pub(crate) dhcp_handle: SocketHandle,
    pub(crate) dns_handle: SocketHandle,
    pub(crate) icmp_handle: SocketHandle,
    pub(crate) ip_config: Option<IpConfig>,
    pub(crate) ipv6_config: Option<Ipv6Config>,
    pub(crate) dns_servers: [Option<IpAddress>; 3],
    pub(crate) dns_from_dhcp: bool,
    pub(crate) link_local_addr: Ipv6Address,
    pub(crate) open_handles: BTreeMap<u64, OpenedFile>,
    pub(crate) tcp_listeners: BTreeMap<u64, TcpListenerState>,
    pub(crate) tcp_connections: BTreeMap<u64, TcpConnState>,
    pub(crate) udp_bound: BTreeMap<u64, UdpBoundState>,
    pub(crate) udp_connections: BTreeMap<u64, UdpConnState>,
    pub(crate) lingering_sockets: alloc::vec::Vec<SocketHandle>,
    pub(crate) next_fid: u64,
    pub(crate) ping_ident: u16,
    pub(crate) next_ping_token: u64,
    pub(crate) pending_pings: alloc::vec::Vec<PendingPing>,
    pub(crate) ping_replies: alloc::vec::Vec<(u16, u64)>,
    pub(crate) dhcp_enabled: bool,
}

impl NetworkStrate {
    pub(crate) fn new(mac: [u8; 6]) -> Self {
        let mut device = Strat9NetDevice;
        let config = Config::new(EthernetAddress(mac).into());
        let mut interface = Interface::new(config, &mut device, Instant::from_micros(0));
        let mut sockets = SocketSet::new(alloc::vec![]);

        let link_local = link_local_from_mac(mac);
        interface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(link_local), 64));
        });

        let dhcp_socket = dhcpv4::Socket::new();
        let dhcp_handle = sockets.add(dhcp_socket);

        let dns_socket = dns::Socket::new(&[], alloc::vec![]);
        let dns_handle = sockets.add(dns_socket);

        let icmp_rx_buf = icmp::PacketBuffer::new(
            alloc::vec![icmp::PacketMetadata::EMPTY; 16],
            alloc::vec![0u8; 4096],
        );
        let icmp_tx_buf = icmp::PacketBuffer::new(
            alloc::vec![icmp::PacketMetadata::EMPTY; 16],
            alloc::vec![0u8; 4096],
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
            ipv6_config: None,
            dns_servers: [None; 3],
            dns_from_dhcp: false,
            link_local_addr: link_local,
            open_handles: BTreeMap::new(),
            tcp_listeners: BTreeMap::new(),
            tcp_connections: BTreeMap::new(),
            udp_bound: BTreeMap::new(),
            udp_connections: BTreeMap::new(),
            lingering_sockets: alloc::vec::Vec::new(),
            next_fid: 1,
            ping_ident: 0x9001,
            next_ping_token: 1,
            pending_pings: alloc::vec::Vec::new(),
            ping_replies: alloc::vec::Vec::new(),
            dhcp_enabled: true,
        }
    }

    pub(crate) fn clear_ipv4_runtime_config(&mut self) {
        self.ip_config = None;
        self.interface.update_ip_addrs(|addrs| {
            let mut kept = [IpCidr::new(IpAddress::Ipv4(Ipv4Address::UNSPECIFIED), 0); 8];
            let mut n = 0usize;
            for addr in addrs.iter() {
                if matches!(addr, IpCidr::Ipv6(_)) && n < kept.len() {
                    kept[n] = *addr;
                    n += 1;
                }
            }
            addrs.clear();
            for addr in kept.into_iter().take(n) {
                let _ = addrs.push(addr);
            }
        });
        let _ = self.interface.routes_mut().remove_default_ipv4_route();
        self.refresh_dns_servers();
    }

    pub(crate) fn drain_spilled_read(
        &mut self,
        sender: u64,
        file_id: u64,
        requested: usize,
    ) -> Option<IpcMessage> {
        let max_inline = requested.min(IpcMessage::READ_INLINE_CAPACITY);
        let mut spill = self.open_handles.get_mut(&file_id)?.read_spill.take()?;
        if spill.len() > max_inline {
            let rest = spill.split_off(max_inline);
            if let Some(handle) = self.open_handles.get_mut(&file_id) {
                handle.read_spill = Some(rest);
            }
        }
        Some(reply_read(sender, &spill))
    }

    pub(crate) fn reply_read_spilling(
        &mut self,
        sender: u64,
        file_id: u64,
        requested: usize,
        mut data: alloc::vec::Vec<u8>,
    ) -> IpcMessage {
        let max_inline = requested.min(IpcMessage::READ_INLINE_CAPACITY);
        if data.len() > max_inline {
            let rest = data.split_off(max_inline);
            if let Some(handle) = self.open_handles.get_mut(&file_id) {
                handle.read_spill = Some(rest);
            }
        }
        reply_read(sender, &data)
    }

    pub(crate) fn reset_dhcp_socket(&mut self) {
        self.sockets
            .get_mut::<dhcpv4::Socket>(self.dhcp_handle)
            .reset();
    }

    pub(crate) fn enable_dhcp(&mut self) {
        self.dhcp_enabled = true;
        self.dns_servers = [None; 3];
        self.dns_from_dhcp = false;
        self.clear_ipv4_runtime_config();
        self.reset_dhcp_socket();
    }

    pub(crate) fn alloc_ping_token(&mut self) -> u64 {
        let token = self.next_ping_token;
        self.next_ping_token = self.next_ping_token.wrapping_add(1);
        token
    }

    pub(crate) fn udp_port_in_use(&self, port: u16) -> bool {
        self.udp_bound
            .values()
            .any(|state| state.local_port == port)
            || self
                .udp_connections
                .values()
                .any(|state| state.local_port == port)
    }

    pub(crate) fn alloc_udp_ephemeral_port(&self) -> Option<u16> {
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

    pub(crate) fn create_udp_socket(
        &mut self,
        local_port: u16,
    ) -> core::result::Result<SocketHandle, i32> {
        let rx_buf = udp::PacketBuffer::new(
            alloc::vec![udp::PacketMetadata::EMPTY; 32],
            alloc::vec![0u8; 65536],
        );
        let tx_buf = udp::PacketBuffer::new(
            alloc::vec![udp::PacketMetadata::EMPTY; 32],
            alloc::vec![0u8; 65536],
        );
        let mut socket = udp::Socket::new(rx_buf, tx_buf);
        if socket.bind(local_port).is_err() {
            return Err(-98);
        }
        Ok(self.sockets.add(socket))
    }

    pub(crate) fn tcp_state_name(state: tcp::State) -> &'static str {
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

    pub(crate) fn alloc_fid(&mut self) -> u64 {
        let id = self.next_fid;
        self.next_fid += 1;
        id
    }
}
