use alloc::vec::Vec;
use strate_net::syscalls::call;

use smoltcp::{
    iface::Route,
    socket::{tcp, udp},
    wire::{IpAddress, IpEndpoint, Ipv4Address},
};
use strat9_syscall::data::IPC_FILE_FLAG_DIRECTORY;
use strate_net::IpcMessage;

use crate::{
    ip::{parse_ip, parse_ip_cidr, parse_ipv4, parse_ipv4_cidr, parse_ipv6, parse_ipv6_cidr},
    ipc::{
        message_file_id, open_path, read_request, reply_ok, reply_open, reply_read, reply_write,
        reply_write_data_len, write_data, HANDLE_FLAG_CONTROL, HANDLE_FLAG_DATAGRAM,
        HANDLE_FLAG_INFO, HANDLE_FLAG_STREAM,
    },
    state::{
        NetworkStrate, OpenedFile, TcpConnState, TcpListenerState, UdpBoundState, UdpConnState,
    },
};

impl NetworkStrate {
    fn insert_open_handle(&mut self, sender: u64, path: &str) -> u64 {
        let fid = self.new_fid(sender);
        self.open_handles.insert(fid, OpenedFile::new(path));
        fid
    }

    fn reply_open_path(&mut self, sender: u64, path: &str, flags: u32) -> IpcMessage {
        let fid = self.insert_open_handle(sender, path);
        reply_open(sender, fid, u64::MAX, flags)
    }

    fn open_tcp_listener_handle(
        &mut self,
        sender: u64,
        path: &str,
        port: u16,
        auto_relisten: bool,
    ) -> IpcMessage {
        let rx_buf = tcp::SocketBuffer::new(alloc::vec![0u8; 16384]);
        let tx_buf = tcp::SocketBuffer::new(alloc::vec![0u8; 16384]);
        let mut socket = tcp::Socket::new(rx_buf, tx_buf);
        if socket.listen(port).is_err() {
            return IpcMessage::error_reply(sender, -98);
        }
        let socket = self.sockets.add(socket);
        let fid = self.insert_open_handle(sender, path);
        self.tcp_listeners.insert(
            fid,
            TcpListenerState {
                socket,
                port,
                auto_relisten,
            },
        );
        reply_open(sender, fid, u64::MAX, HANDLE_FLAG_STREAM)
    }

    fn open_tcp_connection_handle(
        &mut self,
        sender: u64,
        path: &str,
        remote_ip: IpAddress,
        remote_port: u16,
        local_port: u16,
    ) -> IpcMessage {
        let rx_buf = tcp::SocketBuffer::new(alloc::vec![0u8; 16384]);
        let tx_buf = tcp::SocketBuffer::new(alloc::vec![0u8; 16384]);
        let socket = tcp::Socket::new(rx_buf, tx_buf);
        let handle = self.sockets.add(socket);
        if self
            .sockets
            .get_mut::<tcp::Socket>(handle)
            .connect(
                self.interface.context(),
                (remote_ip, remote_port),
                local_port,
            )
            .is_err()
        {
            self.sockets.remove(handle);
            return IpcMessage::error_reply(sender, -111);
        }

        let fid = self.insert_open_handle(sender, path);
        self.tcp_connections.insert(
            fid,
            TcpConnState {
                socket: handle,
                local_port,
                remote: IpEndpoint::new(remote_ip, remote_port),
            },
        );
        reply_open(sender, fid, u64::MAX, HANDLE_FLAG_STREAM)
    }

    fn open_udp_connection_handle(
        &mut self,
        sender: u64,
        path: &str,
        remote: IpEndpoint,
    ) -> IpcMessage {
        let Some(local_port) = self.alloc_udp_ephemeral_port() else {
            return IpcMessage::error_reply(sender, -28);
        };
        let Ok(socket) = self.create_udp_socket(local_port) else {
            return IpcMessage::error_reply(sender, -98);
        };

        let fid = self.insert_open_handle(sender, path);
        self.udp_connections.insert(
            fid,
            UdpConnState {
                socket,
                local_port,
                remote,
            },
        );
        reply_open(sender, fid, u64::MAX, HANDLE_FLAG_DATAGRAM)
    }

    pub(crate) fn handle_open(&mut self, msg: &IpcMessage) -> IpcMessage {
        let path = match open_path(msg) {
            Ok(path) => path,
            Err(err) => return IpcMessage::error_reply(msg.sender, err),
        };

        match path {
            "" => {
                let fid = self.insert_open_handle(msg.sender, "");
                reply_open(msg.sender, fid, u64::MAX, IPC_FILE_FLAG_DIRECTORY)
            }
            "ip" | "address" | "prefix" | "netmask" | "broadcast" | "gateway" | "route"
            | "routes" | "dns" | "resolve" | "ping" | "tcp" | "tcp/listeners"
            | "tcp/connections" | "tcp/stats" | "udp" | "dhcp" | "ip6" | "ip6/address"
            | "ip6/gateway" => self.reply_open_path(msg.sender, path, HANDLE_FLAG_INFO),
            path if path.starts_with("resolve/") => {
                if path.len() <= 8 {
                    return IpcMessage::error_reply(msg.sender, -22);
                }
                self.reply_open_path(msg.sender, path, HANDLE_FLAG_INFO)
            }
            path if path.starts_with("ping/") => {
                if parse_ipv4(&path[5..]).is_none() {
                    return IpcMessage::error_reply(msg.sender, -22);
                }
                self.reply_open_path(msg.sender, path, HANDLE_FLAG_CONTROL)
            }
            path if path.starts_with("ping6/") => {
                if parse_ipv6(&path[6..]).is_none() {
                    return IpcMessage::error_reply(msg.sender, -22);
                }
                self.reply_open_path(msg.sender, path, HANDLE_FLAG_CONTROL)
            }
            path if path.starts_with("tcp/connect/") => {
                let rest = &path[12..];
                let parts: Vec<&str> = rest.split('/').collect();
                if parts.len() < 2 || parts.len() > 3 {
                    return IpcMessage::error_reply(msg.sender, -22);
                }
                let Some(remote_ip) = parse_ip(parts[0]) else {
                    return IpcMessage::error_reply(msg.sender, -22);
                };
                let Some(remote_port) = parts[1].parse::<u16>().ok() else {
                    return IpcMessage::error_reply(msg.sender, -22);
                };
                if remote_port == 0 {
                    return IpcMessage::error_reply(msg.sender, -22);
                }
                let local_port = if parts.len() == 3 {
                    let Some(local_port) = parts[2].parse::<u16>().ok() else {
                        return IpcMessage::error_reply(msg.sender, -22);
                    };
                    if local_port == 0 {
                        return IpcMessage::error_reply(msg.sender, -22);
                    }
                    local_port
                } else {
                    49152 + (self.next_fid as u16 % 16384)
                };
                self.open_tcp_connection_handle(
                    msg.sender,
                    path,
                    remote_ip,
                    remote_port,
                    local_port,
                )
            }
            path if path.starts_with("tcp/listen-once/") => {
                let Some(port) = path[16..].parse::<u16>().ok() else {
                    return IpcMessage::error_reply(msg.sender, -22);
                };
                if port == 0 {
                    return IpcMessage::error_reply(msg.sender, -22);
                }
                self.open_tcp_listener_handle(msg.sender, path, port, false)
            }
            path if path.starts_with("tcp/listen/") => {
                let Some(port) = path[11..].parse::<u16>().ok() else {
                    return IpcMessage::error_reply(msg.sender, -22);
                };
                if port == 0 {
                    return IpcMessage::error_reply(msg.sender, -22);
                }
                self.open_tcp_listener_handle(msg.sender, path, port, true)
            }
            path if path.starts_with("udp/bind/") => {
                let Some(port) = path[9..].parse::<u16>().ok() else {
                    return IpcMessage::error_reply(msg.sender, -22);
                };
                if port == 0 || self.udp_port_in_use(port) {
                    return IpcMessage::error_reply(msg.sender, -98);
                }
                let Ok(socket) = self.create_udp_socket(port) else {
                    return IpcMessage::error_reply(msg.sender, -98);
                };
                let fid = self.insert_open_handle(msg.sender, path);
                self.udp_bound.insert(
                    fid,
                    UdpBoundState {
                        socket,
                        local_port: port,
                        last_peer: None,
                    },
                );
                reply_open(msg.sender, fid, u64::MAX, HANDLE_FLAG_DATAGRAM)
            }
            path if path.starts_with("udp/connect/") => {
                let rest = &path[12..];
                let parts: Vec<&str> = rest.splitn(2, '/').collect();
                if parts.len() != 2 {
                    return IpcMessage::error_reply(msg.sender, -22);
                }
                let Some(remote_ip) = parse_ip(parts[0]) else {
                    return IpcMessage::error_reply(msg.sender, -22);
                };
                let Some(remote_port) = parts[1].parse::<u16>().ok() else {
                    return IpcMessage::error_reply(msg.sender, -22);
                };
                if remote_port == 0 {
                    return IpcMessage::error_reply(msg.sender, -22);
                }
                self.open_udp_connection_handle(
                    msg.sender,
                    path,
                    IpEndpoint::new(remote_ip, remote_port),
                )
            }
            path if path.starts_with("udp/send/") => {
                let rest = &path[9..];
                let parts: Vec<&str> = rest.splitn(2, '/').collect();
                if parts.len() != 2 {
                    return IpcMessage::error_reply(msg.sender, -22);
                }
                let Some(remote_ip) = parse_ip(parts[0]) else {
                    return IpcMessage::error_reply(msg.sender, -22);
                };
                let Some(remote_port) = parts[1].parse::<u16>().ok() else {
                    return IpcMessage::error_reply(msg.sender, -22);
                };
                if remote_port == 0 {
                    return IpcMessage::error_reply(msg.sender, -22);
                }
                self.open_udp_connection_handle(
                    msg.sender,
                    path,
                    IpEndpoint::new(remote_ip, remote_port),
                )
            }
            path if path.starts_with("route/add/")
                || path.starts_with("route/del/")
                || path.starts_with("route/default/set/")
                || path == "route/default/clear" =>
            {
                self.reply_open_path(msg.sender, path, HANDLE_FLAG_CONTROL)
            }
            path if path.starts_with("ip/set/")
                || path.starts_with("ip6/set/")
                || path.starts_with("dns/set/")
                || path == "dhcp/enable"
                || path == "dhcp/disable" =>
            {
                self.reply_open_path(msg.sender, path, HANDLE_FLAG_CONTROL)
            }
            _ => IpcMessage::error_reply(msg.sender, -2),
        }
    }

    pub(crate) fn handle_read(&mut self, msg: &IpcMessage) -> IpcMessage {
        let (file_id, offset, requested) = read_request(msg);

        // Ownership check: fids are sequential and guessable.
        if !self.is_owner(file_id, msg.sender) {
            return IpcMessage::error_reply(msg.sender, -9); // EBADF
        }

        if let Some(listener) = self.tcp_listeners.get(&file_id).copied() {
            return self.handle_tcp_read(msg.sender, listener, requested);
        }
        if let Some(conn) = self.tcp_connections.get(&file_id).copied() {
            return self.handle_tcp_conn_read(msg.sender, conn, requested);
        }
        if self.udp_bound.contains_key(&file_id) {
            return self.handle_udp_bound_read(msg.sender, file_id, requested);
        }
        if let Some(conn) = self.udp_connections.get(&file_id).copied() {
            return self.handle_udp_conn_read(msg.sender, file_id, conn, requested);
        }

        let path = match self.open_handles.get(&file_id) {
            Some(handle) => handle.path.clone(),
            None => return IpcMessage::error_reply(msg.sender, -9),
        };

        let is_ping_path = path.starts_with("ping/") || path.starts_with("ping6/");

        let needs_refresh = offset == 0
            || self
                .open_handles
                .get(&file_id)
                .and_then(|handle| handle.cached_content.as_ref())
                .is_none()
            // Ping paths return dynamic content : one reply per read.
            // Never serve stale cached data.
            || is_ping_path;

        if needs_refresh {
            match self.generate_content(file_id, &path) {
                Ok(content) => {
                    if let Some(handle) = self.open_handles.get_mut(&file_id) {
                        handle.cached_content = Some(content);
                    }
                }
                Err(err) => return IpcMessage::error_reply(msg.sender, err),
            }
        }

        let cached = match self
            .open_handles
            .get(&file_id)
            .and_then(|handle| handle.cached_content.as_ref())
        {
            Some(content) => content,
            None => return IpcMessage::error_reply(msg.sender, -9),
        };

        // Ping endpoints behave like a dequeue, not a seekable file. Reads must
        // ignore the shared file offset because the preceding write advances it.
        let start = if is_ping_path {
            0
        } else {
            (offset as usize).min(cached.len())
        };
        reply_read(msg.sender, &cached[start..])
    }

    pub(crate) fn handle_write(&mut self, msg: &IpcMessage) -> IpcMessage {
        let file_id = message_file_id(msg);

        // Ownership check: fids are sequential and guessable.
        if !self.is_owner(file_id, msg.sender) {
            return IpcMessage::error_reply(msg.sender, -9); // EBADF
        }

        if let Some(listener) = self.tcp_listeners.get(&file_id).copied() {
            return self.handle_tcp_write(msg.sender, listener, msg);
        }
        if let Some(conn) = self.tcp_connections.get(&file_id).copied() {
            return self.handle_tcp_conn_write(msg.sender, conn, msg);
        }
        if self.udp_bound.contains_key(&file_id) {
            return self.handle_udp_bound_write(msg.sender, file_id, msg);
        }
        if let Some(conn) = self.udp_connections.get(&file_id).copied() {
            return self.handle_udp_conn_write(msg.sender, conn, msg);
        }

        let path = match self.open_handles.get(&file_id) {
            Some(handle) => handle.path.clone(),
            None => return IpcMessage::error_reply(msg.sender, -9),
        };

        if path.starts_with("ping/") {
            let Some(target) = parse_ipv4(&path[5..]) else {
                return IpcMessage::error_reply(msg.sender, -22);
            };
            let data_len = u16::from_le_bytes([msg.payload[16], msg.payload[17]]) as usize;
            let data = write_data(msg);
            let seq = data
                .get(0..2)
                .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
                .unwrap_or(0);
            let _ = call::debug_log(b"[ping] write ping/ target=");
            let _ = call::debug_log(&target.octets());
            let _ = call::debug_log(b" seq=");
            let _ = call::debug_log(&[(seq >> 8) as u8, seq as u8]);
            let _ = call::debug_log(b"\n");
            if self.send_ping(target, seq, file_id) {
                return reply_write(msg.sender, data_len);
            }
            let _ = call::debug_log(b"[ping] write: send_ping failed\n");
            return IpcMessage::error_reply(msg.sender, -11);
        }

        if path.starts_with("ping6/") {
            let Some(target) = parse_ipv6(&path[6..]) else {
                return IpcMessage::error_reply(msg.sender, -22);
            };
            let data_len = u16::from_le_bytes([msg.payload[16], msg.payload[17]]) as usize;
            let data = write_data(msg);
            let seq = data
                .get(0..2)
                .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
                .unwrap_or(0);
            let _ = call::debug_log(b"[ping] write ping6/ target=");
            let _ = call::debug_log(&target.octets());
            let _ = call::debug_log(b" seq=");
            let _ = call::debug_log(&[(seq >> 8) as u8, seq as u8]);
            let _ = call::debug_log(b"\n");
            if self.send_ping6(target, seq, file_id) {
                return reply_write(msg.sender, data_len);
            }
            let _ = call::debug_log(b"[ping] write: send_ping6 failed\n");
            return IpcMessage::error_reply(msg.sender, -11);
        }

        if let Some(cidr) = path.strip_prefix("ip/set/").and_then(parse_ipv4_cidr) {
            self.dhcp_enabled = false;
            self.dns_from_dhcp = false;
            let gateway = self.ip_config.as_ref().and_then(|cfg| cfg.gateway);
            self.apply_ipv4_config(cidr, gateway);
            return reply_write_data_len(msg.sender, msg);
        } else if path.starts_with("ip/set/") {
            return IpcMessage::error_reply(msg.sender, -22);
        }

        if let Some(cidr) = path.strip_prefix("ip6/set/").and_then(parse_ipv6_cidr) {
            let gateway = self.ipv6_config.as_ref().and_then(|cfg| cfg.gateway);
            self.apply_ipv6_config(cidr, gateway);
            return reply_write_data_len(msg.sender, msg);
        } else if path.starts_with("ip6/set/") {
            return IpcMessage::error_reply(msg.sender, -22);
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
            let Some(ip) = parse_ip(ip_s) else {
                return IpcMessage::error_reply(msg.sender, -22);
            };
            self.dhcp_enabled = false;
            self.dns_from_dhcp = false;
            self.dns_servers[idx] = if matches!(ip, IpAddress::Ipv4(addr) if addr == Ipv4Address::new(0, 0, 0, 0))
            {
                None
            } else {
                Some(ip)
            };
            if let Some(ref mut cfg) = self.ip_config {
                cfg.dns[idx] = match self.dns_servers[idx] {
                    Some(IpAddress::Ipv4(addr)) => Some(addr),
                    _ => None,
                };
            }
            self.refresh_dns_servers();
            return reply_write_data_len(msg.sender, msg);
        }

        if path == "dhcp/enable" {
            self.enable_dhcp();
            return reply_write_data_len(msg.sender, msg);
        }

        if path == "dhcp/disable" {
            self.dhcp_enabled = false;
            return reply_write_data_len(msg.sender, msg);
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
            let Some(cidr) = parse_ip_cidr(cidr_s) else {
                return IpcMessage::error_reply(msg.sender, -22);
            };
            let Some(gw) = parse_ip(gw_s) else {
                return IpcMessage::error_reply(msg.sender, -22);
            };
            let mut full = false;
            self.interface.routes_mut().update(|table| {
                if let Some((idx, _)) = table
                    .iter()
                    .enumerate()
                    .find(|(_, route)| route.cidr == cidr)
                {
                    let _ = table.remove(idx);
                }
                match (cidr, gw) {
                    (smoltcp::wire::IpCidr::Ipv4(_), IpAddress::Ipv4(_))
                    | (smoltcp::wire::IpCidr::Ipv6(_), IpAddress::Ipv6(_)) => {
                        if table
                            .push(Route {
                                cidr,
                                via_router: gw,
                                preferred_until: None,
                                expires_at: None,
                            })
                            .is_err()
                        {
                            full = true;
                        }
                    }
                    _ => {
                        full = true;
                    }
                }
            });
            if full {
                return IpcMessage::error_reply(msg.sender, -28);
            }
            return reply_write_data_len(msg.sender, msg);
        }

        if let Some(rest) = path.strip_prefix("route/del/") {
            let Some(cidr) = parse_ip_cidr(rest) else {
                return IpcMessage::error_reply(msg.sender, -22);
            };
            let mut removed = false;
            self.interface.routes_mut().update(|table| {
                if let Some((idx, _)) = table
                    .iter()
                    .enumerate()
                    .find(|(_, route)| route.cidr == cidr)
                {
                    let _ = table.remove(idx);
                    removed = true;
                }
            });
            if !removed {
                return IpcMessage::error_reply(msg.sender, -2);
            }
            return reply_write_data_len(msg.sender, msg);
        }

        if let Some(gw_s) = path.strip_prefix("route/default/set/") {
            let Some(gw) = parse_ip(gw_s) else {
                return IpcMessage::error_reply(msg.sender, -22);
            };
            match gw {
                IpAddress::Ipv4(gw4) => {
                    let _ = self.interface.routes_mut().remove_default_ipv4_route();
                    if self
                        .interface
                        .routes_mut()
                        .add_default_ipv4_route(gw4)
                        .is_err()
                    {
                        return IpcMessage::error_reply(msg.sender, -28);
                    }
                    if let Some(ref mut cfg) = self.ip_config {
                        cfg.gateway = Some(gw4);
                    }
                }
                IpAddress::Ipv6(gw6) => {
                    let _ = self.interface.routes_mut().remove_default_ipv6_route();
                    if self
                        .interface
                        .routes_mut()
                        .add_default_ipv6_route(gw6)
                        .is_err()
                    {
                        return IpcMessage::error_reply(msg.sender, -28);
                    }
                    if let Some(ref mut cfg) = self.ipv6_config {
                        cfg.gateway = Some(gw6);
                    }
                }
            }
            self.refresh_dns_servers();
            return reply_write_data_len(msg.sender, msg);
        }

        if path == "route/default/clear" {
            let _ = self.interface.routes_mut().remove_default_ipv4_route();
            let _ = self.interface.routes_mut().remove_default_ipv6_route();
            if let Some(ref mut cfg) = self.ip_config {
                cfg.gateway = None;
            }
            if let Some(ref mut cfg) = self.ipv6_config {
                cfg.gateway = None;
            }
            self.refresh_dns_servers();
            return reply_write_data_len(msg.sender, msg);
        }

        IpcMessage::error_reply(msg.sender, -1)
    }

    pub(crate) fn handle_close(&mut self, msg: &IpcMessage) -> IpcMessage {
        let file_id = message_file_id(msg);

        // Only the owner may close; also prevents destroying another
        // process's sockets by guessing its fid.
        if !self.is_owner(file_id, msg.sender) {
            return IpcMessage::error_reply(msg.sender, -9); // EBADF
        }
        self.forget_handle(file_id);
        self.open_handles.remove(&file_id);
        if let Some(listener) = self.tcp_listeners.remove(&file_id) {
            let _ = self.sockets.remove(listener.socket);
        }
        if let Some(conn) = self.tcp_connections.remove(&file_id) {
            let socket = self.sockets.get_mut::<tcp::Socket>(conn.socket);
            socket.close();
            self.lingering_sockets.push(conn.socket);
        }
        if let Some(state) = self.udp_bound.remove(&file_id) {
            let socket = self.sockets.get_mut::<udp::Socket>(state.socket);
            socket.close();
            self.sockets.remove(state.socket);
        }
        if let Some(conn) = self.udp_connections.remove(&file_id) {
            let socket = self.sockets.get_mut::<udp::Socket>(conn.socket);
            socket.close();
            self.sockets.remove(conn.socket);
        }
        reply_ok(msg.sender)
    }
}
