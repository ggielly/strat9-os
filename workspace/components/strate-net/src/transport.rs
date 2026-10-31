use smoltcp::{
    iface::SocketHandle,
    socket::{tcp, udp},
    wire::IpAddress,
};
use strate_net::IpcMessage;

use crate::{
    ipc::{reply_read, reply_write, write_data},
    state::{NetworkStrate, TcpConnState, UdpConnState},
};

impl NetworkStrate {
    /// Create a fresh listening socket bound to `port`.
    fn make_listener_socket(&mut self, port: u16) -> Option<SocketHandle> {
        let rx_buf = tcp::SocketBuffer::new(alloc::vec![0u8; 16384]);
        let tx_buf = tcp::SocketBuffer::new(alloc::vec![0u8; 16384]);
        let mut socket = tcp::Socket::new(rx_buf, tx_buf);
        if socket.listen(port).is_err() {
            return None;
        }
        Some(self.sockets.add(socket))
    }

    /// Keep the listening socket listening and maintain the accept queue.
    ///
    /// smoltcp has no `accept()`: a socket in `LISTEN` becomes the connection
    /// itself as soon as the handshake starts.  The moment that happens we
    /// replace it with a brand-new listener, so port 23 keeps answering SYNs
    /// for the whole lifetime of the session.  The accepted socket is either
    /// served immediately (`session`) or queued (`backlog`), giving us a real
    /// backlog without ever leaving the port without a listener.
    ///
    /// Returns `true` when a session ended and the next read should report
    /// EOF (0-byte read) to the caller.
    pub(crate) fn service_tcp_listener(&mut self, file_id: u64) -> bool {
        let mut eof = false;
        loop {
            let Some(state) = self.tcp_listeners.get(&file_id).copied() else {
                return eof;
            };

            // 1. Did the listening socket leave LISTEN? Then it is now an
            //    accepted connection: swap in a replacement listener first.
            let listener_state = self.sockets.get::<tcp::Socket>(state.socket).state();
            if listener_state != tcp::State::Listen {
                let accepted = state.socket;
                let Some(fresh) = self.make_listener_socket(state.port) else {
                    // Cannot allocate a replacement: keep the accepted socket
                    // in place so at least this session can finish.
                    return eof;
                };
                let mut overflow = None;
                if let Some(state_mut) = self.tcp_listeners.get_mut(&file_id) {
                    state_mut.socket = fresh;
                    state_mut.eof = false;
                    if state_mut.session.is_none() {
                        state_mut.session = Some(accepted);
                    } else if !state_mut.push_backlog(accepted) {
                        overflow = Some(accepted);
                    }
                }
                if let Some(handle) = overflow {
                    let socket = self.sockets.get_mut::<tcp::Socket>(handle);
                    socket.abort();
                    self.lingering_sockets.push(handle);
                }
                continue;
            }

            // 2. Reap a finished session once its RX data has been drained.
            if let Some(session) = state.session {
                let (finished, state_now) = {
                    let socket = self.sockets.get_mut::<tcp::Socket>(session);
                    let st = socket.state();
                    let drained = !socket.can_recv();
                    let finished = drained
                        && matches!(
                            st,
                            tcp::State::CloseWait
                                | tcp::State::LastAck
                                | tcp::State::Closing
                                | tcp::State::TimeWait
                                | tcp::State::Closed
                        );
                    if finished && st != tcp::State::Closed {
                        socket.close();
                    }
                    (finished, st)
                };
                let _ = state_now;
                if finished {
                    self.lingering_sockets.push(session);
                    if let Some(state_mut) = self.tcp_listeners.get_mut(&file_id) {
                        state_mut.session = None;
                        state_mut.eof = true;
                    }
                    eof = true;
                    continue;
                }
            }

            // 3. Promote the oldest queued connection.
            let promote = self
                .tcp_listeners
                .get(&file_id)
                .map(|state| state.session.is_none())
                .unwrap_or(false);
            if promote {
                let next = self
                    .tcp_listeners
                    .get_mut(&file_id)
                    .and_then(|state| state.pop_backlog());
                if let Some(handle) = next {
                    if let Some(state_mut) = self.tcp_listeners.get_mut(&file_id) {
                        state_mut.session = Some(handle);
                        state_mut.eof = false;
                    }
                    continue;
                }
            }
            return eof;
        }
    }

    /// Service every listen fid.  Called once per poll iteration so the
    /// permanent listener is replaced as soon as a handshake starts, not only
    /// when telnetd happens to call read().
    pub(crate) fn service_all_tcp_listeners(&mut self) {
        if self.tcp_listeners.is_empty() {
            return;
        }
        let fids: alloc::vec::Vec<u64> = self.tcp_listeners.keys().copied().collect();
        for fid in fids {
            let _ = self.service_tcp_listener(fid);
        }
    }

    /// Return the socket serving this listen fid, if a session is active.
    pub(crate) fn listener_session(&self, file_id: u64) -> Option<SocketHandle> {
        self.tcp_listeners
            .get(&file_id)
            .and_then(|state| state.session)
    }

    pub(crate) fn handle_tcp_read(
        &mut self,
        sender: u64,
        file_id: u64,
        requested: usize,
    ) -> IpcMessage {
        if requested == 0 {
            return reply_read(sender, &[]);
        }

        let eof_seen = self.service_tcp_listener(file_id);
        let Some(state) = self.tcp_listeners.get(&file_id).copied() else {
            return IpcMessage::error_reply(sender, -104);
        };

        if let Some(session) = state.session {
            let socket = self.sockets.get_mut::<tcp::Socket>(session);
            if socket.can_recv() {
                let mut data = [0u8; IpcMessage::READ_INLINE_CAPACITY];
                let want = requested.min(data.len());
                match socket.recv_slice(&mut data[..want]) {
                    Ok(n) => {
                        return reply_read(sender, &data[..n])
                    }
                    Err(_) => return IpcMessage::error_reply(sender, -5),
                }
            }
            if matches!(
                socket.state(),
                tcp::State::CloseWait
                    | tcp::State::LastAck
                    | tcp::State::Closing
                    | tcp::State::TimeWait
                    | tcp::State::Closed
            ) {
                // Peer closed and everything was drained.
                return reply_read(sender, &[]);
            }
            return IpcMessage::error_reply(sender, -11);
        }

        if eof_seen {
            if let Some(state_mut) = self.tcp_listeners.get_mut(&file_id) {
                state_mut.eof = false;
            }
            return reply_read(sender, &[]);
        }
        // Healthy listener with no client yet.
        IpcMessage::error_reply(sender, -11)
    }

    pub(crate) fn handle_tcp_write(
        &mut self,
        sender: u64,
        file_id: u64,
        msg: &IpcMessage,
    ) -> IpcMessage {
        let _ = self.service_tcp_listener(file_id);
        let Some(session) = self.listener_session(file_id) else {
            return IpcMessage::error_reply(sender, -11);
        };
        let socket = self.sockets.get_mut::<tcp::Socket>(session);
        if !socket.is_open() || !socket.can_send() {
            return IpcMessage::error_reply(sender, -11);
        }

        let data = write_data(msg);
        match socket.send_slice(data) {
            Ok(n) => {
                reply_write(sender, n)
            }
            Err(_) => {
                IpcMessage::error_reply(sender, -11)
            }
        }
    }

    pub(crate) fn handle_tcp_conn_read(
        &mut self,
        sender: u64,
        conn: TcpConnState,
        requested: usize,
    ) -> IpcMessage {
        if requested == 0 {
            return reply_read(sender, &[]);
        }
        let socket = self.sockets.get_mut::<tcp::Socket>(conn.socket);
        if !socket.is_open() {
            return IpcMessage::error_reply(sender, -104);
        }
        let state = socket.state();
        if state == tcp::State::SynSent || state == tcp::State::SynReceived {
            return IpcMessage::error_reply(sender, -115);
        }

        let mut data = [0u8; IpcMessage::READ_INLINE_CAPACITY];
        if socket.can_recv() {
            let want = requested.min(data.len());
            match socket.recv_slice(&mut data[..want]) {
                Ok(n) => reply_read(sender, &data[..n]),
                Err(_) => IpcMessage::error_reply(sender, -5),
            }
        } else {
            IpcMessage::error_reply(sender, -11)
        }
    }

    pub(crate) fn handle_tcp_conn_write(
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
            return IpcMessage::error_reply(sender, -115);
        }

        let data = write_data(msg);
        if !socket.can_send() {
            return IpcMessage::error_reply(sender, -11);
        }
        match socket.send_slice(data) {
            Ok(n) => reply_write(sender, n),
            Err(_) => IpcMessage::error_reply(sender, -11),
        }
    }

    pub(crate) fn handle_udp_bound_read(
        &mut self,
        sender: u64,
        file_id: u64,
        requested: usize,
    ) -> IpcMessage {
        if requested == 0 {
            return reply_read(sender, &[]);
        }
        if let Some(reply) = self.drain_spilled_read(sender, file_id, requested) {
            return reply;
        }
        let socket_handle = match self.udp_bound.get(&file_id) {
            Some(state) => state.socket,
            None => return IpcMessage::error_reply(sender, -9),
        };

        let (peer, out) = {
            let socket = self.sockets.get_mut::<udp::Socket>(socket_handle);
            let Ok((data, meta)) = socket.recv() else {
                return IpcMessage::error_reply(sender, -11);
            };

            let mut out = alloc::vec![0u8; 19 + data.len()];
            match meta.endpoint.addr {
                IpAddress::Ipv4(src_ip) => {
                    out[0] = 4;
                    out[1..5].copy_from_slice(&src_ip.octets());
                }
                IpAddress::Ipv6(src_ip) => {
                    out[0] = 6;
                    out[1..17].copy_from_slice(&src_ip.octets());
                }
            }
            out[17..19].copy_from_slice(&meta.endpoint.port.to_be_bytes());
            out[19..].copy_from_slice(data);
            (meta.endpoint, out)
        };

        if let Some(state) = self.udp_bound.get_mut(&file_id) {
            state.last_peer = Some(peer);
        }

        self.reply_read_spilling(sender, file_id, requested, out)
    }

    pub(crate) fn handle_udp_bound_write(
        &mut self,
        sender: u64,
        file_id: u64,
        msg: &IpcMessage,
    ) -> IpcMessage {
        let state = match self.udp_bound.get(&file_id).copied() {
            Some(state) => state,
            None => return IpcMessage::error_reply(sender, -9),
        };
        let Some(peer) = state.last_peer else {
            return IpcMessage::error_reply(sender, -89);
        };

        let socket = self.sockets.get_mut::<udp::Socket>(state.socket);
        let data = write_data(msg);
        if !socket.can_send() {
            return IpcMessage::error_reply(sender, -11);
        }
        match socket.send_slice(data, peer) {
            Ok(()) => reply_write(sender, data.len()),
            Err(udp::SendError::BufferFull) => IpcMessage::error_reply(sender, -11),
            Err(udp::SendError::Unaddressable) => IpcMessage::error_reply(sender, -22),
        }
    }

    pub(crate) fn handle_udp_conn_read(
        &mut self,
        sender: u64,
        file_id: u64,
        conn: UdpConnState,
        requested: usize,
    ) -> IpcMessage {
        if requested == 0 {
            return reply_read(sender, &[]);
        }
        if let Some(reply) = self.drain_spilled_read(sender, file_id, requested) {
            return reply;
        }

        let packet = {
            let socket = self.sockets.get_mut::<udp::Socket>(conn.socket);
            let mut packet = None;
            while socket.can_recv() {
                let Ok((data, meta)) = socket.recv() else {
                    break;
                };
                if meta.endpoint.addr == conn.remote.addr && meta.endpoint.port == conn.remote.port
                {
                    packet = Some(data.to_vec());
                    break;
                }
            }
            packet
        };
        if let Some(packet) = packet {
            return self.reply_read_spilling(sender, file_id, requested, packet);
        }
        IpcMessage::error_reply(sender, -11)
    }

    pub(crate) fn handle_udp_conn_write(
        &mut self,
        sender: u64,
        conn: UdpConnState,
        msg: &IpcMessage,
    ) -> IpcMessage {
        let socket = self.sockets.get_mut::<udp::Socket>(conn.socket);
        let data = write_data(msg);
        if !socket.can_send() {
            return IpcMessage::error_reply(sender, -11);
        }
        match socket.send_slice(data, conn.remote) {
            Ok(()) => reply_write(sender, data.len()),
            Err(udp::SendError::BufferFull) => IpcMessage::error_reply(sender, -11),
            Err(udp::SendError::Unaddressable) => IpcMessage::error_reply(sender, -22),
        }
    }
}
