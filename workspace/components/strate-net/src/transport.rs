use smoltcp::{
    socket::{tcp, udp},
    wire::IpAddress,
};
use strate_net::IpcMessage;

use crate::{
    ipc::{reply_read, reply_write, write_data},
    state::{NetworkStrate, TcpConnState, TcpListenerState, UdpConnState},
};

impl NetworkStrate {
    pub(crate) fn handle_tcp_read(
        &mut self,
        sender: u64,
        listener: TcpListenerState,
        requested: usize,
    ) -> IpcMessage {
        if requested == 0 {
            return reply_read(sender, &[]);
        }
        let socket = self.sockets.get_mut::<tcp::Socket>(listener.socket);
        if !socket.is_open() || (!socket.is_listening() && !socket.is_active()) {
            if listener.auto_relisten {
                socket.abort();
                let _ = socket.listen(listener.port);
            } else {
                return IpcMessage::error_reply(sender, -104);
            }
        }

        let mut data = [0u8; IpcMessage::READ_INLINE_CAPACITY];
        if socket.can_recv() {
            let want = requested.min(data.len());
            match socket.recv_slice(&mut data[..want]) {
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

    pub(crate) fn handle_tcp_write(
        &mut self,
        sender: u64,
        listener: TcpListenerState,
        msg: &IpcMessage,
    ) -> IpcMessage {
        let socket = self.sockets.get_mut::<tcp::Socket>(listener.socket);
        if !socket.is_open() || (!socket.is_listening() && !socket.is_active()) {
            if listener.auto_relisten {
                socket.abort();
                let _ = socket.listen(listener.port);
            } else {
                return IpcMessage::error_reply(sender, -104);
            }
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
