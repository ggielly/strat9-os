use alloc::vec::Vec;
use smoltcp::{
    socket::icmp,
    wire::{IpAddress, Ipv4Address, Ipv6Address},
};
use strate_net::syscalls::clock_gettime_ns;

use strate_net::syscalls::call;

use crate::{
    ip::{icmp_checksum, icmpv6_checksum},
    state::{NetworkStrate, PendingPing, PING_TIMEOUT_NS},
};

const MAX_ICMP_QUEUE: usize = 32;

impl NetworkStrate {
    pub(crate) fn process_icmp(&mut self) {
        let now_ns = clock_gettime_ns().unwrap_or(0);

        // Expire timed-out pending pings.
        self.pending_pings
            .retain(|ping| now_ns.saturating_sub(ping.send_ts_ns) < PING_TIMEOUT_NS);

        // Drain received packets into a temporary buffer to release the
        // socket borrow before calling handler methods on &mut self.
        let mut packets: Vec<([u8; 128], IpAddress)> = Vec::new();
        {
            let socket = self.sockets.get_mut::<icmp::Socket>(self.icmp_handle);
            if !socket.can_recv() {
                return;
            }
            while socket.can_recv() && packets.len() < MAX_ICMP_QUEUE {
                let Ok((data, addr)) = socket.recv() else {
                    break;
                };
                let mut buf = [0u8; 128];
                let n = data.len().min(128);
                buf[..n].copy_from_slice(&data[..n]);
                packets.push((buf, addr));
            }
        }

        for (data, addr) in packets.iter() {
            if data.len() < 8 {
                let _ = call::debug_log(b"[ping] recv too short\n");
                continue;
            }

            match data[0] {
                8 => self.handle_echo_request_v4(data, *addr),
                128 => self.handle_echo_request_v6(data, *addr),
                0 => self.handle_echo_reply_v4(data),
                129 => self.handle_echo_reply_v6(data),
                other => {
                    let _ = call::debug_log(b"[ping] recv unexpected type ");
                    let _ = call::debug_log(&[other]);
                    let _ = call::debug_log(b"\n");
                }
            }
        }
    }

    fn handle_echo_request_v4(&mut self, data: &[u8], addr: IpAddress) {
        let IpAddress::Ipv4(src) = addr else {
            return;
        };

        let socket = self.sockets.get_mut::<icmp::Socket>(self.icmp_handle);
        if !socket.can_send() {
            let _ = call::debug_log(b"[ping] echo request v4: can_send false\n");
            return;
        }

        // Build echo reply: swap type 8->0, keep ident+seq, recompute checksum.
        let payload_len = data.len();
        let Ok(buf) = socket.send(payload_len, IpAddress::Ipv4(src)) else {
            let _ = call::debug_log(b"[ping] echo request v4: send failed\n");
            return;
        };
        buf.copy_from_slice(data);
        buf[0] = 0;
        buf[1] = 0;
        let checksum = icmp_checksum(buf);
        buf[2..4].copy_from_slice(&checksum.to_be_bytes());

        let _ = call::debug_log(b"[ping] echo reply v4 sent to ");
        let octets = src.octets();
        let _ = call::debug_log(&[octets[0], b'.', octets[1], b'.', octets[2], b'.', octets[3]]);
        let _ = call::debug_log(b"\n");
    }

    fn handle_echo_request_v6(&mut self, data: &[u8], addr: IpAddress) {
        let IpAddress::Ipv6(src) = addr else {
            return;
        };

        let socket = self.sockets.get_mut::<icmp::Socket>(self.icmp_handle);
        if !socket.can_send() {
            let _ = call::debug_log(b"[ping] echo request v6: can_send false\n");
            return;
        }

        // Build echo reply: swap type 128->129, keep ident+seq, recompute checksum.
        let payload_len = data.len();
        let Ok(buf) = socket.send(payload_len, IpAddress::Ipv6(src)) else {
            let _ = call::debug_log(b"[ping] echo request v6: send failed\n");
            return;
        };
        buf.copy_from_slice(data);
        buf[0] = 129;
        buf[1] = 0;

        let dst = src.octets();
        let src_addr = self.link_local_addr;
        let checksum = icmpv6_checksum(&src_addr.octets(), &dst, buf);
        buf[2..4].copy_from_slice(&checksum.to_be_bytes());

        let _ = call::debug_log(b"[ping] echo reply v6 sent\n");
    }

    fn handle_echo_reply_v4(&mut self, data: &[u8]) {
        if data.len() < 16 {
            return;
        }
        let ident = u16::from_be_bytes([data[4], data[5]]);
        if ident != self.ping_ident {
            return;
        }
        let token = u64::from_le_bytes(data[8..16].try_into().unwrap_or([0u8; 8]));
        if let Some(idx) = self
            .pending_pings
            .iter()
            .position(|p| p.token == token && !p.is_v6)
        {
            let pending = self.pending_pings.remove(idx);
            let now_ns = clock_gettime_ns().unwrap_or(0);
            let rtt_us = now_ns.saturating_sub(pending.send_ts_ns) / 1000;
            self.ping_replies.push((pending.seq, rtt_us));
            let _ = call::debug_log(b"[ping] reply seq=");
            let _ = call::debug_log(&[(pending.seq >> 8) as u8, pending.seq as u8]);
            let _ = call::debug_log(b" rtt=");
            let _ = call::debug_log(&[(rtt_us / 1000) as u8]);
            let _ = call::debug_log(b"ms\n");
        }
    }

    fn handle_echo_reply_v6(&mut self, data: &[u8]) {
        if data.len() < 16 {
            return;
        }
        let ident = u16::from_be_bytes([data[4], data[5]]);
        if ident != self.ping_ident {
            return;
        }
        let token = u64::from_le_bytes(data[8..16].try_into().unwrap_or([0u8; 8]));
        if let Some(idx) = self
            .pending_pings
            .iter()
            .position(|p| p.token == token && p.is_v6)
        {
            let pending = self.pending_pings.remove(idx);
            let now_ns = clock_gettime_ns().unwrap_or(0);
            let rtt_us = now_ns.saturating_sub(pending.send_ts_ns) / 1000;
            self.ping_replies.push((pending.seq, rtt_us));
            let _ = call::debug_log(b"[ping] reply v6 seq=");
            let _ = call::debug_log(&[(pending.seq >> 8) as u8, pending.seq as u8]);
            let _ = call::debug_log(b" rtt=");
            let _ = call::debug_log(&[(rtt_us / 1000) as u8]);
            let _ = call::debug_log(b"ms\n");
        }
    }

    pub(crate) fn is_local_ipv4(&self, target: Ipv4Address) -> bool {
        self.ip_config
            .as_ref()
            .is_some_and(|cfg| cfg.host == target)
    }

    pub(crate) fn is_local_ipv6(&self, target: Ipv6Address) -> bool {
        if target == self.link_local_addr {
            return true;
        }
        self.ipv6_config
            .as_ref()
            .is_some_and(|cfg| cfg.address.address() == target)
    }

    pub(crate) fn send_ping(&mut self, target: Ipv4Address, seq: u16, _file_id: u64) -> bool {
        if self.is_local_ipv4(target) {
            self.ping_replies.push((seq, 1));
            return true;
        }

        let token = self.alloc_ping_token();

        let socket = self.sockets.get_mut::<icmp::Socket>(self.icmp_handle);
        if !socket.is_open() {
            socket.bind(icmp::Endpoint::Ident(self.ping_ident)).ok();
        }
        if !socket.can_send() {
            let _ = call::debug_log(b"[ping] send_ping v4: can_send false\n");
            return false;
        }

        let payload_len = 40;
        let icmp_len = 8 + payload_len;
        let Ok(buf) = socket.send(icmp_len, IpAddress::Ipv4(target)) else {
            return false;
        };
        buf[0] = 8;
        buf[1] = 0;
        buf[2] = 0;
        buf[3] = 0;
        buf[4..6].copy_from_slice(&self.ping_ident.to_be_bytes());
        buf[6..8].copy_from_slice(&seq.to_be_bytes());
        buf[8..16].copy_from_slice(&token.to_le_bytes());
        for byte in buf[16..icmp_len].iter_mut() {
            *byte = 0xAA;
        }
        let checksum = icmp_checksum(buf);
        buf[2..4].copy_from_slice(&checksum.to_be_bytes());

        let _ = call::debug_log(b"[ping] sent seq=");
        let _ = call::debug_log(&[(seq >> 8) as u8, seq as u8]);
        let _ = call::debug_log(b" token=");
        let _ = call::debug_log(&token.to_le_bytes());
        let _ = call::debug_log(b"\n");

        self.pending_pings.push(PendingPing {
            seq,
            token,
            send_ts_ns: 0, // stamped by main loop before interface.poll()
            is_v6: false,
        });
        true
    }

    pub(crate) fn send_ping6(&mut self, target: Ipv6Address, seq: u16, _file_id: u64) -> bool {
        if self.is_local_ipv6(target) {
            self.ping_replies.push((seq, 1));
            return true;
        }

        let token = self.alloc_ping_token();

        let socket = self.sockets.get_mut::<icmp::Socket>(self.icmp_handle);
        if !socket.is_open() {
            socket.bind(icmp::Endpoint::Ident(self.ping_ident)).ok();
        }
        if !socket.can_send() {
            let _ = call::debug_log(b"[ping] send_ping6: can_send false\n");
            return false;
        }

        let payload_len = 40;
        let icmp_len = 8 + payload_len;
        let Ok(buf) = socket.send(icmp_len, IpAddress::Ipv6(target)) else {
            return false;
        };
        buf[0] = 128;
        buf[1] = 0;
        buf[2] = 0;
        buf[3] = 0;
        buf[4..6].copy_from_slice(&self.ping_ident.to_be_bytes());
        buf[6..8].copy_from_slice(&seq.to_be_bytes());
        buf[8..16].copy_from_slice(&token.to_le_bytes());
        for byte in buf[16..icmp_len].iter_mut() {
            *byte = 0xAA;
        }

        let _ = call::debug_log(b"[ping] sent v6 seq=");
        let _ = call::debug_log(&[(seq >> 8) as u8, seq as u8]);
        let _ = call::debug_log(b" token=");
        let _ = call::debug_log(&token.to_le_bytes());
        let _ = call::debug_log(b"\n");

        let src = if target.is_unicast_link_local() {
            self.link_local_addr
        } else {
            self.ipv6_config
                .as_ref()
                .map(|cfg| cfg.address.address())
                .unwrap_or(self.link_local_addr)
        };
        let checksum = icmpv6_checksum(&src.octets(), &target.octets(), buf);
        buf[2..4].copy_from_slice(&checksum.to_be_bytes());

        self.pending_pings.push(PendingPing {
            seq,
            token,
            send_ts_ns: 0, // stamped by main loop before interface.poll()
            is_v6: true,
        });
        true
    }
}
