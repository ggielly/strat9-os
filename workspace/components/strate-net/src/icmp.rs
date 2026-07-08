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

impl NetworkStrate {
    pub(crate) fn process_icmp(&mut self) {
        let now_ns = clock_gettime_ns().unwrap_or(0);

        // Expire timed-out pending pings.
        self.pending_pings
            .retain(|ping| now_ns.saturating_sub(ping.send_ts_ns) < PING_TIMEOUT_NS);

        let socket = self.sockets.get_mut::<icmp::Socket>(self.icmp_handle);
        if !socket.can_recv() {
            return;
        }
        while socket.can_recv() {
            let Ok((data, _addr)) = socket.recv() else {
                break;
            };
            if data.len() < 16 {
                let _ = call::debug_log(b"[ping] recv too short\n");
                continue;
            }
            let is_v6_reply = data[0] == 129;
            if data[0] != 0 && !is_v6_reply {
                let _ = call::debug_log(b"[ping] recv unexpected type ");
                let _ = call::debug_log(&[data[0]]);
                let _ = call::debug_log(b"\n");
                continue;
            }
            let ident = u16::from_be_bytes([data[4], data[5]]);
            if ident != self.ping_ident {
                let _ = call::debug_log(b"[ping] recv wrong ident ");
                let _ = call::debug_log(&[(ident >> 8) as u8, ident as u8]);
                let _ = call::debug_log(b" != ");
                let _ = call::debug_log(&[(self.ping_ident >> 8) as u8, self.ping_ident as u8]);
                let _ = call::debug_log(b"\n");
                continue;
            }
            let token = u64::from_le_bytes(data[8..16].try_into().unwrap_or([0u8; 8]));
            // Match against all pending pings (supports pipelining).
            if let Some(idx) = self
                .pending_pings
                .iter()
                .position(|p| p.token == token && p.is_v6 == is_v6_reply)
            {
                let pending = self.pending_pings.remove(idx);
                let rtt_us = now_ns.saturating_sub(pending.send_ts_ns) / 1000;
                self.ping_replies.push((pending.seq, rtt_us));
                let _ = call::debug_log(b"[ping] reply seq=");
                let _ = call::debug_log(&[(pending.seq >> 8) as u8, pending.seq as u8]);
                let _ = call::debug_log(b" rtt=");
                let _ = call::debug_log(&[(rtt_us / 1000) as u8]);
                let _ = call::debug_log(b"ms\n");
            } else {
                let _ = call::debug_log(b"[ping] recv: no match for token ");
                let _ = call::debug_log(&token.to_le_bytes());
                let _ = call::debug_log(b"\n");
            }
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
