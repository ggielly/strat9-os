use smoltcp::{
    socket::icmp,
    wire::{IpAddress, Ipv4Address, Ipv6Address},
};
use strate_net::syscalls::clock_gettime_ns;

use crate::{
    ip::{icmp_checksum, icmpv6_checksum},
    state::{NetworkStrate, PendingPing, PING_TIMEOUT_NS},
};

impl NetworkStrate {
    pub(crate) fn process_icmp(&mut self) {
        let now_ns = clock_gettime_ns().unwrap_or(0);
        if let Some(ref ping) = self.pending_ping {
            if now_ns.saturating_sub(ping.send_ts_ns) >= PING_TIMEOUT_NS {
                self.pending_ping = None;
            }
        }

        let socket = self.sockets.get_mut::<icmp::Socket>(self.icmp_handle);
        if !socket.can_recv() {
            return;
        }
        while socket.can_recv() {
            let Ok((data, _addr)) = socket.recv() else {
                break;
            };
            if data.len() < 16 {
                continue;
            }
            let is_v6_reply = data[0] == 129;
            if data[0] != 0 && !is_v6_reply {
                continue;
            }
            let ident = u16::from_be_bytes([data[4], data[5]]);
            if ident != self.ping_ident {
                continue;
            }
            let token = u64::from_le_bytes(data[8..16].try_into().unwrap_or([0u8; 8]));
            if let Some(ref pending) = self.pending_ping {
                if pending.token == token && pending.is_v6 == is_v6_reply {
                    let rtt_us = now_ns.saturating_sub(pending.send_ts_ns) / 1000;
                    self.ping_reply = Some((pending.seq, rtt_us));
                    self.pending_ping = None;
                }
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
        if self.pending_ping.is_some() || self.ping_reply.is_some() {
            return false;
        }

        if self.is_local_ipv4(target) {
            self.ping_reply = Some((seq, 1));
            return true;
        }

        let token = self.alloc_ping_token();

        let socket = self.sockets.get_mut::<icmp::Socket>(self.icmp_handle);
        if !socket.is_open() {
            socket.bind(icmp::Endpoint::Ident(self.ping_ident)).ok();
        }
        if !socket.can_send() {
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

        let now_ns = clock_gettime_ns().unwrap_or(0);
        self.pending_ping = Some(PendingPing {
            seq,
            token,
            send_ts_ns: now_ns,
            is_v6: false,
        });
        true
    }

    pub(crate) fn send_ping6(&mut self, target: Ipv6Address, seq: u16, _file_id: u64) -> bool {
        if self.pending_ping.is_some() || self.ping_reply.is_some() {
            return false;
        }

        if self.is_local_ipv6(target) {
            self.ping_reply = Some((seq, 1));
            return true;
        }

        let token = self.alloc_ping_token();

        let socket = self.sockets.get_mut::<icmp::Socket>(self.icmp_handle);
        if !socket.is_open() {
            socket.bind(icmp::Endpoint::Ident(self.ping_ident)).ok();
        }
        if !socket.can_send() {
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

        let now_ns = clock_gettime_ns().unwrap_or(0);
        self.pending_ping = Some(PendingPing {
            seq,
            token,
            send_ts_ns: now_ns,
            is_v6: true,
        });
        true
    }
}
