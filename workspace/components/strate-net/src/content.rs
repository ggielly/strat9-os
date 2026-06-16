use alloc::{string::String, vec, vec::Vec};
use core::fmt::Write;

use smoltcp::socket::tcp;
use strate_net::syscalls::call;

use crate::state::NetworkStrate;

impl NetworkStrate {
    pub(crate) fn generate_content(
        &mut self,
        _file_id: u64,
        path: &str,
    ) -> core::result::Result<Vec<u8>, i32> {
        match path {
            "" => Ok(b"ip\naddress\nprefix\nnetmask\nbroadcast\ngateway\nroute\nroutes\ndns\ndhcp\nresolve\nping\ntcp\nudp\nip6\nip6/address\nip6/gateway\n".to_vec()),
            "ip" => Ok(if let Some(ref cfg) = self.ip_config {
                alloc::format!("{}\n", cfg.address).into_bytes()
            } else {
                b"0.0.0.0/0\n".to_vec()
            }),
            "address" => Ok(if let Some(ref cfg) = self.ip_config {
                alloc::format!("{}\n", cfg.host).into_bytes()
            } else {
                b"0.0.0.0\n".to_vec()
            }),
            "prefix" => Ok(if let Some(ref cfg) = self.ip_config {
                alloc::format!("{}\n", cfg.prefix_len).into_bytes()
            } else {
                b"0\n".to_vec()
            }),
            "netmask" => Ok(if let Some(ref cfg) = self.ip_config {
                alloc::format!("{}\n", cfg.netmask).into_bytes()
            } else {
                b"0.0.0.0\n".to_vec()
            }),
            "broadcast" => Ok(if let Some(ref cfg) = self.ip_config {
                alloc::format!("{}\n", cfg.broadcast).into_bytes()
            } else {
                b"0.0.0.0\n".to_vec()
            }),
            "gateway" => Ok(if let Some(ref cfg) = self.ip_config {
                if let Some(gw) = cfg.gateway {
                    alloc::format!("{}\n", gw).into_bytes()
                } else {
                    b"0.0.0.0\n".to_vec()
                }
            } else {
                b"0.0.0.0\n".to_vec()
            }),
            "dns" => {
                let mut out = String::new();
                let mut wrote = false;
                for server in self.dns_servers.iter().flatten() {
                    let _ = write!(out, "{}\n", server);
                    wrote = true;
                }
                if !wrote {
                    out.push_str("0.0.0.0\n");
                }
                Ok(out.into_bytes())
            }
            "dhcp" => Ok(if self.dhcp_enabled {
                b"on\n".to_vec()
            } else {
                b"off\n".to_vec()
            }),
            "ip6" | "ip6/address" => {
                let addr = if let Some(ref cfg) = self.ipv6_config {
                    cfg.address.address()
                } else {
                    self.link_local_addr
                };
                Ok(alloc::format!("{}\n", addr).into_bytes())
            }
            "ip6/gateway" => Ok(if let Some(ref cfg) = self.ipv6_config {
                if let Some(gw) = cfg.gateway {
                    alloc::format!("{}\n", gw).into_bytes()
                } else {
                    b"::\n".to_vec()
                }
            } else {
                b"::\n".to_vec()
            }),
            "route" => Ok(if let Some(ref cfg) = self.ip_config {
                if let Some(gw) = cfg.gateway {
                    alloc::format!("default via {}\n", gw).into_bytes()
                } else if let Some(ref cfg6) = self.ipv6_config {
                    if let Some(gw) = cfg6.gateway {
                        alloc::format!("default via {}\n", gw).into_bytes()
                    } else {
                        b"none\n".to_vec()
                    }
                } else {
                    b"none\n".to_vec()
                }
            } else if let Some(ref cfg6) = self.ipv6_config {
                if let Some(gw) = cfg6.gateway {
                    alloc::format!("default via {}\n", gw).into_bytes()
                } else {
                    b"none\n".to_vec()
                }
            } else {
                b"none\n".to_vec()
            }),
            "routes" => {
                let mut content = Vec::new();
                self.interface.routes_mut().update(|table| {
                    for route in table.iter() {
                        let line = alloc::format!("{} via {}\n", route.cidr, route.via_router);
                        content.extend_from_slice(line.as_bytes());
                    }
                });
                if content.is_empty() {
                    content.extend_from_slice(b"none\n");
                }
                Ok(content)
            }
            "resolve" => Ok(b"use /net/resolve/<hostname>\n".to_vec()),
            "tcp" => Ok(b"use /net/tcp/listen/<port>, /net/tcp/listen-once/<port>, /net/tcp/connect/<ip>/<port>[/<local_port>], /net/tcp/listeners, /net/tcp/connections, /net/tcp/stats\n".to_vec()),
            "tcp/listeners" => {
                let mut content = Vec::new();
                if self.tcp_listeners.is_empty() {
                    content.extend_from_slice(b"none\n");
                } else {
                    for (fid, listener) in self.tcp_listeners.iter() {
                        let socket = self.sockets.get::<tcp::Socket>(listener.socket);
                        let mode = if listener.auto_relisten { "auto" } else { "once" };
                        let line = alloc::format!(
                            "fid={} port={} state={} mode={}\n",
                            fid,
                            listener.port,
                            Self::tcp_state_name(socket.state()),
                            mode
                        );
                        content.extend_from_slice(line.as_bytes());
                    }
                }
                Ok(content)
            }
            "tcp/connections" => {
                let mut content = Vec::new();
                if self.tcp_connections.is_empty() {
                    content.extend_from_slice(b"none\n");
                } else {
                    for (fid, conn) in self.tcp_connections.iter() {
                        let socket = self.sockets.get::<tcp::Socket>(conn.socket);
                        let local = socket.local_endpoint();
                        let remote = socket.remote_endpoint();
                        let line = match (local, remote) {
                            (Some(local), Some(remote)) => alloc::format!(
                                "fid={} local={} remote={} state={}\n",
                                fid,
                                local,
                                remote,
                                Self::tcp_state_name(socket.state())
                            ),
                            _ => alloc::format!(
                                "fid={} local_port={} remote={} state={}\n",
                                fid,
                                conn.local_port,
                                conn.remote,
                                Self::tcp_state_name(socket.state())
                            ),
                        };
                        content.extend_from_slice(line.as_bytes());
                    }
                }
                Ok(content)
            }
            "tcp/stats" => {
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
                Ok(alloc::format!(
                    "listeners={}\nconnections={}\nestablished={}\nconnecting={}\nclosing={}\n",
                    listeners,
                    connections,
                    established,
                    connecting,
                    closing
                )
                .into_bytes())
            }
            "udp" => Ok(b"use /net/udp/bind/<port>, /net/udp/connect/<ip>/<port> or /net/udp/send/<ip>/<port>\n".to_vec()),
            path if path.starts_with("resolve/") => {
                let name = &path[8..];
                self.resolve_hostname_blocking(name)
                    .map(|addr| alloc::format!("{}\n", addr).into_bytes())
            }
            path if path.starts_with("ping/") || path.starts_with("ping6/") => {
                if let Some((seq, rtt_us)) = self.ping_replies.first().copied() {
                    self.ping_replies.remove(0);
                    let _ = call::debug_log(b"[ping] read returning seq=");
                    let _ = call::debug_log(&[(seq >> 8) as u8, seq as u8]);
                    let _ = call::debug_log(b" rtt=");
                    let _ = call::debug_log(&[(rtt_us / 1000) as u8]);
                    let _ = call::debug_log(b"ms\n");
                    let mut buf = vec![0u8; 10];
                    buf[0..2].copy_from_slice(&seq.to_le_bytes());
                    buf[2..10].copy_from_slice(&rtt_us.to_le_bytes());
                    Ok(buf)
                } else {
                    let _ = call::debug_log(b"[ping] read: no replies waiting\n");
                    Ok(Vec::new())
                }
            }
            _ => Err(-9),
        }
    }
}
