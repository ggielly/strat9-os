use smoltcp::{
    socket::{dhcpv4, dns},
    wire::{DnsQueryType, IpAddress, IpCidr, Ipv4Address, Ipv6Address, Ipv6Cidr},
};
use strate_net::syscalls::clock_gettime_ns;

use crate::{
    ip::{
        broadcast_from_host_prefix, mask_from_prefix, parse_ipv4, parse_ipv6, IpConfig, Ipv6Config,
    },
    now_instant, sleep_micros,
    state::NetworkStrate,
};

impl NetworkStrate {
    pub(crate) fn process_dhcp(&mut self) {
        if !self.dhcp_enabled {
            return;
        }

        let event = self
            .sockets
            .get_mut::<dhcpv4::Socket>(self.dhcp_handle)
            .poll();

        match event {
            Some(dhcpv4::Event::Configured(config)) => {
                crate::log("[strate-net] DHCP: address acquired\n");

                self.interface.update_ip_addrs(|addrs| {
                    let cidr = IpCidr::new(
                        IpAddress::Ipv4(config.address.address()),
                        config.address.prefix_len(),
                    );
                    for addr in addrs.iter_mut() {
                        if matches!(addr, IpCidr::Ipv4(_)) {
                            *addr = cidr;
                            return;
                        }
                    }
                    let _ = addrs.push(cidr);
                });

                let _ = self.interface.routes_mut().remove_default_ipv4_route();
                if let Some(gw) = config.router {
                    self.interface.routes_mut().add_default_ipv4_route(gw).ok();
                }

                let mut dns = [None::<Ipv4Address>; 3];
                self.dns_servers = [None; 3];
                for ((slot_v4, slot_any), &server) in dns
                    .iter_mut()
                    .zip(self.dns_servers.iter_mut())
                    .zip(config.dns_servers.iter())
                {
                    *slot_v4 = Some(server);
                    *slot_any = Some(IpAddress::Ipv4(server));
                }
                self.dns_from_dhcp = true;

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
                crate::log("[strate-net] DHCP: deconfigured (lease expired?)\n");
                if self.dns_from_dhcp {
                    self.dns_servers = [None; 3];
                    self.dns_from_dhcp = false;
                }
                self.clear_ipv4_runtime_config();
            }
            None => {}
        }
    }

    pub(crate) fn refresh_dns_servers(&mut self) {
        let mut servers = [IpAddress::Ipv4(Ipv4Address::new(0, 0, 0, 0)); 3];
        let mut count = 0usize;

        for server in self.dns_servers.iter().flatten() {
            if count < servers.len() {
                servers[count] = *server;
                count += 1;
            }
        }

        if count == 0 {
            if let Some(ref cfg) = self.ip_config {
                if let Some(gw) = cfg.gateway {
                    servers[0] = IpAddress::Ipv4(gw);
                    count = 1;
                }
            }
        }

        if count == 0 {
            if let Some(ref cfg) = self.ipv6_config {
                if let Some(gw) = cfg.gateway {
                    servers[0] = IpAddress::Ipv6(gw);
                    count = 1;
                }
            }
        }

        let socket = self.sockets.get_mut::<dns::Socket>(self.dns_handle);
        socket.update_servers(&servers[..count]);
    }

    pub(crate) fn apply_ipv4_config(
        &mut self,
        address: smoltcp::wire::Ipv4Cidr,
        gateway: Option<Ipv4Address>,
    ) {
        let host = address.address();
        let prefix_len = address.prefix_len();
        let netmask = mask_from_prefix(prefix_len);
        let broadcast = broadcast_from_host_prefix(host, prefix_len);

        self.interface.update_ip_addrs(|addrs| {
            let cidr = IpCidr::new(IpAddress::Ipv4(host), prefix_len);
            for addr in addrs.iter_mut() {
                if matches!(addr, IpCidr::Ipv4(_)) {
                    *addr = cidr;
                    return;
                }
            }
            let _ = addrs.push(cidr);
        });

        let _ = self.interface.routes_mut().remove_default_ipv4_route();
        if let Some(gw) = gateway {
            let _ = self.interface.routes_mut().add_default_ipv4_route(gw);
        }

        let mut dns = [None; 3];
        for (slot, server) in dns.iter_mut().zip(self.dns_servers.iter()) {
            if let Some(IpAddress::Ipv4(addr)) = server {
                *slot = Some(*addr);
            }
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
        self.dns_from_dhcp = false;
        self.refresh_dns_servers();
    }

    pub(crate) fn apply_ipv6_config(&mut self, address: Ipv6Cidr, gateway: Option<Ipv6Address>) {
        self.interface.update_ip_addrs(|addrs| {
            let cidr = IpCidr::new(IpAddress::Ipv6(address.address()), address.prefix_len());
            for addr in addrs.iter_mut() {
                if let IpCidr::Ipv6(current) = addr {
                    if !current.address().is_unicast_link_local() {
                        *addr = cidr;
                        return;
                    }
                }
            }
            let _ = addrs.push(cidr);
        });
        if let Some(gw) = gateway {
            let _ = self.interface.routes_mut().add_default_ipv6_route(gw);
        }
        self.ipv6_config = Some(Ipv6Config { address, gateway });
        self.refresh_dns_servers();
    }

    pub(crate) fn resolve_hostname_query(
        &mut self,
        name: &str,
        q_type: DnsQueryType,
    ) -> core::result::Result<IpAddress, i32> {
        let query = {
            let cx = self.interface.context();
            let socket = self.sockets.get_mut::<dns::Socket>(self.dns_handle);
            match socket.start_query(cx, name, q_type) {
                Ok(query) => query,
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
            self.process_ipv6_slaac();
            self.process_icmp();

            let res = self
                .sockets
                .get_mut::<dns::Socket>(self.dns_handle)
                .get_query_result(query);
            match res {
                Ok(addrs) => {
                    for addr in addrs {
                        return Ok(addr);
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

    pub(crate) fn resolve_hostname_blocking(
        &mut self,
        name: &str,
    ) -> core::result::Result<IpAddress, i32> {
        if let Some(ip) = parse_ipv4(name) {
            return Ok(IpAddress::Ipv4(ip));
        }
        if let Some(ip) = parse_ipv6(name) {
            return Ok(IpAddress::Ipv6(ip));
        }
        if self.ip_config.is_none() && self.ipv6_config.is_none() {
            return Err(-11);
        }

        let mut last_err = -2;
        if self.ipv6_config.is_some() {
            match self.resolve_hostname_query(name, DnsQueryType::Aaaa) {
                Ok(addr) => return Ok(addr),
                Err(-2) => {}
                Err(err) => last_err = err,
            }
        }
        if self.ip_config.is_some() {
            match self.resolve_hostname_query(name, DnsQueryType::A) {
                Ok(addr) => return Ok(addr),
                Err(err) => last_err = err,
            }
        }
        Err(last_err)
    }

    pub(crate) fn process_ipv6_slaac(&mut self) {
        let mut global_addr: Option<Ipv6Cidr> = None;
        self.interface.update_ip_addrs(|addrs| {
            for addr in addrs.iter() {
                if let IpCidr::Ipv6(cidr) = addr {
                    if !cidr.address().is_unicast_link_local() && global_addr.is_none() {
                        global_addr = Some(*cidr);
                    }
                }
            }
        });

        let mut gateway: Option<Ipv6Address> = None;
        self.interface.routes_mut().update(|table| {
            for route in table.iter() {
                if let (IpCidr::Ipv6(cidr), IpAddress::Ipv6(via)) = (route.cidr, route.via_router) {
                    if cidr.prefix_len() == 0 {
                        gateway = Some(via);
                        break;
                    }
                }
            }
        });

        match (global_addr, &mut self.ipv6_config) {
            (Some(addr), Some(cfg)) => {
                cfg.address = addr;
                cfg.gateway = gateway;
            }
            (Some(addr), cfg @ None) => {
                *cfg = Some(Ipv6Config {
                    address: addr,
                    gateway,
                });
            }
            (None, _) => {
                self.ipv6_config = None;
            }
        }
    }
}
