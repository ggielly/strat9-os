use smoltcp::wire::{IpAddress, IpCidr, Ipv4Address, Ipv4Cidr, Ipv6Address, Ipv6Cidr};
use strat9_abi::ip::{parse_ipv4_literal, parse_ipv6_literal};

pub(crate) struct IpConfig {
    pub(crate) address: Ipv4Cidr,
    pub(crate) host: Ipv4Address,
    pub(crate) prefix_len: u8,
    pub(crate) netmask: Ipv4Address,
    pub(crate) broadcast: Ipv4Address,
    pub(crate) gateway: Option<Ipv4Address>,
    pub(crate) dns: [Option<Ipv4Address>; 3],
}

#[derive(Debug, Clone)]
pub(crate) struct Ipv6Config {
    pub(crate) address: Ipv6Cidr,
    pub(crate) gateway: Option<Ipv6Address>,
}

pub(crate) fn icmp_checksum(data: &[u8]) -> u16 {
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

pub(crate) fn mask_from_prefix(prefix: u8) -> Ipv4Address {
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

pub(crate) fn broadcast_from_host_prefix(host: Ipv4Address, prefix: u8) -> Ipv4Address {
    let h = u32::from_be_bytes(host.octets());
    let m = u32::from_be_bytes(mask_from_prefix(prefix).octets());
    let b = (h & m) | (!m);
    let o = b.to_be_bytes();
    Ipv4Address::new(o[0], o[1], o[2], o[3])
}

pub(crate) fn parse_ipv4_cidr(s: &str) -> Option<Ipv4Cidr> {
    let slash = s.find('/')?;
    let ip = parse_ipv4(&s[..slash])?;
    let prefix = s[slash + 1..].parse::<u8>().ok()?;
    if prefix > 32 {
        return None;
    }
    Some(Ipv4Cidr::new(ip, prefix))
}

pub(crate) fn parse_ipv6(s: &str) -> Option<Ipv6Address> {
    parse_ipv6_literal(s).map(Ipv6Address::from_octets)
}

pub(crate) fn parse_ipv6_cidr(s: &str) -> Option<Ipv6Cidr> {
    let slash = s.find('/')?;
    let addr = parse_ipv6(&s[..slash])?;
    let prefix = s[slash + 1..].parse::<u8>().ok()?;
    if prefix > 128 {
        return None;
    }
    Some(Ipv6Cidr::new(addr, prefix))
}

pub(crate) fn link_local_from_mac(mac: [u8; 6]) -> Ipv6Address {
    let eui64: [u8; 8] = [
        mac[0] ^ 0x02,
        mac[1],
        mac[2],
        0xFF,
        0xFE,
        mac[3],
        mac[4],
        mac[5],
    ];
    let addr_bytes: [u8; 16] = [
        0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, eui64[0], eui64[1], eui64[2], eui64[3],
        eui64[4], eui64[5], eui64[6], eui64[7],
    ];
    Ipv6Address::from_octets(addr_bytes)
}

pub(crate) fn icmpv6_checksum(src: &[u8], dst: &[u8], data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in src.chunks_exact(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    for chunk in dst.chunks_exact(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    let len = data.len() as u32;
    sum += len >> 16;
    sum += len & 0xFFFF;
    sum += 58u32;
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

pub(crate) fn parse_ipv4(s: &str) -> Option<Ipv4Address> {
    let octets = parse_ipv4_literal(s)?;
    Some(Ipv4Address::new(octets[0], octets[1], octets[2], octets[3]))
}

pub(crate) fn parse_ip(s: &str) -> Option<IpAddress> {
    if let Some(ip) = parse_ipv4(s) {
        Some(IpAddress::Ipv4(ip))
    } else {
        parse_ipv6(s).map(IpAddress::Ipv6)
    }
}

pub(crate) fn parse_ip_cidr(s: &str) -> Option<IpCidr> {
    if let Some(cidr) = parse_ipv4_cidr(s) {
        Some(IpCidr::Ipv4(cidr))
    } else {
        parse_ipv6_cidr(s).map(IpCidr::Ipv6)
    }
}
