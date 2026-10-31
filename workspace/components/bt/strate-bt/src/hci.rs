//! HCI H4 transport framing, command builders and event parsing.
//!
//! The kernel exposes `/dev/bt/hci0` as one H4 packet per read/write call:
//! the first byte identifies the packet type (CMD/ACL/EVT).  Everything in
//! this module is allocation free and operates on caller supplied buffers.

pub const H4_CMD: u8 = 0x01;
pub const H4_ACL: u8 = 0x02;
pub const H4_EVT: u8 = 0x04;

// Event codes.
pub const EVT_DISCONNECTION_COMPLETE: u8 = 0x05;
pub const EVT_COMMAND_COMPLETE: u8 = 0x0E;
pub const EVT_COMMAND_STATUS: u8 = 0x0F;
pub const EVT_HARDWARE_ERROR: u8 = 0x10;
pub const EVT_NUMBER_OF_COMPLETED_PACKETS: u8 = 0x13;
pub const EVT_LE_META: u8 = 0x3E;

// LE meta sub-event codes.
pub const LE_CONNECTION_COMPLETE: u8 = 0x01;
pub const LE_ADVERTISING_REPORT: u8 = 0x02;
pub const LE_DATA_LENGTH_CHANGE: u8 = 0x07;
pub const LE_PHY_UPDATE: u8 = 0x0C;

// Opcode helpers.  An HCI opcode is OGF[15:10] | OCF[9:0].
pub const fn make_opcode(ogf: u16, ocf: u16) -> u16 {
    ((ogf & 0x3f) << 10) | (ocf & 0x03ff)
}

pub const fn opcode_ogf(opcode: u16) -> u8 {
    (opcode >> 10) as u8
}

pub const fn opcode_ocf(opcode: u16) -> u16 {
    opcode & 0x03ff
}

// Command opcodes used by this peripheral.
pub const OP_RESET: u16 = 0x0C03;
pub const OP_READ_LOCAL_VERSION: u16 = 0x1001;
pub const OP_READ_BD_ADDR: u16 = 0x1009;
pub const OP_SET_EVENT_MASK: u16 = 0x0C01;
pub const OP_LE_SET_EVENT_MASK: u16 = 0x2001;
pub const OP_LE_READ_BUFFER_SIZE: u16 = 0x2002;
pub const OP_LE_SET_ADVERTISING_PARAMS: u16 = 0x2006;
pub const OP_LE_SET_ADVERTISING_DATA: u16 = 0x2008;
pub const OP_LE_SET_SCAN_RESPONSE_DATA: u16 = 0x2009;
pub const OP_LE_SET_ADVERTISING_ENABLE: u16 = 0x200A;
pub const OP_LE_SET_DATA_LENGTH: u16 = 0x2022;
pub const OP_LE_SET_PHY: u16 = 0x2032;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    Truncated,
    BadPacketType,
    BadLength,
    UnsupportedEvent,
    TooManyReports,
}

/// Write an HCI command (including the H4 type byte) into `out`.
pub fn command(out: &mut [u8], opcode: u16, params: &[u8]) -> Option<usize> {
    if params.len() > u8::MAX as usize {
        return None;
    }
    let n = 4 + params.len();
    if out.len() < n {
        return None;
    }
    out[0] = H4_CMD;
    out[1] = opcode as u8;
    out[2] = (opcode >> 8) as u8;
    out[3] = params.len() as u8;
    out[4..n].copy_from_slice(params);
    Some(n)
}

fn cmd_no_params(out: &mut [u8], opcode: u16) -> Option<usize> {
    command(out, opcode, &[])
}

pub fn reset(out: &mut [u8]) -> Option<usize> {
    cmd_no_params(out, OP_RESET)
}

pub fn read_local_version(out: &mut [u8]) -> Option<usize> {
    cmd_no_params(out, OP_READ_LOCAL_VERSION)
}

pub fn read_bd_addr(out: &mut [u8]) -> Option<usize> {
    cmd_no_params(out, OP_READ_BD_ADDR)
}

pub fn set_event_mask(out: &mut [u8], mask: u64) -> Option<usize> {
    command(out, OP_SET_EVENT_MASK, &mask.to_le_bytes())
}

pub fn le_set_event_mask(out: &mut [u8], mask: u64) -> Option<usize> {
    command(out, OP_LE_SET_EVENT_MASK, &mask.to_le_bytes())
}

pub fn le_read_buffer_size(out: &mut [u8]) -> Option<usize> {
    cmd_no_params(out, OP_LE_READ_BUFFER_SIZE)
}

#[allow(clippy::too_many_arguments)]
pub fn le_set_advertising_params(
    out: &mut [u8],
    interval_min: u16,
    interval_max: u16,
    adv_type: u8,
    own_addr_type: u8,
    peer_addr_type: u8,
    peer_addr: &[u8; 6],
    channel_map: u8,
    filter_policy: u8,
) -> Option<usize> {
    let mut p = [0u8; 15];
    p[0..2].copy_from_slice(&interval_min.to_le_bytes());
    p[2..4].copy_from_slice(&interval_max.to_le_bytes());
    p[4] = adv_type;
    p[5] = own_addr_type;
    p[6] = peer_addr_type;
    p[7..13].copy_from_slice(peer_addr);
    p[13] = channel_map;
    p[14] = filter_policy;
    command(out, OP_LE_SET_ADVERTISING_PARAMS, &p)
}

pub fn le_set_advertising_data(out: &mut [u8], data: &[u8]) -> Option<usize> {
    if data.len() > 31 {
        return None;
    }
    let mut p = [0u8; 32];
    p[0] = data.len() as u8;
    p[1..1 + data.len()].copy_from_slice(data);
    command(out, OP_LE_SET_ADVERTISING_DATA, &p[..1 + data.len()])
}

pub fn le_set_scan_response_data(out: &mut [u8], data: &[u8]) -> Option<usize> {
    if data.len() > 31 {
        return None;
    }
    let mut p = [0u8; 32];
    p[0] = data.len() as u8;
    p[1..1 + data.len()].copy_from_slice(data);
    command(out, OP_LE_SET_SCAN_RESPONSE_DATA, &p[..1 + data.len()])
}

pub fn le_set_advertising_enable(out: &mut [u8], enable: bool) -> Option<usize> {
    command(out, OP_LE_SET_ADVERTISING_ENABLE, &[enable as u8])
}

pub fn le_set_data_length(
    out: &mut [u8],
    handle: u16,
    tx_octets: u16,
    tx_time: u16,
) -> Option<usize> {
    let mut p = [0u8; 6];
    p[0..2].copy_from_slice(&handle.to_le_bytes());
    p[2..4].copy_from_slice(&tx_octets.to_le_bytes());
    p[4..6].copy_from_slice(&tx_time.to_le_bytes());
    command(out, OP_LE_SET_DATA_LENGTH, &p)
}

pub fn le_set_phy(
    out: &mut [u8],
    handle: u16,
    all_phys: u8,
    tx_phys: u8,
    rx_phys: u8,
) -> Option<usize> {
    let mut p = [0u8; 5];
    p[0..2].copy_from_slice(&handle.to_le_bytes());
    p[2] = all_phys;
    p[3] = tx_phys;
    p[4] = rx_phys;
    command(out, OP_LE_SET_PHY, &p)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AclHeader {
    pub handle: u16,
    pub pb: u8,
    pub bc: u8,
    pub data_len: u16,
}

impl AclHeader {
    pub fn new(handle: u16, pb: u8, bc: u8, data_len: u16) -> Self {
        Self {
            handle: handle & 0x0fff,
            pb: pb & 0x03,
            bc: bc & 0x03,
            data_len,
        }
    }

    /// Packet boundary flag: 00 first non-flushable, 01 continuation,
    /// 10 first flushable, 11 reserved.
    pub fn packet_boundary(&self) -> u8 {
        self.pb
    }

    pub fn broadcast(&self) -> u8 {
        self.bc
    }

    pub fn is_start(&self) -> bool {
        self.pb == 0b00 || self.pb == 0b10
    }

    pub fn is_continuation(&self) -> bool {
        self.pb == 0b01
    }
}

/// Parse a complete H4 ACL packet (type byte included) into its header and
/// payload.  The payload length must match the header exactly.
pub fn parse_acl(packet: &[u8]) -> Result<(AclHeader, &[u8]), ParseError> {
    if packet.len() < 5 {
        return Err(ParseError::Truncated);
    }
    if packet[0] != H4_ACL {
        return Err(ParseError::BadPacketType);
    }
    let flags = u16::from_le_bytes([packet[1], packet[2]]);
    let data_len = u16::from_le_bytes([packet[3], packet[4]]);
    let header = AclHeader {
        handle: flags & 0x0fff,
        pb: ((flags >> 12) & 0x03) as u8,
        bc: ((flags >> 14) & 0x03) as u8,
        data_len,
    };
    let end = 5usize
        .checked_add(data_len as usize)
        .ok_or(ParseError::BadLength)?;
    if packet.len() < end {
        return Err(ParseError::Truncated);
    }
    if packet.len() != end {
        return Err(ParseError::BadLength);
    }
    if header.pb == 0b11 {
        return Err(ParseError::BadLength);
    }
    Ok((header, &packet[5..end]))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompletedPacket {
    pub handle: u16,
    pub count: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompletedPackets {
    pub num_handles: u8,
    pub items: [CompletedPacket; 8],
}

impl CompletedPackets {
    pub fn iter(&self) -> impl Iterator<Item = &CompletedPacket> {
        self.items[..self.num_handles as usize].iter()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdvertisingReport<'a> {
    pub num_reports: u8,
    pub event_type: u8,
    pub address_type: u8,
    pub address: [u8; 6],
    pub data: &'a [u8],
    pub rssi: i8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeEvent<'a> {
    ConnectionComplete {
        status: u8,
        handle: u16,
        role: u8,
        peer_address_type: u8,
        peer_address: [u8; 6],
        interval: u16,
        latency: u16,
        timeout: u16,
        master_clock_accuracy: u8,
    },
    AdvertisingReport(AdvertisingReport<'a>),
    DataLengthChange {
        handle: u16,
        max_tx_octets: u16,
        max_tx_time: u16,
        max_rx_octets: u16,
        max_rx_time: u16,
    },
    PhyUpdate {
        status: u8,
        handle: u16,
        tx_phy: u8,
        rx_phy: u8,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event<'a> {
    CommandComplete {
        num_packets: u8,
        opcode: u16,
        returns: &'a [u8],
    },
    CommandStatus {
        status: u8,
        num_packets: u8,
        opcode: u16,
    },
    LeMeta(LeEvent<'a>),
    DisconnectionComplete {
        status: u8,
        handle: u16,
        reason: u8,
    },
    NumberOfCompletedPackets(CompletedPackets),
    HardwareError {
        code: u8,
    },
}

fn le16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn parse_le_meta(p: &[u8]) -> Result<LeEvent<'_>, ParseError> {
    if p.is_empty() {
        return Err(ParseError::Truncated);
    }
    let sub = p[0];
    let r = &p[1..];
    match sub {
        LE_CONNECTION_COMPLETE => {
            if r.len() < 18 {
                return Err(ParseError::Truncated);
            }
            let mut addr = [0u8; 6];
            addr.copy_from_slice(&r[5..11]);
            Ok(LeEvent::ConnectionComplete {
                status: r[0],
                handle: le16(r, 1),
                role: r[3],
                peer_address_type: r[4],
                peer_address: addr,
                interval: le16(r, 11),
                latency: le16(r, 13),
                timeout: le16(r, 15),
                master_clock_accuracy: r[17],
            })
        }
        LE_ADVERTISING_REPORT => {
            if r.len() < 2 {
                return Err(ParseError::Truncated);
            }
            let num_reports = r[0];
            if num_reports == 0 {
                return Err(ParseError::BadLength);
            }
            let mut o = 1usize;
            if r.len() < o + 8 {
                return Err(ParseError::Truncated);
            }
            let event_type = r[o];
            let address_type = r[o + 1];
            let mut address = [0u8; 6];
            address.copy_from_slice(&r[o + 2..o + 8]);
            o += 8;
            if r.len() < o + 1 {
                return Err(ParseError::Truncated);
            }
            let dlen = r[o] as usize;
            o += 1;
            if r.len() < o + dlen + 1 {
                return Err(ParseError::Truncated);
            }
            let data = &r[o..o + dlen];
            o += dlen;
            let rssi = r[o] as i8;
            Ok(LeEvent::AdvertisingReport(AdvertisingReport {
                num_reports,
                event_type,
                address_type,
                address,
                data,
                rssi,
            }))
        }
        LE_DATA_LENGTH_CHANGE => {
            if r.len() < 10 {
                return Err(ParseError::Truncated);
            }
            Ok(LeEvent::DataLengthChange {
                handle: le16(r, 0),
                max_tx_octets: le16(r, 2),
                max_tx_time: le16(r, 4),
                max_rx_octets: le16(r, 6),
                max_rx_time: le16(r, 8),
            })
        }
        LE_PHY_UPDATE => {
            if r.len() < 5 {
                return Err(ParseError::Truncated);
            }
            Ok(LeEvent::PhyUpdate {
                status: r[0],
                handle: le16(r, 1),
                tx_phy: r[3],
                rx_phy: r[4],
            })
        }
        _ => Err(ParseError::UnsupportedEvent),
    }
}

/// Parse a complete H4 event packet.  All length fields are validated before
/// any slice is formed.
pub fn parse_event(packet: &[u8]) -> Result<Event<'_>, ParseError> {
    if packet.len() < 3 {
        return Err(ParseError::Truncated);
    }
    if packet[0] != H4_EVT {
        return Err(ParseError::BadPacketType);
    }
    let code = packet[1];
    let plen = packet[2] as usize;
    let end = 3usize
        .checked_add(plen)
        .ok_or(ParseError::BadLength)?;
    if packet.len() < end {
        return Err(ParseError::Truncated);
    }
    if packet.len() != end {
        return Err(ParseError::BadLength);
    }
    let p = &packet[3..end];
    match code {
        EVT_COMMAND_COMPLETE => {
            if p.len() < 3 {
                return Err(ParseError::Truncated);
            }
            Ok(Event::CommandComplete {
                num_packets: p[0],
                opcode: le16(p, 1),
                returns: &p[3..],
            })
        }
        EVT_COMMAND_STATUS => {
            if p.len() < 4 {
                return Err(ParseError::Truncated);
            }
            Ok(Event::CommandStatus {
                status: p[0],
                num_packets: p[1],
                opcode: le16(p, 2),
            })
        }
        EVT_DISCONNECTION_COMPLETE => {
            if p.len() < 4 {
                return Err(ParseError::Truncated);
            }
            Ok(Event::DisconnectionComplete {
                status: p[0],
                handle: le16(p, 1),
                reason: p[3],
            })
        }
        EVT_NUMBER_OF_COMPLETED_PACKETS => {
            if p.is_empty() {
                return Err(ParseError::Truncated);
            }
            let num = p[0];
            if num as usize > 8 {
                return Err(ParseError::TooManyReports);
            }
            let need = 1 + 4 * num as usize;
            if p.len() < need {
                return Err(ParseError::Truncated);
            }
            let mut items = [CompletedPacket {
                handle: 0,
                count: 0,
            }; 8];
            for i in 0..num as usize {
                let o = 1 + i * 4;
                items[i] = CompletedPacket {
                    handle: le16(p, o),
                    count: le16(p, o + 2),
                };
            }
            Ok(Event::NumberOfCompletedPackets(CompletedPackets {
                num_handles: num,
                items,
            }))
        }
        EVT_HARDWARE_ERROR => {
            if p.is_empty() {
                return Err(ParseError::Truncated);
            }
            Ok(Event::HardwareError { code: p[0] })
        }
        EVT_LE_META => Ok(Event::LeMeta(parse_le_meta(p)?)),
        _ => Err(ParseError::UnsupportedEvent),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opcode_of(buf: &[u8]) -> u16 {
        u16::from_le_bytes([buf[1], buf[2]])
    }

    fn assert_cmd(buf: &[u8], opcode: u16, plen: usize) {
        assert_eq!(buf[0], H4_CMD);
        assert_eq!(opcode_of(buf), opcode);
        assert_eq!(buf[3] as usize, plen);
        assert_eq!(buf.len(), 4 + plen);
    }

    #[test]
    fn opcode_parts() {
        assert_eq!(make_opcode(0x03, 0x03), OP_RESET);
        assert_eq!(opcode_ogf(OP_LE_SET_PHY), 0x08);
        assert_eq!(opcode_ocf(OP_LE_SET_PHY), 0x032);
        assert_eq!(opcode_ogf(OP_READ_BD_ADDR), 0x04);
        assert_eq!(opcode_ocf(OP_READ_BD_ADDR), 0x009);
    }

    #[test]
    fn builds_all_commands() {
        let mut b = [0u8; 64];
        let n = reset(&mut b).unwrap();
        assert_cmd(&b[..n], OP_RESET, 0);

        let n = read_local_version(&mut b).unwrap();
        assert_cmd(&b[..n], OP_READ_LOCAL_VERSION, 0);

        let n = read_bd_addr(&mut b).unwrap();
        assert_cmd(&b[..n], OP_READ_BD_ADDR, 0);

        let n = set_event_mask(&mut b, 0x1122_3344_5566_7788).unwrap();
        assert_cmd(&b[..n], OP_SET_EVENT_MASK, 8);
        assert_eq!(&b[4..n], &0x1122_3344_5566_7788u64.to_le_bytes());

        let n = le_set_event_mask(&mut b, 0x0000_0000_0000_001f).unwrap();
        assert_cmd(&b[..n], OP_LE_SET_EVENT_MASK, 8);
        assert_eq!(b[n - 1], 0x00);

        let n = le_read_buffer_size(&mut b).unwrap();
        assert_cmd(&b[..n], OP_LE_READ_BUFFER_SIZE, 0);

        let n = le_set_advertising_params(
            &mut b,
            0x00a0,
            0x00a0,
            0x00,
            0x00,
            0x00,
            &[0u8; 6],
            0x07,
            0x00,
        )
        .unwrap();
        assert_cmd(&b[..n], OP_LE_SET_ADVERTISING_PARAMS, 15);
        assert_eq!(b[4], 0xa0);
        assert_eq!(b[n - 1], 0x00);

        let n = le_set_advertising_data(&mut b, &[0x02, 0x01, 0x06]).unwrap();
        assert_cmd(&b[..n], OP_LE_SET_ADVERTISING_DATA, 4);
        assert_eq!(b[4], 3);

        let n = le_set_scan_response_data(&mut b, &[0x03, 0x08, b'x', b'y']).unwrap();
        assert_cmd(&b[..n], OP_LE_SET_SCAN_RESPONSE_DATA, 5);
        assert_eq!(b[4], 4);

        let n = le_set_advertising_enable(&mut b, true).unwrap();
        assert_cmd(&b[..n], OP_LE_SET_ADVERTISING_ENABLE, 1);
        assert_eq!(b[4], 1);

        let n = le_set_data_length(&mut b, 0x0040, 251, 2120).unwrap();
        assert_cmd(&b[..n], OP_LE_SET_DATA_LENGTH, 6);
        assert_eq!(&b[4..6], &[0x40, 0x00]);

        let n = le_set_phy(&mut b, 0x0040, 0x00, 0x02, 0x02).unwrap();
        assert_cmd(&b[..n], OP_LE_SET_PHY, 5);

        assert!(le_set_advertising_data(&mut b, &[0u8; 32]).is_none());
        assert!(command(&mut b[..3], OP_RESET, &[]).is_none());
    }

    #[test]
    fn parses_command_complete() {
        // H4 EVT, Command Complete, plen 6: ncmd 1, opcode 0x0C03, status 0.
        let pkt = [0x04, 0x0E, 0x06, 0x01, 0x03, 0x0C, 0x00, 0xAA, 0xBB];
        match parse_event(&pkt).unwrap() {
            Event::CommandComplete {
                num_packets,
                opcode,
                returns,
            } => {
                assert_eq!(num_packets, 1);
                assert_eq!(opcode, OP_RESET);
                assert_eq!(returns, &[0x00, 0xAA, 0xBB]);
            }
            _ => panic!("wrong event"),
        }
    }

    #[test]
    fn parses_command_status_and_disconnection() {
        let pkt = [0x04, 0x0F, 0x04, 0x00, 0x01, 0x03, 0x0C];
        assert_eq!(
            parse_event(&pkt).unwrap(),
            Event::CommandStatus {
                status: 0,
                num_packets: 1,
                opcode: OP_RESET
            }
        );

        let pkt = [0x04, 0x05, 0x04, 0x00, 0x40, 0x00, 0x13];
        assert_eq!(
            parse_event(&pkt).unwrap(),
            Event::DisconnectionComplete {
                status: 0,
                handle: 0x0040,
                reason: 0x13
            }
        );
    }

    #[test]
    fn parses_le_connection_complete() {
        let mut pkt = [0u8; 22];
        pkt[0] = 0x04;
        pkt[1] = EVT_LE_META;
        pkt[2] = 19;
        pkt[3] = LE_CONNECTION_COMPLETE;
        pkt[4] = 0x00; // status
        pkt[5] = 0x40;
        pkt[6] = 0x00; // handle
        pkt[7] = 0x01; // role
        pkt[8] = 0x01; // peer addr type
        pkt[9..15].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        pkt[15] = 0x18;
        pkt[16] = 0x00; // interval
        pkt[17] = 0x00;
        pkt[18] = 0x00; // latency
        pkt[19] = 0x48;
        pkt[20] = 0x00; // timeout
        pkt[21] = 0x07; // master clock accuracy
        match parse_event(&pkt).unwrap() {
            Event::LeMeta(LeEvent::ConnectionComplete {
                status,
                handle,
                role,
                peer_address_type,
                peer_address,
                interval,
                latency,
                timeout,
                master_clock_accuracy,
            }) => {
                assert_eq!(status, 0);
                assert_eq!(handle, 0x0040);
                assert_eq!(role, 1);
                assert_eq!(peer_address_type, 1);
                assert_eq!(peer_address, [1, 2, 3, 4, 5, 6]);
                assert_eq!(interval, 0x18);
                assert_eq!(latency, 0);
                assert_eq!(timeout, 0x48);
                assert_eq!(master_clock_accuracy, 7);
            }
            _ => panic!("wrong event"),
        }
    }

    #[test]
    fn parses_advertising_report() {
        let mut pkt = [0u8; 17];
        pkt[0] = 0x04;
        pkt[1] = EVT_LE_META;
        pkt[2] = 14;
        pkt[3] = LE_ADVERTISING_REPORT;
        pkt[4] = 1; // reports
        pkt[5] = 0; // event type
        pkt[6] = 0; // addr type
        pkt[7..13].copy_from_slice(&[9, 8, 7, 6, 5, 4]);
        pkt[13] = 2; // data len
        pkt[14] = 0x02;
        pkt[15] = 0x01;
        pkt[16] = 0xc8; // rssi = -56
        match parse_event(&pkt).unwrap() {
            Event::LeMeta(LeEvent::AdvertisingReport(r)) => {
                assert_eq!(r.num_reports, 1);
                assert_eq!(r.address, [9, 8, 7, 6, 5, 4]);
                assert_eq!(r.data, &[0x02, 0x01]);
                assert_eq!(r.rssi, -56);
            }
            _ => panic!("wrong event"),
        }
    }

    #[test]
    fn parses_data_length_and_phy_update() {
        let mut pkt = [0u8; 14];
        pkt[0] = 0x04;
        pkt[1] = EVT_LE_META;
        pkt[2] = 11;
        pkt[3] = LE_DATA_LENGTH_CHANGE;
        pkt[4] = 0x40;
        pkt[5] = 0x00;
        pkt[6] = 0xfb;
        pkt[7] = 0x00;
        pkt[8] = 0x48;
        pkt[9] = 0x08;
        pkt[10] = 0xfb;
        pkt[11] = 0x00;
        pkt[12] = 0x48;
        pkt[13] = 0x08;
        assert_eq!(
            parse_event(&pkt).unwrap(),
            Event::LeMeta(LeEvent::DataLengthChange {
                handle: 0x0040,
                max_tx_octets: 251,
                max_tx_time: 2120,
                max_rx_octets: 251,
                max_rx_time: 0x0848,
            })
        );

        let pkt = [
            0x04, EVT_LE_META, 0x06, LE_PHY_UPDATE, 0x00, 0x40, 0x00, 0x02, 0x01,
        ];
        assert_eq!(
            parse_event(&pkt).unwrap(),
            Event::LeMeta(LeEvent::PhyUpdate {
                status: 0,
                handle: 0x0040,
                tx_phy: 0x02,
                rx_phy: 0x01,
            })
        );
    }

    #[test]
    fn parses_completed_packets_and_hardware_error() {
        let pkt = [
            0x04,
            EVT_NUMBER_OF_COMPLETED_PACKETS,
            0x09,
            0x02,
            0x40,
            0x00,
            0x01,
            0x00,
            0x41,
            0x00,
            0x02,
            0x00,
        ];
        match parse_event(&pkt).unwrap() {
            Event::NumberOfCompletedPackets(c) => {
                assert_eq!(c.num_handles, 2);
                assert_eq!(
                    c.iter().next().copied(),
                    Some(CompletedPacket { handle: 0x40, count: 1 })
                );
                assert_eq!(
                    c.iter().nth(1).copied(),
                    Some(CompletedPacket { handle: 0x41, count: 2 })
                );
            }
            _ => panic!("wrong event"),
        }

        let pkt = [0x04, EVT_HARDWARE_ERROR, 0x01, 0x2a];
        assert_eq!(
            parse_event(&pkt).unwrap(),
            Event::HardwareError { code: 0x2a }
        );
    }

    #[test]
    fn rejects_truncated_packets() {
        assert_eq!(parse_event(&[]), Err(ParseError::Truncated));
        assert_eq!(parse_event(&[0x04, 0x0e]), Err(ParseError::Truncated));
        assert_eq!(
            parse_event(&[0x04, 0x0e, 0x06, 0x01, 0x03]),
            Err(ParseError::Truncated)
        );
        assert_eq!(
            parse_event(&[0x04, 0x0e, 0x06, 0x01, 0x03, 0x0c, 0x00]),
            Err(ParseError::Truncated)
        );
        assert_eq!(
            parse_event(&[0x04, 0x0e, 0x01, 0x01]),
            Err(ParseError::Truncated)
        );
        assert_eq!(
            parse_event(&[0x04, 0x0e, 0x01, 0x01, 0x02]),
            Err(ParseError::BadLength)
        );
        assert_eq!(
            parse_event(&[0x04, LE_META_BAD, 0x00]),
            Err(ParseError::UnsupportedEvent)
        );
        assert_eq!(parse_event(&[0x02, 0x0e, 0x00]), Err(ParseError::BadPacketType));
    }

    const LE_META_BAD: u8 = 0x99;

    #[test]
    fn parses_acl_header_and_validates_length() {
        let mut pkt = [0u8; 9];
        pkt[0] = H4_ACL;
        pkt[1] = 0x40;
        pkt[2] = 0x20; // handle 0x40, PB=0b10, BC=0
        pkt[3] = 0x04;
        pkt[4] = 0x00;
        pkt[5..9].copy_from_slice(&[1, 2, 3, 4]);
        let (h, body) = parse_acl(&pkt).unwrap();
        assert_eq!(h.handle, 0x40);
        assert_eq!(h.packet_boundary(), 0b10);
        assert!(h.is_start());
        assert_eq!(h.data_len, 4);
        assert_eq!(body, &[1, 2, 3, 4]);

        assert_eq!(parse_acl(&pkt[..4]), Err(ParseError::Truncated));
        let mut short = pkt;
        short[3] = 5;
        assert_eq!(parse_acl(&short), Err(ParseError::Truncated));
        let mut long = pkt;
        long[3] = 3;
        assert_eq!(parse_acl(&long), Err(ParseError::BadLength));
        let mut badpb = pkt;
        badpb[2] = 0x30;
        assert_eq!(parse_acl(&badpb), Err(ParseError::BadLength));
    }
}
