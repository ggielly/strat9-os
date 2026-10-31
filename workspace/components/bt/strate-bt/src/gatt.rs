//! Nordic UART Service compatible GATT attribute table.
//!
//! Layout (handles are assigned sequentially):
//!
//! | handle | attribute | type |
//! |--------|-----------|------|
//! | 1 | GAP service 0x1800 | 0x2800 |
//! | 2 | Device Name declaration | 0x2803 |
//! | 3 | Device Name "S9-DUMP" | 0x2A00 |
//! | 4 | Appearance declaration | 0x2803 |
//! | 5 | Appearance | 0x2A01 |
//! | 6 | NUS service | 0x2800 |
//! | 7 | TX characteristic declaration | 0x2803 |
//! | 8 | TX value (notify) | 0x6E400003-... |
//! | 9 | TX CCCD | 0x2902 |
//! | 10 | RX characteristic declaration | 0x2803 |
//! | 11 | RX value (write / write-no-response) | 0x6E400002-... |

use crate::att::{self, AttServer};

pub const GAP_SERVICE_UUID: [u8; 2] = [0x00, 0x18];
pub const DEVICE_NAME_UUID: [u8; 2] = [0x00, 0x2A];
pub const APPEARANCE_UUID: [u8; 2] = [0x01, 0x2A];
pub const PRIMARY_SERVICE_UUID: [u8; 2] = [0x00, 0x28];
pub const CHARACTERISTIC_UUID: [u8; 2] = [0x03, 0x28];
pub const CCCD_UUID: [u8; 2] = [0x02, 0x29];

pub const NUS_SERVICE_UUID: [u8; 16] = [
    0x9E, 0xCA, 0xDC, 0x24, 0x0E, 0xE5, 0xA9, 0xE0, 0x93, 0xF3, 0xA3, 0xB5, 0x01, 0x00, 0x40, 0x6E,
];
pub const NUS_TX_UUID: [u8; 16] = [
    0x9E, 0xCA, 0xDC, 0x24, 0x0E, 0xE5, 0xA9, 0xE0, 0x93, 0xF3, 0xA3, 0xB5, 0x03, 0x00, 0x40, 0x6E,
];
pub const NUS_RX_UUID: [u8; 16] = [
    0x9E, 0xCA, 0xDC, 0x24, 0x0E, 0xE5, 0xA9, 0xE0, 0x93, 0xF3, 0xA3, 0xB5, 0x02, 0x00, 0x40, 0x6E,
];

pub const DEVICE_NAME: &[u8] = b"S9-DUMP";
pub const APPEARANCE: [u8; 2] = [0x00, 0x00];

pub const HANDLE_GAP_SERVICE: u16 = 1;
pub const HANDLE_DEVICE_NAME_DECL: u16 = 2;
pub const HANDLE_DEVICE_NAME: u16 = 3;
pub const HANDLE_APPEARANCE_DECL: u16 = 4;
pub const HANDLE_APPEARANCE: u16 = 5;
pub const HANDLE_NUS_SERVICE: u16 = 6;
pub const HANDLE_TX_DECL: u16 = 7;
pub const HANDLE_TX_VALUE: u16 = 8;
pub const HANDLE_TX_CCCD: u16 = 9;
pub const HANDLE_RX_DECL: u16 = 10;
pub const HANDLE_RX_VALUE: u16 = 11;
pub const HANDLE_MAX: u16 = HANDLE_RX_VALUE;

pub const MAX_RX: usize = 128;
pub const MAX_TX: usize = 64;
pub const MAX_ATT_MTU: u16 = 247;

// Characteristic declaration values: properties, value handle, UUID.
const DEVICE_NAME_DECL: [u8; 5] = [0x02, 0x03, 0x00, 0x00, 0x2A];
const APPEARANCE_DECL: [u8; 5] = [0x02, 0x05, 0x00, 0x01, 0x2A];
const TX_DECL: [u8; 19] = [
    0x10, // NOTIFY
    0x08, 0x00, // value handle 8
    0x9E, 0xCA, 0xDC, 0x24, 0x0E, 0xE5, 0xA9, 0xE0, 0x93, 0xF3, 0xA3, 0xB5, 0x03, 0x00, 0x40,
    0x6E,
];
const RX_DECL: [u8; 19] = [
    0x0C, // WRITE | WRITE_NO_RESPONSE
    0x0B, 0x00, // value handle 11
    0x9E, 0xCA, 0xDC, 0x24, 0x0E, 0xE5, 0xA9, 0xE0, 0x93, 0xF3, 0xA3, 0xB5, 0x02, 0x00, 0x40,
    0x6E,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RxAction {
    Pause,
    Resume,
    Stats,
    Dump { count: usize },
}

pub struct GattServer {
    tx: [u8; MAX_TX],
    tx_len: usize,
    rx: [u8; MAX_RX],
    rx_len: usize,
    pending: Option<RxAction>,
    cccd: u16,
    mtu: u16,
}

impl Default for GattServer {
    fn default() -> Self {
        Self::new()
    }
}

impl GattServer {
    pub const fn new() -> Self {
        Self {
            tx: [0; MAX_TX],
            tx_len: 0,
            rx: [0; MAX_RX],
            rx_len: 0,
            pending: None,
            cccd: 0,
            mtu: 23,
        }
    }

    pub fn reset_link(&mut self) {
        self.cccd = 0;
        self.mtu = 23;
        self.pending = None;
        self.rx_len = 0;
        self.tx_len = 0;
    }

    pub fn cccd_flags(&self) -> u16 {
        self.cccd
    }

    pub fn take_rx_action(&mut self) -> Option<RxAction> {
        self.pending.take()
    }

    pub fn set_tx(&mut self, data: &[u8]) {
        let n = core::cmp::min(data.len(), MAX_TX);
        self.tx[..n].copy_from_slice(&data[..n]);
        self.tx_len = n;
    }

    pub fn tx_value(&self) -> &[u8] {
        &self.tx[..self.tx_len]
    }

    pub fn rx_value(&self) -> &[u8] {
        &self.rx[..self.rx_len]
    }

    pub fn group_end(handle: u16) -> u16 {
        match handle {
            HANDLE_GAP_SERVICE => HANDLE_APPEARANCE,
            HANDLE_NUS_SERVICE => HANDLE_RX_VALUE,
            _ => handle,
        }
    }

    fn att_type(handle: u16) -> Option<&'static [u8]> {
        Some(match handle {
            HANDLE_GAP_SERVICE | HANDLE_NUS_SERVICE => &PRIMARY_SERVICE_UUID,
            HANDLE_DEVICE_NAME_DECL | HANDLE_APPEARANCE_DECL | HANDLE_TX_DECL | HANDLE_RX_DECL => {
                &CHARACTERISTIC_UUID
            }
            HANDLE_DEVICE_NAME => &DEVICE_NAME_UUID,
            HANDLE_APPEARANCE => &APPEARANCE_UUID,
            HANDLE_TX_VALUE => &NUS_TX_UUID,
            HANDLE_TX_CCCD => &CCCD_UUID,
            HANDLE_RX_VALUE => &NUS_RX_UUID,
            _ => return None,
        })
    }

    fn value_len(&self, handle: u16) -> Option<usize> {
        Some(match handle {
            HANDLE_GAP_SERVICE => GAP_SERVICE_UUID.len(),
            HANDLE_DEVICE_NAME_DECL => DEVICE_NAME_DECL.len(),
            HANDLE_DEVICE_NAME => DEVICE_NAME.len(),
            HANDLE_APPEARANCE_DECL => APPEARANCE_DECL.len(),
            HANDLE_APPEARANCE => APPEARANCE.len(),
            HANDLE_NUS_SERVICE => NUS_SERVICE_UUID.len(),
            HANDLE_TX_DECL => TX_DECL.len(),
            HANDLE_TX_VALUE => self.tx_len,
            HANDLE_TX_CCCD => 2,
            HANDLE_RX_DECL => RX_DECL.len(),
            HANDLE_RX_VALUE => self.rx_len,
            _ => return None,
        })
    }

    fn copy_value(&self, handle: u16, out: &mut [u8]) -> Option<usize> {
        let value: &[u8] = match handle {
            HANDLE_GAP_SERVICE => &GAP_SERVICE_UUID,
            HANDLE_DEVICE_NAME_DECL => &DEVICE_NAME_DECL,
            HANDLE_DEVICE_NAME => DEVICE_NAME,
            HANDLE_APPEARANCE_DECL => &APPEARANCE_DECL,
            HANDLE_APPEARANCE => &APPEARANCE,
            HANDLE_NUS_SERVICE => &NUS_SERVICE_UUID,
            HANDLE_TX_DECL => &TX_DECL,
            HANDLE_TX_VALUE => &self.tx[..self.tx_len],
            HANDLE_TX_CCCD => {
                let n = self.cccd.to_le_bytes();
                if out.len() < 2 {
                    return None;
                }
                out[..2].copy_from_slice(&n);
                return Some(2);
            }
            HANDLE_RX_DECL => &RX_DECL,
            HANDLE_RX_VALUE => &self.rx[..self.rx_len],
            _ => return None,
        };
        if out.len() < value.len() {
            return None;
        }
        out[..value.len()].copy_from_slice(value);
        Some(value.len())
    }
}

fn parse_decimal(s: &str) -> Option<u32> {
    if s.is_empty() {
        return None;
    }
    let mut v = 0u32;
    for b in s.bytes() {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v
            .checked_mul(10)?
            .checked_add((b - b'0') as u32)?;
    }
    Some(v)
}

/// Parse one RX command.  Leading/trailing ASCII whitespace is ignored.
pub fn parse_rx_command(data: &[u8]) -> Option<RxAction> {
    let s = core::str::from_utf8(data).ok()?.trim();
    match s {
        "pause" => Some(RxAction::Pause),
        "resume" => Some(RxAction::Resume),
        "stats" => Some(RxAction::Stats),
        _ => {
            let rest = s.strip_prefix("dump ")?;
            let count = parse_decimal(rest.trim())? as usize;
            Some(RxAction::Dump { count })
        }
    }
}

impl AttServer for GattServer {
    fn read(&self, handle: u16, offset: usize, out: &mut [u8]) -> Option<usize> {
        let len = self.value_len(handle)?;
        if offset > len {
            return None;
        }
        let mut tmp = [0u8; 32];
        let n = self.copy_value(handle, &mut tmp)?;
        let take = core::cmp::min(out.len(), n - offset);
        out[..take].copy_from_slice(&tmp[offset..offset + take]);
        Some(take)
    }

    fn read_by_type(
        &self,
        start: u16,
        end: u16,
        uuid: &[u8],
        out: &mut [u8],
    ) -> Option<(usize, usize)> {
        if start == 0 || start > end {
            return None;
        }
        let end = core::cmp::min(end, HANDLE_MAX);
        let mut first: Option<u16> = None;
        let mut entry_len = 0usize;
        for h in start..=end {
            if let Some(t) = Self::att_type(h) {
                if t == uuid {
                    first = Some(h);
                    entry_len = 2 + self.value_len(h)?;
                    break;
                }
            }
        }
        let first = first?;
        let mut total = 0usize;
        for h in first..=end {
            if let Some(t) = Self::att_type(h) {
                if t != uuid {
                    continue;
                }
                let vlen = self.value_len(h)?;
                if 2 + vlen != entry_len {
                    // Keep all entries the same length; the client will issue
                    // another request from the next handle.
                    break;
                }
                if out.len() < total + entry_len {
                    return None;
                }
                out[total..total + 2].copy_from_slice(&h.to_le_bytes());
                let n = self.copy_value(h, &mut out[total + 2..total + 2 + vlen])?;
                if n != vlen {
                    return None;
                }
                total += entry_len;
            }
        }
        Some((entry_len, total))
    }

    fn read_group(
        &self,
        start: u16,
        end: u16,
        uuid: &[u8],
        out: &mut [u8],
    ) -> Option<(usize, usize)> {
        if start == 0 || start > end {
            return None;
        }
        let end = core::cmp::min(end, HANDLE_MAX);
        let mut first: Option<u16> = None;
        let mut entry_len = 0usize;
        for h in start..=end {
            if let Some(t) = Self::att_type(h) {
                if t == uuid {
                    first = Some(h);
                    entry_len = 4 + self.value_len(h)?;
                    break;
                }
            }
        }
        let first = first?;
        let mut total = 0usize;
        for h in first..=end {
            if let Some(t) = Self::att_type(h) {
                if t != uuid {
                    continue;
                }
                let vlen = self.value_len(h)?;
                if 4 + vlen != entry_len {
                    break;
                }
                if out.len() < total + entry_len {
                    return None;
                }
                out[total..total + 2].copy_from_slice(&h.to_le_bytes());
                out[total + 2..total + 4]
                    .copy_from_slice(&Self::group_end(h).to_le_bytes());
                self.copy_value(h, &mut out[total + 4..total + 4 + vlen])?;
                total += entry_len;
            }
        }
        Some((entry_len, total))
    }

    fn write(&mut self, handle: u16, data: &[u8]) -> Result<(), u8> {
        match handle {
            HANDLE_TX_CCCD => {
                if data.len() != 2 {
                    return Err(att::ERR_INVALID_PDU);
                }
                self.cccd = u16::from_le_bytes([data[0], data[1]]);
                Ok(())
            }
            HANDLE_RX_VALUE => {
                let n = core::cmp::min(data.len(), MAX_RX);
                self.rx[..n].copy_from_slice(&data[..n]);
                self.rx_len = n;
                self.pending = parse_rx_command(&self.rx[..n]);
                Ok(())
            }
            h if self.value_len(h).is_some() => Err(att::ERR_WRITE_NOT_PERMITTED),
            _ => Err(att::ERR_INVALID_HANDLE),
        }
    }

    fn notify_handle(&self) -> u16 {
        HANDLE_TX_VALUE
    }

    fn cccd_enabled(&self) -> bool {
        self.cccd & 0x0001 != 0
    }

    fn mtu(&self) -> u16 {
        self.mtu
    }

    fn set_mtu(&mut self, mtu: u16) {
        self.mtu = mtu.clamp(23, MAX_ATT_MTU);
    }

    fn handle_exists(&self, handle: u16) -> bool {
        Self::att_type(handle).is_some()
    }

    fn find_info(&self, start: u16, end: u16, out: &mut [u8]) -> Option<usize> {
        if start == 0 || start > end {
            return None;
        }
        let end = core::cmp::min(end, HANDLE_MAX);
        let mut total = 0usize;
        for h in start..=end {
            if let Some(t) = Self::att_type(h) {
                if t.len() != 2 {
                    continue;
                }
                if out.len() < total + 4 {
                    return None;
                }
                out[total..total + 2].copy_from_slice(&h.to_le_bytes());
                out[total + 2..total + 4].copy_from_slice(t);
                total += 4;
            }
        }
        if total == 0 {
            None
        } else {
            Some(total)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_layout_matches_documented_handles() {
        assert_eq!(HANDLE_MAX, 11);
        for h in 1..=HANDLE_MAX {
            assert!(GattServer::att_type(h).is_some(), "handle {h}");
        }
        assert!(GattServer::att_type(12).is_none());
        assert_eq!(GattServer::group_end(HANDLE_GAP_SERVICE), HANDLE_APPEARANCE);
        assert_eq!(GattServer::group_end(HANDLE_NUS_SERVICE), HANDLE_RX_VALUE);
    }

    #[test]
    fn characteristic_declarations() {
        let s = GattServer::new();
        let mut buf = [0u8; 32];

        let n = s.read(HANDLE_TX_DECL, 0, &mut buf).unwrap();
        assert_eq!(n, 19);
        assert_eq!(buf[0], 0x10);
        assert_eq!(&buf[1..3], &HANDLE_TX_VALUE.to_le_bytes());
        assert_eq!(&buf[3..19], &NUS_TX_UUID);

        let n = s.read(HANDLE_RX_DECL, 0, &mut buf).unwrap();
        assert_eq!(n, 19);
        assert_eq!(buf[0], 0x0C);
        assert_eq!(&buf[1..3], &HANDLE_RX_VALUE.to_le_bytes());
        assert_eq!(&buf[3..19], &NUS_RX_UUID);
    }

    #[test]
    fn read_group_returns_one_uniform_block() {
        let s = GattServer::new();
        let mut out = [0u8; 64];

        let (len, total) = s
            .read_group(1, 0xFFFF, &PRIMARY_SERVICE_UUID, &mut out)
            .unwrap();
        assert_eq!(len, 6);
        assert_eq!(total, 6);
        assert_eq!(&out[..6], &[0x01, 0x00, 0x05, 0x00, 0x00, 0x18]);

        let (len, total) = s
            .read_group(6, 0xFFFF, &PRIMARY_SERVICE_UUID, &mut out)
            .unwrap();
        assert_eq!(len, 20);
        assert_eq!(total, 20);
        assert_eq!(&out[..2], &[0x06, 0x00]);
        assert_eq!(&out[2..4], &[0x0B, 0x00]);
        assert_eq!(&out[4..20], &NUS_SERVICE_UUID);
    }

    #[test]
    fn read_by_type_stops_at_length_change() {
        let s = GattServer::new();
        let mut out = [0u8; 128];

        // From the very beginning, only the first (5-byte) declaration fits.
        let (len, total) = s
            .read_by_type(1, 0xFFFF, &CHARACTERISTIC_UUID, &mut out)
            .unwrap();
        assert_eq!(len, 7);
        assert_eq!(total, 14);
        assert_eq!(&out[..2], &[0x02, 0x00]);

        // Within the NUS range both 128-bit declarations fit.
        let (len, total) = s
            .read_by_type(HANDLE_TX_DECL, HANDLE_RX_VALUE, &CHARACTERISTIC_UUID, &mut out)
            .unwrap();
        assert_eq!(len, 21);
        assert_eq!(total, 42);
    }

    #[test]
    fn cccd_write_enables_notifications() {
        let mut s = GattServer::new();
        assert!(!s.cccd_enabled());
        assert_eq!(s.write(HANDLE_TX_CCCD, &[0x01, 0x00]), Ok(()));
        assert!(s.cccd_enabled());
        assert_eq!(s.write(HANDLE_TX_CCCD, &[0x00, 0x00]), Ok(()));
        assert!(!s.cccd_enabled());
        assert_eq!(s.write(HANDLE_TX_CCCD, &[0x01]), Err(att::ERR_INVALID_PDU));
        assert_eq!(
            s.write(HANDLE_DEVICE_NAME, &[0x00]),
            Err(att::ERR_WRITE_NOT_PERMITTED)
        );
        assert_eq!(s.write(0x1234, &[0x00]), Err(att::ERR_INVALID_HANDLE));
    }

    #[test]
    fn rx_command_parsing() {
        assert_eq!(parse_rx_command(b"pause"), Some(RxAction::Pause));
        assert_eq!(parse_rx_command(b" resume\r\n"), Some(RxAction::Resume));
        assert_eq!(parse_rx_command(b"stats"), Some(RxAction::Stats));
        assert_eq!(
            parse_rx_command(b"dump 128"),
            Some(RxAction::Dump { count: 128 })
        );
        assert_eq!(parse_rx_command(b"dump 18446744073709551616"), None);
        assert_eq!(parse_rx_command(b"dump"), None);
        assert_eq!(parse_rx_command(b"dump x"), None);
        assert_eq!(parse_rx_command(b"nope"), None);
        assert_eq!(parse_rx_command(&[0xff]), None);
    }

    #[test]
    fn writes_are_visible_to_rx_parser() {
        let mut s = GattServer::new();
        assert_eq!(s.write(HANDLE_RX_VALUE, b"dump 7"), Ok(()));
        assert_eq!(s.rx_value(), b"dump 7");
        assert_eq!(s.take_rx_action(), Some(RxAction::Dump { count: 7 }));
        assert_eq!(s.take_rx_action(), None);
    }

    #[test]
    fn mtu_clamped() {
        let mut s = GattServer::new();
        assert_eq!(s.mtu(), 23);
        s.set_mtu(10);
        assert_eq!(s.mtu(), 23);
        s.set_mtu(247);
        assert_eq!(s.mtu(), 247);
        s.set_mtu(500);
        assert_eq!(s.mtu(), MAX_ATT_MTU);
    }

    #[test]
    fn tx_value_and_reset() {
        let mut s = GattServer::new();
        s.set_tx(b"hello");
        let mut buf = [0u8; 8];
        let n = s.read(HANDLE_TX_VALUE, 0, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");
        s.write(HANDLE_TX_CCCD, &[0x01, 0x00]).unwrap();
        s.reset_link();
        assert!(!s.cccd_enabled());
        assert_eq!(s.mtu(), 23);
        assert_eq!(s.tx_value(), b"");
    }
}
