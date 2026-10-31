//! `strate-bt`: a minimal, allocation-free BLE GATT peripheral plus a
//! console log dump pump for Strat9.
//!
//! The library is transport agnostic: feed H4 packets to [`Session`] and it
//! produces H4 packets to write back.  The runtime binary in `main.rs` wires
//! this to `/dev/bt/hci0`, `/dev/log/stream` and `/dev/log/stats`.
//!
//! No dynamic allocation is used, and the whole crate builds with
//! `default-features = false` (the syscall dependency is only needed by the
//! `runtime` feature).

#![cfg_attr(not(test), no_std)]

pub mod acl;
pub mod adv;
pub mod att;
pub mod dump;
pub mod gatt;
pub mod hci;
pub mod l2cap;

use acl::AclReassembler;
use att::{AttServer, AttServerDispatch};
use dump::Dumper;
use gatt::{GattServer, RxAction};

pub const DEFAULT_ACL_MTU: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    Parse(hci::ParseError),
    Acl(acl::AclError),
    L2cap(l2cap::ParseError),
    BufferTooSmall,
}

impl From<hci::ParseError> for SessionError {
    fn from(e: hci::ParseError) -> Self {
        Self::Parse(e)
    }
}

impl From<acl::AclError> for SessionError {
    fn from(e: acl::AclError) -> Self {
        Self::Acl(e)
    }
}

impl From<l2cap::ParseError> for SessionError {
    fn from(e: l2cap::ParseError) -> Self {
        Self::L2cap(e)
    }
}

/// End-to-end protocol state: link, ATT server, ACL reassembly and dumper.
pub struct Session {
    gatt: GattServer,
    reasm: AclReassembler,
    dumper: Dumper,
    connected: bool,
    handle: u16,
    acl_mtu: usize,
    log_cursor: usize,
    log_len: usize,
    log_active: bool,
    /// Set on disconnection: advertising must be re-enabled by the host.
    rearm_advertising: bool,
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    pub fn new() -> Self {
        Self {
            gatt: GattServer::new(),
            reasm: AclReassembler::new(),
            dumper: Dumper::new(),
            connected: false,
            handle: 0,
            acl_mtu: DEFAULT_ACL_MTU,
            log_cursor: 0,
            log_len: 0,
            log_active: false,
            rearm_advertising: false,
        }
    }

    pub fn gatt(&self) -> &GattServer {
        &self.gatt
    }

    pub fn gatt_mut(&mut self) -> &mut GattServer {
        &mut self.gatt
    }

    pub fn is_connected(&self) -> bool {
        self.connected
    }

    pub fn connection_handle(&self) -> u16 {
        self.handle
    }

    pub fn notifications_enabled(&self) -> bool {
        self.connected && self.gatt.cccd_enabled()
    }

    pub fn take_action(&mut self) -> Option<RxAction> {
        self.gatt.take_rx_action()
    }

    /// Reset link-specific state (used on connect/disconnect).
    fn reset_link_state(&mut self) {
        self.reasm.reset();
        self.gatt.reset_link();
        self.dumper.reset();
        self.log_cursor = 0;
        self.log_len = 0;
        self.log_active = false;
    }

    fn on_event(&mut self, packet: &[u8]) -> Result<(), SessionError> {
        match hci::parse_event(packet)? {
            hci::Event::CommandComplete { opcode, returns, .. } => {
                if opcode == hci::OP_LE_READ_BUFFER_SIZE && returns.len() >= 4 {
                    // status, le_acl_mtu (u16), le_max_pkt (u8), ...
                    let mtu = u16::from_le_bytes([returns[1], returns[2]]) as usize;
                    if mtu >= 27 {
                        self.acl_mtu = core::cmp::min(mtu, 512);
                    }
                }
            }
            hci::Event::LeMeta(hci::LeEvent::ConnectionComplete { status, handle, .. }) => {
                if status == 0 {
                    self.connected = true;
                    self.handle = handle;
                    self.reset_link_state();
                    self.connected = true;
                    self.handle = handle;
                }
            }
            hci::Event::DisconnectionComplete { .. } => {
                self.connected = false;
                self.handle = 0;
                self.reset_link_state();
                // The controller stops advertising on connect; restart it so a
                // viewer can reconnect after a link drop.
                self.rearm_advertising = true;
            }
            hci::Event::HardwareError { .. } => {
                self.connected = false;
                self.handle = 0;
                self.reset_link_state();
                self.rearm_advertising = true;
            }
            _ => {}
        }
        Ok(())
    }

    /// Feed one complete H4 packet read from `/dev/bt/hci0`.  Any packet that
    /// must be written back is produced in `out`; the return value is its
    /// length (`0` when nothing is to be sent).
    pub fn on_hci_packet(
        &mut self,
        packet: &[u8],
        out: &mut [u8],
    ) -> Result<usize, SessionError> {
        if packet.is_empty() {
            return Ok(0);
        }
        match packet[0] {
            hci::H4_EVT => {
                self.on_event(packet)?;
                if self.rearm_advertising {
                    self.rearm_advertising = false;
                    let n = hci::le_set_advertising_enable(out, true)
                        .ok_or(SessionError::BufferTooSmall)?;
                    return Ok(n);
                }
                Ok(0)
            }
            hci::H4_ACL => {
                let (header, payload) = hci::parse_acl(packet)?;
                let complete = self.reasm.push(header, payload)?;
                match complete {
                    Some(len) => {
                        // Copy the frame out of the reassembler so `self` can be
                        // borrowed mutably for the response path.
                        let mut frame = [0u8; acl::MAX_L2CAP_PDU];
                        frame[..len].copy_from_slice(self.reasm.frame());
                        self.on_l2cap(&frame[..len], out)
                    }
                    None => Ok(0),
                }
            }
            _ => Ok(0),
        }
    }

    fn on_l2cap(&mut self, frame: &[u8], out: &mut [u8]) -> Result<usize, SessionError> {
        let (header, payload) = l2cap::parse(frame)?;
        if header.cid != l2cap::CID_ATT {
            return Ok(0);
        }

        let mut att_out = [0u8; 512];
        let response_len = match self.gatt.handle_request(payload, &mut att_out) {
            Some(n) => n,
            None => {
                self.dumper.set_mtu(self.gatt.mtu());
                return Ok(0);
            }
        };
        self.dumper.set_mtu(self.gatt.mtu());

        let mut l2 = [0u8; 520];
        let l2_len = l2cap::build_att(&att_out[..response_len], &mut l2)
            .ok_or(SessionError::BufferTooSmall)?;
        let written = acl::fragment(self.handle, &l2[..l2_len], self.acl_mtu, false, out)?;
        Ok(written)
    }

    /// Write an attribute directly (test/helper path).  Returns the pending
    /// RX command action, if the write produced one.
    pub fn on_att_write(
        &mut self,
        handle: u16,
        data: &[u8],
    ) -> Result<Option<RxAction>, u8> {
        self.gatt.write(handle, data)?;
        Ok(self.gatt.take_rx_action())
    }

    /// Pull the next log notification from `bytes`.
    ///
    /// Call repeatedly with the same slice until it returns `None`, then call
    /// again with the next read from `/dev/log/stream`.  A HELLO frame is
    /// emitted first, followed by DATA frames chunked for the negotiated MTU.
    pub fn poll_log(&mut self, bytes: &[u8], out: &mut [u8]) -> Option<usize> {
        if !self.notifications_enabled() {
            self.log_cursor = 0;
            self.log_len = 0;
            self.log_active = false;
            return None;
        }

        if !self.log_active {
            self.log_active = true;
            self.log_len = bytes.len();
            self.log_cursor = 0;
        }
        if self.log_cursor >= self.log_len {
            self.log_cursor = 0;
            self.log_len = 0;
            self.log_active = false;
            return None;
        }

        let mut att = [0u8; 512];
        let handle = self.gatt.notify_handle();
        att[0] = att::ATT_HANDLE_VALUE_NTF;
        att[1..3].copy_from_slice(&handle.to_le_bytes());

        let mut cursor = self.log_cursor;
        let frame_len = self.dumper.next_frame(bytes, &mut att[3..], &mut cursor)?;
        self.log_cursor = cursor;
        let att_len = 3 + frame_len;

        let mut l2 = [0u8; 520];
        let l2_len = l2cap::build_att(&att[..att_len], &mut l2)?;
        acl::fragment(self.handle, &l2[..l2_len], self.acl_mtu, true, out).ok()
    }

    /// Queue a DROP notice after the log ring reports lost bytes.
    pub fn report_drop(&mut self, lost: u32, out: &mut [u8]) -> Option<usize> {
        if !self.notifications_enabled() {
            return None;
        }
        let mut att = [0u8; 32];
        let handle = self.gatt.notify_handle();
        att[0] = att::ATT_HANDLE_VALUE_NTF;
        att[1..3].copy_from_slice(&handle.to_le_bytes());
        let frame_len = self.dumper.drop_frame(lost, &mut att[3..])?;
        let att_len = 3 + frame_len;

        let mut l2 = [0u8; 64];
        let l2_len = l2cap::build_att(&att[..att_len], &mut l2)?;
        acl::fragment(self.handle, &l2[..l2_len], self.acl_mtu, true, out).ok()
    }

    /// HCI initialization sequence: reset, read version/address, event masks,
    /// LE buffer size, advertising parameters/data and advertising enable.
    pub fn initialization_sequence(out: &mut [u8]) -> Option<usize> {
        let mut pos = 0usize;

        pos += hci::reset(&mut out[pos..])?;
        pos += hci::read_local_version(&mut out[pos..])?;
        pos += hci::read_bd_addr(&mut out[pos..])?;
        pos += hci::set_event_mask(&mut out[pos..], 0x1F_FFFF_FFFF_FFFF)?;
        pos += hci::le_set_event_mask(&mut out[pos..], 0x1F)?;
        pos += hci::le_read_buffer_size(&mut out[pos..])?;

        let mut params = [0u8; 15];
        let pn = adv::build_adv_params(&mut params)?;
        pos += hci::command(
            &mut out[pos..],
            hci::OP_LE_SET_ADVERTISING_PARAMS,
            &params[..pn],
        )?;

        let mut ad = [0u8; 31];
        let an = adv::build_adv_data(&mut ad)?;
        pos += hci::le_set_advertising_data(&mut out[pos..], &ad[..an])?;
        pos += hci::le_set_advertising_enable(&mut out[pos..], true)?;

        Some(pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::att::AttServer;

    fn conn_complete(handle: u16) -> [u8; 22] {
        let mut p = [0u8; 22];
        p[0] = hci::H4_EVT;
        p[1] = hci::EVT_LE_META;
        p[2] = 19;
        p[3] = hci::LE_CONNECTION_COMPLETE;
        p[5..7].copy_from_slice(&handle.to_le_bytes());
        p[7] = 0x01;
        p[8] = 0x01;
        p[21] = 0x00;
        p
    }

    /// Feed one ATT request through ACL fragmentation and return the response
    /// ATT payload, if any.
    fn att_roundtrip(s: &mut Session, req: &[u8]) -> Option<[u8; 128]> {
        let mut l2 = [0u8; 128];
        let l2n = l2cap::build_att(req, &mut l2).unwrap();
        let mut acl_buf = [0u8; 256];
        let acl_n = acl::fragment(s.connection_handle(), &l2[..l2n], 20, false, &mut acl_buf).unwrap();

        let mut response = [0u8; 128];
        let mut response_len = 0usize;
        let mut off = 0usize;
        while off < acl_n {
            let dlen = u16::from_le_bytes([acl_buf[off + 3], acl_buf[off + 4]]) as usize;
            let end = off + 5 + dlen;
            let mut out = [0u8; 512];
            let n = s.on_hci_packet(&acl_buf[off..end], &mut out).unwrap();
            if n > 0 {
                let (_, payload) = l2cap::parse(&out[5..n]).unwrap();
                response_len = payload.len();
                response[..response_len].copy_from_slice(payload);
            }
            off = end;
        }
        if response_len == 0 {
            None
        } else {
            Some(response)
        }
    }

    #[test]
    fn connect_then_exchange_mtu() {
        let mut s = Session::new();
        let mut out = [0u8; 512];
        s.on_hci_packet(&conn_complete(0x0040), &mut out).unwrap();
        assert!(s.is_connected());
        assert_eq!(s.connection_handle(), 0x40);

        let rsp = att_roundtrip(&mut s, &[0x02, 0xF7, 0x00]).unwrap();
        assert_eq!(&rsp[..3], &[0x03, 0xF7, 0x00]);
        assert_eq!(s.gatt().mtu(), 247);
    }

    #[test]
    fn write_cccd_then_poll_log() {
        let mut s = Session::new();
        let mut out = [0u8; 512];
        s.on_hci_packet(&conn_complete(0x0040), &mut out).unwrap();

        let rsp = att_roundtrip(&mut s, &[0x12, 0x09, 0x00, 0x01, 0x00]).unwrap();
        assert_eq!(&rsp[..1], &[0x13]);
        assert!(s.notifications_enabled());

        let data = [0xAAu8; 40];
        let mut kinds = [0u8; 8];
        let mut seqs = [0u32; 8];
        let mut payload = [0u8; 64];
        let mut plen = 0usize;
        let mut nframes = 0usize;
        while let Some(n) = s.poll_log(&data, &mut out) {
            let (_, l2payload) = l2cap::parse(&out[5..n]).unwrap();
            // notification: 0x1B, handle, frame
            assert_eq!(l2payload[0], att::ATT_HANDLE_VALUE_NTF);
            let f = dump::decode(&l2payload[3..]).unwrap();
            kinds[nframes] = f.kind;
            seqs[nframes] = f.seq;
            nframes += 1;
            if f.kind == dump::TYPE_DATA {
                payload[plen..plen + f.payload.len()].copy_from_slice(f.payload);
                plen += f.payload.len();
            }
        }
        assert_eq!(nframes, 4);
        assert_eq!(kinds[0], dump::TYPE_HELLO);
        assert_eq!(seqs, [0, 1, 2, 3, 0, 0, 0, 0]);
        assert_eq!(&payload[..plen], &data);
    }

    #[test]
    fn no_log_before_notifications() {
        let mut s = Session::new();
        let mut out = [0u8; 512];
        s.on_hci_packet(&conn_complete(0x0040), &mut out).unwrap();
        assert_eq!(s.poll_log(&[1, 2, 3], &mut out), None);
    }

    #[test]
    fn disconnection_resets_notifications() {
        let mut s = Session::new();
        let mut out = [0u8; 512];
        s.on_hci_packet(&conn_complete(0x0040), &mut out).unwrap();
        s.gatt_mut().write(9, &[0x01, 0x00]).unwrap();
        assert!(s.notifications_enabled());

        let disc = [
            hci::H4_EVT,
            hci::EVT_DISCONNECTION_COMPLETE,
            0x04,
            0x00,
            0x40,
            0x00,
            0x13,
        ];
        s.on_hci_packet(&disc, &mut out).unwrap();
        assert!(!s.is_connected());
        assert!(!s.notifications_enabled());
    }

    #[test]
    fn disconnection_rearms_advertising() {
        let mut s = Session::new();
        let mut out = [0u8; 128];
        s.on_hci_packet(&conn_complete(0x0040), &mut out).unwrap();

        let disc = [
            hci::H4_EVT,
            hci::EVT_DISCONNECTION_COMPLETE,
            0x04,
            0x00,
            0x40,
            0x00,
            0x13,
        ];
        let n = s.on_hci_packet(&disc, &mut out).unwrap();
        assert_eq!(out[0], hci::H4_CMD);
        assert_eq!(
            u16::from_le_bytes([out[1], out[2]]),
            hci::OP_LE_SET_ADVERTISING_ENABLE
        );
        assert_eq!(out[3], 1); // parameter length
        assert_eq!(out[4], 1); // enabled
        assert_eq!(n, 5);
    }

    #[test]
    fn on_att_write_reports_actions() {
        let mut s = Session::new();
        let mut out = [0u8; 512];
        s.on_hci_packet(&conn_complete(0x0040), &mut out).unwrap();
        assert_eq!(
            s.on_att_write(gatt::HANDLE_RX_VALUE, b"dump 16"),
            Ok(Some(RxAction::Dump { count: 16 }))
        );
        assert_eq!(
            s.on_att_write(gatt::HANDLE_RX_VALUE, b"pause"),
            Ok(Some(RxAction::Pause))
        );
        assert_eq!(s.take_action(), None);
    }

    #[test]
    fn report_drop_only_when_enabled() {
        let mut s = Session::new();
        let mut out = [0u8; 512];
        s.on_hci_packet(&conn_complete(0x0040), &mut out).unwrap();
        assert_eq!(s.report_drop(12, &mut out), None);
        s.gatt_mut().write(9, &[1, 0]).unwrap();
        let n = s.report_drop(12, &mut out).unwrap();
        let (_, payload) = l2cap::parse(&out[5..n]).unwrap();
        let f = dump::decode(&payload[3..]).unwrap();
        assert_eq!(f.kind, dump::TYPE_DROP);
        assert_eq!(u32::from_le_bytes(f.payload.try_into().unwrap()), 12);
    }

    #[test]
    fn initialization_sequence_starts_and_ends_correctly() {
        let mut out = [0u8; 256];
        let n = Session::initialization_sequence(&mut out).unwrap();
        assert!(n > 90);
        assert_eq!(out[0], hci::H4_CMD);
        assert_eq!(
            u16::from_le_bytes([out[1], out[2]]),
            hci::OP_RESET
        );
        let mut pos = 0usize;
        let mut last = 0u16;
        while pos < n {
            last = u16::from_le_bytes([out[pos + 1], out[pos + 2]]);
            let plen = out[pos + 3] as usize;
            pos += 4 + plen;
        }
        assert_eq!(pos, n);
        assert_eq!(last, hci::OP_LE_SET_ADVERTISING_ENABLE);
    }

    #[test]
    fn malformed_hci_is_reported() {
        let mut s = Session::new();
        let mut out = [0u8; 64];
        assert!(s.on_hci_packet(&[hci::H4_EVT, hci::EVT_COMMAND_STATUS, 0x04], &mut out).is_err());
        assert_eq!(s.on_hci_packet(&[], &mut out).unwrap(), 0);
        assert_eq!(s.on_hci_packet(&[0x99, 0x00], &mut out).unwrap(), 0);
    }
}
