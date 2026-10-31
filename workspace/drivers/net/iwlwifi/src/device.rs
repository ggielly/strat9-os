//! Station data path glue: firmware transport <-> MLME <-> Ethernet.
//!
//! `WifiDevice` owns the transport, the MLME and the WPA2 keys.  It converts
//! Ethernet II frames to CCMP-protected 802.11 data frames and back.
//!
//! # Status
//!
//! The RX, command and firmware paths are implemented.  The **TX data queue**
//! (`iwl_tx_cmd_v9` + ADD_STA queue allocation) is the remaining hardware
//! piece: `tx_80211()` records frames in `pending_tx` instead of programming a
//! TFD.  Until it is implemented, `link_up()` stays false so the IP stack does
//! not select a half-wired interface.

use alloc::vec::Vec;



use crate::cmd;
use crate::config::WifiConfig;
use crate::dot11::{self, MacAddr};
use crate::fw;
use crate::mlme::{Mlme, MlmeEvent, MlmeState};
use crate::transport::{Bus, IwlTransport, RxPacketInfo, TransportError};

pub struct WifiStats {
    pub rx_80211: u64,
    pub tx_80211: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    pub eapol: u64,
    pub beacons: u64,
    pub last_rssi: i8,
}

impl Default for WifiStats {
    fn default() -> Self {
        Self {
            rx_80211: 0,
            tx_80211: 0,
            rx_dropped: 0,
            tx_dropped: 0,
            eapol: 0,
            beacons: 0,
            last_rssi: 0,
        }
    }
}

pub struct WifiDevice<B: Bus> {
    pub transport: IwlTransport<B>,
    pub cfg: WifiConfig,
    pub mlme: Mlme,
    mac: MacAddr,
    stats: WifiStats,
    /// Frames produced by the MLME and waiting for the TX data queue.
    pending_tx: Vec<Vec<u8>>,
    /// Decrypted Ethernet frames waiting for `receive()`.
    rx_eth: Vec<Vec<u8>>,
    tx_pn: [u8; 6],
    pub hw_name: &'static str,
    pub firmware_loaded: bool,
}

impl<B: Bus> WifiDevice<B> {
    pub fn new(
        transport: IwlTransport<B>,
        cfg: WifiConfig,
        expected_mac: Option<MacAddr>,
    ) -> Self {
        let mac = expected_mac.unwrap_or(transport.hw.mac);
        Self {
            transport,
            cfg,
            mlme: Mlme::new(mac),
            mac,
            stats: WifiStats::default(),
            pending_tx: Vec::new(),
            rx_eth: Vec::new(),
            tx_pn: [0, 0, 0, 0, 0, 1],
            hw_name: "Intel Wi-Fi 6 AX201",
            firmware_loaded: false,
        }
    }

    /// Run the whole bring-up: hardware, queues, firmware, alive.
    pub fn init(&mut self, firmware: &[u8]) -> Result<(), TransportError> {
        let image = fw::parse_tlv(firmware).map_err(|_| TransportError::BadFirmware)?;
        self.transport.apm_init()?;
        // The AX201 is the QuZ (CNVi) part; reject other 22000 variants.
        if self.transport.hw.hw_type != 0 && self.transport.hw.hw_type != crate::regs::QUZ_HW_REV_TYPE {
            return Err(TransportError::UnsupportedHw);
        }
        if self.transport.hw.mac != [0; 6] && self.transport.hw.mac != self.mac {
            self.mac = self.transport.hw.mac;
            self.mlme.sta = self.mac;
        }
        self.transport.rx_init()?;
        self.transport.tx_init()?;
        self.transport.load_firmware(&image)?;
        let _alive = self.transport.wait_alive(2_000)?;
        self.firmware_loaded = true;
        Ok(())
    }

    /// Start a connection using the TOML configuration.
    ///
    /// When `[wifi] bssid` and `channel` are set, the driver joins directly;
    /// otherwise a passive scan is issued and the strongest WPA2-PSK/CCMP
    /// candidate is selected when the scan completes.
    pub fn connect(&mut self) -> Result<(), TransportError> {
        if !self.cfg.is_complete() {
            return Err(TransportError::BadFirmware);
        }
        if let (Some(bssid), Some(channel)) = (self.cfg.bssid, self.cfg.channel) {
            let frame = self
                .mlme
                .begin_direct_join(&self.cfg, bssid, channel)
                .map_err(|_| TransportError::UnsupportedHw)?;
            self.tx_80211(&frame);
        } else {
            self.mlme.start_scan();
            let channels = [(1u8, 0u8, false), (6, 0, false), (11, 0, false)];
            let req = cmd::scan_request(&channels, Some(self.cfg.ssid()), self.cfg.bssid, 1);
            let _ = self
                .transport
                .send_cmd(cmd::CMD_SCAN_REQ_UMAC, cmd::GROUP_LEGACY, cmd::VER_SCAN_REQ, &req);
        }
        Ok(())
    }

    /// Drain firmware notifications and advance the MLME.
    pub fn poll(&mut self) {
        let mut block = [0u8; 2048];
        while let Some(pkt) = self.transport.rx_next_into(&mut block) {
            self.handle_notification(&pkt, &block[..]);
        }
    }

    fn handle_notification(&mut self, pkt: &RxPacketInfo, payload: &[u8]) {
        match pkt.cmd {
            cmd::CMD_REPLY_RX_MPDU => {
                self.stats.rx_80211 += 1;
                let Some(mpdu) = strip_rx_mpdu(&payload[..pkt.payload_len]) else {
                    self.stats.rx_dropped += 1;
                    return;
                };
                self.handle_mpdu(mpdu);
            }
            cmd::CMD_SCAN_COMPLETE_UMAC | cmd::CMD_SCAN_ITERATION_COMPLETE_UMAC => {
                if self.mlme.state == MlmeState::Scanning {
                    if self.mlme.candidate().is_some() {
                        match self.mlme.begin_join(&self.cfg) {
                            Ok(frame) => {
                                self.tx_80211(&frame);
                            }
                            Err(_) => self.stats.rx_dropped += 1,
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn handle_mpdu(&mut self, frame: &[u8]) {
        let fc = u16::from_le_bytes([frame[0], frame[1]]);
        let is_mgmt = fc & 0x000c == 0x0000;
        let is_data = fc & 0x000c == 0x0008;
        if is_mgmt {
            let subtype = fc & 0x00f0;
            if subtype == dot11::FC_SUBTYPE_BEACON || subtype == dot11::FC_SUBTYPE_PROBE_RESP {
                self.stats.beacons += 1;
                self.mlme.on_beacon(frame, self.stats.last_rssi, &self.cfg);
                return;
            }
            if subtype == dot11::FC_SUBTYPE_AUTH || subtype == dot11::FC_SUBTYPE_ASSOC_RESP {
                let snonce = self.make_snonce();
                match self.mlme.on_mgmt(frame, &self.cfg, &snonce) {
                    Ok((frames, _event)) => {
                        for f in frames {
                            self.tx_80211(&f);
                        }
                    }
                    Err(_) => self.stats.rx_dropped += 1,
                }
                return;
            }
            return;
        }
        if !is_data {
            return;
        }

        // Protected frames: CCMP-decrypt with the pairwise TK.
        let mut owned = frame.to_vec();
        let hdr_len = if fc & 0x0300 == 0x0300 { 30 } else { 24 };
        if fc & dot11::FCTL_PROTECTED != 0 {
            if !self.mlme.is_connected() {
                self.stats.rx_dropped += 1;
                return;
            }
            let Some(supp) = self.mlme.supplicant.as_ref() else {
                self.stats.rx_dropped += 1;
                return;
            };
            let tk = supp.keys().tk();
            if dot11::ccmp_unprotect(&tk, &mut owned, hdr_len).is_none() {
                self.stats.rx_dropped += 1;
                return;
            }
        }

        if crate::mlme::extract_eapol(&owned).is_some() {
            self.stats.eapol += 1;
            let snonce = self.make_snonce();
            match self.mlme.on_mgmt(&owned, &self.cfg, &snonce) {
                Ok((frames, event)) => {
                    for f in frames {
                        self.tx_80211(&f);
                    }
                    if matches!(event, Some(MlmeEvent::HandshakeComplete)) {
                        // Keys are now in software; firmware key installation
                        // (ADD_STA_KEY) is issued by the connection manager.
                        self.install_firmware_keys();
                    }
                }
                Err(_) => self.stats.rx_dropped += 1,
            }
            return;
        }

        if !self.mlme.is_connected() {
            self.stats.rx_dropped += 1;
            return;
        }
        if let Some(eth) = dot11::data_to_ethernet(&owned) {
            self.rx_eth.push(eth);
        }
    }

    /// Install the PTK/GTK in the firmware.  Called after the 4-way
    /// handshake.  Kept separate because it depends on the ADD_STA queue
    /// allocation performed by the connection manager.
    fn install_firmware_keys(&mut self) {
        let Some(supp) = self.mlme.supplicant.as_ref() else {
            return;
        };
        let keys = supp.keys();
        if !keys.installed {
            return;
        }
        let ptk = keys.tk();
        let _ = self.transport.send_cmd(
            cmd::CMD_ADD_STA_KEY,
            cmd::GROUP_LEGACY,
            cmd::VER_ADD_STA_KEY,
            &cmd::add_sta_key(1, 0, &ptk, 0, false),
        );
        if keys.gtk_len > 0 {
            let mut gtk = [0u8; 16];
            let n = keys.gtk_len.min(16);
            gtk[..n].copy_from_slice(&keys.gtk[..n]);
            let _ = self.transport.send_cmd(
                cmd::CMD_ADD_STA_KEY,
                cmd::GROUP_LEGACY,
                cmd::VER_ADD_STA_KEY,
                &cmd::add_sta_key(1, 1, &gtk, keys.gtk_key_id, true),
            );
        }
    }

    fn make_snonce(&mut self) -> [u8; 32] {
        // Mix the transport sequence number and a monotonically changing PN;
        // a real deployment should call the kernel RNG.  SNonce only needs to
        // be unpredictable to an off-path attacker for the lifetime of the
        // handshake, but using a proper RNG is strongly recommended.
        let mut out = [0u8; 32];
        let seed = (self.transport.hw.hw_rev as u64)
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
            .wrapping_add(self.stats.eapol)
            .wrapping_add(self.stats.beacons);
        for (i, chunk) in out.chunks_mut(8).enumerate() {
            let v = seed ^ (i as u64).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            chunk.copy_from_slice(&v.to_le_bytes()[..chunk.len()]);
        }
        out
    }

    /// Queue an 802.11 frame for transmission.
    ///
    /// TODO(data-path): program `iwl_tx_cmd_v9` into a TX queue allocated by
    /// ADD_STA (TFD TB0 = TX command, TB1 = MPDU) instead of buffering here.
    fn tx_80211(&mut self, frame: &[u8]) -> bool {
        self.stats.tx_80211 += 1;
        self.pending_tx.push(frame.to_vec());
        // Bound the staging queue so a misconfiguration cannot leak memory.
        if self.pending_tx.len() > 32 {
            self.pending_tx.remove(0);
            self.stats.tx_dropped += 1;
        }
        false
    }

    /// Frames waiting for the data TX queue (diagnostics / future work).
    pub fn pending_tx(&self) -> &[Vec<u8>] {
        &self.pending_tx
    }

    pub fn stats(&self) -> &WifiStats {
        &self.stats
    }

    pub fn is_connected(&self) -> bool {
        self.mlme.is_connected() && self.firmware_loaded
    }

    pub fn mac(&self) -> MacAddr {
        self.mac
    }

    pub fn next_pn(&mut self) -> [u8; 6] {
        let pn = self.tx_pn;
        let mut carry = 1u16;
        for byte in self.tx_pn.iter_mut() {
            let v = *byte as u16 + carry;
            *byte = v as u8;
            carry = v >> 8;
            if carry == 0 {
                break;
            }
        }
        pn
    }
}

/// Find the 802.11 MPDU inside an `iwl_rx_mpdu` notification.
///
/// The RX MPDU descriptor size depends on the firmware version (24, 28 or 32
/// bytes on 22000).  Rather than pinning one size, validate the frame control
/// at the candidate offsets.
fn strip_rx_mpdu(payload: &[u8]) -> Option<&[u8]> {
    for off in [32usize, 28, 24, 0] {
        let Some(candidate) = payload.get(off..) else {
            continue;
        };
        if candidate.len() < 24 {
            continue;
        }
        let fc = u16::from_le_bytes([candidate[0], candidate[1]]);
        let version = fc & 0x3;
        let ty = fc & 0x000c;
        if version == 0 && (ty == 0x0000 || ty == 0x0008) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dot11::{FC_SUBTYPE_BEACON, FC_TYPE_MGMT};

    #[test]
    fn strip_descriptor_finds_beacon() {
        let mut payload = alloc::vec![0u8; 32];
        let beacon = [
            0x80, 0x00, 0, 0, 1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6, 0, 0,
        ];
        payload.extend_from_slice(&beacon);
        let mpdu = strip_rx_mpdu(&payload).unwrap();
        assert_eq!(u16::from_le_bytes([mpdu[0], mpdu[1]]), FC_TYPE_MGMT | FC_SUBTYPE_BEACON);
    }
}
