/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

//! Station data path glue: firmware transport <-> MLME <-> Ethernet.
//!
//! `WifiDevice` owns the transport, the MLME and the WPA2 keys.  It converts
//! Ethernet II frames to CCMP-protected 802.11 data frames and back.
//!
//! # Status
//!
//! The RX, command and firmware paths are implemented.  The **TX data queue**
//! (`iwl_tx_cmd_v9` + ADD_STA queue allocation) is the remaining hardware
//! TX data path uses `iwl_tx_cmd_v9` on queue 1 (allocated with `ADD_STA` and
//! enabled through `SCD_QUEUE_CONFIG_CMD`).  The management/EAPOL/data frames
//! are CCMP-protected in software and marked `ENCRYPT_DIS` so the firmware
//! does not encrypt them twice.

use alloc::{collections::VecDeque, vec::Vec};

use crate::{
    cmd,
    config::WifiConfig,
    dot11::{self, MacAddr},
    fw,
    mlme::{Mlme, MlmeEvent, MlmeState},
    transport::{Bus, IwlTransport, RxPacketInfo, TransportError},
};

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
    /// Decrypted Ethernet frames waiting for `receive()`.
    rx_eth: VecDeque<Vec<u8>>,
    tx_pn: [u8; 6],
    pub hw_name: &'static str,
    pub firmware_loaded: bool,
    /// Last join frame sent, retransmitted on MLME timeouts.
    last_frame: Option<Vec<u8>>,
    retry_ticks: u32,
    last_generation: u32,
    retries: u32,
}

impl<B: Bus> WifiDevice<B> {
    pub fn new(transport: IwlTransport<B>, cfg: WifiConfig, expected_mac: Option<MacAddr>) -> Self {
        let mac = expected_mac.unwrap_or(transport.hw.mac);
        Self {
            transport,
            cfg,
            mlme: Mlme::new(mac),
            mac,
            stats: WifiStats::default(),
            rx_eth: VecDeque::new(),
            tx_pn: [0, 0, 0, 0, 0, 1],
            hw_name: "Intel Wi-Fi 6 AX201",
            firmware_loaded: false,
            last_frame: None,
            retry_ticks: 0,
            last_generation: 0,
            retries: 0,
        }
    }

    /// Run the whole bring-up: hardware, queues, firmware, alive.
    pub fn init(&mut self, firmware: &[u8]) -> Result<(), TransportError> {
        let image = fw::parse_tlv(firmware).map_err(|_| TransportError::BadFirmware)?;
        self.transport.apm_init()?;
        // The AX201 is the QuZ (CNVi) part; reject other 22000 variants.
        if self.transport.hw.hw_type != 0
            && self.transport.hw.hw_type != crate::regs::QUZ_HW_REV_TYPE
        {
            return Err(TransportError::UnsupportedHw);
        }
        if self.transport.hw.mac != [0; 6] && self.transport.hw.mac != self.mac {
            self.mac = self.transport.hw.mac;
            self.mlme.sta = self.mac;
        }
        self.transport.rx_init()?;
        self.transport.tx_init()?;
        // Data queue 1 carries management/EAPOL/data frames for the AP STA.
        self.transport.data_tx_alloc(1)?;
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
            self.send_join_commands(bssid, channel, false, 0);
            self.last_frame = Some(frame.clone());
            self.tx_80211(&frame);
        } else {
            self.mlme.start_scan();
            let channels = [(1u8, 0u8, false), (6, 0, false), (11, 0, false)];
            let req = cmd::scan_request(&channels, Some(self.cfg.ssid()), self.cfg.bssid, 1);
            let _ = self.transport.send_cmd(
                cmd::CMD_SCAN_REQ_UMAC,
                cmd::GROUP_LEGACY,
                cmd::VER_SCAN_REQ,
                &req,
            );
        }
        Ok(())
    }

    /// Drain firmware notifications and advance the MLME.
    pub fn poll(&mut self) {
        let mut block = [0u8; 2048];
        while let Some(pkt) = self.transport.rx_next_into(&mut block) {
            self.handle_notification(&pkt, &block[..]);
        }

        // Retransmit auth/assoc on timeout (APs do not retry these for us).
        if self.mlme.generation != self.last_generation {
            self.last_generation = self.mlme.generation;
            self.retry_ticks = 0;
            self.retries = 0;
        }
        self.retry_ticks = self.retry_ticks.saturating_add(1);
        let waiting = matches!(
            self.mlme.state,
            MlmeState::Authenticating | MlmeState::Associating
        );
        if waiting && self.retry_ticks >= 3 {
            self.retry_ticks = 0;
            self.retries = self.retries.saturating_add(1);
            if self.retries > 5 {
                self.stats.rx_dropped += 1;
                self.mlme.state = MlmeState::Failed;
                self.last_frame = None;
            } else if let Some(frame) = self.last_frame.clone() {
                let _ = self.tx_80211(&frame);
            }
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
                        let candidate = self.mlme.candidate().copied();
                        match self.mlme.begin_join(&self.cfg) {
                            Ok(frame) => {
                                if let Some(bss) = candidate {
                                    self.send_join_commands(bss.bssid, bss.channel, false, 0);
                                }
                                self.last_frame = Some(frame.clone());
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
                    Ok((frames, event)) => {
                        let last_frame = frames.last().cloned();
                        for f in frames {
                            self.tx_80211(&f);
                        }
                        match event {
                            Some(MlmeEvent::Authenticated) => {
                                self.last_frame = last_frame;
                            }
                            Some(MlmeEvent::Associated { .. }) => {
                                self.on_associated();
                                self.last_frame = None;
                            }
                            _ => {}
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
        let hdr_len = dot11::header_len(fc);
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
                Ok((frames, _event)) => {
                    for f in frames {
                        self.tx_80211(&f);
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
            self.rx_eth.push_back(eth);
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

    /// Send every management command needed before the first auth frame.
    fn send_join_commands(&mut self, bssid: MacAddr, channel: u8, assoc: bool, aid: u16) {
        use crate::cmd::{self, id_and_color};
        let band = if channel <= 14 {
            cmd::PHY_BAND_2GHZ
        } else {
            cmd::PHY_BAND_5GHZ
        };
        let action = if assoc {
            cmd::CTXT_ACTION_MODIFY
        } else {
            cmd::CTXT_ACTION_ADD
        };
        let _ = self.transport.send_cmd(
            cmd::CMD_PHY_CONTEXT,
            cmd::GROUP_LEGACY,
            cmd::VER_PHY_CONTEXT,
            &cmd::phy_context(id_and_color(0, 1), action, channel, band, cmd::PHY_WIDTH_20),
        );
        let mac_ctx = cmd::mac_context_sta(
            id_and_color(1, 1),
            action,
            self.mac,
            bssid,
            assoc,
            aid,
            self.mlme.beacon_interval(),
            self.mlme.dtim_period(),
        );
        let _ = self.transport.send_cmd(
            cmd::CMD_MAC_CONTEXT,
            cmd::GROUP_LEGACY,
            cmd::VER_MAC_CONTEXT,
            &mac_ctx,
        );
        if assoc {
            let _ = self.transport.send_cmd(
                cmd::CMD_ADD_STA,
                cmd::GROUP_LEGACY,
                cmd::VER_ADD_STA,
                &cmd::add_sta_modify(
                    1,
                    id_and_color(1, 1),
                    bssid,
                    aid,
                    1 << 1,
                    cmd::STA_FLAG_ASSOCIATED | cmd::STA_FLAG_AUTHORIZED,
                ),
            );
        } else {
            let _ = self.transport.send_cmd(
                cmd::CMD_ADD_STA,
                cmd::GROUP_LEGACY,
                cmd::VER_ADD_STA,
                &cmd::add_sta(1, id_and_color(1, 1), bssid, 0, 1 << 1, 0),
            );
            let _ = self.transport.data_tx_enable(1, 0);
        }
    }

    /// Association completed: update MAC/STA contexts and install keys.
    fn on_associated(&mut self) {
        let Some(bss) = self.mlme.bss else {
            return;
        };
        let aid = self.mlme.aid();
        self.send_join_commands(bss.bssid, bss.channel, true, aid);
    }

    /// Transmit one 802.11 frame on the data queue.
    ///
    /// Crypto is entirely in software: unprotected data frames (EAPOL msg4,
    /// group-key reply) are CCMP-wrapped once the PTK is installed, and the
    /// firmware is told not to encrypt (`IWL_TX_FLAGS_ENCRYPT_DIS`).  Firmware
    /// key offload is deliberately not used so RX frames stay encrypted and
    /// the software CCMP path sees the real ciphertext.
    fn tx_80211(&mut self, frame: &[u8]) -> bool {
        let mut owned: Vec<u8> = frame.to_vec();
        if owned.len() >= 24 {
            let fc = u16::from_le_bytes([owned[0], owned[1]]);
            let is_data = fc & 0x000c == 0x0008;
            let protected = fc & dot11::FCTL_PROTECTED != 0;
            if is_data && !protected {
                if let Some(supp) = self.mlme.supplicant.as_ref() {
                    if supp.keys().installed {
                        let tk = supp.keys().tk();
                        let pn = self.next_pn();
                        let hdr = dot11::header_len(fc);
                        if !dot11::ccmp_protect(&tk, &mut owned, &pn, hdr) {
                            self.stats.tx_dropped += 1;
                            return false;
                        }
                    }
                }
            }
        }
        match self.transport.send_mpdu(&owned, true) {
            Ok(_) => {
                self.stats.tx_80211 += 1;
                true
            }
            Err(_) => {
                self.stats.tx_dropped += 1;
                false
            }
        }
    }

    /// Pop one decrypted Ethernet frame for the IP stack.
    pub fn receive_eth(&mut self, out: &mut [u8]) -> Option<usize> {
        let frame = self.rx_eth.pop_front()?;
        if frame.len() > out.len() {
            return None;
        }
        out[..frame.len()].copy_from_slice(&frame);
        Some(frame.len())
    }

    /// Send one Ethernet II frame to the AP, adding CCMP when associated.
    pub fn transmit_eth(&mut self, frame: &[u8]) -> bool {
        if frame.len() < 14 || !self.mlme.is_connected() {
            return false;
        }
        let Some(bss) = self.mlme.bss else {
            return false;
        };
        let mut dst = [0u8; 6];
        dst.copy_from_slice(&frame[..6]);
        let mut src = [0u8; 6];
        src.copy_from_slice(&frame[6..12]);
        let seq = self.mlme.next_seq();
        let mpdu = dot11::build_data_frame(dst, src, bss.bssid, &frame[12..], seq);
        // `tx_80211` adds CCMP now that the PTK is installed.
        self.tx_80211(&mpdu)
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
        assert_eq!(
            u16::from_le_bytes([mpdu[0], mpdu[1]]),
            FC_TYPE_MGMT | FC_SUBTYPE_BEACON
        );
    }
}
