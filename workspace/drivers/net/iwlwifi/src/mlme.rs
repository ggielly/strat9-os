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

//! Station MLME: scan selection, open-system authentication, association and
//! WPA2 handshake driving.
//!
//! The MLME is transport-agnostic: it consumes received 802.11 frames and
//! produces the frames that must be transmitted.  `device.rs` feeds it from
//! the iwlwifi RX path and forwards its output through the firmware TX queue.

use alloc::vec::Vec;

use crate::config::WifiConfig;
use crate::dot11::{
    build_assoc_request, build_auth_request, build_deauth, parse_assoc_response,
    parse_auth_response, parse_beacon, BssInfo, MacAddr, SequenceCounter, BROADCAST,
    STATUS_SUCCESS,
};
use crate::wpa2::{Wpa2Supplicant, WpaState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlmeState {
    Idle,
    Scanning,
    Authenticating,
    Associating,
    FourWayHandshake,
    Connected,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlmeError {
    NotConfigured,
    NoCandidate,
    AuthRejected(u16),
    AssocRejected(u16),
    Wpa(crate::wpa2::WpaError),
    Timeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlmeEvent {
    ScanComplete,
    Authenticated,
    Associated { aid: u16 },
    HandshakeComplete,
    Deauthenticated { reason: u16 },
}

pub struct Mlme {
    pub state: MlmeState,
    pub bss: Option<BssInfo>,
    pub supplicant: Option<Wpa2Supplicant>,
    pub sta: MacAddr,
    pub keys_installed: bool,
    seq: SequenceCounter,
    assoc_aid: u16,
    beacon_interval: u16,
    dtim_period: u8,
    /// Last scan result chosen for a join.
    candidate: Option<BssInfo>,
    pub last_error: Option<MlmeError>,
    /// Incremented on every state transition, so the driver can log once.
    pub generation: u32,
}

impl Mlme {
    pub fn new(sta: MacAddr) -> Self {
        Self {
            state: MlmeState::Idle,
            bss: None,
            supplicant: None,
            sta,
            keys_installed: false,
            seq: SequenceCounter::default(),
            assoc_aid: 0,
            beacon_interval: 0,
            dtim_period: 0,
            candidate: None,
            last_error: None,
            generation: 0,
        }
    }

    fn transition(&mut self, state: MlmeState) {
        if self.state != state {
            self.state = state;
            self.generation = self.generation.wrapping_add(1);
        }
    }

    pub fn start_scan(&mut self) {
        self.candidate = None;
        self.bss = None;
        self.supplicant = None;
        self.keys_installed = false;
        self.transition(MlmeState::Scanning);
    }

    /// Feed a beacon/probe-response received during a scan.
    pub fn on_beacon(&mut self, frame: &[u8], rssi: i8, cfg: &WifiConfig) {
        let Some(info) = parse_beacon(frame, rssi) else {
            return;
        };
        if info.ssid() != cfg.ssid() {
            if !cfg.hidden {
                return;
            }
        }
        if !info.wpa2_psk_ccmp {
            return;
        }
        if let Some(want) = cfg.bssid {
            if info.bssid != want {
                return;
            }
        }
        // Prefer the strongest candidate seen so far.
        match &self.candidate {
            Some(previous) if previous.rssi >= info.rssi => {}
            _ => self.candidate = Some(info),
        }
    }

    /// Select the candidate and build the authentication request.
    pub fn begin_join(&mut self, cfg: &WifiConfig) -> Result<Vec<u8>, MlmeError> {
        let Some(bss) = self.candidate else {
            return Err(MlmeError::NoCandidate);
        };
        let pmk = cfg.pmk().ok_or(MlmeError::NotConfigured)?;
        self.supplicant = Some(Wpa2Supplicant::new(pmk, self.sta, bss.bssid));
        self.bss = Some(bss);
        self.beacon_interval = bss.beacon_interval;
        self.dtim_period = 2;
        self.transition(MlmeState::Authenticating);
        Ok(build_auth_request(bss.bssid, self.sta, self.seq.next()))
    }

    /// Join a specific BSS without scanning (config carries BSSID/channel).
    pub fn begin_direct_join(&mut self, cfg: &WifiConfig, bssid: MacAddr, channel: u8) -> Result<Vec<u8>, MlmeError> {
        let pmk = cfg.pmk().ok_or(MlmeError::NotConfigured)?;
        let mut bss = BssInfo {
            bssid,
            channel,
            ..Default::default()
        };
        let n = cfg.ssid_len.min(32);
        bss.ssid[..n].copy_from_slice(&cfg.ssid[..n]);
        bss.ssid_len = n;
        bss.wpa2_psk_ccmp = true;
        self.supplicant = Some(Wpa2Supplicant::new(pmk, self.sta, bssid));
        self.bss = Some(bss);
        self.candidate = Some(bss);
        self.beacon_interval = 100;
        self.dtim_period = 2;
        self.transition(MlmeState::Authenticating);
        Ok(build_auth_request(bssid, self.sta, self.seq.next()))
    }

    /// Handle a management frame addressed to us.
    ///
    /// Returns frames to transmit and an optional event for the driver.
    pub fn on_mgmt(
        &mut self,
        frame: &[u8],
        cfg: &WifiConfig,
        snonce: &[u8; 32],
    ) -> Result<(Vec<Vec<u8>>, Option<MlmeEvent>), MlmeError> {
        let bss = match self.bss {
            Some(b) => b,
            None => return Err(MlmeError::NotConfigured),
        };
        let mut out = Vec::new();
        let mut event = None;

        if let Some((seq, status)) = parse_auth_response(frame) {
            if seq != 2 {
                return Ok((out, None));
            }
            if self.state != MlmeState::Authenticating {
                return Ok((out, None));
            }
            if status != STATUS_SUCCESS {
                self.transition(MlmeState::Failed);
                self.last_error = Some(MlmeError::AuthRejected(status));
                return Err(MlmeError::AuthRejected(status));
            }
            self.transition(MlmeState::Associating);
            event = Some(MlmeEvent::Authenticated);
            out.push(build_assoc_request(
                bss.bssid,
                self.sta,
                cfg.ssid(),
                self.seq.next(),
                bss.channel,
                bss.ht,
                bss.vht,
                bss.he,
            ));
            return Ok((out, event));
        }

        if let Some((status, aid)) = parse_assoc_response(frame) {
            if self.state != MlmeState::Associating {
                return Ok((out, None));
            }
            if status != STATUS_SUCCESS {
                self.transition(MlmeState::Failed);
                self.last_error = Some(MlmeError::AssocRejected(status));
                return Err(MlmeError::AssocRejected(status));
            }
            self.assoc_aid = aid;
            self.transition(MlmeState::FourWayHandshake);
            event = Some(MlmeEvent::Associated { aid });
            return Ok((out, event));
        }

        // EAPOL-Key frames are 802.11 data frames with EtherType 0x888e.
        if let Some(eapol) = extract_eapol(frame) {
            if self.state == MlmeState::FourWayHandshake || self.state == MlmeState::Connected {
                let Some(supp) = self.supplicant.as_mut() else {
                    return Err(MlmeError::NotConfigured);
                };
                match supp.handle_eapol(eapol, snonce) {
                    Ok(responses) => {
                        for response in responses {
                            out.push(build_eapol_data_frame(bss.bssid, self.sta, &response, self.seq.next()));
                        }
                        if supp.state() == WpaState::Installed {
                            self.keys_installed = true;
                            self.transition(MlmeState::Connected);
                            event = Some(MlmeEvent::HandshakeComplete);
                        }
                    }
                    Err(e) => {
                        self.last_error = Some(MlmeError::Wpa(e));
                        return Err(MlmeError::Wpa(e));
                    }
                }
            }
            return Ok((out, event));
        }

        Ok((out, event))
    }

    /// Build a deauthentication frame when leaving the BSS.
    pub fn leave(&mut self) -> Option<Vec<u8>> {
        let bss = self.bss.take()?;
        self.supplicant = None;
        self.keys_installed = false;
        self.transition(MlmeState::Idle);
        Some(build_deauth(bss.bssid, self.sta, self.seq.next(), 3))
    }

    pub fn is_connected(&self) -> bool {
        self.state == MlmeState::Connected && self.keys_installed
    }

    pub fn aid(&self) -> u16 {
        self.assoc_aid
    }

    pub fn beacon_interval(&self) -> u16 {
        self.beacon_interval
    }

    pub fn dtim_period(&self) -> u8 {
        self.dtim_period
    }

    pub fn candidate(&self) -> Option<&BssInfo> {
        self.candidate.as_ref()
    }

    /// Next 802.11 sequence-control value.
    pub fn next_seq(&mut self) -> u16 {
        self.seq.next()
    }

    pub fn set_channel_hint(&mut self, channel: u8) {
        if let Some(mut bss) = self.candidate {
            bss.channel = channel;
            self.candidate = Some(bss);
        }
    }

    /// Broadcast probe request used by the scan path.
    pub fn probe_request(&mut self, ssid: &[u8]) -> Vec<u8> {
        crate::dot11::build_probe_request(ssid, self.seq.next(), true, true)
    }

    /// Helper used by the driver when no explicit BSSID is configured.
    pub fn broadcast_addr() -> MacAddr {
        BROADCAST
    }
}

/// Extract the EAPOL payload from an 802.11 data frame (unprotected or
/// CCMP-protected, already decrypted by the caller).
pub fn extract_eapol(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 24 + 8 {
        return None;
    }
    let fc = u16::from_le_bytes([frame[0], frame[1]]);
    if fc & 0x000c != 0x0008 {
        return None;
    }
    let hdr = crate::dot11::header_len(fc);
    let body = frame.get(hdr..)?;
    // LLC/SNAP + EtherType 0x888e
    if body.len() < 8 || body[..6] != [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00] {
        return None;
    }
    if body[6] != 0x88 || body[7] != 0x8e {
        return None;
    }
    Some(&body[8..])
}

/// Wrap an EAPOL frame in an 802.11 data frame towards the AP.
pub fn build_eapol_data_frame(bssid: MacAddr, sta: MacAddr, eapol: &[u8], seq: u16) -> Vec<u8> {
    // EtherType + EAPOL as the "Ethernet type payload" for build_data_frame.
    let mut payload = Vec::with_capacity(2 + eapol.len());
    payload.extend_from_slice(&[0x88, 0x8e]);
    payload.extend_from_slice(eapol);
    crate::dot11::build_data_frame(bssid, sta, bssid, &payload, seq)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dot11::{FC_SUBTYPE_ASSOC_RESP, FC_SUBTYPE_AUTH, FC_TYPE_MGMT};
    use crate::wpa2::EAPOL_TYPE_KEY;

    fn cfg() -> WifiConfig {
        let text = "[wifi]\nenabled=true\nssid=\"IEEE\"\npassphrase=\"password\"\nbssid=\"02:00:00:00:00:02\"\n";
        crate::config::parse(text).unwrap()
    }

    fn mgmt(fc: u16, a1: MacAddr, a2: MacAddr, body: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&fc.to_le_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(&a1);
        f.extend_from_slice(&a2);
        f.extend_from_slice(&a2);
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(body);
        f
    }

    #[test]
    fn auth_then_assoc() {
        let cfg = cfg();
        let sta = [0x02, 0, 0, 0, 0, 1];
        let bssid = [0x02, 0, 0, 0, 0, 2];
        let mut mlme = Mlme::new(sta);
        mlme.begin_direct_join(&cfg, bssid, 6).unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&0u16.to_le_bytes()); // alg
        body.extend_from_slice(&2u16.to_le_bytes()); // seq
        body.extend_from_slice(&0u16.to_le_bytes()); // status
        let auth = mgmt(FC_TYPE_MGMT | FC_SUBTYPE_AUTH, sta, bssid, &body);
        let (out, ev) = mlme.on_mgmt(&auth, &cfg, &[0; 32]).unwrap();
        assert_eq!(ev, Some(MlmeEvent::Authenticated));
        assert_eq!(out.len(), 1);
        assert_eq!(mlme.state, MlmeState::Associating);

        let mut assoc = Vec::new();
        assoc.extend_from_slice(&0x0431u16.to_le_bytes());
        assoc.extend_from_slice(&0u16.to_le_bytes());
        assoc.extend_from_slice(&0u16.to_le_bytes());
        assoc.extend_from_slice(&0x4000u16.to_le_bytes()); // aid
        let frame = mgmt(FC_TYPE_MGMT | FC_SUBTYPE_ASSOC_RESP, sta, bssid, &assoc);
        let (_, ev) = mlme.on_mgmt(&frame, &cfg, &[0; 32]).unwrap();
        assert_eq!(ev, Some(MlmeEvent::Associated { aid: 0x4000 & 0x3fff }));
        assert_eq!(mlme.state, MlmeState::FourWayHandshake);
    }

    #[test]
    fn eapol_extraction() {
        let bssid = [1; 6];
        let sta = [2; 6];
        let mut eapol = Vec::new();
        eapol.extend_from_slice(&[2, EAPOL_TYPE_KEY, 0, 0]);
        let frame = build_eapol_data_frame(bssid, sta, &eapol, 0);
        assert!(extract_eapol(&frame).is_some());
    }
}
