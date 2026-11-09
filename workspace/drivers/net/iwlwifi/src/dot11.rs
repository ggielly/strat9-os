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

//! Minimal IEEE 802.11 frame layer for AX201 station mode.
//!
//! This is not a full MLME.  It provides exactly what the driver needs:
//! scan/probe frame construction, beacon/probe-response parsing, open-system
//! authentication, association, and 802.3 <-> 802.11 data conversion with
//! CCMP protection.  MAC management (scan scheduling, retries, rate control)
//! is driven by `mlme.rs`.
//!
//! Reference: IEEE 802.11-2016, sections 9 (MAC frames) and 12.5 (CCMP).

use alloc::vec::Vec;

use crate::crypto::ccmp::{ccm_decrypt, ccm_encrypt};
use crate::crypto::CCMP_MIC_LEN;

pub type MacAddr = [u8; 6];
pub const BROADCAST: MacAddr = [0xff; 6];

// Frame control fields (little-endian bit positions).
pub const FC_TYPE_MGMT: u16 = 0x0000;
pub const FC_TYPE_DATA: u16 = 0x0008;
pub const FC_SUBTYPE_PROBE_REQ: u16 = 0x0040;
pub const FC_SUBTYPE_PROBE_RESP: u16 = 0x0050;
pub const FC_SUBTYPE_BEACON: u16 = 0x0080;
pub const FC_SUBTYPE_AUTH: u16 = 0x00b0;
pub const FC_SUBTYPE_ASSOC_REQ: u16 = 0x0000;
pub const FC_SUBTYPE_ASSOC_RESP: u16 = 0x0010;
pub const FC_SUBTYPE_DEAUTH: u16 = 0x00c0;

pub const FCTL_TO_DS: u16 = 0x0100;
pub const FCTL_FROM_DS: u16 = 0x0200;
pub const FCTL_PROTECTED: u16 = 0x4000;

pub const AUTH_ALG_OPEN: u16 = 0;
pub const AUTH_SEQ_OPEN: u16 = 1;
pub const STATUS_SUCCESS: u16 = 0;

pub const IE_SSID: u8 = 0;
pub const IE_SUPPORTED_RATES: u8 = 1;
pub const IE_DS_PARAM: u8 = 3;
pub const IE_RSN: u8 = 48;
pub const IE_HT_CAP: u8 = 45;
pub const IE_VHT_CAP: u8 = 191;
pub const IE_EXTENSION: u8 = 255;
pub const IE_EXT_HE_CAP: u8 = 35;

pub const LLC_SNAP: [u8; 6] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00];
pub const CCMP_HDR_LEN: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BssInfo {
    pub bssid: MacAddr,
    pub ssid_len: usize,
    pub ssid: [u8; 32],
    pub channel: u8,
    pub rssi: i8,
    pub beacon_interval: u16,
    pub capability: u16,
    pub privacy: bool,
    pub wpa2_psk_ccmp: bool,
    pub ht: bool,
    pub vht: bool,
    pub he: bool,
}

impl Default for BssInfo {
    fn default() -> Self {
        Self {
            bssid: [0; 6],
            ssid_len: 0,
            ssid: [0; 32],
            channel: 0,
            rssi: 0,
            beacon_interval: 0,
            capability: 0,
            privacy: false,
            wpa2_psk_ccmp: false,
            ht: false,
            vht: false,
            he: false,
        }
    }
}

impl BssInfo {
    pub fn ssid(&self) -> &[u8] {
        &self.ssid[..self.ssid_len]
    }
}

/// Information-element writer.
pub struct IeWriter<'a> {
    buf: &'a mut Vec<u8>,
}

impl<'a> IeWriter<'a> {
    pub fn new(buf: &'a mut Vec<u8>) -> Self {
        Self { buf }
    }

    pub fn raw(&mut self, id: u8, body: &[u8]) {
        self.buf.push(id);
        self.buf.push(body.len() as u8);
        self.buf.extend_from_slice(body);
    }

    pub fn ssid(&mut self, ssid: &[u8]) {
        self.raw(IE_SSID, &ssid[..ssid.len().min(32)]);
    }

    /// Supported rates: 1, 2, 5.5, 11, 6, 9, 12, 18, 24, 36, 48, 54 Mbps.
    pub fn supported_rates(&mut self) {
        self.raw(
            IE_SUPPORTED_RATES,
            &[
                0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c,
            ],
        );
    }

    pub fn ds_param(&mut self, channel: u8) {
        self.raw(IE_DS_PARAM, &[channel]);
    }

    /// RSN IE for WPA2-PSK with CCMP.
    ///
    /// `group_cipher` / `pairwise_cipher` are cipher suite selectors; WPA2
    /// CCMP is `00:0f:ac:04`.
    pub fn rsn_wpa2_psk_ccmp(&mut self) {
        let body = [
            0x01, 0x00, // version 1
            0x00, 0x0f, 0xac, 0x04, // group cipher: CCMP
            0x01, 0x00, // 1 pairwise suite
            0x00, 0x0f, 0xac, 0x04, // pairwise: CCMP
            0x01, 0x00, // 1 AKM suite
            0x00, 0x0f, 0xac, 0x02, // PSK
            0x00, 0x00, // capabilities: preauth not supported
        ];
        self.raw(IE_RSN, &body);
    }

    /// HT capabilities (20/40 MHz, SGI, MCS 0..15 for 2x2).
    pub fn ht_capabilities(&mut self) {
        let mut body = [0u8; 26];
        // Capabilities info: LDPC, 20/40, SGI20, SGI40, DSSS/CCK.
        body[0] = 0x2c;
        body[1] = 0x00;
        // AMPDU params: max length 64k, density 8.
        body[2] = 0x1b;
        // Rx MCS bitmask: MCS 0..15 (2 spatial streams).
        body[3] = 0xff;
        body[4] = 0xff;
        // Tx MCS set: same.
        body[5] = 0xff;
        body[6] = 0xff;
        // Tx/Rx MCS mismatch: none.
        body[7] = 0x00;
        // HT extended capabilities: MCS 32.
        body[8] = 0x00;
        body[9] = 0x00;
        self.raw(IE_HT_CAP, &body);
    }

    /// VHT capabilities (2x2, up to 80 MHz).
    pub fn vht_capabilities(&mut self) {
        let mut body = [0u8; 12];
        // Max MPDU 11454, supported channel width set.
        body[0] = 0x02;
        body[1] = 0x00;
        body[2] = 0x00;
        body[3] = 0x00;
        // Rx/Tx MCS map: 2 streams.
        body[4] = 0xfa;
        body[5] = 0xff;
        body[6] = 0xfa;
        body[7] = 0xff;
        self.raw(IE_VHT_CAP, &body);
    }

    /// HE (802.11ax) capabilities, minimal 2x2 / 20 MHz form.
    ///
    /// The full HE Capabilities element is 21+ bytes and depends on the PHY
    /// configuration negotiated with the AP.  The driver advertises a
    /// conservative subset and lets the firmware own the actual HE MCS/OMI
    /// negotiation.
    pub fn he_capabilities(&mut self) {
        // Extension element body starts with the HE Capabilities extension ID
        // (35), followed by 32-bit MAC/PHY caps and the MCS/NSS map.
        let mut body = [0u8; 22];
        body[0] = IE_EXT_HE_CAP;
        // HE MAC capabilities: 32-bit.
        body[1] = 0x0d;
        body[2] = 0x00;
        // HE PHY capabilities: 32-bit (channel width set: 20/40/80).
        body[7] = 0x00;
        // Supported HE-MCS and NSS set: 2 streams, 20 MHz only.
        body[13] = 0xfc;
        body[14] = 0xff;
        body[15] = 0xfc;
        body[16] = 0xff;
        self.raw(IE_EXTENSION, &body);
    }
}

/// Serialized sequence counter for management frames.
#[derive(Default)]
pub struct SequenceCounter {
    value: u16,
}

impl SequenceCounter {
    pub fn next(&mut self) -> u16 {
        let v = self.value & 0x0fff;
        self.value = (self.value + 1) & 0x0fff;
        v << 4
    }
}

fn push_header(
    out: &mut Vec<u8>,
    fc: u16,
    a1: MacAddr,
    a2: MacAddr,
    a3: MacAddr,
    seq: u16,
) {
    out.extend_from_slice(&fc.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // duration
    out.extend_from_slice(&a1);
    out.extend_from_slice(&a2);
    out.extend_from_slice(&a3);
    out.extend_from_slice(&seq.to_le_bytes());
}

pub fn build_probe_request(ssid: &[u8], seq: u16, rates: bool, ht: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    push_header(
        &mut out,
        FC_TYPE_MGMT | FC_SUBTYPE_PROBE_REQ,
        BROADCAST,
        BROADCAST,
        BROADCAST,
        seq,
    );
    let mut ie = IeWriter::new(&mut out);
    if ssid.is_empty() {
        ie.raw(IE_SSID, &[]);
    } else {
        ie.ssid(ssid);
    }
    if rates {
        ie.supported_rates();
    }
    if ht {
        ie.ht_capabilities();
    }
    let _ = ie;
    out
}

pub fn build_auth_request(bssid: MacAddr, sta: MacAddr, seq: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    push_header(
        &mut out,
        FC_TYPE_MGMT | FC_SUBTYPE_AUTH,
        bssid,
        sta,
        bssid,
        seq,
    );
    out.extend_from_slice(&AUTH_ALG_OPEN.to_le_bytes());
    out.extend_from_slice(&AUTH_SEQ_OPEN.to_le_bytes());
    out.extend_from_slice(&STATUS_SUCCESS.to_le_bytes());
    out
}

pub fn build_assoc_request(
    bssid: MacAddr,
    sta: MacAddr,
    ssid: &[u8],
    seq: u16,
    channel: u8,
    ht: bool,
    vht: bool,
    he: bool,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    push_header(
        &mut out,
        FC_TYPE_MGMT | FC_SUBTYPE_ASSOC_REQ,
        bssid,
        sta,
        bssid,
        seq,
    );
    // Capabilities: ESS | short preamble | short slot.
    out.extend_from_slice(&0x0431u16.to_le_bytes());
    out.extend_from_slice(&10u16.to_le_bytes()); // listen interval
    {
        let mut ie = IeWriter::new(&mut out);
        ie.ssid(ssid);
        ie.supported_rates();
        ie.rsn_wpa2_psk_ccmp();
        if ht {
            ie.ht_capabilities();
        }
        if vht {
            ie.vht_capabilities();
        }
        if he {
            ie.he_capabilities();
        }
        if channel != 0 {
            ie.ds_param(channel);
        }
    }
    out
}

pub fn build_deauth(bssid: MacAddr, sta: MacAddr, seq: u16, reason: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    push_header(
        &mut out,
        FC_TYPE_MGMT | FC_SUBTYPE_DEAUTH,
        bssid,
        sta,
        bssid,
        seq,
    );
    out.extend_from_slice(&reason.to_le_bytes());
    out
}

/// Parse a beacon or probe response into `BssInfo`.
pub fn parse_beacon(frame: &[u8], rssi: i8) -> Option<BssInfo> {
    if frame.len() < 36 {
        return None;
    }
    let fc = u16::from_le_bytes([frame[0], frame[1]]);
    if fc & 0x00f0 != FC_SUBTYPE_BEACON && fc & 0x00f0 != FC_SUBTYPE_PROBE_RESP {
        return None;
    }
    let mut info = BssInfo {
        rssi,
        ..Default::default()
    };
    info.bssid.copy_from_slice(&frame[16..22]);
    info.capability = u16::from_le_bytes([frame[34], frame[35]]);
    info.privacy = info.capability & 0x0010 != 0;
    let mut pos = 36usize;
    while pos + 2 <= frame.len() {
        let id = frame[pos];
        let len = frame[pos + 1] as usize;
        let body_start = pos + 2;
        let body_end = body_start.checked_add(len)?;
        if body_end > frame.len() {
            break;
        }
        let body = &frame[body_start..body_end];
        match id {
            IE_SSID => {
                let n = body.len().min(32);
                info.ssid[..n].copy_from_slice(&body[..n]);
                info.ssid_len = n;
            }
            IE_DS_PARAM if !body.is_empty() => info.channel = body[0],
            IE_HT_CAP => info.ht = true,
            IE_VHT_CAP => info.vht = true,
            IE_EXTENSION if body.first() == Some(&IE_EXT_HE_CAP) => info.he = true,
            IE_RSN => info.wpa2_psk_ccmp = parse_rsn_wpa2_psk_ccmp(body),
            _ => {}
        }
        pos = body_end;
    }
    // Some APs do not include the DS parameter IE in beacons; derive the
    // channel from the 2.4 GHz channel number in the probe response body is
    // outside the scope of this minimal parser.
    Some(info)
}

fn parse_rsn_wpa2_psk_ccmp(body: &[u8]) -> bool {
    if body.len() < 8 {
        return false;
    }
    let version = u16::from_le_bytes([body[0], body[1]]);
    if version != 1 {
        return false;
    }
    // FF-00-0F-AC group cipher
    if body[2..6] != [0x00, 0x0f, 0xac, 0x04] {
        return false;
    }
    let pairwise_count = u16::from_le_bytes([body[6], body[7]]) as usize;
    let mut pos = 8usize;
    let mut has_ccmp = false;
    for _ in 0..pairwise_count {
        if pos + 4 > body.len() {
            return false;
        }
        if body[pos..pos + 4] == [0x00, 0x0f, 0xac, 0x04] {
            has_ccmp = true;
        }
        pos += 4;
    }
    if !has_ccmp || pos + 2 > body.len() {
        return false;
    }
    let akm_count = u16::from_le_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    for _ in 0..akm_count {
        if pos + 4 > body.len() {
            return false;
        }
        // 00-0F-AC-02 = PSK
        if body[pos..pos + 4] == [0x00, 0x0f, 0xac, 0x02] {
            return true;
        }
        pos += 4;
    }
    false
}

/// Parse an association response.  Returns `(status, aid)`.
pub fn parse_assoc_response(frame: &[u8]) -> Option<(u16, u16)> {
    if frame.len() < 30 {
        return None;
    }
    let fc = u16::from_le_bytes([frame[0], frame[1]]);
    if fc & 0x00f0 != FC_SUBTYPE_ASSOC_RESP {
        return None;
    }
    let status = u16::from_le_bytes([frame[26], frame[27]]);
    let aid = u16::from_le_bytes([frame[28], frame[29]]) & 0x3fff;
    Some((status, aid))
}

/// Parse an authentication response.  Returns `(seq, status)`.
pub fn parse_auth_response(frame: &[u8]) -> Option<(u16, u16)> {
    if frame.len() < 30 {
        return None;
    }
    let fc = u16::from_le_bytes([frame[0], frame[1]]);
    if fc & 0x00f0 != FC_SUBTYPE_AUTH {
        return None;
    }
    Some((
        u16::from_le_bytes([frame[26], frame[27]]),
        u16::from_le_bytes([frame[28], frame[29]]),
    ))
}

/// Build an unprotected 802.11 data frame carrying an Ethernet II frame.
///
/// `from_ds_to_sta` is used for frames the AP sends to us in station mode.
/// `eth_type_payload` is the Ethernet II frame starting at its EtherType
/// field (i.e. the frame without its 14-byte header).
pub fn build_data_frame(
    dst: MacAddr,
    src: MacAddr,
    bssid: MacAddr,
    eth_type_payload: &[u8],
    seq: u16,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(36 + eth_type_payload.len());
    push_header(
        &mut out,
        FC_TYPE_DATA | FCTL_TO_DS,
        bssid,
        src,
        dst,
        seq,
    );
    out.extend_from_slice(&LLC_SNAP);
    out.extend_from_slice(eth_type_payload);
    out
}

/// 802.11 MAC header length (24, 26, 30 or 32 bytes).
pub fn header_len(fc: u16) -> usize {
    let mut len = 24usize;
    if fc & FCTL_TO_DS != 0 && fc & FCTL_FROM_DS != 0 {
        len += 6;
    }
    if fc & 0x0080 != 0 {
        len += 2; // QoS control
    }
    len
}

/// Convert an unprotected 802.11 data payload into an Ethernet II frame.
pub fn data_to_ethernet(frame: &[u8]) -> Option<Vec<u8>> {
    if frame.len() < 24 {
        return None;
    }
    let fc = u16::from_le_bytes([frame[0], frame[1]]);
    if fc & 0x000c != FC_TYPE_DATA {
        return None;
    }
    let to_ds = fc & FCTL_TO_DS != 0;
    let from_ds = fc & FCTL_FROM_DS != 0;
    let hdr_len = header_len(fc);
    if frame.len() < hdr_len + 8 {
        return None;
    }
    let a1 = &frame[4..10];
    let a2 = &frame[10..16];
    let a3 = &frame[16..22];
    let (dst, src) = match (to_ds, from_ds) {
        (false, true) => (a1, a3),
        (true, false) => (a3, a2),
        _ => (a1, a2),
    };
    let payload = &frame[hdr_len..];
    if payload[..6] != LLC_SNAP {
        return None;
    }
    let mut out = Vec::with_capacity(14 + payload.len() - 8);
    out.extend_from_slice(dst);
    out.extend_from_slice(src);
    out.extend_from_slice(&payload[6..8]); // EtherType
    out.extend_from_slice(&payload[8..]);
    Some(out)
}

/// CCMP AAD for a data frame.  Returns the AAD and its length, which depends
/// on A4 (WDS) and QoS control presence.
pub fn ccmp_aad(frame: &[u8]) -> ([u8; 30], usize) {
    let fc = u16::from_le_bytes([frame[0], frame[1]]);
    // Mask Retry/PM/MoreData, clear subtype bits for data, set Protected.
    let mut mask = fc & !(0x0800 | 0x1000 | 0x2000);
    mask &= !0x0070;
    mask |= FCTL_PROTECTED;
    let a4 = mask & FCTL_TO_DS != 0 && mask & FCTL_FROM_DS != 0;
    let qos = mask & 0x0080 != 0;
    let mut aad = [0u8; 30];
    aad[0..2].copy_from_slice(&mask.to_le_bytes());
    aad[2..8].copy_from_slice(&frame[4..10]);
    aad[8..14].copy_from_slice(&frame[10..16]);
    aad[14..20].copy_from_slice(&frame[16..22]);
    aad[20] = frame[22] & 0x0f;
    aad[21] = 0;
    let mut len = 22usize;
    if a4 {
        aad[len..len + 6].copy_from_slice(&frame[24..30]);
        len += 6;
    }
    if qos {
        let qc = if a4 { 30 } else { 24 };
        aad[len] = frame[qc];
        aad[len + 1] = 0;
        len += 2;
    }
    (aad, len)
}

/// CCMP 13-byte nonce: priority | A2 | PN.
pub fn ccmp_nonce(frame: &[u8], pn: &[u8; 6]) -> [u8; 13] {
    let fc = u16::from_le_bytes([frame[0], frame[1]]);
    let hdr = header_len(fc);
    let mut nonce = [0u8; 13];
    nonce[0] = if fc & 0x0080 != 0 && hdr >= 26 {
        frame[hdr - 2] & 0x0f // QoS TID for 802.11 data
    } else {
        0
    };
    nonce[1..7].copy_from_slice(&frame[10..16]);
    nonce[7..13].copy_from_slice(pn);
    nonce
}

/// Encrypt a data frame in place: insert the CCMP header after the 802.11
/// header and append the MIC.  `frame` must be unprotected (no CCMP header).
pub fn ccmp_protect(
    key: &[u8; 16],
    frame: &mut Vec<u8>,
    pn: &[u8; 6],
    hdr_len: usize,
) -> bool {
    if frame.len() < hdr_len {
        return false;
    }
    // Set the Protected bit before computing AAD.
    let fc = u16::from_le_bytes([frame[0], frame[1]]) | FCTL_PROTECTED;
    frame[0..2].copy_from_slice(&fc.to_le_bytes());

    let (aad, aad_len) = ccmp_aad(frame);
    let nonce = ccmp_nonce(frame, pn);
    let mut payload = frame.split_off(hdr_len);
    let mut mic = [0u8; CCMP_MIC_LEN];
    ccm_encrypt(key, &nonce, &aad[..aad_len], &mut payload, &mut mic);

    // CCMP header: LSB..MSB PN with ExtIV.
    let mut hdr = [0u8; CCMP_HDR_LEN];
    hdr[0] = pn[5];
    hdr[1] = pn[4];
    hdr[2] = 0;
    hdr[3] = 0x20;
    hdr[4] = pn[3];
    hdr[5] = pn[2];
    hdr[6] = pn[1];
    hdr[7] = pn[0];

    frame.extend_from_slice(&hdr);
    frame.extend_from_slice(&payload);
    frame.extend_from_slice(&mic);
    true
}

/// Decrypt a CCMP-protected frame in place.  Returns the 802.11 header length
/// on success (payload now decrypted, CCMP header/MIC removed).
pub fn ccmp_unprotect(key: &[u8; 16], frame: &mut Vec<u8>, hdr_len: usize) -> Option<usize> {
    if frame.len() < hdr_len + CCMP_HDR_LEN + CCMP_MIC_LEN {
        return None;
    }
    let pn = [
        frame[hdr_len + 7],
        frame[hdr_len + 6],
        frame[hdr_len + 5],
        frame[hdr_len + 4],
        frame[hdr_len + 1],
        frame[hdr_len],
    ];
    let (aad, aad_len) = ccmp_aad(frame);
    let nonce = ccmp_nonce(frame, &pn);
    let mut mic = [0u8; CCMP_MIC_LEN];
    mic.copy_from_slice(&frame[frame.len() - CCMP_MIC_LEN..]);
    let mut payload =
        frame[hdr_len + CCMP_HDR_LEN..frame.len() - CCMP_MIC_LEN].to_vec();
    if !ccm_decrypt(key, &nonce, &aad[..aad_len], &mut payload, &mic) {
        return None;
    }
    frame.truncate(hdr_len);
    frame.extend_from_slice(&payload);
    Some(hdr_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beacon_parsing() {
        let mut f = Vec::new();
        // FC beacon, dur, bssid, bssid, bssid, seq
        f.extend_from_slice(&(FC_TYPE_MGMT | FC_SUBTYPE_BEACON).to_le_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
        f.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
        f.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
        f.extend_from_slice(&[0, 0]);
        // timestamp + interval + capability
        f.extend_from_slice(&[0u8; 8]);
        f.extend_from_slice(&100u16.to_le_bytes());
        f.extend_from_slice(&0x0431u16.to_le_bytes());
        let mut ie = IeWriter::new(&mut f);
        ie.ssid(b"HomeNet");
        ie.ds_param(6);
        ie.rsn_wpa2_psk_ccmp();
        ie.ht_capabilities();
        let info = parse_beacon(&f, -42).unwrap();
        assert_eq!(info.bssid, [1, 2, 3, 4, 5, 6]);
        assert_eq!(info.ssid(), b"HomeNet");
        assert_eq!(info.channel, 6);
        assert!(info.wpa2_psk_ccmp);
        assert!(info.ht);
        assert!(!info.he);
        assert_eq!(info.rssi, -42);
    }

    #[test]
    fn ethernet_roundtrip_unprotected() {
        let eth = [
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x14,
        ];
        let mut dst = [0u8; 6];
        dst.copy_from_slice(&eth[..6]);
        let mut src = [0u8; 6];
        src.copy_from_slice(&eth[6..12]);
        let f = build_data_frame(dst, src, [0x22; 6], &eth[12..], 0x10);
        let out = data_to_ethernet(&f).unwrap();
        assert_eq!(&out[..6], &eth[..6]);
        assert_eq!(&out[6..12], &eth[6..12]);
        assert_eq!(&out[12..], &eth[12..]);
    }

    #[test]
    fn qos_ccmp_roundtrip() {
        let key = [0x55u8; 16];
        let mut f = Vec::new();
        // QoS data, ToDS.
        f.extend_from_slice(&(FC_TYPE_DATA | FCTL_TO_DS | 0x0080).to_le_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(&[0x22; 6]); // BSSID (A1)
        f.extend_from_slice(&[0x11; 6]); // SA (A2)
        f.extend_from_slice(&[0xaa; 6]); // DA (A3)
        f.extend_from_slice(&[0x10, 0x00]); // seq
        f.extend_from_slice(&[0x05, 0x00]); // QoS control (TID 5)
        f.extend_from_slice(&LLC_SNAP);
        f.extend_from_slice(&[0x08, 0x00, 0xde, 0xad]);
        let hdr = header_len(u16::from_le_bytes([f[0], f[1]]));
        assert_eq!(hdr, 26);
        let pn = [9, 8, 7, 6, 5, 4];
        assert!(ccmp_protect(&key, &mut f, &pn, hdr));
        assert!(ccmp_unprotect(&key, &mut f, hdr).is_some());
        let eth = data_to_ethernet(&f).unwrap();
        assert_eq!(&eth[12..], &[0x08, 0x00, 0xde, 0xad]);
    }

    #[test]
    fn ccmp_protect_roundtrip() {
        let key = [0x42u8; 16];
        let eth = [
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x08, 0x00,
            0x01, 0x02, 0x03, 0x04,
        ];
        let mut f = build_data_frame([0xaa; 6], [0x11; 6], [0x22; 6], &eth[12..], 0x20);
        let hdr_len = 24;
        let pn = [1, 2, 3, 4, 5, 6];
        assert!(ccmp_protect(&key, &mut f, &pn, hdr_len));
        assert!(f.len() > hdr_len + CCMP_HDR_LEN);
        let out = ccmp_unprotect(&key, &mut f, hdr_len).unwrap();
        assert_eq!(out, hdr_len);
        let eth_out = data_to_ethernet(&f).unwrap();
        assert_eq!(&eth_out[12..], &eth[12..]);
    }
}
