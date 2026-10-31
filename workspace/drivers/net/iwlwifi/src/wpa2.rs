//! WPA2-PSK supplicant (4-way handshake + group key handshake).
//!
//! This implements the station side of IEEE 802.11-2016, 12.7.6:
//!
//! ```text
//! AP  --- EAPOL-Key (ANonce, ACK) ----------------------> STA   (Msg 1)
//! AP  <-- EAPOL-Key (SNonce, MIC) ----------------------- STA   (Msg 2)
//! AP  --- EAPOL-Key (ANonce, MIC, Install, Secure, GTK) > STA   (Msg 3)
//! AP  <-- EAPOL-Key (MIC, Secure) ----------------------- STA   (Msg 4)
//! AP  --- EAPOL-Key (group, MIC, Secure, GTK) ----------> STA   (group 1)
//! AP  <-- EAPOL-Key (MIC, Secure) ----------------------- STA   (group 2)
//! ```
//!
//! The driver feeds every received EAPOL-Key frame to
//! [`Wpa2Supplicant::handle_eapol`] and transmits the returned frames.

use alloc::vec::Vec;

use crate::crypto::{
    derive_ptk, hmac_sha1, key_unwrap, CCMP_KEY_LEN, PMK_LEN, PTK_LEN,
};
use crate::dot11::MacAddr;

pub const EAPOL_TYPE_KEY: u8 = 3;
pub const EAPOL_VERSION_2004: u8 = 2;
pub const KEY_DESCRIPTOR_RSN: u8 = 2;
pub const KEY_INFO_VERSION_CCMP: u16 = 2;

pub const KEY_INFO_PAIRWISE: u16 = 0x0008;
pub const KEY_INFO_INSTALL: u16 = 0x0010;
pub const KEY_INFO_ACK: u16 = 0x0020;
pub const KEY_INFO_MIC: u16 = 0x0040;
pub const KEY_INFO_SECURE: u16 = 0x0080;
pub const KEY_INFO_ERROR: u16 = 0x0100;
pub const KEY_INFO_REQUEST: u16 = 0x0200;
pub const KEY_INFO_ENCRYPTED: u16 = 0x0400;
pub const KEY_INFO_SMK: u16 = 0x1000;

pub const KEY_FRAME_FIXED_LEN: usize = 95;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WpaError {
    Malformed,
    WrongDescriptor,
    MicFailure,
    WrongReplay,
    UnexpectedMessage,
    DecryptFailure,
    NoKeyMaterial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WpaState {
    Idle,
    WaitMsg2,
    WaitMsg4,
    Installed,
}

#[derive(Clone, Copy)]
pub struct EapolKey {
    pub key_info: u16,
    pub key_length: u16,
    pub replay_counter: u64,
    pub nonce: [u8; 32],
    pub key_iv: [u8; 16],
    pub key_rsc: [u8; 8],
    pub key_id: [u8; 8],
    pub mic: [u8; 16],
    pub key_data_len: usize,
    pub key_data_offset: usize,
}

impl EapolKey {
    pub fn is_pairwise(&self) -> bool {
        self.key_info & KEY_INFO_PAIRWISE != 0
    }
    pub fn has_mic(&self) -> bool {
        self.key_info & KEY_INFO_MIC != 0
    }
    pub fn is_encrypted(&self) -> bool {
        self.key_info & KEY_INFO_ENCRYPTED != 0
    }
    pub fn is_secure(&self) -> bool {
        self.key_info & KEY_INFO_SECURE != 0
    }
    pub fn is_install(&self) -> bool {
        self.key_info & KEY_INFO_INSTALL != 0
    }
}

/// Parse an EAPOL-Key frame (starting at the EAPOL header).
pub fn parse_eapol_key(frame: &[u8]) -> Result<EapolKey, WpaError> {
    if frame.len() < 4 + KEY_FRAME_FIXED_LEN {
        return Err(WpaError::Malformed);
    }
    if frame[1] != EAPOL_TYPE_KEY {
        return Err(WpaError::Malformed);
    }
    let body_len = u16::from_be_bytes([frame[2], frame[3]]) as usize;
    if 4 + body_len > frame.len() {
        return Err(WpaError::Malformed);
    }
    let b = &frame[4..4 + body_len];
    if b[0] != KEY_DESCRIPTOR_RSN {
        return Err(WpaError::WrongDescriptor);
    }
    let key_info = u16::from_be_bytes([b[1], b[2]]);
    let key_length = u16::from_be_bytes([b[3], b[4]]);
    let mut replay = [0u8; 8];
    replay.copy_from_slice(&b[5..13]);
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&b[13..45]);
    let mut key_iv = [0u8; 16];
    key_iv.copy_from_slice(&b[45..61]);
    let mut key_rsc = [0u8; 8];
    key_rsc.copy_from_slice(&b[61..69]);
    let mut key_id = [0u8; 8];
    key_id.copy_from_slice(&b[69..77]);
    let mut mic = [0u8; 16];
    mic.copy_from_slice(&b[77..93]);
    let key_data_len = u16::from_be_bytes([b[93], b[94]]) as usize;
    let key_data_offset = 4 + KEY_FRAME_FIXED_LEN;
    if key_data_offset + key_data_len > frame.len() {
        return Err(WpaError::Malformed);
    }
    Ok(EapolKey {
        key_info,
        key_length,
        replay_counter: u64::from_be_bytes(replay),
        nonce,
        key_iv,
        key_rsc,
        key_id,
        mic,
        key_data_len,
        key_data_offset,
    })
}

/// Compute the EAPOL-Key MIC (HMAC-SHA1 truncated to 16 bytes) over the
/// frame with the MIC field zeroed.
fn compute_mic(kck: &[u8; 16], frame: &[u8], mic_offset: usize) -> [u8; 16] {
    // The MIC offset is relative to the EAPOL frame: 4 (EAPOL hdr) + 77.
    // HMAC is streaming, but our helper is one-shot; build a small scratch
    // buffer instead (EAPOL frames are tiny).
    let mut buf = Vec::with_capacity(frame.len());
    buf.extend_from_slice(&frame[..mic_offset]);
    buf.extend_from_slice(&[0u8; 16]);
    buf.extend_from_slice(&frame[mic_offset + 16..]);
    let mac = hmac_sha1(kck, &buf);
    let mut out = [0u8; 16];
    out.copy_from_slice(&mac[..16]);
    out
}

#[derive(Clone, Copy)]
pub struct KeyMaterial {
    pub ptk: [u8; PTK_LEN],
    pub gtk: [u8; 32],
    pub gtk_len: usize,
    pub gtk_key_id: u8,
    pub installed: bool,
}

impl KeyMaterial {
    const fn empty() -> Self {
        Self {
            ptk: [0u8; PTK_LEN],
            gtk: [0u8; 32],
            gtk_len: 0,
            gtk_key_id: 0,
            installed: false,
        }
    }

    pub fn kck(&self) -> [u8; 16] {
        let mut k = [0u8; 16];
        k.copy_from_slice(&self.ptk[0..16]);
        k
    }

    pub fn kek(&self) -> [u8; 16] {
        let mut k = [0u8; 16];
        k.copy_from_slice(&self.ptk[16..32]);
        k
    }

    pub fn tk(&self) -> [u8; CCMP_KEY_LEN] {
        let mut k = [0u8; CCMP_KEY_LEN];
        k.copy_from_slice(&self.ptk[32..48]);
        k
    }
}

pub struct Wpa2Supplicant {
    pmk: [u8; PMK_LEN],
    sta: MacAddr,
    bssid: MacAddr,
    state: WpaState,
    anonce: [u8; 32],
    snonce: [u8; 32],
    last_replay: u64,
    keys: KeyMaterial,
    /// Association requires a fresh 4-way handshake.
    pub ready: bool,
}

impl Wpa2Supplicant {
    pub fn new(pmk: [u8; PMK_LEN], sta: MacAddr, bssid: MacAddr) -> Self {
        Self {
            pmk,
            sta,
            bssid,
            state: WpaState::Idle,
            anonce: [0; 32],
            snonce: [0; 32],
            last_replay: 0,
            keys: KeyMaterial::empty(),
            ready: false,
        }
    }

    pub fn state(&self) -> WpaState {
        self.state
    }

    pub fn keys(&self) -> &KeyMaterial {
        &self.keys
    }

    pub fn set_associated(&mut self) {
        if self.state == WpaState::Installed {
            self.state = WpaState::Idle;
            self.keys.installed = false;
            self.last_replay = 0;
        }
        self.ready = false;
    }

    /// Handle one received EAPOL-Key frame.
    ///
    /// `snonce` must be 32 random bytes supplied by the caller (the driver
    /// mixes TSC + hardware RNG).  Returns the frames to transmit, in order.
    pub fn handle_eapol(
        &mut self,
        frame: &[u8],
        snonce: &[u8; 32],
    ) -> Result<Vec<Vec<u8>>, WpaError> {
        let key = parse_eapol_key(frame)?;
        if key.key_info & KEY_INFO_ERROR != 0 {
            return Err(WpaError::UnexpectedMessage);
        }

        let mut out = Vec::new();
        if key.is_pairwise() {
            if key.key_info & KEY_INFO_ACK != 0 && !key.has_mic() {
                // Msg 1: derive PTK and answer with Msg 2.
                self.anonce = key.nonce;
                self.snonce = *snonce;
                self.keys.ptk = derive_ptk(
                    &self.pmk,
                    &self.sta,
                    &self.bssid,
                    &self.anonce,
                    &self.snonce,
                );
                self.last_replay = key.replay_counter;
                let kck = self.keys.kck();
                let msg2 = self.build_key_frame(
                    key.replay_counter,
                    &self.snonce,
                    KEY_INFO_VERSION_CCMP | KEY_INFO_PAIRWISE | KEY_INFO_MIC,
                    &kck,
                    &[],
                    false,
                );
                self.state = WpaState::WaitMsg4;
                out.push(msg2);
            } else if key.has_mic() && key.is_install() {
                // Msg 3: verify MIC, unwrap GTK, install keys.
                if self.state != WpaState::WaitMsg4 && self.state != WpaState::Installed {
                    return Err(WpaError::UnexpectedMessage);
                }
                if key.replay_counter <= self.last_replay && self.state == WpaState::WaitMsg4 {
                    return Err(WpaError::WrongReplay);
                }
                let mic_off = 4 + 77;
                let expect = compute_mic(&self.keys.kck(), frame, mic_off);
                if expect != key.mic {
                    return Err(WpaError::MicFailure);
                }
                if key.is_encrypted() {
                    let kek = self.keys.kek();
                    let wrapped =
                        &frame[key.key_data_offset..key.key_data_offset + key.key_data_len];
                    self.parse_group_key_data(&kek, wrapped, true)?;
                } else if key.key_data_len > 0 {
                    let data = &frame[key.key_data_offset..key.key_data_offset + key.key_data_len];
                    self.parse_group_key_data(&[0u8; 16], data, false)?;
                }
                self.keys.installed = true;
                self.last_replay = key.replay_counter;
                self.state = WpaState::Installed;
                self.ready = true;
                let kck = self.keys.kck();
                let msg4 = self.build_key_frame(
                    key.replay_counter,
                    &[0u8; 32],
                    KEY_INFO_VERSION_CCMP | KEY_INFO_PAIRWISE | KEY_INFO_MIC | KEY_INFO_SECURE,
                    &kck,
                    &[],
                    true,
                );
                out.push(msg4);
            } else {
                return Err(WpaError::UnexpectedMessage);
            }
        } else if key.has_mic() && key.is_secure() {
            // Group key handshake message 1 (pairwise bit clear).
            if self.state != WpaState::Installed {
                return Err(WpaError::UnexpectedMessage);
            }
            let mic_off = 4 + 77;
            if compute_mic(&self.keys.kck(), frame, mic_off) != key.mic {
                return Err(WpaError::MicFailure);
            }
            if key.is_encrypted() {
                let kek = self.keys.kek();
                let wrapped =
                    &frame[key.key_data_offset..key.key_data_offset + key.key_data_len];
                self.parse_group_key_data(&kek, wrapped, true)?;
            }
            let kck = self.keys.kck();
            let reply = self.build_key_frame(
                key.replay_counter,
                &[0u8; 32],
                KEY_INFO_VERSION_CCMP | KEY_INFO_MIC | KEY_INFO_SECURE,
                &kck,
                &[],
                true,
            );
            out.push(reply);
        } else {
            return Err(WpaError::UnexpectedMessage);
        }

        Ok(out)
    }

    fn parse_group_key_data(
        &mut self,
        kek: &[u8; 16],
        data: &[u8],
        encrypted: bool,
    ) -> Result<(), WpaError> {
        let decrypted;
        let data = if encrypted {
            let mut buf = [0u8; 256];
            let n = key_unwrap(kek, data, &mut buf).ok_or(WpaError::DecryptFailure)?;
            decrypted = buf;
            &decrypted[..n]
        } else {
            data
        };
        let mut pos = 0usize;
        while pos + 2 <= data.len() {
            let id = data[pos];
            let len = data[pos + 1] as usize;
            if pos + 2 + len > data.len() {
                break;
            }
            let body = &data[pos + 2..pos + 2 + len];
            if id == 0xdd && len >= 6 && body[..4] == [0x00, 0x0f, 0xac, 0x01] {
                // GTK KDE: OUI 00-0F-AC, type 1, key id, GTK.  `body` starts
                // after the KDE id/length bytes.
                let key_id = body[4] & 0x03;
                let gtk = &body[5..];
                if gtk.is_empty() || gtk.len() > 32 {
                    return Err(WpaError::Malformed);
                }
                self.keys.gtk = [0u8; 32];
                self.keys.gtk[..gtk.len()].copy_from_slice(gtk);
                self.keys.gtk_len = gtk.len();
                self.keys.gtk_key_id = key_id;
                self.keys.installed = true;
            }
            pos += 2 + len;
        }
        Ok(())
    }

    fn build_key_frame(
        &self,
        replay: u64,
        nonce: &[u8; 32],
        key_info: u16,
        kck: &[u8; 16],
        key_data: &[u8],
        with_mic: bool,
    ) -> Vec<u8> {
        let mut f = Vec::with_capacity(4 + KEY_FRAME_FIXED_LEN + key_data.len());
        f.push(EAPOL_VERSION_2004);
        f.push(EAPOL_TYPE_KEY);
        let body_len = (KEY_FRAME_FIXED_LEN + key_data.len()) as u16;
        f.extend_from_slice(&body_len.to_be_bytes());
        f.push(KEY_DESCRIPTOR_RSN);
        f.extend_from_slice(&key_info.to_be_bytes());
        f.extend_from_slice(&16u16.to_be_bytes()); // key length (CCMP=16)
        f.extend_from_slice(&replay.to_be_bytes());
        f.extend_from_slice(nonce);
        f.extend_from_slice(&[0u8; 16]); // key IV
        f.extend_from_slice(&[0u8; 8]); // key RSC
        f.extend_from_slice(&[0u8; 8]); // key ID
        f.extend_from_slice(&[0u8; 16]); // MIC placeholder
        f.extend_from_slice(&(key_data.len() as u16).to_be_bytes());
        f.extend_from_slice(key_data);

        if with_mic {
            let mic = compute_mic(kck, &f, 4 + 77);
            f[4 + 77..4 + 93].copy_from_slice(&mic);
        }
        f
    }
}

/// Build the RSN IE used in association (kept here so supplicant and MLME
/// cannot disagree on the negotiated cipher).
pub fn rsn_ie_wpa2_psk_ccmp() -> [u8; 22] {
    [
        0x30, 0x14, // EID 48, length 20
        0x01, 0x00, // version
        0x00, 0x0f, 0xac, 0x04, // group CCMP
        0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, // pairwise CCMP
        0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, // AKM PSK
        0x00, 0x00, // capabilities
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::derive_pmk;

    #[test]
    fn four_way_handshake_self_test() {
        let sta = [0x02, 0, 0, 0, 0, 0x01];
        let bssid = [0x02, 0, 0, 0, 0, 0x02];
        let pmk = derive_pmk(b"password", b"IEEE");
        let mut supp = Wpa2Supplicant::new(pmk, sta, bssid);

        let anonce = [0x11u8; 32];
        let snonce = [0x22u8; 32];
        // Build Msg1 as the AP would.
        let msg1 = build_msg1(anonce, 1);
        let out = supp.handle_eapol(&msg1, &snonce).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(supp.state(), WpaState::WaitMsg4);
        let msg2 = &out[0];
        let parsed2 = parse_eapol_key(msg2).unwrap();
        assert_eq!(parsed2.nonce, snonce);

        // Derive the AP side PTK and craft Msg3 with a GTK.
        let ap_ptk = derive_ptk(&pmk, &sta, &bssid, &anonce, &snonce);
        let mut ap_kck = [0u8; 16];
        ap_kck.copy_from_slice(&ap_ptk[0..16]);
        let mut ap_kek = [0u8; 16];
        ap_kek.copy_from_slice(&ap_ptk[16..32]);
        let gtk = [0x33u8; 16];
        let msg3 = build_msg3(anonce, 2, &ap_kck, &ap_kek, &gtk);
        let out = supp.handle_eapol(&msg3, &snonce).unwrap();
        assert_eq!(out.len(), 1, "STA must answer Msg4");
        assert_eq!(supp.state(), WpaState::Installed);
        assert!(supp.ready);
        assert_eq!(supp.keys().gtk[..16], gtk);
        assert_eq!(&supp.keys().tk()[..], &ap_ptk[32..48]);
    }

    fn build_msg1(anonce: [u8; 32], replay: u64) -> Vec<u8> {
        let mut f = Vec::new();
        f.push(EAPOL_VERSION_2004);
        f.push(EAPOL_TYPE_KEY);
        f.extend_from_slice(&(KEY_FRAME_FIXED_LEN as u16).to_be_bytes());
        f.push(KEY_DESCRIPTOR_RSN);
        f.extend_from_slice(
            &(KEY_INFO_VERSION_CCMP | KEY_INFO_PAIRWISE | KEY_INFO_ACK).to_be_bytes(),
        );
        f.extend_from_slice(&16u16.to_be_bytes());
        f.extend_from_slice(&replay.to_be_bytes());
        f.extend_from_slice(&anonce);
        f.extend_from_slice(&[0u8; 16 + 8 + 8 + 16]);
        f.extend_from_slice(&0u16.to_be_bytes());
        f
    }

    fn build_msg3(
        anonce: [u8; 32],
        replay: u64,
        kck: &[u8; 16],
        kek: &[u8; 16],
        gtk: &[u8; 16],
    ) -> Vec<u8> {
        // GTK KDE: DD 00 0F AC 01 <reserved|keyid> <gtk...>
        let mut kde = Vec::new();
        kde.push(0xdd);
        let body_len = 5 + gtk.len();
        kde.push(body_len as u8);
        kde.extend_from_slice(&[0x00, 0x0f, 0xac, 0x01]);
        kde.push(0x01); // key id 1
        kde.extend_from_slice(gtk);
        // AES key wrap requires a multiple of 8 bytes; the AP pads key data
        // with 0xdd bytes (802.11-2016, 12.7.6.4).
        while kde.len() % 8 != 0 {
            kde.push(0xdd);
        }
        let mut wrapped = [0u8; 64];
        let n = crate::crypto::aes::key_wrap(kek, &kde, &mut wrapped).unwrap();
        let key_data = &wrapped[..n];

        let mut f = Vec::new();
        f.push(EAPOL_VERSION_2004);
        f.push(EAPOL_TYPE_KEY);
        f.extend_from_slice(&((KEY_FRAME_FIXED_LEN + key_data.len()) as u16).to_be_bytes());
        f.push(KEY_DESCRIPTOR_RSN);
        let info = KEY_INFO_VERSION_CCMP
            | KEY_INFO_PAIRWISE
            | KEY_INFO_INSTALL
            | KEY_INFO_ACK
            | KEY_INFO_MIC
            | KEY_INFO_SECURE
            | KEY_INFO_ENCRYPTED;
        f.extend_from_slice(&info.to_be_bytes());
        f.extend_from_slice(&16u16.to_be_bytes());
        f.extend_from_slice(&replay.to_be_bytes());
        f.extend_from_slice(&anonce);
        f.extend_from_slice(&[0u8; 16 + 8 + 8]);
        f.extend_from_slice(&[0u8; 16]); // MIC placeholder
        f.extend_from_slice(&(key_data.len() as u16).to_be_bytes());
        f.extend_from_slice(key_data);
        let mic = compute_mic(kck, &f, 4 + 77);
        f[4 + 77..4 + 93].copy_from_slice(&mic);
        f
    }
}
