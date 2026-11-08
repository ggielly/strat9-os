//! Firmware command builders for the 22000 (AX201) command ABI.
//!
//! Field layouts are transcribed from the Linux iwlwifi API headers
//! (`fw/api/mac.h`, `phy-ctxt.h`, `sta.h`, `scan.h`, `time-event.h`).  The
//! AX201 runs firmware API 77; command *versions* are therefore the ones used
//! by `iwlmvm` for `IWL_DEVICE_FAMILY_22000`.
//!
//! The builders return a flat payload without the 8-byte
//! `iwl_cmd_header_wide`; the transport prepends that header.

use alloc::vec::Vec;

use crate::dot11::MacAddr;

// Legacy command group/opcodes (`iwl_legacy_cmds`).
pub const GROUP_LEGACY: u8 = 0x00;
pub const CMD_ALIVE: u8 = 0x01;
pub const CMD_PHY_CONTEXT: u8 = 0x08;
pub const CMD_SCAN_REQ_UMAC: u8 = 0x0d;
pub const CMD_SCAN_ABORT_UMAC: u8 = 0x0e;
pub const CMD_ADD_STA_KEY: u8 = 0x17;
pub const CMD_ADD_STA: u8 = 0x18;
pub const CMD_MAC_CONTEXT: u8 = 0x28;
pub const CMD_TIME_EVENT: u8 = 0x29;
pub const CMD_POWER_TABLE: u8 = 0x77;
pub const CMD_REPLY_RX_MPDU: u8 = 0xc1;
pub const CMD_SCAN_COMPLETE_UMAC: u8 = 0x0f;
pub const CMD_SCAN_ITERATION_COMPLETE_UMAC: u8 = 0xb5;

// Command versions used by API 77.
pub const VER_PHY_CONTEXT: u8 = 3;
pub const VER_MAC_CONTEXT: u8 = 1;
pub const VER_ADD_STA: u8 = 10;
pub const VER_ADD_STA_KEY: u8 = 2;
pub const VER_TIME_EVENT: u8 = 2;
pub const VER_SCAN_REQ: u8 = 8;
pub const VER_POWER_TABLE: u8 = 4;

// Context actions (`iwl_ctxt_action`).
pub const CTXT_ACTION_ADD: u32 = 0;
pub const CTXT_ACTION_MODIFY: u32 = 1;
pub const CTXT_ACTION_REMOVE: u32 = 2;

// MAC types (`iwl_mac_types`).
pub const MAC_TYPE_BSS: u32 = 0; // STA / managed
pub const MAC_TYPE_IBSS: u32 = 1;
pub const MAC_TYPE_AP: u32 = 2;
pub const MAC_TYPE_P2P_CLIENT: u32 = 4;

// ID/color encoding (`iwl_ctxt_id_and_color`): id in bits 0..7, color in 8..15.
pub const fn id_and_color(id: u8, color: u8) -> u32 {
    id as u32 | ((color as u32) << 8)
}

// PHY bands / widths (`iwl_fw_channel_info`).
pub const PHY_BAND_2GHZ: u8 = 0;
pub const PHY_BAND_5GHZ: u8 = 1;
pub const PHY_WIDTH_20: u8 = 0;
pub const PHY_WIDTH_40: u8 = 1;
pub const PHY_WIDTH_80: u8 = 2;

pub const STA_MODE_ADD: u8 = 0;
pub const STA_MODE_MODIFY: u8 = 1;
pub const STA_FLAG_ASSOCIATED: u32 = 1 << 0;
pub const STA_FLAG_AUTHORIZED: u32 = 1 << 1;

pub const STA_KEY_FLG_CCM: u16 = 2;
pub const STA_KEY_FLG_KEYID_POS: u16 = 8;
pub const STA_KEY_MULTICAST: u16 = 1 << 14;

// scan general flags (`iwl_umac_scan_general_flags`).
pub const SCAN_FLAG_ACTIVE: u16 = 1 << 0;
pub const SCAN_FLAG_PASSIVE: u16 = 1 << 1;
pub const SCAN_FLAG_PASS_ALL: u16 = 1 << 2;
pub const SCAN_FLAG_FILTER_SSID: u16 = 1 << 3;
pub const SCAN_FLAG_DEVELOPER: u16 = 1 << 15;

// time event actions (`iwl_time_event_apply_type`).
pub const TIME_EVENT_ADD: u32 = 0;
pub const TIME_EVENT_MODIFY: u32 = 1;
pub const TIME_EVENT_REMOVE: u32 = 2;

fn put_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// `struct iwl_phy_context_cmd` (32 bytes for API v3..v7).
pub fn phy_context(
    id_color: u32,
    action: u32,
    channel: u8,
    band: u8,
    width: u8,
) -> Vec<u8> {
    let mut b = alloc::vec![0u8; 32];
    put_u32(&mut b, 0, id_color);
    put_u32(&mut b, 4, action);
    // iwl_fw_channel_info: channel u32, band u8, width u8, ctrl u8, rsv u8
    put_u32(&mut b, 8, channel as u32);
    b[12] = band;
    b[13] = width;
    b[14] = 0;
    b[15] = 0;
    put_u32(&mut b, 16, 0); // lmac_id
    put_u32(&mut b, 20, 0); // rxchain_info
    put_u32(&mut b, 24, 0); // dsp_cfg_flags
    b
}

/// `struct iwl_mac_ctx_cmd` in station mode.
///
/// The union is sized for `iwl_mac_data_sta`; `assoc`/`aid`/`bi` are only
/// meaningful after association.  The command is padded to the layout used by
/// iwlmvm (union max size is larger than the station member).
pub fn mac_context_sta(
    id_color: u32,
    action: u32,
    node: MacAddr,
    bssid: MacAddr,
    assoc: bool,
    aid: u16,
    beacon_interval: u16,
    dtim_period: u8,
) -> Vec<u8> {
    const LEN: usize = 156;
    let mut b = alloc::vec![0u8; LEN];
    put_u32(&mut b, 0, id_color);
    put_u32(&mut b, 4, action);
    put_u32(&mut b, 8, MAC_TYPE_BSS);
    put_u32(&mut b, 12, 0); // tsf_id
    b[16..22].copy_from_slice(&node);
    b[24..30].copy_from_slice(&bssid);
    // Basic rates: 1,2,5.5,11 (CCK) and 6,12,24 (OFDM) as bit masks.
    put_u32(&mut b, 32, 0x0000_000f);
    put_u32(&mut b, 36, 0x0000_0015);
    // Filter flags: accept all management/data in station mode.
    put_u32(&mut b, 52, 0x0000_0000);
    // QoS defaults.
    put_u32(&mut b, 56, 0);
    // iwl_ac_qos ac[5]: cw_min, cw_max, aifsn, fifos_mask, txop
    let ac = [(0x000f, 0x03ff, 2u8), (0x000f, 0x03ff, 2), (0x000f, 0x03ff, 2), (0x000f, 0x03ff, 2), (0x0003, 0x0007, 2)];
    for (i, (cwmin, cwmax, aifsn)) in ac.iter().enumerate() {
        let off = 60 + i * 8;
        put_u16(&mut b, off, *cwmin);
        put_u16(&mut b, off + 2, *cwmax);
        b[off + 4] = *aifsn;
        b[off + 5] = 0;
        put_u16(&mut b, off + 6, 0);
    }
    // iwl_mac_data_sta at offset 100.
    let s = 100;
    put_u32(&mut b, s, assoc as u32);
    put_u32(&mut b, s + 4, 0);
    put_u64(&mut b, s + 8, 0);
    put_u32(&mut b, s + 16, beacon_interval as u32);
    put_u32(&mut b, s + 20, 0);
    put_u32(&mut b, s + 24, dtim_period as u32);
    put_u32(&mut b, s + 28, 0);
    put_u32(&mut b, s + 32, 0);
    put_u32(&mut b, s + 36, aid as u32);
    put_u32(&mut b, s + 40, 0);
    b
}

/// `struct iwl_mvm_add_sta_cmd` (API v10, 48 bytes).
pub fn add_sta(
    sta_id: u8,
    mac_id_color: u32,
    addr: MacAddr,
    assoc_id: u16,
    tfd_queue_msk: u32,
    station_flags: u32,
) -> Vec<u8> {
    let mut b = alloc::vec![0u8; 48];
    b[0] = STA_MODE_ADD;
    b[1] = 0;
    put_u16(&mut b, 2, 0);
    put_u32(&mut b, 4, mac_id_color);
    b[8..14].copy_from_slice(&addr);
    b[16] = sta_id;
    b[17] = 0;
    put_u32(&mut b, 20, station_flags);
    put_u32(&mut b, 24, 0xffff_ffff);
    put_u32(&mut b, 40, tfd_queue_msk);
    put_u16(&mut b, 36, assoc_id | 0x0000);
    b[38] = 0; // station_type = LINK
    b
}

/// Modify an existing station (same layout as `add_sta`, mode = modify).
pub fn add_sta_modify(
    sta_id: u8,
    mac_id_color: u32,
    addr: MacAddr,
    assoc_id: u16,
    tfd_queue_msk: u32,
    station_flags: u32,
) -> Vec<u8> {
    let mut b = add_sta(sta_id, mac_id_color, addr, assoc_id, tfd_queue_msk, station_flags);
    b[0] = STA_MODE_MODIFY;
    // Select which fields are updated: station queues (BIT(7)).
    b[17] = 0x80;
    b
}

/// `struct iwl_mvm_add_sta_key_cmd` (v2/v3) for CCMP.
pub fn add_sta_key(sta_id: u8, key_offset: u8, key: &[u8; 16], key_id: u8, multicast: bool) -> Vec<u8> {
    let mut b = alloc::vec![0u8; 76];
    b[0] = sta_id;
    b[1] = key_offset;
    let mut flags = STA_KEY_FLG_CCM
        | (1 << 3) // STA_KEY_FLG_WEP_KEY_MAP
        | ((key_id as u16 & 0x3) << STA_KEY_FLG_KEYID_POS);
    if multicast {
        flags |= STA_KEY_MULTICAST;
    }
    put_u16(&mut b, 2, flags);
    b[4..20].copy_from_slice(key);
    b
}

/// `struct iwl_scan_req_umac` v8 skeleton with an explicit channel list.
///
/// `channels` is a list of `(channel, band, active)`; the function appends the
/// simple `iwl_scan_channel_cfg_umac` array directly after the fixed header,
/// which is the layout expected when no probe-request template is supplied.
pub fn scan_request(
    channels: &[(u8, u8, bool)],
    ssid: Option<&[u8]>,
    bssid: Option<MacAddr>,
    uid: u32,
) -> Vec<u8> {
    // v8 fixed part: 4+4+4+2+1+1 + 2*2 dwell + 2 + 4*2 maxout + 4*2 suspend
    // + 4 priority + 2 passage + 2 fragments + 4 chan param = 56 bytes.
    let mut b = alloc::vec![0u8; 56];
    put_u32(&mut b, 0, 0);
    put_u32(&mut b, 4, uid);
    put_u32(&mut b, 8, 0);
    let mut general = 0u16;
    if ssid.is_some() {
        general |= SCAN_FLAG_FILTER_SSID | SCAN_FLAG_PASS_ALL;
    }
    if bssid.is_some() {
        general |= SCAN_FLAG_PASS_ALL;
    }
    put_u16(&mut b, 12, general);
    b[14] = 0;
    b[15] = 0;
    // v8 dwell fields.
    b[16] = 10; // active dwell (TU)
    b[17] = 0;
    b[18] = 10;
    b[19] = 10;
    b[20] = 0;
    put_u16(&mut b, 21, 0);
    put_u32(&mut b, 24, 0); // max_out_time[0]
    put_u32(&mut b, 28, 0); // max_out_time[1]
    put_u32(&mut b, 32, 0); // suspend_time[0]
    put_u32(&mut b, 36, 0); // suspend_time[1]
    put_u32(&mut b, 40, 0); // scan_priority
    b[44] = 0; // passive_dwell[0]
    b[45] = 0;
    b[46] = 1; // num_of_fragments[0]
    b[47] = 1;
    // iwl_scan_umac_chan_param: flags u8, count u8, reserved u16
    b[48] = 0;
    b[49] = channels.len() as u8;
    put_u16(&mut b, 50, 0);
    // Channel config array (8 bytes per channel).
    for (ch, band, active) in channels {
        let mut c = [0u8; 8];
        let flags = if *active { 0u32 } else { 0u32 };
        put_u32(&mut c, 0, flags | ((*band as u32) << 30));
        c[4] = *ch;
        c[5] = *band;
        c[6] = 1; // iteration count
        c[7] = 0; // iteration interval
        b.extend_from_slice(&c);
    }
    // Directed SSID / BSSID TLVs (type/length/data), as used by iwlmvm.
    if let Some(ssid) = ssid {
        b.extend_from_slice(&[0x00, ssid.len().min(32) as u8]);
        b.extend_from_slice(&ssid[..ssid.len().min(32)]);
    }
    if let Some(bssid) = bssid {
        b.extend_from_slice(&[0x01, 6]);
        b.extend_from_slice(&bssid);
    }
    b
}

pub fn scan_abort(uid: u32) -> Vec<u8> {
    let mut b = alloc::vec![0u8; 8];
    put_u32(&mut b, 0, uid);
    put_u32(&mut b, 4, 0);
    b
}

/// `struct iwl_time_event_cmd` minimal add/modify request.
pub fn time_event(
    id_and_color: u32,
    action: u32,
    id: u32,
    apply_time: u32,
    max_delay: u32,
    duration: u32,
    interval: u32,
) -> Vec<u8> {
    let mut b = alloc::vec![0u8; 40];
    put_u32(&mut b, 0, id_and_color);
    put_u32(&mut b, 4, action);
    put_u32(&mut b, 8, id);
    put_u32(&mut b, 12, apply_time);
    put_u32(&mut b, 16, max_delay);
    put_u32(&mut b, 20, duration);
    put_u32(&mut b, 24, interval);
    put_u32(&mut b, 28, 0);
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_context_field_offsets() {
        let b = mac_context_sta(
            id_and_color(1, 1),
            CTXT_ACTION_ADD,
            [0x02, 0, 0, 0, 0, 1],
            [0x02, 0, 0, 0, 0, 2],
            true,
            0x1234,
            100,
            2,
        );
        assert_eq!(b.len(), 156);
        assert_eq!(&b[16..22], &[0x02, 0, 0, 0, 0, 1]);
        assert_eq!(&b[24..30], &[0x02, 0, 0, 0, 0, 2]);
        assert_eq!(&b[100..104], &1u32.to_le_bytes());
        assert_eq!(&b[136..140], &0x1234u32.to_le_bytes());
    }

    #[test]
    fn add_sta_is_48_bytes() {
        let b = add_sta(2, id_and_color(1, 1), [1; 6], 0x0100, 0x2, STA_FLAG_ASSOCIATED);
        assert_eq!(b.len(), 48);
        assert_eq!(&b[8..14], &[1u8; 6]);
        assert_eq!(b[16], 2);
    }

    #[test]
    fn scan_request_channel_count() {
        let b = scan_request(&[(1, 0, true), (6, 0, true), (36, 1, false)], None, None, 1);
        assert_eq!(b[49], 3);
        assert_eq!(b.len(), 56 + 3 * 8);
    }
}
