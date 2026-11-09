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

//! Realtek RTL8761BU firmware handling (v1 "Realtech" epatch format).
//!
//! The controller enumerates as a ROM bootloader: it answers HCI commands but
//! will not advertise until the RAM patch has been downloaded with the vendor
//! command `0xFC20`.  This module parses the Linux `rtl8761bu_fw.bin` blob and
//! produces the exact byte stream Linux' `btrtl_download_firmware()` sends.
//!
//! No allocation: the caller provides the input blob, the config blob and the
//! output buffer.

/// Payload bytes per `0xFC20` fragment (Linux `RTL_FRAG_LEN`).
pub const RTL_FRAG_LEN: usize = 252;

/// Vendor command opcodes.
pub const OP_READ_REG16: u16 = 0xFC61;
pub const OP_READ_ROM_VERSION: u16 = 0xFC6D;
pub const OP_DOWNLOAD: u16 = 0xFC20;

/// `RTL_CHIP_SUBVER`: read the chip's LMP subversion (0xFC61 argument).
pub const CHIP_SUBVER_ARG: [u8; 5] = [0x10, 0x38, 0x04, 0x28, 0x80];

/// Firmware version expected after a successful RTL8761BU download.
pub const RTL_ROM_LMP_8761A: u16 = 0x8761;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtlError {
    TooShort,
    BadSignature,
    UnsupportedV2,
    NoPatch(u16),
    PatchOutOfRange,
    BufferTooSmall,
}

/// Metadata of the selected patch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PatchInfo {
    pub chip_id: u16,
    pub fw_version: u32,
    pub patch_len: usize,
    /// `patch_len + config.len()`: bytes to download.
    pub total_len: usize,
}

fn le16(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([data[off], data[off + 1]])
}

fn le32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

/// Parses a v1 epatch blob and builds `patch || config` into `out`.
///
/// `rom_version` is the value returned by `0xFC6D`; the matching chip id is
/// `rom_version + 1` (Linux `chip_id == btrtl_dev->rom_version + 1`).
pub fn build_patch(
    fw: &[u8],
    rom_version: u8,
    config: &[u8],
    out: &mut [u8],
) -> Result<PatchInfo, RtlError> {
    const HDR: usize = 14; // signature[8] + fw_version u32 + num_patches u16
    if fw.len() < HDR {
        return Err(RtlError::TooShort);
    }
    match &fw[..8] {
        b"Realtech" => {}
        b"RTBTCore" => return Err(RtlError::UnsupportedV2),
        _ => return Err(RtlError::BadSignature),
    }

    let fw_version = le32(fw, 8);
    let num = le16(fw, 12) as usize;
    if num == 0 {
        return Err(RtlError::NoPatch(0));
    }
    let ids = HDR;
    let lens = ids + 2 * num;
    let offs = lens + 2 * num;
    if offs + 4 * num > fw.len() {
        return Err(RtlError::TooShort);
    }

    let chip_id = rom_version as u16 + 1;
    let mut found = None;
    for i in 0..num {
        if le16(fw, ids + 2 * i) == chip_id {
            found = Some(i);
            break;
        }
    }
    let i = found.ok_or(RtlError::NoPatch(chip_id))?;

    let patch_len = le16(fw, lens + 2 * i) as usize;
    let patch_off = le32(fw, offs + 4 * i) as usize;
    if patch_len < 4 || patch_off + patch_len > fw.len() {
        return Err(RtlError::PatchOutOfRange);
    }
    let total_len = patch_len + config.len();
    if out.len() < total_len {
        return Err(RtlError::BufferTooSmall);
    }

    // Linux copies `patch_len - 4` bytes, then overwrites the trailing 4 bytes
    // with the patch header's fw_version, then appends the config blob.
    out[..patch_len - 4].copy_from_slice(&fw[patch_off..patch_off + patch_len - 4]);
    out[patch_len - 4..patch_len].copy_from_slice(&fw_version.to_le_bytes());
    out[patch_len..total_len].copy_from_slice(config);

    Ok(PatchInfo {
        chip_id,
        fw_version,
        patch_len,
        total_len,
    })
}

/// Number of `0xFC20` fragments Linux would send (including a final short one).
pub fn fragment_count(fw_len: usize) -> usize {
    fw_len / RTL_FRAG_LEN + 1
}

/// Linux fragment index sequence: 0..=0x7f, then 1..=0x7f again.
fn fragment_index(i: usize) -> u8 {
    if i < 0x80 {
        i as u8
    } else {
        1 + ((i - 0x80) % 0x7f) as u8
    }
}

/// Builds one `0xFC20` command payload: `[index][data]`.
///
/// The final fragment has bit 0x80 set on the index.
pub fn fragment(fw: &[u8], i: usize, out: &mut [u8]) -> Option<usize> {
    let count = fragment_count(fw.len());
    if i >= count {
        return None;
    }
    let last = i + 1 == count;
    let off = i * RTL_FRAG_LEN;
    let n = if last {
        fw.len() % RTL_FRAG_LEN
    } else {
        RTL_FRAG_LEN
    };
    if off + n > fw.len() || out.len() < 1 + n {
        return None;
    }
    let mut index = fragment_index(i);
    if last {
        index |= 0x80;
    }
    out[0] = index;
    out[1..1 + n].copy_from_slice(&fw[off..off + n]);
    Some(1 + n)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal v1 blob: two patches, chip ids 1 and 2.
    fn synthetic() -> (Vec<u8>, Vec<u8>) {
        let fw_version: u32 = 0x1122_3344;
        let p1 = [0xAAu8; 8];
        let p2 = [0xBBu8; 12];
        let mut fw = Vec::new();
        fw.extend_from_slice(b"Realtech");
        fw.extend_from_slice(&fw_version.to_le_bytes());
        fw.extend_from_slice(&2u16.to_le_bytes());
        fw.extend_from_slice(&1u16.to_le_bytes()); // chip id 1
        fw.extend_from_slice(&2u16.to_le_bytes()); // chip id 2
        fw.extend_from_slice(&(p1.len() as u16).to_le_bytes());
        fw.extend_from_slice(&(p2.len() as u16).to_le_bytes());
        let off1 = 14 + 2 * 2 + 2 * 2 + 4 * 2;
        let off2 = off1 + p1.len();
        fw.extend_from_slice(&(off1 as u32).to_le_bytes());
        fw.extend_from_slice(&(off2 as u32).to_le_bytes());
        fw.extend_from_slice(&p1);
        fw.extend_from_slice(&p2);
        (fw, vec![0x55, 0xAB, 0x23, 0x87, 0, 0])
    }

    #[test]
    fn selects_chip_and_appends_config() {
        let (fw, cfg) = synthetic();
        let mut out = [0u8; 32];
        let info = build_patch(&fw, 1, &cfg, &mut out).unwrap();
        assert_eq!(info.chip_id, 2);
        assert_eq!(info.patch_len, 12);
        assert_eq!(info.total_len, 18);
        assert_eq!(&out[..8], &[0xBB; 8]);
        assert_eq!(&out[8..12], &0x1122_3344u32.to_le_bytes());
        assert_eq!(&out[12..18], &cfg);
    }

    #[test]
    fn missing_chip_is_reported() {
        let (fw, cfg) = synthetic();
        let mut out = [0u8; 32];
        assert_eq!(build_patch(&fw, 7, &cfg, &mut out), Err(RtlError::NoPatch(8)));
    }

    #[test]
    fn short_output_and_bad_signature() {
        let (fw, cfg) = synthetic();
        let mut small = [0u8; 10];
        assert_eq!(
            build_patch(&fw, 1, &cfg, &mut small),
            Err(RtlError::BufferTooSmall)
        );
        let mut bad = fw.clone();
        bad[0] = b'X';
        let mut out = [0u8; 32];
        assert_eq!(build_patch(&bad, 1, &cfg, &mut out), Err(RtlError::BadSignature));
    }

    #[test]
    fn fragment_indices_match_linux() {
        assert_eq!(fragment_index(0), 0);
        assert_eq!(fragment_index(0x7e), 0x7e);
        assert_eq!(fragment_index(0x7f), 0x7f);
        assert_eq!(fragment_index(0x80), 1);
        assert_eq!(fragment_index(0x80 + 0x7e), 0x7f);
    }

    #[test]
    fn last_fragment_is_short_and_flagged() {
        let fw = [0x5Au8; RTL_FRAG_LEN * 2 + 10];
        assert_eq!(fragment_count(fw.len()), 3);
        let mut out = [0u8; RTL_FRAG_LEN + 1];
        assert_eq!(fragment(&fw, 0, &mut out), Some(1 + RTL_FRAG_LEN));
        assert_eq!(out[0], 0);
        assert_eq!(fragment(&fw, 2, &mut out), Some(11));
        assert_eq!(out[0], 2 | 0x80);
        assert_eq!(&out[1..11], &[0x5A; 10]);
    }

    #[test]
    fn exact_multiple_gets_empty_last_fragment() {
        let fw = [0u8; RTL_FRAG_LEN];
        assert_eq!(fragment_count(fw.len()), 2);
        let mut out = [0u8; RTL_FRAG_LEN + 1];
        assert_eq!(fragment(&fw, 1, &mut out), Some(1));
        assert_eq!(out[0], 1 | 0x80);
    }

    /// Optional real-blob check: only runs when linux-firmware is installed.
    #[test]
    fn real_rtl8761bu_blob() {
        let Ok(fw) = std::fs::read("/lib/firmware/rtl_bt/rtl8761bu_fw.bin") else {
            return;
        };
        let Ok(cfg) = std::fs::read("/lib/firmware/rtl_bt/rtl8761bu_config.bin") else {
            return;
        };
        let mut out = vec![0u8; 64 * 1024];
        let info = build_patch(&fw, 1, &cfg, &mut out).unwrap();
        assert_eq!(info.chip_id, 2);
        assert_eq!(info.fw_version, 0xDFC6_D922);
        assert_eq!(info.total_len, 30210);
        assert_eq!(&out[info.patch_len..info.total_len], &cfg[..]);
        assert_eq!(fragment_count(info.total_len), 120);
        let mut frag = [0u8; RTL_FRAG_LEN + 1];
        let n = fragment(&out[..info.total_len], 119, &mut frag).unwrap();
        assert_eq!(n, 1 + 30210 % RTL_FRAG_LEN);
        assert_eq!(frag[0], 119 | 0x80);
    }
}
