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

//! MediaTek MT79xx (MT7921/MT7961) firmware parsing.
//!
//! The blob starts with a 32-byte patch header, a 64-byte global descriptor,
//! then `section_num` 64-byte section maps.  Each section with a non-zero
//! `dlsize` is downloaded with WMT `PATCH_DWNLD` commands: first a 53-byte
//! section-resource command, then 250-byte data fragments (flags 1/2/3).
//!
//! Reference: Linux `btmtk_setup_firmware_79xx()`.

pub const PATCH_HEADER_SIZE: usize = 32;
pub const GLOBAL_DESC_SIZE: usize = 64;
pub const SECTION_MAP_SIZE: usize = 64;
pub const SECTION_MAPS_OFF: usize = PATCH_HEADER_SIZE + GLOBAL_DESC_SIZE;
pub const NEED_SEND_SIZE: usize = 52;
/// First WMT payload byte for a legacy section download.
pub const LEGACY_DL_MODE: u8 = 0;
/// Firmware bytes per WMT `PATCH_DWNLD` fragment.
pub const FRAG_LEN: usize = 250;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Section {
    pub index: usize,
    pub offset: usize,
    pub size: usize,
}

fn le32(data: &[u8], off: usize) -> Option<u32> {
    let bytes = data.get(off..off + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Number of sections described by the global descriptor.
pub fn section_count(fw: &[u8]) -> Option<usize> {
    // global_desc.section_num is the 4th u32 of the descriptor.
    le32(fw, PATCH_HEADER_SIZE + 12).map(|n| n as usize)
}

/// Returns section `index` (only the `secoffset` and `dlsize` fields).
pub fn section(fw: &[u8], index: usize) -> Option<Section> {
    let count = section_count(fw)?;
    if index >= count {
        return None;
    }
    let map = SECTION_MAPS_OFF.checked_add(index.checked_mul(SECTION_MAP_SIZE)?)?;
    let offset = le32(fw, map + 4)? as usize;
    let size = le32(fw, map + 16)? as usize; // bin_info_spec.dlsize
    if offset.checked_add(size)? > fw.len() {
        return None;
    }
    Some(Section {
        index,
        offset,
        size,
    })
}

/// Builds the 53-byte WMT section-resource payload:
/// `[0] || section_map[12..64]`.
pub fn section_header(fw: &[u8], index: usize, out: &mut [u8; NEED_SEND_SIZE + 1]) -> Option<()> {
    let count = section_count(fw)?;
    if index >= count {
        return None;
    }
    let map = SECTION_MAPS_OFF + index * SECTION_MAP_SIZE;
    let spec = fw.get(map + 12..map + 64)?;
    out[0] = LEGACY_DL_MODE;
    out[1..].copy_from_slice(spec);
    Some(())
}

/// Number of 250-byte fragments for a section.
pub fn fragment_count(size: usize) -> usize {
    size.div_ceil(FRAG_LEN)
}

/// Fragment `i` of a section and its WMT flag (1 first, 2 middle, 3 last).
pub fn fragment(fw: &[u8], s: Section, i: usize) -> Option<(u8, &[u8])> {
    let total = fragment_count(s.size);
    if i >= total {
        return None;
    }
    let start = i * FRAG_LEN;
    let len = core::cmp::min(FRAG_LEN, s.size - start);
    let data = fw.get(s.offset + start..s.offset + start + len)?;
    let flag = if total == 1 || i + 1 == total {
        3
    } else if i == 0 {
        1
    } else {
        2
    };
    Some((flag, data))
}

/// WMT `PATCH_DWNLD` status decoded from the event `flag` field (Linux
/// `btusb_mtk_hci_wmt_sync`): 1 = progress, 2 = done, else undone.
pub const PATCH_PROGRESS: u8 = 1;
pub const PATCH_DONE: u8 = 2;
pub const PATCH_UNDONE: u8 = 0;

#[cfg(test)]
mod tests {
    use super::*;

    const REAL: &str = "/lib/firmware/mediatek/BT_RAM_CODE_MT7961_1_2_hdr.bin";

    #[test]
    fn synthetic_header_and_section() {
        let mut fw = vec![0u8; 96 + 64 + 64 + 8];
        fw[32 + 12..32 + 16].copy_from_slice(&1u32.to_le_bytes());
        let map = 96;
        fw[map + 4..map + 8].copy_from_slice(&(96 + 128u32).to_le_bytes());
        fw[map + 16..map + 20].copy_from_slice(&8u32.to_le_bytes());
        let s = section(&fw, 0).unwrap();
        assert_eq!(s, Section { index: 0, offset: 224, size: 8 });
        assert!(section(&fw, 1).is_none());

        let mut hdr = [0xFFu8; 53];
        section_header(&fw, 0, &mut hdr).unwrap();
        assert_eq!(hdr[0], 0);
        assert_eq!(&hdr[1..], &fw[map + 12..map + 64]);
    }

    #[test]
    fn real_mt7961_blob() {
        let Ok(fw) = std::fs::read(REAL) else {
            return;
        };
        assert_eq!(section_count(&fw), Some(4));
        let s0 = section(&fw, 0).unwrap();
        assert_eq!(s0.size, 100160);
        assert_eq!(s0.offset, 352);
        let s1 = section(&fw, 1).unwrap();
        assert_eq!(s1.size, 432128);
        assert_eq!(s1.offset, 100512);
        assert_eq!(section(&fw, 2).unwrap().size, 0);

        let mut hdr = [0u8; 53];
        section_header(&fw, 0, &mut hdr).unwrap();
        assert_eq!(hdr[0], 0);

        assert_eq!(fragment_count(100160), 401); // 400 * 250 + 160
        let (flag, data) = fragment(&fw, s0, 0).unwrap();
        assert_eq!(flag, 1);
        assert_eq!(data.len(), 250);
        let (flag, data) = fragment(&fw, s0, 400).unwrap();
        assert_eq!(flag, 3);
        assert_eq!(data.len(), 160);
        let (flag, data) = fragment(&fw, s0, 1).unwrap();
        assert_eq!(flag, 2);
        assert_eq!(data.len(), 250);
    }
}
