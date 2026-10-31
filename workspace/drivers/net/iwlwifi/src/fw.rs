//! Intel iwlwifi TLV firmware image parser.
//!
//! The AX201 firmware (`iwlwifi-QuZ-a0-hr-b0-77.ucode`) uses the TLV container
//! described by `struct iwl_tlv_ucode_header` / `struct iwl_ucode_tlv` in
//! Linux `drivers/net/wireless/intel/iwlwifi/fw/file.h`:
//!
//! ```text
//! u32 zero; u32 magic (0x0a4c5749); u8 human[64];
//! u32 ver; u32 build; u64 ignore;
//! repeat: u32 type; u32 len; u8 data[len]; pad to 4
//! ```
//!
//! Sections of interest are `IWL_UCODE_TLV_SEC_RT` (19) and
//! `IWL_UCODE_TLV_SEC_INIT` (20).  Each section TLV starts with a 32-bit
//! destination offset followed by the payload.  The special offsets
//! `0xFFFFCCCC` / `0xAAAABBBB` delimit LMAC/UMAC/paging images and carry no
//! payload.

use alloc::vec::Vec;

use crate::regs;

pub const HEADER_LEN: usize = 88;
pub const TLV_HEADER_LEN: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FwError {
    TooShort,
    BadMagic,
    TruncatedTlv,
    NoSections,
    BadSection,
    UnsupportedApi { found: u8, expected: u8 },
}

#[derive(Debug, Clone, Copy)]
pub struct FwSection<'a> {
    /// Destination address inside device memory.
    pub dest: u32,
    /// Section payload (may be empty for separators).
    pub data: &'a [u8],
}

impl FwSection<'_> {
    pub fn is_separator(&self) -> bool {
        self.dest == regs::CPU1_CPU2_SEPARATOR_SECTION
            || self.dest == regs::PAGING_SEPARATOR_SECTION
    }
}

#[derive(Debug)]
pub struct UcodeImage<'a> {
    pub version: u32,
    pub build: u32,
    pub api: u8,
    pub serial: u8,
    pub human_readable_len: usize,
    pub human_readable: [u8; 64],
    /// Runtime image (SEC_RT), including separators.
    pub runtime: Vec<FwSection<'a>>,
    /// Initialization image (SEC_INIT), including separators.
    pub init: Vec<FwSection<'a>>,
    /// Paging image (SEC_RT_USNIFFER / IWL_UCODE_TLV_PAGING if present).
    pub paging: Vec<FwSection<'a>>,
    pub num_cpus: u8,
}

impl UcodeImage<'_> {
    pub fn runtime_payload_bytes(&self) -> usize {
        self.runtime.iter().map(|s| s.data.len()).sum()
    }

    /// Split the runtime image into `(lmac, umac, paging)` for the context
    /// info DRAM map.  LMAC comes first, then the CPU separator, then UMAC,
    /// then the paging separator.
    pub fn split_context_sections(
        &self,
    ) -> (Vec<FwSection<'_>>, Vec<FwSection<'_>>, Vec<FwSection<'_>>) {
        let mut lmac = Vec::new();
        let mut umac = Vec::new();
        let mut paging = Vec::new();
        let mut stage = 0u8;
        for section in &self.runtime {
            if section.dest == regs::CPU1_CPU2_SEPARATOR_SECTION {
                stage = 1;
                continue;
            }
            if section.dest == regs::PAGING_SEPARATOR_SECTION {
                stage = 2;
                continue;
            }
            match stage {
                0 => lmac.push(*section),
                1 => umac.push(*section),
                _ => paging.push(*section),
            }
        }
        // Fallback: some firmware files use a single stage with no separators.
        if lmac.is_empty() && !self.runtime.is_empty() {
            lmac = self
                .runtime
                .iter()
                .copied()
                .filter(|s| !s.is_separator())
                .collect();
        }
        (lmac, umac, paging)
    }
}

fn le32(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Parse a TLV ucode image.
pub fn parse_tlv<'a>(raw: &'a [u8]) -> Result<UcodeImage<'a>, FwError> {
    if raw.len() < HEADER_LEN {
        return Err(FwError::TooShort);
    }
    // First dword must be zero (distinguishes TLV from the legacy v1/v2
    // header), followed by the magic.
    if le32(raw, 0) != Some(0) {
        return Err(FwError::UnsupportedApi {
            found: 0,
            expected: regs::AX201_UCODE_API as u8,
        });
    }
    if le32(raw, 4) != Some(regs::IWL_UCODE_TLV_MAGIC) {
        return Err(FwError::BadMagic);
    }
    let version = le32(raw, 72).ok_or(FwError::TooShort)?;
    let build = le32(raw, 76).ok_or(FwError::TooShort)?;
    let api = ((version >> 8) & 0xff) as u8;
    let serial = (version & 0xff) as u8;

    if api != regs::AX201_UCODE_API as u8 {
        return Err(FwError::UnsupportedApi {
            found: api,
            expected: regs::AX201_UCODE_API as u8,
        });
    }

    let mut human_readable = [0u8; 64];
    human_readable.copy_from_slice(&raw[8..72]);
    let human_readable_len = human_readable
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(human_readable.len());

    let mut runtime = Vec::new();
    let mut init = Vec::new();
    let mut paging = Vec::new();
    let mut num_cpus = 1u8;

    let mut pos = HEADER_LEN;
    while pos + TLV_HEADER_LEN <= raw.len() {
        let ty = le32(raw, pos).ok_or(FwError::TruncatedTlv)?;
        let len = le32(raw, pos + 4).ok_or(FwError::TruncatedTlv)? as usize;
        let data_start = pos + TLV_HEADER_LEN;
        let data_end = data_start.checked_add(len).ok_or(FwError::TruncatedTlv)?;
        if data_end > raw.len() {
            return Err(FwError::TruncatedTlv);
        }
        let data = &raw[data_start..data_end];
        match ty {
            regs::IWL_UCODE_TLV_SEC_RT | regs::IWL_UCODE_TLV_SEC_RT_USNIFFER => {
                if let Some(sec) = parse_section(data)? {
                    runtime.push(sec);
                }
            }
            regs::IWL_UCODE_TLV_SEC_INIT => {
                if let Some(sec) = parse_section(data)? {
                    init.push(sec);
                }
            }
            regs::IWL_UCODE_TLV_PAGING => {
                if let Some(sec) = parse_section(data)? {
                    paging.push(sec);
                }
            }
            27 => {
                if let Some(v) = le32(data, 0) {
                    num_cpus = v.min(2) as u8;
                }
            }
            _ => {}
        }
        // TLVs are padded to a 4-byte boundary.
        pos = data_start + ((len + 3) & !3);
    }

    if runtime.is_empty() {
        return Err(FwError::NoSections);
    }

    Ok(UcodeImage {
        version,
        build,
        api,
        serial,
        human_readable_len,
        human_readable,
        runtime,
        init,
        paging,
        num_cpus,
    })
}

fn parse_section(data: &[u8]) -> Result<Option<FwSection<'_>>, FwError> {
    if data.len() < 4 {
        return Err(FwError::BadSection);
    }
    let dest = le32(data, 0).unwrap();
    // Separators have no payload.
    if dest == regs::CPU1_CPU2_SEPARATOR_SECTION || dest == regs::PAGING_SEPARATOR_SECTION {
        return Ok(Some(FwSection {
            dest,
            data: &[],
        }));
    }
    Ok(Some(FwSection {
        dest,
        data: &data[4..],
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_tlv(ty: u32, payload: &[u8]) -> alloc::vec::Vec<u8> {
        let mut v = alloc::vec::Vec::new();
        v.extend_from_slice(&ty.to_le_bytes());
        v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        v.extend_from_slice(payload);
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v
    }

    fn sample_firmware() -> alloc::vec::Vec<u8> {
        let mut fw = alloc::vec::Vec::new();
        fw.extend_from_slice(&0u32.to_le_bytes());
        fw.extend_from_slice(&regs::IWL_UCODE_TLV_MAGIC.to_le_bytes());
        fw.extend_from_slice(&[0u8; 64]);
        fw.extend_from_slice(&(77u32 << 8).to_le_bytes());
        fw.extend_from_slice(&1234u32.to_le_bytes());
        fw.extend_from_slice(&[0u8; 8]);

        let mut sec = alloc::vec::Vec::new();
        sec.extend_from_slice(&0x1000u32.to_le_bytes());
        sec.extend_from_slice(&[1, 2, 3, 4]);
        fw.extend_from_slice(&build_tlv(19, &sec));

        // Separator: dest only.
        let sep = 0xffff_ccccu32.to_le_bytes();
        fw.extend_from_slice(&build_tlv(19, &sep));

        let mut sec2 = alloc::vec::Vec::new();
        sec2.extend_from_slice(&0x2000u32.to_le_bytes());
        sec2.extend_from_slice(&[9, 9, 9, 9]);
        fw.extend_from_slice(&build_tlv(19, &sec2));
        fw
    }

    #[test]
    fn parses_sections_and_separator() {
        let fw = sample_firmware();
        let img = parse_tlv(&fw).unwrap();
        assert_eq!(img.api, 77);
        assert_eq!(img.build, 1234);
        assert_eq!(img.runtime.len(), 3);
        let (lmac, umac, paging) = img.split_context_sections();
        assert_eq!(lmac.len(), 1);
        assert_eq!(umac.len(), 1);
        assert!(paging.is_empty());
        assert_eq!(lmac[0].data, &[1, 2, 3, 4]);
        assert_eq!(umac[0].data, &[9, 9, 9, 9]);
    }

    #[test]
    fn rejects_wrong_magic() {
        let mut fw = sample_firmware();
        fw[4] = 0;
        assert_eq!(parse_tlv(&fw).unwrap_err(), FwError::BadMagic);
    }

    #[test]
    fn rejects_truncated_tlv() {
        let mut fw = sample_firmware();
        fw.truncate(HEADER_LEN + 10);
        assert!(matches!(
            parse_tlv(&fw),
            Err(FwError::TruncatedTlv) | Err(FwError::NoSections)
        ));
    }
}
