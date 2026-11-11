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

//! Guest-side ACPI discovery over a byte window (pure, host-testable).
//!
//! The engine writes the firmware description tables inside the legacy window
//! `0x000E_0000..0x0010_0000`. This module validates and walks them from a
//! plain byte slice, so the exact algorithm the guest runs can be unit-tested
//! on the host against the kernel's [`AcpiBuilder`] output:
//!
//! 1. scan the 16-byte aligned candidates for the `RSD PTR ` signature and
//!    validate the ACPI 1.0 checksum over the first 20 bytes;
//! 2. follow the XSDT (ACPI 2.0+ revision) or the RSDT v1 view;
//! 3. validate every table header (signature, declared length inside the
//!    window, byte checksum) before dereferencing the next pointer.
//!
//! Every rejection is a typed [`AcpiError`]; the slice is never indexed out of
//! bounds. The module knows nothing about paging or MMIO: the caller passes a
//! slice of the ACPI window at [`WINDOW_BASE`].

/// Guest-physical base of the ACPI window the engine writes.
pub const WINDOW_BASE: u64 = 0x000E_0000;
/// Length of the window the guest maps for ACPI discovery.
pub const WINDOW_LEN: usize = 0x0002_0000;

/// `RSD PTR ` signature (8 bytes).
const RSDP_SIGNATURE: &[u8; 8] = b"RSD PTR ";
/// XSDT signature.
const XSDT_SIGNATURE: &[u8; 4] = b"XSDT";
/// RSDT signature.
const RSDT_SIGNATURE: &[u8; 4] = b"RSDT";
/// Length of the ACPI 1.0 checksum range of the RSDP.
const RSDP_V1_LEN: usize = 20;
/// Offset of the RSDP revision byte.
const RSDP_REVISION_OFF: usize = 15;
/// Offset of the 32-bit RSDT pointer.
const RSDP_RSDT_OFF: usize = 16;
/// Offset of the 64-bit XSDT pointer (ACPI 2.0+).
const RSDP_XSDT_OFF: usize = 24;
/// Length of a standard ACPI table header.
const SDT_HEADER_LEN: usize = 36;
/// Maximum number of root-table entries walked (safety bound).
const MAX_TABLES: usize = 16;

/// Reasons why the ACPI window could not be validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcpiError {
    /// No `RSD PTR ` with a valid ACPI 1.0 checksum was found.
    NoRsdp = 1,
    /// The discovered RSDP is too small for the field the walk needs.
    TruncatedRsdp = 2,
    /// The root table pointer is zero or outside the window.
    BadRoot = 3,
    /// The root table signature is not `XSDT`/`RSDT`.
    BadRootSignature = 4,
    /// The root table header/length/checksum is invalid.
    BadRootTable = 5,
    /// A table listed by the root table has an invalid header/checksum.
    BadTable = 6,
}

impl AcpiError {
    /// Stable diagnostic code published on the debug port after `s`.
    pub const fn code(self) -> u8 {
        self as u8
    }
}

/// Summary of the discovered ACPI tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcpiInfo {
    /// Number of root-table entries whose target header validated.
    pub tables: u32,
    /// A MADT (`APIC`) table was found and validated.
    pub madt: bool,
    /// A FADT (`FACP`) table was found and validated.
    pub fadt: bool,
    /// The root table was the 64-bit XSDT (ACPI 2.0+).
    pub xsdt: bool,
}

/// Scans `window` for the RSDP and returns its offset inside the window.
///
/// `window` must start at [`WINDOW_BASE`]. Candidates are 16-byte aligned and
/// the ACPI 1.0 checksum over the first 20 bytes must be zero.
pub fn find_rsdp(window: &[u8]) -> Option<usize> {
    let mut offset = 0usize;
    while offset + RSDP_V1_LEN <= window.len() {
        if &window[offset..offset + 8] == RSDP_SIGNATURE
            && checksum(&window[offset..offset + RSDP_V1_LEN]) == 0
        {
            return Some(offset);
        }
        offset += 16;
    }
    None
}

/// Discovers and validates the ACPI tables in `window`.
///
/// The engine emits both an XSDT and a legacy RSDT v1 view; the walk follows
/// the XSDT first (revision 2 RSDP) and falls back to the RSDT when the XSDT
/// is unusable, merging the facts of whichever roots validate. A window where
/// neither root validates is rejected with the first root error.
pub fn scan(window: &[u8]) -> Result<AcpiInfo, AcpiError> {
    let rsdp = find_rsdp(window).ok_or(AcpiError::NoRsdp)?;
    if rsdp + RSDP_XSDT_OFF + 8 > window.len() {
        return Err(AcpiError::TruncatedRsdp);
    }
    let revision = window[rsdp + RSDP_REVISION_OFF];
    let rsdt = u64::from(read_u32(window, rsdp + RSDP_RSDT_OFF));
    let xsdt = if revision >= 2 {
        read_u64(window, rsdp + RSDP_XSDT_OFF)
    } else {
        0
    };
    let mut info = AcpiInfo {
        tables: 0,
        madt: false,
        fadt: false,
        xsdt: false,
    };
    let mut first_error = None;
    let mut any = false;
    for (address, entry_size, is_xsdt) in [(xsdt, 8usize, true), (rsdt, 4usize, false)] {
        if address == 0 {
            continue;
        }
        match scan_root(window, address, entry_size, is_xsdt) {
            Ok(root) => {
                any = true;
                info.tables = info.tables.max(root.tables);
                info.madt |= root.madt;
                info.fadt |= root.fadt;
                info.xsdt |= root.xsdt;
            }
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
    }
    if any {
        Ok(info)
    } else {
        Err(first_error.unwrap_or(AcpiError::BadRoot))
    }
}

/// Walks one root table (XSDT or RSDT) and validates every listed table.
fn scan_root(
    window: &[u8],
    address: u64,
    entry_size: usize,
    xsdt: bool,
) -> Result<AcpiInfo, AcpiError> {
    let root = root_offset(window, address)?;
    let root_len = table_len(window, root).ok_or(AcpiError::BadRootTable)?;
    let expected: &[u8; 4] = if xsdt { XSDT_SIGNATURE } else { RSDT_SIGNATURE };
    if &window[root..root + 4] != expected {
        return Err(AcpiError::BadRootSignature);
    }
    let entries = (root_len - SDT_HEADER_LEN) / entry_size;
    let limit = entries.min(MAX_TABLES);
    let mut info = AcpiInfo {
        tables: 0,
        madt: false,
        fadt: false,
        xsdt,
    };
    let mut index = 0usize;
    while index < limit {
        let entry = root + SDT_HEADER_LEN + index * entry_size;
        let address = if xsdt {
            read_u64(window, entry)
        } else {
            u64::from(read_u32(window, entry))
        };
        if address != 0 {
            let table = root_offset(window, address)?;
            table_len(window, table).ok_or(AcpiError::BadTable)?;
            if &window[table..table + 4] == b"APIC" {
                info.madt = true;
            }
            if &window[table..table + 4] == b"FACP" {
                info.fadt = true;
            }
            info.tables += 1;
        }
        index += 1;
    }
    Ok(info)
}

/// Converts an absolute ACPI address inside the window to a slice offset.
fn root_offset(window: &[u8], address: u64) -> Result<usize, AcpiError> {
    let offset = address.checked_sub(WINDOW_BASE).ok_or(AcpiError::BadRoot)?;
    let offset = usize::try_from(offset).map_err(|_| AcpiError::BadRoot)?;
    if offset + SDT_HEADER_LEN > window.len() {
        return Err(AcpiError::BadRoot);
    }
    Ok(offset)
}

/// Validates a table header at `offset` and returns its declared length.
fn table_len(window: &[u8], offset: usize) -> Option<usize> {
    if offset + SDT_HEADER_LEN > window.len() {
        return None;
    }
    let length = read_u32(window, offset + 4) as usize;
    if length < SDT_HEADER_LEN || offset + length > window.len() {
        return None;
    }
    if checksum(&window[offset..offset + length]) != 0 {
        return None;
    }
    Some(length)
}

/// Byte sum modulo 256 over `bytes`.
fn checksum(bytes: &[u8]) -> u8 {
    let mut sum = 0u8;
    for byte in bytes {
        sum = sum.wrapping_add(*byte);
    }
    sum
}

/// Reads a little-endian `u32` (callers guarantee the range is in bounds).
fn read_u32(window: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        window[offset],
        window[offset + 1],
        window[offset + 2],
        window[offset + 3],
    ])
}

/// Reads a little-endian `u64` (callers guarantee the range is in bounds).
fn read_u64(window: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&window[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}
