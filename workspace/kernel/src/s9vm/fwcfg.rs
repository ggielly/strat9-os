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

//! QEMU `fw_cfg` firmware-configuration interface (legacy I/O port mode).
//!
//! SeaBIOS in QEMU mode discovers the machine through `fw_cfg` instead of
//! probing every chipset register. The interface is two ports: a 16-bit
//! selector and an 8-bit data port whose reads advance a cursor. The file
//! directory (selector `0x19`) lists named blobs; SeaBIOS registers each one
//! as a `romfile`.
//!
//! s9vm uses it for one purpose: serving the **SeaVGABIOS option ROM** under
//! `vgaroms/vgabios-stdvga.bin`. SeaBIOS clears the `0xC0000` option-ROM window
//! during POST and deploys the ROMs it finds through `fw_cfg`, so a
//! pre-installed ROM would be wiped; a `fw_cfg` file is the QEMU-compatible
//! way to hand it over.
//!
//! The legacy entries SeaBIOS reads unconditionally (NUMA/ACPI/SMBIOS
//! counts, CPU counts, boot-menu flags) are populated with zero counts; a
//! value of `0xFF` for those would make its parser loop over garbage.

use alloc::{vec, vec::Vec};

/// Selector port (16-bit write, little-endian).
pub const CTL_PORT: u16 = 0x510;
/// Data port (8-bit reads/writes, cursor advances on read).
pub const DATA_PORT: u16 = 0x511;

/// `QEMU_CFG_SIGNATURE`.
pub const SIGNATURE: u16 = 0x00;
/// `QEMU_CFG_ID`.
pub const ID: u16 = 0x01;
/// `QEMU_CFG_UUID`.
pub const UUID: u16 = 0x02;
/// `QEMU_CFG_NOGRAPHIC`.
pub const NOGRAPHIC: u16 = 0x04;
/// `QEMU_CFG_NB_CPUS`.
pub const NB_CPUS: u16 = 0x05;
/// `QEMU_CFG_NUMA`.
pub const NUMA: u16 = 0x0D;
/// `QEMU_CFG_BOOT_MENU`.
pub const BOOT_MENU: u16 = 0x0E;
/// `QEMU_CFG_MAX_CPUS`.
pub const MAX_CPUS: u16 = 0x0F;
/// `QEMU_CFG_FILE_DIR`.
pub const FILE_DIR: u16 = 0x19;
/// `QEMU_CFG_ACPI_TABLES` (arch-local).
pub const ACPI_TABLES: u16 = 0x8000;
/// `QEMU_CFG_SMBIOS_ENTRIES` (arch-local).
pub const SMBIOS_ENTRIES: u16 = 0x8001;
/// `QEMU_CFG_IRQ0_OVERRIDE` (arch-local).
pub const IRQ0_OVERRIDE: u16 = 0x8002;

/// First selector assigned to a user file.
pub const FIRST_FILE_SELECT: u16 = 0x20;
/// Length of one file-directory entry.
const DIRECTORY_ENTRY_LEN: usize = 64;
/// Maximum file name carried by the directory.
const MAX_NAME_LEN: usize = 56;

/// True if `port` belongs to the `fw_cfg` interface.
pub const fn handles_port(port: u16) -> bool {
    port == CTL_PORT || port == DATA_PORT
}

/// One named blob exposed through the file directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FwCfgFile {
    /// Name reported to the guest (`vgaroms/...`, `etc/...`).
    pub name: Vec<u8>,
    /// Selector that returns the blob.
    pub select: u16,
    /// Blob content.
    pub data: Vec<u8>,
}

/// `fw_cfg` interface state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FwCfg {
    selector: u16,
    cursor: usize,
    files: Vec<FwCfgFile>,
    legacy: Vec<(u16, Vec<u8>)>,
    directory_bytes: Vec<u8>,
}

impl FwCfg {
    /// Creates the interface with the legacy entries SeaBIOS reads.
    pub fn new() -> Self {
        let legacy = vec![
            (SIGNATURE, b"QEMU".to_vec()),
            (ID, 0u32.to_le_bytes().to_vec()),
            (UUID, vec![0u8; 16]),
            (NOGRAPHIC, 0u16.to_le_bytes().to_vec()),
            (NB_CPUS, 1u16.to_le_bytes().to_vec()),
            (NUMA, 0u64.to_le_bytes().to_vec()),
            (BOOT_MENU, 0u16.to_le_bytes().to_vec()),
            (MAX_CPUS, 1u16.to_le_bytes().to_vec()),
            (ACPI_TABLES, 0u16.to_le_bytes().to_vec()),
            (SMBIOS_ENTRIES, 0u16.to_le_bytes().to_vec()),
            (IRQ0_OVERRIDE, 0u8.to_le_bytes().to_vec()),
        ];
        let mut cfg = Self {
            selector: 0,
            cursor: 0,
            files: Vec::new(),
            legacy,
            directory_bytes: Vec::new(),
        };
        cfg.directory_bytes = cfg.directory();
        cfg
    }

    /// Adds a named file and returns the selector assigned to it.
    pub fn add_file(&mut self, name: &str, data: &[u8]) -> u16 {
        let select = FIRST_FILE_SELECT + self.files.len() as u16;
        self.files.push(FwCfgFile {
            name: name.as_bytes().to_vec(),
            select,
            data: data.to_vec(),
        });
        self.directory_bytes = self.directory();
        select
    }

    /// Selects one entry and resets the data cursor.
    pub fn select(&mut self, selector: u16) {
        self.selector = selector;
        self.cursor = 0;
    }

    /// Current selector (diagnostics).
    pub const fn selector(&self) -> u16 {
        self.selector
    }

    /// Reads the next data byte and advances the cursor.
    ///
    /// An unknown selector, or a read past the end of the selected blob,
    /// returns `0xFF` like an absent device.
    pub fn read_byte(&mut self) -> u8 {
        let value = if self.selector == FILE_DIR {
            self.directory_bytes
                .get(self.cursor)
                .copied()
                .unwrap_or(0xFF)
        } else if let Some((_, data)) = self.legacy.iter().find(|(key, _)| *key == self.selector) {
            data.get(self.cursor).copied().unwrap_or(0xFF)
        } else if let Some(file) = self.files.iter().find(|file| file.select == self.selector) {
            file.data.get(self.cursor).copied().unwrap_or(0xFF)
        } else {
            0xFF
        };
        self.cursor = self.cursor.saturating_add(1);
        value
    }

    /// Writes the data port: the interface is read-only for the guest.
    pub fn write_byte(&mut self, _value: u8) {}

    /// Builds the `QEMU_CFG_FILE_DIR` payload.
    pub fn directory(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.files.len() * DIRECTORY_ENTRY_LEN);
        out.extend_from_slice(&(self.files.len() as u32).to_be_bytes());
        for file in &self.files {
            out.extend_from_slice(&(file.data.len() as u32).to_be_bytes());
            out.extend_from_slice(&file.select.to_be_bytes());
            out.extend_from_slice(&0u16.to_be_bytes());
            let mut name = [0u8; MAX_NAME_LEN];
            let len = file.name.len().min(MAX_NAME_LEN);
            name[..len].copy_from_slice(&file.name[..len]);
            out.extend_from_slice(&name);
        }
        out
    }
}

impl Default for FwCfg {
    fn default() -> Self {
        Self::new()
    }
}
