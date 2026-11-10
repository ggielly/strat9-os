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

//! s9vm — guest boot information page.
//!
//! A world starts with a guest that must be told what its machine looks like:
//! which memory ranges are usable, which virtual devices exist, where their
//! MMIO pages are and which interrupt lines they use. Firmware (ACPI) is the
//! long-term answer for a full operating system; this page is the direct,
//! minimal interface for s9vm's own guests and for early bring-up.
//!
//! The layout is a fixed 512-byte little-endian structure with a magic, a
//! version, bounds-checked counts and a fixed number of slots, so it can be
//! parsed by a guest without allocating and cannot describe itself outside
//! the page. Encoding and decoding live here as pure code and are host-tested;
//! the kernel only computes the contents and copies them into guest memory.

/// Magic value: the ASCII bytes `S9VMBOOT` read as a little-endian `u64`.
pub const MAGIC: u64 = 0x544F_4F42_4D56_3953;
/// Layout version.
pub const VERSION: u32 = 1;
/// Total size of the page.
pub const SIZE: usize = 512;
/// Maximum number of memory ranges described.
pub const MAX_MEMORY_ENTRIES: usize = 16;
/// Maximum number of devices described.
pub const MAX_DEVICE_ENTRIES: usize = 4;

/// Kind of a memory range.
pub mod memory_kind {
    /// Usable guest RAM.
    pub const RAM: u32 = 1;
    /// Reserved (firmware, holes).
    pub const RESERVED: u32 = 2;
    /// Device MMIO window.
    pub const MMIO: u32 = 3;
}

/// Kind of a device.
pub mod device_kind {
    /// Console (virtio-mmio transport).
    pub const CONSOLE: u32 = 1;
    /// Block device (virtio-mmio transport).
    pub const BLOCK: u32 = 2;
    /// Network device (virtio-mmio transport).
    pub const NETWORK: u32 = 3;
}

/// Flags.
pub mod flags {
    /// The page is complete and the guest may boot.
    pub const COMPLETE: u32 = 1;
    /// A console device is present.
    pub const HAS_CONSOLE: u32 = 2;
    /// A block device is present.
    pub const HAS_BLOCK: u32 = 4;
    /// A network device is present.
    pub const HAS_NETWORK: u32 = 8;
}

/// One memory range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryEntry {
    /// Guest-physical base address.
    pub base: u64,
    /// Length in bytes.
    pub len: u64,
    /// [`memory_kind`] value.
    pub kind: u32,
}

/// One device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceEntry {
    /// [`device_kind`] value.
    pub kind: u32,
    /// Interrupt line in the I/O APIC.
    pub irq_line: u32,
    /// Guest-physical address of the MMIO transport page.
    pub mmio_base: u64,
    /// Device-specific value: block capacity in sectors, MAC for network.
    pub config: u64,
}

/// Decoding error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootInfoError {
    /// The magic value does not match.
    BadMagic,
    /// The layout version is not supported.
    BadVersion,
    /// The structure size field does not match [`SIZE`].
    BadSize,
    /// A count exceeds its slot array.
    TooManyEntries,
    /// The input slice is smaller than [`SIZE`].
    Truncated,
}

/// Boot information page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootInfo {
    /// [`flags`] bits.
    pub flags: u32,
    /// Memory ranges.
    pub memory: [MemoryEntry; MAX_MEMORY_ENTRIES],
    /// Number of valid memory ranges.
    pub memory_count: u8,
    /// Devices.
    pub devices: [DeviceEntry; MAX_DEVICE_ENTRIES],
    /// Number of valid devices.
    pub device_count: u8,
}

impl BootInfo {
    /// Empty page.
    pub const fn new() -> Self {
        Self {
            flags: 0,
            memory: [MemoryEntry {
                base: 0,
                len: 0,
                kind: 0,
            }; MAX_MEMORY_ENTRIES],
            memory_count: 0,
            devices: [DeviceEntry {
                kind: 0,
                irq_line: 0,
                mmio_base: 0,
                config: 0,
            }; MAX_DEVICE_ENTRIES],
            device_count: 0,
        }
    }

    /// Adds a memory range. Returns false when the slot array is full.
    pub fn add_memory(&mut self, base: u64, len: u64, kind: u32) -> bool {
        let index = self.memory_count as usize;
        if index >= MAX_MEMORY_ENTRIES {
            return false;
        }
        self.memory[index] = MemoryEntry { base, len, kind };
        self.memory_count += 1;
        true
    }

    /// Adds a device. Returns false when the slot array is full.
    pub fn add_device(&mut self, kind: u32, irq_line: u32, mmio_base: u64, config: u64) -> bool {
        let index = self.device_count as usize;
        if index >= MAX_DEVICE_ENTRIES {
            return false;
        }
        self.devices[index] = DeviceEntry {
            kind,
            irq_line,
            mmio_base,
            config,
        };
        self.device_count += 1;
        true
    }

    /// Encodes the page into `out`.
    pub fn encode(&self, out: &mut [u8; SIZE]) {
        out.fill(0);
        put_u64(out, 0x000, MAGIC);
        put_u32(out, 0x008, VERSION);
        put_u32(out, 0x00C, SIZE as u32);
        put_u32(out, 0x010, self.flags);
        put_u32(out, 0x014, u32::from(self.memory_count));
        put_u32(out, 0x018, u32::from(self.device_count));
        let memory_base = 0x020;
        for (index, entry) in self.memory[..usize::from(self.memory_count)].iter().enumerate() {
            let offset = memory_base + index * 24;
            put_u64(out, offset, entry.base);
            put_u64(out, offset + 8, entry.len);
            put_u32(out, offset + 16, entry.kind);
        }
        let device_base = memory_base + MAX_MEMORY_ENTRIES * 24;
        for (index, entry) in self.devices[..usize::from(self.device_count)].iter().enumerate() {
            let offset = device_base + index * 24;
            put_u32(out, offset, entry.kind);
            put_u32(out, offset + 4, entry.irq_line);
            put_u64(out, offset + 8, entry.mmio_base);
            put_u64(out, offset + 16, entry.config);
        }
    }

    /// Decodes a page.
    pub fn decode(bytes: &[u8]) -> Result<Self, BootInfoError> {
        if bytes.len() < SIZE {
            return Err(BootInfoError::Truncated);
        }
        if get_u64(bytes, 0x000) != MAGIC {
            return Err(BootInfoError::BadMagic);
        }
        if get_u32(bytes, 0x008) != VERSION {
            return Err(BootInfoError::BadVersion);
        }
        if get_u32(bytes, 0x00C) as usize != SIZE {
            return Err(BootInfoError::BadSize);
        }
        let mut info = Self::new();
        info.flags = get_u32(bytes, 0x010);
        let memory_count = get_u32(bytes, 0x014) as usize;
        let device_count = get_u32(bytes, 0x018) as usize;
        if memory_count > MAX_MEMORY_ENTRIES || device_count > MAX_DEVICE_ENTRIES {
            return Err(BootInfoError::TooManyEntries);
        }
        let memory_base = 0x020;
        for index in 0..memory_count {
            let offset = memory_base + index * 24;
            info.memory[index] = MemoryEntry {
                base: get_u64(bytes, offset),
                len: get_u64(bytes, offset + 8),
                kind: get_u32(bytes, offset + 16),
            };
        }
        info.memory_count = memory_count as u8;
        let device_base = memory_base + MAX_MEMORY_ENTRIES * 24;
        for index in 0..device_count {
            let offset = device_base + index * 24;
            info.devices[index] = DeviceEntry {
                kind: get_u32(bytes, offset),
                irq_line: get_u32(bytes, offset + 4),
                mmio_base: get_u64(bytes, offset + 8),
                config: get_u64(bytes, offset + 16),
            };
        }
        info.device_count = device_count as u8;
        Ok(info)
    }
}

impl Default for BootInfo {
    fn default() -> Self {
        Self::new()
    }
}

/// Writes a little-endian `u32` at `offset`.
fn put_u32(out: &mut [u8; SIZE], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// Writes a little-endian `u64` at `offset`.
fn put_u64(out: &mut [u8; SIZE], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

/// Reads a little-endian `u32` at `offset`.
fn get_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

/// Reads a little-endian `u64` at `offset`.
fn get_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}
