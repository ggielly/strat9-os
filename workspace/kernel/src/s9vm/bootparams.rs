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

//! s9vm — guest boot parameters (firmware hand-off block).
//!
//! [`bootinfo`](crate::s9vm::bootinfo) is the compact s9vm-specific boot page.
//! A real operating-system guest needs a richer hand-off: the physical memory
//! map, the kernel command line, initrd/module ranges, console and device
//! hints, and the `RSDP` pointer of the firmware tables built by
//! [`acpi`](crate::s9vm::acpi). This module defines that block.
//!
//! The block has a fixed 1024-byte little-endian layout with a magic, a
//! version, counts, a byte checksum (all the bytes of the block sum to zero
//! modulo 256) and fixed-capacity arrays. Encoding and decoding are pure code
//! and allocate nothing, so the kernel fills a stack buffer and copies it into
//! guest memory, and a guest can validate the block with a single linear sum.
//!
//! # Layout
//!
//! | Offset | Size | Field |
//! |---|---|---|
//! | `0x000` | 8 | magic `S9VMBP\0\0` (little-endian `u64`) |
//! | `0x008` | 4 | version ([`VERSION`]) |
//! | `0x00C` | 4 | block size ([`SIZE`]) |
//! | `0x010` | 4 | boot [`flags`] |
//! | `0x014` | 4 | memory entry count (`<= 32`) |
//! | `0x018` | 4 | module count (`<= 4`) |
//! | `0x01C` | 4 | command-line length (`<= 256`) |
//! | `0x020` | 8 | ACPI RSDP guest-physical address (0 = absent) |
//! | `0x028` | 8 | console MMIO base (virtio-mmio transport page) |
//! | `0x030` | 4 | console I/O APIC line |
//! | `0x034` | 1 | checksum |
//! | `0x035` | 3 | reserved, zero |
//! | `0x038` | 640 | memory map: 32 entries of 20 packed bytes |
//! | `0x2B8` | 64 | modules: 4 entries of 16 packed bytes |
//! | `0x2F8` | 256 | command line, NUL padded |
//! | `0x3F8` | 8 | reserved, zero |
//!
//! A memory entry is `base: u64`, `len: u64`, `kind: u32`; a module entry is
//! `base: u64`, `len: u64`. Entries and the entry count are the only source of
//! truth: unused trailing bytes are zero and must be ignored by readers.
//!
//! The command line is **not** NUL-terminated: its length is authoritative and
//! the remaining bytes of the 256-byte field are NUL padding, so a
//! 256-byte command line uses the whole field with no terminator.
//!
//! # Invariants
//!
//! - the magic, the version and the size match this module;
//! - the checksum of the whole block is zero;
//! - `memory_count <= MAX_MEMORY_ENTRIES`, `module_count <= MAX_MODULE_ENTRIES`
//!   and `cmdline_len <= CMDLINE_MAX`;
//! - every memory entry uses one of the [`memory_kind`] values;
//! - every flag set in [`BootParams::flags`] belongs to [`flags`].
//!
//! This module is pure `core` code and is host-tested by `s9vm-tests`.

/// Magic value: the ASCII bytes `S9VMBP` followed by two NUL bytes, read as a
/// little-endian `u64`.
pub const MAGIC: u64 = 0x0000_5042_4D56_3953;
/// Layout version.
pub const VERSION: u32 = 1;
/// Total size of the block, in bytes.
pub const SIZE: usize = 1024;
/// Maximum number of memory map entries.
pub const MAX_MEMORY_ENTRIES: usize = 32;
/// Maximum number of initrd/module entries.
pub const MAX_MODULE_ENTRIES: usize = 4;
/// Maximum length of the inline kernel command line, in bytes.
pub const CMDLINE_MAX: usize = 256;

/// Offset of the magic field.
pub const OFF_MAGIC: usize = 0x000;
/// Offset of the version field.
pub const OFF_VERSION: usize = 0x008;
/// Offset of the block size field.
pub const OFF_SIZE: usize = 0x00C;
/// Offset of the boot flags field.
pub const OFF_FLAGS: usize = 0x010;
/// Offset of the memory entry count field.
pub const OFF_MEMORY_COUNT: usize = 0x014;
/// Offset of the module count field.
pub const OFF_MODULE_COUNT: usize = 0x018;
/// Offset of the command-line length field.
pub const OFF_CMDLINE_LEN: usize = 0x01C;
/// Offset of the ACPI RSDP address field.
pub const OFF_RSDP_GPA: usize = 0x020;
/// Offset of the console MMIO base field.
pub const OFF_CONSOLE_MMIO: usize = 0x028;
/// Offset of the console I/O APIC line field.
pub const OFF_CONSOLE_IRQ: usize = 0x030;
/// Offset of the checksum byte.
pub const OFF_CHECKSUM: usize = 0x034;

/// Offset of the memory map, packed entries of [`MEMORY_ENTRY_SIZE`] bytes.
pub const MEMORY_OFFSET: usize = 0x038;
/// Wire size of one memory map entry: `base: u64`, `len: u64`, `kind: u32`.
pub const MEMORY_ENTRY_SIZE: usize = 20;
/// Offset of the module table, packed entries of [`MODULE_ENTRY_SIZE`] bytes.
pub const MODULE_OFFSET: usize = MEMORY_OFFSET + MAX_MEMORY_ENTRIES * MEMORY_ENTRY_SIZE;
/// Wire size of one module entry: `base: u64`, `len: u64`.
pub const MODULE_ENTRY_SIZE: usize = 16;
/// Offset of the inline command line.
pub const CMDLINE_OFFSET: usize = MODULE_OFFSET + MAX_MODULE_ENTRIES * MODULE_ENTRY_SIZE;

// The wire layout is part of the ABI: fail the build if the constants drift.
const _: () = assert!(MEMORY_OFFSET + MAX_MEMORY_ENTRIES * MEMORY_ENTRY_SIZE == MODULE_OFFSET);
const _: () = assert!(MODULE_OFFSET + MAX_MODULE_ENTRIES * MODULE_ENTRY_SIZE == CMDLINE_OFFSET);
const _: () = assert!(CMDLINE_OFFSET + CMDLINE_MAX <= SIZE);
const _: () = assert!(SIZE == 1024);

/// Kind of a memory map entry.
pub mod memory_kind {
    /// Guest RAM usable by the guest kernel.
    pub const USABLE: u32 = 1;
    /// Reserved by the machine (holes, firmware structures).
    pub const RESERVED: u32 = 2;
    /// ACPI reclaimable memory (firmware tables, reclaimable after parsing).
    pub const ACPI_RECLAIMABLE: u32 = 3;
    /// Device MMIO window, not ordinary RAM.
    pub const MMIO: u32 = 4;
    /// Every defined kind.
    pub const ALL: [u32; 4] = [USABLE, RESERVED, ACPI_RECLAIMABLE, MMIO];

    /// True when `kind` is one of the defined memory kinds.
    pub const fn is_valid(kind: u32) -> bool {
        kind >= USABLE && kind <= MMIO
    }
}

/// Boot flags.
pub mod flags {
    /// A console device is described by the console fields.
    pub const CONSOLE_PRESENT: u32 = 1 << 0;
    /// A block device is present (described by the firmware tables).
    pub const BLOCK_PRESENT: u32 = 1 << 1;
    /// A network device is present (described by the firmware tables).
    pub const NETWORK_PRESENT: u32 = 1 << 2;
    /// Every defined boot flag.
    pub const ALL: u32 = CONSOLE_PRESENT | BLOCK_PRESENT | NETWORK_PRESENT;
}

/// One memory map entry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemoryEntry {
    /// Guest-physical base address.
    pub base: u64,
    /// Length in bytes (non-zero for a usable entry).
    pub len: u64,
    /// [`memory_kind`] value.
    pub kind: u32,
}

/// One initrd/module entry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ModuleEntry {
    /// Guest-physical base address.
    pub base: u64,
    /// Length in bytes.
    pub len: u64,
}

/// Decoding and construction errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootParamsError {
    /// The input slice is smaller than [`SIZE`].
    Truncated,
    /// The magic value does not match [`MAGIC`].
    BadMagic,
    /// The layout version is not [`VERSION`].
    BadVersion,
    /// The encoded size field is not [`SIZE`].
    BadSize,
    /// The byte sum of the block is not zero.
    BadChecksum,
    /// The memory entry count exceeds [`MAX_MEMORY_ENTRIES`].
    TooManyMemoryEntries,
    /// The module count exceeds [`MAX_MODULE_ENTRIES`].
    TooManyModules,
    /// The command-line length exceeds [`CMDLINE_MAX`].
    CmdlineTooLong,
    /// A memory entry uses an undefined [`memory_kind`] value.
    BadMemoryKind,
    /// A flag bit outside [`flags::ALL`] is set.
    BadFlags,
}

/// Guest boot parameters block.
///
/// The fields are private: the block is built through the validating
/// [`BootParams::add_memory`], [`BootParams::add_module`],
/// [`BootParams::set_cmdline`], [`BootParams::set_console`] and
/// [`BootParams::set_flags`] methods, so an encoded block always satisfies the
/// invariants documented at module level. [`BootParams::decode`] re-checks
/// them on hostile input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootParams {
    flags: u32,
    rsdp_gpa: u64,
    console_mmio_base: u64,
    console_irq_line: u32,
    memory: [MemoryEntry; MAX_MEMORY_ENTRIES],
    memory_count: u8,
    modules: [ModuleEntry; MAX_MODULE_ENTRIES],
    module_count: u8,
    cmdline: [u8; CMDLINE_MAX],
    cmdline_len: u16,
}

impl BootParams {
    /// Empty block: no memory entry, no module, empty command line, all
    /// addresses zero and no flag.
    pub fn new() -> Self {
        Self {
            flags: 0,
            rsdp_gpa: 0,
            console_mmio_base: 0,
            console_irq_line: 0,
            memory: [MemoryEntry::default(); MAX_MEMORY_ENTRIES],
            memory_count: 0,
            modules: [ModuleEntry::default(); MAX_MODULE_ENTRIES],
            module_count: 0,
            cmdline: [0u8; CMDLINE_MAX],
            cmdline_len: 0,
        }
    }

    /// Boot [`flags`] bits.
    pub const fn flags(&self) -> u32 {
        self.flags
    }

    /// ACPI RSDP guest-physical address (0 when the firmware tables are
    /// absent).
    pub const fn rsdp_gpa(&self) -> u64 {
        self.rsdp_gpa
    }

    /// Console MMIO base address.
    pub const fn console_mmio_base(&self) -> u64 {
        self.console_mmio_base
    }

    /// Console I/O APIC line.
    pub const fn console_irq_line(&self) -> u32 {
        self.console_irq_line
    }

    /// Memory map entries, in insertion order.
    pub fn memory(&self) -> &[MemoryEntry] {
        &self.memory[..usize::from(self.memory_count)]
    }

    /// Number of memory map entries.
    pub const fn memory_count(&self) -> usize {
        self.memory_count as usize
    }

    /// Initrd/module entries, in insertion order.
    pub fn modules(&self) -> &[ModuleEntry] {
        &self.modules[..usize::from(self.module_count)]
    }

    /// Number of initrd/module entries.
    pub const fn module_count(&self) -> usize {
        self.module_count as usize
    }

    /// Kernel command line bytes (never NUL-terminated, possibly empty).
    pub fn cmdline(&self) -> &[u8] {
        &self.cmdline[..usize::from(self.cmdline_len)]
    }

    /// Length of the kernel command line, in bytes.
    pub const fn cmdline_len(&self) -> usize {
        self.cmdline_len as usize
    }

    /// Appends one memory map entry.
    ///
    /// Fails with [`BootParamsError::BadMemoryKind`] for an undefined kind and
    /// with [`BootParamsError::TooManyMemoryEntries`] once
    /// [`MAX_MEMORY_ENTRIES`] entries are present.
    pub fn add_memory(&mut self, base: u64, len: u64, kind: u32) -> Result<(), BootParamsError> {
        if !memory_kind::is_valid(kind) {
            return Err(BootParamsError::BadMemoryKind);
        }
        let index = usize::from(self.memory_count);
        if index >= MAX_MEMORY_ENTRIES {
            return Err(BootParamsError::TooManyMemoryEntries);
        }
        self.memory[index] = MemoryEntry { base, len, kind };
        self.memory_count += 1;
        Ok(())
    }

    /// Appends one initrd/module entry.
    ///
    /// Fails with [`BootParamsError::TooManyModules`] once
    /// [`MAX_MODULE_ENTRIES`] entries are present.
    pub fn add_module(&mut self, base: u64, len: u64) -> Result<(), BootParamsError> {
        let index = usize::from(self.module_count);
        if index >= MAX_MODULE_ENTRIES {
            return Err(BootParamsError::TooManyModules);
        }
        self.modules[index] = ModuleEntry { base, len };
        self.module_count += 1;
        Ok(())
    }

    /// Sets the kernel command line.
    ///
    /// The bytes are copied verbatim into the fixed field; the rest of the
    /// field stays NUL (the command line is not NUL-terminated). Fails with
    /// [`BootParamsError::CmdlineTooLong`] beyond [`CMDLINE_MAX`] bytes.
    pub fn set_cmdline(&mut self, cmdline: &[u8]) -> Result<(), BootParamsError> {
        if cmdline.len() > CMDLINE_MAX {
            return Err(BootParamsError::CmdlineTooLong);
        }
        self.cmdline = [0u8; CMDLINE_MAX];
        self.cmdline[..cmdline.len()].copy_from_slice(cmdline);
        self.cmdline_len = cmdline.len() as u16;
        Ok(())
    }

    /// Sets the ACPI RSDP guest-physical address (0 = absent).
    pub const fn set_rsdp(&mut self, gpa: u64) {
        self.rsdp_gpa = gpa;
    }

    /// Sets the console MMIO base and I/O APIC line and marks the console as
    /// present.
    pub const fn set_console(&mut self, mmio_base: u64, irq_line: u32) {
        self.console_mmio_base = mmio_base;
        self.console_irq_line = irq_line;
        self.flags |= flags::CONSOLE_PRESENT;
    }

    /// Replaces the boot [`flags`] bits.
    ///
    /// Fails with [`BootParamsError::BadFlags`] when a bit outside
    /// [`flags::ALL`] is set.
    pub fn set_flags(&mut self, flags: u32) -> Result<(), BootParamsError> {
        if flags & !flags::ALL != 0 {
            return Err(BootParamsError::BadFlags);
        }
        self.flags = flags;
        Ok(())
    }

    /// Re-checks every invariant of the block.
    pub fn validate(&self) -> Result<(), BootParamsError> {
        let memory_count = self.memory_count();
        let module_count = self.module_count();
        if memory_count > MAX_MEMORY_ENTRIES {
            return Err(BootParamsError::TooManyMemoryEntries);
        }
        if module_count > MAX_MODULE_ENTRIES {
            return Err(BootParamsError::TooManyModules);
        }
        if self.cmdline_len() > CMDLINE_MAX {
            return Err(BootParamsError::CmdlineTooLong);
        }
        if self.flags & !flags::ALL != 0 {
            return Err(BootParamsError::BadFlags);
        }
        for entry in &self.memory[..memory_count] {
            if !memory_kind::is_valid(entry.kind) {
                return Err(BootParamsError::BadMemoryKind);
            }
        }
        Ok(())
    }

    /// Encodes the block into `out`.
    ///
    /// The whole 1024-byte buffer is overwritten and the checksum is computed
    /// last so the byte sum of the result is zero.
    pub fn encode(&self, out: &mut [u8; SIZE]) {
        out.fill(0);
        put_u64(out, OFF_MAGIC, MAGIC);
        put_u32(out, OFF_VERSION, VERSION);
        put_u32(out, OFF_SIZE, SIZE as u32);
        put_u32(out, OFF_FLAGS, self.flags);
        put_u32(out, OFF_MEMORY_COUNT, u32::from(self.memory_count));
        put_u32(out, OFF_MODULE_COUNT, u32::from(self.module_count));
        put_u32(out, OFF_CMDLINE_LEN, u32::from(self.cmdline_len));
        put_u64(out, OFF_RSDP_GPA, self.rsdp_gpa);
        put_u64(out, OFF_CONSOLE_MMIO, self.console_mmio_base);
        put_u32(out, OFF_CONSOLE_IRQ, self.console_irq_line);
        for (index, entry) in self.memory().iter().enumerate() {
            let offset = MEMORY_OFFSET + index * MEMORY_ENTRY_SIZE;
            put_u64(out, offset, entry.base);
            put_u64(out, offset + 8, entry.len);
            put_u32(out, offset + 16, entry.kind);
        }
        for (index, entry) in self.modules().iter().enumerate() {
            let offset = MODULE_OFFSET + index * MODULE_ENTRY_SIZE;
            put_u64(out, offset, entry.base);
            put_u64(out, offset + 8, entry.len);
        }
        let cmdline_len = self.cmdline_len();
        out[CMDLINE_OFFSET..CMDLINE_OFFSET + cmdline_len]
            .copy_from_slice(&self.cmdline[..cmdline_len]);
        seal(out);
    }

    /// Decodes and validates a block.
    ///
    /// `bytes` must hold at least [`SIZE`] bytes; trailing bytes are ignored.
    /// Every field is checked (magic, version, size, checksum, counts,
    /// command-line length, memory kinds and flags) before the block is
    /// returned.
    pub fn decode(bytes: &[u8]) -> Result<Self, BootParamsError> {
        if bytes.len() < SIZE {
            return Err(BootParamsError::Truncated);
        }
        if get_u64(bytes, OFF_MAGIC) != MAGIC {
            return Err(BootParamsError::BadMagic);
        }
        if get_u32(bytes, OFF_VERSION) != VERSION {
            return Err(BootParamsError::BadVersion);
        }
        if get_u32(bytes, OFF_SIZE) as usize != SIZE {
            return Err(BootParamsError::BadSize);
        }
        if checksum(bytes) != 0 {
            return Err(BootParamsError::BadChecksum);
        }
        let memory_count = get_u32(bytes, OFF_MEMORY_COUNT) as usize;
        if memory_count > MAX_MEMORY_ENTRIES {
            return Err(BootParamsError::TooManyMemoryEntries);
        }
        let module_count = get_u32(bytes, OFF_MODULE_COUNT) as usize;
        if module_count > MAX_MODULE_ENTRIES {
            return Err(BootParamsError::TooManyModules);
        }
        let cmdline_len = get_u32(bytes, OFF_CMDLINE_LEN) as usize;
        if cmdline_len > CMDLINE_MAX {
            return Err(BootParamsError::CmdlineTooLong);
        }

        let mut params = Self::new();
        params.flags = get_u32(bytes, OFF_FLAGS);
        params.rsdp_gpa = get_u64(bytes, OFF_RSDP_GPA);
        params.console_mmio_base = get_u64(bytes, OFF_CONSOLE_MMIO);
        params.console_irq_line = get_u32(bytes, OFF_CONSOLE_IRQ);
        params.memory_count = memory_count as u8;
        for (index, entry) in params.memory[..memory_count].iter_mut().enumerate() {
            let offset = MEMORY_OFFSET + index * MEMORY_ENTRY_SIZE;
            *entry = MemoryEntry {
                base: get_u64(bytes, offset),
                len: get_u64(bytes, offset + 8),
                kind: get_u32(bytes, offset + 16),
            };
        }
        params.module_count = module_count as u8;
        for (index, entry) in params.modules[..module_count].iter_mut().enumerate() {
            let offset = MODULE_OFFSET + index * MODULE_ENTRY_SIZE;
            *entry = ModuleEntry {
                base: get_u64(bytes, offset),
                len: get_u64(bytes, offset + 8),
            };
        }
        params.cmdline_len = cmdline_len as u16;
        params.cmdline[..cmdline_len]
            .copy_from_slice(&bytes[CMDLINE_OFFSET..CMDLINE_OFFSET + cmdline_len]);
        params.validate()?;
        Ok(params)
    }
}

impl Default for BootParams {
    fn default() -> Self {
        Self::new()
    }
}

/// Writes the checksum byte so the whole block sums to zero.
fn seal(out: &mut [u8; SIZE]) {
    out[OFF_CHECKSUM] = 0;
    let sum = checksum(out);
    out[OFF_CHECKSUM] = 0u8.wrapping_sub(sum);
}

/// Sums the bytes of `bytes` modulo 256.
fn checksum(bytes: &[u8]) -> u8 {
    bytes[..SIZE]
        .iter()
        .fold(0u8, |sum, byte| sum.wrapping_add(*byte))
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
