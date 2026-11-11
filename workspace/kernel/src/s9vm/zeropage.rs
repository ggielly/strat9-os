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

//! s9vm — x86 boot-protocol zero page (`struct boot_params`) builder.
//!
//! A 64-bit x86 kernel entered by a boot loader expects a 4 KiB control page at
//! guest-physical [`BOOT_PARAMS_GPA`] (`0x0001_0000`), the so-called **zero
//! page**. Its first bytes (up to the setup header) are the "boot_params"
//! fields: firmware data, E820 memory map, command-line/initrd pointers, ACPI
//! RSDP address, and a copy of the kernel's **setup header** at `0x1F1`. This
//! module builds that page from a small set of inputs, byte-exactly, without
//! allocation and with every write bounds-checked.
//!
//! This is **not** [`super::bootparams`]: that structure (`S9VMBP`, 1024 bytes)
//! is s9vm's own, minimal hand-off for the s9vm test guest and carries the same
//! kind of information in a deliberately different, s9vm-specific format. The
//! zero page built here follows the **x86 boot protocol** so an unmodified
//! kernel (and, eventually, a real kernel image) can be entered. Keeping the
//! two formats distinct avoids overloading either: `bootparams` evolves with
//! s9vm, the zero page must not.
//!
//! # Verified layout
//!
//! The offsets below were checked against the upstream documentation
//! (`Documentation/arch/x86/zero-page.rst` for `struct boot_params`,
//! `Documentation/arch/x86/boot.rst` for the setup-header semantics); the
//! authoritative struct is `arch/x86/include/uapi/asm/bootparam.h`. Byte order
//! is little-endian throughout, as the protocol requires.
//!
//! | Offset | Size | Field |
//! |---|---|---|
//! | `0x070` | 8 | `acpi_rsdp_addr` (physical address of the ACPI RSDP) |
//! | `0x0C0` | 4 | `ext_ramdisk_image` (high 32 bits of the initrd address) |
//! | `0x0C4` | 4 | `ext_ramdisk_size` (high 32 bits of the initrd size) |
//! | `0x0C8` | 4 | `ext_cmd_line_ptr` (high 32 bits of the command line) |
//! | `0x1E8` | 1 | `e820_entries` (number of valid entries) |
//! | `0x1EF` | 1 | `sentinel` (zero: the loader copied only the header) |
//! | `0x1F1` | 1 | `setup_sects` (0 means 4; size of the real-mode setup) |
//! | `0x1FE` | 2 | `boot_flag` (`0xAA55`) |
//! | `0x202` | 4 | `header` (magic `"HdrS"`, `0x5372_6448`) |
//! | `0x206` | 2 | `version` (boot protocol version, written as 2.15) |
//! | `0x210` | 1 | `type_of_loader` |
//! | `0x211` | 1 | `loadflags` (`LOADED_HIGH` \| `CAN_USE_HEAP`) |
//! | `0x214` | 4 | `code32_start` (protected-mode entry) |
//! | `0x218` | 4 | `ramdisk_image` (low 32 bits of the initrd address) |
//! | `0x21C` | 4 | `ramdisk_size` (low 32 bits of the initrd size) |
//! | `0x224` | 2 | `heap_end_ptr` (setup heap end offset, minus `0x200`) |
//! | `0x228` | 4 | `cmd_line_ptr` (low 32 bits of the command line) |
//! | `0x22C` | 4 | `initrd_addr_max` (highest legal initrd address) |
//! | `0x230` | 4 | `kernel_alignment` |
//! | `0x234` | 1 | `relocatable_kernel` |
//! | `0x235` | 1 | `min_alignment` (power of two) |
//! | `0x236` | 2 | `xloadflags` |
//! | `0x238` | 4 | `cmdline_size` (maximum command-line length) |
//! | `0x23C` | 4 | `hardware_subarch` (always 0: standard x86 PC) |
//! | `0x240` | 8 | `hardware_subarch_data` |
//! | `0x248` | 4 | `payload_offset` |
//! | `0x24C` | 4 | `payload_length` |
//! | `0x250` | 8 | `setup_data` (physical address of the setup-data list) |
//! | `0x258` | 8 | `pref_address` (preferred load address) |
//! | `0x260` | 4 | `init_size` (linear memory needed during init) |
//! | `0x264` | 4 | `handover_offset` |
//! | `0x268` | 4 | `kernel_info_offset` |
//! | `0x2D0` | 2560 | `e820_table` (128 entries of 20 bytes) |
//!
//! The setup header spans `0x1F1..=0x26B` (123 bytes); `e820_table` starts at
//! `0x2D0` and ends at `0xCD0`, both verified against `zero-page.rst`. The
//! zero page is 4096 bytes, so the table and the EDD data area after it fit.
//!
//! # E820 map
//!
//! [`ZeroPage::add_e820`] keeps the map sorted, merges adjacent (or
//! overlapping) entries of the same [`E820Kind`], rejects real overlaps between
//! different kinds (`E820Overlap`), zero-size entries and address overflow, and
//! caps the map at [`E820_MAX_ENTRIES`] entries. The kernel tolerates fewer
//! entries and never more; a boot loader must not invent entries it cannot
//! describe. [`ZeroPage::boot_params_for`] builds a documented, PC-like layout
//! (low RAM, VGA/BIOS holes, ACPI NVS/reclaim, and RAM plus a reserved MMIO
//! window above 4 GiB when the machine has more than 4 GiB).
//!
//! # Invariants
//!
//! - [`ZeroPage::write`] zero-fills the whole page first, so fields the builder
//!   does not model (`screen_info`, `efi_info`, EDD buffers, ...) read as zero
//!   and two writes of the same builder produce identical bytes;
//! - the command line and initrd buffers stay owned by the caller: the builder
//!   stores their **guest-physical addresses and lengths** only. Pointers above
//!   `4 GiB` are written through the protocol's `ext_*` fields and are only
//!   accepted when `xloadflags` announces `XLF_CAN_BE_LOADED_ABOVE_4G`;
//! - `hardware_subarch` is always the standard x86 PC value (`0`); the builder
//!   has no way to emit a non-PC sub-architecture;
//! - nothing here reads the clock, allocates memory or touches hardware: the
//!   kernel computes a [`ZeroPage`], calls [`ZeroPage::write`] into a 4 KiB
//!   buffer and copies that buffer into guest memory.
//!
//! This module is pure `core` code and is host-tested by `s9vm-tests`.

/// Guest-physical address of the zero page / `struct boot_params`.
pub const BOOT_PARAMS_GPA: u64 = 0x0001_0000;
/// Size of the zero page, in bytes.
pub const BOOT_PARAMS_SIZE: usize = 4096;

/// Offset of `acpi_rsdp_addr` (8 bytes).
pub const OFFSET_ACPI_RSDP_ADDR: usize = 0x070;
/// Offset of `ext_ramdisk_image` (4 bytes, high half of the initrd address).
pub const OFFSET_EXT_RAMDISK_IMAGE: usize = 0x0C0;
/// Offset of `ext_ramdisk_size` (4 bytes, high half of the initrd size).
pub const OFFSET_EXT_RAMDISK_SIZE: usize = 0x0C4;
/// Offset of `ext_cmd_line_ptr` (4 bytes, high half of the command line).
pub const OFFSET_EXT_CMD_LINE_PTR: usize = 0x0C8;
/// Offset of `e820_entries` (1 byte).
pub const OFFSET_E820_ENTRIES: usize = 0x1E8;
/// Offset of `sentinel` (1 byte).
pub const OFFSET_SENTINEL: usize = 0x1EF;
/// Offset of the setup header; `setup_sects` is its first byte.
pub const OFFSET_SETUP_HEADER: usize = 0x1F1;
/// Offset of `setup_sects` (1 byte).
pub const OFFSET_SETUP_SECTS: usize = 0x1F1;
/// Offset of `boot_flag` (2 bytes, `0xAA55`).
pub const OFFSET_BOOT_FLAG: usize = 0x1FE;
/// Offset of `header` (4 bytes, magic `"HdrS"`).
pub const OFFSET_HEADER: usize = 0x202;
/// Offset of `version` (2 bytes, boot protocol version).
pub const OFFSET_VERSION: usize = 0x206;
/// Offset of `type_of_loader` (1 byte).
pub const OFFSET_TYPE_OF_LOADER: usize = 0x210;
/// Offset of `loadflags` (1 byte).
pub const OFFSET_LOADFLAGS: usize = 0x211;
/// Offset of `code32_start` (4 bytes).
pub const OFFSET_CODE32_START: usize = 0x214;
/// Offset of `ramdisk_image` (4 bytes, low half of the initrd address).
pub const OFFSET_RAMDISK_IMAGE: usize = 0x218;
/// Offset of `ramdisk_size` (4 bytes, low half of the initrd size).
pub const OFFSET_RAMDISK_SIZE: usize = 0x21C;
/// Offset of `heap_end_ptr` (2 bytes).
pub const OFFSET_HEAP_END_PTR: usize = 0x224;
/// Offset of `cmd_line_ptr` (4 bytes, low half of the command line).
pub const OFFSET_CMD_LINE_PTR: usize = 0x228;
/// Offset of `initrd_addr_max` (4 bytes).
pub const OFFSET_INITRD_ADDR_MAX: usize = 0x22C;
/// Offset of `kernel_alignment` (4 bytes).
pub const OFFSET_KERNEL_ALIGNMENT: usize = 0x230;
/// Offset of `relocatable_kernel` (1 byte).
pub const OFFSET_RELOCATABLE_KERNEL: usize = 0x234;
/// Offset of `min_alignment` (1 byte).
pub const OFFSET_MIN_ALIGNMENT: usize = 0x235;
/// Offset of `xloadflags` (2 bytes).
pub const OFFSET_XLOADFLAGS: usize = 0x236;
/// Offset of `cmdline_size` (4 bytes).
pub const OFFSET_CMDLINE_SIZE: usize = 0x238;
/// Offset of `hardware_subarch` (4 bytes).
pub const OFFSET_HARDWARE_SUBARCH: usize = 0x23C;
/// Offset of `hardware_subarch_data` (8 bytes).
pub const OFFSET_HARDWARE_SUBARCH_DATA: usize = 0x240;
/// Offset of `payload_offset` (4 bytes).
pub const OFFSET_PAYLOAD_OFFSET: usize = 0x248;
/// Offset of `payload_length` (4 bytes).
pub const OFFSET_PAYLOAD_LENGTH: usize = 0x24C;
/// Offset of `setup_data` (8 bytes).
pub const OFFSET_SETUP_DATA: usize = 0x250;
/// Offset of `pref_address` (8 bytes).
pub const OFFSET_PREF_ADDRESS: usize = 0x258;
/// Offset of `init_size` (4 bytes).
pub const OFFSET_INIT_SIZE: usize = 0x260;
/// Offset of `handover_offset` (4 bytes).
pub const OFFSET_HANDOVER_OFFSET: usize = 0x264;
/// Offset of `kernel_info_offset` (4 bytes).
pub const OFFSET_KERNEL_INFO_OFFSET: usize = 0x268;
/// Offset of `e820_table` (128 entries of 20 bytes).
pub const OFFSET_E820_TABLE: usize = 0x2D0;

/// End offset of the setup header (exclusive).
pub const HEADER_END: usize = OFFSET_KERNEL_INFO_OFFSET + 4;
/// Length of the setup header (`0x1F1..=0x26B`, 123 bytes).
pub const SETUP_HEADER_LEN: usize = HEADER_END - OFFSET_SETUP_HEADER;

/// Number of E820 entries the protocol provides room for.
pub const E820_MAX_ENTRIES: usize = 128;
/// Size of one E820 entry (`addr: u64, size: u64, type: u32`).
pub const E820_ENTRY_SIZE: usize = 20;
/// Total size of the E820 table.
pub const E820_TABLE_LEN: usize = E820_MAX_ENTRIES * E820_ENTRY_SIZE;

/// Boot flag value at `0x1FE`.
pub const BOOT_FLAG: u16 = 0xAA55;
/// Setup-header magic `"HdrS"` (`0x5372_6448`) at `0x202`.
pub const HEADER_MAGIC: u32 = 0x5372_6448;
/// Boot protocol version emitted by the builder (2.15).
pub const BOOT_PROTOCOL_VERSION: u16 = 0x020F;
/// `setup_sects` value meaning "4 sectors" for old kernels.
pub const SETUP_SECTS_FALLBACK: u8 = 4;
/// Value subtracted from the setup-heap end to form `heap_end_ptr`.
pub const HEAP_END_ADJUST: u16 = 0x0200;
/// `LOADED_HIGH`: the protected-mode kernel is loaded at `0x10_0000`.
pub const LOADFLAG_LOADED_HIGH: u8 = 1 << 0;
/// `CAN_USE_HEAP`: `heap_end_ptr` is valid.
pub const LOADFLAG_CAN_USE_HEAP: u8 = 1 << 7;
/// `loadflags` value emitted by the builder.
pub const LOADFLAGS: u8 = LOADFLAG_LOADED_HIGH | LOADFLAG_CAN_USE_HEAP;
/// `XLF_KERNEL_64`: the kernel has the legacy 64-bit entry point.
pub const XLF_KERNEL_64: u16 = 1 << 0;
/// `XLF_CAN_BE_LOADED_ABOVE_4G`: kernel/boot params/cmdline/initrd may be >4G.
pub const XLF_CAN_BE_LOADED_ABOVE_4G: u16 = 1 << 1;
/// Standard x86 PC sub-architecture value.
pub const HARDWARE_SUBARCH_PC: u32 = 0;
/// Default maximum command-line length announced to the kernel.
pub const DEFAULT_CMDLINE_SIZE: u32 = 2048;
/// Default highest legal initrd address (`0x37FF_FFFF`, protocol fallback).
pub const DEFAULT_INITRD_ADDR_MAX: u32 = 0x37FF_FFFF;

/// End of the conventional low RAM described by the PC layout.
pub const LOW_RAM_END: u64 = 0x0009_FC00;
/// Start of the VGA/legacy hole (`0xA0000`), reserved.
pub const VGA_HOLE_START: u64 = 0x000A_0000;
/// Start of the BIOS ROM area (`0xF0000`), reserved.
pub const BIOS_ROM_START: u64 = 0x000F_0000;
/// End of the low 1 MiB (start of extended RAM).
pub const LOW_MEMORY_TOP: u64 = 0x0010_0000;
/// Base of RAM and MMIO above 4 GiB.
pub const HIGH_BASE: u64 = 0x1_0000_0000;
/// Size of the synthetic ACPI NVS region carved from the top of low RAM.
pub const ACPI_NVS_LEN: u64 = 0x1_0000;
/// Size of the synthetic ACPI reclaimable region carved from low RAM.
pub const ACPI_RECLAIM_LEN: u64 = 0x1_0000;
/// Size of the reserved MMIO window placed above 4 GiB RAM.
pub const HIGH_MMIO_LEN: u64 = 0x1000_0000;
/// Smallest RAM size accepted by [`ZeroPage::boot_params_for`].
pub const MIN_BOOT_MEMORY: u64 = 0x0020_0000;

/// E820 memory type values understood by the kernel.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum E820Kind {
    /// Usable RAM (`1`).
    #[default]
    Ram = 1,
    /// Reserved (`2`).
    Reserved = 2,
    /// ACPI reclaimable (`3`).
    Acpi = 3,
    /// ACPI NVS (`4`).
    Nvs = 4,
    /// Unusable (`5`).
    Unusable = 5,
}

impl E820Kind {
    /// Numeric type written in the E820 table.
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    /// Parses a numeric E820 type; unknown values are rejected.
    pub const fn from_u32(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::Ram),
            2 => Some(Self::Reserved),
            3 => Some(Self::Acpi),
            4 => Some(Self::Nvs),
            5 => Some(Self::Unusable),
            _ => None,
        }
    }
}

/// One 20-byte E820 table entry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct E820Entry {
    /// First guest-physical byte of the range.
    pub addr: u64,
    /// Length of the range in bytes; never zero.
    pub size: u64,
    /// Memory type.
    pub kind: E820Kind,
}

/// Errors returned while validating or encoding a zero page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZeroPageError {
    /// The destination buffer is shorter than [`BOOT_PARAMS_SIZE`].
    DestinationTooSmall,
    /// An E820 entry has a zero length.
    E820ZeroSize,
    /// Two E820 entries of different kinds overlap.
    E820Overlap,
    /// The E820 map would exceed [`E820_MAX_ENTRIES`] entries.
    E820TooManyEntries,
    /// `addr + size` overflows `u64`.
    E820AddressOverflow,
    /// The command line is longer than the header's `cmdline_size`.
    CmdlineTooLong,
    /// The command-line pointer is zero, overlaps the zero page, or is above
    /// 4 GiB without the `XLF_CAN_BE_LOADED_ABOVE_4G` flag.
    InvalidCmdlineAddress,
    /// The initrd pointer/size pair is inconsistent, overlaps the zero page or
    /// is above 4 GiB without the `XLF_CAN_BE_LOADED_ABOVE_4G` flag.
    InvalidInitrdAddress,
    /// The byte buffer does not hold a valid setup header.
    InvalidHeader,
    /// `boot_params_for` was asked for less than [`MIN_BOOT_MEMORY`] bytes.
    MemoryTooSmall,
}

/// The setup-header fields a boot loader copies from the kernel image.
///
/// Only the fields the builder needs to reproduce are kept; the builder writes
/// them at the protocol offsets listed in the module documentation. The CLI
/// `setup_sects == 0` fallback (4 sectors) is applied when computing
/// `heap_end_ptr`, but the raw value is written unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelHeader {
    /// Size of the real-mode setup, in 512-byte sectors (0 means 4).
    pub setup_sects: u8,
    /// Protected-mode entry address.
    pub code32_start: u32,
    /// Highest address the initrd may occupy.
    pub initrd_addr_max: u32,
    /// Preferred kernel load alignment.
    pub kernel_alignment: u32,
    /// Non-zero when the kernel may be loaded at any aligned address.
    pub relocatable_kernel: u8,
    /// Minimum alignment, as a power of two.
    pub min_alignment: u8,
    /// Feature flags for 64-bit loaders.
    pub xloadflags: u16,
    /// Maximum command-line length (without the terminating NUL).
    pub cmdline_size: u32,
    /// Offset of the compressed payload inside the kernel image.
    pub payload_offset: u32,
    /// Length of the compressed payload.
    pub payload_length: u32,
    /// Physical address of the setup-data linked list.
    pub setup_data: u64,
    /// Preferred load address.
    pub pref_address: u64,
    /// Linear memory required while the kernel initialises.
    pub init_size: u32,
    /// Offset of the 32-bit EFI handover entry point.
    pub handover_offset: u32,
    /// Offset of the `kernel_info` structure.
    pub kernel_info_offset: u32,
}

impl Default for KernelHeader {
    fn default() -> Self {
        Self {
            setup_sects: 0x1F,
            code32_start: 0x0010_0000,
            initrd_addr_max: DEFAULT_INITRD_ADDR_MAX,
            kernel_alignment: 0x0020_0000,
            relocatable_kernel: 1,
            min_alignment: 0x15,
            xloadflags: XLF_KERNEL_64 | XLF_CAN_BE_LOADED_ABOVE_4G,
            cmdline_size: DEFAULT_CMDLINE_SIZE,
            payload_offset: 0,
            payload_length: 0,
            setup_data: 0,
            pref_address: 0,
            init_size: 0,
            handover_offset: 0,
            kernel_info_offset: 0,
        }
    }
}

impl KernelHeader {
    /// Parses the header fields out of a complete zero-page image.
    ///
    /// `image` must start at the zero-page base and be at least
    /// [`HEADER_END`] bytes long; the boot flag and `"HdrS"` magic are
    /// validated, so a random buffer is rejected with
    /// [`ZeroPageError::InvalidHeader`].
    pub fn parse(image: &[u8]) -> Result<Self, ZeroPageError> {
        if image.len() < HEADER_END {
            return Err(ZeroPageError::InvalidHeader);
        }
        let header = Self {
            setup_sects: read_u8(image, OFFSET_SETUP_SECTS)?,
            code32_start: read_u32(image, OFFSET_CODE32_START)?,
            initrd_addr_max: read_u32(image, OFFSET_INITRD_ADDR_MAX)?,
            kernel_alignment: read_u32(image, OFFSET_KERNEL_ALIGNMENT)?,
            relocatable_kernel: read_u8(image, OFFSET_RELOCATABLE_KERNEL)?,
            min_alignment: read_u8(image, OFFSET_MIN_ALIGNMENT)?,
            xloadflags: read_u16(image, OFFSET_XLOADFLAGS)?,
            cmdline_size: read_u32(image, OFFSET_CMDLINE_SIZE)?,
            payload_offset: read_u32(image, OFFSET_PAYLOAD_OFFSET)?,
            payload_length: read_u32(image, OFFSET_PAYLOAD_LENGTH)?,
            setup_data: read_u64(image, OFFSET_SETUP_DATA)?,
            pref_address: read_u64(image, OFFSET_PREF_ADDRESS)?,
            init_size: read_u32(image, OFFSET_INIT_SIZE)?,
            handover_offset: read_u32(image, OFFSET_HANDOVER_OFFSET)?,
            kernel_info_offset: read_u32(image, OFFSET_KERNEL_INFO_OFFSET)?,
        };
        if read_u16(image, OFFSET_BOOT_FLAG)? != BOOT_FLAG
            || read_u32(image, OFFSET_HEADER)? != HEADER_MAGIC
        {
            return Err(ZeroPageError::InvalidHeader);
        }
        Ok(header)
    }
}

/// Builder for the x86 boot-protocol zero page.
///
/// The builder stores values; [`ZeroPage::write`] turns them into exactly
/// [`BOOT_PARAMS_SIZE`] bytes. Command-line and initrd byte strings are **not**
/// copied: the caller keeps them somewhere in guest memory and passes their
/// guest-physical address and length here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZeroPage {
    header: KernelHeader,
    loader_id: u8,
    cmdline_gpa: u64,
    cmdline_len: u32,
    initrd_gpa: u64,
    initrd_size: u64,
    rsdp_gpa: u64,
    subarch_data: u64,
    e820: [E820Entry; E820_MAX_ENTRIES],
    e820_len: usize,
}

impl Default for ZeroPage {
    fn default() -> Self {
        Self::new()
    }
}

impl ZeroPage {
    /// Creates a zero page with no E820 entries, no initrd and no RSDP.
    ///
    /// The setup header uses protocol defaults: a 32-sector setup area, a
    /// kernel loaded at `0x10_0000`, 2 MiB preferred alignment, BCD/24h status
    /// equivalent fields, and `xloadflags` announcing a 64-bit kernel that may
    /// be loaded above 4 GiB. The command-line pointer starts at
    /// [`BOOT_PARAMS_GPA`] + [`BOOT_PARAMS_SIZE`] with length zero.
    pub fn new() -> Self {
        Self {
            header: KernelHeader::default(),
            loader_id: 0xFF,
            cmdline_gpa: BOOT_PARAMS_GPA + BOOT_PARAMS_SIZE as u64,
            cmdline_len: 0,
            initrd_gpa: 0,
            initrd_size: 0,
            rsdp_gpa: 0,
            subarch_data: 0,
            e820: [E820Entry::default(); E820_MAX_ENTRIES],
            e820_len: 0,
        }
    }

    /// Replaces the kernel header fields copied into the page.
    pub fn with_kernel_header(mut self, header: KernelHeader) -> Self {
        self.header = header;
        self
    }

    /// Sets the boot-loader identifier (`type_of_loader`).
    pub fn with_loader_id(mut self, loader_id: u8) -> Self {
        self.loader_id = loader_id;
        self
    }

    /// Sets the command-line guest-physical address and length.
    ///
    /// The caller is responsible for placing a NUL-terminated string at
    /// `gpa`; the builder only publishes the pointer. The pointer must not be
    /// zero, must not point into the zero page itself, and may only exceed
    /// 4 GiB when `xloadflags` contains [`XLF_CAN_BE_LOADED_ABOVE_4G`]. The
    /// length (excluding the NUL) must not exceed the header's `cmdline_size`.
    pub fn with_cmdline(mut self, gpa: u64, len: u32) -> Result<Self, ZeroPageError> {
        self.set_cmdline(gpa, len)?;
        Ok(self)
    }

    /// Mutable form of [`ZeroPage::with_cmdline`].
    pub fn set_cmdline(&mut self, gpa: u64, len: u32) -> Result<(), ZeroPageError> {
        if gpa == 0
            || overlaps_zero_page(gpa, u64::from(len))
            || gpa.checked_add(u64::from(len) + 1).is_none()
        {
            return Err(ZeroPageError::InvalidCmdlineAddress);
        }
        if gpa > u64::from(u32::MAX) && self.header.xloadflags & XLF_CAN_BE_LOADED_ABOVE_4G == 0 {
            return Err(ZeroPageError::InvalidCmdlineAddress);
        }
        if len > self.header.cmdline_size {
            return Err(ZeroPageError::CmdlineTooLong);
        }
        self.cmdline_gpa = gpa;
        self.cmdline_len = len;
        Ok(())
    }

    /// Sets the initrd guest-physical address and size.
    ///
    /// A zero size means "no initrd" and requires a zero address. A non-zero
    /// initrd must not overlap the zero page and may only live above 4 GiB
    /// when `xloadflags` contains [`XLF_CAN_BE_LOADED_ABOVE_4G`].
    pub fn with_initrd(mut self, gpa: u64, size: u64) -> Result<Self, ZeroPageError> {
        self.set_initrd(gpa, size)?;
        Ok(self)
    }

    /// Mutable form of [`ZeroPage::with_initrd`].
    pub fn set_initrd(&mut self, gpa: u64, size: u64) -> Result<(), ZeroPageError> {
        if size == 0 {
            if gpa != 0 {
                return Err(ZeroPageError::InvalidInitrdAddress);
            }
        } else if gpa == 0
            || overlaps_zero_page(gpa, size)
            || gpa.checked_add(size).is_none()
            || (gpa > u64::from(u32::MAX)
                && self.header.xloadflags & XLF_CAN_BE_LOADED_ABOVE_4G == 0)
        {
            return Err(ZeroPageError::InvalidInitrdAddress);
        }
        self.initrd_gpa = gpa;
        self.initrd_size = size;
        Ok(())
    }

    /// Sets the ACPI RSDP physical address (zero means "no ACPI tables").
    pub fn with_rsdp(mut self, gpa: u64) -> Self {
        self.rsdp_gpa = gpa;
        self
    }

    /// Sets `hardware_subarch_data`; `hardware_subarch` itself stays `0`.
    pub fn with_hardware_subarch_data(mut self, data: u64) -> Self {
        self.subarch_data = data;
        self
    }

    /// Adds one E820 range, normalising the map.
    ///
    /// Entries are kept in ascending address order. Adjacent or overlapping
    /// ranges of the same kind are merged; an overlap between different kinds
    /// is rejected. Zero-size ranges, address overflows and maps larger than
    /// [`E820_MAX_ENTRIES`] entries are rejected. The operation is atomic: on
    /// error the previous map is preserved.
    pub fn add_e820(&mut self, addr: u64, size: u64, kind: E820Kind) -> Result<(), ZeroPageError> {
        if size == 0 {
            return Err(ZeroPageError::E820ZeroSize);
        }
        if addr.checked_add(size).is_none() {
            return Err(ZeroPageError::E820AddressOverflow);
        }
        let mut tmp = [E820Entry::default(); E820_MAX_ENTRIES + 1];
        tmp[..self.e820_len].copy_from_slice(&self.e820[..self.e820_len]);
        tmp[self.e820_len] = E820Entry { addr, size, kind };
        let len = normalise_e820(&mut tmp, self.e820_len + 1)?;
        if len > E820_MAX_ENTRIES {
            return Err(ZeroPageError::E820TooManyEntries);
        }
        self.e820[..len].copy_from_slice(&tmp[..len]);
        for entry in &mut self.e820[len..] {
            *entry = E820Entry::default();
        }
        self.e820_len = len;
        Ok(())
    }

    /// The normalised E820 map.
    pub fn e820_entries(&self) -> &[E820Entry] {
        &self.e820[..self.e820_len]
    }

    /// The command-line guest-physical address and length, as published.
    pub const fn cmdline(&self) -> (u64, u32) {
        (self.cmdline_gpa, self.cmdline_len)
    }

    /// The initrd guest-physical address and size, as published.
    pub const fn initrd(&self) -> (u64, u64) {
        (self.initrd_gpa, self.initrd_size)
    }

    /// The kernel header fields that will be written.
    pub fn header(&self) -> &KernelHeader {
        &self.header
    }

    /// Encodes the zero page into `dst`.
    ///
    /// `dst` must be at least [`BOOT_PARAMS_SIZE`] bytes; the whole page is
    /// zero-filled before the modelled fields are written, and bytes past
    /// [`BOOT_PARAMS_SIZE`] are left untouched.
    pub fn write(&self, dst: &mut [u8]) -> Result<(), ZeroPageError> {
        if dst.len() < BOOT_PARAMS_SIZE {
            return Err(ZeroPageError::DestinationTooSmall);
        }
        dst[..BOOT_PARAMS_SIZE].fill(0);

        // E820 map: count at 0x1E8, 20-byte entries at 0x2D0.
        write_u8(dst, OFFSET_E820_ENTRIES, self.e820_len as u8)?;
        for (index, entry) in self.e820_entries().iter().enumerate() {
            let base = OFFSET_E820_TABLE + index * E820_ENTRY_SIZE;
            write_u64(dst, base, entry.addr)?;
            write_u64(dst, base + 8, entry.size)?;
            write_u32(dst, base + 16, entry.kind.as_u32())?;
        }

        // Setup header identification.
        write_u8(dst, OFFSET_SETUP_SECTS, self.header.setup_sects)?;
        write_u16(dst, OFFSET_BOOT_FLAG, BOOT_FLAG)?;
        write_u32(dst, OFFSET_HEADER, HEADER_MAGIC)?;
        write_u16(dst, OFFSET_VERSION, BOOT_PROTOCOL_VERSION)?;
        write_u8(dst, OFFSET_TYPE_OF_LOADER, self.loader_id)?;
        write_u8(dst, OFFSET_LOADFLAGS, LOADFLAGS)?;
        write_u16(
            dst,
            OFFSET_HEAP_END_PTR,
            heap_end_ptr(self.header.setup_sects),
        )?;

        // Kernel entry and copied header fields.
        write_u32(dst, OFFSET_CODE32_START, self.header.code32_start)?;
        write_u32(dst, OFFSET_RAMDISK_IMAGE, self.initrd_gpa as u32)?;
        write_u32(dst, OFFSET_RAMDISK_SIZE, self.initrd_size as u32)?;
        write_u32(
            dst,
            OFFSET_EXT_RAMDISK_IMAGE,
            (self.initrd_gpa >> 32) as u32,
        )?;
        write_u32(
            dst,
            OFFSET_EXT_RAMDISK_SIZE,
            (self.initrd_size >> 32) as u32,
        )?;
        write_u32(dst, OFFSET_CMD_LINE_PTR, self.cmdline_gpa as u32)?;
        write_u32(
            dst,
            OFFSET_EXT_CMD_LINE_PTR,
            (self.cmdline_gpa >> 32) as u32,
        )?;
        write_u32(dst, OFFSET_INITRD_ADDR_MAX, self.header.initrd_addr_max)?;
        write_u32(dst, OFFSET_KERNEL_ALIGNMENT, self.header.kernel_alignment)?;
        write_u8(
            dst,
            OFFSET_RELOCATABLE_KERNEL,
            self.header.relocatable_kernel,
        )?;
        write_u8(dst, OFFSET_MIN_ALIGNMENT, self.header.min_alignment)?;
        write_u16(dst, OFFSET_XLOADFLAGS, self.header.xloadflags)?;
        write_u32(dst, OFFSET_CMDLINE_SIZE, self.header.cmdline_size)?;
        write_u32(dst, OFFSET_HARDWARE_SUBARCH, HARDWARE_SUBARCH_PC)?;
        write_u64(dst, OFFSET_HARDWARE_SUBARCH_DATA, self.subarch_data)?;
        write_u32(dst, OFFSET_PAYLOAD_OFFSET, self.header.payload_offset)?;
        write_u32(dst, OFFSET_PAYLOAD_LENGTH, self.header.payload_length)?;
        write_u64(dst, OFFSET_SETUP_DATA, self.header.setup_data)?;
        write_u64(dst, OFFSET_PREF_ADDRESS, self.header.pref_address)?;
        write_u32(dst, OFFSET_INIT_SIZE, self.header.init_size)?;
        write_u32(dst, OFFSET_HANDOVER_OFFSET, self.header.handover_offset)?;
        write_u32(
            dst,
            OFFSET_KERNEL_INFO_OFFSET,
            self.header.kernel_info_offset,
        )?;
        write_u64(dst, OFFSET_ACPI_RSDP_ADDR, self.rsdp_gpa)?;

        // `sentinel` stays zero: the loader copied only the setup header.
        write_u8(dst, OFFSET_SENTINEL, 0)?;
        Ok(())
    }

    /// Builds a documented, PC-like zero page for `mem_bytes` of RAM.
    ///
    /// The command line is published at `cmdline_gpa` (the caller places the
    /// string there; length zero is assumed because the builder does not own
    /// the bytes). The E820 layout is:
    ///
    /// - `0x0..0x9FC00` usable RAM (the conventional 639 KiB);
    /// - `0x9FC00..0xA0000` reserved (VGA/EBDA hole);
    /// - `0xF0000..0x100000` reserved (BIOS ROM area);
    /// - `0x100000..low_top` usable RAM, where `low_top` is `min(mem_bytes,
    ///   4 GiB)`, minus a 128 KiB tail reserved for ACPI NVS (64 KiB) and ACPI
    ///   reclaimable (64 KiB) memory when at least 2 MiB of RAM is present;
    /// - when `mem_bytes > 4 GiB`: usable RAM at `0x1_0000_0000` for the
    ///   remaining bytes, then a 256 MiB reserved MMIO window above it.
    pub fn boot_params_for(cmdline_gpa: u64, mem_bytes: u64) -> Result<Self, ZeroPageError> {
        if mem_bytes < MIN_BOOT_MEMORY {
            return Err(ZeroPageError::MemoryTooSmall);
        }
        let mut page = Self::new().with_cmdline(cmdline_gpa, 0)?;
        page.add_e820(0, LOW_RAM_END, E820Kind::Ram)?;
        page.add_e820(
            LOW_RAM_END,
            VGA_HOLE_START - LOW_RAM_END,
            E820Kind::Reserved,
        )?;
        page.add_e820(
            BIOS_ROM_START,
            LOW_MEMORY_TOP - BIOS_ROM_START,
            E820Kind::Reserved,
        )?;

        let low_top = mem_bytes.min(HIGH_BASE);
        let acpi_len = ACPI_NVS_LEN + ACPI_RECLAIM_LEN;
        if low_top >= LOW_MEMORY_TOP + MIN_BOOT_MEMORY + acpi_len {
            let ram_end = low_top - acpi_len;
            page.add_e820(LOW_MEMORY_TOP, ram_end - LOW_MEMORY_TOP, E820Kind::Ram)?;
            page.add_e820(ram_end, ACPI_NVS_LEN, E820Kind::Nvs)?;
            page.add_e820(ram_end + ACPI_NVS_LEN, ACPI_RECLAIM_LEN, E820Kind::Acpi)?;
        } else if low_top > LOW_MEMORY_TOP {
            page.add_e820(LOW_MEMORY_TOP, low_top - LOW_MEMORY_TOP, E820Kind::Ram)?;
        }

        if mem_bytes > HIGH_BASE {
            let high_ram = mem_bytes - HIGH_BASE;
            page.add_e820(HIGH_BASE, high_ram, E820Kind::Ram)?;
            page.add_e820(HIGH_BASE + high_ram, HIGH_MMIO_LEN, E820Kind::Reserved)?;
        }
        Ok(page)
    }
}

/// True when `[gpa, gpa + max(len, 1))` intersects the zero page itself.
fn overlaps_zero_page(gpa: u64, len: u64) -> bool {
    let end = gpa.saturating_add(len.max(1));
    let page_start = BOOT_PARAMS_GPA;
    let page_end = BOOT_PARAMS_GPA + BOOT_PARAMS_SIZE as u64;
    gpa < page_end && end > page_start
}

/// `heap_end_ptr`: setup end offset minus [`HEAP_END_ADJUST`], clamped to u16.
fn heap_end_ptr(setup_sects: u8) -> u16 {
    let sectors = if setup_sects == 0 {
        SETUP_SECTS_FALLBACK
    } else {
        setup_sects
    };
    let setup_size = (u32::from(sectors) + 1) * 512;
    let heap_end = setup_size.saturating_sub(u32::from(HEAP_END_ADJUST));
    heap_end.min(u32::from(u16::MAX)) as u16
}

/// Sorts and merges an E820 map, rejecting cross-kind overlaps.
fn normalise_e820(
    entries: &mut [E820Entry; E820_MAX_ENTRIES + 1],
    len: usize,
) -> Result<usize, ZeroPageError> {
    // Insertion sort by address; the map is small and bounded.
    for index in 1..len {
        let entry = entries[index];
        let mut position = index;
        while position > 0 && entries[position - 1].addr > entry.addr {
            entries[position] = entries[position - 1];
            position -= 1;
        }
        entries[position] = entry;
    }

    let mut written = 0;
    for index in 0..len {
        let entry = entries[index];
        if written > 0 {
            let previous = &mut entries[written - 1];
            let previous_end = previous.addr + previous.size;
            if entry.addr < previous_end {
                if entry.kind == previous.kind {
                    let entry_end = entry.addr + entry.size;
                    if entry_end > previous_end {
                        previous.size = entry_end - previous.addr;
                    }
                    continue;
                }
                return Err(ZeroPageError::E820Overlap);
            }
            if entry.addr == previous_end && entry.kind == previous.kind {
                previous.size += entry.size;
                continue;
            }
        }
        entries[written] = entry;
        written += 1;
    }
    Ok(written)
}

/// Bounds-checked little-endian write helpers.
fn write_u8(dst: &mut [u8], offset: usize, value: u8) -> Result<(), ZeroPageError> {
    *dst.get_mut(offset)
        .ok_or(ZeroPageError::DestinationTooSmall)? = value;
    Ok(())
}

fn write_u16(dst: &mut [u8], offset: usize, value: u16) -> Result<(), ZeroPageError> {
    let bytes = value.to_le_bytes();
    let slot = dst
        .get_mut(offset..offset + 2)
        .ok_or(ZeroPageError::DestinationTooSmall)?;
    slot.copy_from_slice(&bytes);
    Ok(())
}

fn write_u32(dst: &mut [u8], offset: usize, value: u32) -> Result<(), ZeroPageError> {
    let bytes = value.to_le_bytes();
    let slot = dst
        .get_mut(offset..offset + 4)
        .ok_or(ZeroPageError::DestinationTooSmall)?;
    slot.copy_from_slice(&bytes);
    Ok(())
}

fn write_u64(dst: &mut [u8], offset: usize, value: u64) -> Result<(), ZeroPageError> {
    let bytes = value.to_le_bytes();
    let slot = dst
        .get_mut(offset..offset + 8)
        .ok_or(ZeroPageError::DestinationTooSmall)?;
    slot.copy_from_slice(&bytes);
    Ok(())
}

/// Bounds-checked little-endian read helpers.
fn read_u8(src: &[u8], offset: usize) -> Result<u8, ZeroPageError> {
    src.get(offset).copied().ok_or(ZeroPageError::InvalidHeader)
}

fn read_u16(src: &[u8], offset: usize) -> Result<u16, ZeroPageError> {
    let bytes = src
        .get(offset..offset + 2)
        .ok_or(ZeroPageError::InvalidHeader)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(src: &[u8], offset: usize) -> Result<u32, ZeroPageError> {
    let bytes = src
        .get(offset..offset + 4)
        .ok_or(ZeroPageError::InvalidHeader)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(src: &[u8], offset: usize) -> Result<u64, ZeroPageError> {
    let bytes = src
        .get(offset..offset + 8)
        .ok_or(ZeroPageError::InvalidHeader)?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}
