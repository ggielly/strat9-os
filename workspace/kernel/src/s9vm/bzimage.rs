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

//! s9vm — boot-protocol image ("bzImage") parser and load plan.
//!
//! A boot-protocol image is the classic x86 operating-system image: a real-mode
//! *setup* part followed by a *protected-mode* part (the compressed kernel).
//! The loader parses a fixed header embedded in the setup part (starting at
//! file offset [`SETUP_HEADER_OFFSET`]), validates it, loads the setup part and
//! the protected-mode part at guest-physical addresses and enters the kernel
//! through the 64-bit entry point.
//!
//! The authoritative field offsets come from the upstream
//! `Documentation/arch/x86/boot.rst` description of the x86 boot protocol; the
//! module documents every offset it reads. Fields that this loader does not
//! support (for example `handover_offset` at `0x264` and
//! `kernel_info_offset` at `0x268`) are deliberately not decoded: the header
//! is only required to be long enough for the last field used here, `init_size`
//! at `0x260`.
//!
//! # Header fields decoded (little-endian)
//!
//! | Offset | Size | Field | Use |
//! |---|---|---|---|
//! | `0x1F1` | 1 | `setup_sects` | number of setup sectors after the boot sector (`0` means `4`) |
//! | `0x1FE` | 2 | `boot_flag` | must be `0xAA55` |
//! | `0x202` | 4 | `header` | must be `"HdrS"` (`0x5372_6448`) |
//! | `0x206` | 2 | `version` | boot protocol version, (`major << 8) \| minor` |
//! | `0x210` | 1 | `type_of_loader` | loader identifier (exposed, not interpreted) |
//! | `0x211` | 1 | `loadflags` | [`LOADED_HIGH`], [`KASLR_FLAG`], [`QUIET_FLAG`], [`KEEP_SEGMENTS`] |
//! | `0x214` | 4 | `code32_start` | protected-mode kernel load address (`0` means `0x10_0000`) |
//! | `0x22C` | 4 | `initrd_addr_max` | highest address the kernel accepts for the initrd (exposed) |
//! | `0x230` | 4 | `kernel_alignment` | relocation alignment (`0` means `2 MiB`) |
//! | `0x234` | 1 | `relocatable_kernel` | non-zero when the kernel may be relocated |
//! | `0x235` | 1 | `min_alignment` | minimum relocation alignment (`0` means "unspecified") |
//! | `0x236` | 2 | `xloadflags` | [`XLF_KERNEL_64`], [`XLF_CAN_BE_LOADED_ABOVE_4G`], [`XLF_EFI_HANDOVER`] |
//! | `0x238` | 4 | `cmdline_size` | command-line buffer size accepted by the kernel |
//! | `0x23C` | 4 | `hardware_subarch` | must be [`SUBARCH_PC`] for this loader |
//! | `0x248` | 4 | `payload_offset` | compressed payload offset in the file (optional) |
//! | `0x24C` | 4 | `payload_length` | compressed payload length in the file (optional) |
//! | `0x250` | 8 | `setup_data` | guest-physical address of the first `setup_data` node |
//! | `0x258` | 8 | `pref_address` | preferred load address of a relocatable kernel |
//! | `0x260` | 4 | `init_size` | memory window the kernel needs once running |
//!
//! # File layout
//!
//! The protected-mode kernel starts at `(setup_sects + 1) * 512` bytes from the
//! beginning of the file (the boot sector is the first 512-byte unit). Its
//! length is the rest of the file. `setup_sects == 0` is the architectural
//! shorthand for four setup sectors.
//!
//! # 64-bit entry contract
//!
//! When [`XLF_KERNEL_64`] is set, the entry point is the loaded kernel base
//! plus [`ENTRY_OFFSET_64`] (`0x200`). The loader must enter with:
//!
//! - the CPU in 64-bit mode with paging enabled;
//! - an identity mapping covering the kernel window, the `boot_params` zero
//!   page and the command-line buffer ([`LoadPlan::required_identity_span`]);
//! - a GDT whose `0x10` entry is a 4 GiB flat code descriptor
//!   (`__BOOT_CS`, execute/read) and whose `0x18` entry is a 4 GiB flat data
//!   descriptor (`__BOOT_DS`, read/write); `CS = 0x10`, `DS = ES = SS = 0x18`;
//! - interrupts disabled;
//! - `%rsi` = guest-physical base address of `struct boot_params`.
//!
//! The 32-bit entry point is the loaded kernel base itself; [`EntryPoint`]
//! keeps both variants so the selection is explicit and documented.
//!
//! # Load plan conventions
//!
//! The plan produced here uses the s9vm loader conventions for the auxiliary
//! buffers: the setup part is loaded at [`SETUP_GPA`], `boot_params` at
//! [`BOOT_PARAMS_GPA`] and the command-line buffer at [`CMDLINE_GPA`]. They are
//! independent of the kernel base and are part of the identity span.
//!
//! This module is **pure**: it parses and validates the image bytes and
//! computes the plan without allocating and without touching guest memory.
//! Every rejection is a typed [`BzError`]; malformed input can never make the
//! parser panic, and all address arithmetic is checked.
//!
//! Testable on the host (L2 tests).

/// File offset of `setup_sects` (first byte of the setup header).
pub const SETUP_HEADER_OFFSET: usize = 0x1F1;
/// Minimum file length to decode every field used by this module
/// (`init_size` ends at `0x264`).
pub const HEADER_END: usize = 0x260 + 4;
/// Real-mode sector size.
pub const SECTOR_SIZE: usize = 512;
/// Architectural default when `setup_sects` is zero.
pub const DEFAULT_SETUP_SECTORS: u8 = 4;
/// Expected `boot_flag` value.
pub const BOOT_FLAG: u16 = 0xAA55;
/// `"HdrS"` read as a little-endian `u32`.
pub const HEADER_MAGIC: u32 = 0x5372_6448;
/// Lowest supported boot protocol version (`2.00`).
pub const MIN_HEADER_VERSION: u16 = 0x0200;
/// Highest supported boot protocol version (`2.255`).
pub const MAX_HEADER_VERSION: u16 = 0x02FF;
/// Default protected-mode load address when `code32_start` is zero (`1 MiB`).
pub const DEFAULT_CODE32_START: u64 = 0x0010_0000;
/// Default relocation alignment when `kernel_alignment` is zero (`2 MiB`).
pub const DEFAULT_KERNEL_ALIGNMENT: u64 = 0x0020_0000;
/// Offset of the 64-bit entry point inside the protected-mode kernel.
pub const ENTRY_OFFSET_64: u64 = 0x200;
/// Maximum command-line buffer accepted by this loader.
pub const MAX_CMDLINE_SIZE: u32 = 4096;
/// Maximum number of `setup_data` nodes walked (safety bound).
pub const MAX_SETUP_DATA_ENTRIES: u32 = 64;
/// Maximum `setup_data` payload length accepted (64 MiB, safety bound).
pub const MAX_SETUP_DATA_LEN: u32 = 64 * 1024 * 1024;
/// Size of one `setup_data` header: `next: u64`, `type: u32`, `len: u32`.
pub const SETUP_DATA_HEADER_SIZE: u64 = 16;
/// Alignment required of a `setup_data` node address.
pub const SETUP_DATA_ALIGN: u64 = 8;
/// End of the 32-bit address space: loading above it requires
/// [`XLF_CAN_BE_LOADED_ABOVE_4G`].
pub const FOUR_GIB: u64 = 1 << 32;

/// `loadflags` bit 0: the protected-mode kernel is loaded above `1 MiB`.
pub const LOADED_HIGH: u8 = 1 << 0;
/// `loadflags` bit 1: the kernel accepts a randomized load address.
pub const KASLR_FLAG: u8 = 1 << 1;
/// `loadflags` bit 5: the kernel should be quiet on the console.
pub const QUIET_FLAG: u8 = 1 << 5;
/// `loadflags` bit 6: the loader preserved the segment registers.
pub const KEEP_SEGMENTS: u8 = 1 << 6;

/// `xloadflags` bit 0: a legacy 64-bit entry point exists at
/// [`ENTRY_OFFSET_64`] from the loaded kernel base.
pub const XLF_KERNEL_64: u16 = 1 << 0;
/// `xloadflags` bit 1: the kernel can be loaded above the 4 GiB boundary.
pub const XLF_CAN_BE_LOADED_ABOVE_4G: u16 = 1 << 1;
/// `xloadflags` bits 2..=6: EFI handover protocol support (exposed only).
pub const XLF_EFI_HANDOVER: u16 = 0b0011_1110;

/// `hardware_subarch` value of the standard PC sub-architecture.
pub const SUBARCH_PC: u32 = 0;

/// Guest-physical address where the setup part is loaded (loader convention).
pub const SETUP_GPA: u64 = 0x0001_0000;
/// Guest-physical address of the `boot_params` zero page (loader convention).
pub const BOOT_PARAMS_GPA: u64 = 0x0000_7000;
/// Size of the `boot_params` zero page.
pub const BOOT_PARAMS_SIZE: u64 = 4096;
/// Guest-physical address of the command-line buffer (loader convention).
pub const CMDLINE_GPA: u64 = 0x0002_0000;

/// Reasons why a boot-protocol image is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BzError {
    /// The file is shorter than the setup header fields this loader reads.
    TooShort,
    /// The `boot_flag` field is not `0xAA55`.
    BadBootFlag,
    /// The `header` magic is not `"HdrS"`.
    BadMagic,
    /// The boot protocol version is outside [`MIN_HEADER_VERSION`]..=
    /// [`MAX_HEADER_VERSION`].
    UnsupportedVersion(u16),
    /// `loadflags.LOADED_HIGH` is clear: a 64-bit kernel is loaded high.
    NotLoadedHigh,
    /// `xloadflags.XLF_KERNEL_64` is clear: no 64-bit entry point.
    Not64Bit,
    /// The protected-mode kernel starts past the end of the file.
    SetupTruncated,
    /// The protected-mode kernel is too small to contain the 64-bit entry.
    ProtectedModeTooSmall,
    /// The protected-mode kernel is larger than `init_size`.
    ProtectedModeTooLarge,
    /// A relocation alignment is not a power of two, or the load address is
    /// not aligned.
    BadAlignment,
    /// `init_size` is zero.
    BadInitSize,
    /// `pref_address` is below `code32_start`.
    BadPreferredAddress,
    /// The command-line size is zero or larger than [`MAX_CMDLINE_SIZE`].
    BadCmdlineSize,
    /// `hardware_subarch` is not [`SUBARCH_PC`].
    UnsupportedSubarch,
    /// The optional compressed payload extends past the end of the file.
    PayloadOutOfBounds,
    /// The requested load address is below `code32_start`.
    BadLoadAddress,
    /// A non-relocatable kernel was asked to load somewhere other than its
    /// required address.
    RelocationNotPossible,
    /// The load window extends past 4 GiB without
    /// [`XLF_CAN_BE_LOADED_ABOVE_4G`].
    Above4GNotSupported,
    /// An address or length computation overflowed 64 bits.
    AddressOverflow,
    /// A `setup_data` node header could not be read through the supplied
    /// reader (unmapped or out of bounds).
    SetupDataOutOfBounds,
    /// A `setup_data` node address is not [`SETUP_DATA_ALIGN`]-aligned.
    SetupDataBadAlignment,
    /// A `setup_data` payload length exceeds [`MAX_SETUP_DATA_LEN`].
    SetupDataBadLength,
    /// The `setup_data` list loops or is not in increasing address order.
    SetupDataCycle,
    /// The `setup_data` list has more than [`MAX_SETUP_DATA_ENTRIES`] nodes.
    SetupDataTooManyEntries,
    /// The required identity span is not contained in the supplied guest
    /// span.
    OutsideGuestSpan,
}

/// The 64-bit or 32-bit entry point of a boot-protocol image.
///
/// The 64-bit variant is the one used by this loader; the 32-bit variant is
/// produced for images without [`XLF_KERNEL_64`] and is kept so callers can
/// handle both boot protocols explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryPoint {
    /// 64-bit entry point at the loaded kernel base plus
    /// [`ENTRY_OFFSET_64`]. The CPU must already be in 64-bit mode with paging
    /// enabled (see the module documentation for the full entry contract).
    Bits64 {
        /// Guest-physical entry address.
        gpa: u64,
    },
    /// 32-bit entry point at the loaded kernel base.
    Bits32 {
        /// Guest-physical entry address.
        gpa: u64,
    },
}

impl EntryPoint {
    /// Guest-physical address of the entry point.
    pub const fn gpa(self) -> u64 {
        match self {
            Self::Bits64 { gpa } | Self::Bits32 { gpa } => gpa,
        }
    }

    /// True for the 64-bit entry point.
    pub const fn is_64(self) -> bool {
        matches!(self, Self::Bits64 { .. })
    }
}

/// Source of guest memory used to walk the `setup_data` list.
///
/// The parser works on a file image only; the `setup_data` list lives in guest
/// memory at guest-physical addresses, so the walker asks a reader for the
/// 16-byte header of each node. The reader must validate bounds itself and
/// return `false` when the address is not readable.
pub trait SetupDataReader {
    /// Copies [`SETUP_DATA_HEADER_SIZE`] bytes from `gpa` into `out` and
    /// returns `true` on success.
    fn read_header(&mut self, gpa: u64, out: &mut [u8; SETUP_DATA_HEADER_SIZE as usize]) -> bool;
}

/// What a successful `setup_data` walk found.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SetupDataSummary {
    /// Number of chained nodes.
    pub entries: u32,
    /// Total payload bytes across the nodes.
    pub data_bytes: u64,
    /// Guest-physical address of the first node (0 when the list is empty).
    pub start_gpa: u64,
    /// End (exclusive) guest-physical address of the last node.
    pub end_gpa: u64,
}

impl SetupDataSummary {
    /// Guest-physical span covered by the list, `None` when it is empty.
    pub const fn span(&self) -> Option<(u64, u64)> {
        if self.entries == 0 {
            None
        } else {
            Some((self.start_gpa, self.end_gpa))
        }
    }
}

/// A parsed boot-protocol image.
///
/// Borrows the image bytes; the load plan is computed from the decoded header
/// on demand. Copying the structure is cheap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BzImage<'a> {
    bytes: &'a [u8],
    version: u16,
    type_of_loader: u8,
    loadflags: u8,
    xloadflags: u16,
    setup_sects: u8,
    code32_start: u64,
    initrd_addr_max: u32,
    kernel_alignment: u64,
    min_alignment: u8,
    relocatable: bool,
    cmdline_size: u32,
    hardware_subarch: u32,
    payload_offset: u32,
    payload_length: u32,
    setup_data: u64,
    pref_address: u64,
    init_size: u32,
    kernel_offset: u64,
}

impl<'a> BzImage<'a> {
    /// Parses and validates a boot-protocol image.
    ///
    /// Never panics: malformed input yields a [`BzError`]. The protected-mode
    /// kernel and the optional payload are bounds-checked against the file;
    /// the `setup_data` list is validated separately because it lives in guest
    /// memory ([`Self::walk_setup_data`]).
    pub fn parse(bytes: &'a [u8]) -> Result<Self, BzError> {
        if bytes.len() < HEADER_END {
            return Err(BzError::TooShort);
        }
        if read_u16(bytes, 0x1FE) != BOOT_FLAG {
            return Err(BzError::BadBootFlag);
        }
        if read_u32(bytes, 0x202) != HEADER_MAGIC {
            return Err(BzError::BadMagic);
        }
        let version = read_u16(bytes, 0x206);
        if version < MIN_HEADER_VERSION || version > MAX_HEADER_VERSION {
            return Err(BzError::UnsupportedVersion(version));
        }
        let type_of_loader = read_u8(bytes, 0x210);
        let loadflags = read_u8(bytes, 0x211);
        if loadflags & LOADED_HIGH == 0 {
            return Err(BzError::NotLoadedHigh);
        }
        let xloadflags = read_u16(bytes, 0x236);
        if xloadflags & XLF_KERNEL_64 == 0 {
            return Err(BzError::Not64Bit);
        }

        // `0` is the architectural shorthand for four setup sectors.
        let raw_setup_sects = read_u8(bytes, 0x1F1);
        let setup_sects = if raw_setup_sects == 0 {
            DEFAULT_SETUP_SECTORS
        } else {
            raw_setup_sects
        };
        let kernel_offset = (u64::from(setup_sects) + 1) * SECTOR_SIZE as u64;
        let file_len = bytes.len() as u64;
        if kernel_offset > file_len {
            return Err(BzError::SetupTruncated);
        }
        let protected_mode_bytes = file_len - kernel_offset;
        // The 64-bit entry point must be inside the loaded protected-mode part.
        if protected_mode_bytes <= ENTRY_OFFSET_64 {
            return Err(BzError::ProtectedModeTooSmall);
        }

        let raw_code32_start = read_u32(bytes, 0x214);
        let code32_start = if raw_code32_start == 0 {
            DEFAULT_CODE32_START
        } else {
            u64::from(raw_code32_start)
        };

        let raw_alignment = read_u32(bytes, 0x230);
        let kernel_alignment = if raw_alignment == 0 {
            DEFAULT_KERNEL_ALIGNMENT
        } else {
            u64::from(raw_alignment)
        };
        if !kernel_alignment.is_power_of_two() {
            return Err(BzError::BadAlignment);
        }
        let min_alignment = read_u8(bytes, 0x235);
        // The field holds the minimum alignment **as a power of two**, i.e. the
        // exponent (`12` means 4 KiB), not the alignment itself; only an
        // exponent that cannot describe a usable alignment is rejected.
        if min_alignment > 63 {
            return Err(BzError::BadAlignment);
        }

        let init_size = read_u32(bytes, 0x260);
        if init_size == 0 {
            return Err(BzError::BadInitSize);
        }
        if protected_mode_bytes > u64::from(init_size) {
            return Err(BzError::ProtectedModeTooLarge);
        }

        let pref_address = read_u64(bytes, 0x258);
        if pref_address != 0 && pref_address < code32_start {
            return Err(BzError::BadPreferredAddress);
        }

        let cmdline_size = read_u32(bytes, 0x238);
        if cmdline_size == 0 || cmdline_size > MAX_CMDLINE_SIZE {
            return Err(BzError::BadCmdlineSize);
        }

        let hardware_subarch = read_u32(bytes, 0x23C);
        if hardware_subarch != SUBARCH_PC {
            return Err(BzError::UnsupportedSubarch);
        }

        let payload_offset = read_u32(bytes, 0x248);
        let payload_length = read_u32(bytes, 0x24C);
        if payload_length != 0 {
            let payload_end = u64::from(payload_offset)
                .checked_add(u64::from(payload_length))
                .ok_or(BzError::AddressOverflow)?;
            if payload_end > file_len {
                return Err(BzError::PayloadOutOfBounds);
            }
        }

        let setup_data = read_u64(bytes, 0x250);
        let initrd_addr_max = read_u32(bytes, 0x22C);
        let relocatable = read_u8(bytes, 0x234) != 0;

        Ok(Self {
            bytes,
            version,
            type_of_loader,
            loadflags,
            xloadflags,
            setup_sects,
            code32_start,
            initrd_addr_max,
            kernel_alignment,
            min_alignment,
            relocatable,
            cmdline_size,
            hardware_subarch,
            payload_offset,
            payload_length,
            setup_data,
            pref_address,
            init_size,
            kernel_offset,
        })
    }

    /// Number of setup sectors, with the `0 -> 4` rule already applied.
    pub const fn setup_sects(&self) -> u8 {
        self.setup_sects
    }

    /// File length of the setup part: boot sector plus setup sectors.
    pub const fn setup_bytes(&self) -> u64 {
        self.kernel_offset
    }

    /// File offset of the protected-mode kernel.
    pub const fn kernel_offset(&self) -> u64 {
        self.kernel_offset
    }

    /// Length of the protected-mode kernel inside the file.
    pub fn protected_mode_bytes(&self) -> u64 {
        self.bytes.len() as u64 - self.kernel_offset
    }

    /// Protected-mode kernel bytes.
    pub fn protected_mode(&self) -> &'a [u8] {
        &self.bytes[self.kernel_offset as usize..]
    }

    /// Boot protocol version (`major << 8 | minor`).
    pub const fn version(&self) -> u16 {
        self.version
    }

    /// Major protocol version.
    pub const fn version_major(&self) -> u8 {
        (self.version >> 8) as u8
    }

    /// Minor protocol version.
    pub const fn version_minor(&self) -> u8 {
        (self.version & 0xFF) as u8
    }

    /// Loader identifier written by the boot loader.
    pub const fn type_of_loader(&self) -> u8 {
        self.type_of_loader
    }

    /// Raw `loadflags` byte (see [`LOADED_HIGH`], [`KASLR_FLAG`],
    /// [`QUIET_FLAG`], [`KEEP_SEGMENTS`]).
    pub const fn loadflags(&self) -> u8 {
        self.loadflags
    }

    /// True when `loadflags.LOADED_HIGH` is set.
    pub const fn loaded_high(&self) -> bool {
        self.loadflags & LOADED_HIGH != 0
    }

    /// Raw `xloadflags` word (see [`XLF_KERNEL_64`],
    /// [`XLF_CAN_BE_LOADED_ABOVE_4G`], [`XLF_EFI_HANDOVER`]).
    pub const fn xloadflags(&self) -> u16 {
        self.xloadflags
    }

    /// True when the image has the legacy 64-bit entry point.
    pub const fn has_64bit_entry(&self) -> bool {
        self.xloadflags & XLF_KERNEL_64 != 0
    }

    /// True when the kernel may be loaded above the 4 GiB boundary.
    pub const fn can_load_above_4g(&self) -> bool {
        self.xloadflags & XLF_CAN_BE_LOADED_ABOVE_4G != 0
    }

    /// Protected-mode kernel load address (`code32_start`, defaulted).
    pub const fn code32_start(&self) -> u64 {
        self.code32_start
    }

    /// Raw `initrd_addr_max` header field (0 when unset).
    pub const fn initrd_addr_max(&self) -> u32 {
        self.initrd_addr_max
    }

    /// Relocation alignment (`kernel_alignment`, defaulted).
    pub const fn kernel_alignment(&self) -> u64 {
        self.kernel_alignment
    }

    /// Raw `min_alignment` header field (0 when unset).
    pub const fn min_alignment(&self) -> u8 {
        self.min_alignment
    }

    /// True when the kernel may be relocated.
    pub const fn relocatable(&self) -> bool {
        self.relocatable
    }

    /// Command-line buffer size accepted by the kernel.
    pub const fn cmdline_size(&self) -> u32 {
        self.cmdline_size
    }

    /// Hardware sub-architecture (`0` for the standard PC).
    pub const fn hardware_subarch(&self) -> u32 {
        self.hardware_subarch
    }

    /// Optional compressed payload offset in the file.
    pub const fn payload_offset(&self) -> u32 {
        self.payload_offset
    }

    /// Optional compressed payload length in the file.
    pub const fn payload_length(&self) -> u32 {
        self.payload_length
    }

    /// Compressed payload bytes, when the header describes one.
    pub fn payload(&self) -> Option<&'a [u8]> {
        if self.payload_length == 0 {
            return None;
        }
        let start = self.payload_offset as usize;
        let end = start + self.payload_length as usize;
        self.bytes.get(start..end)
    }

    /// Guest-physical address of the first `setup_data` node (0 = none).
    pub const fn setup_data(&self) -> u64 {
        self.setup_data
    }

    /// Preferred load address (0 when the header has no preference).
    pub const fn pref_address(&self) -> u64 {
        self.pref_address
    }

    /// Memory window the kernel needs once running (0 is rejected at parse).
    pub const fn init_size(&self) -> u32 {
        self.init_size
    }

    /// Length of the image file.
    pub const fn file_len(&self) -> usize {
        self.bytes.len()
    }

    /// Computes the load plan for a caller-chosen protected-mode load address.
    ///
    /// The kernel executable is copied at `load_address`. The linked address
    /// ([`Self::code32_start`]) is always accepted; any other address must be
    /// aligned to [`Self::kernel_alignment`] (that is the alignment a loader
    /// choosing a relocation target must respect) and must not be below
    /// [`Self::code32_start`]. The *runtime* window is then:
    ///
    /// - relocatable kernel:
    ///   `runtime_start = align_up(max(load_address, pref_address), alignment)`;
    /// - non-relocatable kernel: `runtime_start = pref_address` when the
    ///   header advertises one, otherwise `load_address` (and the requested
    ///   address must match it).
    ///
    /// The memory window is `[runtime_start, runtime_start + init_size)`; its
    /// end is also the highest address the kernel may use (`initrd_max_gpa`).
    pub fn load_plan(&self, load_address: u64) -> Result<LoadPlan, BzError> {
        let alignment = self.kernel_alignment;
        if alignment == 0 || !alignment.is_power_of_two() {
            return Err(BzError::BadAlignment);
        }
        // The linked address (`code32_start`) is the conventional bzImage load
        // address and is not necessarily aligned; a loader choosing a
        // relocation target must honour the kernel alignment.
        if load_address != self.code32_start && load_address % alignment != 0 {
            return Err(BzError::BadAlignment);
        }
        if load_address < self.code32_start {
            return Err(BzError::BadLoadAddress);
        }
        let preference = if self.pref_address != 0 {
            self.pref_address
        } else {
            load_address
        };
        let runtime_start = if self.relocatable {
            let highest = load_address.max(preference);
            align_up(highest, alignment).ok_or(BzError::AddressOverflow)?
        } else {
            if load_address != preference {
                return Err(BzError::RelocationNotPossible);
            }
            preference
        };
        // The loaded copy must also stay inside the runtime window: a kernel
        // cannot be loaded above the memory it may use.
        let kernel_end = load_address
            .checked_add(self.protected_mode_bytes())
            .ok_or(BzError::AddressOverflow)?;
        let runtime_end = runtime_start
            .checked_add(u64::from(self.init_size))
            .ok_or(BzError::AddressOverflow)?;
        if kernel_end > runtime_end {
            return Err(BzError::ProtectedModeTooLarge);
        }
        let highest_used = kernel_end.max(runtime_end);
        if highest_used > FOUR_GIB && !self.can_load_above_4g() {
            return Err(BzError::Above4GNotSupported);
        }
        let entry_gpa = load_address
            .checked_add(ENTRY_OFFSET_64)
            .ok_or(BzError::AddressOverflow)?;
        Ok(LoadPlan {
            load_address,
            setup_gpa: SETUP_GPA,
            setup_bytes: self.kernel_offset,
            kernel_gpa: load_address,
            kernel_bytes: self.protected_mode_bytes(),
            init_size: self.init_size,
            runtime_start,
            runtime_end,
            initrd_max_gpa: runtime_end,
            boot_params_gpa: BOOT_PARAMS_GPA,
            boot_params_bytes: BOOT_PARAMS_SIZE,
            cmdline_gpa: CMDLINE_GPA,
            cmdline_max: self.cmdline_size,
            entry: EntryPoint::Bits64 { gpa: entry_gpa },
            entry_32_gpa: load_address,
            relocatable: self.relocatable,
            loadflags: self.loadflags,
            kernel_alignment: self.kernel_alignment,
        })
    }

    /// Load plan using the linked load address ([`Self::code32_start`]).
    pub fn default_load_plan(&self) -> Result<LoadPlan, BzError> {
        self.load_plan(self.code32_start)
    }

    /// Walks the `setup_data` linked list through `reader`.
    ///
    /// Each node is a 16-byte header (`next: u64`, `type: u32`, `len: u32`)
    /// followed by `len` payload bytes. The walk is bounded
    /// ([`MAX_SETUP_DATA_ENTRIES`]), rejects oversized payloads, unaligned or
    /// unreadable nodes, and requires node addresses to increase: the boot
    /// protocol builds the list by appending, so a node starting before the end
    /// of the previous one means a loop or an overlap. The `type` field is not
    /// interpreted (the loader only forwards the nodes); it is still read as
    /// part of the header.
    pub fn walk_setup_data(
        &self,
        reader: &mut impl SetupDataReader,
    ) -> Result<SetupDataSummary, BzError> {
        let mut summary = SetupDataSummary::default();
        let mut address = self.setup_data;
        if address == 0 {
            return Ok(summary);
        }
        summary.start_gpa = address;
        let mut header = [0u8; SETUP_DATA_HEADER_SIZE as usize];
        while address != 0 {
            if summary.entries >= MAX_SETUP_DATA_ENTRIES {
                return Err(BzError::SetupDataTooManyEntries);
            }
            if address % SETUP_DATA_ALIGN != 0 {
                return Err(BzError::SetupDataBadAlignment);
            }
            if summary.entries != 0 && address < summary.end_gpa {
                return Err(BzError::SetupDataCycle);
            }
            if !reader.read_header(address, &mut header) {
                return Err(BzError::SetupDataOutOfBounds);
            }
            let next = u64::from_le_bytes([
                header[0], header[1], header[2], header[3], header[4], header[5], header[6],
                header[7],
            ]);
            let length = u32::from_le_bytes([header[12], header[13], header[14], header[15]]);
            if length > MAX_SETUP_DATA_LEN {
                return Err(BzError::SetupDataBadLength);
            }
            let end = address
                .checked_add(SETUP_DATA_HEADER_SIZE)
                .and_then(|value| value.checked_add(u64::from(length)))
                .ok_or(BzError::AddressOverflow)?;
            summary.entries += 1;
            summary.data_bytes = summary.data_bytes.saturating_add(u64::from(length));
            summary.end_gpa = end;
            address = next;
        }
        Ok(summary)
    }
}

/// A validated load plan for a boot-protocol image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadPlan {
    /// Guest-physical address the protected-mode kernel is copied to.
    pub load_address: u64,
    /// Guest-physical address of the setup part.
    pub setup_gpa: u64,
    /// Length of the setup part (boot sector plus setup sectors).
    pub setup_bytes: u64,
    /// Guest-physical address of the protected-mode kernel (same as
    /// [`Self::load_address`]).
    pub kernel_gpa: u64,
    /// Length of the protected-mode kernel.
    pub kernel_bytes: u64,
    /// Memory window the kernel needs once running.
    pub init_size: u32,
    /// First address of the runtime window (see [`BzImage::load_plan`]).
    pub runtime_start: u64,
    /// End (exclusive) of the runtime window.
    pub runtime_end: u64,
    /// Highest address usable for the initrd (end of the runtime window).
    pub initrd_max_gpa: u64,
    /// Guest-physical address of the `boot_params` zero page.
    pub boot_params_gpa: u64,
    /// Size of the `boot_params` zero page.
    pub boot_params_bytes: u64,
    /// Guest-physical address of the command-line buffer.
    pub cmdline_gpa: u64,
    /// Command-line buffer size accepted by the kernel.
    pub cmdline_max: u32,
    /// Entry point selected for this image (64-bit for parsed images).
    pub entry: EntryPoint,
    /// 32-bit entry point address (loaded kernel base).
    pub entry_32_gpa: u64,
    /// True when the kernel may be relocated.
    pub relocatable: bool,
    /// Raw `loadflags` byte of the image.
    pub loadflags: u8,
    /// Relocation alignment required by the kernel.
    pub kernel_alignment: u64,
}

impl LoadPlan {
    /// Guest-physical address of the selected entry point.
    pub const fn entry_gpa(&self) -> u64 {
        self.entry.gpa()
    }

    /// Guest-physical identity span the loader must map before entry:
    /// the kernel window, the `boot_params` zero page and the command-line
    /// buffer.
    ///
    /// The kernel part starts at the lowest of the load address and the
    /// runtime start (a relocatable kernel may move itself) and ends at the
    /// highest of `load_address + init_size` and the runtime window end.
    pub fn required_identity_span(&self) -> (u64, u64) {
        let kernel_start = self.load_address.min(self.runtime_start);
        let kernel_end = self
            .load_address
            .saturating_add(u64::from(self.init_size))
            .max(self.runtime_end);
        let start = kernel_start.min(BOOT_PARAMS_GPA).min(CMDLINE_GPA);
        let end = kernel_end
            .max(BOOT_PARAMS_GPA.saturating_add(BOOT_PARAMS_SIZE))
            .max(CMDLINE_GPA.saturating_add(u64::from(self.cmdline_max)));
        (start, end)
    }

    /// Checks that the required identity span fits in the guest span
    /// `[span_start, span_end)`.
    pub fn validate_against(&self, span_start: u64, span_end: u64) -> Result<(), BzError> {
        let (start, end) = self.required_identity_span();
        if span_end <= span_start || start < span_start || end > span_end {
            return Err(BzError::OutsideGuestSpan);
        }
        Ok(())
    }
}

/// Rounds `value` up to the next multiple of `alignment` (power of two).
const fn align_up(value: u64, alignment: u64) -> Option<u64> {
    let mask = alignment - 1;
    match value.checked_add(mask) {
        Some(sum) => Some(sum & !mask),
        None => None,
    }
}

/// Reads a little-endian `u8` at `offset`.
///
/// The caller guarantees `offset < HEADER_END <= bytes.len()` (checked by
/// [`BzImage::parse`] before any field is read).
fn read_u8(bytes: &[u8], offset: usize) -> u8 {
    bytes[offset]
}

/// Reads a little-endian `u16` at `offset`.
fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

/// Reads a little-endian `u32` at `offset`.
fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

/// Reads a little-endian `u64` at `offset`.
fn read_u64(bytes: &[u8], offset: usize) -> u64 {
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
