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

//! s9vm : generic guest-firmware images (SeaBIOS and other BIOS ROMs).
//!
//! A world can boot either the s9vm stub firmware built by [`biosrom`] or a
//! **real firmware image** supplied by the caller. This module owns the second
//! path and makes it reusable: it validates a flat BIOS image and its optional
//! VGA option ROM, places them at the PC-compatible addresses, and returns the
//! reset state the vCPU must start from.
//!
//! # Image kinds
//!
//! | Kind | Layout | Validation |
//! |---|---|---|
//! | BIOS | flat image ending at `0x10_0000` | power-of-two size, reset vector at `size - 16` |
//! | option ROM | starts at `0xC_0000` | `0x55AA` signature, size code, checksum zero |
//!
//! A **BIOS image** is not an option ROM: QEMU-style BIOSes such as SeaBIOS
//! carry no `0x55AA` trailer. The classic x86 reset vector is the far jump at
//! `0xF000:0xFFF0` (linear `0xFFFF0`), which is the 16 bytes at the end of the
//! image; [`validate_bios`] checks that jump and [`FirmwareLayout`] exposes the
//! linear address the vCPU must start at.
//!
//! # Example
//!
//! ```ignore
//! let layout = firmware::install_seabios(&mut memory, firmware::FirmwareConfig::freedos())?;
//! let guest = layout.reset_state();
//! ```
//!
//! The caller maps the memory windows first: the BIOS at
//! `layout.bios_base..0x10_0000`, the option ROM at
//! `layout.option_rom_base..+option_rom_len`, and the low RAM the firmware
//! sizes from CMOS. Nothing in this module touches the world: it only writes
//! through [`RomMemory`].

use alloc::{vec, vec::Vec};

use super::biosrom::{RomMemory, SECTOR_SIZE};

/// Top of the 1 MiB legacy address space; the BIOS image ends here.
pub const BIOS_TOP: u32 = 0x10_0000;
/// Conventional base of the option-ROM scan window.
pub const OPTION_ROM_BASE: u32 = 0xC_0000;
/// End of the option-ROM scan window (the BIOS window starts here).
pub const OPTION_ROM_END: u32 = 0xF_0000;
/// Smallest accepted BIOS image (32 KiB).
pub const MIN_BIOS_LEN: usize = 0x8000;
/// Largest accepted BIOS image (256 KiB).
pub const MAX_BIOS_LEN: usize = 0x4_0000;
/// Number of bytes at the end of a BIOS image holding the reset vector.
pub const RESET_VECTOR_LEN: usize = 16;
/// Real-mode segment of the reset vector.
pub const RESET_SEGMENT: u16 = 0xF000;
/// Instruction pointer of the reset vector inside [`RESET_SEGMENT`].
pub const RESET_IP: u16 = 0xFFF0;
/// Linear address of the reset vector (`0xF000:0xFFF0`).
pub const RESET_LINEAR: u32 = 0xFFFF0;
/// Option-ROM signature.
pub const OPTION_ROM_SIGNATURE: [u8; 2] = [0x55, 0xAA];
/// Offset of the option-ROM size code, in 512-byte units.
pub const OPTION_ROM_SIZE_OFFSET: usize = 2;
/// Offset of the option-ROM initialisation entry point.
pub const OPTION_ROM_ENTRY_OFFSET: usize = 3;
/// CMOS register holding the floppy drive types (high nibble = drive A).
pub const CMOS_FLOPPY_TYPE: u8 = 0x10;
/// CMOS register holding the low byte of the extended-memory size.
pub const CMOS_EXTMEM_LOW: u8 = 0x30;
/// CMOS register holding the high byte of the extended-memory size.
pub const CMOS_EXTMEM_HIGH: u8 = 0x31;
/// CMOS register holding the high nibble of the QEMU/SeaBIOS boot order.
pub const CMOS_BOOTFLAG1: u8 = 0x38;
/// CMOS register holding the low byte of the QEMU/SeaBIOS boot order.
pub const CMOS_BOOTFLAG2: u8 = 0x3D;
/// Boot-order value selecting the floppy first (`1` in the first nibble).
pub const BOOT_ORDER_FLOPPY_FIRST: u8 = 0x01;
/// CMOS value advertising one 1.44 MiB drive as drive A (`4 << 4`).
pub const FLOPPY_TYPE_1_44M: u8 = 0x40;

/// SeaBIOS 1.17.0 flat BIOS image (`bios.bin`, 256 KiB).
///
/// Provenance, checksums and licence are documented in
/// `workspace/assets/firmware/README.md`.
pub fn seabios_image() -> &'static [u8] {
    include_bytes!("../../../assets/firmware/seabios-1.17.0.bin")
}

/// SeaVGABIOS standard-VGA option ROM shipped with SeaBIOS 1.17.0.
pub fn seabios_vga_rom() -> &'static [u8] {
    include_bytes!("../../../assets/firmware/seabios-vgabios-stdvga-1.17.0.bin")
}

/// Why a firmware image was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareError {
    /// The image is empty or smaller than [`MIN_BIOS_LEN`].
    TooSmall,
    /// The image is larger than [`MAX_BIOS_LEN`].
    TooLarge,
    /// The BIOS size is not a power of two.
    NotPowerOfTwo,
    /// The last 16 bytes are not a `FAR JMP 0xF000:xxxx` reset vector.
    BadResetVector,
    /// The option ROM does not start with `0x55AA`.
    BadOptionRomSignature,
    /// The option ROM size code does not fit the image.
    BadOptionRomSize,
    /// The option ROM checksum is not zero (modulo 256).
    BadOptionRomChecksum,
    /// The BIOS image and the option ROM would occupy the same addresses.
    OverlappingImages,
    /// The target memory refused a write.
    WriteFailed,
}

impl FirmwareError {
    /// Human-readable reason, used in the kernel diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TooSmall => "firmware image too small",
            Self::TooLarge => "firmware image too large",
            Self::NotPowerOfTwo => "firmware image size is not a power of two",
            Self::BadResetVector => "firmware reset vector is invalid",
            Self::BadOptionRomSignature => "option ROM signature is invalid",
            Self::BadOptionRomSize => "option ROM size code is invalid",
            Self::BadOptionRomChecksum => "option ROM checksum is invalid",
            Self::OverlappingImages => "firmware images overlap",
            Self::WriteFailed => "firmware memory write failed",
        }
    }
}

/// Validated BIOS image description.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BiosInfo {
    /// Image length in bytes (power of two).
    pub len: u32,
    /// Guest-physical base the image must be copied to.
    pub base: u32,
    /// Far-jump target of the reset vector, relative to [`RESET_SEGMENT`].
    pub reset_offset: u16,
    /// Modulo-256 sum of the image (QEMU-style BIOSes are not required to be
    /// zero, so this is informational).
    pub checksum: u8,
}

/// Validated option-ROM description.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptionRomInfo {
    /// Effective length declared by the size code, in bytes.
    pub len: u32,
    /// Guest-physical base the ROM must be copied to.
    pub base: u32,
    /// Initialisation entry point, relative to [`OPTION_ROM_BASE`].
    pub entry: u16,
}

/// Result of installing a firmware image in a world.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirmwareLayout {
    /// Validated BIOS image.
    pub bios: BiosInfo,
    /// VGA option ROM, when one was installed.
    pub option_rom: Option<OptionRomInfo>,
    /// CMOS floppy-drive type written by the caller.
    pub cmos_floppy_type: u8,
    /// Extended memory advertised to the firmware, in KiB (above 1 MiB).
    pub extended_memory_kib: u16,
}

impl FirmwareLayout {
    /// Linear address of the first instruction the vCPU executes.
    pub const fn reset_linear(&self) -> u32 {
        RESET_LINEAR
    }

    /// Real-mode segment of the reset state.
    pub const fn reset_segment(&self) -> u16 {
        RESET_SEGMENT
    }

    /// Real-mode instruction pointer of the reset state.
    pub const fn reset_ip(&self) -> u16 {
        RESET_IP
    }

    /// True when `gpa` lies inside the installed BIOS image.
    pub const fn contains_bios(&self, gpa: u32) -> bool {
        gpa >= self.bios.base && gpa < BIOS_TOP
    }
}

/// Tunables a firmware image needs from the machine description.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirmwareConfig {
    /// CMOS `0x10` value: high nibble = drive A type, low nibble = drive B.
    pub cmos_floppy_type: u8,
    /// Extended memory above 1 MiB, in KiB. SeaBIOS derives `RamSize` from
    /// CMOS `0x30`/`0x31` when no fw_cfg channel is present.
    pub extended_memory_kib: u16,
    /// Install the bundled SeaVGABIOS option ROM at [`OPTION_ROM_BASE`].
    pub install_vga_rom: bool,
}

impl FirmwareConfig {
    /// Configuration used by the FreeDOS test world: one 1.44 MiB floppy and
    /// 3 MiB of extended memory (a 4 MiB machine).
    pub const fn freedos() -> Self {
        Self {
            cmos_floppy_type: FLOPPY_TYPE_1_44M,
            extended_memory_kib: 3 * 1024,
            install_vga_rom: true,
        }
    }

    /// CMOS `0x30`/`0x31` bytes encoding [`Self::extended_memory_kib`].
    ///
    /// SeaBIOS computes `(low << 10) | (high << 18) + 1 MiB`; the encoding is
    /// therefore a 16-bit count in KiB split as `low` (1 KiB units) and
    /// `high` (256 KiB units).
    pub const fn extmem_cmos(self) -> (u8, u8) {
        let kib = self.extended_memory_kib as u32;
        let low = (kib & 0xFF) as u8;
        let high = ((kib >> 8) & 0xFF) as u8;
        (low, high)
    }
}

impl Default for FirmwareConfig {
    fn default() -> Self {
        Self::freedos()
    }
}

/// Validates a flat BIOS image and computes its placement.
///
/// The image must be a power-of-two length between [`MIN_BIOS_LEN`] and
/// [`MAX_BIOS_LEN`] and end with a `FAR JMP 0xF000:xxxx` reset vector, which is
/// the architectural x86 reset entry. The image is placed so that it **ends**
/// at [`BIOS_TOP`]; the official 256 KiB SeaBIOS therefore lands at `0xC_0000`
/// and leaves its first 64 KiB zero-filled for option ROMs.
pub fn validate_bios(image: &[u8]) -> Result<BiosInfo, FirmwareError> {
    let len = image.len();
    if len < MIN_BIOS_LEN {
        return Err(FirmwareError::TooSmall);
    }
    if len > MAX_BIOS_LEN {
        return Err(FirmwareError::TooLarge);
    }
    if !len.is_power_of_two() {
        return Err(FirmwareError::NotPowerOfTwo);
    }
    let reset = &image[len - RESET_VECTOR_LEN..];
    // `EA off_lo off_hi seg_lo seg_hi`: far jump to F000:offset.
    if reset[0] != 0xEA || reset[3] != 0x00 || reset[4] != 0xF0 {
        return Err(FirmwareError::BadResetVector);
    }
    let reset_offset = u16::from_le_bytes([reset[1], reset[2]]);
    Ok(BiosInfo {
        len: len as u32,
        base: BIOS_TOP - len as u32,
        reset_offset,
        checksum: checksum(image),
    })
}

/// Validates an option ROM and computes its placement.
///
/// The size code at offset 2 is in 512-byte units. Only the declared portion
/// is checksummed and installed, which is what the PC option-ROM scan does.
pub fn validate_option_rom(image: &[u8]) -> Result<OptionRomInfo, FirmwareError> {
    if image.len() < SECTOR_SIZE || image[..2] != OPTION_ROM_SIGNATURE {
        return Err(FirmwareError::BadOptionRomSignature);
    }
    let units = u32::from(image[OPTION_ROM_SIZE_OFFSET]);
    let len = units * SECTOR_SIZE as u32;
    if len == 0 || len as usize > image.len() {
        return Err(FirmwareError::BadOptionRomSize);
    }
    if checksum(&image[..len as usize]) != 0 {
        return Err(FirmwareError::BadOptionRomChecksum);
    }
    let entry = u16::from_le_bytes([
        image[OPTION_ROM_ENTRY_OFFSET],
        image[OPTION_ROM_ENTRY_OFFSET + 1],
    ]);
    Ok(OptionRomInfo {
        len,
        base: OPTION_ROM_BASE,
        entry,
    })
}

/// Installs a validated BIOS image and an optional VGA option ROM.
///
/// The BIOS is written at `bios.base`; the option ROM at
/// [`OPTION_ROM_BASE`]. Both ranges must already be mapped writable in the
/// world, and the caller must map the RAM the returned configuration
/// describes before entering the guest.
pub fn install(
    memory: &mut impl RomMemory,
    image: &[u8],
    option_rom: Option<&[u8]>,
    config: FirmwareConfig,
) -> Result<FirmwareLayout, FirmwareError> {
    let bios = validate_bios(image)?;
    let option_info = match (config.install_vga_rom, option_rom) {
        (true, Some(rom)) => {
            let info = validate_option_rom(rom)?;
            if info.base + info.len > OPTION_ROM_END {
                return Err(FirmwareError::BadOptionRomSize);
            }
            if info.base + info.len > bios.base && info.base < BIOS_TOP {
                // A 256 KiB BIOS starts at 0xC0000 and covers the option-ROM
                // window. The official SeaBIOS image leaves that prefix
                // zero-filled: an option ROM may live there, but only if the
                // bytes it replaces are unused padding.
                let start = (info.base - bios.base) as usize;
                let end = start + info.len as usize;
                let Some(padding) = image.get(start..end) else {
                    return Err(FirmwareError::OverlappingImages);
                };
                if padding.iter().any(|byte| *byte != 0) {
                    return Err(FirmwareError::OverlappingImages);
                }
            }
            Some(info)
        }
        _ => None,
    };
    if !memory.write(bios.base, image) {
        return Err(FirmwareError::WriteFailed);
    }
    let option_rom = match (option_info, option_rom) {
        (Some(info), Some(rom)) => {
            if !memory.write(info.base, &rom[..info.len as usize]) {
                return Err(FirmwareError::WriteFailed);
            }
            Some(info)
        }
        _ => None,
    };
    Ok(FirmwareLayout {
        bios,
        option_rom,
        cmos_floppy_type: config.cmos_floppy_type,
        extended_memory_kib: config.extended_memory_kib,
    })
}

/// Installs the bundled SeaBIOS images with the FreeDOS configuration.
pub fn install_seabios(
    memory: &mut impl RomMemory,
    config: FirmwareConfig,
) -> Result<FirmwareLayout, FirmwareError> {
    install(memory, seabios_image(), Some(seabios_vga_rom()), config)
}

/// Modulo-256 sum of `bytes`.
pub fn checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte))
}

/// Reads the validated reset vector bytes as `(offset, segment)`.
///
/// Useful for diagnostics and host tests; the installer already checked them.
pub fn reset_vector(image: &[u8]) -> Option<(u16, u16)> {
    let info = validate_bios(image).ok()?;
    Some((info.reset_offset, RESET_SEGMENT))
}

/// Builds a flat zero image with the given BIOS placed at its final address.
///
/// Host-test helper: the kernel installs into world memory directly.
pub fn flat_image_with_bios(image: &[u8]) -> Result<Vec<u8>, FirmwareError> {
    let info = validate_bios(image)?;
    let mut flat = vec![0u8; BIOS_TOP as usize];
    flat[info.base as usize..].copy_from_slice(image);
    Ok(flat)
}
