//! L2: generic firmware image validation and placement (SeaBIOS assets).
//!
//! The module is pure: it only writes through `RomMemory`. The tests pin the
//! two image formats the installation handles (flat BIOS and option ROM) and
//! the exact placement a world must map.

extern crate alloc;

#[path = "../../kernel/src/s9vm/biosrom.rs"]
mod biosrom;
#[path = "../../kernel/src/s9vm/firmware.rs"]
mod firmware;

use alloc::vec;
use biosrom::RomMemory;
use firmware::{
    checksum, validate_bios, validate_option_rom, FirmwareConfig, FirmwareError, BIOS_TOP,
    OPTION_ROM_BASE, RESET_LINEAR, RESET_SEGMENT,
};

/// Flat 1 MiB guest image implementing the installer memory trait.
struct FlatMemory(Vec<u8>);

impl FlatMemory {
    fn new() -> Self {
        Self(vec![0u8; BIOS_TOP as usize])
    }
}

impl RomMemory for FlatMemory {
    fn write(&mut self, linear: u32, bytes: &[u8]) -> bool {
        let start = linear as usize;
        let Some(slot) = self.0.get_mut(start..start + bytes.len()) else {
            return false;
        };
        slot.copy_from_slice(bytes);
        true
    }

    fn read(&mut self, linear: u32, out: &mut [u8]) -> bool {
        let start = linear as usize;
        let Some(bytes) = self.0.get(start..start + out.len()) else {
            return false;
        };
        out.copy_from_slice(bytes);
        true
    }
}

#[test]
fn seabios_image_is_a_valid_flat_bios() {
    let image = firmware::seabios_image();
    let info = validate_bios(image).expect("SeaBIOS image must validate");
    assert_eq!(info.len, 0x4_0000, "256 KiB official image");
    assert_eq!(info.base, 0xC_0000, "placed just below 1 MiB");
    assert_eq!(info.checksum, checksum(image));
    // The reset vector is a far jump to F000:E05B in SeaBIOS 1.17.0.
    let reset = &image[image.len() - firmware::RESET_VECTOR_LEN..];
    assert_eq!(reset[0], 0xEA);
    assert_eq!(reset[3], 0x00);
    assert_eq!(reset[4], 0xF0);
    assert_eq!(RESET_SEGMENT, 0xF000);
    assert_eq!(RESET_LINEAR, 0xF0000 + 0xFFF0);
}

#[test]
fn seabios_vga_rom_is_a_valid_option_rom() {
    let rom = firmware::seabios_vga_rom();
    let info = validate_option_rom(rom).expect("SeaVGABIOS must validate");
    assert_eq!(info.base, OPTION_ROM_BASE);
    assert_eq!(
        info.len as usize,
        rom.len(),
        "the size code covers the image"
    );
    assert_eq!(checksum(&rom[..info.len as usize]), 0);
}

#[test]
fn install_places_both_images() {
    let mut memory = FlatMemory::new();
    let layout = firmware::install_seabios(&mut memory, FirmwareConfig::freedos())
        .expect("installation must succeed");
    assert_eq!(layout.bios.base, 0xC_0000);
    assert_eq!(layout.option_rom.expect("VGA ROM").base, 0xC_0000);
    assert_eq!(layout.reset_linear(), RESET_LINEAR);

    let image = firmware::seabios_image();
    let rom = firmware::seabios_vga_rom();
    let rom_info = validate_option_rom(rom).expect("VGA ROM");
    let mut copied = vec![0u8; image.len()];
    assert!(memory.read(layout.bios.base, &mut copied));
    // The option ROM lives in the BIOS image's zero-filled prefix.
    let end = rom_info.len as usize;
    assert_eq!(copied[..end], rom[..end]);
    assert_eq!(copied[end..], image[end..]);

    let mut reset = [0u8; firmware::RESET_VECTOR_LEN];
    assert!(memory.read(RESET_LINEAR, &mut reset));
    assert_eq!(reset[0], 0xEA);
}

#[test]
fn install_can_skip_the_vga_rom() {
    let mut memory = FlatMemory::new();
    let config = FirmwareConfig {
        install_vga_rom: false,
        ..FirmwareConfig::freedos()
    };
    let layout = firmware::install_seabios(&mut memory, config).expect("installation");
    assert!(layout.option_rom.is_none());
}

#[test]
fn invalid_images_are_rejected() {
    assert_eq!(validate_bios(&[0u8; 16]), Err(FirmwareError::TooSmall));
    // A power-of-two image without the far-jump reset vector.
    let mut image = vec![0u8; 0x8000];
    image[0x8000 - 16] = 0xEA;
    assert_eq!(validate_bios(&image), Err(FirmwareError::BadResetVector));
    // A non-power-of-two size.
    let image = vec![0u8; 0x8001];
    assert_eq!(validate_bios(&image), Err(FirmwareError::NotPowerOfTwo));

    let mut rom = vec![0u8; 0x400];
    assert_eq!(
        validate_option_rom(&rom),
        Err(FirmwareError::BadOptionRomSignature)
    );
    rom[0] = 0x55;
    rom[1] = 0xAA;
    rom[2] = 1; // 512 bytes
    rom[10] = 1; // make the checksum nonzero
    assert_eq!(
        validate_option_rom(&rom),
        Err(FirmwareError::BadOptionRomChecksum)
    );
    // Fix the checksum: every byte sums to zero modulo 256.
    rom[3] = 0u8.wrapping_sub(1);
    assert!(validate_option_rom(&rom).is_ok());
}

#[test]
fn a_256k_bios_can_share_its_zero_prefix_with_the_vga_rom() {
    // 256 KiB BIOS starts at 0xC0000 and covers the option-ROM window; the
    // official image leaves the prefix zero-filled, so the installer accepts
    // the VGA ROM there. A non-zero prefix is a real conflict.
    let mut image = vec![0u8; 0x4_0000];
    let reset = image.len() - firmware::RESET_VECTOR_LEN;
    image[reset] = 0xEA;
    image[reset + 3] = 0x00;
    image[reset + 4] = 0xF0;
    let mut memory = FlatMemory::new();
    assert!(firmware::install(
        &mut memory,
        &image,
        Some(firmware::seabios_vga_rom()),
        FirmwareConfig::freedos()
    )
    .is_ok());

    image[0x10] = 0xAA;
    assert_eq!(
        firmware::install(
            &mut memory,
            &image,
            Some(firmware::seabios_vga_rom()),
            FirmwareConfig::freedos()
        ),
        Err(FirmwareError::OverlappingImages)
    );
}

#[test]
fn freedos_config_advertises_four_megabytes() {
    let config = FirmwareConfig::freedos();
    assert_eq!(config.cmos_floppy_type, firmware::FLOPPY_TYPE_1_44M);
    assert_eq!(config.extended_memory_kib, 3 * 1024);
    assert_eq!(config.extmem_cmos(), (0x00, 0x0C));
}
