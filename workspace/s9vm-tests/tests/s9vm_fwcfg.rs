//! L2: QEMU `fw_cfg` file directory used to hand SeaVGABIOS to SeaBIOS.

extern crate alloc;

use alloc::{vec, vec::Vec};

#[path = "../../kernel/src/s9vm/fwcfg.rs"]
mod fwcfg;

use fwcfg::{FwCfg, CTL_PORT, DATA_PORT, FILE_DIR, SIGNATURE};

#[test]
fn signature_and_data_cursor() {
    let mut cfg = FwCfg::new();
    assert!(fwcfg::handles_port(CTL_PORT));
    assert!(fwcfg::handles_port(DATA_PORT));
    assert!(!fwcfg::handles_port(0x512));

    cfg.select(SIGNATURE);
    let signature: Vec<u8> = (0..4).map(|_| cfg.read_byte()).collect();
    assert_eq!(signature, b"QEMU");
    assert_eq!(cfg.read_byte(), 0xFF, "reads past the blob return 0xFF");
}

#[test]
fn file_directory_lists_the_vga_rom() {
    let mut cfg = FwCfg::new();
    let rom = vec![0x55u8, 0xAA, 0x02, 0x00];
    let select = cfg.add_file("vgaroms/vgabios-stdvga.bin", &rom);
    assert_eq!(select, fwcfg::FIRST_FILE_SELECT);

    cfg.select(FILE_DIR);
    let mut count = [0u8; 4];
    for byte in &mut count {
        *byte = cfg.read_byte();
    }
    assert_eq!(u32::from_be_bytes(count), 1);
    let mut entry = [0u8; 64];
    for byte in &mut entry {
        *byte = cfg.read_byte();
    }
    assert_eq!(u32::from_be_bytes(entry[0..4].try_into().unwrap()), 4);
    assert_eq!(
        u16::from_be_bytes(entry[4..6].try_into().unwrap()),
        fwcfg::FIRST_FILE_SELECT
    );
    let name = core::str::from_utf8(&entry[8..8 + 22]).unwrap();
    assert_eq!(name, "vgaroms/vgabios-stdvga");
}

#[test]
fn file_payload_is_returned_byte_by_byte() {
    let mut cfg = FwCfg::new();
    let rom = vec![0x55u8, 0xAA, 0x4E, 0xE9];
    let select = cfg.add_file("vgaroms/vgabios-stdvga.bin", &rom);
    cfg.select(select);
    let read: Vec<u8> = (0..rom.len()).map(|_| cfg.read_byte()).collect();
    assert_eq!(read, rom);
    assert_eq!(cfg.read_byte(), 0xFF);
}

#[test]
fn legacy_counts_are_zero_not_ff() {
    // SeaBIOS loops over the NUMA/ACPI/SMBIOS counts; 0xFF would make it read
    // megabytes of garbage.
    let mut cfg = FwCfg::new();
    cfg.select(fwcfg::ACPI_TABLES);
    assert_eq!(cfg.read_byte(), 0);
    assert_eq!(cfg.read_byte(), 0);
    cfg.select(fwcfg::SMBIOS_ENTRIES);
    assert_eq!(cfg.read_byte(), 0);
    assert_eq!(cfg.read_byte(), 0);
    cfg.select(fwcfg::NUMA);
    for _ in 0..8 {
        assert_eq!(cfg.read_byte(), 0);
    }
}
