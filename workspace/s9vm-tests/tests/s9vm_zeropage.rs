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

//! L2: x86 boot-protocol zero page builder (real kernel code, not executed).

#[path = "../../kernel/src/s9vm/zeropage.rs"]
mod zeropage;

use zeropage::{
    ACPI_NVS_LEN, ACPI_RECLAIM_LEN, BIOS_ROM_START, BOOT_FLAG, BOOT_PARAMS_GPA, BOOT_PARAMS_SIZE,
    BOOT_PROTOCOL_VERSION, DEFAULT_CMDLINE_SIZE, E820_ENTRY_SIZE, E820_MAX_ENTRIES, E820_TABLE_LEN,
    E820Kind, HEADER_END, HEADER_MAGIC, HIGH_BASE, HIGH_MMIO_LEN, KernelHeader, LOADFLAGS,
    LOW_MEMORY_TOP, LOW_RAM_END, MIN_BOOT_MEMORY, OFFSET_ACPI_RSDP_ADDR, OFFSET_BOOT_FLAG,
    OFFSET_CMD_LINE_PTR, OFFSET_CMDLINE_SIZE, OFFSET_CODE32_START, OFFSET_E820_ENTRIES,
    OFFSET_E820_TABLE, OFFSET_EXT_CMD_LINE_PTR, OFFSET_EXT_RAMDISK_IMAGE, OFFSET_EXT_RAMDISK_SIZE,
    OFFSET_HANDOVER_OFFSET, OFFSET_HARDWARE_SUBARCH, OFFSET_HARDWARE_SUBARCH_DATA, OFFSET_HEADER,
    OFFSET_HEAP_END_PTR, OFFSET_INIT_SIZE, OFFSET_INITRD_ADDR_MAX, OFFSET_KERNEL_ALIGNMENT,
    OFFSET_KERNEL_INFO_OFFSET, OFFSET_LOADFLAGS, OFFSET_MIN_ALIGNMENT, OFFSET_PAYLOAD_LENGTH,
    OFFSET_PAYLOAD_OFFSET, OFFSET_PREF_ADDRESS, OFFSET_RAMDISK_IMAGE, OFFSET_RAMDISK_SIZE,
    OFFSET_RELOCATABLE_KERNEL, OFFSET_SENTINEL, OFFSET_SETUP_DATA, OFFSET_SETUP_HEADER,
    OFFSET_SETUP_SECTS, OFFSET_TYPE_OF_LOADER, OFFSET_VERSION, OFFSET_XLOADFLAGS, SETUP_HEADER_LEN,
    VGA_HOLE_START, XLF_CAN_BE_LOADED_ABOVE_4G, XLF_KERNEL_64, ZeroPage, ZeroPageError,
};

/// Encodes a builder into a fresh zero page.
fn encode(page: &ZeroPage) -> Vec<u8> {
    let mut buffer = vec![0u8; BOOT_PARAMS_SIZE];
    page.write(&mut buffer).expect("zero page must encode");
    buffer
}

fn read_u8(buf: &[u8], offset: usize) -> u8 {
    buf[offset]
}

fn read_u16(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([buf[offset], buf[offset + 1]])
}

fn read_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ])
}

fn read_u64(buf: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buf[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

/// Entry at `index` of the encoded E820 table.
fn e820_entry(buf: &[u8], index: usize) -> (u64, u64, u32) {
    let base = OFFSET_E820_TABLE + index * E820_ENTRY_SIZE;
    (
        read_u64(buf, base),
        read_u64(buf, base + 8),
        read_u32(buf, base + 16),
    )
}

fn custom_header() -> KernelHeader {
    KernelHeader {
        setup_sects: 0x17,
        code32_start: 0x0020_0000,
        initrd_addr_max: 0x7FFF_FFFF,
        kernel_alignment: 0x0010_0000,
        relocatable_kernel: 1,
        min_alignment: 0x12,
        xloadflags: XLF_KERNEL_64 | XLF_CAN_BE_LOADED_ABOVE_4G,
        cmdline_size: 4096,
        payload_offset: 0x1234,
        payload_length: 0x5678_9ABC,
        setup_data: 0x1122_3344_5566_7788,
        pref_address: 0x0000_0000_0100_0000,
        init_size: 0x00A0_0000,
        handover_offset: 0x30,
        kernel_info_offset: 0x40,
    }
}

#[test]
fn accessors_expose_the_builder_state() {
    let page = ZeroPage::new();
    assert_eq!(
        page.cmdline(),
        (BOOT_PARAMS_GPA + BOOT_PARAMS_SIZE as u64, 0)
    );
    assert_eq!(page.initrd(), (0, 0));
    assert_eq!(page.header(), &KernelHeader::default());
    let page = page
        .with_cmdline(0x0002_0000, 11)
        .expect("cmdline")
        .with_initrd(0x0200_0000, 0x1000)
        .expect("initrd");
    assert_eq!(page.cmdline(), (0x0002_0000, 11));
    assert_eq!(page.initrd(), (0x0200_0000, 0x1000));
}

#[test]
fn protocol_offsets_are_the_authoritative_values() {
    assert_eq!(BOOT_PARAMS_GPA, 0x0001_0000);
    assert_eq!(BOOT_PARAMS_SIZE, 4096);
    assert_eq!(OFFSET_ACPI_RSDP_ADDR, 0x070);
    assert_eq!(OFFSET_EXT_RAMDISK_IMAGE, 0x0C0);
    assert_eq!(OFFSET_EXT_RAMDISK_SIZE, 0x0C4);
    assert_eq!(OFFSET_EXT_CMD_LINE_PTR, 0x0C8);
    assert_eq!(OFFSET_E820_ENTRIES, 0x1E8);
    assert_eq!(OFFSET_SENTINEL, 0x1EF);
    assert_eq!(OFFSET_SETUP_HEADER, 0x1F1);
    assert_eq!(OFFSET_SETUP_SECTS, 0x1F1);
    assert_eq!(OFFSET_BOOT_FLAG, 0x1FE);
    assert_eq!(OFFSET_HEADER, 0x202);
    assert_eq!(OFFSET_VERSION, 0x206);
    assert_eq!(OFFSET_TYPE_OF_LOADER, 0x210);
    assert_eq!(OFFSET_LOADFLAGS, 0x211);
    assert_eq!(OFFSET_CODE32_START, 0x214);
    assert_eq!(OFFSET_RAMDISK_IMAGE, 0x218);
    assert_eq!(OFFSET_RAMDISK_SIZE, 0x21C);
    assert_eq!(OFFSET_HEAP_END_PTR, 0x224);
    assert_eq!(OFFSET_CMD_LINE_PTR, 0x228);
    assert_eq!(OFFSET_INITRD_ADDR_MAX, 0x22C);
    assert_eq!(OFFSET_KERNEL_ALIGNMENT, 0x230);
    assert_eq!(OFFSET_RELOCATABLE_KERNEL, 0x234);
    assert_eq!(OFFSET_MIN_ALIGNMENT, 0x235);
    assert_eq!(OFFSET_XLOADFLAGS, 0x236);
    assert_eq!(OFFSET_CMDLINE_SIZE, 0x238);
    assert_eq!(OFFSET_HARDWARE_SUBARCH, 0x23C);
    assert_eq!(OFFSET_HARDWARE_SUBARCH_DATA, 0x240);
    assert_eq!(OFFSET_PAYLOAD_OFFSET, 0x248);
    assert_eq!(OFFSET_PAYLOAD_LENGTH, 0x24C);
    assert_eq!(OFFSET_SETUP_DATA, 0x250);
    assert_eq!(OFFSET_PREF_ADDRESS, 0x258);
    assert_eq!(OFFSET_INIT_SIZE, 0x260);
    assert_eq!(OFFSET_HANDOVER_OFFSET, 0x264);
    assert_eq!(OFFSET_KERNEL_INFO_OFFSET, 0x268);
    assert_eq!(OFFSET_E820_TABLE, 0x2D0);
    assert_eq!(HEADER_END, 0x26C);
    assert_eq!(SETUP_HEADER_LEN, 0x7B);
    assert_eq!(E820_ENTRY_SIZE, 20);
    assert_eq!(E820_MAX_ENTRIES, 128);
    assert_eq!(E820_TABLE_LEN, 2560);
    assert_eq!(BOOT_FLAG, 0xAA55);
    assert_eq!(HEADER_MAGIC, 0x5372_6448);
    assert_eq!(BOOT_PROTOCOL_VERSION, 0x020F);
    assert_eq!(LOADFLAGS, 0x81);
}

#[test]
fn new_page_has_the_expected_defaults() {
    let buffer = encode(&ZeroPage::new());
    assert_eq!(read_u8(&buffer, OFFSET_E820_ENTRIES), 0);
    assert_eq!(read_u8(&buffer, OFFSET_SETUP_SECTS), 0x1F);
    assert_eq!(read_u16(&buffer, OFFSET_BOOT_FLAG), 0xAA55);
    assert_eq!(read_u32(&buffer, OFFSET_HEADER), HEADER_MAGIC);
    assert_eq!(read_u16(&buffer, OFFSET_VERSION), BOOT_PROTOCOL_VERSION);
    assert_eq!(read_u8(&buffer, OFFSET_TYPE_OF_LOADER), 0xFF);
    assert_eq!(read_u8(&buffer, OFFSET_LOADFLAGS), LOADFLAGS);
    assert_eq!(read_u8(&buffer, OFFSET_SENTINEL), 0);
    assert_eq!(read_u32(&buffer, OFFSET_HARDWARE_SUBARCH), 0);
    assert_eq!(
        read_u32(&buffer, OFFSET_CMD_LINE_PTR),
        (BOOT_PARAMS_GPA + BOOT_PARAMS_SIZE as u64) as u32
    );
    assert_eq!(read_u32(&buffer, OFFSET_EXT_CMD_LINE_PTR), 0);
    assert_eq!(read_u32(&buffer, OFFSET_CMDLINE_SIZE), DEFAULT_CMDLINE_SIZE);
}

#[test]
fn setup_header_fields_are_copied_byte_exactly() {
    let header = custom_header();
    let buffer = encode(&ZeroPage::new().with_kernel_header(header));
    assert_eq!(read_u8(&buffer, OFFSET_SETUP_SECTS), header.setup_sects);
    assert_eq!(read_u32(&buffer, OFFSET_CODE32_START), header.code32_start);
    assert_eq!(
        read_u32(&buffer, OFFSET_INITRD_ADDR_MAX),
        header.initrd_addr_max
    );
    assert_eq!(
        read_u32(&buffer, OFFSET_KERNEL_ALIGNMENT),
        header.kernel_alignment
    );
    assert_eq!(
        read_u8(&buffer, OFFSET_RELOCATABLE_KERNEL),
        header.relocatable_kernel
    );
    assert_eq!(read_u8(&buffer, OFFSET_MIN_ALIGNMENT), header.min_alignment);
    assert_eq!(read_u16(&buffer, OFFSET_XLOADFLAGS), header.xloadflags);
    assert_eq!(read_u32(&buffer, OFFSET_CMDLINE_SIZE), header.cmdline_size);
    assert_eq!(
        read_u32(&buffer, OFFSET_PAYLOAD_OFFSET),
        header.payload_offset
    );
    assert_eq!(
        read_u32(&buffer, OFFSET_PAYLOAD_LENGTH),
        header.payload_length
    );
    assert_eq!(read_u64(&buffer, OFFSET_SETUP_DATA), header.setup_data);
    assert_eq!(read_u64(&buffer, OFFSET_PREF_ADDRESS), header.pref_address);
    assert_eq!(read_u32(&buffer, OFFSET_INIT_SIZE), header.init_size);
    assert_eq!(
        read_u32(&buffer, OFFSET_HANDOVER_OFFSET),
        header.handover_offset
    );
    assert_eq!(
        read_u32(&buffer, OFFSET_KERNEL_INFO_OFFSET),
        header.kernel_info_offset
    );
}

#[test]
fn e820_single_entry_is_encoded_byte_exactly() {
    let mut page = ZeroPage::new();
    page.add_e820(0x0010_0000, 0x0020_0000, E820Kind::Ram)
        .expect("add");
    let buffer = encode(&page);
    assert_eq!(read_u8(&buffer, OFFSET_E820_ENTRIES), 1);
    assert_eq!(
        e820_entry(&buffer, 0),
        (0x0010_0000, 0x0020_0000, E820Kind::Ram.as_u32())
    );
}

#[test]
fn e820_entries_are_sorted_by_address() {
    let mut page = ZeroPage::new();
    page.add_e820(0x0020_0000, 0x1000, E820Kind::Reserved)
        .expect("add high");
    page.add_e820(0x0010_0000, 0x1000, E820Kind::Ram)
        .expect("add low");
    page.add_e820(0x0030_0000, 0x1000, E820Kind::Acpi)
        .expect("add highest");
    let buffer = encode(&page);
    assert_eq!(read_u8(&buffer, OFFSET_E820_ENTRIES), 3);
    assert_eq!(e820_entry(&buffer, 0).0, 0x0010_0000);
    assert_eq!(e820_entry(&buffer, 1).0, 0x0020_0000);
    assert_eq!(e820_entry(&buffer, 2).0, 0x0030_0000);
}

#[test]
fn e820_merges_adjacent_entries_of_the_same_kind() {
    let mut page = ZeroPage::new();
    page.add_e820(0, 0x1000, E820Kind::Ram).expect("first");
    page.add_e820(0x1000, 0x2000, E820Kind::Ram)
        .expect("second");
    assert_eq!(
        page.e820_entries(),
        &[zeropage::E820Entry {
            addr: 0,
            size: 0x3000,
            kind: E820Kind::Ram,
        }]
    );
    let buffer = encode(&page);
    assert_eq!(read_u8(&buffer, OFFSET_E820_ENTRIES), 1);
    assert_eq!(e820_entry(&buffer, 0), (0, 0x3000, 1));
}

#[test]
fn e820_merges_adjacent_entries_added_in_reverse_order() {
    let mut page = ZeroPage::new();
    page.add_e820(0x2000, 0x1000, E820Kind::Acpi).expect("high");
    page.add_e820(0x1000, 0x1000, E820Kind::Acpi).expect("low");
    assert_eq!(page.e820_entries().len(), 1);
    assert_eq!(page.e820_entries()[0].addr, 0x1000);
    assert_eq!(page.e820_entries()[0].size, 0x2000);
}

#[test]
fn e820_merges_overlapping_entries_of_the_same_kind() {
    let mut page = ZeroPage::new();
    page.add_e820(0, 0x2000, E820Kind::Ram).expect("first");
    page.add_e820(0x1000, 0x2000, E820Kind::Ram)
        .expect("second");
    assert_eq!(page.e820_entries().len(), 1);
    assert_eq!(page.e820_entries()[0].addr, 0);
    assert_eq!(page.e820_entries()[0].size, 0x3000);
}

#[test]
fn e820_rejects_overlap_between_different_kinds() {
    let mut page = ZeroPage::new();
    page.add_e820(0x1000, 0x1000, E820Kind::Ram).expect("first");
    assert_eq!(
        page.add_e820(0x1800, 0x1000, E820Kind::Reserved),
        Err(ZeroPageError::E820Overlap)
    );
    assert_eq!(page.e820_entries().len(), 1);
}

#[test]
fn e820_rejects_zero_size_entries() {
    let mut page = ZeroPage::new();
    assert_eq!(
        page.add_e820(0x1000, 0, E820Kind::Ram),
        Err(ZeroPageError::E820ZeroSize)
    );
    assert!(page.e820_entries().is_empty());
}

#[test]
fn e820_rejects_address_overflow() {
    let mut page = ZeroPage::new();
    assert_eq!(
        page.add_e820(u64::MAX - 0x10, 0x100, E820Kind::Ram),
        Err(ZeroPageError::E820AddressOverflow)
    );
}

#[test]
fn e820_caps_the_table_at_128_entries() {
    let mut page = ZeroPage::new();
    for index in 0..E820_MAX_ENTRIES {
        page.add_e820((index as u64) * 0x2000, 0x1000, E820Kind::Reserved)
            .expect("entry must fit");
    }
    assert_eq!(page.e820_entries().len(), E820_MAX_ENTRIES);
    assert_eq!(
        page.add_e820(0x0010_0000, 0x1000, E820Kind::Ram),
        Err(ZeroPageError::E820TooManyEntries)
    );
}

#[test]
fn e820_accepts_a_merge_at_the_128_entry_cap() {
    let mut page = ZeroPage::new();
    for index in 0..E820_MAX_ENTRIES {
        page.add_e820((index as u64) * 0x2000, 0x1000, E820Kind::Ram)
            .expect("entry must fit");
    }
    assert_eq!(page.e820_entries().len(), E820_MAX_ENTRIES);
    // Adjacent to the first entry: merges instead of needing a 129th slot.
    page.add_e820(0x1000, 0x800, E820Kind::Ram)
        .expect("adjacent entry must merge");
    assert_eq!(page.e820_entries().len(), E820_MAX_ENTRIES);
    assert_eq!(page.e820_entries()[0].addr, 0);
    assert_eq!(page.e820_entries()[0].size, 0x1800);
}
#[test]
fn e820_kinds_map_to_the_kernel_values() {
    assert_eq!(E820Kind::Ram.as_u32(), 1);
    assert_eq!(E820Kind::Reserved.as_u32(), 2);
    assert_eq!(E820Kind::Acpi.as_u32(), 3);
    assert_eq!(E820Kind::Nvs.as_u32(), 4);
    assert_eq!(E820Kind::Unusable.as_u32(), 5);
    for (value, kind) in [
        (1, E820Kind::Ram),
        (2, E820Kind::Reserved),
        (3, E820Kind::Acpi),
        (4, E820Kind::Nvs),
        (5, E820Kind::Unusable),
    ] {
        assert_eq!(E820Kind::from_u32(value), Some(kind));
    }
    assert_eq!(E820Kind::from_u32(0), None);
    assert_eq!(E820Kind::from_u32(6), None);
}

#[test]
fn e820_error_is_atomic() {
    let mut page = ZeroPage::new();
    page.add_e820(0x1000, 0x1000, E820Kind::Ram).expect("first");
    let before = page.clone();
    assert_eq!(
        page.add_e820(0x1000, 0x1000, E820Kind::Reserved),
        Err(ZeroPageError::E820Overlap)
    );
    assert_eq!(page, before);
}

#[test]
fn cmdline_pointer_is_split_into_low_and_high_halves() {
    let page = ZeroPage::new()
        .with_cmdline(0x0002_0000, 12)
        .expect("low pointer");
    let buffer = encode(&page);
    assert_eq!(read_u32(&buffer, OFFSET_CMD_LINE_PTR), 0x0002_0000);
    assert_eq!(read_u32(&buffer, OFFSET_EXT_CMD_LINE_PTR), 0);

    let high = 0x1_0002_0000;
    let page = ZeroPage::new()
        .with_cmdline(high, 12)
        .expect("high pointer");
    let buffer = encode(&page);
    assert_eq!(read_u32(&buffer, OFFSET_CMD_LINE_PTR), 0x0002_0000);
    assert_eq!(read_u32(&buffer, OFFSET_EXT_CMD_LINE_PTR), 1);
}

#[test]
fn cmdline_rejects_invalid_pointers() {
    assert_eq!(
        ZeroPage::new().with_cmdline(0, 0),
        Err(ZeroPageError::InvalidCmdlineAddress)
    );
    assert_eq!(
        ZeroPage::new().with_cmdline(BOOT_PARAMS_GPA, 0),
        Err(ZeroPageError::InvalidCmdlineAddress)
    );
    assert_eq!(
        ZeroPage::new().with_cmdline(BOOT_PARAMS_GPA + 0x100, 8),
        Err(ZeroPageError::InvalidCmdlineAddress)
    );
    assert_eq!(
        ZeroPage::new().with_cmdline(u64::MAX, 1),
        Err(ZeroPageError::InvalidCmdlineAddress)
    );
}

#[test]
fn cmdline_rejects_a_length_above_the_announced_size() {
    assert_eq!(
        ZeroPage::new().with_cmdline(0x0002_0000, DEFAULT_CMDLINE_SIZE + 1),
        Err(ZeroPageError::CmdlineTooLong)
    );
    assert!(
        ZeroPage::new()
            .with_cmdline(0x0002_0000, DEFAULT_CMDLINE_SIZE)
            .is_ok()
    );
}

#[test]
fn cmdline_above_4g_requires_the_load_flag() {
    let flat = KernelHeader {
        xloadflags: XLF_KERNEL_64,
        ..KernelHeader::default()
    };
    let page = ZeroPage::new().with_kernel_header(flat);
    assert_eq!(
        page.with_cmdline(0x1_0002_0000, 8),
        Err(ZeroPageError::InvalidCmdlineAddress)
    );
}

#[test]
fn initrd_pointers_are_split_into_low_and_high_halves() {
    let page = ZeroPage::new()
        .with_initrd(0x0200_0000, 0x0012_3456)
        .expect("initrd");
    let buffer = encode(&page);
    assert_eq!(read_u32(&buffer, OFFSET_RAMDISK_IMAGE), 0x0200_0000);
    assert_eq!(read_u32(&buffer, OFFSET_RAMDISK_SIZE), 0x0012_3456);
    assert_eq!(read_u32(&buffer, OFFSET_EXT_RAMDISK_IMAGE), 0);
    assert_eq!(read_u32(&buffer, OFFSET_EXT_RAMDISK_SIZE), 0);

    let high = 0x2_0000_0000 + 0x0100_0000;
    let page = ZeroPage::new()
        .with_initrd(high, 0x1_0000_0000)
        .expect("high initrd");
    let buffer = encode(&page);
    assert_eq!(read_u32(&buffer, OFFSET_RAMDISK_IMAGE), 0x0100_0000);
    assert_eq!(read_u32(&buffer, OFFSET_EXT_RAMDISK_IMAGE), 2);
    assert_eq!(read_u32(&buffer, OFFSET_RAMDISK_SIZE), 0);
    assert_eq!(read_u32(&buffer, OFFSET_EXT_RAMDISK_SIZE), 1);
}

#[test]
fn initrd_above_4g_requires_the_load_flag() {
    let flat = KernelHeader {
        xloadflags: XLF_KERNEL_64,
        ..KernelHeader::default()
    };
    let page = ZeroPage::new().with_kernel_header(flat);
    assert_eq!(
        page.with_initrd(0x1_0000_0000, 0x1000),
        Err(ZeroPageError::InvalidInitrdAddress)
    );
}

#[test]
fn initrd_rejects_inconsistent_address_and_size() {
    assert_eq!(
        ZeroPage::new().with_initrd(0, 0x1000),
        Err(ZeroPageError::InvalidInitrdAddress)
    );
    assert_eq!(
        ZeroPage::new().with_initrd(0x100_0000, 0),
        Err(ZeroPageError::InvalidInitrdAddress)
    );
    assert_eq!(
        ZeroPage::new().with_initrd(BOOT_PARAMS_GPA, 0x1000),
        Err(ZeroPageError::InvalidInitrdAddress)
    );
    assert_eq!(
        ZeroPage::new().with_initrd(u64::MAX - 0x10, 0x100),
        Err(ZeroPageError::InvalidInitrdAddress)
    );
}

#[test]
fn acpi_rsdp_address_is_written_at_0x70() {
    let page = ZeroPage::new().with_rsdp(0x000E_0000);
    let buffer = encode(&page);
    assert_eq!(read_u64(&buffer, OFFSET_ACPI_RSDP_ADDR), 0x000E_0000);
    // No RSDP is the zero value.
    let buffer = encode(&ZeroPage::new());
    assert_eq!(read_u64(&buffer, OFFSET_ACPI_RSDP_ADDR), 0);
}

#[test]
fn hardware_subarch_is_pc_and_data_is_written() {
    let page = ZeroPage::new().with_hardware_subarch_data(0xDEAD_BEEF_0BAD_F00D);
    let buffer = encode(&page);
    assert_eq!(read_u32(&buffer, OFFSET_HARDWARE_SUBARCH), 0);
    assert_eq!(
        read_u64(&buffer, OFFSET_HARDWARE_SUBARCH_DATA),
        0xDEAD_BEEF_0BAD_F00D
    );
}

#[test]
fn loader_id_is_written_to_type_of_loader() {
    let buffer = encode(&ZeroPage::new().with_loader_id(0x12));
    assert_eq!(read_u8(&buffer, OFFSET_TYPE_OF_LOADER), 0x12);
}

#[test]
fn heap_end_ptr_follows_setup_sects() {
    // 0x1F sectors -> 32 sectors of setup -> 16 KiB - 0x200 = 0x3E00.
    let buffer = encode(&ZeroPage::new());
    assert_eq!(read_u16(&buffer, OFFSET_HEAP_END_PTR), 0x3E00);
    // Zero means four sectors: 5 * 512 - 0x200 = 0x600? No: (4+1)*512 = 0xA00,
    // minus 0x200 is 0x800.
    let header = KernelHeader {
        setup_sects: 0,
        ..KernelHeader::default()
    };
    let buffer = encode(&ZeroPage::new().with_kernel_header(header));
    assert_eq!(read_u16(&buffer, OFFSET_HEAP_END_PTR), 0x800);
    // 16 sectors -> 17 * 512 - 0x200 = 0x2000.
    let header = KernelHeader {
        setup_sects: 0x10,
        ..KernelHeader::default()
    };
    let buffer = encode(&ZeroPage::new().with_kernel_header(header));
    assert_eq!(read_u16(&buffer, OFFSET_HEAP_END_PTR), 0x2000);
}

#[test]
fn destination_must_be_a_full_zero_page() {
    let mut short = vec![0u8; BOOT_PARAMS_SIZE - 1];
    assert_eq!(
        ZeroPage::new().write(&mut short),
        Err(ZeroPageError::DestinationTooSmall)
    );
}

#[test]
fn write_is_idempotent() {
    let mut page = ZeroPage::new();
    page.add_e820(0, 0x9FC00, E820Kind::Ram).expect("ram");
    page.add_e820(0x9FC00, 0x400, E820Kind::Reserved)
        .expect("reserved");
    let first = encode(&page);
    let second = encode(&page);
    assert_eq!(first, second);
}

#[test]
fn write_zero_fills_unmodelled_fields() {
    let mut buffer = vec![0xFFu8; BOOT_PARAMS_SIZE];
    ZeroPage::new().write(&mut buffer).expect("write");
    for offset in [
        0x000, 0x040, 0x080, 0x100, 0x140, 0x1C0, 0x1E9, 0x1EA, 0x1EB, 0x1EC, 0x290, 0xCD0, 0xD00,
        0xFFF,
    ] {
        assert_eq!(buffer[offset], 0, "offset {offset:#x} must be zero");
    }
}

#[test]
fn bytes_after_the_zero_page_are_left_untouched() {
    let mut buffer = vec![0xAAu8; BOOT_PARAMS_SIZE + 8];
    ZeroPage::new().write(&mut buffer).expect("write");
    assert_eq!(&buffer[BOOT_PARAMS_SIZE..], &[0xAA; 8]);
}

#[test]
fn e820_count_and_table_do_not_disturb_the_setup_header() {
    let mut page = ZeroPage::new();
    page.add_e820(0, 0x9FC00, E820Kind::Ram).expect("ram");
    let buffer = encode(&page);
    assert_eq!(read_u8(&buffer, OFFSET_E820_ENTRIES), 1);
    assert_eq!(read_u32(&buffer, OFFSET_HEADER), HEADER_MAGIC);
    assert_eq!(read_u8(&buffer, OFFSET_SETUP_SECTS), 0x1F);
    // The 20-byte entry ends before the EDD area at 0xCD0.
    assert_eq!(e820_entry(&buffer, 0), (0, 0x9FC00, 1));
    assert_eq!(buffer[OFFSET_E820_TABLE + E820_ENTRY_SIZE], 0);
}

#[test]
fn kernel_header_round_trips_through_the_page() {
    let header = custom_header();
    let buffer = encode(&ZeroPage::new().with_kernel_header(header));
    assert_eq!(KernelHeader::parse(&buffer), Ok(header));
}

#[test]
fn kernel_header_parse_rejects_short_or_foreign_buffers() {
    assert_eq!(KernelHeader::parse(&[]), Err(ZeroPageError::InvalidHeader));
    assert_eq!(
        KernelHeader::parse(&[0u8; HEADER_END - 1]),
        Err(ZeroPageError::InvalidHeader)
    );
    let mut buffer = encode(&ZeroPage::new());
    buffer[OFFSET_HEADER] ^= 0xFF;
    assert_eq!(
        KernelHeader::parse(&buffer),
        Err(ZeroPageError::InvalidHeader)
    );
}

#[test]
fn boot_params_for_builds_the_pc_layout_below_4g() {
    let mem = 0x2000_0000u64;
    let page = ZeroPage::boot_params_for(0x0002_0000, mem).expect("layout");
    let entries = page.e820_entries();
    let acpi_len = ACPI_NVS_LEN + ACPI_RECLAIM_LEN;
    assert_eq!(entries.len(), 6);
    assert_eq!(
        entries[0],
        zeropage::E820Entry {
            addr: 0,
            size: LOW_RAM_END,
            kind: E820Kind::Ram
        }
    );
    assert_eq!(
        entries[1],
        zeropage::E820Entry {
            addr: LOW_RAM_END,
            size: VGA_HOLE_START - LOW_RAM_END,
            kind: E820Kind::Reserved
        }
    );
    assert_eq!(
        entries[2],
        zeropage::E820Entry {
            addr: BIOS_ROM_START,
            size: LOW_MEMORY_TOP - BIOS_ROM_START,
            kind: E820Kind::Reserved
        }
    );
    assert_eq!(entries[3].addr, LOW_MEMORY_TOP);
    assert_eq!(entries[3].size, mem - LOW_MEMORY_TOP - acpi_len);
    assert_eq!(entries[3].kind, E820Kind::Ram);
    assert_eq!(
        entries[4],
        zeropage::E820Entry {
            addr: mem - acpi_len,
            size: ACPI_NVS_LEN,
            kind: E820Kind::Nvs
        }
    );
    assert_eq!(
        entries[5],
        zeropage::E820Entry {
            addr: mem - ACPI_RECLAIM_LEN,
            size: ACPI_RECLAIM_LEN,
            kind: E820Kind::Acpi
        }
    );
    let buffer = encode(&page);
    assert_eq!(read_u8(&buffer, OFFSET_E820_ENTRIES), 6);
    assert_eq!(read_u32(&buffer, OFFSET_CMD_LINE_PTR), 0x0002_0000);
}

#[test]
fn boot_params_for_builds_high_memory_and_mmio_above_4g() {
    let mem = 0x1_8000_0000u64; // 6 GiB
    let page = ZeroPage::boot_params_for(0x0002_0000, mem).expect("layout");
    let entries = page.e820_entries();
    let high_ram = mem - HIGH_BASE;
    assert_eq!(entries.len(), 8);
    // Low layout: the last low entry is the ACPI reclaim region ending at 4G.
    assert_eq!(entries[5].addr + entries[5].size, HIGH_BASE);
    assert_eq!(
        entries[6],
        zeropage::E820Entry {
            addr: HIGH_BASE,
            size: high_ram,
            kind: E820Kind::Ram
        }
    );
    assert_eq!(
        entries[7],
        zeropage::E820Entry {
            addr: HIGH_BASE + high_ram,
            size: HIGH_MMIO_LEN,
            kind: E820Kind::Reserved
        }
    );
}

#[test]
fn boot_params_for_rejects_tiny_machines() {
    assert_eq!(
        ZeroPage::boot_params_for(0x0002_0000, MIN_BOOT_MEMORY - 1),
        Err(ZeroPageError::MemoryTooSmall)
    );
    assert!(ZeroPage::boot_params_for(0x0002_0000, MIN_BOOT_MEMORY).is_ok());
}
