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

//! L2: s9vm boot-protocol image (bzImage) parser and load plan.

#![allow(dead_code)]

#[path = "../../kernel/src/s9vm/bzimage.rs"]
mod bzimage;

use bzimage::{
    BzError, BzImage, EntryPoint, LoadPlan, SetupDataReader, SetupDataSummary, BOOT_FLAG,
    BOOT_PARAMS_GPA, BOOT_PARAMS_SIZE, CMDLINE_GPA, DEFAULT_CODE32_START, DEFAULT_SETUP_SECTORS,
    ENTRY_OFFSET_64, HEADER_END, HEADER_MAGIC, LOADED_HIGH, MAX_CMDLINE_SIZE,
    MAX_SETUP_DATA_ENTRIES, MAX_SETUP_DATA_LEN, MIN_HEADER_VERSION, SECTOR_SIZE, SETUP_DATA_ALIGN,
    SETUP_DATA_HEADER_SIZE, SETUP_GPA, XLF_CAN_BE_LOADED_ABOVE_4G, XLF_EFI_HANDOVER, XLF_KERNEL_64,
};

// ---------------------------------------------------------------------------
// Synthetic image builder
// ---------------------------------------------------------------------------

/// One synthetic boot-protocol image description.
#[derive(Debug, Clone, Copy)]
struct ImageSpec {
    /// Raw `setup_sects` byte (`0` means the architectural four).
    setup_sects: u8,
    version: u16,
    type_of_loader: u8,
    loadflags: u8,
    xloadflags: u16,
    code32_start: u32,
    initrd_addr_max: u32,
    kernel_alignment: u32,
    min_alignment: u8,
    relocatable: u8,
    cmdline_size: u32,
    hardware_subarch: u32,
    payload_offset: u32,
    payload_length: u32,
    setup_data: u64,
    pref_address: u64,
    init_size: u32,
    boot_flag: u16,
    magic: u32,
    kernel_len: usize,
}

impl Default for ImageSpec {
    fn default() -> Self {
        Self {
            setup_sects: 4,
            version: 0x020F,
            type_of_loader: 0xE0,
            loadflags: LOADED_HIGH,
            xloadflags: XLF_KERNEL_64,
            code32_start: 0x0010_0000,
            initrd_addr_max: 0x37FF_FFFF,
            kernel_alignment: 0x0020_0000,
            min_alignment: 0,
            relocatable: 1,
            cmdline_size: 2048,
            hardware_subarch: 0,
            payload_offset: 0,
            payload_length: 0,
            setup_data: 0,
            pref_address: 0x0100_0000,
            init_size: 0x0040_0000,
            boot_flag: BOOT_FLAG,
            magic: HEADER_MAGIC,
            kernel_len: 0x1000,
        }
    }
}

/// Effective number of setup sectors for a raw byte.
fn effective_setup_sects(raw: u8) -> u8 {
    if raw == 0 {
        DEFAULT_SETUP_SECTORS
    } else {
        raw
    }
}

/// Builds a synthetic boot-protocol image from `spec`.
fn build_image(spec: &ImageSpec) -> Vec<u8> {
    let setup_bytes = (usize::from(effective_setup_sects(spec.setup_sects)) + 1) * SECTOR_SIZE;
    let mut bytes = vec![0u8; setup_bytes + spec.kernel_len];
    bytes[0x1F1] = spec.setup_sects;
    put_u16(&mut bytes, 0x1FE, spec.boot_flag);
    put_u32(&mut bytes, 0x202, spec.magic);
    put_u16(&mut bytes, 0x206, spec.version);
    bytes[0x210] = spec.type_of_loader;
    bytes[0x211] = spec.loadflags;
    put_u32(&mut bytes, 0x214, spec.code32_start);
    put_u32(&mut bytes, 0x22C, spec.initrd_addr_max);
    put_u32(&mut bytes, 0x230, spec.kernel_alignment);
    bytes[0x234] = spec.relocatable;
    bytes[0x235] = spec.min_alignment;
    put_u16(&mut bytes, 0x236, spec.xloadflags);
    put_u32(&mut bytes, 0x238, spec.cmdline_size);
    put_u32(&mut bytes, 0x23C, spec.hardware_subarch);
    put_u32(&mut bytes, 0x248, spec.payload_offset);
    put_u32(&mut bytes, 0x24C, spec.payload_length);
    put_u64(&mut bytes, 0x250, spec.setup_data);
    put_u64(&mut bytes, 0x258, spec.pref_address);
    put_u32(&mut bytes, 0x260, spec.init_size);
    for (index, byte) in bytes[setup_bytes..].iter_mut().enumerate() {
        *byte = (index & 0xFF) as u8;
    }
    bytes
}

/// Builds a valid image and mutates it with `edit`.
fn image_with(edit: impl FnOnce(&mut ImageSpec)) -> Vec<u8> {
    let mut spec = ImageSpec::default();
    edit(&mut spec);
    build_image(&spec)
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn parse(bytes: &[u8]) -> Result<BzImage<'_>, BzError> {
    BzImage::parse(bytes)
}

/// A reader backed by a fixed set of `setup_data` nodes.
struct MockReader {
    nodes: Vec<(u64, [u8; SETUP_DATA_HEADER_SIZE as usize])>,
}

impl MockReader {
    fn new() -> Self {
        Self { nodes: Vec::new() }
    }

    fn push_node(&mut self, address: u64, next: u64, kind: u32, len: u32) {
        let mut header = [0u8; SETUP_DATA_HEADER_SIZE as usize];
        header[0..8].copy_from_slice(&next.to_le_bytes());
        header[8..12].copy_from_slice(&kind.to_le_bytes());
        header[12..16].copy_from_slice(&len.to_le_bytes());
        self.nodes.push((address, header));
    }
}

impl SetupDataReader for MockReader {
    fn read_header(&mut self, gpa: u64, out: &mut [u8; SETUP_DATA_HEADER_SIZE as usize]) -> bool {
        let Some((_, header)) = self.nodes.iter().find(|(address, _)| *address == gpa) else {
            return false;
        };
        out.copy_from_slice(header);
        true
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

#[test]
fn parses_minimal_image() {
    let bytes = build_image(&ImageSpec::default());
    let image = parse(&bytes).expect("valid image");
    assert_eq!(image.version(), 0x020F);
    assert_eq!(image.version_major(), 2);
    assert_eq!(image.version_minor(), 15);
    assert_eq!(image.type_of_loader(), 0xE0);
    assert_eq!(image.setup_sects(), 4);
    assert_eq!(image.setup_bytes(), 5 * SECTOR_SIZE as u64);
    assert_eq!(image.kernel_offset(), 5 * SECTOR_SIZE as u64);
    assert_eq!(image.protected_mode_bytes(), 0x1000);
    assert_eq!(image.protected_mode().len(), 0x1000);
    assert_eq!(image.file_len(), 5 * SECTOR_SIZE + 0x1000);
    assert!(image.loaded_high());
    assert!(image.has_64bit_entry());
    assert!(!image.can_load_above_4g());
    assert!(image.relocatable());
    assert_eq!(image.code32_start(), 0x0010_0000);
    assert_eq!(image.kernel_alignment(), 0x0020_0000);
    assert_eq!(image.init_size(), 0x0040_0000);
    assert_eq!(image.cmdline_size(), 2048);
    assert_eq!(image.hardware_subarch(), 0);
    assert_eq!(image.pref_address(), 0x0100_0000);
    assert_eq!(image.setup_data(), 0);
    assert_eq!(image.payload(), None);
}

#[test]
fn setup_sects_zero_means_four() {
    let bytes = image_with(|spec| spec.setup_sects = 0);
    let image = parse(&bytes).expect("valid image");
    assert_eq!(image.setup_sects(), 4);
    assert_eq!(image.kernel_offset(), 5 * SECTOR_SIZE as u64);
}

#[test]
fn code32_start_zero_defaults_to_one_mib() {
    let bytes = image_with(|spec| spec.code32_start = 0);
    let image = parse(&bytes).expect("valid image");
    assert_eq!(image.code32_start(), DEFAULT_CODE32_START);
}

#[test]
fn kernel_alignment_zero_defaults_to_two_mib() {
    let bytes = image_with(|spec| spec.kernel_alignment = 0);
    let image = parse(&bytes).expect("valid image");
    assert_eq!(image.kernel_alignment(), 0x0020_0000);
}

#[test]
fn exposes_all_decoded_header_fields() {
    let bytes = image_with(|spec| {
        spec.type_of_loader = 0x42;
        spec.loadflags = LOADED_HIGH | (1 << 1) | (1 << 5);
        spec.xloadflags = XLF_KERNEL_64 | XLF_CAN_BE_LOADED_ABOVE_4G | XLF_EFI_HANDOVER;
        spec.code32_start = 0x0020_0000;
        spec.initrd_addr_max = 0x3FFF_FFFF;
        spec.kernel_alignment = 0x0040_0000;
        spec.min_alignment = 0x10;
        spec.relocatable = 1;
        spec.cmdline_size = 4096;
        spec.pref_address = 0x0200_0000;
        spec.init_size = 0x0080_0000;
    });
    let image = parse(&bytes).expect("valid image");
    assert_eq!(image.type_of_loader(), 0x42);
    assert_eq!(image.loadflags(), LOADED_HIGH | (1 << 1) | (1 << 5));
    assert_eq!(
        image.xloadflags(),
        XLF_KERNEL_64 | XLF_CAN_BE_LOADED_ABOVE_4G | XLF_EFI_HANDOVER
    );
    assert_eq!(image.code32_start(), 0x0020_0000);
    assert_eq!(image.initrd_addr_max(), 0x3FFF_FFFF);
    assert_eq!(image.kernel_alignment(), 0x0040_0000);
    assert_eq!(image.min_alignment(), 0x10);
    assert_eq!(image.cmdline_size(), 4096);
    assert_eq!(image.pref_address(), 0x0200_0000);
    assert_eq!(image.init_size(), 0x0080_0000);
    assert!(image.can_load_above_4g());
}

#[test]
fn payload_is_exposed_and_bounds_checked() {
    let mut spec = ImageSpec::default();
    let setup_bytes = (usize::from(DEFAULT_SETUP_SECTORS) + 1) * SECTOR_SIZE;
    spec.payload_offset = setup_bytes as u32 + 0x10;
    spec.payload_length = 8;
    let bytes = build_image(&spec);
    let image = parse(&bytes).expect("valid image");
    assert_eq!(image.payload_offset(), spec.payload_offset);
    assert_eq!(image.payload_length(), 8);
    assert_eq!(image.payload().expect("payload").len(), 8);
}

#[test]
fn rejects_too_short_file() {
    let bytes = build_image(&ImageSpec::default());
    for length in [0usize, 1, HEADER_END - 1] {
        assert_eq!(parse(&bytes[..length]).unwrap_err(), BzError::TooShort);
    }
}

#[test]
fn rejects_bad_boot_flag() {
    let bytes = image_with(|spec| spec.boot_flag = 0x0000);
    assert_eq!(parse(&bytes).unwrap_err(), BzError::BadBootFlag);
}

#[test]
fn rejects_bad_header_magic() {
    let bytes = image_with(|spec| spec.magic = 0xDEAD_BEEF);
    assert_eq!(parse(&bytes).unwrap_err(), BzError::BadMagic);
}

#[test]
fn rejects_version_below_minimum() {
    let bytes = image_with(|spec| spec.version = 0x0100);
    assert_eq!(
        parse(&bytes).unwrap_err(),
        BzError::UnsupportedVersion(0x0100)
    );
}

#[test]
fn rejects_version_above_maximum() {
    let bytes = image_with(|spec| spec.version = 0x0300);
    assert_eq!(
        parse(&bytes).unwrap_err(),
        BzError::UnsupportedVersion(0x0300)
    );
    let bytes = image_with(|spec| spec.version = MIN_HEADER_VERSION);
    assert!(parse(&bytes).is_ok());
}

#[test]
fn rejects_not_loaded_high() {
    let bytes = image_with(|spec| spec.loadflags = 0);
    assert_eq!(parse(&bytes).unwrap_err(), BzError::NotLoadedHigh);
}

#[test]
fn rejects_missing_64bit_entry() {
    let bytes = image_with(|spec| spec.xloadflags = 0);
    assert_eq!(parse(&bytes).unwrap_err(), BzError::Not64Bit);
}

#[test]
fn rejects_setup_truncated() {
    let bytes = build_image(&ImageSpec::default());
    let truncated = &bytes[..5 * SECTOR_SIZE - 1];
    assert_eq!(parse(truncated).unwrap_err(), BzError::SetupTruncated);
}

#[test]
fn rejects_protected_mode_too_small_for_entry() {
    let bytes = image_with(|spec| spec.kernel_len = 0x100);
    assert_eq!(parse(&bytes).unwrap_err(), BzError::ProtectedModeTooSmall);
}

#[test]
fn rejects_protected_mode_larger_than_init_size() {
    let bytes = image_with(|spec| {
        spec.kernel_len = 0x2000;
        spec.init_size = 0x1000;
    });
    assert_eq!(parse(&bytes).unwrap_err(), BzError::ProtectedModeTooLarge);
}

#[test]
fn rejects_bad_kernel_alignment() {
    let bytes = image_with(|spec| spec.kernel_alignment = 3);
    assert_eq!(parse(&bytes).unwrap_err(), BzError::BadAlignment);
}

#[test]
fn rejects_bad_min_alignment() {
    // `min_alignment` is an exponent: `12` (4 KiB) and `21` (2 MiB) are the
    // values real kernels use; an exponent above 63 cannot describe an
    // alignment a loader can honour.
    let bytes = image_with(|spec| spec.min_alignment = 64);
    assert_eq!(parse(&bytes).unwrap_err(), BzError::BadAlignment);
    let bytes = image_with(|spec| spec.min_alignment = 200);
    assert_eq!(parse(&bytes).unwrap_err(), BzError::BadAlignment);
    let bytes = image_with(|spec| spec.min_alignment = 12);
    assert_eq!(parse(&bytes).unwrap().min_alignment(), 12);
    let bytes = image_with(|spec| spec.min_alignment = 21);
    assert_eq!(parse(&bytes).unwrap().min_alignment(), 21);
}

#[test]
fn rejects_zero_init_size() {
    let bytes = image_with(|spec| spec.init_size = 0);
    assert_eq!(parse(&bytes).unwrap_err(), BzError::BadInitSize);
}

#[test]
fn rejects_preferred_address_below_code32_start() {
    let bytes = image_with(|spec| spec.pref_address = 0x0008_0000);
    assert_eq!(parse(&bytes).unwrap_err(), BzError::BadPreferredAddress);
}

#[test]
fn rejects_bad_cmdline_size() {
    let bytes = image_with(|spec| spec.cmdline_size = 0);
    assert_eq!(parse(&bytes).unwrap_err(), BzError::BadCmdlineSize);
    let bytes = image_with(|spec| spec.cmdline_size = MAX_CMDLINE_SIZE + 1);
    assert_eq!(parse(&bytes).unwrap_err(), BzError::BadCmdlineSize);
}

#[test]
fn rejects_unsupported_subarch() {
    let bytes = image_with(|spec| spec.hardware_subarch = 1);
    assert_eq!(parse(&bytes).unwrap_err(), BzError::UnsupportedSubarch);
}

#[test]
fn rejects_payload_out_of_bounds() {
    let bytes = image_with(|spec| {
        spec.payload_offset = (5 * SECTOR_SIZE) as u32 + 0x800;
        spec.payload_length = 0x1000;
    });
    assert_eq!(parse(&bytes).unwrap_err(), BzError::PayloadOutOfBounds);
}

// ---------------------------------------------------------------------------
// Load plan
// ---------------------------------------------------------------------------

#[test]
fn default_plan_selects_64bit_entry() {
    let bytes = build_image(&ImageSpec::default());
    let image = parse(&bytes).expect("valid image");
    let plan = image.default_load_plan().expect("plan");
    assert_eq!(plan.load_address, 0x0010_0000);
    assert_eq!(plan.kernel_gpa, 0x0010_0000);
    assert_eq!(plan.kernel_bytes, 0x1000);
    assert_eq!(plan.setup_gpa, SETUP_GPA);
    assert_eq!(plan.setup_bytes, 5 * SECTOR_SIZE as u64);
    assert_eq!(plan.entry_gpa(), 0x0010_0000 + ENTRY_OFFSET_64);
    assert_eq!(plan.entry, EntryPoint::Bits64 { gpa: 0x0010_0200 });
    assert!(plan.entry.is_64());
    assert_eq!(plan.entry_32_gpa, 0x0010_0000);
    assert_eq!(plan.cmdline_max, 2048);
    assert_eq!(plan.cmdline_gpa, CMDLINE_GPA);
    assert_eq!(plan.boot_params_gpa, BOOT_PARAMS_GPA);
    assert_eq!(plan.boot_params_bytes, BOOT_PARAMS_SIZE);
    assert_eq!(plan.loadflags, LOADED_HIGH);
    assert!(plan.relocatable);
}

#[test]
fn relocatable_runtime_start_is_aligned_up() {
    let bytes = build_image(&ImageSpec::default());
    let image = parse(&bytes).expect("valid image");
    // Preferred address is 16 MiB, so a 1 MiB load is relocated above it.
    let plan = image.load_plan(0x0010_0000).expect("plan");
    assert_eq!(plan.runtime_start, 0x0100_0000);
    assert_eq!(plan.runtime_end, 0x0100_0000 + 0x0040_0000);
    assert_eq!(plan.initrd_max_gpa, plan.runtime_end);
}

#[test]
fn relocatable_load_above_preference_is_used_directly() {
    let bytes = build_image(&ImageSpec::default());
    let image = parse(&bytes).expect("valid image");
    let plan = image.load_plan(0x0200_0000).expect("plan");
    assert_eq!(plan.runtime_start, 0x0200_0000);
    assert_eq!(plan.runtime_end, 0x0200_0000 + 0x0040_0000);
}

#[test]
fn non_relocatable_plan_requires_preferred_address() {
    let bytes = image_with(|spec| spec.relocatable = 0);
    let image = parse(&bytes).expect("valid image");
    // At the preferred address the plan is accepted.
    let plan = image.load_plan(0x0100_0000).expect("plan");
    assert_eq!(plan.runtime_start, 0x0100_0000);
    assert!(!plan.relocatable);
    // Anywhere else relocation is impossible.
    assert_eq!(
        image.load_plan(0x0020_0000).unwrap_err(),
        BzError::RelocationNotPossible
    );
}

#[test]
fn non_relocatable_without_preference_uses_load_address() {
    let bytes = image_with(|spec| {
        spec.relocatable = 0;
        spec.pref_address = 0;
    });
    let image = parse(&bytes).expect("valid image");
    let plan = image.load_plan(0x0010_0000).expect("plan");
    assert_eq!(plan.runtime_start, 0x0010_0000);
}

#[test]
fn plan_rejects_unaligned_load_address() {
    let bytes = build_image(&ImageSpec::default());
    let image = parse(&bytes).expect("valid image");
    assert_eq!(
        image.load_plan(0x0010_1000).unwrap_err(),
        BzError::BadAlignment
    );
}

#[test]
fn plan_rejects_load_address_below_code32_start() {
    let bytes = image_with(|spec| spec.code32_start = 0x0040_0000);
    let image = parse(&bytes).expect("valid image");
    assert_eq!(
        image.load_plan(0x0020_0000).unwrap_err(),
        BzError::BadLoadAddress
    );
}

#[test]
fn plan_rejects_above_4g_without_xloadflag() {
    let bytes = build_image(&ImageSpec::default());
    let image = parse(&bytes).expect("valid image");
    assert_eq!(
        image.load_plan(0x1_0000_0000).unwrap_err(),
        BzError::Above4GNotSupported
    );
}

#[test]
fn plan_accepts_above_4g_with_xloadflag() {
    let bytes = image_with(|spec| spec.xloadflags = XLF_KERNEL_64 | XLF_CAN_BE_LOADED_ABOVE_4G);
    let image = parse(&bytes).expect("valid image");
    let plan = image.load_plan(0x1_0000_0000).expect("plan");
    assert_eq!(plan.load_address, 0x1_0000_0000);
    assert_eq!(plan.runtime_start, 0x1_0000_0000);
    assert_eq!(plan.entry_gpa(), 0x1_0000_0200);
}

#[test]
fn plan_rejects_address_overflow() {
    let bytes = build_image(&ImageSpec::default());
    let image = parse(&bytes).expect("valid image");
    // 2 MiB-aligned address whose runtime window overflows 64 bits.
    let load = 0xFFFF_FFFF_FFE0_0000u64;
    assert_eq!(image.load_plan(load).unwrap_err(), BzError::AddressOverflow);
}

#[test]
fn required_identity_span_covers_kernel_and_buffers() {
    let bytes = build_image(&ImageSpec::default());
    let image = parse(&bytes).expect("valid image");
    let plan = image.default_load_plan().expect("plan");
    let (start, end) = plan.required_identity_span();
    // Lowest address of the plan is the boot_params zero page.
    assert_eq!(start, BOOT_PARAMS_GPA);
    // Highest address is the end of the runtime window (16 MiB + 4 MiB).
    assert_eq!(end, 0x0100_0000 + 0x0040_0000);
    assert_eq!(plan.required_identity_span(), (start, end));
}

#[test]
fn validate_against_accepts_covering_span() {
    let bytes = build_image(&ImageSpec::default());
    let image = parse(&bytes).expect("valid image");
    let plan = image.default_load_plan().expect("plan");
    let (start, end) = plan.required_identity_span();
    plan.validate_against(start, end).expect("exact span");
    plan.validate_against(0, 0x2000_0000).expect("larger span");
}

#[test]
fn validate_against_rejects_small_or_inverted_span() {
    let bytes = build_image(&ImageSpec::default());
    let image = parse(&bytes).expect("valid image");
    let plan = image.default_load_plan().expect("plan");
    let (start, end) = plan.required_identity_span();
    assert_eq!(
        plan.validate_against(start + 0x1000, end).unwrap_err(),
        BzError::OutsideGuestSpan
    );
    assert_eq!(
        plan.validate_against(start, end - 0x1000).unwrap_err(),
        BzError::OutsideGuestSpan
    );
    assert_eq!(
        plan.validate_against(end, start).unwrap_err(),
        BzError::OutsideGuestSpan
    );
}

// ---------------------------------------------------------------------------
// setup_data
// ---------------------------------------------------------------------------

#[test]
fn setup_data_empty_list_is_accepted() {
    let bytes = build_image(&ImageSpec::default());
    let image = parse(&bytes).expect("valid image");
    let mut reader = MockReader::new();
    let summary = image.walk_setup_data(&mut reader).expect("walk");
    assert_eq!(summary, SetupDataSummary::default());
    assert_eq!(summary.span(), None);
}

#[test]
fn setup_data_walks_single_node() {
    let base = 0x0005_0000u64;
    let mut reader = MockReader::new();
    reader.push_node(base, 0, 1, 16);
    let bytes = image_with(|spec| spec.setup_data = base);
    let image = parse(&bytes).expect("valid image");
    let summary = image.walk_setup_data(&mut reader).expect("walk");
    assert_eq!(summary.entries, 1);
    assert_eq!(summary.data_bytes, 16);
    assert_eq!(summary.span(), Some((base, base + 16 + 16)));
    assert_eq!(summary.start_gpa, base);
    assert_eq!(summary.end_gpa, base + 16 + 16);
}

#[test]
fn setup_data_walks_chain() {
    let base = 0x0005_0000u64;
    let second = base + 0x1000;
    let third = second + 0x800;
    let mut reader = MockReader::new();
    reader.push_node(base, second, 2, 0x40);
    reader.push_node(second, third, 3, 0x10);
    reader.push_node(third, 0, 4, 0);
    let bytes = image_with(|spec| spec.setup_data = base);
    let image = parse(&bytes).expect("valid image");
    let summary = image.walk_setup_data(&mut reader).expect("walk");
    assert_eq!(summary.entries, 3);
    assert_eq!(summary.data_bytes, 0x40 + 0x10);
    assert_eq!(summary.span(), Some((base, third + 16)));
}

#[test]
fn setup_data_rejects_unaligned_node() {
    let mut reader = MockReader::new();
    reader.push_node(0x0005_0004, 0, 1, 0);
    let bytes = image_with(|spec| spec.setup_data = 0x0005_0004);
    let image = parse(&bytes).expect("valid image");
    assert_eq!(
        image.walk_setup_data(&mut reader).unwrap_err(),
        BzError::SetupDataBadAlignment
    );
}

#[test]
fn setup_data_rejects_unreadable_node() {
    let bytes = image_with(|spec| spec.setup_data = 0x0005_0000);
    let image = parse(&bytes).expect("valid image");
    let mut reader = MockReader::new();
    assert_eq!(
        image.walk_setup_data(&mut reader).unwrap_err(),
        BzError::SetupDataOutOfBounds
    );
}

#[test]
fn setup_data_rejects_oversized_payload() {
    let base = 0x0005_0000u64;
    let mut reader = MockReader::new();
    reader.push_node(base, 0, 1, MAX_SETUP_DATA_LEN + 1);
    let bytes = image_with(|spec| spec.setup_data = base);
    let image = parse(&bytes).expect("valid image");
    assert_eq!(
        image.walk_setup_data(&mut reader).unwrap_err(),
        BzError::SetupDataBadLength
    );
}

#[test]
fn setup_data_accepts_contiguous_nodes() {
    let base = 0x0005_0000u64;
    let second = base + SETUP_DATA_HEADER_SIZE;
    let mut reader = MockReader::new();
    reader.push_node(base, second, 1, 0);
    reader.push_node(second, 0, 2, 0);
    let bytes = image_with(|spec| spec.setup_data = base);
    let image = parse(&bytes).expect("valid image");
    let summary = image.walk_setup_data(&mut reader).expect("walk");
    assert_eq!(summary.entries, 2);
    assert_eq!(
        summary.span(),
        Some((base, second + SETUP_DATA_HEADER_SIZE))
    );
}

#[test]
fn setup_data_rejects_cycle() {
    let base = 0x0005_0000u64;
    let mut reader = MockReader::new();
    // The next pointer goes backwards: a loop.
    reader.push_node(base, base, 1, 8);
    let bytes = image_with(|spec| spec.setup_data = base);
    let image = parse(&bytes).expect("valid image");
    assert_eq!(
        image.walk_setup_data(&mut reader).unwrap_err(),
        BzError::SetupDataCycle
    );
}

#[test]
fn setup_data_rejects_too_many_entries() {
    let base = 0x0005_0000u64;
    let mut reader = MockReader::new();
    for index in 0..=MAX_SETUP_DATA_ENTRIES {
        let address = base + u64::from(index) * 0x100;
        let next = if index == MAX_SETUP_DATA_ENTRIES {
            0
        } else {
            address + 0x100
        };
        reader.push_node(address, next, 1, 0);
    }
    let bytes = image_with(|spec| spec.setup_data = base);
    let image = parse(&bytes).expect("valid image");
    assert_eq!(
        image.walk_setup_data(&mut reader).unwrap_err(),
        BzError::SetupDataTooManyEntries
    );
}

#[test]
fn setup_data_rejects_address_overflow() {
    let base = 0xFFFF_FFFF_FFFF_FFF0u64;
    let mut reader = MockReader::new();
    reader.push_node(base, 0, 1, 0x1000);
    let bytes = image_with(|spec| spec.setup_data = base);
    let image = parse(&bytes).expect("valid image");
    assert_eq!(
        image.walk_setup_data(&mut reader).unwrap_err(),
        BzError::AddressOverflow
    );
}

// ---------------------------------------------------------------------------
// Robustness
// ---------------------------------------------------------------------------

#[test]
fn arbitrary_input_never_panics() {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = || {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        state
    };
    for _ in 0..2048 {
        let length = (next() % 1024) as usize;
        let bytes: Vec<u8> = (0..length).map(|_| next() as u8).collect();
        if let Ok(image) = parse(&bytes) {
            let _ = image.default_load_plan();
            let mut reader = MockReader::new();
            let _ = image.walk_setup_data(&mut reader);
        }
    }
}

#[test]
fn mutated_images_never_panic() {
    let reference = build_image(&ImageSpec::default());
    let mut state = 0x1234_5678_9ABC_DEF0u64;
    let mut next = || {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        state
    };
    for _ in 0..1024 {
        let mut bytes = reference.clone();
        let index = (next() as usize) % bytes.len();
        bytes[index] ^= 1 << ((next() as usize) % 8);
        if let Ok(image) = parse(&bytes) {
            let _ = image.load_plan(image.code32_start());
            let mut reader = MockReader::new();
            let _ = image.walk_setup_data(&mut reader);
        }
    }
}

#[test]
fn load_plan_is_stable_and_copyable() {
    let bytes = build_image(&ImageSpec::default());
    let image = parse(&bytes).expect("valid image");
    let first: LoadPlan = image.default_load_plan().expect("plan");
    let second: LoadPlan = image.default_load_plan().expect("plan");
    assert_eq!(first, second);
    // The plan and the entry point are `Copy`.
    let copied = first;
    assert_eq!(copied.entry_gpa(), first.entry_gpa());
    assert_eq!(
        copied.required_identity_span(),
        first.required_identity_span()
    );
    // `SETUP_DATA_ALIGN` is the documented node alignment.
    assert_eq!(SETUP_DATA_ALIGN, 8);
}
