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

//! L2: static guest ACPI image builder (real kernel code, not executed).

#[path = "../../kernel/src/s9vm/acpi.rs"]
mod acpi;

use acpi::{
    AcpiBuilder, AcpiError, AcpiImage, FADT_FLAG_RESET_REG_SUP, FADT_FLAG_WBINVD, ISA_OVERRIDES,
};

/// Conventional low firmware window where the image is copied.
const BASE: u64 = 0x000E_0000;

/// Encodes a builder into an exact-size buffer.
fn encode(builder: &AcpiBuilder<'_>) -> (Vec<u8>, AcpiImage) {
    let layout = builder.layout().expect("layout must succeed");
    let mut buffer = vec![0u8; layout.total_len];
    let image = builder.encode(&mut buffer).expect("encode must succeed");
    assert_eq!(image.len, buffer.len());
    (buffer, image)
}

/// Signature bytes of the table at `offset`.
fn signature(bytes: &[u8], offset: usize) -> &[u8] {
    &bytes[offset..offset + 4]
}

/// Table slice (header included) at `offset`.
fn table(bytes: &[u8], offset: usize) -> &[u8] {
    let length = u32_at(bytes, offset + 4) as usize;
    &bytes[offset..offset + length]
}

/// MADT entry descriptors as `(offset, type, length)`, in table order.
fn madt_entries(bytes: &[u8], image: &AcpiImage) -> Vec<(usize, u8, usize)> {
    let end = image.madt_offset + u32_at(bytes, image.madt_offset + 4) as usize;
    let mut offset = image.madt_offset + acpi::MADT_HEADER_LEN;
    let mut entries = Vec::new();
    while offset + 2 <= end {
        let kind = bytes[offset];
        let length = bytes[offset + 1] as usize;
        assert!(length >= 2 && offset + length <= end);
        entries.push((offset, kind, length));
        offset += length;
    }
    assert_eq!(offset, end);
    entries
}

/// Sum of the bytes modulo 256.
fn checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte))
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
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

#[test]
fn rsdp_v2_has_both_checksums() {
    let ids = [0u8, 1, 2];
    let builder = AcpiBuilder::new(BASE, &ids);
    let (bytes, image) = encode(&builder);
    assert_eq!(image.rsdp_offset, acpi::RSDP_OFFSET);
    assert_eq!(image.rsdp_offset, 0);
    assert_eq!(image.rsdp_address(0x0010_0000), 0x0010_0000);
    assert_eq!(&bytes[0..8], b"RSD PTR ".as_slice());
    assert_eq!(bytes[15], acpi::RSDP_REVISION);
    assert_eq!(u32_at(&bytes, 20) as usize, acpi::RSDP_LEN);
    // ACPI 1.0 checksum over the first 20 bytes, extended checksum over 36.
    assert_eq!(checksum(&bytes[..acpi::RSDP_V1_LEN]), 0);
    assert_eq!(checksum(&bytes[..acpi::RSDP_LEN]), 0);
}

#[test]
fn xsdt_lists_fadt_and_madt() {
    let ids = [0u8];
    let builder = AcpiBuilder::new(BASE, &ids);
    let (bytes, image) = encode(&builder);
    let offset = image.xsdt_offset;
    assert_eq!(offset % acpi::TABLE_ALIGN, 0);
    assert_eq!(signature(&bytes, offset), b"XSDT".as_slice());
    assert_eq!(u32_at(&bytes, offset + 4) as usize, acpi::XSDT_LEN);
    assert_eq!(bytes[offset + 8], acpi::XSDT_REVISION);
    assert_eq!(checksum(table(&bytes, offset)), 0);
    assert_eq!(
        u64_at(&bytes, offset + acpi::SDT_HEADER_LEN),
        BASE + image.fadt_offset as u64
    );
    assert_eq!(
        u64_at(&bytes, offset + acpi::SDT_HEADER_LEN + 8),
        BASE + image.madt_offset as u64
    );
}

#[test]
fn fadt_subset_fields_and_checksum() {
    let ids = [0u8];
    let builder = AcpiBuilder::new(BASE, &ids);
    let (bytes, image) = encode(&builder);
    let offset = image.fadt_offset;
    let dsdt_address = BASE + image.dsdt_offset as u64;
    assert_eq!(offset % acpi::TABLE_ALIGN, 0);
    assert_eq!(signature(&bytes, offset), b"FACP".as_slice());
    assert_eq!(u32_at(&bytes, offset + 4) as usize, acpi::FADT_LEN);
    assert_eq!(bytes[offset + 8], acpi::FADT_REVISION);
    assert_eq!(checksum(table(&bytes, offset)), 0);
    // DSDT pointers: 32-bit legacy field and 64-bit extended field.
    assert_eq!(u32_at(&bytes, offset + 0x28), dsdt_address as u32);
    assert_eq!(u64_at(&bytes, offset + 0x8C), dsdt_address);
    // SCI line and PM blocks.
    assert_eq!(u16_at(&bytes, offset + 0x2E), acpi::SCI_IRQ);
    assert_eq!(u32_at(&bytes, offset + 0x38), acpi::PM1A_EVENT_BLOCK);
    assert_eq!(u32_at(&bytes, offset + 0x40), acpi::PM1A_CONTROL_BLOCK);
    assert_eq!(u32_at(&bytes, offset + 0x4C), acpi::PM_TIMER_BLOCK);
    assert_eq!(u32_at(&bytes, offset + 0x50), acpi::GPE0_BLOCK);
    assert_eq!(bytes[offset + 0x58], acpi::PM1_EVENT_LENGTH);
    assert_eq!(bytes[offset + 0x59], acpi::PM1_CONTROL_LENGTH);
    assert_eq!(bytes[offset + 0x5B], acpi::PM_TIMER_LENGTH);
    assert_eq!(bytes[offset + 0x5C], acpi::GPE0_LENGTH);
    // Flags advertise WBINVD and a valid reset register.
    let flags = u32_at(&bytes, offset + 0x70);
    assert_eq!(flags, acpi::FADT_FLAGS);
    assert_ne!(flags & FADT_FLAG_WBINVD, 0);
    assert_ne!(flags & FADT_FLAG_RESET_REG_SUP, 0);
    // Reset register: system I/O space, port 0xCF9, value 0x0E.
    assert_eq!(bytes[offset + 0x74], 1);
    assert_eq!(u64_at(&bytes, offset + 0x78), acpi::RESET_REGISTER_PORT);
    assert_eq!(bytes[offset + 0x80], acpi::RESET_VALUE);
    // Extended PM block views are system I/O with the same ports.
    assert_eq!(bytes[offset + 0x94], 1);
    assert_eq!(
        u64_at(&bytes, offset + 0x98),
        u64::from(acpi::PM1A_EVENT_BLOCK)
    );
    assert_eq!(u64_at(&bytes, offset + 0xE0), u64::from(acpi::GPE0_BLOCK));
}

#[test]
fn dsdt_holds_minimal_aml_namespace() {
    let ids = [0u8];
    let builder = AcpiBuilder::new(BASE, &ids);
    let (bytes, image) = encode(&builder);
    let offset = image.dsdt_offset;
    assert_eq!(offset % acpi::TABLE_ALIGN, 0);
    assert_eq!(signature(&bytes, offset), b"DSDT".as_slice());
    assert_eq!(u32_at(&bytes, offset + 4) as usize, acpi::DSDT_LEN);
    assert_eq!(bytes[offset + 8], acpi::DSDT_REVISION);
    assert_eq!(checksum(table(&bytes, offset)), 0);
    assert_eq!(
        &bytes[offset + acpi::SDT_HEADER_LEN..offset + acpi::DSDT_LEN],
        acpi::DSDT_AML.as_slice()
    );
    // ScopeOp, package length, root prefix, `_SB_` name segment.
    assert_eq!(bytes[offset + acpi::SDT_HEADER_LEN], 0x10);
    assert_eq!(bytes[offset + acpi::SDT_HEADER_LEN + 1], 0x06);
    assert_eq!(bytes[offset + acpi::SDT_HEADER_LEN + 2], 0x5C);
}

#[test]
fn madt_has_one_local_apic_per_vcpu() {
    let ids = [3u8, 7, 11];
    let builder = AcpiBuilder::new(BASE, &ids);
    let (bytes, image) = encode(&builder);
    let offset = image.madt_offset;
    assert_eq!(offset % acpi::TABLE_ALIGN, 0);
    assert_eq!(signature(&bytes, offset), b"APIC".as_slice());
    assert_eq!(bytes[offset + 8], acpi::MADT_REVISION);
    assert_eq!(
        u32_at(&bytes, offset + acpi::SDT_HEADER_LEN),
        acpi::LOCAL_APIC_ADDRESS
    );
    assert_eq!(
        u32_at(&bytes, offset + acpi::SDT_HEADER_LEN + 4),
        acpi::MADT_PCAT_COMPAT
    );
    assert_eq!(checksum(table(&bytes, offset)), 0);
    let entries = madt_entries(&bytes, &image);
    let local_apics: Vec<_> = entries.iter().filter(|entry| entry.1 == 0).collect();
    assert_eq!(local_apics.len(), ids.len());
    for (index, (entry_offset, kind, length)) in local_apics.iter().enumerate() {
        assert_eq!(*kind, 0);
        assert_eq!(*length, acpi::LOCAL_APIC_ENTRY_LEN);
        assert_eq!(bytes[entry_offset + 2], index as u8);
        assert_eq!(bytes[entry_offset + 3], ids[index]);
        assert_eq!(u32_at(&bytes, entry_offset + 4), acpi::LOCAL_APIC_ENABLED);
    }
}

#[test]
fn madt_ioapic_is_at_fixed_address() {
    let ids = [0u8];
    let builder = AcpiBuilder::new(BASE, &ids);
    let (bytes, image) = encode(&builder);
    let entries = madt_entries(&bytes, &image);
    let ioapics: Vec<_> = entries.iter().filter(|entry| entry.1 == 1).collect();
    assert_eq!(ioapics.len(), 1);
    let (offset, kind, length) = ioapics[0];
    assert_eq!(*kind, 1);
    assert_eq!(*length, acpi::IOAPIC_ENTRY_LEN);
    assert_eq!(bytes[offset + 2], acpi::IOAPIC_ID);
    assert_eq!(u32_at(&bytes, offset + 4), acpi::IOAPIC_ADDRESS);
    assert_eq!(u32_at(&bytes, offset + 4), 0xFEC0_0000);
    assert_eq!(u32_at(&bytes, offset + 8), acpi::IOAPIC_GSI_BASE);
    assert_eq!(u32_at(&bytes, offset + 8), 0);
}

#[test]
fn madt_isa_overrides_are_correct() {
    let ids = [0u8, 1];
    let builder = AcpiBuilder::new(BASE, &ids);
    let (bytes, image) = encode(&builder);
    let entries = madt_entries(&bytes, &image);
    let overrides: Vec<_> = entries.iter().filter(|entry| entry.1 == 2).collect();
    assert_eq!(overrides.len(), ISA_OVERRIDES.len());
    let mut sources = Vec::new();
    for (entry, expected) in overrides.iter().zip(ISA_OVERRIDES.iter()) {
        let (offset, kind, length) = **entry;
        assert_eq!(kind, 2);
        assert_eq!(length, acpi::INT_SOURCE_OVERRIDE_LEN);
        assert_eq!(bytes[offset + 2], acpi::ISA_BUS);
        assert_eq!(bytes[offset + 3], expected.irq_source);
        assert_eq!(u32_at(&bytes, offset + 4), expected.gsi);
        assert_eq!(u16_at(&bytes, offset + 8), expected.flags);
        sources.push(bytes[offset + 3]);
    }
    // Only IRQ0 (cascade to GSI2) and IRQ9 (level, active high) need an
    // override; every other ISA line stays identity-mapped.
    assert_eq!(sources, [0u8, 9]);
    assert_eq!(ISA_OVERRIDES[0].irq_source, 0);
    assert_eq!(ISA_OVERRIDES[0].gsi, 2);
    assert_eq!(ISA_OVERRIDES[0].flags, 0);
    assert_eq!(ISA_OVERRIDES[1].irq_source, 9);
    assert_eq!(ISA_OVERRIDES[1].gsi, 9);
    assert_eq!(ISA_OVERRIDES[1].flags, 0x000D);
    assert!(acpi::ISA_IRQ_COUNT > 9);
}

#[test]
fn x2apic_policy_emits_type_9_entries() {
    let ids = [2u8, 5];
    let builder = AcpiBuilder::new(BASE, &ids).with_x2apic(true);
    let (bytes, image) = encode(&builder);
    let entries = madt_entries(&bytes, &image);
    let x2apics: Vec<_> = entries.iter().filter(|entry| entry.1 == 9).collect();
    assert_eq!(x2apics.len(), ids.len());
    assert!(entries.iter().all(|entry| entry.1 != 0));
    for (index, (offset, kind, length)) in x2apics.iter().enumerate() {
        assert_eq!(*kind, 9);
        assert_eq!(*length, acpi::LOCAL_X2APIC_ENTRY_LEN);
        assert_eq!(u32_at(&bytes, offset + 4), u32::from(ids[index]));
        assert_eq!(u32_at(&bytes, offset + 8), acpi::LOCAL_APIC_ENABLED);
        assert_eq!(u32_at(&bytes, offset + 12), index as u32);
    }
    let expected = acpi::MADT_HEADER_LEN
        + ids.len() * acpi::LOCAL_X2APIC_ENTRY_LEN
        + acpi::IOAPIC_ENTRY_LEN
        + ISA_OVERRIDES.len() * acpi::INT_SOURCE_OVERRIDE_LEN;
    assert_eq!(u32_at(&bytes, image.madt_offset + 4) as usize, expected);
}

#[test]
fn buffer_too_small_is_rejected() {
    let ids = [0u8];
    let builder = AcpiBuilder::new(BASE, &ids);
    let layout = builder.layout().expect("layout must succeed");
    let mut buffer = vec![0u8; layout.total_len - 1];
    assert_eq!(
        builder.encode(&mut buffer),
        Err(AcpiError::BufferTooSmall {
            needed: layout.total_len,
            provided: layout.total_len - 1,
        })
    );
    assert_eq!(
        builder.encode(&mut []),
        Err(AcpiError::BufferTooSmall {
            needed: layout.total_len,
            provided: 0,
        })
    );
}

#[test]
fn exact_and_larger_buffers_are_accepted() {
    let ids = [0u8];
    let builder = AcpiBuilder::new(BASE, &ids);
    let layout = builder.layout().expect("layout must succeed");
    let mut exact = vec![0u8; layout.total_len];
    let image = builder.encode(&mut exact).expect("exact buffer works");
    assert_eq!(image.len, layout.total_len);
    // A larger buffer is accepted and its tail is left untouched.
    let mut larger = vec![0xAAu8; layout.total_len + 64];
    let image = builder.encode(&mut larger).expect("larger buffer works");
    assert_eq!(image.len, layout.total_len);
    assert_eq!(&larger[..layout.total_len], &exact[..]);
    assert!(larger[layout.total_len..].iter().all(|byte| *byte == 0xAA));
}

#[test]
fn encode_is_deterministic() {
    let ids = [5u8, 6];
    let builder = AcpiBuilder::new(BASE, &ids);
    let (first, first_image) = encode(&builder);
    let (second, second_image) = encode(&builder);
    assert_eq!(first_image, second_image);
    assert_eq!(first, second);
    let copy = builder;
    let (third, _) = encode(&copy);
    assert_eq!(first, third);
}

#[test]
fn layout_scales_with_vcpu_count() {
    let mut previous_total = 0;
    for count in 1..=8usize {
        let ids: Vec<u8> = (0..count).map(|index| index as u8).collect();
        let builder = AcpiBuilder::new(BASE, &ids);
        let layout = builder.layout().expect("layout must succeed");
        assert_eq!(layout.rsdp_offset, 0);
        assert!(layout.rsdp_offset < layout.xsdt_offset);
        assert!(layout.xsdt_offset < layout.fadt_offset);
        assert!(layout.fadt_offset < layout.madt_offset);
        assert!(layout.madt_offset < layout.dsdt_offset);
        assert!(layout.rsdt_offset.expect("RSDT present") < layout.dsdt_offset);
        for offset in [
            layout.xsdt_offset,
            layout.fadt_offset,
            layout.madt_offset,
            layout.rsdt_offset.expect("RSDT present"),
            layout.dsdt_offset,
        ] {
            assert_eq!(offset % acpi::TABLE_ALIGN, 0);
        }
        let mut buffer = vec![0u8; layout.total_len];
        builder.encode(&mut buffer).expect("encode must succeed");
        let expected_madt = acpi::MADT_HEADER_LEN
            + count * acpi::LOCAL_APIC_ENTRY_LEN
            + acpi::IOAPIC_ENTRY_LEN
            + ISA_OVERRIDES.len() * acpi::INT_SOURCE_OVERRIDE_LEN;
        assert_eq!(
            u32_at(&buffer, layout.madt_offset + 4) as usize,
            expected_madt
        );
        // Growing the vCPU count never shrinks the image; 64-byte alignment
        // can absorb a few entries, so the growth is monotonic, not strict.
        assert!(layout.total_len >= previous_total);
        previous_total = layout.total_len;
    }
}

#[test]
fn max_vcpus_is_accepted_and_above_limit_is_rejected() {
    let ids: Vec<u8> = (0..acpi::MAX_VCPUS).map(|index| index as u8).collect();
    let builder = AcpiBuilder::new(BASE, &ids);
    let (bytes, image) = encode(&builder);
    assert_eq!(image.len, bytes.len());
    let entries = madt_entries(&bytes, &image);
    assert_eq!(
        entries.iter().filter(|entry| entry.1 == 0).count(),
        acpi::MAX_VCPUS
    );

    let too_many = vec![0u8; acpi::MAX_VCPUS + 1];
    let builder = AcpiBuilder::new(BASE, &too_many);
    assert_eq!(builder.layout(), Err(AcpiError::VcpuLimitExceeded));
    let mut buffer = vec![0u8; acpi::MAX_IMAGE_LEN];
    assert_eq!(
        builder.encode(&mut buffer),
        Err(AcpiError::VcpuLimitExceeded)
    );
}

#[test]
fn no_vcpu_is_rejected() {
    let ids: [u8; 0] = [];
    let builder = AcpiBuilder::new(BASE, &ids);
    assert_eq!(builder.vcpu_count(), 0);
    assert_eq!(builder.layout(), Err(AcpiError::NoVcpu));
    let mut buffer = vec![0u8; acpi::MAX_IMAGE_LEN];
    assert_eq!(builder.encode(&mut buffer), Err(AcpiError::NoVcpu));
}

#[test]
fn misaligned_base_is_rejected() {
    let ids = [0u8];
    let builder = AcpiBuilder::new(BASE + 8, &ids);
    assert_eq!(builder.layout(), Err(AcpiError::MisalignedBase));
    let mut buffer = vec![0u8; acpi::MAX_IMAGE_LEN];
    assert_eq!(builder.encode(&mut buffer), Err(AcpiError::MisalignedBase));
}

#[test]
fn image_above_four_gib_is_rejected() {
    let ids = [0u8];
    let builder = AcpiBuilder::new(1 << 32, &ids);
    assert_eq!(builder.layout(), Err(AcpiError::AddressNotRepresentable));
    assert_eq!(builder.base(), 1 << 32);
}

#[test]
fn legacy_rsdt_v1_view_is_consistent() {
    let ids = [0u8];
    let builder = AcpiBuilder::new(BASE, &ids).with_legacy_rsdt(true);
    let (bytes, image) = encode(&builder);
    let rsdt_offset = image.rsdt_offset.expect("legacy RSDT present");
    assert_eq!(rsdt_offset % acpi::TABLE_ALIGN, 0);
    assert_eq!(signature(&bytes, rsdt_offset), b"RSDT".as_slice());
    assert_eq!(u32_at(&bytes, rsdt_offset + 4) as usize, acpi::RSDT_LEN);
    assert_eq!(bytes[rsdt_offset + 8], acpi::RSDT_REVISION);
    assert_eq!(checksum(table(&bytes, rsdt_offset)), 0);
    assert_eq!(
        u32_at(&bytes, rsdt_offset + acpi::SDT_HEADER_LEN),
        (BASE + image.fadt_offset as u64) as u32
    );
    assert_eq!(
        u32_at(&bytes, rsdt_offset + acpi::SDT_HEADER_LEN + 4),
        (BASE + image.madt_offset as u64) as u32
    );
    // The RSDP v1 pointer targets the RSDT and the v1 checksum still holds.
    assert_eq!(u32_at(&bytes, 16), (BASE + rsdt_offset as u64) as u32);
    assert_eq!(checksum(&bytes[..acpi::RSDP_V1_LEN]), 0);
}

#[test]
fn legacy_rsdt_view_can_be_disabled() {
    let ids = [0u8];
    let with_rsdt = AcpiBuilder::new(BASE, &ids).with_legacy_rsdt(true);
    let without_rsdt = AcpiBuilder::new(BASE, &ids).with_legacy_rsdt(false);
    let (with_bytes, with_image) = encode(&with_rsdt);
    let (without_bytes, without_image) = encode(&without_rsdt);
    assert!(with_image.rsdt_offset.is_some());
    assert!(without_image.rsdt_offset.is_none());
    assert!(without_image.len < with_image.len);
    // No legacy pointer, but the ACPI 1.0 checksum is still valid.
    assert_eq!(u32_at(&without_bytes, 16), 0);
    assert_eq!(checksum(&without_bytes[..acpi::RSDP_V1_LEN]), 0);
    assert_eq!(
        u64_at(&without_bytes, 24),
        BASE + without_image.xsdt_offset as u64
    );
    assert_eq!(
        u32_at(&with_bytes, 16),
        (BASE + with_image.rsdt_offset.expect("present") as u64) as u32
    );
}

#[test]
fn duplicate_apic_ids_are_rejected() {
    let ids = [4u8, 4];
    let builder = AcpiBuilder::new(BASE, &ids);
    assert_eq!(builder.layout(), Err(AcpiError::DuplicateApicId));
    let mut buffer = vec![0u8; acpi::MAX_IMAGE_LEN];
    assert_eq!(builder.encode(&mut buffer), Err(AcpiError::DuplicateApicId));
}

#[test]
fn every_table_checksum_sums_to_zero() {
    let ids = [0u8, 1];
    let builder = AcpiBuilder::new(BASE, &ids).with_x2apic(true);
    let (bytes, image) = encode(&builder);
    let rsdt_offset = image.rsdt_offset.expect("legacy RSDT present");
    let madt_len = u32_at(&bytes, image.madt_offset + 4) as usize;
    for (name, offset, length) in [
        ("XSDT", image.xsdt_offset, acpi::XSDT_LEN),
        ("FADT", image.fadt_offset, acpi::FADT_LEN),
        ("MADT", image.madt_offset, madt_len),
        ("RSDT", rsdt_offset, acpi::RSDT_LEN),
        ("DSDT", image.dsdt_offset, acpi::DSDT_LEN),
    ] {
        assert_eq!(checksum(&bytes[offset..offset + length]), 0, "{name}");
    }
    assert_eq!(checksum(&bytes[..acpi::RSDP_LEN]), 0, "RSDP");
    assert!(image.len <= acpi::MAX_IMAGE_LEN);
}

#[test]
fn xsdt_and_rsdt_list_the_serial_console_table() {
    let ids = [0u8];
    let builder = AcpiBuilder::new(BASE, &ids);
    let (bytes, image) = encode(&builder);
    // XSDT: FADT, MADT, SPCR in order.
    let xsdt = image.xsdt_offset;
    assert_eq!(
        u64::from_le_bytes(bytes[xsdt + 52..xsdt + 60].try_into().unwrap()),
        BASE + image.spcr_offset as u64,
        "the SPCR must be reachable through the XSDT"
    );
    // The legacy RSDT view lists it too.
    let rsdt = image.rsdt_offset.expect("legacy RSDT present");
    assert_eq!(
        u32::from_le_bytes(bytes[rsdt + 44..rsdt + 48].try_into().unwrap()),
        (BASE + image.spcr_offset as u64) as u32
    );
}

#[test]
fn spcr_describes_the_modeled_com1_uart() {
    let ids = [0u8];
    let builder = AcpiBuilder::new(BASE, &ids);
    let (bytes, image) = encode(&builder);
    let offset = image.spcr_offset;
    assert_eq!(&bytes[offset..offset + 4], b"SPCR");
    assert_eq!(u32_at(&bytes, offset + 4) as usize, acpi::SPCR_LEN);
    assert_eq!(bytes[offset + 8], acpi::SPCR_REVISION);
    // Interface type and generic address structure (system I/O, byte access).
    assert_eq!(bytes[offset + 36], acpi::SPCR_INTERFACE_16550);
    assert_eq!(bytes[offset + 40], 1);
    assert_eq!(bytes[offset + 41], 8);
    assert_eq!(bytes[offset + 43], 1);
    assert_eq!(
        u64::from_le_bytes(bytes[offset + 44..offset + 52].try_into().unwrap()),
        u64::from(acpi::SPCR_COM1_PORT)
    );
    // Interrupt: through the I/O APIC on the COM1 global system interrupt.
    assert_eq!(bytes[offset + 52], acpi::SPCR_INTERRUPT_IOAPIC);
    assert_eq!(
        u32_at(&bytes, offset + 54),
        acpi::SPCR_COM1_GSI,
        "the SPCR must name the same GSI as the MADT wiring"
    );
    assert_eq!(bytes[offset + 58], acpi::SPCR_BAUD_115200);
    assert_eq!(checksum(&bytes[offset..offset + acpi::SPCR_LEN]), 0);
}

#[test]
fn fadt_advertises_the_rtc_century_register() {
    let ids = [0u8];
    let builder = AcpiBuilder::new(BASE, &ids);
    let (bytes, image) = encode(&builder);
    // FADT: CENTURY byte at offset 0x6C.
    assert_eq!(bytes[image.fadt_offset + 0x6C], 0x32);
}
