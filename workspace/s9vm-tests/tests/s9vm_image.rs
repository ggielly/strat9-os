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

//! L2: s9vm guest image loader : ELF64 parser and load plan.

#![allow(dead_code)]

#[path = "../../kernel/src/s9vm/image.rs"]
mod image;

use image::{Image, ImageError, ImageKind, MAX_SEGMENTS, PAGE_SIZE, Segment};

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;
const EHDR: usize = 64;
const PHDR: usize = 56;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
/// Read plus execute, the usual text segment permissions.
const RX: u32 = PF_R | PF_X;
/// Read plus write, the usual data segment permissions.
const RW: u32 = PF_R | PF_W;

/// Synthetic program header description.
#[derive(Clone, Copy)]
struct Spec {
    vaddr: u64,
    memsz: u64,
    filesz: u64,
    offset: u64,
    flags: u32,
}

/// Segment whose file-backed data starts at page `index + 1`.
fn seg(index: usize, vaddr: u64, memsz: u64, filesz: u64, flags: u32) -> Spec {
    Spec {
        vaddr,
        memsz,
        filesz,
        offset: (index as u64 + 1) * PAGE_SIZE,
        flags,
    }
}

/// Byte written in the file-backed payload of segment `index`.
fn payload(index: usize) -> u8 {
    0x40u8.wrapping_add(index as u8)
}

/// Standalone segment value (for pure permission/geometry checks).
fn segment(vaddr: u64, memsz: u64, filesz: u64, offset: u64, flags: u32) -> Segment {
    Segment {
        vaddr,
        memsz,
        filesz,
        file_offset: offset,
        flags,
    }
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

/// Builds a well-formed synthetic image (callers then corrupt fields to test
/// the rejection paths).
fn build(kind: u16, machine: u16, entry: u64, specs: &[Spec]) -> Vec<u8> {
    let mut bytes = vec![0u8; EHDR + PHDR * specs.len()];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2; // ELFCLASS64
    bytes[5] = 1; // ELFDATA2LSB
    bytes[6] = 1; // EV_CURRENT
    put_u16(&mut bytes, 0x10, kind);
    put_u16(&mut bytes, 0x12, machine);
    put_u32(&mut bytes, 0x14, 1);
    put_u64(&mut bytes, 0x18, entry);
    put_u64(&mut bytes, 0x20, EHDR as u64);
    put_u16(&mut bytes, 0x34, EHDR as u16);
    put_u16(&mut bytes, 0x36, PHDR as u16);
    put_u16(&mut bytes, 0x38, specs.len() as u16);
    for (index, spec) in specs.iter().enumerate() {
        let base = EHDR + index * PHDR;
        put_u32(&mut bytes, base, 1); // PT_LOAD
        put_u32(&mut bytes, base + 4, spec.flags);
        put_u64(&mut bytes, base + 8, spec.offset);
        put_u64(&mut bytes, base + 16, spec.vaddr);
        put_u64(&mut bytes, base + 24, spec.vaddr);
        put_u64(&mut bytes, base + 32, spec.filesz);
        put_u64(&mut bytes, base + 40, spec.memsz);
        put_u64(&mut bytes, base + 48, PAGE_SIZE);
        let end = spec.offset as usize + spec.filesz as usize;
        if bytes.len() < end {
            bytes.resize(end, 0);
        }
        for byte in 0..spec.filesz as usize {
            bytes[spec.offset as usize + byte] = payload(index);
        }
    }
    bytes
}

/// Minimal valid image: one read/execute segment at virtual address `0x1000`,
/// entered 0x100 bytes into the segment.
fn simple() -> Vec<u8> {
    build(
        ET_EXEC,
        EM_X86_64,
        0x1100,
        &[seg(0, 0x1000, 0x200, 0x200, RX)],
    )
}

#[test]
fn parses_minimal_image() {
    let bytes = simple();
    let parsed = Image::parse(&bytes).expect("valid image");
    assert_eq!(parsed.kind(), ImageKind::Exec);
    assert_eq!(parsed.entry(), 0x1100);
    assert_eq!(parsed.segment_count(), 1);
    assert_eq!(parsed.segments().len(), 1);
    let segment = parsed.segments()[0];
    assert_eq!(segment.vaddr, 0x1000);
    assert_eq!(segment.memsz, 0x200);
    assert_eq!(segment.filesz, 0x200);
    assert_eq!(segment.file_offset, 0x1000);
    assert_eq!(segment.flags, RX);
    assert_eq!(segment.end_vaddr(), 0x1200);
    assert_eq!(parsed.base_vaddr(), 0x1000);
    assert_eq!(parsed.span_len(), PAGE_SIZE);
    assert_eq!(parsed.total_pages(), 1);
    assert_eq!(parsed.file_size(), bytes.len());
}

#[test]
fn maps_elf_permissions_to_world_memory_bits() {
    // ELF PF_X/PF_W/PF_R are not the world-memory bit assignments.
    assert_eq!(segment(0x1000, 0x10, 0x10, 0x1000, RX).perms_bits(), 5);
    assert_eq!(segment(0x1000, 0x10, 0x10, 0x1000, RW).perms_bits(), 3);
    assert_eq!(segment(0x1000, 0x10, 0x10, 0x1000, PF_R).perms_bits(), 1);
    assert_eq!(segment(0x1000, 0x10, 0x10, 0x1000, PF_X).perms_bits(), 4);
    assert_eq!(segment(0x1000, 0x10, 0x10, 0x1000, 0).perms_bits(), 0);
}

#[test]
fn exposes_file_backed_prefix_of_segment() {
    let bytes = simple();
    let parsed = Image::parse(&bytes).expect("valid image");
    let segment = parsed.segments()[0];
    let data = parsed.bytes_for_segment(&segment).expect("in bounds");
    assert_eq!(data.len(), 0x200);
    assert!(data.iter().all(|byte| *byte == payload(0)));
    assert_eq!(segment.file_end(), 0x1200);

    // A segment that does not belong to the image is rejected, not panicked.
    let foreign = Segment {
        file_offset: u64::MAX,
        ..segment
    };
    assert!(parsed.bytes_for_segment(&foreign).is_none());
}

#[test]
fn relocates_segments_and_entry_on_load_base() {
    let bytes = simple();
    let parsed = Image::parse(&bytes).expect("valid image");
    let base = 0x20_0000u64;
    assert_eq!(parsed.load_span(base), Some((base, base + PAGE_SIZE)));
    assert_eq!(parsed.segment_gpa(base, &parsed.segments()[0]), Some(base));
    assert_eq!(parsed.entry_gpa(base), Some(base + 0x100));
    assert_eq!(parsed.entry_gpa(0), Some(0x100));

    // Relocation must not wrap around the 64-bit address space.
    assert_eq!(parsed.load_span(u64::MAX), None);
}

#[test]
fn keeps_multiple_segments_ordered_and_spans_whole_image() {
    let bytes = build(
        ET_EXEC,
        EM_X86_64,
        0x2000,
        &[
            seg(0, 0x1000, 0x1000, 0x1000, RX),
            seg(1, 0x3000, 0x2000, 0x100, RW),
        ],
    );
    let parsed = Image::parse(&bytes).expect("valid image");
    assert_eq!(parsed.segment_count(), 2);
    assert_eq!(parsed.segments()[0].vaddr, 0x1000);
    assert_eq!(parsed.segments()[1].vaddr, 0x3000);
    assert_eq!(parsed.base_vaddr(), 0x1000);
    // Pages 0x1000..0x5000.
    assert_eq!(parsed.span_len(), 0x4000);
    assert_eq!(parsed.total_pages(), 3);
    let base = 0x80_0000u64;
    assert_eq!(
        parsed.segment_gpa(base, &parsed.segments()[1]),
        Some(base + 0x2000)
    );
    assert_eq!(parsed.load_span(base), Some((base, base + 0x4000)));
}

#[test]
fn accepts_position_independent_executable() {
    let bytes = build(
        ET_DYN,
        EM_X86_64,
        0x1000,
        &[seg(0, 0x1000, 0x100, 0x100, RX)],
    );
    let parsed = Image::parse(&bytes).expect("valid ET_DYN image");
    assert_eq!(parsed.kind(), ImageKind::Dynamic);
    assert_eq!(parsed.base_vaddr(), 0x1000);
    assert_eq!(parsed.entry_gpa(0x40_0000), Some(0x40_0000));
}

#[test]
fn rejects_truncated_header() {
    let bytes = simple();
    assert_eq!(
        Image::parse(&bytes[..EHDR - 1]).unwrap_err(),
        ImageError::TruncatedHeader
    );
    assert_eq!(Image::parse(&[]).unwrap_err(), ImageError::TruncatedHeader);
}

#[test]
fn rejects_bad_identification_fields() {
    let mut bytes = simple();
    bytes[1] = b'X';
    assert_eq!(Image::parse(&bytes).unwrap_err(), ImageError::BadMagic);

    let mut bytes = simple();
    bytes[4] = 1; // ELFCLASS32
    assert_eq!(Image::parse(&bytes).unwrap_err(), ImageError::BadClass);

    let mut bytes = simple();
    bytes[5] = 2; // big-endian
    assert_eq!(Image::parse(&bytes).unwrap_err(), ImageError::BadEndianness);

    let mut bytes = simple();
    bytes[6] = 0;
    assert_eq!(
        Image::parse(&bytes).unwrap_err(),
        ImageError::BadIdentVersion
    );

    let mut bytes = simple();
    put_u32(&mut bytes, 0x14, 0);
    assert_eq!(Image::parse(&bytes).unwrap_err(), ImageError::BadVersion);
}

#[test]
fn rejects_bad_header_sizes() {
    let mut bytes = simple();
    put_u16(&mut bytes, 0x34, 52);
    assert_eq!(Image::parse(&bytes).unwrap_err(), ImageError::BadHeaderSize);

    let mut bytes = simple();
    put_u16(&mut bytes, 0x36, 54);
    assert_eq!(
        Image::parse(&bytes).unwrap_err(),
        ImageError::BadProgramHeaderSize
    );
}

#[test]
fn rejects_unsupported_object() {
    let mut bytes = simple();
    put_u16(&mut bytes, 0x12, 3); // EM_386
    assert_eq!(
        Image::parse(&bytes).unwrap_err(),
        ImageError::UnsupportedMachine
    );

    let mut bytes = simple();
    put_u16(&mut bytes, 0x10, 1); // ET_REL
    assert_eq!(
        Image::parse(&bytes).unwrap_err(),
        ImageError::UnsupportedType
    );
}

#[test]
fn rejects_missing_loadable_segment() {
    let empty = build(ET_EXEC, EM_X86_64, 0, &[]);
    assert_eq!(
        Image::parse(&empty).unwrap_err(),
        ImageError::NoLoadableSegments
    );

    // A program header table with no PT_LOAD entry (here PT_NOTE).
    let mut bytes = simple();
    put_u32(&mut bytes, EHDR, 4);
    assert_eq!(
        Image::parse(&bytes).unwrap_err(),
        ImageError::NoLoadableSegments
    );
}

#[test]
fn rejects_program_header_table_out_of_bounds() {
    let mut bytes = simple();
    put_u64(&mut bytes, 0x20, 0x1000_0000);
    assert_eq!(
        Image::parse(&bytes).unwrap_err(),
        ImageError::TruncatedProgramHeaders
    );

    let mut bytes = simple();
    put_u64(&mut bytes, 0x20, 0);
    assert_eq!(
        Image::parse(&bytes).unwrap_err(),
        ImageError::BadProgramHeaders
    );

    let mut bytes = simple();
    put_u64(&mut bytes, 0x20, EHDR as u64 + 1);
    assert_eq!(
        Image::parse(&bytes).unwrap_err(),
        ImageError::BadProgramHeaders
    );
}

#[test]
fn rejects_truncated_program_header_table() {
    let mut bytes = build(ET_EXEC, EM_X86_64, 0x1000, &[seg(0, 0x1000, 0x100, 0, RX)]);
    bytes.truncate(EHDR + PHDR / 2);
    assert_eq!(
        Image::parse(&bytes).unwrap_err(),
        ImageError::TruncatedProgramHeaders
    );
}

#[test]
fn rejects_too_many_program_headers() {
    // A well-formed table, but above the guest loader's policy limit.
    let mut bytes = simple();
    let count = 129usize;
    bytes.resize(EHDR + count * PHDR, 0);
    put_u16(&mut bytes, 0x38, count as u16);
    assert_eq!(
        Image::parse(&bytes).unwrap_err(),
        ImageError::TooManyProgramHeaders
    );
}

#[test]
fn rejects_invalid_segment_sizes() {
    let bytes = build(
        ET_EXEC,
        EM_X86_64,
        0x1000,
        &[seg(0, 0x1000, 0x100, 0x200, RW)],
    );
    assert_eq!(
        Image::parse(&bytes).unwrap_err(),
        ImageError::FileSizeExceedsMemorySize
    );

    let bytes = build(ET_EXEC, EM_X86_64, 0x1000, &[seg(0, 0x1000, 0, 0, RW)]);
    assert_eq!(Image::parse(&bytes).unwrap_err(), ImageError::EmptySegment);
}

#[test]
fn rejects_segment_payload_past_end_of_file() {
    let mut bytes = simple();
    // Segment 0 data starts at 0x1000 and spans 0x200 bytes.
    bytes.truncate(0x11FF);
    assert_eq!(
        Image::parse(&bytes).unwrap_err(),
        ImageError::SegmentOutOfBounds
    );
}

#[test]
fn rejects_segment_without_page_congruence() {
    let spec = Spec {
        vaddr: 0x2000,
        memsz: 0x10,
        filesz: 0x10,
        offset: 0x1100, // 0x1100 % PAGE != 0x2000 % PAGE
        flags: RX,
    };
    let bytes = build(ET_EXEC, EM_X86_64, 0x2000, &[spec]);
    assert_eq!(
        Image::parse(&bytes).unwrap_err(),
        ImageError::MisalignedSegment
    );
}

#[test]
fn rejects_segment_alignment_that_is_not_a_power_of_two() {
    let mut bytes = simple();
    put_u64(&mut bytes, EHDR + 48, 3);
    assert_eq!(
        Image::parse(&bytes).unwrap_err(),
        ImageError::BadSegmentAlignment
    );
}

#[test]
fn rejects_segment_address_overflow() {
    let spec = Spec {
        vaddr: u64::MAX - 0xFFF,
        memsz: 0x2000,
        filesz: 0x2000,
        offset: 0x2000,
        flags: RW,
    };
    let bytes = build(ET_EXEC, EM_X86_64, spec.vaddr, &[spec]);
    assert_eq!(
        Image::parse(&bytes).unwrap_err(),
        ImageError::SegmentOverflow
    );
}

#[test]
fn rejects_unordered_segments() {
    let bytes = build(
        ET_EXEC,
        EM_X86_64,
        0x3000,
        &[
            seg(0, 0x3000, 0x100, 0x100, RX),
            seg(1, 0x2000, 0x100, 0x100, RW),
        ],
    );
    assert_eq!(
        Image::parse(&bytes).unwrap_err(),
        ImageError::UnorderedSegments
    );
}

#[test]
fn rejects_page_overlapping_segments() {
    // Two segments sharing a page even though their virtual addresses differ.
    let first = seg(0, 0x1000, 0x1000, 0x1000, RX);
    let second = Spec {
        vaddr: 0x1800,
        memsz: 0x80,
        filesz: 0x80,
        offset: 0x2800,
        flags: RW,
    };
    let bytes = build(ET_EXEC, EM_X86_64, 0x1000, &[first, second]);
    assert_eq!(
        Image::parse(&bytes).unwrap_err(),
        ImageError::OverlappingSegments
    );
}

#[test]
fn accepts_up_to_the_segment_limit() {
    let specs: Vec<Spec> = (0..MAX_SEGMENTS)
        .map(|index| seg(index, (index as u64 + 1) * 0x1_0000, 0x10, 0x10, RX))
        .collect();
    let bytes = build(ET_EXEC, EM_X86_64, 0x1_0000, &specs);
    let parsed = Image::parse(&bytes).expect("image at the segment limit");
    assert_eq!(parsed.segment_count(), MAX_SEGMENTS);
}

#[test]
fn rejects_too_many_segments() {
    let specs: Vec<Spec> = (0..MAX_SEGMENTS + 1)
        .map(|index| seg(index, (index as u64 + 1) * 0x1_0000, 0x10, 0x10, RX))
        .collect();
    let bytes = build(ET_EXEC, EM_X86_64, 0x1_0000, &specs);
    assert_eq!(
        Image::parse(&bytes).unwrap_err(),
        ImageError::TooManySegments
    );
}

#[test]
fn reports_entry_outside_segments() {
    // Entry point below the only loadable segment.
    let bytes = build(
        ET_EXEC,
        EM_X86_64,
        0x9000,
        &[seg(0, 0x1000, 0x100, 0x100, RX)],
    );
    let parsed = Image::parse(&bytes).expect("valid image");
    assert!(!parsed.entry_is_mapped());
    assert!(!parsed.entry_is_executable());

    // Entry inside a mapped but non-executable segment.
    let bytes = build(
        ET_EXEC,
        EM_X86_64,
        0x1000,
        &[seg(0, 0x1000, 0x100, 0x100, RW)],
    );
    let parsed = Image::parse(&bytes).expect("valid image");
    assert!(parsed.entry_is_mapped());
    assert!(!parsed.entry_is_executable());

    // Entry executable.
    let reference = simple();
    let parsed = Image::parse(&reference).expect("valid image");
    assert!(parsed.entry_is_mapped());
    assert!(parsed.entry_is_executable());
}

#[test]
fn computes_page_range_of_unaligned_segment() {
    // A segment may start inside a page as long as vaddr and file offset are
    // congruent; the loader maps whole pages.
    let spec = Spec {
        vaddr: 0x2100,
        memsz: 0x1100,
        filesz: 0x100,
        offset: 0x1100,
        flags: RW,
    };
    let bytes = build(ET_EXEC, EM_X86_64, 0x2100, &[spec]);
    let parsed = Image::parse(&bytes).expect("valid image");
    let segment = parsed.segments()[0];
    assert_eq!(segment.page_start(), 0x2000);
    assert_eq!(segment.page_offset(), 0x100);
    assert_eq!(segment.page_len(), 2 * PAGE_SIZE);
    assert_eq!(segment.page_count(), 2);
    assert_eq!(parsed.base_vaddr(), 0x2000);
    assert_eq!(parsed.span_len(), 2 * PAGE_SIZE);
    assert_eq!(parsed.entry_gpa(0x10_0000), Some(0x10_0100));
}

#[test]
fn rejects_oversized_load_footprint() {
    // A single segment claiming more than the loader's footprint cap. The
    // boundary is checked before any allocation, using only header math.
    let span = image::MAX_LOAD_BYTES + PAGE_SIZE;
    let spec = Spec {
        vaddr: 0x10_0000,
        memsz: span,
        filesz: 0,
        offset: 0,
        flags: RW,
    };
    let bytes = build(ET_EXEC, EM_X86_64, 0x10_0000, &[spec]);
    assert_eq!(Image::parse(&bytes).unwrap_err(), ImageError::LoadTooLarge);
}

#[test]
fn random_input_never_panics() {
    // Deterministic pseudo-random fuzzing of completely arbitrary input.
    let mut state = 0x1234_5678_9ABC_DEF0u64;
    let mut next = || {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        state
    };
    for _ in 0..2048 {
        let length = (next() % 512) as usize;
        let bytes: Vec<u8> = (0..length).map(|_| next() as u8).collect();
        if let Ok(parsed) = Image::parse(&bytes) {
            let _ = parsed.kind();
            let _ = parsed.entry();
            let _ = parsed.segments();
            let _ = parsed.load_span(next());
            let _ = parsed.entry_gpa(next());
            let _ = parsed.entry_is_mapped();
            let _ = parsed.total_pages();
            for segment in parsed.segments() {
                let _ = parsed.bytes_for_segment(segment);
                let _ = parsed.segment_gpa(0, segment);
            }
        }
    }
}

#[test]
fn mutated_images_never_panic() {
    // Single-byte mutations of a valid image must always yield a typed error
    // or a still-consistent plan, never a panic.
    let reference = simple();
    let mut state = 0xDEAD_BEEF_CAFE_0001u64;
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
        if let Ok(parsed) = Image::parse(&bytes) {
            let _ = parsed.load_span(0x10_0000);
            for segment in parsed.segments() {
                let _ = parsed.bytes_for_segment(segment);
            }
        }
    }
}
