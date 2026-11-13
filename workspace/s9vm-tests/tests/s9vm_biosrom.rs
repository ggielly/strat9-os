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

//! L2: s9vm real-mode BIOS ROM stubs, low-memory layout and demo boot image.

#![allow(dead_code)]

extern crate alloc;

#[path = "../../kernel/src/s9vm/biosrom.rs"]
mod biosrom;

use biosrom::{
    bios_port, chs_to_lba, demo_boot_sector, demo_disk_image, demo_stage2, install,
    is_supported_vector, lba_to_chs, rom_image, shared_tail_bytes, shared_tail_gpa, stub_bytes,
    stub_gpa, stub_offset, write_bda, write_ivt, RomError, RomMemory, BDA_BASE, BDA_CHAR_HEIGHT,
    BDA_COLUMNS, BDA_CRTC_PORT, BDA_CURSOR, BDA_EBDA_SEGMENT, BDA_EQUIPMENT, BDA_MEMORY_SIZE,
    BDA_ROWS, BDA_TICK_COUNT, BDA_VIDEO_MODE, BIOS_PORT_BASE, BOOT_SECTOR_GPA, BOOT_STACK_TOP,
    CHAR_HEIGHT_VALUE, COLUMNS_VALUE, CRTC_PORT_VALUE, CURSOR_VALUE, DEMO_BANNER, DEMO_DEBUG_PORT,
    DEMO_ERROR, DEMO_FAILURE_MARKER, DEMO_STAGE2_BANNER, DEMO_SUCCESS_MARKER, EBDA_SEGMENT_VALUE,
    EQUIPMENT_VALUE, FLOPPY_BYTES, FLOPPY_CYLINDERS, FLOPPY_HEADS, FLOPPY_SECTORS,
    FLOPPY_TOTAL_SECTORS, IVT_BASE, MAX_SHARED_TAIL_LEN, MAX_STUB_LEN, MEMORY_SIZE_VALUE, ROM_BASE,
    ROM_LEN, ROM_SEGMENT, ROM_SHARED_TAIL, ROM_STUB_BASE, ROWS_VALUE, SCRATCH_GPA, SECTOR_SIZE,
    STUB_STRIDE, TAIL_FLAGS_OFFSET, TICK_COUNT_VALUE, VECTORS, VIDEO_BASE, VIDEO_MODE_VALUE,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Flat guest memory of `size` bytes, addressed with linear (guest-physical)
/// addresses.
struct FlatMemory {
    data: Vec<u8>,
}

impl FlatMemory {
    fn new(size: usize) -> Self {
        Self {
            data: vec![0u8; size],
        }
    }

    fn u8_at(&self, address: u32) -> u8 {
        self.data[address as usize]
    }

    fn u16_at(&self, address: u32) -> u16 {
        let index = address as usize;
        u16::from_le_bytes([self.data[index], self.data[index + 1]])
    }

    fn u32_at(&self, address: u32) -> u32 {
        let index = address as usize;
        u32::from_le_bytes([
            self.data[index],
            self.data[index + 1],
            self.data[index + 2],
            self.data[index + 3],
        ])
    }

    fn bytes_at(&self, address: u32, len: usize) -> &[u8] {
        let index = address as usize;
        &self.data[index..index + len]
    }
}

impl RomMemory for FlatMemory {
    fn write(&mut self, linear: u32, bytes: &[u8]) -> bool {
        let Some(start) = usize::try_from(linear).ok() else {
            return false;
        };
        let Some(end) = start.checked_add(bytes.len()) else {
            return false;
        };
        if end > self.data.len() {
            return false;
        }
        self.data[start..end].copy_from_slice(bytes);
        true
    }

    fn read(&mut self, linear: u32, out: &mut [u8]) -> bool {
        let Some(start) = usize::try_from(linear).ok() else {
            return false;
        };
        let Some(end) = start.checked_add(out.len()) else {
            return false;
        };
        if end > self.data.len() {
            return false;
        }
        out.copy_from_slice(&self.data[start..end]);
        true
    }
}

/// Memory that refuses every access, to exercise the error paths.
struct DeniedMemory;

impl RomMemory for DeniedMemory {
    fn write(&mut self, _linear: u32, _bytes: &[u8]) -> bool {
        false
    }

    fn read(&mut self, _linear: u32, _out: &mut [u8]) -> bool {
        false
    }
}

fn memory() -> FlatMemory {
    FlatMemory::new(0x10_0000)
}

/// True when `needle` appears in `haystack`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Index of the first occurrence of `needle`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

// ---------------------------------------------------------------------------
// Layout constants
// ---------------------------------------------------------------------------

#[test]
fn layout_constants_match_the_low_memory_map() {
    assert_eq!(IVT_BASE, 0x0000);
    assert_eq!(BDA_BASE, 0x0400);
    assert_eq!(SCRATCH_GPA, 0x0500);
    assert_eq!(BOOT_SECTOR_GPA, 0x7C00);
    assert_eq!(BOOT_STACK_TOP, 0x7C00);
    assert_eq!(VIDEO_BASE, 0xB8000);
    assert_eq!(ROM_SEGMENT, 0xF000);
    assert_eq!(ROM_BASE, 0xF0000);
    assert_eq!(ROM_LEN, 0x8000);
    assert_eq!(ROM_STUB_BASE, 0x0100);
    assert_eq!(BIOS_PORT_BASE, 0xE000);
    assert_eq!(STUB_STRIDE, 0x10);
    assert_eq!(MAX_STUB_LEN, 11);
    assert_eq!(ROM_SHARED_TAIL, 0x1100);
    assert_eq!(MAX_SHARED_TAIL_LEN, 0x80);
    assert_eq!(TAIL_FLAGS_OFFSET, 0x0A);
}

#[test]
fn regions_do_not_overlap() {
    // IVT, BDA, scratch byte, boot sector and stage 2 are disjoint low memory.
    assert!(BDA_BASE >= IVT_BASE + 256 * 4);
    assert!(SCRATCH_GPA >= BDA_BASE + 256);
    assert!(BOOT_SECTOR_GPA >= SCRATCH_GPA + 1);
    assert!(BOOT_SECTOR_GPA + 2 * SECTOR_SIZE as u32 <= VIDEO_BASE);
    // Video memory is above all the low-memory artefacts.
    assert!(VIDEO_BASE > BOOT_SECTOR_GPA);
    // The ROM is the last 32 KiB of the first MiB.
    assert_eq!(ROM_BASE + ROM_LEN, 0xF8000);
    assert!(ROM_BASE >= VIDEO_BASE);
    assert!(ROM_BASE + ROM_LEN <= 0x10_0000);
}

#[test]
fn stub_area_and_tail_fit_inside_the_rom() {
    let stub_area_end = u32::from(ROM_STUB_BASE) + 256 * u32::from(STUB_STRIDE);
    assert_eq!(stub_area_end, 0x1100);
    assert_eq!(stub_area_end, u32::from(ROM_SHARED_TAIL));
    // The highest per-vector stub plus its length stays below the tail.
    let last = u32::from(stub_offset(0xFF)) + u32::from(MAX_STUB_LEN);
    assert!(last <= u32::from(ROM_SHARED_TAIL));
    // The tail fits in the free ROM after the stub area.
    let tail_end = u32::from(ROM_SHARED_TAIL) + u32::from(MAX_SHARED_TAIL_LEN);
    assert!(tail_end <= ROM_LEN);
    assert!(shared_tail_gpa() + u32::from(MAX_SHARED_TAIL_LEN) <= ROM_BASE + ROM_LEN);
    assert!(shared_tail_bytes().len() <= usize::from(MAX_SHARED_TAIL_LEN));
}

#[test]
fn vector_list_is_sorted_unique_and_complete() {
    assert!(VECTORS.contains(&0x05));
    assert!(VECTORS.contains(&0x08));
    assert!(VECTORS.contains(&0x10));
    assert!(VECTORS.contains(&0x13));
    assert!(VECTORS.contains(&0x16));
    // Reboot and ROM-BASIC vectors: a boot sector that cannot load its kernel
    // calls int 19h/int 18h; without a stub it jumps through the zeroed IVT
    // entry and executes garbage at 0000:0000.
    assert!(VECTORS.contains(&0x18));
    assert!(VECTORS.contains(&0x19));
    assert!(VECTORS.contains(&0x1A));
    assert!(VECTORS.contains(&0x1C));
    assert_eq!(VECTORS.len(), 22);
    for pair in VECTORS.windows(2) {
        assert!(pair[0] < pair[1], "vectors must be strictly sorted");
    }
    for vector in VECTORS {
        assert!(is_supported_vector(vector));
    }
    assert!(!is_supported_vector(0x00));
    assert!(!is_supported_vector(0x20));
    assert!(!is_supported_vector(0xFF));
}

#[test]
fn ports_and_offsets_follow_the_formula() {
    assert_eq!(bios_port(0x00), 0xE000);
    assert_eq!(bios_port(0x10), 0xE010);
    assert_eq!(bios_port(0xFF), 0xE0FF);
    assert_eq!(stub_offset(0x00), 0x0100);
    assert_eq!(stub_offset(0x10), 0x0200);
    assert_eq!(stub_offset(0xFF), 0x10F0);
    assert_eq!(stub_gpa(0x10), ROM_BASE + 0x0200);
    assert_eq!(shared_tail_gpa(), ROM_BASE + u32::from(ROM_SHARED_TAIL));
}

// ---------------------------------------------------------------------------
// Interrupt stubs and shared tail
// ---------------------------------------------------------------------------

/// Resolves the `jmp rel16` of a per-vector stub back to a ROM offset.
///
/// Stub layout: `push ax` (1), `push dx` (1), `mov al, ah` (2), `mov dx, port`
/// (3), `out dx, al` (1), `jmp rel16` (3): the displacement is at bytes 9..11.
fn stub_jump_target(vector: u8) -> u16 {
    let stub = stub_bytes(vector);
    let displacement = i16::from_le_bytes([stub[9], stub[10]]);
    let next = stub_offset(vector) + MAX_STUB_LEN;
    (i32::from(next) + i32::from(displacement)) as u16
}

#[test]
fn stub_for_vector_0x10_has_the_expected_encoding() {
    let stub = stub_bytes(0x10);
    assert_eq!(stub.len(), 11);
    assert_eq!(stub.len(), usize::from(MAX_STUB_LEN));
    // Save the caller AX (BIOS command in AH) and DX (page/drive), then send
    // AH as the OUT byte on the vector port 0xE010.
    assert_eq!(&stub[0..4], &[0x50, 0x52, 0x88, 0xE0]);
    assert_eq!(&stub[4..7], &[0xBA, 0x10, 0xE0]);
    assert_eq!(stub[7], 0xEE);
    // JMP rel16 to the shared tail: 0x1100 - (0x0200 + 11) = 0x0EF5.
    assert_eq!(stub[8], 0xE9);
    assert_eq!(&stub[8..11], &[0xE9, 0xF5, 0x0E]);
    assert_eq!(stub_jump_target(0x10), ROM_SHARED_TAIL);
    // The OUT moved into the stub (it needs the caller's AH); the tail keeps
    // the flag patch.
    assert_eq!(stub.iter().filter(|byte| **byte == 0xEE).count(), 1);
}

#[test]
fn stub_port_immediate_matches_each_vector() {
    for vector in 0..=255u8 {
        let stub = stub_bytes(vector);
        let port = bios_port(vector);
        assert_eq!(&stub[4..7], &[0xBA, (port & 0xFF) as u8, (port >> 8) as u8]);
        assert_eq!(stub[8], 0xE9);
        assert_eq!(stub_jump_target(vector), ROM_SHARED_TAIL);
    }
}

#[test]
fn every_stub_is_bounded_and_jumps_to_the_tail() {
    for vector in 0..=255u8 {
        let stub = stub_bytes(vector);
        assert!(stub.len() <= usize::from(MAX_STUB_LEN));
        assert_eq!(stub.len(), 11);
        assert_eq!(stub_jump_target(vector), ROM_SHARED_TAIL);
    }
}

#[test]
fn stubs_do_not_overlap_in_the_rom() {
    let mut previous_end = None;
    for vector in 0..=255u8 {
        let start = u32::from(stub_offset(vector));
        let end = start + usize::from(MAX_STUB_LEN) as u32;
        if let Some(previous) = previous_end {
            assert!(start >= previous, "stub {vector:#04x} overlaps");
        }
        previous_end = Some(end);
    }
    assert!(usize::from(MAX_STUB_LEN) <= usize::from(STUB_STRIDE));
}

#[test]
fn stub_bytes_are_deterministic_and_vector_specific() {
    let first = stub_bytes(0x13);
    let second = stub_bytes(0x13);
    assert_eq!(first, second);
    assert_ne!(stub_bytes(0x10), stub_bytes(0x13));
    // Byte 5 is the low half of the port immediate: 0xE013 / 0xE010.
    assert_eq!(stub_bytes(0x13)[5], 0x13);
    assert_eq!(stub_bytes(0x10)[5], 0x10);
}

#[test]
fn tail_frame_offset_matches_the_push_sequence() {
    // Stack at tail entry: [SP]=saved DX, [SP+2]=saved AX, [SP+4]=IP,
    // [SP+6]=CS, [SP+8]=FLAGS. The tail drops the two saved words, pushes the
    // kernel result (AX), BP and DS, then frames: [BP]=DS, [BP+2]=BP,
    // [BP+4]=AX, [BP+6]=IP, [BP+8]=CS, [BP+0x0A]=FLAGS.
    assert_eq!(TAIL_FLAGS_OFFSET, 0x0A);
    let tail = shared_tail_bytes();
    assert_eq!(
        &tail[0..11],
        &[0x83, 0xC4, 0x04, 0x50, 0x55, 0x1E, 0x6A, 0x00, 0x1F, 0x89, 0xE5]
    );
}

#[test]
fn shared_tail_returns_with_iret_and_uses_no_pusha() {
    let tail = shared_tail_bytes();
    assert!(tail.len() <= usize::from(MAX_SHARED_TAIL_LEN));
    assert_eq!(tail.len(), 46);
    // The tail starts by dropping the stub's saved DX/AX and ends with IRET.
    assert_eq!(&tail[0..3], &[0x83, 0xC4, 0x04]);
    assert_eq!(*tail.last().expect("tail"), 0xCF);
    // `safe-registers` fix: no PUSHA/POPA (which would discard the values the
    // kernel writes into the register file at the OUT exit).
    assert!(!tail.contains(&0x60));
    assert!(!tail.contains(&0x61));
}

#[test]
fn shared_tail_preserves_the_caller_registers() {
    // Byte-for-byte encoding contract. The stub saved the caller DX/AX on the
    // guest stack (the kernel re-reads them there); the tail drops those two
    // words, keeps the kernel-written AX, patches only the stacked FLAGS and
    // returns through IRET. Every other register is untouched.
    let expected: &[u8] = &[
        0x83, 0xC4, 0x04, // add sp, 4 (drop saved DX, AX)
        0x50, // push ax (kernel result)
        0x55, // push bp
        0x1E, // push ds
        0x6A, 0x00, // push 0
        0x1F, // pop ds
        0x89, 0xE5, // mov bp, sp
        0xA0, 0x00, 0x05, // mov al, [0x0500]
        0xA8, 0x01, // test al, 1
        0x74, 0x06, // jz
        0x83, 0x4E, 0x0A, 0x01, // or word [bp+0x0A], 0x0001
        0xEB, 0x04, // jmp
        0x83, 0x66, 0x0A, 0xFE, // and word [bp+0x0A], 0xFFFE
        0xA8, 0x02, // test al, 2
        0x74, 0x06, // jz
        0x83, 0x4E, 0x0A, 0x40, // or word [bp+0x0A], 0x0040
        0xEB, 0x04, // jmp
        0x83, 0x66, 0x0A, 0xBF, // and word [bp+0x0A], 0xFFBF
        0x5D, // pop bp
        0x58, // pop ax
        0x1F, // pop ds
        0xCF, // iret
    ];
    assert_eq!(shared_tail_bytes(), expected);
    // Push/pop balance for every register the tail touches.
    assert!(contains(&shared_tail_bytes(), &[0x1E]));
    assert!(contains(&shared_tail_bytes(), &[0x1F]));
    assert!(contains(&shared_tail_bytes(), &[0x83, 0xC4, 0x04, 0x50]));
    assert!(contains(&shared_tail_bytes(), &[0x5D, 0x58, 0x1F, 0xCF]));
}

#[test]
fn shared_tail_patches_the_stacked_flags_with_the_scratch_bits() {
    let tail = shared_tail_bytes();
    // Scratch byte read through DS:0x0500.
    assert!(contains(&tail, &[0xA0, 0x00, 0x05]));
    // CF (bit 0) and ZF (bit 1) tests.
    assert!(contains(&tail, &[0xA8, 0x01]));
    assert!(contains(&tail, &[0xA8, 0x02]));
    // Set/clear sequences on the stacked FLAGS word at [BP + TAIL_FLAGS_OFFSET].
    let offset = TAIL_FLAGS_OFFSET as u8;
    assert!(contains(&tail, &[0x83, 0x4E, offset, 0x01]));
    assert!(contains(&tail, &[0x83, 0x66, offset, 0xFE]));
    assert!(contains(&tail, &[0x83, 0x4E, offset, 0x40]));
    assert!(contains(&tail, &[0x83, 0x66, offset, 0xBF]));
    // The tail patches exactly one word (the stacked FLAGS) and does not
    // return through the interrupt frame more than once.
    assert_eq!(tail.iter().filter(|byte| **byte == 0xCF).count(), 1);
}
// ---------------------------------------------------------------------------
// IVT / BDA / install
// ---------------------------------------------------------------------------

#[test]
fn write_ivt_writes_far_pointers() {
    let mut mem = memory();
    write_ivt(&mut mem, &VECTORS).expect("ivt");
    for vector in VECTORS {
        let entry = IVT_BASE + u32::from(vector) * 4;
        assert_eq!(mem.u16_at(entry), stub_offset(vector));
        assert_eq!(mem.u16_at(entry + 2), ROM_SEGMENT);
    }
    // An unsupported vector entry is untouched.
    assert_eq!(mem.u16_at(0x20 * 4), 0);
}

#[test]
fn write_ivt_rejects_unsupported_vectors() {
    let mut mem = memory();
    assert_eq!(
        write_ivt(&mut mem, &[0x10, 0x20]).unwrap_err(),
        RomError::UnsupportedVector(0x20)
    );
    assert_eq!(
        write_ivt(&mut mem, &[0xFF]).unwrap_err(),
        RomError::UnsupportedVector(0xFF)
    );
}

#[test]
fn write_ivt_reports_write_failures() {
    let mut mem = DeniedMemory;
    assert_eq!(
        write_ivt(&mut mem, &[0x10]).unwrap_err(),
        RomError::WriteFailed
    );
}

#[test]
fn write_bda_writes_exact_values() {
    let mut mem = memory();
    write_bda(&mut mem).expect("bda");
    assert_eq!(mem.u16_at(BDA_EQUIPMENT), EQUIPMENT_VALUE);
    assert_eq!(EQUIPMENT_VALUE, 0x0021);
    assert_eq!(mem.u16_at(BDA_MEMORY_SIZE), MEMORY_SIZE_VALUE);
    assert_eq!(MEMORY_SIZE_VALUE, 640);
    assert_eq!(mem.u16_at(BDA_EBDA_SEGMENT), EBDA_SEGMENT_VALUE);
    assert_eq!(EBDA_SEGMENT_VALUE, 0x9FC0);
    assert_eq!(mem.u8_at(BDA_VIDEO_MODE), VIDEO_MODE_VALUE);
    assert_eq!(VIDEO_MODE_VALUE, 3);
    assert_eq!(mem.u16_at(BDA_COLUMNS), COLUMNS_VALUE);
    assert_eq!(COLUMNS_VALUE, 80);
    assert_eq!(mem.u16_at(BDA_CURSOR), CURSOR_VALUE);
    assert_eq!(CURSOR_VALUE, 0);
    assert_eq!(mem.u16_at(BDA_CRTC_PORT), CRTC_PORT_VALUE);
    assert_eq!(CRTC_PORT_VALUE, 0x03D4);
    assert_eq!(mem.u8_at(BDA_ROWS), ROWS_VALUE);
    assert_eq!(ROWS_VALUE, 24);
    assert_eq!(mem.u8_at(BDA_CHAR_HEIGHT), CHAR_HEIGHT_VALUE);
    assert_eq!(CHAR_HEIGHT_VALUE, 16);
    assert_eq!(mem.u32_at(BDA_TICK_COUNT), TICK_COUNT_VALUE);
    assert_eq!(TICK_COUNT_VALUE, 0);
}

#[test]
fn write_bda_reports_write_failures() {
    let mut mem = DeniedMemory;
    assert_eq!(write_bda(&mut mem).unwrap_err(), RomError::WriteFailed);
}

#[test]
fn install_writes_stubs_tail_ivt_and_bda() {
    let mut mem = memory();
    install(&mut mem, &VECTORS).expect("install");
    for vector in VECTORS {
        let expected = stub_bytes(vector);
        assert_eq!(
            mem.bytes_at(stub_gpa(vector), expected.len()),
            &expected[..]
        );
        let entry = IVT_BASE + u32::from(vector) * 4;
        assert_eq!(mem.u16_at(entry), stub_offset(vector));
        assert_eq!(mem.u16_at(entry + 2), ROM_SEGMENT);
    }
    // The shared tail is installed once, at the documented ROM offset.
    let tail = shared_tail_bytes();
    assert_eq!(mem.bytes_at(shared_tail_gpa(), tail.len()), &tail[..]);
    assert_eq!(mem.u16_at(BDA_EQUIPMENT), EQUIPMENT_VALUE);
    // The scratch byte is host-owned and left untouched by install.
    assert_eq!(mem.u8_at(SCRATCH_GPA), 0);
}

#[test]
fn install_rejects_unsupported_vectors_before_writing_bda() {
    let mut mem = memory();
    assert_eq!(
        install(&mut mem, &[0x10, 0x30]).unwrap_err(),
        RomError::UnsupportedVector(0x30)
    );
    assert_eq!(mem.u16_at(BDA_EQUIPMENT), 0);
}

#[test]
fn install_reports_write_failures() {
    let mut mem = DeniedMemory;
    assert_eq!(
        install(&mut mem, &[0x10]).unwrap_err(),
        RomError::WriteFailed
    );
}

#[test]
fn install_with_no_vectors_only_writes_the_bda() {
    let mut mem = memory();
    install(&mut mem, &[]).expect("install");
    assert_eq!(mem.u16_at(BDA_EQUIPMENT), EQUIPMENT_VALUE);
    assert_eq!(mem.u16_at(IVT_BASE), 0);
}

#[test]
fn rom_image_contains_the_stubs_and_the_tail() {
    let rom = rom_image(&VECTORS).expect("rom");
    assert_eq!(rom.len(), ROM_LEN as usize);
    for vector in VECTORS {
        let offset = usize::from(stub_offset(vector));
        let expected = stub_bytes(vector);
        assert_eq!(&rom[offset..offset + expected.len()], &expected[..]);
    }
    // The shared tail is present exactly once at ROM_SHARED_TAIL.
    let tail = shared_tail_bytes();
    let tail_offset = usize::from(ROM_SHARED_TAIL);
    assert_eq!(&rom[tail_offset..tail_offset + tail.len()], &tail[..]);
    // Bytes outside every stub and the tail stay zero.
    assert_eq!(rom[0], 0);
    let after_last_stub = usize::from(stub_offset(0x4A)) + usize::from(MAX_STUB_LEN);
    assert_eq!(rom[after_last_stub], 0);
    assert_eq!(rom[after_last_stub + 1], 0);
}

#[test]
fn rom_image_rejects_unsupported_vectors() {
    assert_eq!(
        rom_image(&[0x20]).unwrap_err(),
        RomError::UnsupportedVector(0x20)
    );
}

// ---------------------------------------------------------------------------
// Floppy geometry
// ---------------------------------------------------------------------------

#[test]
fn floppy_geometry_is_consistent() {
    assert_eq!(FLOPPY_CYLINDERS, 80);
    assert_eq!(FLOPPY_HEADS, 2);
    assert_eq!(FLOPPY_SECTORS, 18);
    assert_eq!(SECTOR_SIZE, 512);
    assert_eq!(FLOPPY_TOTAL_SECTORS, 2_880);
    assert_eq!(FLOPPY_BYTES, FLOPPY_TOTAL_SECTORS as usize * SECTOR_SIZE);
}

#[test]
fn chs_to_lba_maps_the_edges() {
    assert_eq!(chs_to_lba(0, 0, 1), Some(0));
    assert_eq!(chs_to_lba(0, 0, 18), Some(17));
    assert_eq!(chs_to_lba(0, 1, 1), Some(18));
    assert_eq!(chs_to_lba(1, 0, 1), Some(36));
    assert_eq!(chs_to_lba(79, 1, 18), Some(2879));
}

#[test]
fn chs_to_lba_rejects_out_of_range_values() {
    assert_eq!(chs_to_lba(80, 0, 1), None);
    assert_eq!(chs_to_lba(0, 2, 1), None);
    assert_eq!(chs_to_lba(0, 0, 0), None);
    assert_eq!(chs_to_lba(0, 0, 19), None);
    assert_eq!(chs_to_lba(u16::MAX, 0, 1), None);
}

#[test]
fn lba_round_trips_through_chs() {
    for lba in 0..FLOPPY_TOTAL_SECTORS {
        let (cyl, head, sector) = lba_to_chs(lba).expect("chs");
        assert_eq!(chs_to_lba(cyl, head, sector), Some(lba));
    }
    assert_eq!(lba_to_chs(FLOPPY_TOTAL_SECTORS), None);
    assert_eq!(lba_to_chs(u64::MAX), None);
}

// ---------------------------------------------------------------------------
// Demo boot image
// ---------------------------------------------------------------------------

#[test]
fn demo_boot_sector_has_the_boot_signature() {
    let sector = demo_boot_sector();
    assert_eq!(sector[510], 0x55);
    assert_eq!(sector[511], 0xAA);
    assert_eq!(&sector[..2], &[0xEB, 0x1C]);
    assert_eq!(sector[2], 0x90);
    // The short jump lands on the code after the two strings.
    let target = 2 + i16::from(sector[1] as i8) as usize;
    assert_eq!(target, 0x1E);
    assert_eq!(sector[target], 0xFA);
}

#[test]
fn demo_boot_sector_contains_the_banner_and_error_strings() {
    let sector = demo_boot_sector();
    assert!(contains(&sector, DEMO_BANNER));
    assert!(contains(&sector, DEMO_ERROR));
    assert!(contains(&sector, &[0x0D, 0x0A, 0x00]));
}

#[test]
fn demo_boot_sector_contains_the_required_sequences() {
    let sector = demo_boot_sector();
    // Real-mode prologue: cli, xor ax,ax, mov ss,ax, mov sp,0x7C00, mov ds,ax,
    // mov es,ax, sti.
    assert!(contains(
        &sector,
        &[0xFA, 0x31, 0xC0, 0x8E, 0xD0, 0xBC, 0x00, 0x7C]
    ));
    assert!(contains(&sector, &[0x8E, 0xD8]));
    assert!(contains(&sector, &[0x8E, 0xC0]));
    assert!(contains(&sector, &[0xFB]));
    // INT 10h teletype: mov ah,0x0E; int 0x10.
    assert!(contains(&sector, &[0xB4, 0x0E]));
    assert!(contains(&sector, &[0xCD, 0x10]));
    // INT 13h read: AH=02, AL=1, CH=0, CL=2, DH=0, DL=0, BX=0x7E00, INT 13h.
    assert!(contains(
        &sector,
        &[
            0xB4, 0x02, 0xB0, 0x01, 0xB5, 0x00, 0xB1, 0x02, 0xB6, 0x00, 0xB2, 0x00, 0xBB, 0x00,
            0x7E, 0xCD, 0x13
        ]
    ));
    // JC to the error path and the far jump to the second stage.
    assert!(contains(&sector, &[0x72]));
    assert!(contains(&sector, &[0xEA, 0x00, 0x7E, 0x00, 0x00]));
    // Failure marker 'F' on port 0xE9.
    assert!(contains(
        &sector,
        &[0xB0, DEMO_FAILURE_MARKER, 0xBA, 0xE9, 0x00, 0xEE]
    ));
}

#[test]
fn demo_boot_sector_code_fits_before_the_signature() {
    let sector = demo_boot_sector();
    // Everything after the last code byte up to the signature is zero.
    let code_end = find(
        &sector,
        &[
            0xB4, 0x0E, 0xAC, 0x84, 0xC0, 0x74, 0x04, 0xCD, 0x10, 0xEB, 0xF7, 0xC3,
        ],
    )
    .expect("print helper")
        + 12;
    assert!(code_end < 510);
    assert!(sector[code_end..510].iter().all(|byte| *byte == 0));
}

#[test]
fn demo_stage2_has_the_boot_signature_and_banner() {
    let stage2 = demo_stage2();
    assert_eq!(stage2[510], 0x55);
    assert_eq!(stage2[511], 0xAA);
    assert!(contains(&stage2, DEMO_STAGE2_BANNER));
    assert_eq!(&stage2[..2], &[0xFA, 0x31]);
}

#[test]
fn demo_stage2_contains_the_timer_and_key_sequences() {
    let stage2 = demo_stage2();
    // Segment setup with a fresh stack.
    assert!(contains(
        &stage2,
        &[0x8E, 0xD8, 0x8E, 0xC0, 0x8E, 0xD0, 0xBC, 0x00, 0x7C]
    ));
    // Bounded INT 16h retry loop.
    assert!(contains(&stage2, &[0xB9, 0x10, 0x00]));
    assert!(contains(&stage2, &[0xB4, 0x00, 0xCD, 0x16]));
    assert!(contains(&stage2, &[0x75]));
    assert!(contains(&stage2, &[0xE2]));
    // '?' fallback and INT 10h teletype output.
    assert!(contains(&stage2, &[0xB0, b'?']));
    assert!(contains(&stage2, &[0xB4, 0x0E, 0xCD, 0x10]));
    // Success marker 'K' on port 0xE9 followed by cli/hlt.
    assert!(contains(
        &stage2,
        &[
            0xB0,
            DEMO_SUCCESS_MARKER,
            0xBA,
            0xE9,
            0x00,
            0xEE,
            0xFA,
            0xF4
        ]
    ));
    assert_eq!(DEMO_DEBUG_PORT, 0x00E9);
}

#[test]
fn demo_stage2_code_fits_before_the_signature() {
    let stage2 = demo_stage2();
    let banner = find(&stage2, DEMO_STAGE2_BANNER).expect("banner");
    let code_end = banner + DEMO_STAGE2_BANNER.len() + 3; // CR, LF, NUL
    assert!(code_end < 510);
    assert!(stage2[code_end..510].iter().all(|byte| *byte == 0));
}

#[test]
fn demo_disk_image_has_the_expected_size_and_layout() {
    let image = demo_disk_image();
    assert_eq!(image.len(), FLOPPY_BYTES);
    assert_eq!(&image[..SECTOR_SIZE], &demo_boot_sector()[..]);
    assert_eq!(&image[SECTOR_SIZE..2 * SECTOR_SIZE], &demo_stage2()[..]);
    // All remaining sectors are zero.
    assert!(image[2 * SECTOR_SIZE..].iter().all(|byte| *byte == 0));
    // The boot sector is LBA 0 and the stage is LBA 1.
    assert_eq!(chs_to_lba(0, 0, 1), Some(0));
    assert_eq!(chs_to_lba(0, 0, 2), Some(1));
}

#[test]
fn demo_disk_image_is_deterministic() {
    assert_eq!(demo_disk_image(), demo_disk_image());
}

#[test]
fn demo_sectors_report_the_debug_marker() {
    let boot = demo_boot_sector();
    let stage2 = demo_stage2();
    assert!(contains(&boot, &[0xB0, 0x46]));
    assert!(contains(&stage2, &[0xB0, 0x4B]));
    assert!(contains(&stage2, &[0xBA, 0xE9, 0x00, 0xEE]));
}

// ---------------------------------------------------------------------------
// Robustness
// ---------------------------------------------------------------------------

#[test]
fn adversarial_vector_slices_never_panic() {
    let mut mem = memory();
    for vector in 0..=255u8 {
        let slice = [vector];
        let _ = write_ivt(&mut mem, &slice);
        let _ = install(&mut mem, &slice);
        let _ = rom_image(&slice);
    }
    // Duplicates and an empty slice are accepted.
    write_ivt(&mut mem, &[0x10, 0x10]).expect("duplicates");
    install(&mut mem, &[]).expect("empty");
}

#[test]
fn out_of_range_writes_are_reported() {
    // A memory that does not even cover the BDA rejects the BDA writes, and a
    // memory smaller than the ROM rejects the stub writes.
    let mut small = FlatMemory::new(0x400);
    assert_eq!(
        install(&mut small, &[0x10]).unwrap_err(),
        RomError::WriteFailed
    );
    assert_eq!(write_bda(&mut small).unwrap_err(), RomError::WriteFailed);
}

#[test]
fn vector_helpers_are_total() {
    // Every value of the byte type maps to a port and a ROM offset inside the
    // ROM image.
    for vector in 0..=255u8 {
        let port = bios_port(vector);
        assert!(port >= BIOS_PORT_BASE);
        assert!(u32::from(stub_offset(vector)) + u32::from(MAX_STUB_LEN) <= ROM_LEN);
        assert_eq!(stub_offset(vector) % STUB_STRIDE, 0);
    }
}
