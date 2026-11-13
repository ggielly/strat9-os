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

//! Host tests for the shared ELF64 parser and image writer.

use strat9_elf_core::{
    build::{BuildError, ImageWriter},
    ElfError, Header, LoadSegment, ProgramHeader, SectionHeader, Symbol, ELF_HEADER_SIZE, ET_DYN,
    ET_EXEC, EV_CURRENT, PF_R, PF_W, PF_X, PROGRAM_HEADER_SIZE, PT_LOAD,
};

/// Builds a two-segment `ET_EXEC` image linked at `0x10_0000`.
fn sample_image() -> Vec<u8> {
    let mut image = vec![0u8; 0x4000];
    let mut writer = ImageWriter::new(&mut image, ET_EXEC, 0x10_0100).expect("header fits");
    writer
        .add_load(
            PF_R,
            0,
            0x10_0000,
            0x1000,
            0x2000,
            strat9_elf_core::PAGE_SIZE,
        )
        .unwrap();
    writer
        .add_load(
            PF_R | PF_X,
            0x1000,
            0x10_2000,
            0x800,
            0x1000,
            strat9_elf_core::PAGE_SIZE,
        )
        .unwrap();
    let end = writer.finish();
    image.truncate(end.max(0x1800));
    image
}

#[test]
fn parses_file_and_program_headers() {
    let bytes = sample_image();
    let header = Header::parse(&bytes).expect("valid image");
    assert_eq!(header.e_type, ET_EXEC);
    assert!(header.is_exec());
    assert!(!header.is_dynamic());
    assert_eq!(header.e_entry, 0x10_0100);
    assert_eq!(header.e_phnum, 2);
    assert_eq!(header.e_phentsize as usize, PROGRAM_HEADER_SIZE);

    let headers: Vec<ProgramHeader> = header.program_headers(&bytes).collect();
    assert_eq!(headers.len(), 2);
    assert_eq!(headers[0].p_type, PT_LOAD);
    assert_eq!(headers[0].p_flags, PF_R);
    assert_eq!(headers[0].p_vaddr, 0x10_0000);
    assert_eq!(headers[0].p_filesz, 0x1000);
    assert_eq!(headers[0].p_memsz, 0x2000);
    assert_eq!(headers[1].p_flags, PF_R | PF_X);
}

#[test]
fn validates_load_segments() {
    let bytes = sample_image();
    let header = Header::parse(&bytes).unwrap();
    let headers: Vec<ProgramHeader> = header.program_headers(&bytes).collect();

    let first = headers[0]
        .load_segment(bytes.len())
        .unwrap()
        .expect("non-empty segment");
    assert_eq!(first.vaddr, 0x10_0000);
    assert_eq!(first.end_vaddr(), 0x10_2000);
    assert_eq!(first.file_end(), 0x1000);

    let second = headers[1].load_segment(bytes.len()).unwrap().unwrap();
    assert_eq!(second.filesz, 0x800);
    assert_eq!(second.memsz, 0x1000);

    // A pure BSS segment accepts a nominal offset outside the file.
    let bss = ProgramHeader {
        p_type: PT_LOAD,
        p_flags: PF_R | PF_W,
        p_offset: 0x8000,
        p_vaddr: 0x10_8000,
        p_paddr: 0x10_8000,
        p_filesz: 0,
        p_memsz: 0x1000,
        p_align: 0x1000,
    };
    assert!(bss.load_segment(bytes.len()).unwrap().is_some());
}

#[test]
fn rejects_bad_load_segments() {
    let file_len = 0x2000;
    let base = ProgramHeader {
        p_type: PT_LOAD,
        p_flags: PF_R,
        p_offset: 0,
        p_vaddr: 0x1000,
        p_paddr: 0x1000,
        p_filesz: 0x100,
        p_memsz: 0x200,
        p_align: 0x1000,
    };
    assert!(base.load_segment(file_len).unwrap().is_some());

    let empty = ProgramHeader { p_memsz: 0, ..base };
    assert_eq!(empty.load_segment(file_len), Ok(None));

    let larger_file = ProgramHeader {
        p_filesz: 0x300,
        ..base
    };
    assert_eq!(
        larger_file.load_segment(file_len),
        Err(ElfError::FileSizeExceedsMemorySize)
    );

    let overflow = ProgramHeader {
        p_vaddr: u64::MAX - 8,
        ..base
    };
    assert_eq!(
        overflow.load_segment(file_len),
        Err(ElfError::SegmentOverflow)
    );

    let outside = ProgramHeader {
        p_offset: 0x1F80,
        p_filesz: 0x100,
        ..base
    };
    assert_eq!(
        outside.load_segment(file_len),
        Err(ElfError::SegmentOutOfBounds)
    );

    let misaligned = ProgramHeader {
        p_vaddr: 0x1100,
        ..base
    };
    assert_eq!(
        misaligned.load_segment(file_len),
        Err(ElfError::MisalignedSegment)
    );

    let alignment = ProgramHeader { p_align: 3, ..base };
    assert_eq!(
        alignment.load_segment(file_len),
        Err(ElfError::BadSegmentAlignment)
    );
}

#[test]
fn rejects_malformed_headers() {
    let good = sample_image();

    assert_eq!(Header::parse(&[]), Err(ElfError::TruncatedHeader));
    assert_eq!(
        Header::parse(&good[..ELF_HEADER_SIZE - 1]),
        Err(ElfError::TruncatedHeader)
    );

    let mut bytes = good.clone();
    bytes[0] = b'X';
    assert_eq!(Header::parse(&bytes), Err(ElfError::BadMagic));

    let mut bytes = good.clone();
    bytes[4] = 1;
    assert_eq!(Header::parse(&bytes), Err(ElfError::BadClass));

    let mut bytes = good.clone();
    bytes[5] = 2;
    assert_eq!(Header::parse(&bytes), Err(ElfError::BadEndianness));

    let mut bytes = good.clone();
    bytes[6] = 0;
    assert_eq!(Header::parse(&bytes), Err(ElfError::BadIdentVersion));

    let mut bytes = good.clone();
    bytes[0x10] = 1; // e_type = ET_REL
    assert_eq!(Header::parse(&bytes), Err(ElfError::UnsupportedType));

    let mut bytes = good.clone();
    bytes[0x12] = 3; // e_machine = EM_386
    assert_eq!(Header::parse(&bytes), Err(ElfError::UnsupportedMachine));

    let mut bytes = good.clone();
    bytes[0x14] = 0;
    assert_eq!(Header::parse(&bytes), Err(ElfError::BadVersion));

    let mut bytes = good.clone();
    bytes[0x34] = 0;
    assert_eq!(Header::parse(&bytes), Err(ElfError::BadHeaderSize));

    let mut bytes = good.clone();
    bytes[0x36] = 0;
    assert_eq!(Header::parse(&bytes), Err(ElfError::BadProgramHeaderSize));

    let mut bytes = good.clone();
    bytes[0x20] = 8; // e_phoff too small / misaligned
    assert_eq!(Header::parse(&bytes), Err(ElfError::BadProgramHeaders));

    let mut bytes = good.clone();
    bytes[0x38] = 1;
    bytes[0x39] = 0;
    let truncated = bytes[..ELF_HEADER_SIZE].to_vec();
    assert_eq!(
        Header::parse(&truncated),
        Err(ElfError::TruncatedProgramHeaders)
    );
}

#[test]
fn parses_dynamic_images() {
    let mut image = vec![0u8; 0x2000];
    let mut writer = ImageWriter::new(&mut image, ET_DYN, 0x400).unwrap();
    writer
        .add_load(PF_R | PF_X, 0, 0, 0x400, 0x800, 0x1000)
        .unwrap();
    let end = writer.finish();
    image.truncate(end.max(0x400));

    let header = Header::parse(&image).unwrap();
    assert!(header.is_dynamic());
    let segment = header
        .program_headers(&image)
        .next()
        .unwrap()
        .load_segment(image.len())
        .unwrap()
        .unwrap();
    assert_eq!(segment.vaddr, 0);
    assert_eq!(segment.end_vaddr(), 0x800);
}

#[test]
fn writer_reports_small_buffers() {
    let mut tiny = [0u8; 32];
    assert_eq!(
        ImageWriter::new(&mut tiny, ET_EXEC, 0).unwrap_err(),
        BuildError::BufferTooSmall
    );

    let mut header_only = [0u8; ELF_HEADER_SIZE];
    let mut writer = ImageWriter::new(&mut header_only, ET_EXEC, 0).unwrap();
    assert_eq!(
        writer.add_load(PF_R, 0, 0, 0, 0x1000, 0x1000).unwrap_err(),
        BuildError::BufferTooSmall
    );
}

/// Builds a minimal file with section headers: `.shstrtab`, `.symtab` and
/// `.strtab`, enough to exercise the symbol reader used by the kernel.
fn image_with_symbols() -> Vec<u8> {
    let names = b"\0.shstrtab\0.strtab\0.symtab\0";
    let strings = b"\0alpha\0beta\0";
    let mut symbols = vec![0u8; 3 * 24];
    // Symbol 0: null entry.
    // Symbol 1: "alpha" at 0x10_0000, size 0x20.
    symbols[24] = 1; // st_name = 1
    symbols[24 + 8..24 + 16].copy_from_slice(&0x10_0000u64.to_le_bytes());
    symbols[24 + 16..24 + 24].copy_from_slice(&0x20u64.to_le_bytes());
    // Symbol 2: "beta" at 0x10_0100, size 0x10.
    symbols[48] = 6; // st_name = 6
    symbols[48 + 8..48 + 16].copy_from_slice(&0x10_0100u64.to_le_bytes());
    symbols[48 + 16..48 + 24].copy_from_slice(&0x10u64.to_le_bytes());

    let names_offset = ELF_HEADER_SIZE + PROGRAM_HEADER_SIZE;
    let strings_offset = names_offset + names.len();
    let symbols_offset = strings_offset + strings.len();
    // ELF section header tables are 8-byte aligned.
    let sections_offset = (symbols_offset + symbols.len() + 7) & !7;

    let mut image = vec![0u8; sections_offset + 4 * 64];
    let mut writer = ImageWriter::new(&mut image, ET_EXEC, 0x10_0000).unwrap();
    writer
        .add_load(PF_R | PF_X, 0, 0x10_0000, 0x200, 0x200, 0x1000)
        .unwrap();
    let end = writer.finish();
    assert!(end <= names_offset);

    image[names_offset..names_offset + names.len()].copy_from_slice(names);
    image[strings_offset..strings_offset + strings.len()].copy_from_slice(strings);
    image[symbols_offset..symbols_offset + symbols.len()].copy_from_slice(&symbols);

    // e_shoff / e_shentsize / e_shnum / e_shstrndx.
    image[0x28..0x30].copy_from_slice(&(sections_offset as u64).to_le_bytes());
    image[0x3A..0x3C].copy_from_slice(&64u16.to_le_bytes());
    image[0x3C..0x3E].copy_from_slice(&4u16.to_le_bytes());
    image[0x3E..0x40].copy_from_slice(&1u16.to_le_bytes());

    let put =
        |image: &mut Vec<u8>, index: usize, name: u32, kind: u32, offset: usize, size: usize| {
            let base = sections_offset + index * 64;
            image[base..base + 4].copy_from_slice(&name.to_le_bytes());
            image[base + 4..base + 8].copy_from_slice(&kind.to_le_bytes());
            image[base + 24..base + 32].copy_from_slice(&(offset as u64).to_le_bytes());
            image[base + 32..base + 40].copy_from_slice(&(size as u64).to_le_bytes());
        };
    put(&mut image, 0, 0, 0, 0, 0);
    put(&mut image, 1, 1, 3, names_offset, names.len()); // .shstrtab
    put(&mut image, 2, 11, 3, strings_offset, strings.len()); // .strtab
    put(&mut image, 3, 19, 2, symbols_offset, symbols.len()); // .symtab

    image
}

#[test]
fn finds_sections_and_symbols() {
    let image = image_with_symbols();
    let header = Header::parse(&image).unwrap();
    assert_eq!(header.e_shnum, 4);
    assert_eq!(header.e_shstrndx, 1);

    let shstrtab = header.section_header(&image, 1).unwrap();
    assert!(shstrtab.is_strtab());
    assert_eq!(header.section_name(&image, 1).unwrap(), ".shstrtab");
    let symtab = header.find_section(&image, ".symtab").unwrap().unwrap();
    assert!(symtab.is_symtab());

    let strtab = header.find_section(&image, ".strtab").unwrap().unwrap();
    let strings = strtab.data(&image).unwrap();
    let symbols: Vec<Symbol> = Symbol::iter(symtab.data(&image).unwrap()).collect();
    assert_eq!(symbols.len(), 3);
    assert_eq!(symbols[1].value, 0x10_0000);
    assert_eq!(symbols[2].size, 0x10);
    assert_eq!(&strings[1..6], b"alpha");
}

#[test]
fn section_data_is_bounds_checked() {
    let section = SectionHeader {
        sh_name: 0,
        sh_type: 0,
        sh_flags: 0,
        sh_addr: 0,
        sh_offset: 0x1000,
        sh_size: 0x100,
        sh_link: 0,
        sh_info: 0,
        sh_addralign: 0,
        sh_entsize: 0,
    };
    assert_eq!(
        section.data(&[0u8; 0x100]),
        Err(ElfError::SectionOutOfBounds)
    );
    assert!(section.data(&[0u8; 0x1100]).is_ok());
}

#[test]
fn parser_never_panics_on_truncated_or_corrupted_input() {
    let complete = image_with_symbols();
    // Every truncation must be rejected without panicking.
    for len in 0..complete.len() {
        let _ = Header::parse(&complete[..len]);
    }

    // Deterministic byte corruption: the parser must only ever return a
    // header or an error, never panic on out-of-bounds reads.
    let mut state = 0x1234_5678u32;
    for _ in 0..4096 {
        let mut bytes = complete.clone();
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let index = state as usize % bytes.len();
        bytes[index] ^= 0xA5;
        let _ = Header::parse(&bytes);
        if let Ok(header) = Header::parse(&bytes) {
            for phdr in header.program_headers(&bytes) {
                let _ = phdr.load_segment(bytes.len());
                let _: Option<LoadSegment> = phdr.load_segment(bytes.len()).ok().flatten();
            }
            for index in 0..header.e_shnum as usize {
                let _ = header.section_name(&bytes, index);
            }
        }
    }
}

#[test]
fn constants_match_the_elf_specification() {
    assert_eq!(ELF_HEADER_SIZE, 64);
    assert_eq!(PROGRAM_HEADER_SIZE, 56);
    assert_eq!(EV_CURRENT, 1);
    assert_eq!(PF_R | PF_W | PF_X, 7);
}
