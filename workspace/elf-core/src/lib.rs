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

//! Shared, pure ELF64/x86-64 parsing layer.
//!
//! This crate is the **single** implementation of the ELF64 file format used
//! by the whole operating system:
//!
//! - the UEFI bootloader validates the kernel image before copying it;
//! - the kernel userland loader validates and maps programs;
//! - the kernel symbol-table reader (`.symtab`/`.strtab`) resolves addresses;
//! - the `s9vm` hypervisor validates untrusted guest images.
//!
//! It only decodes and validates the file format. It never allocates, never
//! touches memory and never panics: every malformed input yields a typed
//! [`ElfError`]. Loading policies (where segments are mapped, which bases and
//! permissions are legal, how many segments an image may have) stay in the
//! callers, because they differ per consumer:
//!
//! | consumer | policy |
//! |---|---|
//! | bootloader | `ET_EXEC` only, fixed higher-half virtual window |
//! | kernel loader | `ET_EXEC`/`ET_DYN`, user address space, dynamic linking |
//! | `s9vm` | guest-physical relocation, `PT_LOAD` footprint limits |
//!
//! [`build`] contains the mirror-image writer used to generate test guest
//! images; sharing it guarantees that the tests exercise exactly the layout
//! the parser accepts.
//!
//! Testable on the host (L2 tests): no `unsafe`, no allocation, `no_std`.

#![no_std]
#![forbid(unsafe_code)]

pub mod build;

/// Size of the ELF64 file header (`e_ehsize`).
pub const ELF_HEADER_SIZE: usize = 64;
/// Size of one ELF64 program header entry (`e_phentsize`).
pub const PROGRAM_HEADER_SIZE: usize = 56;
/// Size of one ELF64 section header entry (`e_shentsize`).
pub const SECTION_HEADER_SIZE: usize = 64;
/// Size of one ELF64 symbol-table entry.
pub const SYMBOL_ENTRY_SIZE: usize = 24;
/// Size of a base page, used by the `PT_LOAD` congruence rule.
pub const PAGE_SIZE: u64 = 4096;

/// ELF type: fixed-address executable.
pub const ET_EXEC: u16 = 2;
/// ELF type: position-independent executable / shared object.
pub const ET_DYN: u16 = 3;

/// ELF machine: x86-64.
pub const EM_X86_64: u16 = 62;

/// Current ELF version (`EI_VERSION` and `e_version`).
pub const EV_CURRENT: u32 = 1;

/// Program header type: loadable segment.
pub const PT_LOAD: u32 = 1;
/// Program header type: dynamic linking information.
pub const PT_DYNAMIC: u32 = 2;
/// Program header type: program interpreter path.
pub const PT_INTERP: u32 = 3;
/// Program header type: notes.
pub const PT_NOTE: u32 = 4;
/// Program header type: program header table itself.
pub const PT_PHDR: u32 = 6;
/// Program header type: thread-local storage template.
pub const PT_TLS: u32 = 7;
/// Program header type: GNU stack flags.
pub const PT_GNU_STACK: u32 = 0x6474_e551;
/// Program header type: GNU read-only after relocation.
pub const PT_GNU_RELRO: u32 = 0x6474_e552;

/// Segment flag: executable.
pub const PF_X: u32 = 1;
/// Segment flag: writable.
pub const PF_W: u32 = 2;
/// Segment flag: readable.
pub const PF_R: u32 = 4;
/// Mask of the segment flags defined by the ELF specification.
pub const PF_MASK: u32 = PF_R | PF_W | PF_X;

/// Section header type: symbol table.
pub const SHT_SYMTAB: u32 = 2;
/// Section header type: string table.
pub const SHT_STRTAB: u32 = 3;
/// Section index of the undefined section name.
pub const SHN_UNDEF: u16 = 0;

/// ELF class of 64-bit objects.
const ELFCLASS64: u8 = 2;
/// ELF data encoding of little-endian objects.
const ELFDATA2LSB: u8 = 1;
/// ELF magic bytes.
const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];

/// Safety bound on the number of program headers accepted by the decoder.
///
/// Consumers enforce their own, tighter policy (the bootloader accepts at most
/// 16 loadable segments, the guest loader 128 program headers); this bound only
/// prevents pathological tables from being walked.
pub const MAX_PROGRAM_HEADERS: usize = 4096;
/// Safety bound on the number of section headers accepted by the decoder.
pub const MAX_SECTION_HEADERS: usize = 4096;

/// Reason why a file is not a valid ELF64/x86-64 image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError {
    /// The input is shorter than the 64-byte file header.
    TruncatedHeader,
    /// The magic bytes are not `\x7fELF`.
    BadMagic,
    /// The object is not 64-bit (`ELFCLASS64`).
    BadClass,
    /// The object is not little-endian (`ELFDATA2LSB`).
    BadEndianness,
    /// The `e_ident` version is not [`EV_CURRENT`].
    BadIdentVersion,
    /// The `e_version` field is not [`EV_CURRENT`].
    BadVersion,
    /// The ELF type is neither `ET_EXEC` nor `ET_DYN`.
    UnsupportedType,
    /// The machine is not x86-64.
    UnsupportedMachine,
    /// `e_ehsize` is not [`ELF_HEADER_SIZE`].
    BadHeaderSize,
    /// `e_phentsize` is not [`PROGRAM_HEADER_SIZE`].
    BadProgramHeaderSize,
    /// The program header table location or size is invalid.
    BadProgramHeaders,
    /// The program header table contains too many entries.
    TooManyProgramHeaders,
    /// The program header table extends past the end of the file.
    TruncatedProgramHeaders,
    /// `e_shentsize` is not [`SECTION_HEADER_SIZE`].
    BadSectionHeaderSize,
    /// The section header table location or size is invalid.
    BadSectionHeaders,
    /// A section header table entry extends past the end of the file.
    TruncatedSectionHeaders,
    /// The section header string table index is out of range.
    BadSectionNameTable,
    /// A section name is not a valid NUL-terminated UTF-8 string.
    BadSectionName,
    /// A section's data range is outside the file.
    SectionOutOfBounds,
    /// A `PT_LOAD` segment has a zero memory size.
    EmptySegment,
    /// `p_filesz` exceeds `p_memsz`.
    FileSizeExceedsMemorySize,
    /// A segment address or size overflows the 64-bit range.
    SegmentOverflow,
    /// A segment's file-backed bytes extend past the end of the file.
    SegmentOutOfBounds,
    /// A segment's virtual address and file offset are not page congruent.
    MisalignedSegment,
    /// A segment's `p_align` is neither 0/1 nor a power of two.
    BadSegmentAlignment,
}

impl ElfError {
    /// Human-readable description, used in logs by the bootloader and kernel.
    pub const fn message(self) -> &'static str {
        match self {
            Self::TruncatedHeader => "truncated ELF header",
            Self::BadMagic => "invalid ELF magic",
            Self::BadClass => "not an ELF64 object",
            Self::BadEndianness => "not a little-endian ELF object",
            Self::BadIdentVersion => "unsupported ELF identification version",
            Self::BadVersion => "unsupported ELF version",
            Self::UnsupportedType => "unsupported ELF type",
            Self::UnsupportedMachine => "not an x86-64 ELF object",
            Self::BadHeaderSize => "invalid ELF header size",
            Self::BadProgramHeaderSize => "invalid program header entry size",
            Self::BadProgramHeaders => "invalid program header table",
            Self::TooManyProgramHeaders => "too many program headers",
            Self::TruncatedProgramHeaders => "truncated program header table",
            Self::BadSectionHeaderSize => "invalid section header entry size",
            Self::BadSectionHeaders => "invalid section header table",
            Self::TruncatedSectionHeaders => "truncated section header table",
            Self::BadSectionNameTable => "invalid section name table index",
            Self::BadSectionName => "invalid section name",
            Self::SectionOutOfBounds => "section data outside the file",
            Self::EmptySegment => "empty loadable segment",
            Self::FileSizeExceedsMemorySize => "segment file size exceeds memory size",
            Self::SegmentOverflow => "segment address or size overflow",
            Self::SegmentOutOfBounds => "segment data outside the file",
            Self::MisalignedSegment => {
                "segment virtual address and file offset are not page congruent"
            }
            Self::BadSegmentAlignment => "invalid segment alignment",
        }
    }
}

impl core::fmt::Display for ElfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.message())
    }
}

/// Parsed ELF64 file header.
///
/// Every field is the raw little-endian value from the file; validation of the
/// generic format (class, endianness, machine, table bounds) already happened
/// in [`Header::parse`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Object file type (`ET_EXEC`, `ET_DYN`, ...).
    pub e_type: u16,
    /// Target machine ([`EM_X86_64`]).
    pub e_machine: u16,
    /// Object file version ([`EV_CURRENT`]).
    pub e_version: u32,
    /// Entry point address.
    pub e_entry: u64,
    /// File offset of the program header table.
    pub e_phoff: u64,
    /// File offset of the section header table.
    pub e_shoff: u64,
    /// Processor-specific flags.
    pub e_flags: u32,
    /// Size of this header.
    pub e_ehsize: u16,
    /// Size of one program header entry.
    pub e_phentsize: u16,
    /// Number of program header entries.
    pub e_phnum: u16,
    /// Size of one section header entry.
    pub e_shentsize: u16,
    /// Number of section header entries.
    pub e_shnum: u16,
    /// Section header index of the section name string table.
    pub e_shstrndx: u16,
}

impl Header {
    /// Parses and validates an ELF64/x86-64 file header.
    ///
    /// Validates the generic format only: magic, class, endianness, versions,
    /// machine, x86-64 type (`ET_EXEC`/`ET_DYN`), header entry sizes and the
    /// bounds of the program and section header tables. Address-space and
    /// loading policies belong to the caller.
    pub fn parse(file: &[u8]) -> Result<Self, ElfError> {
        if file.len() < ELF_HEADER_SIZE {
            return Err(ElfError::TruncatedHeader);
        }
        if file[0..4] != ELF_MAGIC {
            return Err(ElfError::BadMagic);
        }
        if file[4] != ELFCLASS64 {
            return Err(ElfError::BadClass);
        }
        if file[5] != ELFDATA2LSB {
            return Err(ElfError::BadEndianness);
        }
        if file[6] != EV_CURRENT as u8 {
            return Err(ElfError::BadIdentVersion);
        }
        let header = Self {
            e_type: get_u16(file, 0x10)?,
            e_machine: get_u16(file, 0x12)?,
            e_version: get_u32(file, 0x14)?,
            e_entry: get_u64(file, 0x18)?,
            e_phoff: get_u64(file, 0x20)?,
            e_shoff: get_u64(file, 0x28)?,
            e_flags: get_u32(file, 0x30)?,
            e_ehsize: get_u16(file, 0x34)?,
            e_phentsize: get_u16(file, 0x36)?,
            e_phnum: get_u16(file, 0x38)?,
            e_shentsize: get_u16(file, 0x3A)?,
            e_shnum: get_u16(file, 0x3C)?,
            e_shstrndx: get_u16(file, 0x3E)?,
        };
        if !matches!(header.e_type, ET_EXEC | ET_DYN) {
            return Err(ElfError::UnsupportedType);
        }
        if header.e_machine != EM_X86_64 {
            return Err(ElfError::UnsupportedMachine);
        }
        if header.e_version != EV_CURRENT {
            return Err(ElfError::BadVersion);
        }
        if header.e_ehsize as usize != ELF_HEADER_SIZE {
            return Err(ElfError::BadHeaderSize);
        }
        if header.e_phentsize as usize != PROGRAM_HEADER_SIZE {
            return Err(ElfError::BadProgramHeaderSize);
        }
        header.program_header_bounds(file.len())?;
        header.section_header_bounds(file.len())?;
        Ok(header)
    }

    /// True for a fixed-address executable (`ET_EXEC`).
    pub const fn is_exec(&self) -> bool {
        self.e_type == ET_EXEC
    }

    /// True for a position-independent executable (`ET_DYN`).
    pub const fn is_dynamic(&self) -> bool {
        self.e_type == ET_DYN
    }

    /// Iterator over the program header table.
    ///
    /// `file` must be the same slice that was passed to [`Header::parse`]; the
    /// table bounds were validated there, so the iterator never panics (it
    /// simply stops early on a truncated slice).
    pub fn program_headers<'a>(&self, file: &'a [u8]) -> ProgramHeaders<'a> {
        let offset = usize::try_from(self.e_phoff).unwrap_or(usize::MAX);
        ProgramHeaders {
            file,
            offset,
            remaining: self.e_phnum as usize,
        }
    }

    /// Iterator over the section header table.
    pub fn section_headers(&self) -> SectionHeaders {
        SectionHeaders {
            index: 0,
            remaining: self.e_shnum as usize,
        }
    }

    /// Validates the program header table location within a file of
    /// `file_len` bytes and returns its end offset.
    fn program_header_bounds(&self, file_len: usize) -> Result<usize, ElfError> {
        if self.e_phnum == 0 {
            return Ok(ELF_HEADER_SIZE);
        }
        if self.e_phnum as usize > MAX_PROGRAM_HEADERS {
            return Err(ElfError::TooManyProgramHeaders);
        }
        let offset = usize::try_from(self.e_phoff).map_err(|_| ElfError::BadProgramHeaders)?;
        if offset < ELF_HEADER_SIZE || offset % 8 != 0 {
            return Err(ElfError::BadProgramHeaders);
        }
        let table_len = (self.e_phnum as usize)
            .checked_mul(PROGRAM_HEADER_SIZE)
            .ok_or(ElfError::TruncatedProgramHeaders)?;
        offset
            .checked_add(table_len)
            .filter(|end| *end <= file_len)
            .ok_or(ElfError::TruncatedProgramHeaders)
    }

    /// Validates the section header table location within a file of `file_len`
    /// bytes.
    ///
    /// A file without sections is valid (`e_shnum == 0`, as emitted by
    /// stripped images and test fixtures). Extended numbering (`e_shnum == 0`
    /// with a real count in section 0) is not required by any consumer here
    /// and is treated as "no sections".
    fn section_header_bounds(&self, file_len: usize) -> Result<(), ElfError> {
        if self.e_shnum == 0 {
            return Ok(());
        }
        if self.e_shentsize as usize != SECTION_HEADER_SIZE {
            return Err(ElfError::BadSectionHeaderSize);
        }
        if self.e_shnum as usize > MAX_SECTION_HEADERS {
            return Err(ElfError::BadSectionHeaders);
        }
        if self.e_shstrndx >= self.e_shnum && self.e_shstrndx != SHN_UNDEF {
            return Err(ElfError::BadSectionNameTable);
        }
        let offset = usize::try_from(self.e_shoff).map_err(|_| ElfError::BadSectionHeaders)?;
        if offset < ELF_HEADER_SIZE || offset % 8 != 0 {
            return Err(ElfError::BadSectionHeaders);
        }
        let table_len = (self.e_shnum as usize)
            .checked_mul(SECTION_HEADER_SIZE)
            .ok_or(ElfError::TruncatedSectionHeaders)?;
        offset
            .checked_add(table_len)
            .filter(|end| *end <= file_len)
            .ok_or(ElfError::TruncatedSectionHeaders)?;
        Ok(())
    }

    /// Decodes the section header at `index` from the file.
    pub fn section_header(&self, file: &[u8], index: usize) -> Result<SectionHeader, ElfError> {
        if index >= self.e_shnum as usize {
            return Err(ElfError::BadSectionHeaders);
        }
        let offset = usize::try_from(self.e_shoff)
            .ok()
            .and_then(|base| base.checked_add(index * SECTION_HEADER_SIZE))
            .ok_or(ElfError::BadSectionHeaders)?;
        let raw = file
            .get(offset..offset + SECTION_HEADER_SIZE)
            .ok_or(ElfError::TruncatedSectionHeaders)?;
        SectionHeader::decode(raw)
    }

    /// Resolves the name of a section through `e_shstrndx`.
    pub fn section_name<'a>(&self, file: &'a [u8], index: usize) -> Result<&'a str, ElfError> {
        if self.e_shstrndx == SHN_UNDEF {
            return Err(ElfError::BadSectionNameTable);
        }
        let section = self.section_header(file, index)?;
        let names = self
            .section_header(file, self.e_shstrndx as usize)?
            .data(file)?;
        let start = section.sh_name as usize;
        let tail = names.get(start..).ok_or(ElfError::BadSectionName)?;
        let len = tail
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(ElfError::BadSectionName)?;
        core::str::from_utf8(&tail[..len]).map_err(|_| ElfError::BadSectionName)
    }

    /// Finds a section by name.
    pub fn find_section(&self, file: &[u8], name: &str) -> Result<Option<SectionHeader>, ElfError> {
        if self.e_shnum == 0 || self.e_shstrndx == SHN_UNDEF {
            return Ok(None);
        }
        for index in 0..self.e_shnum as usize {
            let section = self.section_header(file, index)?;
            if self.section_name(file, index)? == name {
                return Ok(Some(section));
            }
        }
        Ok(None)
    }
}

/// Iterator over a validated program header table.
#[derive(Debug, Clone, Copy)]
pub struct ProgramHeaders<'a> {
    file: &'a [u8],
    offset: usize,
    remaining: usize,
}

impl Iterator for ProgramHeaders<'_> {
    type Item = ProgramHeader;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let raw = self
            .file
            .get(self.offset..self.offset.checked_add(PROGRAM_HEADER_SIZE)?)?;
        self.offset += PROGRAM_HEADER_SIZE;
        self.remaining -= 1;
        ProgramHeader::decode(raw).ok()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for ProgramHeaders<'_> {}

/// Iterator over the section header table.
#[derive(Debug, Clone, Copy)]
pub struct SectionHeaders {
    index: usize,
    remaining: usize,
}

impl Iterator for SectionHeaders {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let index = self.index;
        self.index += 1;
        self.remaining -= 1;
        Some(index)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for SectionHeaders {}

/// Parsed ELF64 program header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramHeader {
    /// Segment type (`PT_LOAD`, `PT_DYNAMIC`, ...).
    pub p_type: u32,
    /// Segment permission flags (`PF_R`, `PF_W`, `PF_X`).
    pub p_flags: u32,
    /// File offset of the segment.
    pub p_offset: u64,
    /// Virtual address of the segment.
    pub p_vaddr: u64,
    /// Physical address of the segment (unused by this operating system).
    pub p_paddr: u64,
    /// Size of the file-backed prefix.
    pub p_filesz: u64,
    /// Size of the segment in memory, including the zero-filled tail.
    pub p_memsz: u64,
    /// Required alignment of the segment.
    pub p_align: u64,
}

impl ProgramHeader {
    /// Decodes one program header from at least [`PROGRAM_HEADER_SIZE`] bytes.
    pub fn decode(raw: &[u8]) -> Result<Self, ElfError> {
        if raw.len() < PROGRAM_HEADER_SIZE {
            return Err(ElfError::TruncatedProgramHeaders);
        }
        Ok(Self {
            p_type: get_u32(raw, 0)?,
            p_flags: get_u32(raw, 4)?,
            p_offset: get_u64(raw, 8)?,
            p_vaddr: get_u64(raw, 16)?,
            p_paddr: get_u64(raw, 24)?,
            p_filesz: get_u64(raw, 32)?,
            p_memsz: get_u64(raw, 40)?,
            p_align: get_u64(raw, 48)?,
        })
    }

    /// True if this is a loadable segment (`PT_LOAD`).
    pub const fn is_load(&self) -> bool {
        self.p_type == PT_LOAD
    }

    /// Validates this program header as a `PT_LOAD` segment of a file of
    /// `file_len` bytes and returns its load description.
    ///
    /// Format-level checks only:
    /// - `p_filesz <= p_memsz`;
    /// - no address/size overflow;
    /// - the file-backed prefix is inside the file;
    /// - `p_vaddr % PAGE_SIZE == p_offset % PAGE_SIZE`;
    /// - `p_align` is 0/1 or a power of two.
    ///
    /// Returns `Ok(None)` for an empty segment (`p_memsz == 0`): callers decide
    /// whether that is an error (the guest loader rejects it) or a segment to
    /// skip (the bootloader and the userland loader skip it).
    pub fn load_segment(&self, file_len: usize) -> Result<Option<LoadSegment>, ElfError> {
        if self.p_memsz == 0 {
            return Ok(None);
        }
        if self.p_filesz > self.p_memsz {
            return Err(ElfError::FileSizeExceedsMemorySize);
        }
        self.p_vaddr
            .checked_add(self.p_memsz)
            .ok_or(ElfError::SegmentOverflow)?;
        if self.p_filesz != 0 {
            let file_end = self
                .p_offset
                .checked_add(self.p_filesz)
                .ok_or(ElfError::SegmentOverflow)?;
            if file_end > file_len as u64 {
                return Err(ElfError::SegmentOutOfBounds);
            }
        }
        if self.p_vaddr % PAGE_SIZE != self.p_offset % PAGE_SIZE {
            return Err(ElfError::MisalignedSegment);
        }
        if self.p_align > 1 && !self.p_align.is_power_of_two() {
            return Err(ElfError::BadSegmentAlignment);
        }
        Ok(Some(LoadSegment {
            vaddr: self.p_vaddr,
            memsz: self.p_memsz,
            filesz: self.p_filesz,
            file_offset: self.p_offset,
            flags: self.p_flags,
        }))
    }
}

/// A validated `PT_LOAD` segment: the file format guarantees are already
/// checked, only loading policy remains.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LoadSegment {
    /// First virtual address of the segment.
    pub vaddr: u64,
    /// Size in memory, including the zero-filled tail (BSS).
    pub memsz: u64,
    /// Size of the file-backed prefix.
    pub filesz: u64,
    /// Offset of the file-backed prefix in the image file.
    pub file_offset: u64,
    /// Raw ELF `p_flags` bits.
    pub flags: u32,
}

impl LoadSegment {
    /// End virtual address (exclusive).
    ///
    /// Valid because [`ProgramHeader::load_segment`] checked for overflow.
    pub const fn end_vaddr(&self) -> u64 {
        self.vaddr + self.memsz
    }

    /// End offset of the file-backed prefix (exclusive).
    pub const fn file_end(&self) -> u64 {
        self.file_offset + self.filesz
    }
}

/// Parsed ELF64 section header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionHeader {
    /// Offset of the section name in the section name string table.
    pub sh_name: u32,
    /// Section type (`SHT_SYMTAB`, `SHT_STRTAB`, ...).
    pub sh_type: u32,
    /// Section flags.
    pub sh_flags: u64,
    /// Virtual address of the section when loaded.
    pub sh_addr: u64,
    /// File offset of the section data.
    pub sh_offset: u64,
    /// Size of the section data in bytes.
    pub sh_size: u64,
    /// Link to another section (e.g. the string table of a symbol table).
    pub sh_link: u32,
    /// Extra information whose meaning depends on the section type.
    pub sh_info: u32,
    /// Required alignment of the section.
    pub sh_addralign: u64,
    /// Size of one entry for sections that hold entries.
    pub sh_entsize: u64,
}

impl SectionHeader {
    /// Decodes one section header from at least [`SECTION_HEADER_SIZE`] bytes.
    pub fn decode(raw: &[u8]) -> Result<Self, ElfError> {
        if raw.len() < SECTION_HEADER_SIZE {
            return Err(ElfError::TruncatedSectionHeaders);
        }
        Ok(Self {
            sh_name: get_u32(raw, 0)?,
            sh_type: get_u32(raw, 4)?,
            sh_flags: get_u64(raw, 8)?,
            sh_addr: get_u64(raw, 16)?,
            sh_offset: get_u64(raw, 24)?,
            sh_size: get_u64(raw, 32)?,
            sh_link: get_u32(raw, 40)?,
            sh_info: get_u32(raw, 44)?,
            sh_addralign: get_u64(raw, 48)?,
            sh_entsize: get_u64(raw, 56)?,
        })
    }

    /// Section data, checked against the file length.
    pub fn data<'a>(&self, file: &'a [u8]) -> Result<&'a [u8], ElfError> {
        let start = usize::try_from(self.sh_offset).map_err(|_| ElfError::SectionOutOfBounds)?;
        let len = usize::try_from(self.sh_size).map_err(|_| ElfError::SectionOutOfBounds)?;
        let end = start.checked_add(len).ok_or(ElfError::SectionOutOfBounds)?;
        file.get(start..end).ok_or(ElfError::SectionOutOfBounds)
    }

    /// True for a symbol table (`.symtab`).
    pub const fn is_symtab(&self) -> bool {
        self.sh_type == SHT_SYMTAB
    }

    /// True for a string table (`.strtab`, `.shstrtab`).
    pub const fn is_strtab(&self) -> bool {
        self.sh_type == SHT_STRTAB
    }
}

/// Parsed ELF64 symbol-table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Symbol {
    /// Offset of the symbol name in the linked string table.
    pub name: u32,
    /// Symbol binding and type.
    pub info: u8,
    /// Symbol visibility.
    pub other: u8,
    /// Index of the section the symbol is defined in.
    pub shndx: u16,
    /// Symbol value (address for functions and objects).
    pub value: u64,
    /// Symbol size in bytes.
    pub size: u64,
}

impl Symbol {
    /// Decodes one symbol from at least [`SYMBOL_ENTRY_SIZE`] bytes.
    pub fn decode(raw: &[u8]) -> Result<Self, ElfError> {
        if raw.len() < SYMBOL_ENTRY_SIZE {
            return Err(ElfError::TruncatedSectionHeaders);
        }
        Ok(Self {
            name: get_u32(raw, 0)?,
            info: raw[4],
            other: raw[5],
            shndx: get_u16(raw, 6)?,
            value: get_u64(raw, 8)?,
            size: get_u64(raw, 16)?,
        })
    }

    /// Iterates over a symbol table, ignoring trailing partial entries.
    pub fn iter(table: &[u8]) -> impl Iterator<Item = Symbol> + '_ {
        table
            .chunks_exact(SYMBOL_ENTRY_SIZE)
            .filter_map(|raw| Symbol::decode(raw).ok())
    }
}

/// Reads a little-endian `u16` at `offset`.
fn get_u16(bytes: &[u8], offset: usize) -> Result<u16, ElfError> {
    let end = offset.checked_add(2).ok_or(ElfError::TruncatedHeader)?;
    let raw = bytes.get(offset..end).ok_or(ElfError::TruncatedHeader)?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

/// Reads a little-endian `u32` at `offset`.
fn get_u32(bytes: &[u8], offset: usize) -> Result<u32, ElfError> {
    let end = offset.checked_add(4).ok_or(ElfError::TruncatedHeader)?;
    let raw = bytes.get(offset..end).ok_or(ElfError::TruncatedHeader)?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

/// Reads a little-endian `u64` at `offset`.
fn get_u64(bytes: &[u8], offset: usize) -> Result<u64, ElfError> {
    let end = offset.checked_add(8).ok_or(ElfError::TruncatedHeader)?;
    let raw = bytes.get(offset..end).ok_or(ElfError::TruncatedHeader)?;
    Ok(u64::from_le_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]))
}
