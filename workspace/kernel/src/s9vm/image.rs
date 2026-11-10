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

//! s9vm — guest image format and loading plan.
//!
//! A guest image is a static, little-endian ELF64 executable for x86-64:
//! `ET_EXEC` linked at a fixed virtual address, or `ET_DYN` relocatable at a
//! caller-chosen base. Only `PT_LOAD` program headers are meaningful: they
//! describe the guest-physical footprint of the image, the file-backed bytes
//! and the zero-filled tail (BSS) of each segment.
//!
//! The generic ELF64 decoding is shared with the bootloader and the kernel
//! userland loader (`strat9-elf-core`); this module only keeps the guest
//! loading policy (footprint limits, relocation to guest-physical memory).
//!
//! This module is **pure**: it parses and validates the image bytes and
//! computes the load plan (guest-physical span, per-segment page range,
//! permissions) without allocating and without touching memory. The kernel
//! layer (`s9vm::vm`) executes the plan: it maps the pages, copies the
//! file-backed bytes and zeroes the rest.
//!
//! Validation is strict and every rejection is a typed [`ImageError`]: a
//! malformed image can never make the parser panic or describe ranges outside
//! the input slice.
//!
//! Testable on the host (L2 tests).

use strat9_elf_core::{ElfError, Header, ET_DYN, ET_EXEC, PF_R, PF_W, PF_X};

/// Size of a base page (4 KiB); must match `s9vm::memmap::PAGE_SIZE`.
pub const PAGE_SIZE: u64 = 4096;
/// Maximum number of `PT_LOAD` segments in a guest image.
pub const MAX_SEGMENTS: usize = 32;
/// Maximum number of program headers scanned (safety bound).
pub const MAX_PROGRAM_HEADERS: usize = 128;
/// Maximum size of the image file (64 MiB).
pub const MAX_IMAGE_BYTES: usize = 64 * 1024 * 1024;
/// Maximum guest-physical footprint of a loaded image (256 MiB).
pub const MAX_LOAD_BYTES: u64 = 256 * 1024 * 1024;

/// Kind of guest executable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageKind {
    /// Fixed-address executable (`ET_EXEC`): virtual addresses are absolute.
    Exec,
    /// Position-independent executable (`ET_DYN`): the caller chooses a base.
    Dynamic,
}

/// Reasons why an image is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageError {
    /// The input is smaller than the ELF64 header.
    TruncatedHeader,
    /// The magic bytes are not `\x7fELF`.
    BadMagic,
    /// The ELF class is not 64-bit.
    BadClass,
    /// The data encoding is not little-endian.
    BadEndianness,
    /// The `e_ident` version is not 1.
    BadIdentVersion,
    /// The header version is not 1.
    BadVersion,
    /// `e_ehsize` is not 64.
    BadHeaderSize,
    /// `e_phentsize` is not 56.
    BadProgramHeaderSize,
    /// The program header table location is invalid.
    BadProgramHeaders,
    /// The section header table is malformed (unused by the guest loader, but
    /// rejected by the shared parser).
    BadSectionHeaders,
    /// The program header table extends past the end of the file.
    TruncatedProgramHeaders,
    /// The program header count exceeds [`MAX_PROGRAM_HEADERS`].
    TooManyProgramHeaders,
    /// The ELF type is neither `ET_EXEC` nor `ET_DYN`.
    UnsupportedType,
    /// The ELF machine is not x86-64.
    UnsupportedMachine,
    /// No `PT_LOAD` segment was found.
    NoLoadableSegments,
    /// More than [`MAX_SEGMENTS`] loadable segments.
    TooManySegments,
    /// A segment's file-backed data extends past the end of the file.
    SegmentOutOfBounds,
    /// A segment address or size overflows the 64-bit range.
    SegmentOverflow,
    /// A loadable segment has a zero memory size.
    EmptySegment,
    /// A segment's `p_filesz` exceeds its `p_memsz`.
    FileSizeExceedsMemorySize,
    /// A segment's virtual address and file offset are not page congruent.
    MisalignedSegment,
    /// A segment's `p_align` is neither 0/1 nor a power of two.
    BadSegmentAlignment,
    /// Loadable segments are not sorted by increasing virtual address.
    UnorderedSegments,
    /// Loadable segments overlap after page alignment.
    OverlappingSegments,
    /// The image file is larger than [`MAX_IMAGE_BYTES`].
    ImageTooLarge,
    /// The loaded footprint is larger than [`MAX_LOAD_BYTES`].
    LoadTooLarge,
}

/// One loadable segment of a guest image.
///
/// All addresses are guest virtual addresses as encoded in the image; the
/// kernel layer relocates them through [`Image::segment_gpa`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Segment {
    /// First guest virtual address of the segment.
    pub vaddr: u64,
    /// Size in memory, including the zero-filled tail (BSS).
    pub memsz: u64,
    /// Size of the file-backed prefix.
    pub filesz: u64,
    /// Offset of the file-backed prefix in the image file.
    pub file_offset: u64,
    /// Raw ELF `p_flags` bits (`PF_X`, `PF_W`, `PF_R`).
    pub flags: u32,
}

impl Segment {
    /// First virtual address of the segment, page-aligned down.
    pub const fn page_start(&self) -> u64 {
        align_down(self.vaddr)
    }

    /// Offset of the segment start inside its first page.
    pub const fn page_offset(&self) -> u64 {
        self.vaddr - self.page_start()
    }

    /// Number of 4 KiB pages covered by the segment.
    pub fn page_count(&self) -> u64 {
        self.page_len() / PAGE_SIZE
    }

    /// Length in bytes of the page-aligned footprint.
    ///
    /// Only meaningful for a segment parsed by [`Image::parse`] (the length is
    /// then always a non-zero multiple of [`PAGE_SIZE`]); a segment built by
    /// hand with overflowing values yields `0` instead of panicking.
    pub fn page_len(&self) -> u64 {
        match align_up(self.vaddr.saturating_add(self.memsz)) {
            Some(end) => end.saturating_sub(self.page_start()),
            None => 0,
        }
    }

    /// End virtual address (exclusive); valid because parsing checked for
    /// overflow.
    pub const fn end_vaddr(&self) -> u64 {
        self.vaddr + self.memsz
    }

    /// End offset of the file-backed prefix (exclusive).
    pub const fn file_end(&self) -> u64 {
        self.file_offset + self.filesz
    }

    /// True if the segment is readable.
    pub const fn is_readable(&self) -> bool {
        self.flags & PF_R != 0
    }

    /// True if the segment is writable.
    pub const fn is_writable(&self) -> bool {
        self.flags & PF_W != 0
    }

    /// True if the segment is executable.
    pub const fn is_executable(&self) -> bool {
        self.flags & PF_X != 0
    }

    /// Permissions encoded for the world memory map (`s9vm::memmap`):
    /// bit 1 = read, bit 2 = write, bit 4 = execute.
    ///
    /// A segment without any ELF permission maps to `0`, which the ABI layer
    /// interprets as implicit read; this is harmless because such a segment
    /// cannot be used as intended anyway.
    pub const fn perms_bits(&self) -> u32 {
        let mut bits = 0;
        if self.is_readable() {
            bits |= 1;
        }
        if self.is_writable() {
            bits |= 2;
        }
        if self.is_executable() {
            bits |= 4;
        }
        bits
    }
}

/// A parsed guest image.
///
/// Borrows the image bytes; the returned plan is valid as long as the slice
/// is. Copying the structure is cheap (the segment table is inline).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Image<'a> {
    bytes: &'a [u8],
    kind: ImageKind,
    entry: u64,
    base_vaddr: u64,
    span_len: u64,
    segments: [Segment; MAX_SEGMENTS],
    count: usize,
}

impl<'a> Image<'a> {
    /// Parses and validates a guest image.
    ///
    /// Never panics: every malformed input yields an [`ImageError`].
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ImageError> {
        if bytes.len() > MAX_IMAGE_BYTES {
            return Err(ImageError::ImageTooLarge);
        }
        let header = Header::parse(bytes).map_err(map_elf_error)?;
        let kind = match header.e_type {
            ET_EXEC => ImageKind::Exec,
            ET_DYN => ImageKind::Dynamic,
            _ => return Err(ImageError::UnsupportedType),
        };
        let phnum = header.e_phnum as usize;
        if phnum == 0 {
            return Err(ImageError::NoLoadableSegments);
        }
        if phnum > MAX_PROGRAM_HEADERS {
            return Err(ImageError::TooManyProgramHeaders);
        }
        let entry = header.e_entry;

        let mut segments = [Segment::default(); MAX_SEGMENTS];
        let mut count = 0usize;
        let mut base_vaddr: Option<u64> = None;
        let mut span_end = 0u64;
        let mut previous_vaddr: Option<u64> = None;
        let mut previous_page_end: Option<u64> = None;

        for phdr in header.program_headers(bytes) {
            if !phdr.is_load() {
                continue;
            }
            let Some(segment) = phdr.load_segment(bytes.len()).map_err(map_elf_error)? else {
                return Err(ImageError::EmptySegment);
            };
            // The guest loader is stricter than the bootloader: even a pure BSS
            // segment must have its nominal file offset inside the file.
            if segment.filesz == 0 && segment.file_offset > bytes.len() as u64 {
                return Err(ImageError::SegmentOutOfBounds);
            }
            let page_start = align_down(segment.vaddr);
            if let Some(previous) = previous_vaddr {
                if segment.vaddr <= previous {
                    return Err(ImageError::UnorderedSegments);
                }
            }
            let page_end =
                align_up(segment.end_vaddr()).ok_or(ImageError::SegmentOverflow)?;
            if let Some(previous_end) = previous_page_end {
                if page_start < previous_end {
                    return Err(ImageError::OverlappingSegments);
                }
            }
            if count >= MAX_SEGMENTS {
                return Err(ImageError::TooManySegments);
            }
            segments[count] = Segment {
                vaddr: segment.vaddr,
                memsz: segment.memsz,
                filesz: segment.filesz,
                file_offset: segment.file_offset,
                flags: segment.flags,
            };
            count += 1;
            previous_vaddr = Some(segment.vaddr);
            previous_page_end = Some(page_end);
            if base_vaddr.is_none() {
                base_vaddr = Some(page_start);
            }
            span_end = page_end;
        }

        let base_vaddr = base_vaddr.ok_or(ImageError::NoLoadableSegments)?;
        let span_len = span_end - base_vaddr;
        if span_len > MAX_LOAD_BYTES {
            return Err(ImageError::LoadTooLarge);
        }
        Ok(Self {
            bytes,
            kind,
            entry,
            base_vaddr,
            span_len,
            segments,
            count,
        })
    }

    /// Kind of executable.
    pub const fn kind(&self) -> ImageKind {
        self.kind
    }

    /// Entry point, as a guest virtual address encoded in the image.
    pub const fn entry(&self) -> u64 {
        self.entry
    }

    /// Loadable segments, sorted by increasing virtual address.
    pub fn segments(&self) -> &[Segment] {
        &self.segments[..self.count]
    }

    /// Number of loadable segments.
    pub const fn segment_count(&self) -> usize {
        self.count
    }

    /// Lowest page-aligned virtual address covered by the image.
    pub const fn base_vaddr(&self) -> u64 {
        self.base_vaddr
    }

    /// Length in bytes of the page-aligned image footprint.
    pub const fn span_len(&self) -> u64 {
        self.span_len
    }

    /// Total number of 4 KiB pages covered by the image.
    pub fn total_pages(&self) -> u64 {
        self.segments().iter().map(Segment::page_count).sum()
    }

    /// Size of the image file in bytes.
    pub const fn file_size(&self) -> usize {
        self.bytes.len()
    }

    /// File-backed bytes of a segment.
    ///
    /// Returns `None` only if the caller passes a segment that does not belong
    /// to this image; parsed segments are always in bounds.
    pub fn bytes_for_segment(&self, segment: &Segment) -> Option<&'a [u8]> {
        let start = usize::try_from(segment.file_offset).ok()?;
        let len = usize::try_from(segment.filesz).ok()?;
        let end = start.checked_add(len)?;
        self.bytes.get(start..end)
    }

    /// Guest-physical span of the image when loaded at `load_base_gpa`.
    ///
    /// Returns `(min, max)` with `max` exclusive. `load_base_gpa` must be
    /// page-aligned (the kernel layer enforces it); the span is page-aligned on
    /// both ends. `None` when the span does not fit in a 64-bit address.
    pub fn load_span(&self, load_base_gpa: u64) -> Option<(u64, u64)> {
        let max = load_base_gpa.checked_add(self.span_len)?;
        Some((load_base_gpa, max))
    }

    /// Guest-physical address of the first page of `segment` when the image is
    /// loaded at `load_base_gpa` (page-aligned).
    pub fn segment_gpa(&self, load_base_gpa: u64, segment: &Segment) -> Option<u64> {
        let delta = segment.page_start().checked_sub(self.base_vaddr)?;
        load_base_gpa.checked_add(delta)
    }

    /// Guest-physical entry point when the image is loaded at `load_base_gpa`.
    ///
    /// `None` when the entry point lies below the image base or when the
    /// relocation overflows.
    pub fn entry_gpa(&self, load_base_gpa: u64) -> Option<u64> {
        let delta = self.entry.checked_sub(self.base_vaddr)?;
        load_base_gpa.checked_add(delta)
    }

    /// True if the entry point lies inside a loadable segment.
    pub fn entry_is_mapped(&self) -> bool {
        self.segments()
            .iter()
            .any(|segment| self.entry >= segment.vaddr && self.entry < segment.end_vaddr())
    }

    /// True if the entry point lies inside an executable segment.
    pub fn entry_is_executable(&self) -> bool {
        self.segments().iter().any(|segment| {
            segment.is_executable()
                && self.entry >= segment.vaddr
                && self.entry < segment.end_vaddr()
        })
    }
}

/// Maps a shared-parser error onto the guest image error space.
fn map_elf_error(error: ElfError) -> ImageError {
    match error {
        ElfError::TruncatedHeader => ImageError::TruncatedHeader,
        ElfError::BadMagic => ImageError::BadMagic,
        ElfError::BadClass => ImageError::BadClass,
        ElfError::BadEndianness => ImageError::BadEndianness,
        ElfError::BadIdentVersion => ImageError::BadIdentVersion,
        ElfError::BadVersion => ImageError::BadVersion,
        ElfError::UnsupportedType => ImageError::UnsupportedType,
        ElfError::UnsupportedMachine => ImageError::UnsupportedMachine,
        ElfError::BadHeaderSize => ImageError::BadHeaderSize,
        ElfError::BadProgramHeaderSize => ImageError::BadProgramHeaderSize,
        ElfError::BadProgramHeaders => ImageError::BadProgramHeaders,
        ElfError::TooManyProgramHeaders => ImageError::TooManyProgramHeaders,
        ElfError::TruncatedProgramHeaders => ImageError::TruncatedProgramHeaders,
        ElfError::EmptySegment => ImageError::EmptySegment,
        ElfError::FileSizeExceedsMemorySize => ImageError::FileSizeExceedsMemorySize,
        ElfError::SegmentOverflow => ImageError::SegmentOverflow,
        ElfError::SegmentOutOfBounds => ImageError::SegmentOutOfBounds,
        ElfError::MisalignedSegment => ImageError::MisalignedSegment,
        ElfError::BadSegmentAlignment => ImageError::BadSegmentAlignment,
        // Section headers are irrelevant to a guest image, but the shared
        // parser still validates them when present.
        ElfError::BadSectionHeaderSize
        | ElfError::BadSectionHeaders
        | ElfError::TruncatedSectionHeaders
        | ElfError::BadSectionNameTable
        | ElfError::BadSectionName
        | ElfError::SectionOutOfBounds => ImageError::BadSectionHeaders,
    }
}

/// Rounds `value` down to a 4 KiB boundary.
const fn align_down(value: u64) -> u64 {
    value & !(PAGE_SIZE - 1)
}

/// Rounds `value` up to a 4 KiB boundary.
fn align_up(value: u64) -> Option<u64> {
    value
        .checked_add(PAGE_SIZE - 1)
        .map(|rounded| align_down(rounded))
}
