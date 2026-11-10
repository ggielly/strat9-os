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

//! Writer for synthetic ELF64 images (test fixtures).
//!
//! The small guest images used by the `s9vm` self-tests and by the userspace
//! policy are assembled byte by byte. This module is the mirror image of
//! [`crate::Header::parse`]: it writes the canonical layout (file header at
//! offset 0, program header table at offset 64) so that a generated image is
//! parsed back exactly as the production loader expects.
//!
//! The writer never panics: it reports [`BuildError::BufferTooSmall`] when the
//! caller's buffer cannot hold the header and the requested table, and
//! [`BuildError::TooManySegments`] when the program header count does not fit
//! the `e_phnum` field.
//!
//! Available in `no_std` and without allocation (callers own the buffer).

use crate::{
    ELF_HEADER_SIZE, EM_X86_64, EV_CURRENT, PF_MASK, PROGRAM_HEADER_SIZE, PT_LOAD,
};

/// Canonical file offset of the program header table written by this module.
pub const DEFAULT_PROGRAM_HEADER_OFFSET: usize = ELF_HEADER_SIZE;

/// Reasons why an image cannot be written into the caller's buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildError {
    /// The output buffer cannot hold the ELF header or the program header
    /// table.
    BufferTooSmall,
    /// More program headers were added than `e_phnum` can describe.
    TooManySegments,
}

impl core::fmt::Display for BuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::BufferTooSmall => "ELF image buffer too small",
            Self::TooManySegments => "too many ELF program headers",
        })
    }
}

/// Builds an ELF64 image in a caller-provided buffer.
///
/// The caller zeroes / fills the payload region itself; the writer only owns
/// the file header and the program header table.
#[derive(Debug)]
pub struct ImageWriter<'a> {
    out: &'a mut [u8],
    phoff: usize,
    count: u16,
}

impl<'a> ImageWriter<'a> {
    /// Starts an image with the file header at offset 0 and the program header
    /// table at [`DEFAULT_PROGRAM_HEADER_OFFSET`].
    ///
    /// `e_type` is [`ET_EXEC`] or [`ET_DYN`]; `entry` is the entry virtual
    /// address. Returns [`BuildError::BufferTooSmall`] if `out` cannot hold the
    /// file header.
    pub fn new(out: &'a mut [u8], e_type: u16, entry: u64) -> Result<Self, BuildError> {
        let header = out
            .get_mut(..ELF_HEADER_SIZE)
            .ok_or(BuildError::BufferTooSmall)?;
        for byte in header.iter_mut() {
            *byte = 0;
        }
        header[0..4].copy_from_slice(b"\x7fELF");
        header[4] = 2; // ELFCLASS64
        header[5] = 1; // ELFDATA2LSB
        header[6] = EV_CURRENT as u8;
        put_u16(header, 0x10, e_type);
        put_u16(header, 0x12, EM_X86_64);
        put_u32(header, 0x14, EV_CURRENT);
        put_u64(header, 0x18, entry);
        put_u64(header, 0x20, DEFAULT_PROGRAM_HEADER_OFFSET as u64);
        put_u16(header, 0x34, ELF_HEADER_SIZE as u16);
        put_u16(header, 0x36, PROGRAM_HEADER_SIZE as u16);
        Ok(Self {
            out,
            phoff: DEFAULT_PROGRAM_HEADER_OFFSET,
            count: 0,
        })
    }

    /// Number of program headers added so far.
    pub const fn segment_count(&self) -> u16 {
        self.count
    }

    /// Length in bytes of the header and program header table.
    pub fn header_len(&self) -> usize {
        self.phoff + self.count as usize * PROGRAM_HEADER_SIZE
    }

    /// Appends one program header (written at the next table slot).
    pub fn add(&mut self, header: &crate::ProgramHeader) -> Result<(), BuildError> {
        if self.count == u16::MAX {
            return Err(BuildError::TooManySegments);
        }
        let offset = self.phoff + self.count as usize * PROGRAM_HEADER_SIZE;
        let end = offset
            .checked_add(PROGRAM_HEADER_SIZE)
            .ok_or(BuildError::BufferTooSmall)?;
        let raw = self
            .out
            .get_mut(offset..end)
            .ok_or(BuildError::BufferTooSmall)?;
        put_u32(raw, 0, header.p_type);
        put_u32(raw, 4, header.p_flags & PF_MASK);
        put_u64(raw, 8, header.p_offset);
        put_u64(raw, 16, header.p_vaddr);
        put_u64(raw, 24, header.p_paddr);
        put_u64(raw, 32, header.p_filesz);
        put_u64(raw, 40, header.p_memsz);
        put_u64(raw, 48, header.p_align);
        self.count += 1;
        Ok(())
    }

    /// Appends one `PT_LOAD` program header.
    ///
    /// `p_paddr` mirrors `p_vaddr`: this operating system uses virtual
    /// addresses only.
    #[allow(clippy::too_many_arguments)]
    pub fn add_load(
        &mut self,
        flags: u32,
        file_offset: u64,
        vaddr: u64,
        filesz: u64,
        memsz: u64,
        align: u64,
    ) -> Result<(), BuildError> {
        self.add(&crate::ProgramHeader {
            p_type: PT_LOAD,
            p_flags: flags,
            p_offset: file_offset,
            p_vaddr: vaddr,
            p_paddr: vaddr,
            p_filesz: filesz,
            p_memsz: memsz,
            p_align: align,
        })
    }

    /// Finalizes the file header (`e_phnum`) and returns the image length.
    pub fn finish(self) -> usize {
        put_u16(self.out, 0x38, self.count);
        self.phoff + self.count as usize * PROGRAM_HEADER_SIZE
    }
}

/// Writes a little-endian `u16` at `offset` (in-bounds callers only).
fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

/// Writes a little-endian `u32` at `offset` (in-bounds callers only).
fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// Writes a little-endian `u64` at `offset` (in-bounds callers only).
fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
