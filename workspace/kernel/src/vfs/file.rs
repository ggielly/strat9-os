//! Open file state.
//!
//! Represents an open file with its associated scheme and current offset.

use super::scheme::{DynScheme, FileFlags, OpenFlags};
use crate::{sync::SpinLock, syscall::error::SyscallError};
use alloc::string::String;

/// An open file handle.
pub struct OpenFile {
    /// Scheme handling this file.
    scheme: DynScheme,
    /// File ID within the scheme.
    file_id: u64,
    /// Original path (for debugging).
    path: String,
    /// Current read/write offset.
    offset: SpinLock<u64>,
    /// Flags from open().
    open_flags: OpenFlags,
    /// File properties.
    file_flags: FileFlags,
    /// Cached file size (if known).
    size: Option<u64>,
}

impl OpenFile {
    /// Create a new open file.
    pub fn new(
        scheme: DynScheme,
        file_id: u64,
        path: String,
        open_flags: OpenFlags,
        file_flags: FileFlags,
        size: Option<u64>,
    ) -> Self {
        OpenFile {
            scheme,
            file_id,
            path,
            offset: SpinLock::new(0),
            open_flags,
            file_flags,
            size,
        }
    }

    /// Read from the file at current offset, advancing the offset.
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, SyscallError> {
        if !self.open_flags.contains(OpenFlags::READ) {
            return Err(SyscallError::PermissionDenied);
        }

        let mut offset = self.offset.lock();
        let bytes_read = self.scheme.read(self.file_id, *offset, buf)?;
        *offset += bytes_read as u64;
        Ok(bytes_read)
    }

    /// Write to the file at current offset, advancing the offset.
    pub fn write(&self, buf: &[u8]) -> Result<usize, SyscallError> {
        if !self.open_flags.contains(OpenFlags::WRITE) {
            return Err(SyscallError::PermissionDenied);
        }

        let mut offset = self.offset.lock();
        if self.open_flags.contains(OpenFlags::APPEND) {
            // For append mode, always write at end
            if let Some(size) = self.size {
                *offset = size;
            }
        }

        let bytes_written = self.scheme.write(self.file_id, *offset, buf)?;
        *offset += bytes_written as u64;
        Ok(bytes_written)
    }

    /// Read at a specific offset without changing current offset (pread).
    pub fn pread(&self, offset: u64, buf: &mut [u8]) -> Result<usize, SyscallError> {
        if !self.open_flags.contains(OpenFlags::READ) {
            return Err(SyscallError::PermissionDenied);
        }
        self.scheme.read(self.file_id, offset, buf)
    }

    /// Write at a specific offset without changing current offset (pwrite).
    pub fn pwrite(&self, offset: u64, buf: &[u8]) -> Result<usize, SyscallError> {
        if !self.open_flags.contains(OpenFlags::WRITE) {
            return Err(SyscallError::PermissionDenied);
        }
        self.scheme.write(self.file_id, offset, buf)
    }

    /// Seek to a new offset.
    pub fn seek(&self, new_offset: u64) -> Result<u64, SyscallError> {
        let mut offset = self.offset.lock();
        *offset = new_offset;
        Ok(*offset)
    }

    /// Get current offset.
    pub fn tell(&self) -> u64 {
        *self.offset.lock()
    }

    /// Get file size.
    pub fn size(&self) -> Result<u64, SyscallError> {
        if let Some(size) = self.size {
            Ok(size)
        } else {
            self.scheme.size(self.file_id)
        }
    }

    /// Sync file to storage.
    pub fn sync(&self) -> Result<(), SyscallError> {
        self.scheme.sync(self.file_id)
    }

    /// Close the file (called when last reference is dropped).
    pub fn close(&self) -> Result<(), SyscallError> {
        self.scheme.close(self.file_id)
    }

    /// Get file flags.
    pub fn flags(&self) -> FileFlags {
        self.file_flags
    }

    /// Get open flags.
    pub fn open_flags(&self) -> OpenFlags {
        self.open_flags
    }

    /// Get path (for debugging).
    pub fn path(&self) -> &str {
        &self.path
    }
}

impl Drop for OpenFile {
    fn drop(&mut self) {
        // Best-effort close on drop
        let _ = self.scheme.close(self.file_id);
    }
}
