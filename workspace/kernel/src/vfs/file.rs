//! Open file state.
//!
//! Represents an open file with its associated scheme and current offset.

use super::scheme::{DirEntry, DynScheme, FileFlags, FileStat, OpenFlags};
use crate::{sync::SpinLock, syscall::error::SyscallError};
use alloc::{string::String, vec::Vec};

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

    /// Seek to a new offset (absolute).
    pub fn seek(&self, new_offset: u64) -> Result<u64, SyscallError> {
        let mut offset = self.offset.lock();
        *offset = new_offset;
        Ok(*offset)
    }

    /// POSIX lseek: whence=0 SET, 1 CUR, 2 END.
    pub fn lseek(&self, off: i64, whence: u32) -> Result<u64, SyscallError> {
        let mut cur = self.offset.lock();
        let new_pos: i64 = match whence {
            0 => off,
            1 => (*cur as i64).checked_add(off).ok_or(SyscallError::InvalidArgument)?,
            2 => {
                let sz = self.size().unwrap_or(0) as i64;
                sz.checked_add(off).ok_or(SyscallError::InvalidArgument)?
            }
            _ => return Err(SyscallError::InvalidArgument),
        };
        if new_pos < 0 {
            return Err(SyscallError::InvalidArgument);
        }
        *cur = new_pos as u64;
        Ok(*cur)
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

    /// Get file metadata.
    pub fn stat(&self) -> Result<FileStat, SyscallError> {
        self.scheme.stat(self.file_id)
    }

    /// List directory entries (only valid for directories).
    pub fn readdir(&self) -> Result<Vec<DirEntry>, SyscallError> {
        if !self.file_flags.contains(FileFlags::DIRECTORY) {
            return Err(SyscallError::InvalidArgument);
        }
        self.scheme.readdir(self.file_id)
    }

    /// Get internal file_id (for scheme delegation).
    pub fn file_id(&self) -> u64 {
        self.file_id
    }

    /// Get the underlying scheme.
    pub fn scheme(&self) -> &DynScheme {
        &self.scheme
    }
}

impl Drop for OpenFile {
    fn drop(&mut self) {
        // Best-effort close on drop
        let _ = self.scheme.close(self.file_id);
    }
}
