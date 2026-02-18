//! Adapter between Redox Disk implementation and EXT4 BlockDevice trait

use fs_abstraction::{BlockDevice, FsError};
use super::DiskBios;

/// Wrapper to adapt DiskBios (Redox-style) to EXT4 BlockDevice trait
pub struct DiskExt4Adapter {
    inner: DiskBios,
}

impl DiskExt4Adapter {
    pub fn new(disk: DiskBios) -> Self {
        Self { inner: disk }
    }
}

impl BlockDevice for DiskExt4Adapter {
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<usize, FsError> {
        // DiskBios uses the redoxfs Disk trait which works with blocks
        // We need to adapt byte offsets to block offsets
        unsafe {
            use syscall::error::Result as SyscallResult;

            // Call the Disk trait read_at method
            let result: SyscallResult<usize> = redoxfs::Disk::read_at(&mut self.inner, offset, buffer);

            result.map_err(|e| {
                // Map syscall errors to FsError
                match e.errno {
                    syscall::EIO => FsError::Io,
                    syscall::ENOENT => FsError::NotFound,
                    syscall::EINVAL => FsError::InvalidInput,
                    _ => FsError::Other,
                }
            })
        }
    }

    fn write_at(&mut self, offset: u64, buffer: &[u8]) -> Result<usize, FsError> {
        // Write not supported in bootloader
        Err(FsError::ReadOnly)
    }

    fn size(&mut self) -> Result<u64, FsError> {
        // DiskBios doesn't implement size, return a large value
        // This will be improved when we add proper disk geometry detection
        Ok(u64::MAX)
    }

    fn sector_size(&self) -> usize {
        512 // Standard sector size for BIOS disks
    }
}