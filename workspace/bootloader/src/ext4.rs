// EXT4 filesystem module for Strat9-OS bootloader
// This module provides EXT4 filesystem mounting and file access functionality

use crate::os::Os;
use alloc::{string::String, vec::Vec};
use core::{ptr, slice};

// Re-export from fs-ext4
pub use fs_ext4::{BlockDevice, BlockDeviceError, Ext4FileSystem};

/// EXT4 filesystem wrapper for bootloader use
pub struct FileSystem<D> {
    pub ext4: Ext4FileSystem,
    pub device: D,
    pub block_offset: u64,
}

impl<D> FileSystem<D>
where
    D: BlockDevice + 'static,
{
    /// Open an EXT4 filesystem from a device
    pub fn open(device: D, password: Option<&[u8]>) -> Result<Self, Ext4Error> {
        // EXT4 doesn't use passwords, but we keep the API compatible
        if password.is_some() {
            log::warn!("EXT4 does not support password protection, ignoring password");
        }

        let block_offset = 0; // TODO: Detect partition offset
        let ext4 = Ext4FileSystem::mount(alloc::sync::Arc::new(device))?;

        Ok(Self {
            ext4,
            device,
            block_offset,
        })
    }

    /// Get the size of the filesystem
    pub fn size(&self) -> u64 {
        // TODO: Get actual filesystem size from superblock
        0
    }

    /// Get the filesystem UUID
    pub fn uuid(&self) -> [u8; 16] {
        // TODO: Read UUID from EXT4 superblock
        [0u8; 16]
    }

    /// Get block offset
    pub fn block_offset(&self) -> u64 {
        self.block_offset
    }

    /// Read a file from the filesystem
    pub fn read_file(&mut self, dirname: &str, filename: &str) -> Result<Vec<u8>, Ext4Error> {
        // TODO: Implement actual file reading using ext4_rs
        // For now, return empty vector
        log::warn!("EXT4 file reading not yet fully implemented");
        Ok(Vec::new())
    }

    /// Get file size
    pub fn get_file_size(&self, dirname: &str, filename: &str) -> Result<u64, Ext4Error> {
        // TODO: Implement file size retrieval
        log::warn!("EXT4 file size retrieval not yet fully implemented");
        Ok(0)
    }
}

/// EXT4 error type
#[derive(Debug)]
pub struct Ext4Error {
    pub message: &'static str,
}

impl Ext4Error {
    pub fn new(message: &'static str) -> Self {
        Self { message }
    }
}

impl core::fmt::Display for Ext4Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "EXT4 Error: {}", self.message)
    }
}
