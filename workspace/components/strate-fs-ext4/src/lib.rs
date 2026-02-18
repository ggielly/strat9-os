//! EXT4 filesystem component for Strat9-OS
//!
//! This component provides EXT4 filesystem support using the ext4_rs library.
//! It implements the filesystem abstraction for Strat9-OS and provides
//! read/write access to EXT4 volumes.

#![no_std]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

// Re-export the ext4_rs types
pub use ext4_rs::{Ext4, Ext4Error};

/// Block device trait that ext4_rs requires
///
/// This trait must be implemented by any device driver that wants to
/// provide block-level access to EXT4 filesystems.
pub trait BlockDevice: Send + Sync {
    /// Read data from the device at the given byte offset
    fn read_offset(&self, offset: usize) -> Result<Vec<u8>, BlockDeviceError>;

    /// Write data to the device at the given byte offset
    fn write_offset(&mut self, offset: usize, data: &[u8]) -> Result<(), BlockDeviceError>;

    /// Get the size of the device in bytes
    fn size(&self) -> Result<usize, BlockDeviceError>;
}

/// Errors that can occur during block device operations
#[derive(Debug)]
pub enum BlockDeviceError {
    /// I/O error
    Io,
    /// Invalid offset
    InvalidOffset,
    /// Device not ready
    NotReady,
    /// Other error
    Other,
}

impl fmt::Display for BlockDeviceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockDeviceError::Io => write!(f, "I/O error"),
            BlockDeviceError::InvalidOffset => write!(f, "Invalid offset"),
            BlockDeviceError::NotReady => write!(f, "Device not ready"),
            BlockDeviceError::Other => write!(f, "Other error"),
        }
    }
}

/// EXT4 Filesystem wrapper for Strat9-OS
pub struct Ext4FileSystem {
    // TODO: Use actual ext4_rs once we figure out the BlockDevice trait mismatch
    _marker: core::marker::PhantomData<()>,
}

impl Ext4FileSystem {
    /// Mount an EXT4 filesystem from a block device
    pub fn mount<D: BlockDevice + 'static>(_device: Arc<D>) -> Result<Self, ()> {
        // TODO: Actually mount ext4_rs
        // For now, return stub filesystem
        Ok(Self {
            _marker: core::marker::PhantomData,
        })
    }
}

/// Strat9-OS filesystem operations
impl Ext4FileSystem {
    /// List entries in a directory
    pub fn read_dir(&self, _path: &str) -> Result<Vec<DirEntry>, ()> {
        // TODO: Implement using ext4_rs directory iteration
        Ok(Vec::new())
    }

    /// Open a file for reading
    pub fn open(&self, _path: &str) -> Result<File, ()> {
        // TODO: Implement file opening
        Ok(File {
            inode: 0,
            size: 0,
            offset: 0,
        })
    }

    /// Create a new file
    pub fn create(&mut self, _path: &str) -> Result<File, ()> {
        // TODO: Implement file creation
        Ok(File {
            inode: 0,
            size: 0,
            offset: 0,
        })
    }
}

/// Directory entry
#[derive(Debug)]
pub struct DirEntry {
    pub name: alloc::string::String,
    pub inode: u64,
    pub file_type: FileType,
}

/// File type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    RegularFile,
    Directory,
    SymLink,
    CharDevice,
    BlockDevice,
    Fifo,
    Socket,
    Unknown,
}

/// File handle
#[derive(Debug)]
pub struct File {
    inode: u64,
    size: u64,
    offset: u64,
}

impl File {
    /// Read data from the file
    pub fn read(&mut self, _buf: &mut [u8]) -> Result<usize, ()> {
        // TODO: Implement file reading
        Ok(0)
    }

    /// Write data to the file
    pub fn write(&mut self, _buf: &[u8]) -> Result<usize, ()> {
        // TODO: Implement file writing
        Ok(0)
    }

    /// Seek to a position in the file
    pub fn seek(&mut self, pos: u64) -> Result<u64, ()> {
        self.offset = pos;
        Ok(self.offset)
    }

    /// Get the file size
    pub fn size(&self) -> u64 {
        self.size
    }
}
