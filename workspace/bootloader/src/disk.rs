//! Block device abstraction for bootloader
//! This is used by the EXT4 filesystem driver

/// Block device trait
pub trait BlockDevice {
    /// Read blocks from the device
    fn read(&mut self, block: u64, buffer: &mut [u8]) -> Result<(), BlockError>;

    /// Write blocks to the device
    fn write(&mut self, block: u64, buffer: &[u8]) -> Result<(), BlockError>;

    /// Get the block size in bytes
    fn block_size(&self) -> usize;

    /// Get the total number of blocks
    fn block_count(&self) -> u64;
}

/// Block device error types
#[derive(Debug, Clone, Copy)]
pub enum BlockError {
    /// I/O error
    IoError,
    /// Invalid block number
    InvalidBlock,
    /// Device not ready
    NotReady,
    /// Other error
    Other,
}

impl core::fmt::Display for BlockError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            BlockError::IoError => write!(f, "I/O error"),
            BlockError::InvalidBlock => write!(f, "Invalid block"),
            BlockError::NotReady => write!(f, "Device not ready"),
            BlockError::Other => write!(f, "Unknown error"),
        }
    }
}
