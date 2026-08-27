//! Block device abstraction for boot partition access.
//!
//! Provides a trait for reading blocks from storage devices,
//! used by the FAT32 module loader to read userspace ELFs.

/// Trait for block-based storage devices.
pub trait BlockDevice {
    /// Read blocks from the device into the buffer.
    ///
    /// # Arguments
    /// * `lba` - Logical Block Address to start reading from
    /// * `buf` - Buffer to read into (must be at least block_size() bytes)
    ///
    /// # Returns
    /// `Ok(())` on success, `Err(())` on failure.
    fn read_block(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), ()>;

    /// Get the block size in bytes (typically 512 or 4096).
    fn block_size(&self) -> u64;
}

/// Initialize a block device from the Device Tree.
///
/// # Safety
///
/// `dtb_ptr` must point to a valid flattened device tree.
pub unsafe fn init_block_device_from_dtb(dtb_ptr: u64) -> Option<&'static mut dyn BlockDevice> {
    // TODO: Parse DTB to find virtio-blk or other block devices
    // For now, return None until Phase 4 is fully implemented
    crate::serial_println!("[block] Block device init from DTB not yet implemented");
    None
}
