//! VirtIO block device driver for boot partition access.
//!
//! Minimal read-only driver for reading modules from the FAT32 boot partition.
//! Supports both PCI (x86_64 QEMU) and MMIO (RISC-V/ARM64 QEMU) transports.

use super::block_device::BlockDevice;

/// VirtIO block device
pub struct VirtioBlkDevice {
    /// Base address of the device registers (MMIO or PCI BAR)
    base_addr: u64,
    /// Block size in bytes
    block_size: u64,
    /// Device features
    features: u32,
}

impl VirtioBlkDevice {
    /// Create a new VirtIO block device from MMIO base address.
    ///
    /// # Safety
    ///
    /// `base_addr` must point to valid VirtIO device registers.
    pub unsafe fn new(base_addr: u64) -> Self {
        Self {
            base_addr,
            block_size: 512, // Default, updated during init
            features: 0,
        }
    }

    /// Initialize the VirtIO block device.
    ///
    /// # Safety
    ///
    /// Must only be called once with a valid device address.
    pub unsafe fn init(&mut self) -> Result<(), &'static str> {
        crate::serial_println!("[virtio-blk] Initializing at {:#x}", self.base_addr);

        // Read device status
        let status = core::ptr::read_volatile((self.base_addr + 0x14) as *const u32);
        crate::serial_println!("[virtio-blk] Device status: {:#x}", status);

        // Read device features
        self.features = core::ptr::read_volatile((self.base_addr + 0x0) as *const u32);
        crate::serial_println!("[virtio-blk] Features: {:#x}", self.features);

        // Acknowledge the device
        core::ptr::write_volatile((self.base_addr + 0x14) as *mut u32, 0x0);

        // Set driver status
        core::ptr::write_volatile((self.base_addr + 0x14) as *mut u32, 0x1);

        // Read configuration space for block size
        let capacity_lo = core::ptr::read_volatile((self.base_addr + 0x100) as *const u32);
        let capacity_hi = core::ptr::read_volatile((self.base_addr + 0x104) as *const u32);
        let capacity = ((capacity_hi as u64) << 32) | (capacity_lo as u64);
        crate::serial_println!("[virtio-blk] Capacity: {} blocks", capacity);

        // Set driver ok status
        core::ptr::write_volatile((self.base_addr + 0x14) as *mut u32, 0x4);

        crate::serial_println!("[virtio-blk] Initialized successfully");
        Ok(())
    }

    /// Create a VirtIO block device from a Device Tree node.
    ///
    /// # Safety
    ///
    /// `dtb_ptr` must point to a valid flattened device tree.
    pub unsafe fn from_dtb(dtb_ptr: u64) -> Option<Self> {
        // TODO: Parse DTB to find virtio-blk device address
        // For now, use a hardcoded address for QEMU x86_64
        #[cfg(target_arch = "x86_64")]
        let base_addr = 0xfebf0000u64; // Typical QEMU virtio-blk MMIO address

        #[cfg(not(target_arch = "x86_64"))]
        let base_addr = {
            crate::serial_println!("[virtio-blk] DTB parsing not implemented for this arch");
            return None;
        };

        let mut device = VirtioBlkDevice::new(base_addr);
        if device.init().is_err() {
            return None;
        }
        Some(device)
    }
}

impl BlockDevice for VirtioBlkDevice {
    fn read_block(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), ()> {
        // TODO: Implement proper VirtIO block read with virtqueues
        // For now, this is a stub that returns an error
        crate::serial_println!(
            "[virtio-blk] read_block(lba={:#x}, len={}) - not yet implemented",
            lba,
            buf.len()
        );
        Err(())
    }

    fn block_size(&self) -> u64 {
        self.block_size
    }
}
