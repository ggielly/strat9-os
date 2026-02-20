//! VirtIO Block Device driver
//!
//! Provides disk I/O via VirtIO-blk protocol for QEMU/KVM environments.
//! Implements the BlockDevice trait for integration with filesystem layers.
//!
//! Reference: VirtIO spec v1.2, Section 5.2 (Block Device)

use super::{
    common::{VirtioDevice, Virtqueue},
    status,
};
use crate::{
    arch::x86_64::pci::{self, PciDevice},
    memory::{get_allocator, FrameAllocator, PhysFrame},
    sync::SpinLock,
};
use alloc::{boxed::Box, vec::Vec};
use core::{mem, ptr};

/// Block device sector size
pub const SECTOR_SIZE: usize = 512;

/// VirtIO block device features
pub mod features {
    pub const VIRTIO_BLK_F_SIZE_MAX: u32 = 1 << 1;
    pub const VIRTIO_BLK_F_SEG_MAX: u32 = 1 << 2;
    pub const VIRTIO_BLK_F_GEOMETRY: u32 = 1 << 4;
    pub const VIRTIO_BLK_F_RO: u32 = 1 << 5;
    pub const VIRTIO_BLK_F_BLK_SIZE: u32 = 1 << 6;
    pub const VIRTIO_BLK_F_FLUSH: u32 = 1 << 9;
    pub const VIRTIO_BLK_F_TOPOLOGY: u32 = 1 << 10;
    pub const VIRTIO_BLK_F_CONFIG_WCE: u32 = 1 << 11;
    pub const VIRTIO_BLK_F_DISCARD: u32 = 1 << 13;
    pub const VIRTIO_BLK_F_WRITE_ZEROES: u32 = 1 << 14;
}

/// VirtIO block request types
#[allow(dead_code)]
#[repr(u32)]
pub enum RequestType {
    /// Read from device
    In = 0,
    /// Write to device
    Out = 1,
    /// Flush write cache
    Flush = 4,
    /// Get device ID
    GetId = 8,
    /// Discard sectors
    Discard = 11,
    /// Write zeroes
    WriteZeroes = 13,
}

/// VirtIO block request header
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BlockRequestHeader {
    pub request_type: u32,
    pub reserved: u32,
    pub sector: u64,
}

/// VirtIO block request status
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockStatus {
    Ok = 0,
    IoError = 1,
    Unsupported = 2,
}

/// Block device configuration space
#[repr(C)]
struct BlockConfig {
    capacity: u64,
    size_max: u32,
    seg_max: u32,
    geometry_cylinders: u16,
    geometry_heads: u8,
    geometry_sectors: u8,
    blk_size: u32,
    // ... other fields omitted for brevity
}

/// Block device trait (implemented by VirtIO-blk driver)
pub trait BlockDevice {
    /// Read sectors from the device
    fn read_sector(&self, sector: u64, buf: &mut [u8]) -> Result<(), BlockError>;
    /// Write sectors to the device
    fn write_sector(&self, sector: u64, buf: &[u8]) -> Result<(), BlockError>;
    /// Get the total number of sectors
    fn sector_count(&self) -> u64;
}

/// Block device errors
#[derive(Debug)]
pub enum BlockError {
    /// Device I/O error
    IoError,
    /// Invalid sector number
    InvalidSector,
    /// Buffer too small
    BufferTooSmall,
    /// Device not ready
    NotReady,
}

/// VirtIO Block Device driver
pub struct VirtioBlockDevice {
    device: VirtioDevice,
    queue: SpinLock<Virtqueue>,
    capacity: u64,
}

// Send and Sync are safe because we use SpinLocks
unsafe impl Send for VirtioBlockDevice {}
unsafe impl Sync for VirtioBlockDevice {}

impl VirtioBlockDevice {
    /// Initialize a VirtIO block device from a PCI device
    ///
    /// # Safety
    /// The PCI device must be a valid VirtIO block device
    pub unsafe fn new(pci_dev: PciDevice) -> Result<Self, &'static str> {
        log::info!("VirtIO-blk: Initializing device at {:?}", pci_dev.address);

        // Create VirtIO device
        let device = VirtioDevice::new(pci_dev)?;

        // Reset device
        device.reset();

        // Acknowledge device
        device.add_status(status::ACKNOWLEDGE as u8);

        // Indicate we know how to drive it
        device.add_status(status::DRIVER as u8);

        // Read and negotiate features
        let device_features = device.read_device_features();
        log::debug!("VirtIO-blk: Device features: 0x{:08x}", device_features);

        // We don't need any special features for basic operation yet
        let guest_features = 0;
        device.write_guest_features(guest_features);

        // Features OK
        device.add_status(status::FEATURES_OK as u8);

        // Verify features OK
        if device.get_status() & (status::FEATURES_OK as u8) == 0 {
            return Err("Device doesn't support our feature set");
        }

        // Create virtqueue (queue 0 is the request queue)
        let queue = Virtqueue::new(128)?;

        // Setup queue with device
        device.setup_queue(0, &queue);

        // Driver ready
        device.add_status(status::DRIVER_OK as u8);

        // Read device capacity from config space (offset 0 in device-specific config)
        // For legacy devices, device-specific config starts at offset 20 (after header)
        // Or strictly speaking, after common config.
        // Legacy VirtIO Header: 20 bytes.
        // Block Config starts at offset 20.
        let capacity_low = device.read_reg_u32(20);
        let capacity_high = device.read_reg_u32(24);
        let capacity = ((capacity_high as u64) << 32) | (capacity_low as u64);

        log::info!(
            "VirtIO-blk: Capacity: {} sectors ({} MB)",
            capacity,
            (capacity * SECTOR_SIZE as u64) / (1024 * 1024)
        );

        log::info!("VirtIO-blk: Device initialized successfully");

        Ok(Self {
            device,
            queue: SpinLock::new(queue),
            capacity,
        })
    }

    /// Submit a block request and wait for completion
    fn do_request(
        &self,
        request_type: RequestType,
        sector: u64,
        mut data_buf: Option<(&mut [u8], bool)>, // (buffer, is_write)
    ) -> Result<(), BlockError> {
        // Allocate request header and status byte
        // We use a single frame for both if possible, or small allocations?
        // To be safe and simple with the frame allocator, we'll alloc a frame.
        // In a real optimized driver, we would have a slab allocator or pre-allocated pool.

        let mut lock = get_allocator().lock();
        let allocator = lock.as_mut().ok_or(BlockError::NotReady)?;
        let metadata_frame = allocator.alloc_frame().map_err(|_| BlockError::NotReady)?;
        drop(lock);

        let metadata_phys = metadata_frame.start_address.as_u64();
        let metadata_virt = crate::memory::phys_to_virt(metadata_phys);
        let status_offset = mem::size_of::<BlockRequestHeader>() as u64;

        // Layout: [Header (16 bytes)] ... [Status (1 byte)]
        let header_ptr = metadata_virt as *mut BlockRequestHeader;
        let status_ptr = (metadata_virt + status_offset) as *mut u8;

        // Setup request header (CPU access → virtual address)
        unsafe {
            ptr::write(
                header_ptr,
                BlockRequestHeader {
                    request_type: request_type as u32,
                    reserved: 0,
                    sector,
                },
            );
            ptr::write(status_ptr, 0xFF); // Initialize with invalid status
        }

        // Build descriptor chain (DMA → physical addresses)
        let mut buffers = Vec::with_capacity(3);

        // 1. Header (Device Readable) — physical addr for DMA
        buffers.push((
            metadata_phys,
            mem::size_of::<BlockRequestHeader>() as u32,
            false,
        ));

        // 2. Data (Device Readable OR Writable)
        // If data_buf is provided
        let mut data_frame_info = None;

        if let Some((buf, is_write)) = data_buf.as_mut() {
            // We need a physically contiguous buffer for DMA
            // For now, we allocate a bounce buffer.
            // TODO: Support scatter-gather if the input buffer crosses page boundaries or isn't physical.

            let buf_size = buf.len();
            let buf_pages = (buf_size + 4095) / 4096;
            let buf_order = buf_pages.next_power_of_two().trailing_zeros() as u8;

            let mut lock = get_allocator().lock();
            let allocator = lock.as_mut().ok_or(BlockError::NotReady)?;
            let buf_frame = allocator.alloc(buf_order).map_err(|_| {
                allocator.free(metadata_frame, 0);
                BlockError::NotReady
            })?;
            drop(lock);

            let buf_phys = buf_frame.start_address.as_u64();
            let buf_virt = crate::memory::phys_to_virt(buf_phys);
            data_frame_info = Some((buf_frame, buf_order));

            // If WRITE (Out): Copy from source buf to DMA bounce buffer (CPU access → virtual)
            if *is_write {
                unsafe {
                    ptr::copy_nonoverlapping(buf.as_ptr(), buf_virt as *mut u8, buf_size);
                }
            }

            // `is_write` param tells us if we are writing TO disk.
            // Write to disk: device reads from memory (flags = 0)
            // Read from disk: device writes to memory (flags = WRITE)
            let device_writable = !*is_write;

            // DMA → physical address
            buffers.push((buf_phys, buf_size as u32, device_writable));
        }

        // 3. Status (Device Writable) — physical addr for DMA
        buffers.push((metadata_phys + status_offset, 1, true));

        // Submit request
        let mut queue = self.queue.lock();
        let token = match queue.add_buffer(&buffers) {
            Ok(t) => t,
            Err(_) => {
                drop(queue);
                // Cleanup
                let mut lock = get_allocator().lock();
                if let Some(allocator) = lock.as_mut() {
                    allocator.free(metadata_frame, 0);
                    if let Some((f, o)) = data_frame_info {
                        allocator.free(f, o);
                    }
                }
                return Err(BlockError::IoError);
            }
        };

        // Notify device
        if queue.should_notify() {
            self.device.notify_queue(0);
        }
        drop(queue);

        // Wait for completion (busy-poll for now).
        //
        // IMPORTANT:
        // Do not use HLT here. This path can run from syscall context where IF
        // may be masked, and HLT would deadlock the CPU.
        // TODO: replace with proper waitqueue + interrupt completion.
        loop {
            let mut queue = self.queue.lock();
            if queue.has_used() {
                // We don't check the token because we are single-threaded/blocking per device for now
                // But to be correct we should find OUR token.
                // virtio::common::Virtqueue::get_used currently pops the *next* used.
                // If there are multiple in flight, we might pop someone else's.
                // But here we are blocking, so only one in flight effectively.
                if let Some((used_token, _len)) = queue.get_used() {
                    if used_token == token {
                        break;
                    } else {
                        // This shouldn't happen in single-threaded blocking mode
                        // If it does, we just dropped someone else's completion.
                        log::warn!("VirtIO-blk: Received unexpected token {}", used_token);
                    }
                }
            }
            drop(queue);
            core::hint::spin_loop();
        }

        // Check status
        let status_byte = unsafe { ptr::read(status_ptr) };

        // Post-processing
        if let Some((buf, is_write)) = data_buf {
            if let Some((buf_frame, buf_order)) = data_frame_info {
                let buf_virt = crate::memory::phys_to_virt(buf_frame.start_address.as_u64());

                // If Read (In): Copy from DMA buf to destination buf (CPU access → virtual)
                if !is_write && status_byte == BlockStatus::Ok as u8 {
                    unsafe {
                        ptr::copy_nonoverlapping(
                            buf_virt as *const u8,
                            buf.as_mut_ptr(),
                            buf.len(),
                        );
                    }
                }

                // Free DMA buffer
                let mut lock = get_allocator().lock();
                if let Some(allocator) = lock.as_mut() {
                    allocator.free(buf_frame, buf_order);
                }
                // drop(lock) implied at end of scope but explicit drop is better if reused
                drop(lock);
            }
        }

        // Free metadata frame
        let mut lock = get_allocator().lock();
        if let Some(allocator) = lock.as_mut() {
            allocator.free(metadata_frame, 0);
        }
        drop(lock);

        if status_byte == BlockStatus::Ok as u8 {
            Ok(())
        } else {
            log::error!("VirtIO-blk: Request failed with status {}", status_byte);
            Err(BlockError::IoError)
        }
    }
}

impl BlockDevice for VirtioBlockDevice {
    fn read_sector(&self, sector: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        if sector >= self.capacity {
            return Err(BlockError::InvalidSector);
        }

        if buf.len() < SECTOR_SIZE {
            return Err(BlockError::BufferTooSmall);
        }

        self.do_request(RequestType::In, sector, Some((buf, false)))
    }

    fn write_sector(&self, sector: u64, buf: &[u8]) -> Result<(), BlockError> {
        if sector >= self.capacity {
            return Err(BlockError::InvalidSector);
        }

        if buf.len() < SECTOR_SIZE {
            return Err(BlockError::BufferTooSmall);
        }

        // Need mutable buffer for internal DMA operations signature (though we won't modify it if is_write=true)
        // Our do_request takes &mut [u8], so we need to either change do_request or cast.
        // It's safer to copy the input slice to a temp buffer if we needed to, but here do_request copies it to DMA anyway.
        // But do_request signature expects &mut [u8] because it handles both read and write.
        // We can just cast const to mut since we know we won't write to it if is_write=true.
        // Or better, let's fix do_request to take Option<(&mut [u8], Direction)>.
        // For now, let's do a safe copy to avoid unsafe hacks.

        let mut buf_copy = [0u8; SECTOR_SIZE];
        buf_copy[..SECTOR_SIZE].copy_from_slice(&buf[..SECTOR_SIZE]);

        self.do_request(RequestType::Out, sector, Some((&mut buf_copy, true)))
    }

    fn sector_count(&self) -> u64 {
        self.capacity
    }
}

/// Global VirtIO block device
static VIRTIO_BLOCK: SpinLock<Option<Box<VirtioBlockDevice>>> = SpinLock::new(None);

/// VirtIO block IRQ line (will be set during init)
static mut VIRTIO_BLOCK_IRQ: u8 = 0;

/// Initialize VirtIO block device
///
/// Scans PCI bus for VirtIO block devices and initializes the first one found.
pub fn init() {
    log::info!("VirtIO-blk: Scanning for devices...");

    // Find VirtIO block device
    let pci_dev = match pci::find_virtio_device(pci::device::VIRTIO_BLOCK) {
        Some(dev) => dev,
        None => {
            log::warn!("VirtIO-blk: No block device found");
            return;
        }
    };

    // Read interrupt line from PCI config
    let irq_line = pci_dev.read_config_u8(pci::config::INTERRUPT_LINE);

    // Initialize device
    match unsafe { VirtioBlockDevice::new(pci_dev) } {
        Ok(device) => {
            // Store IRQ line for interrupt handler
            unsafe {
                VIRTIO_BLOCK_IRQ = irq_line;
            }

            // Register device
            *VIRTIO_BLOCK.lock() = Some(Box::new(device));

            // Register IRQ handler in IDT
            crate::arch::x86_64::idt::register_virtio_block_irq(irq_line);

            log::info!("VirtIO-blk: Device initialized on IRQ {}", irq_line);
        }
        Err(e) => {
            log::error!("VirtIO-blk: Failed to initialize device: {}", e);
        }
    }
}

/// Handle VirtIO block device interrupt
///
/// Called from the IDT IRQ handler when the VirtIO device signals completion.
/// Acknowledges the interrupt and processes completed requests.
pub fn handle_interrupt() {
    // Acknowledge the interrupt at the device level
    let lock = VIRTIO_BLOCK.lock();
    if let Some(device) = lock.as_ref() {
        // Read ISR status to check if interrupt is for us
        let isr_status = device.device.read_isr_status();
        if isr_status != 0 {
            // Acknowledge the interrupt
            device.device.ack_interrupt();

            // Process completed requests (wake up waiting tasks)
            // For now, just log the interrupt
            log::trace!("VirtIO-blk: Interrupt handled (ISR={})", isr_status);
        }
    }
}

/// Get the global VirtIO block device
pub fn get_device() -> Option<&'static VirtioBlockDevice> {
    unsafe {
        let lock = VIRTIO_BLOCK.lock();
        if lock.is_some() {
            // This is slightly unsafe if the lock is dropped and the box is moved,
            // but the static Option is never cleared in this kernel.
            // A safer way is needed for production.
            let ptr = &**lock.as_ref().unwrap() as *const VirtioBlockDevice;
            Some(&*ptr)
        } else {
            None
        }
    }
}

/// Get the VirtIO block IRQ line
pub fn get_irq() -> u8 {
    unsafe { VIRTIO_BLOCK_IRQ }
}
