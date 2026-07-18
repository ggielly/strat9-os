//! VirtIO Block Device driver
//!
//! Provides disk I/O via VirtIO-blk protocol for QEMU/KVM environments.
//! Implements the BlockDevice trait for integration with filesystem layers.
//!
//! Reference: VirtIO spec v1.2, Section 5.2 (Block Device)

use crate::{
    arch::pci::{self, PciDevice},
    hardware::virtio::{
        common::{VirtioDevice, Virtqueue},
        status,
    },
    memory,
    sync::SpinLock,
};
use alloc::{boxed::Box, vec::Vec};
use core::{mem, ptr, sync::atomic::Ordering};

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
#[allow(dead_code)]
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

/// Block device trait (implemented by VirtIO-blk and AHCI drivers)
pub trait BlockDevice {
    /// Read a single sector from the device.
    fn read_sector(&self, sector: u64, buf: &mut [u8]) -> Result<(), BlockError>;

    /// Write a single sector to the device.
    fn write_sector(&self, sector: u64, buf: &[u8]) -> Result<(), BlockError>;

    /// Read multiple contiguous sectors in a single I/O operation.
    ///
    /// The default implementation falls back to calling `read_sector` in a loop.
    /// Drivers that support multi-sector commands (AHCI, NVMe, VirtIO with large
    /// descriptors) SHOULD override this for bulk throughput.
    fn read_sectors(&self, sector: u64, count: u16, buf: &mut [u8]) -> Result<(), BlockError> {
        let sector_size = SECTOR_SIZE;
        for i in 0..count as u64 {
            let off = (i as usize) * sector_size;
            if off + sector_size > buf.len() {
                return Err(BlockError::BufferTooSmall);
            }
            self.read_sector(sector + i, &mut buf[off..off + sector_size])?;
        }
        Ok(())
    }

    /// Write multiple contiguous sectors in a single I/O operation.
    ///
    /// The default implementation falls back to calling `write_sector` in a loop.
    /// Drivers that support multi-sector commands SHOULD override this.
    fn write_sectors(&self, sector: u64, count: u16, buf: &[u8]) -> Result<(), BlockError> {
        let sector_size = SECTOR_SIZE;
        for i in 0..count as u64 {
            let off = (i as usize) * sector_size;
            if off + sector_size > buf.len() {
                return Err(BlockError::BufferTooSmall);
            }
            self.write_sector(sector + i, &buf[off..off + sector_size])?;
        }
        Ok(())
    }

    /// Get the total number of sectors on the device.
    fn sector_count(&self) -> u64;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BlockError {
    #[error("device I/O error")]
    IoError,
    #[error("invalid sector number")]
    InvalidSector,
    #[error("buffer too small")]
    BufferTooSmall,
    #[error("device not ready")]
    NotReady,
}

/// Size of the pre-allocated bounce buffer pool (64 KB = 128 sectors).
/// Requests up to this size avoid per-I/O buddy allocator calls.
const BOUNCE_POOL_SIZE: usize = 64 * 1024;

/// Pre-allocated DMA buffer used for all data transfers.
///
/// Eliminates per-I/O frame allocation/free for the common case.
/// Large requests (> BOUNCE_POOL_SIZE) fall back to on-demand allocation.
struct BouncePool {
    frame: memory::PhysFrame,
    order: u8,
}

impl BouncePool {
    /// Allocate a single physically-contiguous bounce buffer.
    unsafe fn allocate() -> Result<Self, BlockError> {
        let pages = (BOUNCE_POOL_SIZE + 4095) / 4096;
        let order = pages.next_power_of_two().trailing_zeros() as u8;
        let frame =
            crate::sync::with_irqs_disabled(|token| memory::allocate_phys_contiguous(token, order))
                .map_err(|_| BlockError::NotReady)?;
        Ok(Self { frame, order })
    }

    fn phys(&self) -> u64 {
        self.frame.start_address.as_u64()
    }

    fn virt(&self) -> u64 {
        crate::memory::phys_to_virt(self.phys())
    }
}

impl Drop for BouncePool {
    fn drop(&mut self) {
        crate::sync::with_irqs_disabled(|token| {
            memory::free_phys_contiguous(token, self.frame, self.order);
        });
    }
}

/// Pre-allocated metadata frame: [Header (16 B)] + padding + [Status (1 B)].
/// Reused for every request — never alloc/freed per I/O.
struct MetaPool {
    frame: memory::PhysFrame,
}

impl MetaPool {
    unsafe fn allocate() -> Result<Self, BlockError> {
        let frame = crate::sync::with_irqs_disabled(|token| memory::allocate_frame(token))
            .map_err(|_| BlockError::NotReady)?;
        Ok(Self { frame })
    }

    fn phys(&self) -> u64 {
        self.frame.start_address.as_u64()
    }

    fn virt(&self) -> u64 {
        crate::memory::phys_to_virt(self.phys())
    }

    /// Layout offset for the status byte (right after the header).
    fn status_offset(&self) -> u64 {
        mem::size_of::<BlockRequestHeader>() as u64
    }
}

impl Drop for MetaPool {
    fn drop(&mut self) {
        crate::sync::with_irqs_disabled(|token| {
            memory::free_frame(token, self.frame);
        });
    }
}

/// VirtIO Block Device driver
pub struct VirtioBlockDevice {
    device: VirtioDevice,
    queue: SpinLock<Virtqueue>,
    capacity: u64,
    block_size: u32,
    /// Pre-allocated DMA resources — no per-I/O alloc/free for common requests.
    bounce_pool: BouncePool,
    meta_pool: MetaPool,
}

// Send and Sync are safe because we use SpinLocks
unsafe impl Send for VirtioBlockDevice {}
unsafe impl Sync for VirtioBlockDevice {}

/// WaitQueue used for IRQ-driven completion (see `handle_interrupt` / `do_request`).
static VIRTIO_BLK_WQ: crate::sync::WaitQueue = crate::sync::WaitQueue::new();

/// Atomic flag set by the IRQ handler to signal request completion.
static VIRTIO_BLK_DONE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Atomic flag set by the IRQ handler on error.
static VIRTIO_BLK_ERROR: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

impl VirtioBlockDevice {
    /// Initialize a VirtIO block device from a PCI device
    ///
    /// # Safety
    /// The PCI device must be a valid VirtIO block device
    pub unsafe fn new(pci_dev: PciDevice) -> Result<Self, &'static str> {
        log::info!("VirtIO-blk: Initializing device at {:?}", pci_dev.address);

        // Pre-allocate DMA resources before touching the device.
        let bounce_pool = BouncePool::allocate().map_err(|_| "Failed to allocate bounce pool")?;
        let meta_pool = MetaPool::allocate().map_err(|_| "Failed to allocate meta pool")?;

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

        // Negotiate useful block-device features (legacy PCI — all u32).
        //   VIRTIO_BLK_F_BLK_SIZE  (1 << 6)  — honour device block size
        //   VIRTIO_BLK_F_FLUSH     (1 << 9)  — write cache flush
        //   VIRTIO_F_RING_EVENT_IDX(1 << 29) — suppress needless notifications
        let dev_feat = device_features;
        let mut guest_features: u32 = 0;
        let has_blk_size = dev_feat & (1 << 6) != 0;
        if has_blk_size {
            guest_features |= 1 << 6;
        }
        if dev_feat & (1 << 9) != 0 {
            guest_features |= 1 << 9; // VIRTIO_BLK_F_FLUSH
        }
        if dev_feat & (1 << 29) != 0 {
            guest_features |= 1 << 29; // VIRTIO_F_RING_EVENT_IDX
        }
        log::info!("VirtIO-blk: Negotiated features: 0x{:08x}", guest_features);
        device.write_guest_features(guest_features);

        // Features OK
        device.add_status(status::FEATURES_OK as u8);

        // Verify features OK
        if device.get_status() & (status::FEATURES_OK as u8) == 0 {
            return Err("Device doesn't support our feature set");
        }

        // Legacy PCI VirtIO exposes a fixed queue size in QUEUE_NUM.
        // The vring layout must match exactly what the device expects.
        let queue_size = device.queue_max_size(0);
        if queue_size == 0 {
            return Err("VirtIO-blk queue 0 is unavailable");
        }
        log::info!("VirtIO-blk: queue 0 size = {}", queue_size);

        // Create virtqueue (queue 0 is the request queue)
        let queue = Virtqueue::new(queue_size)?;

        // Setup queue with device
        device.setup_queue(0, &queue);

        // Driver ready
        device.add_status(status::DRIVER_OK as u8);

        // Read device capacity from config space (offset 0 in device-specific config)
        // For legacy devices, device-specific config starts at offset 20 (after header)
        let capacity_low = device.read_reg_u32(20);
        let capacity_high = device.read_reg_u32(24);
        let capacity = ((capacity_high as u64) << 32) | (capacity_low as u64);

        // Read device block size if the feature was negotiated (offset 28).
        let blk_size = if has_blk_size {
            let sz = device.read_reg_u32(28);
            if sz == 0 {
                SECTOR_SIZE as u32
            } else {
                sz
            }
        } else {
            SECTOR_SIZE as u32
        };

        log::info!(
            "VirtIO-blk: Capacity: {} sectors ({} MB), block_size={}",
            capacity,
            (capacity * SECTOR_SIZE as u64) / (1024 * 1024),
            blk_size,
        );

        log::info!("VirtIO-blk: Device initialized successfully");

        Ok(Self {
            device,
            queue: SpinLock::new(queue),
            capacity,
            block_size: blk_size,
            bounce_pool,
            meta_pool,
        })
    }

    /// Determine the DMA buffer strategy: use the pre-allocated pool when the
    /// request fits; fall back to a per-I/O allocation for large transfers.
    fn acquire_dma_buffer(
        &self,
        buf_size: usize,
        is_write: bool,
        src: Option<&[u8]>,
    ) -> Result<(u64, u64, Option<(memory::PhysFrame, u8)>), BlockError> {
        if buf_size <= BOUNCE_POOL_SIZE {
            let phys = self.bounce_pool.phys();
            let virt = self.bounce_pool.virt();
            if is_write {
                if let Some(s) = src {
                    unsafe {
                        ptr::copy_nonoverlapping(s.as_ptr(), virt as *mut u8, buf_size);
                    }
                }
            }
            Ok((phys, virt, None))
        } else {
            // Large request: fall back to per-I/O allocation.
            let buf_pages = (buf_size + 4095) / 4096;
            let buf_order = buf_pages.next_power_of_two().trailing_zeros() as u8;
            let buf_frame = crate::sync::with_irqs_disabled(|token| {
                memory::allocate_phys_contiguous(token, buf_order)
            })
            .map_err(|_| BlockError::NotReady)?;
            let buf_phys = buf_frame.start_address.as_u64();
            let buf_virt = crate::memory::phys_to_virt(buf_phys);
            if is_write {
                if let Some(s) = src {
                    unsafe {
                        ptr::copy_nonoverlapping(s.as_ptr(), buf_virt as *mut u8, buf_size);
                    }
                }
            }
            Ok((buf_phys, buf_virt, Some((buf_frame, buf_order))))
        }
    }

    fn release_dma_buffer(&self, allocated: Option<(memory::PhysFrame, u8)>) {
        if let Some((frame, order)) = allocated {
            crate::sync::with_irqs_disabled(|token| {
                memory::free_phys_contiguous(token, frame, order);
            });
        }
    }

    /// Submit a block request and wait for completion
    fn do_request(
        &self,
        request_type: RequestType,
        sector: u64,
        mut data_buf: Option<(&mut [u8], bool)>, // (buffer, is_write)
    ) -> Result<(), BlockError> {
        // ── Metadata (pre-allocated, reused — no per-I/O alloc) ──────────
        let meta_phys = self.meta_pool.phys();
        let meta_virt = self.meta_pool.virt();
        let status_off = self.meta_pool.status_offset();

        let header_ptr = meta_virt as *mut BlockRequestHeader;
        let status_ptr = (meta_virt + status_off) as *mut u8;
        unsafe {
            ptr::write(
                header_ptr,
                BlockRequestHeader {
                    request_type: request_type as u32,
                    reserved: 0,
                    sector,
                },
            );
            ptr::write(status_ptr, 0xFF);
        }

        // ── Data buffer (pool → fallback alloc) ──────────────────────────
        let mut data_alloc: Option<(memory::PhysFrame, u8)> = None;
        let mut dma_buf_virt: u64 = 0;

        let mut buffers = Vec::with_capacity(3);
        buffers.push((
            meta_phys,
            mem::size_of::<BlockRequestHeader>() as u32,
            false,
        ));

        if let Some((buf, is_write)) = data_buf.as_mut() {
            let buf_size = buf.len();
            let (dma_phys, dma_virt, alloc) =
                self.acquire_dma_buffer(buf_size, *is_write, Some(buf))?;
            data_alloc = alloc;
            dma_buf_virt = dma_virt;

            let device_writable = !*is_write;
            buffers.push((dma_phys, buf_size as u32, device_writable));
        }

        // 3. Status (Device Writable)
        buffers.push((meta_phys + status_off, 1, true));

        // ── Submit ────────────────────────────────────────────────────────
        let mut queue = self.queue.lock();
        let token = match queue.add_buffer(&buffers) {
            Ok(t) => t,
            Err(e) => {
                drop(queue);
                self.release_dma_buffer(data_alloc);
                log::error!("VirtIO-blk: add_buffer failed: {}", e);
                return Err(BlockError::IoError);
            }
        };
        if queue.should_notify() {
            self.device.notify_queue(0);
        }
        drop(queue);

        // ── Completion ────────────────────────────────────────────────────
        let has_data = data_buf.is_some();

        if has_data && crate::process::current_task_id().is_some() {
            // Task context: IRQ-driven via WaitQueue (avoids busy-polling).
            VIRTIO_BLK_DONE.store(false, Ordering::Release);
            VIRTIO_BLK_ERROR.store(false, Ordering::Release);
            VIRTIO_BLK_WQ.wait_until(|| {
                if VIRTIO_BLK_DONE.load(Ordering::Acquire) {
                    VIRTIO_BLK_DONE.store(false, Ordering::Release);
                    Some(())
                } else {
                    None
                }
            });
            if VIRTIO_BLK_ERROR.load(Ordering::Acquire) {
                VIRTIO_BLK_ERROR.store(false, Ordering::Release);
                self.release_dma_buffer(data_alloc);
                return Err(BlockError::IoError);
            }
        } else {
            // Boot / no-task context: busy-poll.
            let mut spins = 0u32;
            loop {
                let q = self.queue.lock();
                if q.has_used() {
                    if let Some((t, _)) = q.peek_used() {
                        if t == token {
                            drop(q);
                            let mut q = self.queue.lock();
                            q.get_used();
                            break;
                        }
                    }
                    // Used entry exists but not ours — drop lock and retry.
                }
                drop(q);
                spins = spins.saturating_add(1);
                if spins >= 5_000_000 {
                    let isr = self.device.read_isr_status();
                    log::error!(
                        "VirtIO-blk: timeout sector={} token={} isr={}",
                        sector,
                        token,
                        isr
                    );
                    self.release_dma_buffer(data_alloc);
                    return Err(BlockError::IoError);
                }
                core::hint::spin_loop();
            }
        }

        // ── Post-processing ──────────────────────────────────────────────
        let status_byte = unsafe { ptr::read(status_ptr) };

        if let Some((buf, is_write)) = data_buf {
            if !is_write && status_byte == BlockStatus::Ok as u8 {
                unsafe {
                    ptr::copy_nonoverlapping(
                        dma_buf_virt as *const u8,
                        buf.as_mut_ptr(),
                        buf.len(),
                    );
                }
            }
        }

        self.release_dma_buffer(data_alloc);

        if status_byte == BlockStatus::Ok as u8 {
            Ok(())
        } else {
            log::error!("VirtIO-blk: Request failed with status {}", status_byte);
            Err(BlockError::IoError)
        }
    }
}

impl BlockDevice for VirtioBlockDevice {
    /// Reads sector.
    fn read_sector(&self, sector: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        if sector >= self.capacity {
            return Err(BlockError::InvalidSector);
        }
        if buf.len() < SECTOR_SIZE {
            return Err(BlockError::BufferTooSmall);
        }
        self.do_request(RequestType::In, sector, Some((buf, false)))
    }

    /// Writes sector.
    fn write_sector(&self, sector: u64, buf: &[u8]) -> Result<(), BlockError> {
        if sector >= self.capacity {
            return Err(BlockError::InvalidSector);
        }
        if buf.len() < SECTOR_SIZE {
            return Err(BlockError::BufferTooSmall);
        }
        // Use the writable alias path: do_request copies the data into the DMA
        // bounce buffer before issuing the command, so the const-to-mut cast is safe
        // (the buffer is never written from the CPU side during a write request).
        let buf_mut = buf.as_ptr() as *mut u8;
        let buf_slice = unsafe { core::slice::from_raw_parts_mut(buf_mut, buf.len()) };
        self.do_request(RequestType::Out, sector, Some((buf_slice, true)))
    }

    /// Read multiple sectors in a single I/O.
    ///
    /// VirtIO block uses a single descriptor whose length encodes the transfer
    /// size, so `do_request` naturally handles multi-sector transfers when given
    /// a large enough buffer.
    fn read_sectors(&self, sector: u64, count: u16, buf: &mut [u8]) -> Result<(), BlockError> {
        let nbytes = (count as usize) * SECTOR_SIZE;
        if sector.saturating_add(count as u64) > self.capacity {
            return Err(BlockError::InvalidSector);
        }
        if buf.len() < nbytes {
            return Err(BlockError::BufferTooSmall);
        }
        self.do_request(RequestType::In, sector, Some((buf, false)))
    }

    /// Write multiple sectors in a single I/O.
    fn write_sectors(&self, sector: u64, count: u16, buf: &[u8]) -> Result<(), BlockError> {
        let nbytes = (count as usize) * SECTOR_SIZE;
        if sector.saturating_add(count as u64) > self.capacity {
            return Err(BlockError::InvalidSector);
        }
        if buf.len() < nbytes {
            return Err(BlockError::BufferTooSmall);
        }
        let buf_mut = buf.as_ptr() as *mut u8;
        let buf_slice = unsafe { core::slice::from_raw_parts_mut(buf_mut, buf.len()) };
        self.do_request(RequestType::Out, sector, Some((buf_slice, true)))
    }

    /// Performs the sector count operation.
    fn sector_count(&self) -> u64 {
        self.capacity
    }
}

/// Global VirtIO block device reference (leaked Box, never freed).
static VIRTIO_BLOCK_PTR: core::sync::atomic::AtomicPtr<VirtioBlockDevice> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// VirtIO block IRQ line (will be set during init)
static VIRTIO_BLOCK_IRQ: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0xFF);

/// Initialize VirtIO block device
///
/// Scans PCI bus for VirtIO block devices and initializes the first one found.
pub fn init() {
    log::info!("VirtIO-blk: Scanning for devices...");

    // Prefer strict class-based probe (mass storage), with fallback to
    // vendor+device for odd firmware/virtual setups.
    let pci_dev = match pci::probe_first(pci::ProbeCriteria {
        vendor_id: Some(pci::vendor::VIRTIO),
        device_id: Some(pci::device::VIRTIO_BLOCK),
        class_code: Some(pci::class::MASS_STORAGE),
        subclass: None,
        prog_if: None,
    })
    .or_else(|| pci::find_virtio_device(pci::device::VIRTIO_BLOCK))
    {
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
            // Leak the Box to get a 'static reference — safe because the device
            // lives for the entire kernel lifetime.
            let leaked: &'static mut VirtioBlockDevice = Box::leak(Box::new(device));
            VIRTIO_BLOCK_PTR.store(leaked as *mut VirtioBlockDevice, Ordering::Release);
            VIRTIO_BLOCK_IRQ.store(irq_line, Ordering::Relaxed);

            // Register IRQ handler in IDT
            crate::arch::idt::register_virtio_block_irq(irq_line);

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
/// Acknowledges the interrupt and wakes any task waiting in `do_request`.
pub fn handle_interrupt() {
    let ptr = VIRTIO_BLOCK_PTR.load(Ordering::Acquire);
    if ptr.is_null() {
        return;
    }

    // SAFETY: ptr is a valid leaked Box that lives forever.
    let device = unsafe { &*ptr };

    let isr_status = device.device.read_isr_status();
    if isr_status == 0 {
        return; // spurious
    }

    // Acknowledge the interrupt (legacy PCI: reading ISR acks it).
    device.device.ack_interrupt();

    // Signal completion to the waiting task.
    // A real implementation would check which token(s) completed and signal
    // the correct ones. For the current single-in-flight design, we just
    // set the global flag and wake the first waiter.
    VIRTIO_BLK_DONE.store(true, Ordering::Release);

    // TODO: check task-file error status for proper VIRTIO_BLK_ERROR signalling.
    VIRTIO_BLK_WQ.wake_one();

    log::trace!("VirtIO-blk: Interrupt handled (ISR={})", isr_status);
}

/// Get the global VirtIO block device
///
/// Returns a `'static` reference that is valid for the entire kernel lifetime.
/// The device is initialised once during boot and never removed.
pub fn get_device() -> Option<&'static VirtioBlockDevice> {
    let ptr = VIRTIO_BLOCK_PTR.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        // SAFETY: ptr was obtained from Box::leak, so it is valid for 'static.
        Some(unsafe { &*ptr })
    }
}

/// Get the VirtIO block IRQ line
pub fn get_irq() -> u8 {
    VIRTIO_BLOCK_IRQ.load(Ordering::Relaxed)
}
