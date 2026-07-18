//! VirtIO block device driver for boot partition access.
//!
//! Minimal read-only driver for reading modules from the FAT32 boot partition.
//! Supports VirtIO MMIO transport (common on RISC-V/ARM64 QEMU) with a
//! working virtqueue-based block read implementation.
//!
//! Uses the kernel frame allocator (available after buddy init) to allocate
//! physically-contiguous vring and bounce-buffer memory.

use super::block_device::BlockDevice;

// ── Legacy VirtIO MMIO register offsets ────────────────────────────────
const REG_DEVICE_FEATURES: u64 = 0x000;
const REG_DRIVER_FEATURES: u64 = 0x008;
const REG_QUEUE_SEL: u64 = 0x010;
const REG_QUEUE_NUM_MAX: u64 = 0x014;
const REG_QUEUE_NUM: u64 = 0x018;
const REG_QUEUE_ALIGN: u64 = 0x01C;
const REG_QUEUE_PFN: u64 = 0x020;
const REG_QUEUE_NOTIFY: u64 = 0x024;
const REG_STATUS: u64 = 0x030;
const REG_CAPACITY: u64 = 0x100;

// ── VirtIO device status flags ─────────────────────────────────────────
const STATUS_ACK: u32 = 0x01;
const STATUS_DRIVER: u32 = 0x02;
const STATUS_FEATURES_OK: u32 = 0x08;
const STATUS_DRIVER_OK: u32 = 0x04;
const STATUS_FAILED: u32 = 0x80;

// ── VRING descriptor flags ────────────────────────────────────────────
const VRING_DESC_F_NEXT: u16 = 0x01;
const VRING_DESC_F_WRITE: u16 = 0x02;

// ── Block request types ───────────────────────────────────────────────
const REQ_TYPE_IN: u32 = 0;

// ── Queue configuration ───────────────────────────────────────────────
/// Small queue size is enough for single-block boot reads (header+data+status = 3 descs).
const BOOT_QUEUE_SIZE: u16 = 8;

/// VirtIO block request header (must match device layout exactly).
#[repr(C)]
struct BootBlockHeader {
    request_type: u32,
    reserved: u32,
    sector: u64,
}

/// VirtIO block request status byte.
#[repr(u8)]
#[derive(PartialEq, Eq)]
enum BootBlockStatus {
    Ok = 0,
    Error = 1,
    Unsupported = 2,
}

/// VRING descriptor (16 bytes).
#[repr(C)]
struct VringDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

/// Available ring header (followed by `queue_size` u16 ring entries + optional used_event).
#[repr(C)]
struct VringAvail {
    flags: u16,
    idx: u16,
    // ring: [u16; queue_size],
    // used_event: u16 (if VIRTIO_F_EVENT_IDX)
}

/// Used ring element (8 bytes).
#[repr(C)]
struct VringUsedElem {
    id: u32,
    len: u32,
}

/// Used ring header (followed by `queue_size` VringUsedElem entries + optional avail_event).
#[repr(C)]
struct VringUsed {
    flags: u16,
    idx: u16,
    // ring: [VringUsedElem; queue_size],
    // avail_event: u16 (if VIRTIO_F_EVENT_IDX)
}

/// Minimal boot-time virtqueue with a static vring allocation.
///
/// Legacy MMIO layout requires the vring to occupy physically-contiguous
/// pages with the three sections page-aligned:
///   ┌─ Page 0: descriptor table (page-aligned)
///   ├─ Page 1: available ring    (page-aligned)
///   └─ Page 2: used ring         (tail, may share page 3)
struct BootVirtqueue {
    /// Physical address of the vring base (written to QueuePFN >> 12).
    vring_phys: u64,
    /// Virtual (HHDM) address of the vring base.
    vring_virt: u64,
    /// Queue size.
    queue_size: u16,
    /// Next available index.
    avail_idx: u16,
    /// Last observed used index.
    last_used_idx: u16,
}

impl BootVirtqueue {
    /// Allocate and initialise a boot-time virtqueue.
    ///
    /// # Safety
    /// `device_base` must be a valid MMIO VirtIO device address.
    unsafe fn init(device_base: u64, queue_size: u16) -> Result<Self, &'static str> {
        if !queue_size.is_power_of_two() {
            return Err("Boot virtqueue size must be power of 2");
        }

        let desc_size = queue_size as usize * core::mem::size_of::<VringDesc>();
        let avail_size = core::mem::size_of::<VringAvail>() + queue_size as usize * 2;
        let used_elem_size = core::mem::size_of::<VringUsedElem>();
        let used_size = core::mem::size_of::<VringUsed>() + queue_size as usize * used_elem_size;

        let page_size: usize = 4096;
        let avail_offset = (desc_size + page_size - 1) / page_size * page_size;
        let used_offset = (avail_offset + avail_size + page_size - 1) / page_size * page_size;
        let total_size = used_offset + used_size;
        let total_pages = (total_size + page_size - 1) / page_size;
        let order = total_pages.next_power_of_two().trailing_zeros() as u8;

        // Allocate physically-contiguous pages for the vring.
        let frame = crate::sync::with_irqs_disabled(|token| {
            crate::memory::allocate_phys_contiguous(token, order)
        })
        .map_err(|_| "Failed to allocate boot vring")?;

        let vring_phys = frame.start_address.as_u64();
        let vring_virt = crate::memory::phys_to_virt(vring_phys);

        // Zero the whole region.
        core::ptr::write_bytes(vring_virt as *mut u8, 0, total_size);

        // Select queue 0.
        core::ptr::write_volatile((device_base + REG_QUEUE_SEL) as *mut u32, 0);

        // Write queue size.
        core::ptr::write_volatile((device_base + REG_QUEUE_NUM) as *mut u32, queue_size as u32);

        // Write queue alignment (legacy MMIO).
        core::ptr::write_volatile(
            (device_base + REG_QUEUE_ALIGN) as *mut u32,
            page_size as u32,
        );

        // Write PFN = phys_addr >> 12.
        let pfn = (vring_phys >> 12) as u32;
        core::ptr::write_volatile((device_base + REG_QUEUE_PFN) as *mut u32, pfn);

        Ok(Self {
            vring_phys,
            vring_virt,
            queue_size,
            avail_idx: 0,
            last_used_idx: 0,
        })
    }

    /// Submit a single-block read request and busy-poll for completion.
    ///
    /// Uses a 3-descriptor chain: header (device-read) | data (device-write) | status (device-write).
    ///
    /// # Safety
    /// `device_base` must be a valid MMIO VirtIO device address.
    unsafe fn read_block(
        &mut self,
        device_base: u64,
        lba: u64,
        bounce_phys: u64,
        bounce_virt: u64,
        buf: &mut [u8],
    ) -> Result<(), ()> {
        let qs = self.queue_size as usize;
        let desc_off = 0;
        let avail_off = ((qs * core::mem::size_of::<VringDesc>()) + 4095) / 4096 * 4096;
        let used_off =
            ((avail_off + core::mem::size_of::<VringAvail>() + qs * 2) + 4095) / 4096 * 4096;

        let desc_ptr = (self.vring_virt + desc_off) as *mut VringDesc;
        let avail_ptr = (self.vring_virt + avail_off) as *mut VringAvail;
        let used_ptr = (self.vring_virt + used_off) as *mut VringUsed;

        // Write header into the bounce buffer (first 16 bytes).
        let header_ptr = bounce_virt as *mut BootBlockHeader;
        core::ptr::write(
            header_ptr,
            BootBlockHeader {
                request_type: REQ_TYPE_IN,
                reserved: 0,
                sector: lba,
            },
        );

        // Status byte at the end of the bounce buffer (past the data region).
        let data_len = buf.len() as u32;
        let status_off = data_len as u64; // status follows data in the same frame
        let status_ptr = (bounce_virt + status_off) as *mut u8;
        core::ptr::write(status_ptr, 0xFF);

        // Descriptor 0: header (device-read, 16 bytes)
        core::ptr::write(
            desc_ptr,
            VringDesc {
                addr: bounce_phys,
                len: core::mem::size_of::<BootBlockHeader>() as u32,
                flags: VRING_DESC_F_NEXT,
                next: 1,
            },
        );
        // Descriptor 1: data (device-write)
        core::ptr::write(
            desc_ptr.add(1),
            VringDesc {
                addr: bounce_phys + core::mem::size_of::<BootBlockHeader>() as u64,
                len: data_len,
                flags: VRING_DESC_F_NEXT | VRING_DESC_F_WRITE,
                next: 2,
            },
        );
        // Descriptor 2: status (device-write, 1 byte)
        core::ptr::write(
            desc_ptr.add(2),
            VringDesc {
                addr: bounce_phys + status_off,
                len: 1,
                flags: VRING_DESC_F_WRITE,
                next: 0,
            },
        );

        // Place head index into the available ring.
        let avail_ring_ptr =
            (self.vring_virt + avail_off + core::mem::size_of::<VringAvail>() as u64) as *mut u16;
        let avail_slot = (self.avail_idx as usize) % qs;
        core::ptr::write(avail_ring_ptr.add(avail_slot), 0u16); // head descriptor index

        // Update avail index with a write barrier.
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        core::ptr::write(&mut (*avail_ptr).idx, self.avail_idx.wrapping_add(1));
        self.avail_idx = self.avail_idx.wrapping_add(1);

        // Notify the device.
        core::ptr::write_volatile((device_base + REG_QUEUE_NOTIFY) as *mut u32, 0u32);

        // Busy-poll for completion (boot context — no IRQs, no scheduler).
        let mut spins = 0u32;
        loop {
            let used_idx = core::ptr::read_volatile(&(*used_ptr).idx);
            if self.last_used_idx != used_idx {
                let used_ring_ptr =
                    (self.vring_virt + used_off + core::mem::size_of::<VringUsed>() as u64)
                        as *mut VringUsedElem;
                let slot = (self.last_used_idx as usize) % qs;
                let _elem = core::ptr::read_volatile(used_ring_ptr.add(slot));
                self.last_used_idx = self.last_used_idx.wrapping_add(1);
                break;
            }
            spins = spins.saturating_add(1);
            if spins >= 5_000_000 {
                crate::serial_println!("[virtio-blk] boot read timeout lba={:#x}", lba);
                return Err(());
            }
            core::hint::spin_loop();
        }

        // Check status.
        let status = core::ptr::read(status_ptr);
        if status != BootBlockStatus::Ok as u8 {
            return Err(());
        }

        // Copy data from bounce buffer to final buffer.
        let src = (bounce_virt + core::mem::size_of::<BootBlockHeader>() as u64) as *const u8;
        core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), data_len as usize);

        Ok(())
    }
}

impl Drop for BootVirtqueue {
    fn drop(&mut self) {
        // The vring frames are leaked for now (kernel lifetime).
        // In a production kernel we would track the frame and free it.
    }
}

/// VirtIO block device (boot-time MMIO transport)
pub struct VirtioBlkDevice {
    /// Base address of the device registers (MMIO BAR)
    base_addr: u64,
    /// Block size in bytes
    block_size: u64,
    /// Device features
    features: u32,
    /// Boot-time virtqueue
    queue: Option<BootVirtqueue>,
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
            queue: None,
        }
    }

    /// Initialize the VirtIO block device.
    ///
    /// # Safety
    ///
    /// Must only be called once with a valid device address.
    pub unsafe fn init(&mut self) -> Result<(), &'static str> {
        crate::serial_println!("[virtio-blk] Initializing at {:#x}", self.base_addr);

        // Reset device
        let status = self.read_status();
        crate::serial_println!("[virtio-blk] Device status: {:#x}", status);
        self.write_status(0);

        // Acknowledge + DRIVER
        self.add_status(STATUS_ACK);
        self.add_status(STATUS_DRIVER);

        // Read device features
        self.features = self.read_device_features();
        crate::serial_println!("[virtio-blk] Features: {:#x}", self.features);

        // We do not need special features; write 0 (but negotiate version 1 if available).
        // For now, pass-through: accept device defaults.
        if self.features & (1 << 32) != 0 {
            // VIRTIO_F_VERSION_1 — device supports modern interface.
            // Legacy MMIO works either way.
        }
        self.write_driver_features(0);

        // FEATURES_OK
        self.add_status(STATUS_FEATURES_OK);
        if self.read_status() & STATUS_FEATURES_OK == 0 {
            return Err("Device rejected feature negotiation");
        }

        // Read capacity from device config.
        let capacity_lo = core::ptr::read_volatile((self.base_addr + REG_CAPACITY) as *const u32);
        let capacity_hi =
            core::ptr::read_volatile((self.base_addr + REG_CAPACITY + 4) as *const u32);
        let capacity = ((capacity_hi as u64) << 32) | (capacity_lo as u64);
        crate::serial_println!("[virtio-blk] Capacity: {} blocks", capacity);

        // Set up the boot virtqueue (must be before DRIVER_OK per spec).
        let queue = BootVirtqueue::init(self.base_addr, BOOT_QUEUE_SIZE)?;
        self.queue = Some(queue);

        // DRIVER_OK
        self.add_status(STATUS_DRIVER_OK);

        crate::serial_println!("[virtio-blk] Initialized successfully");
        Ok(())
    }

    unsafe fn read_status(&self) -> u32 {
        core::ptr::read_volatile((self.base_addr + REG_STATUS) as *const u32)
    }

    unsafe fn write_status(&self, val: u32) {
        core::ptr::write_volatile((self.base_addr + REG_STATUS) as *mut u32, val);
    }

    unsafe fn add_status(&self, bit: u32) {
        let s = self.read_status();
        self.write_status(s | bit);
    }

    unsafe fn read_device_features(&self) -> u32 {
        core::ptr::read_volatile((self.base_addr + REG_DEVICE_FEATURES) as *const u32)
    }

    unsafe fn write_driver_features(&self, features: u32) {
        core::ptr::write_volatile((self.base_addr + REG_DRIVER_FEATURES) as *mut u32, features);
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
        let queue = self.queue.as_mut().ok_or(())?;
        let block_sz = self.block_size as usize;

        // Allocate a bounce frame (header + data + status fit in one 4K page).
        let bounce_frame =
            crate::sync::with_irqs_disabled(|token| crate::memory::allocate_frame(token))
                .map_err(|_| ())?;
        let bounce_phys = bounce_frame.start_address.as_u64();
        let bounce_virt = crate::memory::phys_to_virt(bounce_phys);

        let result =
            unsafe { queue.read_block(self.base_addr, lba, bounce_phys, bounce_virt, buf) };

        crate::sync::with_irqs_disabled(|token| {
            crate::memory::free_frame(token, bounce_frame);
        });

        result
    }

    fn block_size(&self) -> u64 {
        self.block_size
    }
}
