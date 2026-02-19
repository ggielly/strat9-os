//! Common VirtIO infrastructure
//!
//! Provides virtqueue management and device initialization logic
//! shared across all VirtIO drivers.
//!
//! Reference: VirtIO spec v1.2, Section 2 (Basic Facilities of a Virtio Device)
//! https://docs.oasis-open.org/virtio/virtio/v1.2/os/virtio-v1.2-os.html#_basic-facilities-of-a-virtio-device

use super::{vring_flags, VirtqDesc};
use crate::{
    arch::x86_64::pci::{Bar, PciDevice},
    memory::{get_allocator, FrameAllocator, PhysFrame},
};
use alloc::vec::Vec;
use core::{
    ptr::{read_volatile, write_volatile},
    sync::atomic::{fence, AtomicU16, Ordering},
};

/// VirtIO device features
pub mod features {
    pub const VIRTIO_F_RING_INDIRECT_DESC: u64 = 1 << 28;
    pub const VIRTIO_F_RING_EVENT_IDX: u64 = 1 << 29;
    pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;
    pub const VIRTIO_F_ACCESS_PLATFORM: u64 = 1 << 33;
    pub const VIRTIO_F_RING_PACKED: u64 = 1 << 34;
    pub const VIRTIO_F_IN_ORDER: u64 = 1 << 35;
    pub const VIRTIO_F_ORDER_PLATFORM: u64 = 1 << 36;
    pub const VIRTIO_F_SR_IOV: u64 = 1 << 37;
    pub const VIRTIO_F_NOTIFICATION_DATA: u64 = 1 << 38;
}

/// Available ring structure (device -> driver notifications)
#[repr(C)]
pub struct VirtqAvail {
    pub flags: AtomicU16,
    pub idx: AtomicU16,
    // ring follows (variable length)
    // used_event follows ring (if VIRTIO_F_RING_EVENT_IDX)
}

/// Used ring element
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VirtqUsedElem {
    /// Index of start of used descriptor chain
    pub id: u32,
    /// Total length of the descriptor chain
    pub len: u32,
}

/// Used ring structure (driver -> device notifications)
#[repr(C)]
pub struct VirtqUsed {
    pub flags: AtomicU16,
    pub idx: AtomicU16,
    // ring follows (variable length)
    // avail_event follows ring (if VIRTIO_F_RING_EVENT_IDX)
}

/// A VirtIO virtqueue
///
/// This structure manages the split virtqueue format as described in
/// VirtIO spec section 2.6 (Split Virtqueues).
pub struct Virtqueue {
    /// Queue size (must be power of 2)
    queue_size: u16,

    /// Physical address of descriptor table
    desc_area: PhysFrame,

    /// Physical address of available ring
    avail_area: PhysFrame,

    /// Physical address of used ring
    used_area: PhysFrame,

    /// Virtual address of descriptor table
    desc_ptr: *mut VirtqDesc,

    /// Virtual address of available ring
    avail_ptr: *mut VirtqAvail,

    /// Virtual address of available ring entries
    avail_ring_ptr: *mut u16,

    /// Virtual address of used ring
    used_ptr: *mut VirtqUsed,

    /// Virtual address of used ring entries
    used_ring_ptr: *mut VirtqUsedElem,

    /// Free descriptor list (indices of free descriptors)
    free_descriptors: Vec<u16>,

    /// Last seen used index
    last_used_idx: u16,

    /// Next available index
    next_avail_idx: u16,
}

// Send is safe because we manage synchronization via SpinLocks in usage
unsafe impl Send for Virtqueue {}

impl Virtqueue {
    /// Create a new virtqueue with the specified size
    ///
    /// # Safety
    /// The caller must ensure that the allocated memory is properly mapped
    /// and accessible.
    pub unsafe fn new(queue_size: u16) -> Result<Self, &'static str> {
        if !queue_size.is_power_of_two() {
            return Err("Queue size must be power of 2");
        }

        let mut lock = get_allocator().lock();
        let allocator = lock.as_mut().ok_or("Allocator not initialized")?;

        // Allocate descriptor table (16 bytes per descriptor)
        let desc_size = queue_size as usize * core::mem::size_of::<VirtqDesc>();
        let desc_pages = (desc_size + 4095) / 4096;
        let desc_order = desc_pages.next_power_of_two().trailing_zeros() as u8;
        let desc_area = allocator
            .alloc(desc_order)
            .map_err(|_| "Failed to allocate descriptor table")?;

        // Allocate available ring (2 + 2 + queue_size * 2 + 2 bytes)
        let avail_size = 4 + queue_size as usize * 2 + 2;
        let avail_pages = (avail_size + 4095) / 4096;
        let avail_order = avail_pages.next_power_of_two().trailing_zeros() as u8;
        let avail_area = allocator
            .alloc(avail_order)
            .map_err(|_| "Failed to allocate available ring")?;

        // Allocate used ring (2 + 2 + queue_size * 8 + 2 bytes)
        let used_size = 4 + queue_size as usize * core::mem::size_of::<VirtqUsedElem>() + 2;
        let used_pages = (used_size + 4095) / 4096;
        let used_order = used_pages.next_power_of_two().trailing_zeros() as u8;
        let used_area = allocator
            .alloc(used_order)
            .map_err(|_| "Failed to allocate used ring")?;

        drop(lock);

        // SAFETY: we just allocated these frames; convert phys => virt via HHDM
        // With Limine HHDM, all physical memory is already mapped, so we can
        // directly use phys_to_virt without additional page table modifications.
        // DO NOT call ensure_identity_map here - it can corrupt active page tables!

        let desc_virt = crate::memory::phys_to_virt(desc_area.start_address.as_u64());
        let avail_virt = crate::memory::phys_to_virt(avail_area.start_address.as_u64());
        let used_virt = crate::memory::phys_to_virt(used_area.start_address.as_u64());

        let desc_ptr = desc_virt as *mut VirtqDesc;
        let avail_ptr = avail_virt as *mut VirtqAvail;
        let avail_ring_ptr = (avail_virt + 4) as *mut u16;
        let used_ptr = used_virt as *mut VirtqUsed;
        let used_ring_ptr = (used_virt + 4) as *mut VirtqUsedElem;

        // Zero out the memory
        // SAFETY: we allocated these pages and they're mapped via HHDM
        // Each descriptor is 16 bytes, so we write queue_size * 16 bytes
        core::ptr::write_bytes(
            desc_ptr,
            0,
            queue_size as usize * core::mem::size_of::<VirtqDesc>(),
        );
        core::ptr::write_bytes(avail_ptr as *mut u8, 0, avail_size);
        core::ptr::write_bytes(used_ptr as *mut u8, 0, used_size);

        // Initialize free descriptor list
        let mut free_descriptors = Vec::with_capacity(queue_size as usize);
        for i in (0..queue_size).rev() {
            free_descriptors.push(i);
        }

        Ok(Self {
            queue_size,
            desc_area,
            avail_area,
            used_area,
            desc_ptr,
            avail_ptr,
            avail_ring_ptr,
            used_ptr,
            used_ring_ptr,
            free_descriptors,
            last_used_idx: 0,
            next_avail_idx: 0,
        })
    }

    /// Get the physical address of the descriptor table
    pub fn desc_area(&self) -> u64 {
        self.desc_area.start_address.as_u64()
    }

    /// Get the physical address of the available ring
    pub fn avail_area(&self) -> u64 {
        self.avail_area.start_address.as_u64()
    }

    /// Get the physical address of the used ring
    pub fn used_area(&self) -> u64 {
        self.used_area.start_address.as_u64()
    }

    /// Get the queue size
    pub fn size(&self) -> u16 {
        self.queue_size
    }

    /// Allocate a descriptor chain
    ///
    /// Returns the head descriptor index
    pub fn alloc_descriptor(&mut self) -> Option<u16> {
        self.free_descriptors.pop()
    }

    /// Free a descriptor chain
    ///
    /// Walks the chain following NEXT flags and frees all descriptors
    pub fn free_descriptor(&mut self, head: u16) {
        let mut current = head;

        loop {
            // SAFETY: current is a valid descriptor index
            let desc = unsafe { &*self.desc_ptr.add(current as usize) };
            let has_next = desc.flags & vring_flags::NEXT != 0;
            let next = desc.next;

            self.free_descriptors.push(current);

            if !has_next {
                break;
            }
            current = next;
        }
    }

    /// Add a buffer to the virtqueue
    ///
    /// Returns the descriptor index (token) that can be used to track completion
    ///
    /// # Arguments
    /// * `buffers`: A list of (physical_address, length, is_write_only)
    pub fn add_buffer(&mut self, buffers: &[(u64, u32, bool)]) -> Result<u16, &'static str> {
        if buffers.is_empty() {
            return Err("Empty buffer list");
        }

        if buffers.len() > self.free_descriptors.len() {
            return Err("Not enough free descriptors");
        }

        // Allocate descriptor chain
        let head = self.alloc_descriptor().ok_or("No free descriptors")?;
        let mut current = head;

        for (i, &(addr, len, write)) in buffers.iter().enumerate() {
            let is_last = i == buffers.len() - 1;

            // SAFETY: current is a valid index regulated by alloc_descriptor
            let desc = unsafe { &mut *self.desc_ptr.add(current as usize) };
            desc.addr = addr;
            desc.len = len;
            desc.flags = if write { vring_flags::WRITE } else { 0 };

            if !is_last {
                let next = self.alloc_descriptor().ok_or("No free descriptors")?;
                desc.flags |= vring_flags::NEXT;
                desc.next = next;
                current = next;
            }
        }

        // Add to available ring
        // SAFETY: Atomic load
        let avail_idx = unsafe { (*self.avail_ptr).idx.load(Ordering::Acquire) };
        let ring_idx = (avail_idx % self.queue_size) as usize;

        // SAFETY: ring_idx is bounded by queue_size
        unsafe {
            write_volatile(self.avail_ring_ptr.add(ring_idx), head);
        }

        // Memory barrier before updating index to ensure device sees the descriptor table updates
        fence(Ordering::Release);

        // Update available index
        // SAFETY: Atomic store
        unsafe {
            (*self.avail_ptr)
                .idx
                .store(avail_idx.wrapping_add(1), Ordering::Release);
        }

        self.next_avail_idx = avail_idx.wrapping_add(1);

        Ok(head)
    }

    /// Check if there are any used buffers
    pub fn has_used(&self) -> bool {
        // SAFETY: Atomic load
        let used_idx = unsafe { (*self.used_ptr).idx.load(Ordering::Acquire) };
        self.last_used_idx != used_idx
    }

    /// Get the next used buffer
    ///
    /// Returns (descriptor_index, length_written)
    pub fn get_used(&mut self) -> Option<(u16, u32)> {
        // SAFETY: Atomic load
        let used_idx = unsafe { (*self.used_ptr).idx.load(Ordering::Acquire) };

        if self.last_used_idx == used_idx {
            return None;
        }

        let ring_idx = (self.last_used_idx % self.queue_size) as usize;

        // SAFETY: ring_idx is bounded by queue_size
        let elem = unsafe { read_volatile(self.used_ring_ptr.add(ring_idx)) };

        self.last_used_idx = self.last_used_idx.wrapping_add(1);

        // We do NOT free the descriptor here immediately, because the caller might need to read the data.
        // But in the current design, the caller is responsible for freeing.
        // Wait, the previous implementation freed it here.
        // Let's stick to the previous pattern: free the chain, return the Head ID.
        // The implementation assumes the caller is done with the *descriptors*,
        // but the data is in the buffers pointed to by the descriptors.
        self.free_descriptor(elem.id as u16);

        Some((elem.id as u16, elem.len))
    }

    /// Notify the device (should write to queue_notify register)
    pub fn should_notify(&self) -> bool {
        // Simple implementation: always notify
        // Improved: Check VIRTQ_USED_F_NO_NOTIFY flag if we implemented negotiation
        true
    }
}

/// VirtIO device base
///
/// Common functionality for all VirtIO devices
pub struct VirtioDevice {
    /// PCI device
    pub pci_dev: PciDevice,

    /// I/O base address (BAR0 for legacy devices)
    pub io_base: u16,
}

impl VirtioDevice {
    /// Create a new VirtIO device from a PCI device
    ///
    /// # Safety
    /// The PCI device must be a valid VirtIO device
    pub unsafe fn new(pci_dev: PciDevice) -> Result<Self, &'static str> {
        // Read BAR0 (I/O space for legacy VirtIO devices)
        let bar0 = pci_dev.read_bar(0).ok_or("BAR0 not present")?;

        let io_base = match bar0 {
            Bar::Io { port } => port,
            _ => return Err("BAR0 is not I/O space (legacy VirtIO required)"),
        };

        // Enable I/O space and bus mastering
        pci_dev.enable_io_space();
        pci_dev.enable_bus_master();

        Ok(Self { pci_dev, io_base })
    }

    /// Read an 8-bit value from a device register
    pub fn read_reg_u8(&self, offset: u16) -> u8 {
        // SAFETY: I/O port access to VirtIO device registers
        unsafe { crate::arch::x86_64::io::inb(self.io_base + offset) }
    }

    /// Read a 16-bit value from a device register
    pub fn read_reg_u16(&self, offset: u16) -> u16 {
        // SAFETY: I/O port access to VirtIO device registers
        unsafe { crate::arch::x86_64::io::inw(self.io_base + offset) }
    }

    /// Read a 32-bit value from a device register
    pub fn read_reg_u32(&self, offset: u16) -> u32 {
        // SAFETY: I/O port access to VirtIO device registers
        unsafe { crate::arch::x86_64::io::inl(self.io_base + offset) }
    }

    /// Write an 8-bit value to a device register
    pub fn write_reg_u8(&self, offset: u16, value: u8) {
        // SAFETY: I/O port access to VirtIO device registers
        unsafe { crate::arch::x86_64::io::outb(self.io_base + offset, value) }
    }

    /// Write a 16-bit value to a device register
    pub fn write_reg_u16(&self, offset: u16, value: u16) {
        // SAFETY: I/O port access to VirtIO device registers
        unsafe { crate::arch::x86_64::io::outw(self.io_base + offset, value) }
    }

    /// Write a 32-bit value to a device register
    pub fn write_reg_u32(&self, offset: u16, value: u32) {
        // SAFETY: I/O port access to VirtIO device registers
        unsafe { crate::arch::x86_64::io::outl(self.io_base + offset, value) }
    }

    /// Read device features
    pub fn read_device_features(&self) -> u32 {
        self.read_reg_u32(0) // VIRTIO_PCI_HOST_FEATURES
    }

    /// Write guest features
    pub fn write_guest_features(&self, features: u32) {
        self.write_reg_u32(4, features); // VIRTIO_PCI_GUEST_FEATURES
    }

    /// Get device status
    pub fn get_status(&self) -> u8 {
        self.read_reg_u8(18) // VIRTIO_PCI_STATUS
    }

    /// Set device status
    pub fn set_status(&self, status: u8) {
        self.write_reg_u8(18, status); // VIRTIO_PCI_STATUS
    }

    /// Add status flags
    pub fn add_status(&self, status: u8) {
        let current = self.get_status();
        self.set_status(current | status);
    }

    /// Reset the device
    pub fn reset(&self) {
        self.set_status(0);
    }

    /// Read ISR status (clears interrupt)
    pub fn read_isr_status(&self) -> u8 {
        self.read_reg_u8(19) // VIRTIO_PCI_ISR
    }

    /// Acknowledge interrupt (write 0 to ISR)
    pub fn ack_interrupt(&self) {
        // Reading ISR already clears it, but we can also write to acknowledge
        let _ = self.read_reg_u8(19); // VIRTIO_PCI_ISR
    }

    /// Setup a virtqueue
    pub fn setup_queue(&self, queue_index: u16, queue: &Virtqueue) {
        // Select queue
        self.write_reg_u16(14, queue_index); // VIRTIO_PCI_QUEUE_SEL

        // Set queue size
        self.write_reg_u16(12, queue.size()); // VIRTIO_PCI_QUEUE_NUM

        // Set queue addresses (page-aligned physical addresses >> 12)
        let desc_pfn = (queue.desc_area() >> 12) as u32;
        self.write_reg_u32(8, desc_pfn); // VIRTIO_PCI_QUEUE_PFN
    }

    /// Notify a queue
    pub fn notify_queue(&self, queue_index: u16) {
        self.write_reg_u16(16, queue_index); // VIRTIO_PCI_QUEUE_NOTIFY
    }
}
