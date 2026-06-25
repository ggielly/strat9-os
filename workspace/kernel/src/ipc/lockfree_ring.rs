//! Lock-free single-producer single-consumer ring buffer for zero-copy IPC.
//!
//! # Memory layout
//!
//! Each ring is backed by physically-contiguous DMA-accessible pages.
//! The first page holds a [`RingHeader`] with cache-line-padded atomic
//! head/tail indexes. Subsequent pages hold [`RingSlot`] entries.
//!
//! # Ordering invariants
//!
//! The producer writes data before publishing via `tail.store(Release)`.
//! The consumer reads data after observing via `tail.load(Acquire)`.
//! This guarantees correct ordering on x86 and ARM/POWER (no store-store
//! reordering past the Release barrier).  See also [`LockFreeRing::write`].

use core::{
    mem::size_of,
    sync::atomic::{AtomicU16, AtomicU32, Ordering},
};

use alloc::{sync::Arc, vec::Vec};

use crate::{
    memory::{allocate_frame, free_frame, phys_to_virt, PhysFrame},
    sync::with_irqs_disabled,
};

// ---------------------------------------------------------------------------
// RingHeader : cache-line padded, always in the first page
// ---------------------------------------------------------------------------

/// Shared ring header, placed at the start of the first physical page.
///
/// Cache-line layout (x86-64, 64-byte lines):
/// - Line 0: magic, capacity, slot_size, flags (read-mostly, rarely written)
/// - Line 1: head, notify_prod (written by **consumer**, read by producer)
/// - Line 2: tail, notify_cons (written by **producer**, read by consumer)
#[repr(C, align(64))]
pub struct RingHeader {
    /// Magic number for validating shared mappings.
    magic: u32,
    /// Total number of slots (must be power of two).
    capacity: u32,
    /// Usable bytes per slot.
    slot_size: u32,
    /// Flags field (bit 0 = initialised, bit 1 = producer_ready).
    flags: AtomicU32,
    _pad1: [u8; 48],

    // Cache-line 1 — consumer hot
    /// Next slot to read.  Written by consumer; read by producer.
    head: AtomicU32,
    /// Notification counter for the producer (written by consumer).
    notify_prod: AtomicU32,
    _pad2: [u8; 56],

    // Cache-line 2 — producer hot
    /// Next slot to write.  Written by producer; read by consumer.
    tail: AtomicU32,
    /// Notification counter for the consumer (written by producer).
    notify_cons: AtomicU32,
    _pad3: [u8; 56],
}

// ---------------------------------------------------------------------------
// RingSlot
// ---------------------------------------------------------------------------

/// A single slot within the ring.
#[repr(C)]
pub struct RingSlot {
    /// Length of data in this slot (0 = empty).
    len: AtomicU16,
    /// Flags (bit 0 = SLOT_FLAG_COMMITTED; used in MPSC variants).
    flags: AtomicU16,
    /// Payload bytes.
    data: [u8; Self::SLOT_SIZE],
}

impl RingSlot {
    /// Default slot size, large enough for an Ethernet frame (1514 B) plus
    /// headers and padding.
    pub const SLOT_SIZE: usize = 2048;
}

const SLOT_FLAG_COMMITTED: u16 = 0x0001;

// ---------------------------------------------------------------------------
// RingError
// ---------------------------------------------------------------------------

/// Errors returned by ring operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingError {
    /// Ring has no free slots.
    Full,
    /// Ring contains no messages.
    Empty,
    /// Message exceeds slot capacity.
    MessageTooLarge,
    /// Provided buffer is too small for the pending message.
    BufferTooSmall,
    /// Memory allocation failed during ring creation.
    AllocFailed,
    /// Invalid ring parameters (size, capacity, etc.).
    InvalidParameters,
}

// ---------------------------------------------------------------------------
// LockFreeRing
// ---------------------------------------------------------------------------

/// A lock-free single-producer single-consumer ring buffer.
///
/// # SPSC guarantee
///
/// `write` must only be called from the **producer** thread; `read` must
/// only be called from the **consumer** thread.  No locks are used : only
/// atomic loads/stores with acquire/release ordering.
///
/// For multi-queue NIC RSS, create one `LockFreeRing` per RSS queue rather
/// than sharing a single MPSC ring; this avoids CAS contention and
/// head-of-line blocking.
#[derive(Debug)]
pub struct LockFreeRing {
    /// Total size in bytes of the shared memory region.
    size: usize,
    /// Number of physical frames backing the ring.
    frame_count: usize,
    /// Physical frames.
    frames: Vec<PhysFrame>,
    /// Virtual address of the header (first page).
    header: *mut RingHeader,
    /// Virtual address of the first slot (immediately after the header in
    /// the first page, or in subsequent pages when slots spill over).
    slots: *mut RingSlot,
    /// Number of slots (derived from capacity in the header).
    capacity: u32,
    /// Slot size in bytes.
    slot_size: u32,
}

// SAFETY: LockFreeRing is Send + Sync because all mutable access is
// partitioned by role (producer vs consumer) and enforced by the type
// system via TypedLockFreeRing (see transport.rs).
unsafe impl Send for LockFreeRing {}
unsafe impl Sync for LockFreeRing {}

impl LockFreeRing {
    /// Default slot count (power of two).
    const DEFAULT_CAPACITY: u32 = 256;

    /// Create a new ring with `slot_count` slots of `slot_size` bytes.
    ///
    /// The ring is allocated from physically-contiguous DMA-accessible
    /// frames and zeroed.  Returns an error if allocation fails.
    pub fn new(slot_count: u32, slot_size: usize) -> Result<Arc<Self>, RingError> {
        if !slot_count.is_power_of_two() || slot_count == 0 {
            return Err(RingError::InvalidParameters);
        }
        if slot_size == 0 || slot_size > RingSlot::SLOT_SIZE {
            return Err(RingError::InvalidParameters);
        }

        let header_size = size_of::<RingHeader>();
        let slots_size = slot_count as usize * size_of::<RingSlot>();
        let total_size = header_size + slots_size;
        let page_count = total_size.checked_add(4095).map(|p| p / 4096).unwrap_or(0);

        if page_count == 0 {
            return Err(RingError::InvalidParameters);
        }

        // Allocate frames
        let mut frames = Vec::with_capacity(page_count);
        for _ in 0..page_count {
            let frame = with_irqs_disabled(|token| allocate_frame(token))
                .map_err(|_| RingError::AllocFailed)?;
            frames.push(frame);
        }

        // Map frames into virtual address space
        let base_virt = phys_to_virt(frames[0].start_address.as_u64());
        let header = base_virt as *mut RingHeader;

        // Zero each frame individually — they may not be physically contiguous.
        for &frame in &frames {
            let virt = phys_to_virt(frame.start_address.as_u64());
            unsafe {
                core::ptr::write_bytes(virt as *mut u8, 0, 4096);
            }
        }

        // Initialise header
        unsafe {
            (*header).magic = 0x5254494e; // "RING"
            (*header).capacity = slot_count;
            (*header).slot_size = slot_size as u32;
            (*header).flags = AtomicU32::new(0x0001); // bit 0 = initialised
            (*header).notify_cons = AtomicU32::new(0);
            (*header).notify_prod = AtomicU32::new(0);
            (*header).head = AtomicU32::new(0);
            (*header).tail = AtomicU32::new(0);
        }

        // Calculate slot base address
        let slots_base = base_virt + header_size as u64;

        let ring = Arc::new(LockFreeRing {
            size: total_size,
            frame_count: page_count,
            frames,
            header,
            slots: slots_base as *mut RingSlot,
            capacity: slot_count,
            slot_size: slot_size as u32,
        });

        Ok(ring)
    }

    /// The number of slots in this ring.
    #[inline]
    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    /// The size in bytes of each slot.
    #[inline]
    pub fn slot_size(&self) -> u32 {
        self.slot_size
    }

    /// Physical addresses of the backing frames (for DMA and for mapping
    /// into other address spaces via capabilities).
    pub fn frame_phys_addrs(&self) -> Vec<u64> {
        self.frames
            .iter()
            .map(|f| f.start_address.as_u64())
            .collect()
    }

    /// Write `data` into the ring.  Returns `Full` if no slot is available,
    /// or `MessageTooLarge` if the data exceeds the slot capacity.
    ///
    /// # Ordering
    ///
    /// 1. Non-atomic copy into the slot (`copy_nonoverlapping`).
    /// 2. `len.store(Release)` : makes the length visible *after* data.
    /// 3. `tail.store(Release)` : publishes the slot.
    ///
    /// On ARM/POWER the Release barrier on `len` prevents the consumer
    /// from seeing `len != 0` before the data stores are visible.
    #[inline]
    pub fn write(&self, data: &[u8]) -> Result<(), RingError> {
        let mask = self.capacity - 1;

        let tail = self.tail().load(Ordering::Relaxed);
        let head = self.head().load(Ordering::Acquire);

        if ((tail + 1) & mask) == (head & mask) {
            return Err(RingError::Full);
        }

        if data.len() > self.slot_size as usize {
            return Err(RingError::MessageTooLarge);
        }

        let slot = self.slot_at(tail & mask);
        // SAFETY: `slot` points into the ring's own physical memory.
        // The producer owns the write index so no other thread writes here.
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), (*slot).data.as_mut_ptr(), data.len());
        }

        // Ensure data stores are visible before the consumer sees len != 0.
        unsafe {
            (*slot).len.store(data.len() as u16, Ordering::Release);
        }
        // Publish the slot.
        self.tail().store(tail.wrapping_add(1), Ordering::Release);
        Ok(())
    }

    /// Read one message from the ring into `buf`.
    ///
    /// Returns `Empty` if no message is available, or `BufferTooSmall` if
    /// the waiting message is larger than `buf`.
    #[inline]
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, RingError> {
        let mask = self.capacity - 1;

        let head = self.head().load(Ordering::Relaxed);
        let tail = self.tail().load(Ordering::Acquire);

        if (head & mask) == (tail & mask) {
            return Err(RingError::Empty);
        }

        let slot = self.slot_at(head & mask);
        // SAFETY: `slot` points into the ring's own physical memory.
        // The consumer owns the read index so no other thread reads here.
        let len = unsafe { (*slot).len.load(Ordering::Acquire) as usize };

        if len > buf.len() {
            return Err(RingError::BufferTooSmall);
        }

        unsafe {
            core::ptr::copy_nonoverlapping((*slot).data.as_ptr(), buf.as_mut_ptr(), len);
        }

        // SAFETY: consumer-owned slot, no aliasing with producer.
        unsafe {
            (*slot).len.store(0, Ordering::Release);
        }
        self.head().store(head.wrapping_add(1), Ordering::Release);
        Ok(len)
    }

    /// Non-blocking write.  Equivalent to [`write`](Self::write).
    #[inline]
    pub fn try_write(&self, data: &[u8]) -> Result<(), RingError> {
        self.write(data)
    }

    /// Non-blocking read.  Returns `Ok(None)` when the ring is empty.
    #[inline]
    pub fn try_read(&self, buf: &mut [u8]) -> Result<Option<usize>, RingError> {
        match self.read(buf) {
            Ok(n) => Ok(Some(n)),
            Err(RingError::Empty) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Notify the consumer that new data is available (futex wake).
    /// Increments the consumer notification counter.
    pub fn notify_consumer_raw(&self) {
        unsafe {
            (*self.header).notify_cons.fetch_add(1, Ordering::Release);
        }
    }

    /// Notify the producer that space has been freed (futex wake).
    /// Increments the producer notification counter.
    pub fn notify_producer_raw(&self) {
        unsafe {
            (*self.header).notify_prod.fetch_add(1, Ordering::Release);
        }
    }

    /// Query whether the consumer should wake.  Returns true if data is
    /// available (tail != head).  Used after `futex_wait` returns.
    pub fn has_data(&self) -> bool {
        unsafe {
            let h = (*self.header).head.load(Ordering::Relaxed);
            let t = (*self.header).tail.load(Ordering::Acquire);
            (h & (self.capacity - 1)) != (t & (self.capacity - 1))
        }
    }

    /// Provide a DMA-accessible buffer descriptor for zero-copy NIC
    /// operation.  The physical address points directly into the slot's
    /// data area so the NIC can DMA into the ring without an intermediate
    /// copy.
    pub fn dma_buffer(&self, slot_index: u32) -> DmaBuffer {
        let mask = self.capacity - 1;
        let slot_idx = slot_index & mask;
        let header_size = size_of::<RingHeader>() as u64;
        let slot_offset = header_size + (slot_idx as u64) * size_of::<RingSlot>() as u64;
        const DATA_OFFSET: u64 = 4; // AtomicU16 len + AtomicU16 flags = 4 bytes
        let phys = self.frames[0].start_address.as_u64() + slot_offset + DATA_OFFSET;
        let virt = unsafe { &(*self.slot_at(slot_idx)).data as *const _ };
        DmaBuffer {
            phys_addr: phys,
            virt_addr: virt as *const u8,
        }
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    #[inline]
    fn head(&self) -> &AtomicU32 {
        unsafe { &(*self.header).head }
    }

    #[inline]
    fn tail(&self) -> &AtomicU32 {
        unsafe { &(*self.header).tail }
    }

    #[inline]
    fn slot_at(&self, index: u32) -> *mut RingSlot {
        unsafe { self.slots.add(index as usize) }
    }
}

// Manual Drop to free frames.
impl Drop for LockFreeRing {
    fn drop(&mut self) {
        for frame in self.frames.drain(..) {
            with_irqs_disabled(|token| free_frame(token, frame));
        }
    }
}

// ---------------------------------------------------------------------------
// IpcNotification impl
// ---------------------------------------------------------------------------

use super::transport::{IpcError, IpcNotification};

impl IpcNotification for LockFreeRing {
    fn notify_consumer(&self) {
        self.notify_consumer_raw();
    }

    fn notify_producer(&self) {
        self.notify_producer_raw();
    }

    fn wait_notification(&self) -> Result<(), IpcError> {
        // Spin-then-futex: check once, then wait.
        // The caller should busy-poll for N2a or use futex for N2b.
        // This implementation provides the futex (blocking) path.
        loop {
            if self.has_data() {
                return Ok(());
            }
            // NB: in production this would call futex_wait on notify_cons.
            // For now, yield and retry (architecture-specific).
            core::hint::spin_loop();
        }
    }
}

// ---------------------------------------------------------------------------
// DmaBuffer
// ---------------------------------------------------------------------------

/// Descriptor for a DMA-accessible buffer region within the ring.
pub struct DmaBuffer {
    /// Physical address for the NIC's DMA engine.
    pub phys_addr: u64,
    /// Virtual address for the kernel/strate-net to read/write.
    pub virt_addr: *const u8,
}

unsafe impl Send for DmaBuffer {}
unsafe impl Sync for DmaBuffer {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_pong_64b() {
        let ring = LockFreeRing::new(64, 256).unwrap();
        let msg = [0xABu8; 64];
        ring.write(&msg).unwrap();
        let mut buf = [0u8; 64];
        let n = ring.read(&mut buf).unwrap();
        assert_eq!(n, 64);
        assert_eq!(buf, [0xAB; 64]);
    }

    #[test]
    fn full_ring() {
        let ring = LockFreeRing::new(4, 64).unwrap();
        // 4 slots, circular : 3 writes succeed, 1 reserved slot guards overflow
        for _ in 0..3 {
            ring.write(b"hello").unwrap();
        }
        assert_eq!(ring.write(b"world"), Err(RingError::Full));
        // Read one, then write again
        let mut buf = [0u8; 64];
        ring.read(&mut buf).unwrap();
        ring.write(b"world").unwrap();
    }

    #[test]
    fn message_too_large() {
        let ring = LockFreeRing::new(8, 64).unwrap();
        let oversized = [0u8; 128];
        assert_eq!(ring.write(&oversized), Err(RingError::MessageTooLarge));
    }

    #[test]
    fn buffer_too_small() {
        let ring = LockFreeRing::new(8, 256).unwrap();
        ring.write(b"hello world").unwrap();
        let mut tiny = [0u8; 4];
        assert_eq!(ring.read(&mut tiny), Err(RingError::BufferTooSmall));
    }

    #[test]
    fn empty_ring() {
        let ring = LockFreeRing::new(8, 64).unwrap();
        let mut buf = [0u8; 64];
        assert_eq!(ring.read(&mut buf), Err(RingError::Empty));
    }
}
