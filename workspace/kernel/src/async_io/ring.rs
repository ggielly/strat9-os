//! Ring buffer for async I/O submission and completion.
//!
//! Each ring consists of two pages mapped into the owning process's address
//! space: a Submission Queue (SQ) page and a Completion Queue (CQ) page.
//! The kernel tracks metadata (head/tail pointers, ownership) internally;
//! only the raw SQE/CQE arrays are visible to userspace.

use crate::{
    memory::{self, phys_to_virt, PhysFrame},
    sync::SpinLock,
};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::ops::{AsyncCqe, AsyncSqe, DEFAULT_RING_ENTRIES};

// =============================================================================
// Ring
// =============================================================================

/// A shared submission/completion ring for a single process.
pub struct Ring {
    /// Opaque handle returned to userspace.
    pub id: u64,
    /// Process that owns this ring (by PID).
    pub owner_pid: u32,
    /// Physical frame backing the SQ page.
    pub sq_frame: PhysFrame,
    /// Kernel virtual address of the SQ metadata header.
    pub sq_virt: u64,
    /// Physical frame backing the CQ page.
    pub cq_frame: PhysFrame,
    /// Kernel virtual address of the CQ metadata header.
    pub cq_virt: u64,
    /// Number of entries (power of two, min 2, max MAX_IN_FLIGHT).
    pub entries: u32,
    /// Number of in-flight operations (not yet completed).
    pub in_flight: AtomicU32,
    /// Whether this ring has been destroyed (no new ops accepted).
    pub destroyed: AtomicU32,
    /// Lock for pushing completions.
    pub cq_lock: SpinLock<()>,
    /// Order used for SQ allocation.
    pub sq_order: u8,
    /// Order used for CQ allocation.
    pub cq_order: u8,
    /// Wait queue for tasks blocked on this ring.
    pub wq: crate::sync::WaitQueue,
}

impl Ring {
    /// Create a new ring and map it into the calling process's address space.
    pub fn create(pid: u32, entries: u32) -> Result<u64, RingError> {
        let entries = entries.max(2).min(DEFAULT_RING_ENTRIES).next_power_of_two();

        let sq_bytes = RING_META_SIZE + (entries as usize * core::mem::size_of::<AsyncSqe>());
        let cq_bytes = RING_META_SIZE + (entries as usize * core::mem::size_of::<AsyncCqe>());

        let sq_order = ((sq_bytes + 4095) / 4096)
            .next_power_of_two()
            .trailing_zeros() as u8;
        let cq_order = ((cq_bytes + 4095) / 4096)
            .next_power_of_two()
            .trailing_zeros() as u8;

        // Allocate SQ frames
        let sq_frame =
            crate::sync::with_irqs_disabled(|t| memory::allocate_phys_contiguous(t, sq_order))
                .map_err(|_| RingError::Alloc)?;
        let sq_virt = phys_to_virt(sq_frame.start_address.as_u64());

        // Allocate CQ frames
        let cq_frame = match crate::sync::with_irqs_disabled(|t| {
            memory::allocate_phys_contiguous(t, cq_order)
        }) {
            Ok(f) => f,
            Err(_) => {
                crate::sync::with_irqs_disabled(|t| {
                    memory::free_phys_contiguous(t, sq_frame, sq_order);
                });
                return Err(RingError::Alloc);
            }
        };
        let cq_virt = phys_to_virt(cq_frame.start_address.as_u64());

        // Initialize metadata
        unsafe {
            let sq = sq_virt as *mut RingMeta;
            (*sq).entries.store(entries, Ordering::Release);
            (*sq).mask.store(entries - 1, Ordering::Release);
            (*sq).head.store(0, Ordering::Release);
            (*sq).tail.store(0, Ordering::Release);
            (*sq).flags.store(0, Ordering::Release);

            let cq = cq_virt as *mut RingMeta;
            (*cq).entries.store(entries, Ordering::Release);
            (*cq).mask.store(entries - 1, Ordering::Release);
            (*cq).head.store(0, Ordering::Release);
            (*cq).tail.store(0, Ordering::Release);
            (*cq).flags.store(0, Ordering::Release);
        }

        let ring = Ring {
            id: next_ring_id(),
            owner_pid: pid,
            sq_frame,
            sq_virt,
            cq_frame,
            cq_virt,
            entries,
            in_flight: AtomicU32::new(0),
            destroyed: AtomicU32::new(0),
            cq_lock: SpinLock::new(()),
            sq_order,
            cq_order,
            wq: crate::sync::WaitQueue::new(),
        };

        let id = ring.id;
        RING_REGISTRY.lock().push(ring);
        Ok(id)
    }

    /// Read the SQ tail (written by userspace, read by kernel).
    #[inline]
    pub fn sq_tail(&self) -> u32 {
        self.sq_meta().tail.load(Ordering::Acquire)
    }

    /// Read the SQ head (written by kernel, read by userspace).
    #[inline]
    pub fn sq_head(&self) -> u32 {
        self.sq_meta().head.load(Ordering::Acquire)
    }

    /// Advance the SQ head after processing submissions.
    #[inline]
    pub fn sq_advance_head(&self, count: u32) {
        self.sq_meta().head.fetch_add(count, Ordering::Release);
    }

    /// Advance the CQ tail after pushing completions.
    #[inline]
    pub fn cq_advance_tail(&self, count: u32) {
        self.cq_meta().tail.fetch_add(count, Ordering::Release);
    }

    /// Read the CQ head (written by userspace after consuming).
    #[inline]
    pub fn cq_head(&self) -> u32 {
        self.cq_meta().head.load(Ordering::Acquire)
    }

    /// Get a pointer to the SQE at the given index.
    #[inline]
    pub unsafe fn sqe_at(&self, index: u32) -> *const AsyncSqe {
        let base = (self.sq_virt + RING_META_SIZE as u64) as *const AsyncSqe;
        base.add(index as usize)
    }

    /// Get a mutable pointer to the CQE at the given index.
    #[inline]
    pub unsafe fn cqe_at(&self, index: u32) -> *mut AsyncCqe {
        let base = (self.cq_virt + RING_META_SIZE as u64) as *mut AsyncCqe;
        base.add(index as usize)
    }

    /// Mark the ring as destroyed (no new submissions accepted).
    #[inline]
    pub fn destroy(&self) {
        self.destroyed.store(1, Ordering::Release);
    }

    pub(crate) fn sq_meta(&self) -> &RingMeta {
        unsafe { &*(self.sq_virt as *const RingMeta) }
    }
    pub(crate) fn cq_meta(&self) -> &RingMeta {
        unsafe { &*(self.cq_virt as *const RingMeta) }
    }
}

// =============================================================================
// RingMeta : header at the start of each ring page
// =============================================================================

/// Metadata header embedded at offset 0 of each ring page.
/// The SQE/CQE array starts at `RING_META_SIZE` bytes from the page base.
#[repr(C)]
pub(crate) struct RingMeta {
    pub(crate) head: AtomicU32,    // Producer offset
    pub(crate) tail: AtomicU32,    // Consumer offset
    pub(crate) mask: AtomicU32,    // entries - 1 (for index wrapping)
    pub(crate) entries: AtomicU32, // total number of slots
    pub(crate) flags: AtomicU32,   // ring flags (NEED_WAKEUP, etc.)
}

const RING_META_SIZE: usize = 64; // leave room for future flags

// =============================================================================
// RingRegistry
// =============================================================================

const MAX_RINGS: usize = 128;

static RING_REGISTRY: SpinLock<Vec<Ring>> = SpinLock::new(Vec::new());

static NEXT_RING_ID: AtomicU64 = AtomicU64::new(1);

fn next_ring_id() -> u64 {
    NEXT_RING_ID.fetch_add(1, Ordering::Relaxed)
}

/// Find a ring by its opaque id.
pub fn find_ring(id: u64) -> Option<*const Ring> {
    let guard = RING_REGISTRY.lock();
    guard.iter().find(|r| r.id == id).map(|r| r as *const Ring)
}

/// Remove a ring from the registry and free its pages.
pub fn destroy_ring(id: u64) -> Result<(), RingError> {
    let mut guard = RING_REGISTRY.lock();
    if let Some(pos) = guard.iter().position(|r| r.id == id) {
        let ring = guard.remove(pos);
        ring.destroy();
        crate::sync::with_irqs_disabled(|t| {
            memory::free_phys_contiguous(t, ring.sq_frame, ring.sq_order);
            memory::free_phys_contiguous(t, ring.cq_frame, ring.cq_order);
        });
        Ok(())
    } else {
        Err(RingError::NotFound)
    }
}

// =============================================================================
// RingError
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingError {
    Alloc,
    NotFound,
    TooManyRings,
}
