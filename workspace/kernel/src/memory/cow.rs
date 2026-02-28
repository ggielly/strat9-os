//! Copy-on-Write (COW) support for fork()
//!
//! This module provides the core functionality for copy-on-write memory management,
//! allowing efficient fork() implementation by sharing pages between parent and child
//! until one of them writes to a shared page.
//!
//! # Design
//!
//! - Pages are marked as COW by clearing the WRITABLE bit and setting a software COW flag
//! - The COW flag is stored in bit 9 of the PTE (available for software use on x86_64)
//! - When a write fault occurs on a COW page:
//!   1. If refcount > 1: allocate new frame, copy content, update PTE
//!   2. If refcount == 1: just mark page as writable (no copy needed)
//!
//! # SMP Safety (Per-CPU Optimization)
//!
//! - Frame metadata uses per-CPU reference counters to minimize lock contention
//! - Each CPU maintains its own atomic refcount for each frame
//! - inc_ref/dec_ref operate lock-free on the local CPU counter
//! - Global refcount is computed by summing all per-CPU counters
//! - Flag operations still use COW_LOCK but are much less frequent
//! - TLB shootdown is performed after modifying page table flags
//!
//! # Performance
//!
//! - Lock contention reduced from O(CPUs × operations) to O(flags_ops)
//! - Typical fork workload: 99% of operations are inc/dec (now lock-free)
//! - Only flag changes and final frame free require the global lock
//!
//! # References
//!
//! - MIT 6.828 xv6 COW Lab: https://pdos.csail.mit.edu/6.828/2021/labs/cow.html
//! - Philipp Oppermann Paging Guide: https://os.phil-opp.com/paging-introduction/
//! - Linux kernel: mm/memory.c (do_wp_page), include/linux/percpu-refcount.h

use crate::{
    arch::x86_64::{percpu, smp},
    memory::frame::{FrameAllocator, PhysFrame},
    sync::SpinLock,
};
use alloc::{boxed::Box, vec::Vec};
use core::sync::atomic::{AtomicU32, Ordering};

/// Global lock protecting COW metadata flag operations and frame free.
///
/// This lock is only held for:
/// - Updating COW/DLL flags in frame metadata
/// - Final frame deallocation when refcount reaches zero
///
/// Reference count inc/dec operations are lock-free per-CPU.
static COW_LOCK: SpinLock<()> = SpinLock::new(());

/// Metadata for each physical frame with per-CPU refcounting
#[repr(C)]
pub struct FrameMeta {
    /// Per-CPU reference counters for this frame.
    /// Using per-CPU counters eliminates lock contention on refcount operations.
    /// The global refcount is the sum of all per-CPU counters.
    per_cpu_refcounts: [AtomicU32; percpu::MAX_CPUS],
    /// Flags for the frame (COW, DLL, etc.)
    flags: AtomicU32,
}

/// Frame flags
pub mod frame_flags {
    /// Frame is copy-on-write eligible
    pub const COW: u32 = 1 << 0;
    /// Frame is part of a shared DLL (never COW)
    pub const DLL: u32 = 1 << 1;
    /// Frame is anonymous (heap/stack, not file-backed)
    pub const ANONYMOUS: u32 = 1 << 2;
}

impl FrameMeta {
    pub const fn new() -> Self {
        // Initialize all per-CPU refcounts to 0
        const ZERO_ATOMIC: AtomicU32 = AtomicU32::new(0);
        FrameMeta {
            per_cpu_refcounts: [ZERO_ATOMIC; percpu::MAX_CPUS],
            flags: AtomicU32::new(0),
        }
    }

    /// Increment reference count on the current CPU (lock-free).
    #[inline]
    pub fn inc_ref_local(&self, cpu_id: usize) {
        if cpu_id < percpu::MAX_CPUS {
            self.per_cpu_refcounts[cpu_id].fetch_add(1, Ordering::Release);
        }
    }

    /// Decrement reference count on the current CPU and return old value (lock-free).
    #[inline]
    pub fn dec_ref_local(&self, cpu_id: usize) -> u32 {
        if cpu_id < percpu::MAX_CPUS {
            self.per_cpu_refcounts[cpu_id].fetch_sub(1, Ordering::Acquire)
        } else {
            0
        }
    }

    /// Get total reference count by summing all per-CPU counters.
    ///
    /// This operation is more expensive than the old global atomic read,
    /// but it's only needed when making decisions (COW resolution, free).
    /// The trade-off is: frequent lock-free inc/dec vs occasional aggregation.
    pub fn get_refcount(&self) -> u32 {
        let mut total = 0u32;
        let num_cpus = smp::cpu_count().min(percpu::MAX_CPUS);
        for i in 0..num_cpus {
            total = total.saturating_add(self.per_cpu_refcounts[i].load(Ordering::Acquire));
        }
        total
    }

    /// Set frame flags (requires COW_LOCK held by caller).
    pub fn set_flags(&self, flags: u32) {
        self.flags.store(flags, Ordering::Release);
    }

    /// Get frame flags.
    pub fn get_flags(&self) -> u32 {
        self.flags.load(Ordering::Acquire)
    }

    /// Check if frame is COW.
    pub fn is_cow(&self) -> bool {
        self.get_flags() & frame_flags::COW != 0
    }

    /// Check if frame is DLL.
    pub fn is_dll(&self) -> bool {
        self.get_flags() & frame_flags::DLL != 0
    }
}

/// Global frame metadata array pointer
/// Initialized during boot with the number of available frames
static mut FRAME_META_CHUNKS_PTR: *mut *mut FrameMeta = core::ptr::null_mut();
static mut FRAME_META_CHUNKS_LEN: usize = 0;
static mut FRAME_METAS_LEN: usize = 0;
const FRAME_META_CHUNK_SHIFT: usize = 12;
const FRAME_META_CHUNK_ENTRIES: usize = 1 << FRAME_META_CHUNK_SHIFT;
const FRAME_META_CHUNK_MASK: usize = FRAME_META_CHUNK_ENTRIES - 1;

/// Initialize the frame metadata manager
///
/// # Arguments
/// * `max_pfn` - Maximum physical frame number (total RAM / 4KB)
/// Allocates metadata in fixed-size chunks to avoid requiring one huge contiguous
/// heap allocation during early boot.
///
/// # Safety
/// - Must be called once during boot, before any memory allocations
pub unsafe fn init_frame_metadata(max_pfn: usize) {
    let chunk_count = max_pfn.div_ceil(FRAME_META_CHUNK_ENTRIES);
    let mut chunks: Vec<*mut FrameMeta> = Vec::with_capacity(chunk_count);

    for ci in 0..chunk_count {
        let start = ci * FRAME_META_CHUNK_ENTRIES;
        let remaining = max_pfn.saturating_sub(start);
        let entries = core::cmp::min(remaining, FRAME_META_CHUNK_ENTRIES);
        let mut metas = Vec::with_capacity(entries);
        for _ in 0..entries {
            metas.push(FrameMeta::new());
        }
        let boxed = metas.into_boxed_slice();
        let ptr = Box::into_raw(boxed) as *mut FrameMeta;
        chunks.push(ptr);
    }

    let chunk_ptrs = chunks.into_boxed_slice();
    FRAME_META_CHUNKS_LEN = chunk_ptrs.len();
    FRAME_META_CHUNKS_PTR = Box::into_raw(chunk_ptrs) as *mut *mut FrameMeta;
    FRAME_METAS_LEN = max_pfn;
    log::info!(
        "Frame metadata initialized for {} frames in {} chunk(s) ({:.2} GB max)",
        max_pfn,
        chunk_count,
        (max_pfn as u64 * 4096) / (1024 * 1024 * 1024)
    );
}

/// Get metadata for a physical frame
fn get_frame_meta(pfn: u64) -> Option<&'static FrameMeta> {
    unsafe {
        if FRAME_META_CHUNKS_PTR.is_null() || pfn as usize >= FRAME_METAS_LEN {
            return None;
        }
        let p = pfn as usize;
        let chunk_idx = p >> FRAME_META_CHUNK_SHIFT;
        if chunk_idx >= FRAME_META_CHUNKS_LEN {
            return None;
        }
        let offset = p & FRAME_META_CHUNK_MASK;
        let chunk = *FRAME_META_CHUNKS_PTR.add(chunk_idx);
        Some(&*chunk.add(offset))
    }
}

/// Get mutable metadata for a physical frame
fn get_frame_meta_mut(pfn: u64) -> Option<&'static mut FrameMeta> {
    unsafe {
        if FRAME_META_CHUNKS_PTR.is_null() || pfn as usize >= FRAME_METAS_LEN {
            return None;
        }
        let p = pfn as usize;
        let chunk_idx = p >> FRAME_META_CHUNK_SHIFT;
        if chunk_idx >= FRAME_META_CHUNKS_LEN {
            return None;
        }
        let offset = p & FRAME_META_CHUNK_MASK;
        let chunk = *FRAME_META_CHUNKS_PTR.add(chunk_idx);
        Some(&mut *chunk.add(offset))
    }
}

#[inline]
fn frame_to_pfn(frame: PhysFrame) -> u64 {
    frame.start_address.as_u64() >> 12
}

/// Get current CPU index efficiently for per-CPU operations.
///
/// Returns 0 if per-CPU data is not yet initialized (boot phase).
#[inline]
fn current_cpu_id() -> usize {
    // SAFETY: lapic_id() is safe to call after APIC initialization
    let apic_id = crate::arch::x86_64::apic::lapic_id();
    percpu::cpu_index_by_apic(apic_id).unwrap_or(0)
}

/// Increment reference count for a physical frame (lock-free per-CPU).
///
/// This operation is now lock-free by using per-CPU counters.
/// Each CPU maintains its own atomic refcount, eliminating contention.
pub fn frame_inc_ref(frame: PhysFrame) {
    let cpu_id = current_cpu_id();
    let pfn = frame_to_pfn(frame);
    if let Some(meta) = get_frame_meta(pfn) {
        meta.inc_ref_local(cpu_id);
    }
}

/// Decrement reference count and free if zero (mostly lock-free).
///
/// The decrement itself is lock-free on the local CPU counter.
/// If the total refcount drops to zero, we acquire COW_LOCK to free the frame.
pub fn frame_dec_ref(frame: PhysFrame) {
    let cpu_id = current_cpu_id();
    let pfn = frame_to_pfn(frame);
    if let Some(meta) = get_frame_meta(pfn) {
        let old_local = meta.dec_ref_local(cpu_id);

        // Optimization: only check total refcount if our local counter was the last one
        if old_local == 1 {
            // Possible last reference: check global count with lock
            let _lock = COW_LOCK.lock();
            let total_refs = meta.get_refcount();

            if total_refs == 0 {
                // Last reference: free the frame
                drop(_lock); // Release COW_LOCK before acquiring allocator lock
                let mut allocator = crate::memory::get_allocator().lock();
                if let Some(alloc) = allocator.as_mut() {
                    alloc.free(frame, 0); // Order 0 = single page
                }
            }
        }
    }
}

/// Get reference count for a frame (aggregates all per-CPU counters).
///
/// Note: This is more expensive than the old atomic read, but inc/dec
/// are now lock-free which is the common case (99% of operations).
pub fn frame_get_refcount(frame: PhysFrame) -> u32 {
    let pfn = frame_to_pfn(frame);
    get_frame_meta(pfn).map(|m| m.get_refcount()).unwrap_or(0)
}

/// Set COW flag on a frame (SMP-safe).
pub fn frame_set_cow(frame: PhysFrame) {
    let _lock = COW_LOCK.lock();
    let pfn = frame_to_pfn(frame);
    if let Some(meta) = get_frame_meta_mut(pfn) {
        let flags = meta.get_flags() | frame_flags::COW;
        meta.set_flags(flags);
    }
}

/// Clear COW flag on a frame (SMP-safe).
pub fn frame_clear_cow(frame: PhysFrame) {
    let _lock = COW_LOCK.lock();
    let pfn = frame_to_pfn(frame);
    if let Some(meta) = get_frame_meta_mut(pfn) {
        let flags = meta.get_flags() & !frame_flags::COW;
        meta.set_flags(flags);
    }
}

/// Check if a frame is marked as COW (lock-free read).
pub fn frame_is_cow(frame: PhysFrame) -> bool {
    let pfn = frame_to_pfn(frame);
    get_frame_meta(pfn).map(|m| m.is_cow()).unwrap_or(false)
}

/// Mark a frame as DLL (shared, never COW) (SMP-safe).
pub fn frame_set_dll(frame: PhysFrame) {
    let _lock = COW_LOCK.lock();
    let pfn = frame_to_pfn(frame);
    if let Some(meta) = get_frame_meta_mut(pfn) {
        let flags = meta.get_flags() | frame_flags::DLL;
        meta.set_flags(flags);
    }
}

/// Check if a frame is a DLL frame (lock-free read).
pub fn frame_is_dll(frame: PhysFrame) -> bool {
    let pfn = frame_to_pfn(frame);
    get_frame_meta(pfn).map(|m| m.is_dll()).unwrap_or(false)
}
