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
//! # References
//!
//! - MIT 6.828 xv6 COW Lab: https://pdos.csail.mit.edu/6.828/2021/labs/cow.html
//! - Philipp Oppermann Paging Guide: https://os.phil-opp.com/paging-introduction/

use crate::memory::frame::{FrameAllocator, PhysFrame};
use core::sync::atomic::{AtomicU32, Ordering};

/// Maximum number of physical frames we can track
/// Adjust based on your system's maximum RAM (e.g., 64GB = 16M frames)
const MAX_FRAMES: usize = 1024 * 1024; // 1M frames = 4GB RAM

/// Metadata for each physical frame
#[repr(C)]
pub struct FrameMeta {
    /// Number of processes sharing this frame
    refcount: AtomicU32,
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
        FrameMeta {
            refcount: AtomicU32::new(0),
            flags: AtomicU32::new(0),
        }
    }

    /// Increment reference count
    pub fn inc_ref(&self) -> u32 {
        self.refcount.fetch_add(1, Ordering::SeqCst)
    }

    /// Decrement reference count and return old value
    pub fn dec_ref(&self) -> u32 {
        self.refcount.fetch_sub(1, Ordering::SeqCst)
    }

    /// Get current reference count
    pub fn get_refcount(&self) -> u32 {
        self.refcount.load(Ordering::Acquire)
    }

    /// Set frame flags
    pub fn set_flags(&self, flags: u32) {
        self.flags.store(flags, Ordering::Release);
    }

    /// Get frame flags
    pub fn get_flags(&self) -> u32 {
        self.flags.load(Ordering::Acquire)
    }

    /// Check if frame is COW
    pub fn is_cow(&self) -> bool {
        self.get_flags() & frame_flags::COW != 0
    }

    /// Check if frame is DLL
    pub fn is_dll(&self) -> bool {
        self.get_flags() & frame_flags::DLL != 0
    }
}

/// Global frame metadata array pointer
/// Initialized during boot with the number of available frames
static mut FRAME_METAS_PTR: *mut FrameMeta = core::ptr::null_mut();
static mut FRAME_METAS_LEN: usize = 0;

/// Initialize the frame metadata manager
///
/// # Arguments
/// * `max_pfn` - Maximum physical frame number (total RAM / 4KB)
/// * `metas_ptr` - Pointer to pre-allocated metadata array
///
/// # Safety
/// - `metas_ptr` must point to a valid array of `max_pfn` FrameMeta entries
/// - Must be called once during boot, before any memory allocations
pub unsafe fn init_frame_metadata(max_pfn: usize, metas_ptr: *mut FrameMeta) {
    FRAME_METAS_PTR = metas_ptr;
    FRAME_METAS_LEN = max_pfn;
    log::info!("Frame metadata initialized for {} frames ({:.2} GB max)",
               max_pfn, (max_pfn as u64 * 4096) / (1024 * 1024 * 1024));
}

/// Get metadata for a physical frame
fn get_frame_meta(pfn: u64) -> Option<&'static FrameMeta> {
    unsafe {
        if FRAME_METAS_PTR.is_null() || pfn as usize >= FRAME_METAS_LEN {
            return None;
        }
        Some(&*FRAME_METAS_PTR.add(pfn as usize))
    }
}

/// Get mutable metadata for a physical frame
fn get_frame_meta_mut(pfn: u64) -> Option<&'static mut FrameMeta> {
    unsafe {
        if FRAME_METAS_PTR.is_null() || pfn as usize >= FRAME_METAS_LEN {
            return None;
        }
        Some(&mut *FRAME_METAS_PTR.add(pfn as usize))
    }
}

#[inline]
fn frame_to_pfn(frame: PhysFrame) -> u64 {
    frame.start_address.as_u64() >> 12
}

/// Increment reference count for a physical frame
pub fn frame_inc_ref(frame: PhysFrame) {
    let pfn = frame_to_pfn(frame);
    if let Some(meta) = get_frame_meta_mut(pfn) {
        meta.inc_ref();
    }
}

/// Decrement reference count and free if zero
pub fn frame_dec_ref(frame: PhysFrame) {
    let pfn = frame_to_pfn(frame);
    if let Some(meta) = get_frame_meta_mut(pfn) {
        let old_ref = meta.dec_ref();
        if old_ref == 1 {
            // Last reference: free the frame
            let mut allocator = crate::memory::get_allocator().lock();
            if let Some(alloc) = allocator.as_mut() {
                alloc.free(frame, 0); // Order 0 = single page
            }
        }
    }
}

/// Get reference count for a frame
pub fn frame_get_refcount(frame: PhysFrame) -> u32 {
    let pfn = frame_to_pfn(frame);
    get_frame_meta(pfn).map(|m| m.get_refcount()).unwrap_or(0)
}

/// Set COW flag on a frame
pub fn frame_set_cow(frame: PhysFrame) {
    let pfn = frame_to_pfn(frame);
    if let Some(meta) = get_frame_meta_mut(pfn) {
        let flags = meta.get_flags() | frame_flags::COW;
        meta.set_flags(flags);
    }
}

/// Clear COW flag on a frame
pub fn frame_clear_cow(frame: PhysFrame) {
    let pfn = frame_to_pfn(frame);
    if let Some(meta) = get_frame_meta_mut(pfn) {
        let flags = meta.get_flags() & !frame_flags::COW;
        meta.set_flags(flags);
    }
}

/// Check if a frame is marked as COW
pub fn frame_is_cow(frame: PhysFrame) -> bool {
    let pfn = frame_to_pfn(frame);
    get_frame_meta(pfn).map(|m| m.is_cow()).unwrap_or(false)
}

/// Mark a frame as DLL (shared, never COW)
pub fn frame_set_dll(frame: PhysFrame) {
    let pfn = frame_to_pfn(frame);
    if let Some(meta) = get_frame_meta_mut(pfn) {
        let flags = meta.get_flags() | frame_flags::DLL;
        meta.set_flags(flags);
    }
}

/// Check if a frame is a DLL frame
pub fn frame_is_dll(frame: PhysFrame) -> bool {
    let pfn = frame_to_pfn(frame);
    get_frame_meta(pfn).map(|m| m.is_dll()).unwrap_or(false)
}
