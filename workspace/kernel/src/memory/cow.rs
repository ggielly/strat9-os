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
//! # SMP Safety
//!
//! - Atomic refcount per frame (lock-free inc/dec)
//! - COW_LOCK protects flag changes and frame free
//! - TLB shootdown is performed after modifying page table flags

use crate::{
    memory::frame::{FrameAllocator, PhysFrame},
    sync::SpinLock,
};
use alloc::{boxed::Box, vec::Vec};
use core::sync::atomic::{AtomicU32, Ordering, fence};

static COW_LOCK: SpinLock<()> = SpinLock::new(());

#[repr(C)]
pub struct FrameMeta {
    refcount: AtomicU32,
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

    #[inline]
    pub fn inc_ref(&self) {
        self.refcount.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn dec_ref(&self) -> u32 {
        self.refcount.fetch_sub(1, Ordering::Release)
    }

    pub fn get_refcount(&self) -> u32 {
        self.refcount.load(Ordering::Acquire)
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

pub fn frame_inc_ref(frame: PhysFrame) {
    let pfn = frame_to_pfn(frame);
    if let Some(meta) = get_frame_meta(pfn) {
        meta.inc_ref();
    }
}

pub fn frame_dec_ref(frame: PhysFrame) {
    let pfn = frame_to_pfn(frame);
    if let Some(meta) = get_frame_meta(pfn) {
        let old = meta.dec_ref();
        if old == 1 {
            fence(Ordering::Acquire);
            let mut allocator = crate::memory::get_allocator().lock();
            if let Some(alloc) = allocator.as_mut() {
                alloc.free(frame, 0);
            }
        }
    }
}

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
