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
    memory::frame::{frame_flags, get_meta, PhysFrame},
    sync::SpinLock,
};
use core::sync::atomic::{fence, Ordering};

static COW_LOCK: SpinLock<()> = SpinLock::new(());

/// Performs the frame to pfn operation.
#[inline]
fn frame_meta(frame: PhysFrame) -> &'static crate::memory::frame::FrameMeta {
    get_meta(frame.start_address)
}

/// Performs the frame inc ref operation.
pub fn frame_inc_ref(frame: PhysFrame) {
    frame_meta(frame).inc_ref();
}

/// Performs the frame dec ref operation.
pub fn frame_dec_ref(frame: PhysFrame) {
    let meta = frame_meta(frame);
    let old = meta.dec_ref();
    if old == 1 {
        fence(Ordering::Acquire);
        crate::sync::with_irqs_disabled(|token| {
            crate::memory::free_frame(token, frame);
        });
    }
}

/// Performs the frame get refcount operation.
pub fn frame_get_refcount(frame: PhysFrame) -> u32 {
    frame_meta(frame).get_refcount()
}

/// Set COW flag on a frame (SMP-safe).
pub fn frame_set_cow(frame: PhysFrame) {
    let _lock = COW_LOCK.lock();
    let meta = frame_meta(frame);
    let flags = meta.get_flags() | frame_flags::COW;
    meta.set_flags(flags);
}

/// Clear COW flag on a frame (SMP-safe).
pub fn frame_clear_cow(frame: PhysFrame) {
    let _lock = COW_LOCK.lock();
    let meta = frame_meta(frame);
    let flags = meta.get_flags() & !frame_flags::COW;
    meta.set_flags(flags);
}

/// Check if a frame is marked as COW (lock-free read).
pub fn frame_is_cow(frame: PhysFrame) -> bool {
    frame_meta(frame).is_cow()
}

/// Mark a frame as DLL (shared, never COW) (SMP-safe).
pub fn frame_set_dll(frame: PhysFrame) {
    let _lock = COW_LOCK.lock();
    let meta = frame_meta(frame);
    let flags = meta.get_flags() | frame_flags::DLL;
    meta.set_flags(flags);
}

/// Check if a frame is a DLL frame (lock-free read).
pub fn frame_is_dll(frame: PhysFrame) -> bool {
    frame_meta(frame).is_dll()
}
