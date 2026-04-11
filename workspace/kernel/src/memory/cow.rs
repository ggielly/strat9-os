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
    memory::{
        frame::{frame_flags, get_meta, PhysFrame},
        ownership_table, release_owned_block, resolve_handle, BlockHandle, OwnerError,
        RemoveRefResult,
    },
    sync::SpinLock,
};

static COW_LOCK: SpinLock<()> = SpinLock::new(());

/// Performs the frame to pfn operation.
#[inline]
fn frame_meta(frame: PhysFrame) -> &'static crate::memory::frame::FrameMeta {
    get_meta(frame.start_address)
}

/// Returns the metadata slot backing a physical block handle.
#[inline]
fn handle_meta(handle: BlockHandle) -> &'static crate::memory::frame::FrameMeta {
    get_meta(handle.base)
}

/// Increments the shared reference count of a physical block.
pub fn handle_inc_ref(handle: BlockHandle) -> Result<u32, OwnerError> {
    ownership_table().pin(handle)
}

/// Decrements the shared reference count of a physical block.
pub fn handle_dec_ref(handle: BlockHandle) {
    match ownership_table().unpin(handle) {
        Ok(RemoveRefResult::Freed(block)) => release_owned_block(block),
        Ok(RemoveRefResult::NowExclusive { .. })
        | Ok(RemoveRefResult::StillPinned { .. })
        | Ok(RemoveRefResult::StillShared { .. }) => {}
        Err(error) => {
            log::warn!(
                "memory: failed to unpin shared handle {:#x}/{}: {:?}",
                handle.base.as_u64(),
                handle.order,
                error
            );
        }
    }
}

/// Returns the current shared reference count of a physical block.
pub fn handle_get_refcount(handle: BlockHandle) -> u32 {
    ownership_table()
        .refcount(handle)
        .unwrap_or_else(|| handle_meta(handle).get_refcount())
}

/// Marks a freshly allocated physical block as exclusively owned.
pub fn handle_init_ref(handle: BlockHandle) {
    let meta = handle_meta(handle);
    meta.set_order(handle.order);
    meta.set_refcount(1);
}

/// Performs the frame inc ref operation.
pub fn frame_inc_ref(frame: PhysFrame) -> Result<u32, OwnerError> {
    handle_inc_ref(resolve_handle(frame.start_address))
}

/// Performs the frame dec ref operation.
pub fn frame_dec_ref(frame: PhysFrame) {
    handle_dec_ref(resolve_handle(frame.start_address));
}

/// Performs the frame get refcount operation.
pub fn frame_get_refcount(frame: PhysFrame) -> u32 {
    handle_get_refcount(resolve_handle(frame.start_address))
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
