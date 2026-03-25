//! Compatibility layer for the block-oriented metadata API.
//!
//! This module exposes the new block-level entry points on top of the current
//! frame metadata implementation. The dedicated head/sub-frame layout is
//! introduced in a later migration step.

use x86_64::PhysAddr;

use crate::memory::{block::BlockHandle, frame};

/// Current metadata backing a block head.
pub type BlockMeta = frame::FrameMeta;

/// Sentinel refcount for an unused block.
pub const REFCOUNT_UNUSED: u32 = frame::REFCOUNT_UNUSED;

/// Returns the metadata entry associated with the given physical address.
pub fn get_block_meta(phys: PhysAddr) -> &'static BlockMeta {
    frame::get_meta(phys)
}

/// Resolves a physical address to the current block handle.
pub fn resolve_handle(phys: PhysAddr) -> BlockHandle {
    let meta = get_block_meta(phys);
    BlockHandle::new(phys, meta.get_order())
}