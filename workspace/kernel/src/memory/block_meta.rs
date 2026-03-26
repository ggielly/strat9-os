//! Compatibility layer for the block-oriented metadata API.
//!
//! This module exposes the new block-level entry points on top of the current
//! frame metadata implementation. The dedicated head/sub-frame layout is
//! introduced in a later migration step.

use x86_64::PhysAddr;

use crate::memory::{block::BlockHandle, frame, ownership_table};

/// Current metadata backing a block head.
pub type BlockMeta = frame::FrameMeta;

/// Sentinel refcount for an unused block.
pub const REFCOUNT_UNUSED: u32 = frame::REFCOUNT_UNUSED;

/// Returns the metadata entry associated with the given physical address.
pub fn get_block_meta(phys: PhysAddr) -> &'static BlockMeta {
    frame::get_meta(phys)
}

/// Returns the metadata entry associated with the given block handle.
#[inline]
fn align_down_to_block_base(phys: PhysAddr, order: u8) -> PhysAddr {
    let size = 4096u64.checked_shl(order as u32).unwrap_or(0);
    if size == 0 {
        return phys;
    }
    PhysAddr::new(phys.as_u64() & !(size - 1))
}

/// Resolves a physical address to the current block handle.
/// If the address is not currently owned, a new handle is reconstructed from the metadata.
///
pub fn resolve_handle(phys: PhysAddr) -> BlockHandle {
    if let Some(handle) = ownership_table().handle_containing(phys) {
        return handle;
    }

    let meta = get_block_meta(phys);
    let order = meta.get_order();
    let handle = BlockHandle::new(align_down_to_block_base(phys, order), order);
    debug_assert!(
        handle.is_valid(),
        "block_meta: reconstructed invalid handle for phys={:#x} order={}",
        phys.as_u64(),
        order
    );
    handle
}
