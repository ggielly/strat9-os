/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

//! Compatibility layer for the block-oriented metadata API.
//!
//! This module exposes the new block-level entry points on top of the current
//! frame metadata implementation. The dedicated head/sub-frame layout is
//! introduced in a later migration step.

use crate::arch::xshim::PhysAddr;

use crate::memory::{block::BlockHandle, frame, ownership_table};

/// Current metadata backing a block head (see [`frame::MetaSlot`] / issue #38).
pub type BlockMeta = frame::MetaSlot;

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
