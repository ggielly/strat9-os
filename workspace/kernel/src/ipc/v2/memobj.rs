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

//! Memory objects (IPC ABI v2, §9.1).
//!
//! A MemObject owns zeroed frames registered in the frame ownership table
//! (the `SharedRing` machinery). Lifetime is reference-counted per frame:
//!
//! - the object holds one owner reference per frame, dropped with the last
//!   handle;
//! - every `SYS_MEMOBJ_MAP` mapping registers a **fresh** mapping identity per
//!   page, dropped by `munmap` or address-space teardown.
//!
//! A frame returns to the allocator only when both kinds of reference are
//! gone, so closing every handle while a mapping exists (or the reverse) can
//! never expose a freed frame.
//!
//! Accounting: the backing is charged to the creator's silo at creation
//! (released with the object). Each mapping is additionally charged as a
//! virtual region to the mapping silo, like every other mapping, because
//! `munmap` and address-space teardown always refund the mapping length:
//! an uncharged (`AlreadyCharged`) mapping would make that refund credit
//! bytes that were never charged.

use super::quota::MemCharge;
use crate::{
    ipc::shared_ring::{self, SharedRing},
    memory::address_space::{AddressSpace, SiloCharge, VmaFlags, VmaPageSize, VmaType},
    syscall::error::SyscallError,
};
use alloc::vec::Vec;
use strat9_abi::ipc_v2::{
    MEMOBJ_MAX_SIZE, MEMOBJ_PROT_EXEC, MEMOBJ_PROT_READ, MEMOBJ_PROT_WRITE, MEM_EXEC, MEM_READ,
    MEM_WRITE,
};

const PAGE: u64 = 4096;

/// A shareable, mappable memory object.
pub struct MemObject {
    frames: SharedRing,
    /// Page-rounded size in bytes.
    size: u64,
    _charge: Option<MemCharge>,
}

impl MemObject {
    /// Allocate a zeroed object of `size` bytes (rounded up to pages).
    ///
    /// `charge` pays for the backing; it is taken by the caller so a quota
    /// failure happens before any frame is allocated.
    pub fn create(size: u64, charge: Option<MemCharge>) -> Result<MemObject, SyscallError> {
        let size = page_round(size)?;
        let frames = shared_ring::allocate_ring(size as usize).map_err(|e| match e {
            shared_ring::RingError::InvalidSize => SyscallError::InvalidArgument,
            _ => SyscallError::OutOfMemory,
        })?;
        Ok(MemObject {
            frames,
            size,
            _charge: charge,
        })
    }

    /// Page-rounded size in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Map `[offset, offset + len)` of the object into `aspace`.
    ///
    /// `prot` (`MEMOBJ_PROT_*`) must be covered by `rights` (`MEM_*`);
    /// `addr_hint == 0` lets the kernel choose. Returns the mapped address.
    pub fn map(
        &self,
        aspace: &AddressSpace,
        rights: u32,
        addr_hint: u64,
        offset: u64,
        len: u64,
        prot: u32,
    ) -> Result<u64, SyscallError> {
        if prot & !(MEMOBJ_PROT_READ | MEMOBJ_PROT_WRITE | MEMOBJ_PROT_EXEC) != 0 {
            return Err(SyscallError::InvalidArgument);
        }
        let needs = |p: u32, r: u32| prot & p == 0 || rights & r != 0;
        if !(needs(MEMOBJ_PROT_READ, MEM_READ)
            && needs(MEMOBJ_PROT_WRITE, MEM_WRITE)
            && needs(MEMOBJ_PROT_EXEC, MEM_EXEC))
        {
            return Err(SyscallError::PermissionDenied);
        }
        if len == 0 || offset % PAGE != 0 || len % PAGE != 0 || addr_hint % PAGE != 0 {
            return Err(SyscallError::InvalidArgument);
        }
        let end = offset
            .checked_add(len)
            .ok_or(SyscallError::InvalidArgument)?;
        if end > self.size {
            return Err(SyscallError::InvalidArgument);
        }
        let first = (offset / PAGE) as usize;
        let count = (len / PAGE) as usize;
        let phys: Vec<u64> = self.frames.frame_phys_addrs()[first..first + count].to_vec();
        let handles: Vec<_> = phys
            .iter()
            .map(|p| crate::memory::resolve_handle(crate::arch::xshim::PhysAddr::new(*p)))
            .collect();

        let base = if addr_hint != 0 {
            addr_hint
        } else {
            aspace
                .find_free_vma_range(crate::kaslr::mmap_base(), count, VmaPageSize::Small)
                .ok_or(SyscallError::OutOfMemory)?
        };
        // Fresh per-page mapping identities (`None`): each mapping holds its
        // own frame reference. Charged as a region (refunded by munmap).
        aspace
            .map_shared_handles_with_cap_ids_charged(
                base,
                &handles,
                None,
                VmaFlags {
                    readable: prot & MEMOBJ_PROT_READ != 0,
                    writable: prot & MEMOBJ_PROT_WRITE != 0,
                    executable: prot & MEMOBJ_PROT_EXEC != 0,
                    user_accessible: true,
                },
                VmaType::Anonymous,
                VmaPageSize::Small,
                SiloCharge::Charge,
            )
            .map_err(|_| SyscallError::OutOfMemory)?;
        Ok(base)
    }
}

/// Validate a requested size and round it up to whole pages.
pub fn page_round(size: u64) -> Result<u64, SyscallError> {
    if size == 0 || size > MEMOBJ_MAX_SIZE {
        return Err(SyscallError::InvalidArgument);
    }
    Ok(size.div_ceil(PAGE) * PAGE)
}
