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

//! UEFI allocations owned by the bootloader until handoff or error cleanup.

use core::ptr::NonNull;
use uefi::{
    boot::{self, AllocateType},
    mem::memory_map::MemoryType,
    Status,
};

use crate::memory_map::{page_allocation_size, PhysicalRange, PAGE_SIZE};

// 64 module payloads, kernel, page tables, stack, map, environment and arguments.
const MAX_ALLOCATIONS: usize = 80;

#[derive(Debug)]
pub struct BootError {
    pub operation: &'static str,
    pub status: Status,
}

impl BootError {
    pub fn invalid(operation: &'static str) -> Self {
        Self {
            operation,
            status: Status::LOAD_ERROR,
        }
    }

    pub fn out_of_resources(operation: &'static str) -> Self {
        Self {
            operation,
            status: Status::OUT_OF_RESOURCES,
        }
    }

    pub fn firmware(operation: &'static str, status: Status) -> Self {
        Self { operation, status }
    }
}

pub type BootResult<T> = Result<T, BootError>;

pub struct BootMemory {
    ranges: [PhysicalRange; MAX_ALLOCATIONS],
    count: usize,
    // Drop is only allowed to call FreePages before ExitBootServices.
    release_on_drop: bool,
}

impl BootMemory {
    pub fn new() -> Self {
        Self {
            ranges: [PhysicalRange { base: 0, size: 0 }; MAX_ALLOCATIONS],
            count: 0,
            release_on_drop: true,
        }
    }

    pub fn allocate(&mut self, size: u64, operation: &'static str) -> BootResult<PhysicalRange> {
        self.allocate_inner(size, None, operation)
    }

    /// Keep the existing physical placement if available, otherwise relocate the
    /// contiguous image. Its higher-half virtual addresses do not change.
    pub fn allocate_preferred(
        &mut self,
        base: u64,
        size: u64,
        operation: &'static str,
    ) -> BootResult<PhysicalRange> {
        self.allocate_inner(size, Some(base), operation)
    }

    fn allocate_inner(
        &mut self,
        size: u64,
        preferred: Option<u64>,
        operation: &'static str,
    ) -> BootResult<PhysicalRange> {
        if self.count == self.ranges.len() {
            return Err(BootError::out_of_resources("boot allocation registry full"));
        }
        let size = page_allocation_size(size).map_err(BootError::invalid)?;
        let limit = crate::paging::INITIAL_PHYS_LIMIT;
        if size >= limit || size > isize::MAX as u64 {
            return Err(BootError::out_of_resources(operation));
        }
        let pages = (size / PAGE_SIZE) as usize;
        let preferred = preferred.filter(|base| {
            *base != 0
                && *base % PAGE_SIZE == 0
                && base.checked_add(size).is_some_and(|end| end <= limit)
        });
        let allocation = if let Some(base) = preferred {
            boot::allocate_pages(AllocateType::Address(base), MemoryType::LOADER_DATA, pages)
                .or_else(|_| {
                    boot::allocate_pages(
                        AllocateType::MaxAddress(limit - 1),
                        MemoryType::LOADER_DATA,
                        pages,
                    )
                })
        } else {
            boot::allocate_pages(
                AllocateType::MaxAddress(limit - 1),
                MemoryType::LOADER_DATA,
                pages,
            )
        }
        .map_err(|error| BootError::firmware(operation, error.status()))?;

        let range = PhysicalRange {
            base: allocation.as_ptr() as u64,
            size,
        };
        // Record ownership before the first write. All allocations come from
        // AllocatePages, so they are page-aligned and cannot overlap live pools.
        self.ranges[self.count] = range;
        self.count += 1;
        unsafe { core::ptr::write_bytes(allocation.as_ptr(), 0, size as usize) };
        Ok(range)
    }

    /// Order the recorded allocations by base address. Call once before reading
    /// them back; the result is stable as long as no further allocation runs.
    pub fn sort_reservations(&mut self) {
        self.ranges[..self.count].sort_unstable_by_key(|range| range.base);
    }

    pub fn reservations(&self) -> &[PhysicalRange] {
        &self.ranges[..self.count]
    }

    /// No fallible preparation may follow this call. The next operation must
    /// leave boot services, after which the kernel owns these reservations.
    pub fn retain_for_handoff(&mut self) {
        self.release_on_drop = false;
    }
}

impl Drop for BootMemory {
    fn drop(&mut self) {
        if !self.release_on_drop {
            return;
        }
        for range in self.ranges[..self.count].iter().rev() {
            // SAFETY: these pages were allocated here. On an error return all
            // callers have stopped using their raw pointers before this owner drops.
            if let Some(ptr) = NonNull::new(range.base as *mut u8) {
                let _ = unsafe { boot::free_pages(ptr, (range.size / PAGE_SIZE) as usize) };
            }
        }
    }
}
