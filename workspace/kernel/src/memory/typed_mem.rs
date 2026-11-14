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

//! Named typed-memory objects.
//!
//! A registry of physically backed memory objects carrying attributes (contiguous, DMA-safe,
//! uncached, shared) and an owner silo. An object is either:
//!
//! - **registered** around a physical range reserved elsewhere (boot tables,
//!   firmware, MMIO-adjacent buffers), or
//! - **allocated** from the buddy allocator as one physically contiguous
//!   block (`2^order` pages), then released on [`release`].
//!
//! The registry only owns bookkeeping. Mapping an object into an address
//! space still goes through [`crate::memory::address_space::AddressSpace`],
//! which charges the mapping silo for the VMA length; `munmap` and teardown
//! always refund that length, so the mapping must be charged even when the
//! backing was already accounted to its owner.
//!
//! Deliberately minimal: no POSIX `posix_typed_mem_open` ABI yet, no
//! per-object lock (the registry lock is enough for `register`/`lookup`);
//! those belong to the syscall layer when the interface is exposed.

use alloc::{string::String, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};

use crate::{
    arch::xshim::PhysAddr,
    memory::frame::PhysFrame,
    silo::SiloId,
    sync::{with_irqs_disabled, SpinLock},
};

use super::{allocate_phys_contiguous, free_phys_contiguous};

/// Page granularity of typed-memory objects.
pub const PAGE_SIZE: u64 = 4096;
/// Maximum name length, excluding the terminating NUL.
pub const MAX_NAME_LEN: usize = 63;
/// Highest buddy order a single typed object may request.
pub const MAX_ORDER: u8 = crate::memory::zone::MAX_ORDER as u8;

/// Attributes of a typed-memory object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TypedMemFlags {
    /// Backing is one physically contiguous block.
    pub contiguous: bool,
    /// Suitable for DMA (as opposed to CPU-only memory).
    pub dma: bool,
    /// Must be mapped uncached.
    pub uncached: bool,
    /// May be mapped by more than one address space.
    pub shared: bool,
}

impl TypedMemFlags {
    /// No special attribute.
    pub const NONE: Self = Self {
        contiguous: false,
        dma: false,
        uncached: false,
        shared: false,
    };

    /// Physically contiguous DMA memory, the common driver case.
    pub const CONTIGUOUS_DMA: Self = Self {
        contiguous: true,
        dma: true,
        uncached: false,
        shared: true,
    };
}

/// One registered typed-memory object.
#[derive(Debug, Clone)]
pub struct TypedMemoryObject {
    /// Stable identifier, never reused during a boot.
    pub id: u64,
    /// Lookup name (unique).
    pub name: String,
    /// Physical base address, page aligned.
    pub phys: PhysAddr,
    /// Object length in bytes (a multiple of [`PAGE_SIZE`]).
    pub len: u64,
    /// Object attributes.
    pub flags: TypedMemFlags,
    /// Silo that owns / is charged for the object, when known.
    pub owner: Option<SiloId>,
    /// Whether the frames came from the buddy allocator and must be freed.
    allocated: bool,
    /// Buddy order used by [`allocate`]; `0` for externally reserved ranges.
    order: u8,
}

impl TypedMemoryObject {
    /// True when [`release`] will return the frames to the buddy allocator.
    pub fn is_allocated(&self) -> bool {
        self.allocated
    }

    /// Buddy order of the allocation (`0` for registered ranges).
    pub fn order(&self) -> u8 {
        self.order
    }

    /// End physical address, exclusive.
    pub fn end(&self) -> u64 {
        self.phys.as_u64().saturating_add(self.len)
    }

    /// True when `[phys, phys + len)` lies entirely inside this object.
    pub fn contains_range(&self, phys: PhysAddr, len: u64) -> bool {
        let start = phys.as_u64();
        start >= self.phys.as_u64() && start.saturating_add(len) <= self.end()
    }
}

/// Typed-memory registry errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypedMemError {
    /// Another object already uses this name.
    AlreadyExists,
    /// No object with this name / id.
    NotFound,
    /// Empty or oversized name.
    InvalidName,
    /// Length not page-aligned, zero, or beyond the buddy's maximum order.
    InvalidLength,
    /// The buddy allocator could not provide a contiguous block.
    OutOfMemory,
}

static REGISTRY: SpinLock<Vec<TypedMemoryObject>> = SpinLock::new(Vec::new());
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

fn validate_name(name: &str) -> Result<(), TypedMemError> {
    if name.is_empty() || name.len() > MAX_NAME_LEN || name.as_bytes().contains(&0) {
        return Err(TypedMemError::InvalidName);
    }
    Ok(())
}

/// Round a byte length up to whole pages.
pub fn pages_for_len(len: u64) -> Option<usize> {
    if len == 0 {
        return None;
    }
    let pages = len.checked_add(PAGE_SIZE - 1)? / PAGE_SIZE;
    usize::try_from(pages).ok()
}

/// Smallest buddy order covering `pages` pages.
pub fn order_for_pages(pages: usize) -> Option<u8> {
    if pages == 0 {
        return None;
    }
    if pages == 1 {
        return Some(0);
    }
    let pow2 = pages.checked_next_power_of_two()?;
    u8::try_from(pow2.trailing_zeros()).ok()
}

/// Registers an already reserved physical range.
///
/// `phys` and `len` must be page aligned. The caller keeps ownership of the
/// memory: [`release`] only removes the registry entry.
pub fn register(
    name: &str,
    phys: PhysAddr,
    len: u64,
    flags: TypedMemFlags,
    owner: Option<SiloId>,
) -> Result<u64, TypedMemError> {
    validate_name(name)?;
    if len == 0
        || len % PAGE_SIZE != 0
        || phys.as_u64() % PAGE_SIZE != 0
        || phys.as_u64().checked_add(len).is_none()
    {
        return Err(TypedMemError::InvalidLength);
    }

    let mut registry = REGISTRY.lock();
    if registry.iter().any(|object| object.name == name) {
        return Err(TypedMemError::AlreadyExists);
    }
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    registry.push(TypedMemoryObject {
        id,
        name: String::from(name),
        phys,
        len,
        flags,
        owner,
        allocated: false,
        order: 0,
    });
    Ok(id)
}

/// Allocates a physically contiguous typed-memory object from the buddy.
///
/// The stored `len` is the rounded-up power-of-two block actually allocated
/// (`PAGE_SIZE << order`), not the requested byte count.
pub fn allocate(
    name: &str,
    len: u64,
    flags: TypedMemFlags,
    owner: Option<SiloId>,
) -> Result<u64, TypedMemError> {
    validate_name(name)?;
    let pages = pages_for_len(len).ok_or(TypedMemError::InvalidLength)?;
    let order = order_for_pages(pages).ok_or(TypedMemError::InvalidLength)?;
    if order > MAX_ORDER {
        return Err(TypedMemError::InvalidLength);
    }
    if REGISTRY.lock().iter().any(|object| object.name == name) {
        return Err(TypedMemError::AlreadyExists);
    }

    let frame = with_irqs_disabled(|token| allocate_phys_contiguous(token, order))
        .map_err(|_| TypedMemError::OutOfMemory)?;
    let phys = frame.start_address;
    let allocated_len = PAGE_SIZE << order;

    let mut registry = REGISTRY.lock();
    // Recheck: another CPU may have registered the same name while the
    // allocation ran without the registry lock held.
    if registry.iter().any(|object| object.name == name) {
        drop(registry);
        with_irqs_disabled(|token| free_phys_contiguous(token, frame, order));
        return Err(TypedMemError::AlreadyExists);
    }

    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    registry.push(TypedMemoryObject {
        id,
        name: String::from(name),
        phys,
        len: allocated_len,
        flags,
        owner,
        allocated: true,
        order,
    });
    Ok(id)
}

/// Looks an object up by name.
pub fn lookup(name: &str) -> Option<TypedMemoryObject> {
    REGISTRY
        .lock()
        .iter()
        .find(|object| object.name == name)
        .cloned()
}

/// Looks an object up by identifier.
pub fn by_id(id: u64) -> Option<TypedMemoryObject> {
    REGISTRY
        .lock()
        .iter()
        .find(|object| object.id == id)
        .cloned()
}

/// Returns a snapshot of every registered object.
pub fn list() -> Vec<TypedMemoryObject> {
    REGISTRY.lock().clone()
}

/// Number of registered objects.
pub fn count() -> usize {
    REGISTRY.lock().len()
}

/// Total bytes described by the registry.
pub fn total_bytes() -> u64 {
    REGISTRY
        .lock()
        .iter()
        .fold(0u64, |sum, object| sum.saturating_add(object.len))
}

/// True when `[phys, phys + len)` is covered by some registered object.
pub fn contains_range(phys: PhysAddr, len: u64) -> bool {
    REGISTRY
        .lock()
        .iter()
        .any(|object| object.contains_range(phys, len))
}

/// Removes an object, freeing its frames when it was buddy-allocated.
pub fn release(name: &str) -> Result<(), TypedMemError> {
    let object = {
        let mut registry = REGISTRY.lock();
        let index = registry
            .iter()
            .position(|object| object.name == name)
            .ok_or(TypedMemError::NotFound)?;
        registry.remove(index)
    };

    if object.allocated {
        let frame = PhysFrame::containing_address(object.phys);
        with_irqs_disabled(|token| free_phys_contiguous(token, frame, object.order));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_round_up_to_whole_pages() {
        assert_eq!(pages_for_len(1), Some(1));
        assert_eq!(pages_for_len(PAGE_SIZE), Some(1));
        assert_eq!(pages_for_len(PAGE_SIZE + 1), Some(2));
        assert_eq!(pages_for_len(0), None);
    }

    #[test]
    fn order_is_the_smallest_power_of_two() {
        assert_eq!(order_for_pages(1), Some(0));
        assert_eq!(order_for_pages(2), Some(1));
        assert_eq!(order_for_pages(3), Some(2));
        assert_eq!(order_for_pages(4), Some(2));
        assert_eq!(order_for_pages(0), None);
    }

    #[test]
    fn names_are_validated() {
        assert_eq!(validate_name(""), Err(TypedMemError::InvalidName));
        assert!(validate_name("dma-ring").is_ok());
        assert_eq!(
            validate_name(&"x".repeat(MAX_NAME_LEN + 1)),
            Err(TypedMemError::InvalidName)
        );
    }

    #[test]
    fn register_lookup_release_roundtrip() {
        let name = "typed-mem-unit-test";
        let base = PhysAddr::new(0x1000_0000);
        let id = register(name, base, PAGE_SIZE, TypedMemFlags::NONE, None).unwrap();
        assert_eq!(
            by_id(id).map(|object| object.name),
            Some(String::from(name))
        );
        assert!(contains_range(base, PAGE_SIZE));
        assert!(register(name, base, PAGE_SIZE, TypedMemFlags::NONE, None).is_err());
        release(name).unwrap();
        assert!(lookup(name).is_none());
    }
}
