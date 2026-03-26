//! Block-oriented physical memory handles.

use core::marker::PhantomData;
use x86_64::PhysAddr;

use crate::memory::{frame::PAGE_SIZE, zone::MAX_ORDER};

/// Lightweight identifier for a physical block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockHandle {
    /// Base physical address of the block.
    pub base: PhysAddr,
    /// Buddy order of the block.
    pub order: u8,
}

impl BlockHandle {
    /// Creates a new block handle.
    pub fn new(base: PhysAddr, order: u8) -> Self {
        Self { base, order }
    }

    /// Returns the block size in bytes.
    pub fn size_bytes(&self) -> u64 {
        PAGE_SIZE.checked_shl(self.order as u32).unwrap_or(0)
    }

    /// Returns the number of 4 KiB pages covered by the block.
    pub fn page_count(&self) -> u64 {
        1u64.checked_shl(self.order as u32).unwrap_or(0)
    }

    /// Returns `true` when the handle is aligned and within the supported buddy range.
    pub fn is_valid(&self) -> bool {
        let size = self.size_bytes();
        size != 0 && self.order <= MAX_ORDER as u8 && self.base.is_aligned(size)
    }
}

/// State marker for a block reserved by the buddy allocator.
#[derive(Debug)]
pub struct BuddyReserved;

/// State marker for an exclusively owned block.
#[derive(Debug)]
pub struct Exclusive;

/// State marker for an exclusively owned mapped block.
#[derive(Debug)]
pub struct MappedExclusive;

/// State marker for a shared mapped block.
#[derive(Debug)]
pub struct MappedShared;

/// State marker for a block released back to the buddy layer.
#[derive(Debug)]
pub struct Released;

/// Ephemeral typed handle for local state transitions.
#[derive(Debug)]
pub struct PhysBlock<S> {
    handle: BlockHandle,
    _state: PhantomData<S>,
}

impl<S> PhysBlock<S> {
    /// Returns the underlying block handle.
    pub fn handle(&self) -> BlockHandle {
        self.handle
    }

    /// Returns the base physical address of the block.
    pub fn base(&self) -> PhysAddr {
        self.handle.base
    }

    /// Returns the buddy order of the block.
    pub fn order(&self) -> u8 {
        self.handle.order
    }

    /// Creates a typed block from a raw handle.
    pub(crate) fn from_handle(handle: BlockHandle) -> Self {
        Self {
            handle,
            _state: PhantomData,
        }
    }
}

impl PhysBlock<BuddyReserved> {
    /// Transitions a reserved block into exclusive ownership.
    pub(crate) fn into_exclusive(self) -> PhysBlock<Exclusive> {
        PhysBlock::from_handle(self.handle)
    }
}

impl PhysBlock<Exclusive> {
    /// Marks the block as mapped while remaining exclusive.
    pub(crate) fn into_mapped(self) -> PhysBlock<MappedExclusive> {
        PhysBlock::from_handle(self.handle)
    }

    /// Releases the block to the buddy-facing state.
    pub(crate) fn into_released(self) -> PhysBlock<Released> {
        PhysBlock::from_handle(self.handle)
    }
}

impl PhysBlock<MappedExclusive> {
    /// Transitions a mapped exclusive block into a shared mapped block.
    pub(crate) fn into_shared(self) -> PhysBlock<MappedShared> {
        PhysBlock::from_handle(self.handle)
    }

    /// Transitions a mapped exclusive block back to an unmapped exclusive block.
    pub(crate) fn into_unmapped(self) -> PhysBlock<Exclusive> {
        PhysBlock::from_handle(self.handle)
    }
}

impl PhysBlock<MappedShared> {
    /// Transitions a shared mapped block back to a mapped exclusive block.
    pub(crate) fn into_exclusive_mapped(self) -> PhysBlock<MappedExclusive> {
        PhysBlock::from_handle(self.handle)
    }

    /// Rebuilds the shared typed handle after an ownership-layer check.
    pub(crate) fn still_shared(self) -> PhysBlock<MappedShared> {
        self
    }
}

impl PhysBlock<Released> {
    /// Consumes the released block and returns its raw handle.
    pub(crate) fn into_handle(self) -> BlockHandle {
        self.handle
    }
}
