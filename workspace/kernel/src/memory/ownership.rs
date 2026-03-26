//! Central ownership tracking for physical blocks.

use alloc::collections::BTreeMap;

use smallvec::{smallvec, SmallVec};

use crate::{capability::CapId, sync::SpinLock};

use super::{
    block::{BlockHandle, BuddyReserved, Exclusive, PhysBlock, Released},
    block_meta::get_block_meta,
};

/// Runtime ownership state of a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BlockState {
    /// Block reserved by the buddy and not yet claimed.
    BuddyReserved = 0,
    /// Block exclusively owned by a single capability.
    Exclusive = 1,
    /// Block shared by multiple capabilities.
    Shared = 2,
    /// Block released to the buddy-facing state.
    Free = 3,
}

/// Ownership entry associated with a block.
#[derive(Debug, Clone)]
pub struct OwnerEntry {
    /// Current runtime state of the block.
    pub state: BlockState,
    /// Number of capabilities referencing the block.
    pub refcount: u32,
    /// Capabilities that currently reference the block.
    pub caps: SmallVec<[CapId; 4]>,
    /// Temporary non-capability pins held while publishing or revoking a mapping.
    pub transient_refs: u32,
}

/// Errors returned by the ownership layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerError {
    /// The block has no ownership entry.
    NotFound,
    /// The block has already been claimed.
    DoubleClaim,
    /// The capability is already recorded for the block.
    CapAlreadyPresent,
    /// The capability is not recorded for the block.
    CapNotFound,
    /// The block still has live references after a release attempt.
    StillReferenced,
    /// The reference count cannot be represented in `u32`.
    CountOverflow,
}

/// Result of removing one capability reference from a block.
#[derive(Debug)]
pub enum RemoveRefResult {
    /// The block has no remaining owners and can return to the buddy.
    Freed(PhysBlock<Released>),
    /// Exactly one owner remains.
    NowExclusive {
        /// The last remaining capability.
        remaining_cap: CapId,
    },
    /// Multiple owners still reference the block.
    StillShared {
        /// Current shared reference count.
        refcount: u32,
    },
}

/// Source of truth for block ownership.
pub struct OwnershipTable {
    entries: SpinLock<BTreeMap<BlockHandle, OwnerEntry>>,
}

impl OwnershipTable {
    /// Creates an empty ownership table.
    pub fn new() -> Self {
        Self {
            entries: SpinLock::new(BTreeMap::new()),
        }
    }

    fn sync_meta(handle: BlockHandle, refcount: u32) {
        let meta = get_block_meta(handle.base);
        meta.set_order(handle.order);
        meta.set_refcount(refcount);
    }

    fn classify_refcount(refcount: u32) -> BlockState {
        if refcount <= 1 {
            BlockState::Exclusive
        } else {
            BlockState::Shared
        }
    }

    fn total_refs(entry: &OwnerEntry) -> Result<u32, OwnerError> {
        let cap_refs = u32::try_from(entry.caps.len()).map_err(|_| OwnerError::CountOverflow)?;
        cap_refs
            .checked_add(entry.transient_refs)
            .ok_or(OwnerError::CountOverflow)
    }

    /// Claims a reserved block for the provided capability.
    pub fn claim(
        &self,
        block: PhysBlock<BuddyReserved>,
        cap_id: CapId,
    ) -> Result<PhysBlock<Exclusive>, OwnerError> {
        let handle = block.handle();
        let mut entries = self.entries.lock();
        if entries.contains_key(&handle) {
            return Err(OwnerError::DoubleClaim);
        }
        entries.insert(
            handle,
            OwnerEntry {
                state: BlockState::Exclusive,
                refcount: 1,
                caps: smallvec![cap_id],
                transient_refs: 0,
            },
        );
        Self::sync_meta(handle, 1);
        Ok(block.into_exclusive())
    }

    /// Ensures `cap_id` is recorded as a live reference on `handle`.
    pub fn ensure_ref(&self, handle: BlockHandle, cap_id: CapId) -> Result<BlockState, OwnerError> {
        let mut entries = self.entries.lock();
        if let Some(entry) = entries.get_mut(&handle) {
            if entry.caps.iter().any(|existing| *existing == cap_id) {
                return Err(OwnerError::CapAlreadyPresent);
            }
            entry.caps.push(cap_id);
            entry.refcount = Self::total_refs(entry)?;
            entry.state = Self::classify_refcount(entry.refcount);
            Self::sync_meta(handle, entry.refcount);
            Ok(entry.state)
        } else {
            entries.insert(
                handle,
                OwnerEntry {
                    state: BlockState::Exclusive,
                    refcount: 1,
                    caps: smallvec![cap_id],
                    transient_refs: 0,
                },
            );
            Self::sync_meta(handle, 1);
            Ok(BlockState::Exclusive)
        }
    }

    /// Adds a capability reference to an existing owned block.
    pub fn add_ref(&self, handle: BlockHandle, cap_id: CapId) -> Result<BlockState, OwnerError> {
        let mut entries = self.entries.lock();
        let entry = entries.get_mut(&handle).ok_or(OwnerError::NotFound)?;
        if entry.caps.iter().any(|existing| *existing == cap_id) {
            return Err(OwnerError::CapAlreadyPresent);
        }

        entry.caps.push(cap_id);
        entry.refcount = Self::total_refs(entry)?;
        entry.state = Self::classify_refcount(entry.refcount);
        Self::sync_meta(handle, entry.refcount);

        Ok(entry.state)
    }

    /// Adds a temporary pin to keep the block alive while publishing a mapping.
    pub fn pin(&self, handle: BlockHandle) -> Result<u32, OwnerError> {
        let mut entries = self.entries.lock();
        let entry = entries.entry(handle).or_insert_with(|| OwnerEntry {
            state: BlockState::Exclusive,
            refcount: 0,
            caps: smallvec![],
            transient_refs: 0,
        });
        entry.transient_refs = entry
            .transient_refs
            .checked_add(1)
            .ok_or(OwnerError::CountOverflow)?;
        entry.refcount = Self::total_refs(entry)?;
        entry.state = Self::classify_refcount(entry.refcount);
        Self::sync_meta(handle, entry.refcount);
        Ok(entry.refcount)
    }

    /// Removes a capability reference from a block.
    pub fn remove_ref(
        &self,
        handle: BlockHandle,
        cap_id: CapId,
    ) -> Result<RemoveRefResult, OwnerError> {
        let mut entries = self.entries.lock();
        let entry = entries.get_mut(&handle).ok_or(OwnerError::NotFound)?;
        let position = entry
            .caps
            .iter()
            .position(|existing| *existing == cap_id)
            .ok_or(OwnerError::CapNotFound)?;

        entry.caps.remove(position);
        entry.refcount = Self::total_refs(entry)?;

        match entry.refcount {
            0 => {
                entries.remove(&handle);
                Self::sync_meta(handle, 0);
                Ok(RemoveRefResult::Freed(PhysBlock::from_handle(handle)))
            }
            1 => {
                entry.state = BlockState::Exclusive;
                Self::sync_meta(handle, entry.refcount);
                Ok(RemoveRefResult::NowExclusive {
                    remaining_cap: entry.caps[0],
                })
            }
            refcount => {
                entry.state = BlockState::Shared;
                Self::sync_meta(handle, entry.refcount);
                Ok(RemoveRefResult::StillShared { refcount })
            }
        }
    }

    /// Removes one temporary pin and releases the block if this was the last live reference.
    pub fn unpin(&self, handle: BlockHandle) -> Result<RemoveRefResult, OwnerError> {
        let mut entries = self.entries.lock();
        let entry = entries.get_mut(&handle).ok_or(OwnerError::NotFound)?;
        if entry.transient_refs == 0 {
            return Err(OwnerError::CapNotFound);
        }

        entry.transient_refs -= 1;
        entry.refcount = Self::total_refs(entry)?;

        match entry.refcount {
            0 => {
                entries.remove(&handle);
                Self::sync_meta(handle, 0);
                Ok(RemoveRefResult::Freed(PhysBlock::from_handle(handle)))
            }
            1 => {
                entry.state = BlockState::Exclusive;
                Self::sync_meta(handle, entry.refcount);
                Ok(RemoveRefResult::NowExclusive {
                    remaining_cap: entry.caps[0],
                })
            }
            refcount => {
                entry.state = BlockState::Shared;
                Self::sync_meta(handle, entry.refcount);
                Ok(RemoveRefResult::StillShared { refcount })
            }
        }
    }

    /// Releases an exclusive block and returns a buddy-facing handle if it becomes free.
    pub fn release(
        &self,
        block: PhysBlock<Exclusive>,
        cap_id: CapId,
    ) -> Result<PhysBlock<Released>, OwnerError> {
        match self.remove_ref(block.handle(), cap_id)? {
            RemoveRefResult::Freed(released) => Ok(released),
            RemoveRefResult::NowExclusive { .. } | RemoveRefResult::StillShared { .. } => {
                Err(OwnerError::StillReferenced)
            }
        }
    }

    /// Returns a snapshot of the ownership entry for the given block.
    pub fn get(&self, handle: BlockHandle) -> Option<OwnerEntry> {
        self.entries.lock().get(&handle).cloned()
    }

    /// Returns the live handle whose base physical address matches `base`, if any.
    pub fn handle_for_base(&self, base: x86_64::PhysAddr) -> Option<BlockHandle> {
        self.entries
            .lock()
            .keys()
            .find(|handle| handle.base == base)
            .copied()
    }

    /// Returns the current reference count for the given block.
    pub fn refcount(&self, handle: BlockHandle) -> Option<u32> {
        self.entries.lock().get(&handle).map(|entry| entry.refcount)
    }
}

impl Default for OwnershipTable {
    /// Creates an empty ownership table.
    fn default() -> Self {
        Self::new()
    }
}
