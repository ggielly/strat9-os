//! Reverse mapping index for memory capabilities.

use alloc::collections::BTreeMap;

use smallvec::SmallVec;
use x86_64::VirtAddr;

use crate::{
    capability::CapId, memory::address_space::VmaPageSize, process::task::Pid, sync::SpinLock,
};

/// Reference to a concrete mapping in an address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingRef {
    /// Process that owns the address space.
    pub pid: Pid,
    /// Virtual address of the mapping.
    pub vaddr: VirtAddr,
    /// Effective page size of the mapping.
    pub page_size: VmaPageSize,
}

/// Reverse index from capability ID to live mappings.
///
/// The inline capacity of 4 covers the common case (a memory region mapped
/// in the kernel + up to 3 user address spaces) without heap allocation.
/// If a capability ever acquires more than 4 mappings, `SmallVec` spills to
/// the heap while the `SpinLock` is held.  This is not an IRQ path and the
/// heap lock order (mapping_index → heap) does not conflict with any other
/// known lock order, so the spill is not a correctness issue : only a minor
/// latency concern noted in ticket #49.
pub struct MappingIndex {
    index: SpinLock<BTreeMap<CapId, SmallVec<[MappingRef; 4]>>>,
}

impl MappingIndex {
    /// Creates an empty reverse mapping index.
    pub fn new() -> Self {
        Self {
            index: SpinLock::new(BTreeMap::new()),
        }
    }

    /// Registers a mapping for the given capability.
    pub fn register(&self, cap_id: CapId, mapping: MappingRef) {
        let mut index = self.index.lock();
        let mappings = index.entry(cap_id).or_default();
        if !mappings.iter().any(|existing| *existing == mapping) {
            mappings.push(mapping);
        }
    }

    /// Removes a single mapping for the given capability.
    pub fn unregister(&self, cap_id: CapId, pid: Pid, vaddr: VirtAddr) {
        let mut index = self.index.lock();
        let should_remove = if let Some(mappings) = index.get_mut(&cap_id) {
            mappings.retain(|mapping| !(mapping.pid == pid && mapping.vaddr == vaddr));
            mappings.is_empty()
        } else {
            false
        };
        if should_remove {
            index.remove(&cap_id);
        }
    }

    /// Returns a snapshot of the mappings for the given capability.
    pub fn lookup(&self, cap_id: CapId) -> SmallVec<[MappingRef; 4]> {
        self.index.lock().get(&cap_id).cloned().unwrap_or_default()
    }

    /// Removes and returns every mapping associated with the given capability.
    pub fn remove_all(&self, cap_id: CapId) -> SmallVec<[MappingRef; 4]> {
        self.index.lock().remove(&cap_id).unwrap_or_default()
    }
}

impl Default for MappingIndex {
    /// Creates an empty reverse mapping index.
    fn default() -> Self {
        Self::new()
    }
}
