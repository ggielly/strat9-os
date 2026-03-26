//! Public memory-region capability registry.

use alloc::{collections::BTreeMap, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};

use smallvec::{smallvec, SmallVec};

use crate::{capability::CapId, sync::SpinLock};

use super::{
    address_space::{AddressSpace, VmaFlags, VmaPageSize, VmaType},
    cow, ownership_table, register_mapping_identity, release_owned_block, revoke_mapping_cap_id,
    unregister_mapping_identity, BlockHandle,
};

/// Public metadata about an exported memory region.
#[derive(Debug, Clone, Copy)]
pub struct PublicMemoryRegionInfo {
    /// Total byte size of the region.
    pub size: u64,
    /// Page size used by the region.
    pub page_size: VmaPageSize,
    /// Access flags for the region.
    pub flags: VmaFlags,
}

#[derive(Debug, Clone)]
struct ExportedMemoryRegion {
    size: u64,
    page_size: VmaPageSize,
    flags: VmaFlags,
    vma_type: VmaType,
    handles: Vec<BlockHandle>,
    mapping_cap_ids: Vec<CapId>,
    handle_caps: SmallVec<[CapId; 2]>,
}

/// Errors returned by the public memory-region capability layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionCapError {
    /// The requested region capability does not exist.
    NotFound,
    /// The requested virtual region cannot be exported.
    InvalidRegion,
    /// The region is not fully materialized in the effective mapping table.
    IncompleteRegion,
    /// The target address or range is invalid.
    InvalidAddress,
    /// The caller lacks sufficient permissions for the requested operation.
    PermissionDenied,
    /// The target address space cannot host the mapping.
    OutOfMemory,
}

/// Result of releasing one public region-handle reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseRegionResult {
    /// Other handles still reference the exported region.
    Retained,
    /// This was the last handle and the region descriptor was destroyed.
    Destroyed {
        /// Number of live mappings revoked while destroying the region.
        revoked_mappings: usize,
    },
}

/// Global registry for exported memory-region capabilities.
pub struct MemoryRegionRegistry {
    next_id: AtomicU64,
    entries: SpinLock<BTreeMap<u64, ExportedMemoryRegion>>,
}

impl MemoryRegionRegistry {
    /// Creates an empty memory-region registry.
    pub fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            entries: SpinLock::new(BTreeMap::new()),
        }
    }

    /// Exports the tracked region starting at `start` into a public capability resource.
    pub fn export_region(
        &self,
        address_space: &AddressSpace,
        start: u64,
        handle_cap: CapId,
    ) -> Result<u64, RegionCapError> {
        let region = address_space
            .region_by_start(start)
            .ok_or(RegionCapError::InvalidRegion)?;
        let page_bytes = region.page_size.bytes();
        let size = (region.page_count as u64)
            .checked_mul(page_bytes)
            .ok_or(RegionCapError::InvalidRegion)?;

        let mut handles = Vec::with_capacity(region.page_count);
        let mut mapping_cap_ids = Vec::with_capacity(region.page_count);

        for index in 0..region.page_count {
            let vaddr = start
                .checked_add((index as u64).saturating_mul(page_bytes))
                .ok_or(RegionCapError::InvalidRegion)?;
            let mapping = address_space
                .effective_mapping_by_start(vaddr)
                .ok_or(RegionCapError::IncompleteRegion)?;
            register_mapping_identity(mapping.handle, handle_cap);
            handles.push(mapping.handle);
            mapping_cap_ids.push(mapping.cap_id);
        }

        let resource_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.entries.lock().insert(
            resource_id,
            ExportedMemoryRegion {
                size,
                page_size: region.page_size,
                flags: region.flags,
                vma_type: region.vma_type,
                handles,
                mapping_cap_ids,
                handle_caps: smallvec![handle_cap],
            },
        );
        Ok(resource_id)
    }

    /// Adds one handle reference to an exported memory region.
    pub fn retain_handle(&self, resource_id: u64, handle_cap: CapId) -> Result<(), RegionCapError> {
        let mut entries = self.entries.lock();
        let entry = entries
            .get_mut(&resource_id)
            .ok_or(RegionCapError::NotFound)?;
        if !entry
            .handle_caps
            .iter()
            .any(|existing| *existing == handle_cap)
        {
            for handle in &entry.handles {
                register_mapping_identity(*handle, handle_cap);
            }
            entry.handle_caps.push(handle_cap);
        }
        Ok(())
    }

    /// Returns public metadata about an exported memory region.
    pub fn info(&self, resource_id: u64) -> Option<PublicMemoryRegionInfo> {
        self.entries
            .lock()
            .get(&resource_id)
            .map(|entry| PublicMemoryRegionInfo {
                size: entry.size,
                page_size: entry.page_size,
                flags: entry.flags,
            })
    }

    /// Maps an exported memory region into `address_space`.
    pub fn map_region(
        &self,
        resource_id: u64,
        address_space: &AddressSpace,
        addr_hint: u64,
        requested_flags: VmaFlags,
    ) -> Result<(u64, u64), RegionCapError> {
        let entry = {
            let entries = self.entries.lock();
            let entry = entries.get(&resource_id).ok_or(RegionCapError::NotFound)?;
            let mut pinned = 0usize;
            for handle in &entry.handles {
                match ownership_table().pin(*handle) {
                    Ok(_) => {
                        pinned += 1;
                    }
                    Err(error) => {
                        log::warn!(
                            "memory: failed to pin exported handle resource={} block={:#x}/{}: {:?}",
                            resource_id,
                            handle.base.as_u64(),
                            handle.order,
                            error
                        );
                        for pinned_handle in entry.handles.iter().take(pinned) {
                            cow::handle_dec_ref(*pinned_handle);
                        }
                        return Err(RegionCapError::OutOfMemory);
                    }
                }
            }
            entry.clone()
        };

        let map_result = (|| {
            let effective_flags = VmaFlags {
                readable: entry.flags.readable && requested_flags.readable,
                writable: entry.flags.writable && requested_flags.writable,
                executable: entry.flags.executable && requested_flags.executable,
                user_accessible: true,
            };
            let page_count = entry.handles.len();
            let page_bytes = entry.page_size.bytes();

            let base = if addr_hint != 0 {
                if addr_hint % page_bytes != 0 {
                    return Err(RegionCapError::InvalidAddress);
                }
                address_space
                    .find_free_vma_range(addr_hint, page_count, entry.page_size)
                    .or_else(|| {
                        address_space.find_free_vma_range(
                            crate::syscall::mmap::MMAP_BASE,
                            page_count,
                            entry.page_size,
                        )
                    })
                    .ok_or(RegionCapError::OutOfMemory)?
            } else {
                address_space
                    .find_free_vma_range(
                        crate::syscall::mmap::MMAP_BASE,
                        page_count,
                        entry.page_size,
                    )
                    .ok_or(RegionCapError::OutOfMemory)?
            };

            address_space
                .map_shared_handles_with_cap_ids(
                    base,
                    &entry.handles,
                    Some(&entry.mapping_cap_ids),
                    effective_flags,
                    entry.vma_type,
                    entry.page_size,
                )
                .map(|_| (base, entry.size))
                .map_err(|_| RegionCapError::OutOfMemory)
        })();

        for handle in &entry.handles {
            cow::handle_dec_ref(*handle);
        }

        map_result
    }

    /// Releases one handle reference to an exported memory region.
    pub fn release_handle(
        &self,
        resource_id: u64,
        handle_cap: CapId,
    ) -> Result<ReleaseRegionResult, RegionCapError> {
        let entry = {
            let mut entries = self.entries.lock();
            let current = entries
                .get_mut(&resource_id)
                .ok_or(RegionCapError::NotFound)?;
            let position = current
                .handle_caps
                .iter()
                .position(|existing| *existing == handle_cap)
                .ok_or(RegionCapError::NotFound)?;
            current.handle_caps.remove(position);
            for handle in &current.handles {
                if let Some(block) = unregister_mapping_identity(*handle, handle_cap) {
                    release_owned_block(block);
                }
            }
            if !current.handle_caps.is_empty() {
                return Ok(ReleaseRegionResult::Retained);
            }
            entries
                .remove(&resource_id)
                .ok_or(RegionCapError::NotFound)?
        };

        let mut revoked_mappings = 0usize;
        for cap_id in entry.mapping_cap_ids {
            revoked_mappings = revoked_mappings.saturating_add(revoke_mapping_cap_id(cap_id));
        }

        Ok(ReleaseRegionResult::Destroyed { revoked_mappings })
    }
}

impl Default for MemoryRegionRegistry {
    /// Creates an empty memory-region registry.
    fn default() -> Self {
        Self::new()
    }
}
