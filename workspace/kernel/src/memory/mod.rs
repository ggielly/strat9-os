// Memory management module

pub mod address_space;
pub mod block;
pub mod block_meta;
pub mod boot_alloc;
pub mod buddy;
pub mod cow;
pub mod frame;
pub mod heap;
pub mod mapping_index;
pub mod ownership;
pub mod paging;
pub mod region_cap;
pub mod userslice;
pub mod vmalloc;
pub mod zone;

use crate::{
    boot::entry::MemoryRegion, capability::CapId, process::get_task_by_pid, sync::IrqDisabledToken,
};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Once;

/// Higher Half Direct Map offset.
/// Set by Limine entry (non-zero) or left at 0 for BIOS/identity-mapped boot.
/// All physical-to-virtual conversions must add this offset.
static HHDM_OFFSET: AtomicU64 = AtomicU64::new(0);

/// Store the HHDM offset (call once, early in boot)
pub fn set_hhdm_offset(offset: u64) {
    HHDM_OFFSET.store(offset, Ordering::Relaxed);
}

/// Get the current HHDM offset
pub fn hhdm_offset() -> u64 {
    HHDM_OFFSET.load(Ordering::Relaxed)
}

/// Convert a physical address to a virtual address using the HHDM offset
#[inline]
pub fn phys_to_virt(phys: u64) -> u64 {
    phys.wrapping_add(HHDM_OFFSET.load(Ordering::Relaxed))
}

/// Convert a virtual address back to a physical address (reverse of phys_to_virt)
#[inline]
pub fn virt_to_phys(virt: u64) -> u64 {
    virt.wrapping_sub(HHDM_OFFSET.load(Ordering::Relaxed))
}

/// Initialize the memory management subsystem
pub fn init_memory_manager(memory_regions: &[MemoryRegion]) {
    buddy::init_buddy_allocator(memory_regions);
    // Race/corruption diagnostic: register slab lock for E9 LOCK-A/LOCK-R traces.
    heap::debug_register_slab_trace();
}

/// Initialize copy-on-write metadata.
pub fn init_cow_subsystem(_memory_regions: &[MemoryRegion]) {}

static OWNERSHIP_TABLE: Once<OwnershipTable> = Once::new();
static GLOBAL_MAPPING_INDEX: Once<MappingIndex> = Once::new();
static MEMORY_REGION_REGISTRY: Once<MemoryRegionRegistry> = Once::new();

// Re-exports
pub use crate::sync::with_irqs_disabled;
pub use address_space::{
    kernel_address_space, AddressSpace, EffectiveMapping, VmaFlags, VmaPageSize, VmaType,
};
pub use block::{
    BlockHandle, BuddyReserved, Exclusive, MappedExclusive, MappedShared, PhysBlock, Released,
};
pub use block_meta::{get_block_meta, resolve_handle};
pub use buddy::get_allocator;
pub use frame::{AllocError, FrameAllocOptions, FrameAllocator, FramePurpose, PhysFrame};
pub use heap::KernelHeapBackend;
pub use mapping_index::{MappingIndex, MappingRef};
pub use ownership::{BlockState, OwnerEntry, OwnerError, OwnershipTable, RemoveRefResult};
pub use region_cap::{
    MemoryRegionRegistry, PublicMemoryRegionInfo, RegionCapError, ReleaseRegionResult,
};
pub use userslice::{UserSliceError, UserSliceRead, UserSliceReadWrite, UserSliceWrite};

/// Returns the global ownership table used by the memory runtime.
pub fn ownership_table() -> &'static OwnershipTable {
    OWNERSHIP_TABLE.call_once(OwnershipTable::new)
}

/// Returns the global reverse mapping index used by the memory runtime.
pub fn mapping_index() -> &'static MappingIndex {
    GLOBAL_MAPPING_INDEX.call_once(MappingIndex::new)
}

/// Returns the global public memory-region registry.
pub fn memory_region_registry() -> &'static MemoryRegionRegistry {
    MEMORY_REGION_REGISTRY.call_once(MemoryRegionRegistry::new)
}

/// Allocates a fresh internal mapping capability identifier.
pub fn allocate_mapping_cap_id() -> CapId {
    CapId::new()
}

/// Records that `cap_id` now names `handle` in the ownership table.
pub fn register_mapping_identity(handle: BlockHandle, cap_id: CapId) {
    match try_register_mapping_identity(handle, cap_id) {
        Ok(_) | Err(OwnerError::CapAlreadyPresent) => {}
        Err(error) => {
            log::warn!(
                "memory: failed to register block identity cap={} handle={:#x}/{}: {:?}",
                cap_id.as_u64(),
                handle.base.as_u64(),
                handle.order,
                error
            );
        }
    }
}

/// Fallible variant of mapping identity registration for transactional callers.
pub fn try_register_mapping_identity(handle: BlockHandle, cap_id: CapId) -> Result<(), OwnerError> {
    ownership_table().ensure_ref(handle, cap_id).map(|_| ())
}

/// Releases a block back to the buddy allocator.
pub fn release_owned_block(block: PhysBlock<Released>) {
    let handle = block.into_handle();
    with_irqs_disabled(|token| {
        buddy::free(
            token,
            PhysFrame {
                start_address: handle.base,
            },
            handle.order,
        );
    });
}

/// Removes `cap_id` from the ownership table entry associated with `handle`.
pub fn unregister_mapping_identity(
    handle: BlockHandle,
    cap_id: CapId,
) -> Option<PhysBlock<Released>> {
    match ownership_table().remove_ref(handle, cap_id) {
        Ok(RemoveRefResult::Freed(block)) => Some(block),
        Ok(_) | Err(OwnerError::NotFound) | Err(OwnerError::CapNotFound) => None,
        Err(error) => {
            log::warn!(
                "memory: failed to unregister mapping identity cap={} handle={:#x}/{}: {:?}",
                cap_id.as_u64(),
                handle.base.as_u64(),
                handle.order,
                error
            );
            None
        }
    }
}

/// Revokes every live mapping associated with `cap_id`.
pub fn revoke_mapping_cap_id(cap_id: CapId) -> usize {
    let mappings = mapping_index().lookup(cap_id);
    let mut revoked = 0usize;

    for mapping in mappings {
        let Some(task) = get_task_by_pid(mapping.pid) else {
            mapping_index().unregister(cap_id, mapping.pid, mapping.vaddr);
            continue;
        };

        let address_space = task.process.address_space_arc();
        match address_space.unmap_effective_mapping(mapping.vaddr.as_u64()) {
            Ok(()) => {
                revoked = revoked.saturating_add(1);
            }
            Err(error) => {
                if address_space
                    .effective_mapping_by_start(mapping.vaddr.as_u64())
                    .is_none()
                {
                    mapping_index().unregister(cap_id, mapping.pid, mapping.vaddr);
                } else {
                    log::warn!(
                        "memory: failed to revoke mapping cap={} pid={} vaddr={:#x}: {}",
                        cap_id.as_u64(),
                        mapping.pid,
                        mapping.vaddr.as_u64(),
                        error
                    );
                }
            }
        }
    }

    if revoked != 0 {
        crate::arch::x86_64::tlb::shootdown_all();
    }

    revoked
}

/// Allocate `2^order` contiguous physical frames (raw, no zeroing).
///
/// **Deprecated** — use [`allocate_phys_contiguous`] for DMA / hardware-ring
/// allocations where physical contiguity is the explicit requirement, or
/// [`allocate_frame`] for single kernel-data frames.  This name remains for
/// internal callers that pre-date the explicit-intent API.
#[deprecated(
    note = "use allocate_phys_contiguous() for DMA/contiguous allocations, \
            or allocate_frame() for single kernel-data frames"
)]
#[inline]
pub fn allocate_frames(token: &IrqDisabledToken, order: u8) -> Result<PhysFrame, AllocError> {
    buddy::alloc(token, order)
}

/// Allocate a physically contiguous block of `2^order` pages.
///
/// This is the explicit contiguous-physical allocator for DMA rings,
/// MMIO-adjacent buffers, large hardware descriptors, and similar cases
/// where physical contiguity is the actual requirement.
#[inline]
pub fn allocate_phys_contiguous(
    token: &IrqDisabledToken,
    order: u8,
) -> Result<PhysFrame, AllocError> {
    buddy::alloc(token, order)
}

/// Free `2^order` contiguous physical frames.
///
/// **Deprecated** — use [`free_phys_contiguous`] for blocks returned by
/// [`allocate_phys_contiguous`], or [`free_frame`] for single frames.
#[deprecated(
    note = "use free_phys_contiguous() for blocks from allocate_phys_contiguous, \
            or free_frame() for single frames"
)]
#[inline]
pub fn free_frames(token: &IrqDisabledToken, frame: PhysFrame, order: u8) {
    buddy::free(token, frame, order);
}

/// Free a physically contiguous block previously returned by
/// [`allocate_phys_contiguous`].
#[inline]
pub fn free_phys_contiguous(token: &IrqDisabledToken, frame: PhysFrame, order: u8) {
    buddy::free(token, frame, order);
}

/// Allocate a single **zeroed** physical frame with `KernelData` purpose.
///
/// This is the standard allocation path for all kernel-internal frames.  It
/// uses `FrameAllocOptions::new()` (zeroed = true, purpose = KernelData) and
/// performs the UNUSED → 0 → 1 refcount CAS (Asterinas OSTD pattern).
///
/// For page-table node allocation use `BuddyFrameAllocator` (via paging.rs)
/// or `FrameAllocOptions::new().purpose(FramePurpose::PageTable).allocate()`.
/// For user-space frames use `FrameAllocOptions::new().purpose(FramePurpose::UserData)`.
#[inline]
pub fn allocate_frame(token: &IrqDisabledToken) -> Result<PhysFrame, AllocError> {
    FrameAllocOptions::new().allocate(token)
}

/// Free a single physical frame.
/// Requires an `IrqDisabledToken` proving that IRQs are disabled on the calling CPU.
/// The caller must ensure that the frame is not currently mapped anywhere and that
/// the buddy allocator's internal metadata is consistent with the frame's state (e.g. refcount = 0).
/// Prefer `free_frames()` for multi-frame blocks or when the buddy allocator's internal state may need to be updated.
/// This raw path is kept for symmetry with `allocate_frames()` and for special cases where the caller manages zeroing and metadata explicitly.
/// For standard single-frame deallocation, prefer `release_owned_block()` which also handles ownership table updates and safety checks.
#[inline]
pub fn free_frame(token: &IrqDisabledToken, frame: PhysFrame) {
    buddy::free(token, frame, 0);
}

/// Allocate virtually contiguous kernel memory backed by fragmented physical
/// pages.
///
/// This is the explicit large-allocation API for kernel callers that require a
/// large contiguous virtual range but do not require physical contiguity.
#[inline]
pub fn allocate_kernel_virtual(
    size: usize,
    token: &IrqDisabledToken,
) -> Result<*mut u8, vmalloc::VmallocError> {
    vmalloc::vmalloc(size, token)
}

/// Free memory previously returned by [`allocate_kernel_virtual`].
#[inline]
pub fn free_kernel_virtual(ptr: *mut u8, token: &IrqDisabledToken) {
    vmalloc::vfree(ptr, token);
}

/// Allocate a zeroed 4 KiB frame suitable for DMA operations.
///
/// Disables IRQs internally.  The frame is zeroed before being returned
/// (guaranteed by `FrameAllocOptions::new()` — zeroed = true by default).
pub fn allocate_dma_frame() -> Option<PhysFrame> {
    with_irqs_disabled(|token| {
        // `FrameAllocOptions::new()` defaults to zeroed = true; no manual
        // `write_bytes` call is needed here any more.
        FrameAllocOptions::new()
            .purpose(FramePurpose::KernelData)
            .allocate(token)
            .ok()
    })
}
