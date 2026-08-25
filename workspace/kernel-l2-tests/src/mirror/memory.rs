//! Mirror of kernel/src/memory — the allocator core, verbatim.
//!
//! Included modules: `boot_alloc`, `zone`, `frame`, `buddy`.
//! Faked at this level: HHDM translation (fixed offset), everything
//! else is the real kernel code under test.

// ---------------------------------------------------------------------------
// Fake address-translation helpers (kernel/src/memory/mod.rs equivalents)
// ---------------------------------------------------------------------------

/// Fixed fake HHDM offset used by all host tests (64 GiB mark).
pub const FAKE_HHDM: u64 = 0x10_0000_0000;

static HHDM_OFFSET: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(FAKE_HHDM);

pub fn set_hhdm_offset(offset: u64) {
    HHDM_OFFSET.store(offset, core::sync::atomic::Ordering::Relaxed);
}

pub fn hhdm_offset() -> u64 {
    HHDM_OFFSET.load(core::sync::atomic::Ordering::Relaxed)
}

#[inline]
pub fn phys_to_virt(phys: u64) -> u64 {
    phys.wrapping_add(HHDM_OFFSET.load(core::sync::atomic::Ordering::Relaxed))
}

#[inline]
pub fn virt_to_phys(virt: u64) -> u64 {
    virt.wrapping_sub(HHDM_OFFSET.load(core::sync::atomic::Ordering::Relaxed))
}

// ---------------------------------------------------------------------------
// Real kernel modules
// ---------------------------------------------------------------------------

#[path = "../../../kernel/src/memory/boot_alloc.rs"]
pub mod boot_alloc;
#[path = "../../../kernel/src/memory/zone.rs"]
pub mod zone;
#[path = "../../../kernel/src/memory/frame.rs"]
pub mod frame;
#[path = "../../../kernel/src/memory/buddy.rs"]
pub mod buddy;

/// Fake paging check: on the host every HHDM page is trivially "mapped".
pub mod paging {
    pub fn is_hhdm_range_mapped_now(_phys_base: u64, _size: u64) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// memory/mod.rs surface used by included modules (allocate_frame/free_frame)
// ---------------------------------------------------------------------------

use crate::sync::IrqDisabledToken;

pub use frame::{AllocError, PhysFrame};

/// Mirror of memory/mod.rs `allocate_frame`: order-0 buddy alloc.
#[inline]
pub fn allocate_frame(token: &IrqDisabledToken) -> Result<PhysFrame, AllocError> {
    buddy::alloc(token, 0)
}

/// Mirror of memory/mod.rs `free_frame`.
#[inline]
pub fn free_frame(token: &IrqDisabledToken, frame: PhysFrame) {
    buddy::free(token, frame, 0);
}

/// Mirror of memory/mod.rs `allocate_frames`.
#[inline]
pub fn allocate_frames(token: &IrqDisabledToken, order: u8) -> Result<PhysFrame, AllocError> {
    buddy::alloc(token, order)
}

/// Mirror of memory/mod.rs `free_frames`.
#[inline]
pub fn free_frames(token: &IrqDisabledToken, frame: PhysFrame, order: u8) {
    buddy::free(token, frame, order);
}
