//! Boot-time Bump Allocator
//!
//! Provides a simple, lock-free (single-threaded boot) allocator for
//! critical kernel structures like AP stacks before the full buddy
//! allocator and scheduler are active.

use crate::memory::{hhdm_offset, phys_to_virt};
use core::sync::atomic::{AtomicUsize, Ordering};

/// Size of the static boot allocation pool (1 MiB).
const BOOT_POOL_SIZE: usize = 1024 * 1024;

/// Static buffer for early kernel allocations.
/// This is placed in the kernel's .bss section.
static mut BOOT_POOL: [u8; BOOT_POOL_SIZE] = [0; BOOT_POOL_SIZE];

/// Current offset in the boot pool.
static BOOT_PTR: AtomicUsize = AtomicUsize::new(0);

/// Allocate a block of memory from the boot pool.
///
/// # Safety
/// This is intended for use during the single-threaded boot phase only.
/// Alignment is forced to 16 bytes.
pub fn alloc(size: usize) -> Option<*mut u8> {
    let size = (size + 15) & !15; // Align to 16 bytes

    let old_ptr = BOOT_PTR.fetch_add(size, Ordering::SeqCst);
    if old_ptr + size > BOOT_POOL_SIZE {
        return None;
    }

    unsafe { Some(BOOT_POOL.as_mut_ptr().add(old_ptr)) }
}

/// Helper to allocate a stack and return its top (highest address).
pub fn alloc_stack(size: usize) -> Option<u64> {
    let base = alloc(size)?;
    Some(base as u64 + size as u64)
}

/// Returns the physical address of a pointer allocated from the boot pool.
pub fn virt_to_phys(virt: *mut u8) -> u64 {
    let hhdm = hhdm_offset();
    let addr = virt as u64;
    if addr >= hhdm {
        addr - hhdm
    } else {
        // Fallback for kernel-base mappings if HHDM is not yet active/correct
        // (Though boot pool is in .bss, usually mapped at kernel offset)
        addr // Should be adjusted based on kernel load offset if needed
    }
}
