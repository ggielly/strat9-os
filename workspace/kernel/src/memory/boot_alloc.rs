//! Boot-time Bump Allocator
//!
//! Provides a simple, lock-free (single-threaded boot) allocator for
//! critical kernel structures like AP stacks before the full buddy
//! allocator and scheduler are active.
//!
//! The pool lives in the kernel's .bss section (1 MiB).  All allocations
//! are permanent — there is no deallocation.  This is intentional: boot
//! structures (AP kernel stacks) must outlive the boot phase.
//!
//! NOTE: stacks allocated here do NOT have a guard page.  A stack overflow
//! on an AP will silently corrupt adjacent boot-pool memory.  Once the
//! scheduler creates tasks through the normal path (KernelStack::allocate),
//! those stacks do get proper guard-page protection.

use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicUsize, Ordering},
};

/// Size of the static boot allocation pool (1 MiB).
const BOOT_POOL_SIZE: usize = 1024 * 1024;

/// Wrapper to hold the boot pool in a `UnsafeCell` instead of `static mut`.
///
/// `static mut` is deprecated in Rust 2024 edition and any aliased reference
/// to it is UB.  `UnsafeCell` is the correct primitive for interior mutability.
#[repr(C, align(4096))]
struct BootPool(UnsafeCell<[u8; BOOT_POOL_SIZE]>);

// SAFETY: The boot pool is only accessed during the single-threaded BSP boot
// phase (before APs are started).  The atomic bump pointer serializes access
// if it were ever used concurrently.
unsafe impl Sync for BootPool {}

static BOOT_POOL: BootPool = BootPool(UnsafeCell::new([0; BOOT_POOL_SIZE]));

/// Current offset in the boot pool (bump pointer).
static BOOT_PTR: AtomicUsize = AtomicUsize::new(0);

/// Allocate a block of memory from the boot pool.
///
/// Returns a pointer to a 16-byte-aligned region of `size` bytes, or `None`
/// if the pool is exhausted.  This is intended for use during the
/// single-threaded boot phase only.
pub fn alloc(size: usize) -> Option<*mut u8> {
    let aligned_size = (size + 15) & !15;

    let old_ptr = BOOT_PTR.fetch_add(aligned_size, Ordering::Relaxed);
    if old_ptr + aligned_size > BOOT_POOL_SIZE {
        // Roll back so the counter doesn't drift (best-effort).
        BOOT_PTR.fetch_sub(aligned_size, Ordering::Relaxed);
        return None;
    }

    // SAFETY: `old_ptr` is within [0, BOOT_POOL_SIZE - aligned_size].
    // The boot pool is only accessed during the single-threaded BSP phase.
    let base = BOOT_POOL.0.get() as *mut u8;
    unsafe { Some(base.add(old_ptr)) }
}

/// Helper to allocate a stack and return its top (highest address).
pub fn alloc_stack(size: usize) -> Option<u64> {
    let base = alloc(size)?;
    Some(base as u64 + size as u64)
}
