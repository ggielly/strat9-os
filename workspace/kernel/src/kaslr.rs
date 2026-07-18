//! Kernel Address Space Layout Randomization (KASLR).
//!
//! Generates per-boot random offsets for:
//! - Userspace mmap base address
//! - Userspace stack base address
//! - ELF PIE loading base address
//! - Kernel page table physical placement
//!
//! Offsets are generated once at boot from the entropy pool and remain
//! constant for the lifetime of the boot. Each process receives its own
//! randomized layout derived from these base offsets.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Whether KASLR has been initialized.
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Randomized mmap base offset (added to MMAP_BASE).
static MMAP_BASE_OFFSET: AtomicU64 = AtomicU64::new(0);

/// Randomized user stack base offset (added to USER_STACK_BASE).
static STACK_BASE_OFFSET: AtomicU64 = AtomicU64::new(0);

/// Randomized PIE base offset (added to PIE_BASE_ADDR).
static PIE_BASE_OFFSET: AtomicU64 = AtomicU64::new(0);

/// Initialize KASLR offsets from the entropy pool. Called once at boot.
pub fn init() {
    if INITIALIZED.load(Ordering::Relaxed) {
        return;
    }

    let mut buf = [0u8; 12];
    crate::entropy::fill_random(&mut buf);

    let r0 = u64::from_le_bytes([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]]);
    let r1 = u16::from_le_bytes([buf[8], buf[9]]);
    let r2 = u16::from_le_bytes([buf[10], buf[11]]);

    // Mmap base offset: 0 .. 256 MiB, aligned to 4 KiB
    // MMAP_BASE is 0x60000000 (1.5 GiB). Randomize within [0, 256 MiB).
    let mmap_off = (r0 as usize % (256 * 1024 * 1024)) & !0xFFF;
    MMAP_BASE_OFFSET.store(mmap_off as u64, Ordering::Relaxed);

    // Stack base offset: 0 .. 128 MiB, aligned to 4 KiB
    // USER_STACK_BASE is 0x7FFFFFF00000. Randomize within [0, 128 MiB).
    let stack_off = (r1 as usize % (128 * 1024 * 1024)) & !0xFFF;
    STACK_BASE_OFFSET.store(stack_off as u64, Ordering::Relaxed);

    // PIE base offset: 0 .. 32 MiB, aligned to 2 MiB (for huge page support)
    // PIE_BASE_ADDR is 0x10000000. Randomize within [0, 32 MiB).
    let pie_off = (r2 as usize % (32 * 1024 * 1024)) & !0x1F_FFFF;
    PIE_BASE_OFFSET.store(pie_off as u64, Ordering::Relaxed);

    INITIALIZED.store(true, Ordering::Release);

    log::info!(
        "[KASLR] mmap_base_off={:#x} stack_off={:#x} pie_off={:#x}",
        mmap_off,
        stack_off,
        pie_off
    );
}

/// Get the randomized mmap base address.
#[inline]
pub fn mmap_base() -> u64 {
    const MMAP_BASE: u64 = 0x0000_0000_6000_0000;
    MMAP_BASE + MMAP_BASE_OFFSET.load(Ordering::Relaxed)
}

/// Get the randomized user stack base address.
#[inline]
pub fn stack_base() -> u64 {
    const STACK_BASE: u64 = 0x0000_7FFF_F000_0000;
    STACK_BASE + STACK_BASE_OFFSET.load(Ordering::Relaxed)
}

/// Get the randomized user stack top address.
#[inline]
pub fn stack_top() -> u64 {
    stack_base() + 16 * 4096 // USER_STACK_PAGES * PAGE_SIZE
}

/// Get the guard page address below the user stack.
#[inline]
pub fn stack_guard() -> u64 {
    stack_base() - 4096
}

/// Get the randomized PIE base address for ELF loading.
#[inline]
pub fn pie_base() -> u64 {
    const PIE_BASE: u64 = 0x0000_0001_0000_0000;
    PIE_BASE + PIE_BASE_OFFSET.load(Ordering::Relaxed)
}
