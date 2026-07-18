//! Kernel Address Space Layout Randomization (KASLR).
//!
//! Generates per-boot random offsets for:
//! - Userspace mmap base address
//! - Userspace stack base address
//! - ELF PIE loading base address
//!
//! Offsets are generated once at boot from the entropy pool and remain
//! constant for the lifetime of the boot. Each process receives its own
//! randomized layout derived from these base offsets.
//!
//! # Entropy requirements
//!
//! `init()` calls `entropy::fill_random()` which blocks until the pool
//! has accumulated at least 64 bytes of entropy. On a live system with
//! keyboard/timer interrupts this takes < 1 ms. On QEMU without RDRAND
//! the pool seeds from TSC and accumulates quickly via IRQ noise.

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
///
/// Blocks on `fill_random()` until the entropy pool is seeded.
pub fn init() {
    if INITIALIZED.load(Ordering::Relaxed) {
        return;
    }

    // We need 10 bytes total: 8 for mmap, 1 for stack, 1 for PIE.
    // fill_random writes exactly buf.len() bytes.
    let mut buf = [0u8; 10];
    crate::entropy::fill_random(&mut buf);

    let r0 = u64::from_le_bytes([
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ]);
    // Use low byte for stack offset (1 byte = 0..255 pages = 0..1 MiB)
    let r1 = buf[8];
    // Use low byte for PIE offset (1 byte = 0..15 pages * 2 MiB = 0..30 MiB)
    let r2 = buf[9];

    // Mmap base offset: 0 .. 256 MiB, aligned to 4 KiB.
    // Use bitmask instead of modulo to avoid modulo bias.
    let mmap_off = (r0 & 0x0FFF_FFFF) & !0xFFF;
    MMAP_BASE_OFFSET.store(mmap_off, Ordering::Relaxed);

    // Stack base offset: 0 .. 255 pages = 0 ~ 1 MiB.
    // r1 is a byte (0..255); multiply by page size for byte offset.
    let stack_off = (r1 as u64) * 4096;
    STACK_BASE_OFFSET.store(stack_off, Ordering::Relaxed);

    // PIE base offset: 0 .. 15 * 2 MiB = 0 ~ 30 MiB, aligned to 2 MiB.
    // Mask to 4 bits (0..15) then shift left by 21 bits (2 MiB).
    let pie_off = ((r2 as u64) & 0x0F) << 21;
    PIE_BASE_OFFSET.store(pie_off, Ordering::Relaxed);

    INITIALIZED.store(true, Ordering::Release);

    log::info!(
        "[KASLR] mmap_base_off={:#x} stack_off={:#x} pie_off={:#x}",
        mmap_off,
        stack_off,
        pie_off
    );
}

/// Get the randomized mmap base address.
///
/// # Panics
/// Panics if `init()` has not been called yet.
#[inline]
pub fn mmap_base() -> u64 {
    debug_assert!(
        INITIALIZED.load(Ordering::Relaxed),
        "kaslr::init() not called"
    );
    const MMAP_BASE: u64 = 0x0000_0000_6000_0000;
    MMAP_BASE + MMAP_BASE_OFFSET.load(Ordering::Relaxed)
}

/// Get the randomized user stack base address.
///
/// # Panics
/// Panics if `init()` has not been called yet.
#[inline]
pub fn stack_base() -> u64 {
    debug_assert!(
        INITIALIZED.load(Ordering::Relaxed),
        "kaslr::init() not called"
    );
    const STACK_BASE: u64 = 0x0000_7FFF_F000_0000;
    STACK_BASE + STACK_BASE_OFFSET.load(Ordering::Relaxed)
}

/// Get the randomized user stack top address.
#[inline]
pub fn stack_top() -> u64 {
    stack_base() + 16 * 4096
}

/// Get the guard page address below the user stack.
#[inline]
pub fn stack_guard() -> u64 {
    stack_base() - 4096
}

/// Get the randomized PIE base address for ELF loading.
///
/// # Panics
/// Panics if `init()` has not been called yet.
#[inline]
pub fn pie_base() -> u64 {
    debug_assert!(
        INITIALIZED.load(Ordering::Relaxed),
        "kaslr::init() not called"
    );
    const PIE_BASE: u64 = 0x0000_0001_0000_0000;
    PIE_BASE + PIE_BASE_OFFSET.load(Ordering::Relaxed)
}
