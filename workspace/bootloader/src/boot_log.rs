//! Boot log ring reserved by the loader and replayed by the kernel (ABI v6).
//!
//! The ring is a plain byte buffer: [`written`] counts every byte ever
//! appended, and the kernel derives the valid window from it with
//! [`KernelArgs::boot_log_spans`]. Nothing here allocates, formats to a
//! heap, or calls firmware, so the log keeps recording after
//! `ExitBootServices`, when the UEFI console is gone -- which is precisely
//! when the kernel cannot show what the loader did.
//!
//! [`KernelArgs::boot_log_spans`]: strat9_abi::boot::KernelArgs::boot_log_spans
//! [`written`]: written

use core::{
    cell::UnsafeCell,
    fmt, ptr,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

use crate::memory_map::{PhysicalRange, PAGE_SIZE};

/// Capacity of the ring. Loader messages are about 1 KiB, so a wrap only
/// happens on a pathological boot; keeping it small also keeps the reserve
/// cheap and the kernel replay short.
pub const BOOT_LOG_CAPACITY: u64 = 16 * 1024;

struct Ring {
    /// Set once by [`init`], read-only afterwards: `(base, capacity)`.
    window: UnsafeCell<Option<(*mut u8, usize)>>,
    written: AtomicU64,
    console: AtomicBool,
}

// SAFETY: the loader is single-threaded; `window` is written once before
// logging starts, and `written` only ever changes through atomics so a
// firmware callback cannot tear the cursor.
unsafe impl Sync for Ring {}

static RING: Ring = Ring {
    window: UnsafeCell::new(None),
    written: AtomicU64::new(0),
    console: AtomicBool::new(false),
};

/// Reserve `range` (already allocated, zeroed and page-aligned) as the ring.
///
/// Must run before the first [`append`]; a second call is rejected rather than
/// silently discarding the log already recorded.
pub fn init(range: PhysicalRange) -> Result<(), &'static str> {
    if range.base == 0 || range.base % PAGE_SIZE != 0 {
        return Err("unaligned boot log ring");
    }
    if !range.size.is_power_of_two()
        || !(PAGE_SIZE..=strat9_abi::boot::MAX_BOOT_LOG_SIZE).contains(&range.size)
    {
        return Err("invalid boot log ring size");
    }
    // SAFETY: single-threaded, before any append or console read.
    let slot = unsafe { &mut *RING.window.get() };
    if slot.is_some() {
        return Err("boot log already initialised");
    }
    *slot = Some((range.base as *mut u8, range.size as usize));
    RING.console.store(true, Ordering::Release);
    Ok(())
}

/// Append raw bytes, keeping only the most recent `capacity` bytes.
///
/// A message longer than the ring is truncated to its tail, which is also what
/// the `written` counter reports, so the kernel never reads stale bytes.
pub fn append(bytes: &[u8]) {
    // SAFETY: `window` is only assigned by `init`, before this can be reached.
    let Some((base, capacity)) = (unsafe { *RING.window.get() }) else {
        return;
    };
    if bytes.is_empty() {
        return;
    }
    let previous = RING.written.load(Ordering::Relaxed);
    let total = previous + bytes.len() as u64;
    let keep = bytes.len().min(capacity);
    let kept = &bytes[bytes.len() - keep..];
    let mut offset = ((total - keep as u64) % capacity as u64) as usize;
    for &byte in kept {
        // SAFETY: the ring is exclusively owned and reserved for the handoff,
        // and `offset` stays below `capacity`.
        unsafe { ptr::write_volatile(base.add(offset), byte) };
        offset += 1;
        if offset == capacity {
            offset = 0;
        }
    }
    RING.written.store(total, Ordering::Release);
}

/// Total bytes ever appended, monotonic across wraps.
pub fn written() -> u64 {
    RING.written.load(Ordering::Acquire)
}

/// Whether boot-message mirroring to the UEFI console is still allowed.
pub fn console_enabled() -> bool {
    RING.console.load(Ordering::Relaxed)
}

/// Stop mirroring to the console. Must precede `ExitBootServices`, after which
/// calling firmware output protocols is undefined.
pub fn disable_console() {
    RING.console.store(false, Ordering::Relaxed);
}

struct Sink;

impl fmt::Write for Sink {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        append(text.as_bytes());
        Ok(())
    }
}

/// Record one formatted line (a trailing newline is added).
pub fn record(args: fmt::Arguments<'_>) {
    let mut sink = Sink;
    let _ = fmt::Write::write_fmt(&mut sink, args);
    append(b"\n");
}
