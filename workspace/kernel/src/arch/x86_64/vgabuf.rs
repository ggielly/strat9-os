//! Lock-free circular buffer for VGA log lines.
//!
//! The kernel's `log::info!` / `log::warn!` / etc. macros write to this buffer
//! instead of directly locking `VGA_WRITER`.  A background display task (or the
//! panic handler) calls `vgabuf_flush_to_framebuffer()` to render the buffered
//! lines onto the actual framebuffer.
//!
//! This decouples the hot logging path from the (comparatively) slow framebuffer
//! drawing, preventing deadlocks and keeping log output fast.

use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicU16, AtomicUsize, Ordering},
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of lines stored in the circular buffer.
/// 512 gives ample headroom: at 100Hz flush × 30 lines/batch, the writer
/// would need to produce >512 log messages between two reader ticks to
/// overwrite an unread slot.
pub const VGABUF_CAPACITY: usize = 512;

/// Maximum byte length of a single log line (including trailing newline).
pub const VGABUF_LINE_LEN: usize = 256;

// ---------------------------------------------------------------------------
// Global buffer state
// ---------------------------------------------------------------------------

/// Raw storage: each slot is a fixed-size byte buffer.
/// Wrapped in a newtype that is `Sync` because we only access slots via
/// atomically-coordinated indices (single writer per slot).
struct VgaSlot(UnsafeCell<[u8; VGABUF_LINE_LEN]>);
unsafe impl Sync for VgaSlot {}

static STORAGE: [VgaSlot; VGABUF_CAPACITY] =
    [const { VgaSlot(UnsafeCell::new([0u8; VGABUF_LINE_LEN])) }; VGABUF_CAPACITY];

/// Length (in bytes) of each stored line.  0 means the slot is unused.
static LENS: [AtomicU16; VGABUF_CAPACITY] = [const { AtomicU16::new(0) }; VGABUF_CAPACITY];

/// Next slot to write into (monotonic, wraps via `% CAPACITY`).
static WRITE_IDX: AtomicUsize = AtomicUsize::new(0);

/// Slot that the display task has rendered up to (exclusive).
static DISPLAY_IDX: AtomicUsize = AtomicUsize::new(0);

/// Total lines written since boot (for ordering / watermark).
static TOTAL_WRITTEN: AtomicUsize = AtomicUsize::new(0);

// ---------------------------------------------------------------------------
// Public API : writer side
// ---------------------------------------------------------------------------

/// Write a line into the circular buffer.
///
/// `line` should be **pre-formatted** (including colour codes if desired) and
/// should not exceed `VGABUF_LINE_LEN - 1` bytes.  Trailing bytes beyond the
/// capacity are silently truncated.
///
/// This is **lock-free** (single atomic increment) and safe to call from
/// interrupt handlers or any CPU core.
pub fn vgabuf_write(line: &[u8]) {
    let len = line.len().min(VGABUF_LINE_LEN - 1);
    if len == 0 {
        return;
    }

    // Claim the next slot.
    let slot = WRITE_IDX.fetch_add(1, Ordering::Relaxed) % VGABUF_CAPACITY;

    // If the slot is still occupied (reader hasn't consumed it yet), skip
    // this message rather than overwriting unread data.
    if LENS[slot].load(Ordering::Acquire) != 0 {
        return;
    }

    // Copy data into the slot.
    // SAFETY: each slot is owned by the writer that claimed it (one writer per
    // fetch_add call).  No other thread will write to this slot concurrently.
    let cell = &STORAGE[slot].0;
    let ptr = cell.get() as *mut u8;
    unsafe {
        // Write bytes one-by-one (volatile not needed: the reader will see the
        // finalised length via the LENS store-with-release below).
        for i in 0..len {
            core::ptr::write(ptr.add(i), line[i]);
        }
        // Zero the rest to avoid leaking old data.
        if len < VGABUF_LINE_LEN {
            core::ptr::write_bytes(ptr.add(len), 0, VGABUF_LINE_LEN - len);
        }
    }
    // Publish the length : reader sees this after a successful acquire load.
    LENS[slot].store(len as u16, Ordering::Release);
    TOTAL_WRITTEN.fetch_add(1, Ordering::Relaxed);
}

/// Return the total number of lines written since boot.
pub fn vgabuf_total_written() -> usize {
    TOTAL_WRITTEN.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Public API : reader / display side
// ---------------------------------------------------------------------------

/// Maximum number of lines we render in one flush call (to keep frame time
/// bounded).
const FLUSH_BATCH: usize = 30;

/// Read buffered lines and render them onto the framebuffer via
/// `crate::arch::x86_64::vga::VGA_WRITER`.
///
/// Call this periodically (e.g. from the status-line task or after a batch of
/// `log::info!` calls).  It consumes at most `FLUSH_BATCH` lines per call to
/// keep individual frame times predictable.
///
/// This function **locks `VGA_WRITER`** and is **not** safe to call from
/// interrupt handlers.
pub fn vgabuf_flush_to_framebuffer() {
    use core::fmt::Write;

    if !crate::arch::x86_64::vga::is_available() {
        // No framebuffer : drain and discard.
        vgabuf_drain_discard();
        return;
    }

    let Some(mut writer) = crate::arch::x86_64::vga::VGA_WRITER.try_lock() else {
        return; // Already locked : try again next cycle.
    };

    let mut flushed = 0usize;
    loop {
        let slot = DISPLAY_IDX.load(Ordering::Relaxed) % VGABUF_CAPACITY;
        let len = LENS[slot].load(Ordering::Acquire);
        if len == 0 {
            break; // No more new lines.
        }

        // Read the line content.
        // SAFETY: LENS[slot] is non-zero, so the slot was published by a writer.
        let cell = &STORAGE[slot].0;
        let ptr = cell.get() as *const u8;
        let line = unsafe { core::slice::from_raw_parts(ptr, len as usize) };

        // Write to the framebuffer terminal, ensuring each line ends with \n.
        if let Ok(s) = core::str::from_utf8(line) {
            let _ = writer.write_str(s);
            let _ = writer.write_str("\n");
        } else {
            let _ = writer.write_str("<non-utf8>\n");
        }

        // Mark slot as consumed.
        LENS[slot].store(0, Ordering::Release);
        DISPLAY_IDX.fetch_add(1, Ordering::Relaxed);
        flushed += 1;

        if flushed >= FLUSH_BATCH {
            break; // Yield to the scheduler; resume on next cycle.
        }
    }

    // Only present if we actually wrote something to the framebuffer.
    if flushed > 0 {
        writer.present();
    }
    // Drop writer to release the lock.
}

/// Drain all pending lines without rendering (e.g. framebuffer not available).
fn vgabuf_drain_discard() {
    loop {
        let slot = DISPLAY_IDX.load(Ordering::Relaxed) % VGABUF_CAPACITY;
        let len = LENS[slot].load(Ordering::Acquire);
        if len == 0 {
            break;
        }
        LENS[slot].store(0, Ordering::Release);
        DISPLAY_IDX.fetch_add(1, Ordering::Relaxed);
    }
}

/// Flush all remaining lines (used by the panic handler before halting).
pub fn vgabuf_flush_all() {
    use core::fmt::Write;

    if !crate::arch::x86_64::vga::is_available() {
        vgabuf_drain_discard();
        return;
    }

    let Some(mut writer) = crate::arch::x86_64::vga::VGA_WRITER.try_lock() else {
        // Cannot lock : fall back to direct framebuffer drawing.
        vgabuf_flush_all_direct();
        return;
    };

    loop {
        let slot = DISPLAY_IDX.load(Ordering::Relaxed) % VGABUF_CAPACITY;
        let len = LENS[slot].load(Ordering::Acquire);
        if len == 0 {
            break;
        }
        let cell = &STORAGE[slot].0;
        let ptr = cell.get() as *const u8;
        let line = unsafe { core::slice::from_raw_parts(ptr, len as usize) };
        if let Ok(s) = core::str::from_utf8(line) {
            let _ = writer.write_str(s);
        }
        LENS[slot].store(0, Ordering::Release);
        DISPLAY_IDX.fetch_add(1, Ordering::Relaxed);
    }
    writer.present();
}

/// Fallback when VGA_WRITER is locked: use the direct panic drawer.
/// Uses a fixed-size stack buffer to avoid heap allocation in panic context.
fn vgabuf_flush_all_direct() {
    // Fixed buffer: max 64 pending lines. If more, excess lines are discarded.
    const MAX_LINES: usize = 64;
    let mut lines: [&str; MAX_LINES] = [""; MAX_LINES];
    let mut count = 0usize;
    loop {
        let slot = DISPLAY_IDX.load(Ordering::Relaxed) % VGABUF_CAPACITY;
        let len = LENS[slot].load(Ordering::Acquire);
        if len == 0 {
            break;
        }
        let cell = &STORAGE[slot].0;
        let ptr = cell.get() as *const u8;
        let line = unsafe { core::slice::from_raw_parts(ptr, len as usize) };
        if let Ok(s) = core::str::from_utf8(line) {
            if count < MAX_LINES {
                lines[count] = s;
                count += 1;
            }
        }
        LENS[slot].store(0, Ordering::Release);
        DISPLAY_IDX.fetch_add(1, Ordering::Relaxed);
    }
    if count > 0 {
        crate::arch::x86_64::vga::panic_draw_direct(&lines[..count]);
    }
}
