/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

//! Boot log ring buffer : capture kernel output from the first serial byte.
//!
//! The kernel logger feeds every formatted record into a fixed-size byte ring
//! that lives in `.bss`. The ring is usable before the allocator exists, never
//! allocates, never blocks on a reader and never panics.
//!
//! # Absolute positions
//!
//! [`WRITTEN`] is a monotonically increasing 64-bit counter of every byte ever
//! appended. A reader holds an absolute cursor and asks for the bytes starting
//! there. The oldest retained byte is `WRITTEN.saturating_sub(CAPACITY)`; a
//! cursor below that boundary has lost data and [`read_at`] reports how many
//! bytes were skipped.
//!
//! # Concurrency
//!
//! Producers take a [`SpinLock`] (default `IrqDisabled` guardian) while they
//! copy into the ring. Readers take the same lock while copying, which makes
//! them safe against a producer lapping them. [`try_push`] is the panic/IRQ
//! path: if the lock is already held, the bytes are dropped and counted in
//! `dropped` instead of spinning forever.
//!
//! "Overwritten" is not "dropped": once the ring is full, older bytes roll out
//! of the retained window. That is normal operation and is reported by
//! [`overwritten`]. `dropped` only counts pushes that were refused.

use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::sync::SpinLock;

/// Size of the retained byte window (128 KiB).
pub const CAPACITY: usize = 128 * 1024;

/// Maximum number of bytes captured by [`TeeWriter`].
pub const TEE_CAPTURE_MAX: usize = 512;

/// Absolute monotonic count of bytes appended since boot (or since [`clear`]).
static WRITTEN: AtomicU64 = AtomicU64::new(0);

/// Bytes refused by [`try_push`] because the lock was already held, or because
/// the absolute counter would have overflowed.
static DROPPED: AtomicU64 = AtomicU64::new(0);

/// Serialises access to [`RING`]. Kept separate from the storage so that the
/// 128 KiB array stays all-zero and therefore lands in `.bss`.
static LOCK: SpinLock<()> = SpinLock::new(());

/// Backing storage. All-zero initialiser keeps this in `.bss`.
///
/// SAFETY: every access goes through the raw pointer returned by
/// [`ring_ptr`] while [`LOCK`] is held. No `&mut` reference to the static is
/// ever created, which also avoids `static_mut_refs` diagnostics.
static mut RING: [u8; CAPACITY] = [0u8; CAPACITY];

/// Returns a raw pointer to the ring storage.
#[inline]
fn ring_ptr() -> *mut u8 {
    // `addr_of_mut!` does not create a reference, so no aliasing rule is
    // violated; the pointer is only dereferenced while `LOCK` is held.
    core::ptr::addr_of_mut!(RING) as *mut u8
}

/// Snapshot of the ring counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    /// Absolute number of bytes ever appended.
    pub written: u64,
    /// Retained window size in bytes.
    pub capacity: usize,
    /// Bytes refused by [`try_push`] (lock contention or counter overflow).
    pub dropped: u64,
    /// Absolute position of the oldest retained byte.
    pub oldest: u64,
}

/// Result of one [`read_at`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadOut {
    /// Bytes actually copied into the caller's buffer.
    pub copied: usize,
    /// Absolute cursor to pass to the next call.
    pub next: u64,
    /// Bytes skipped because the caller's cursor was older than [`Stats::oldest`].
    pub lost: u64,
}

/// Appends `bytes`, overwriting the oldest retained bytes when the ring is full.
///
/// Acquires the ring lock (spinning briefly under contention) and never waits on
/// a reader. This is the normal logger path.
pub fn push(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    let _guard = LOCK.lock();
    push_locked(bytes);
}

/// Best-effort append for panic, IRQ or other no-spin contexts.
///
/// Returns `false` and counts the bytes in [`Stats::dropped`] if the lock is
/// already held.
pub fn try_push(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    match LOCK.try_lock() {
        Some(_guard) => {
            push_locked(bytes);
            true
        }
        None => {
            DROPPED.fetch_add(bytes.len() as u64, Ordering::Relaxed);
            false
        }
    }
}

/// Appends bytes while the lock is held.
fn push_locked(bytes: &[u8]) {
    let written = WRITTEN.load(Ordering::Relaxed);
    let Some(end) = written.checked_add(bytes.len() as u64) else {
        // Absolute counter exhausted: refuse rather than wrap and confuse
        // cursors.
        DROPPED.fetch_add(bytes.len() as u64, Ordering::Relaxed);
        return;
    };

    // If the input is larger than the window, only its tail can survive. Skip
    // the prefix instead of copying bytes that are immediately overwritten.
    let skip = bytes.len().saturating_sub(CAPACITY);
    let tail = &bytes[skip..];
    let mut index = ((written + skip as u64) % CAPACITY as u64) as usize;
    let base = ring_ptr();

    for &byte in tail {
        // SAFETY: `index` is always < CAPACITY.
        unsafe { core::ptr::write(base.add(index), byte) };
        index += 1;
        if index == CAPACITY {
            index = 0;
        }
    }

    WRITTEN.store(end, Ordering::Release);
}

/// Copies retained bytes starting at absolute `cursor` into `out`.
///
/// The cursor is clamped to `[oldest, written]`:
/// * a cursor older than `oldest` skips the evicted prefix (`lost`),
/// * a cursor ahead of `written` (possible after [`clear`]) is pulled back to
///   `written`.
///
/// The ring lock is held for the duration of the copy, so a concurrent writer
/// cannot lap the reader mid-copy. `out` is never larger than the ring itself,
/// keeping the critical section short.
pub fn read_at(cursor: u64, out: &mut [u8]) -> ReadOut {
    let _guard = LOCK.lock();
    let written = WRITTEN.load(Ordering::Acquire);
    let oldest = written.saturating_sub(CAPACITY as u64);

    let (start, lost) = if cursor < oldest {
        (oldest, oldest - cursor)
    } else if cursor > written {
        (written, 0)
    } else {
        (cursor, 0)
    };

    let available = written.saturating_sub(start);
    let copied = core::cmp::min(out.len() as u64, available) as usize;

    let base = ring_ptr();
    let mut index = (start % CAPACITY as u64) as usize;
    for slot in out[..copied].iter_mut() {
        // SAFETY: `index` is always < CAPACITY.
        *slot = unsafe { core::ptr::read(base.add(index)) };
        index += 1;
        if index == CAPACITY {
            index = 0;
        }
    }

    ReadOut {
        copied,
        next: start + copied as u64,
        lost,
    }
}

/// Returns a consistent-enough snapshot of the ring counters.
pub fn stats() -> Stats {
    let written = WRITTEN.load(Ordering::Acquire);
    Stats {
        written,
        capacity: CAPACITY,
        dropped: DROPPED.load(Ordering::Relaxed),
        oldest: written.saturating_sub(CAPACITY as u64),
    }
}

/// Number of bytes that have rolled out of the retained window since boot (or
/// since the last [`clear`]).
///
/// This is *not* an error counter: it is exactly `written - capacity` once the
/// window is full. Use [`Stats::dropped`] for refused pushes.
pub fn overwritten() -> u64 {
    WRITTEN
        .load(Ordering::Acquire)
        .saturating_sub(CAPACITY as u64)
}

/// Resets the ring and its counters.
///
/// Existing readers keep their (now stale) absolute cursor; [`read_at`] clamps
/// such a cursor back to the new write position, so they resume from fresh data
/// instead of blocking forever. This is a rare control-path operation.
pub fn clear() {
    let _guard = LOCK.lock();
    // SAFETY: the whole array is valid for writes while LOCK is held.
    unsafe { core::ptr::write_bytes(ring_ptr(), 0, CAPACITY) };
    WRITTEN.store(0, Ordering::Release);
    DROPPED.store(0, Ordering::Relaxed);
}

/// Returns the retained window size in bytes.
#[inline]
pub const fn capacity() -> usize {
    CAPACITY
}

/// Writer adapter used by the serial hook.
///
/// Every `write_str` is forwarded to the wrapped writer *and* copied into a
/// fixed 512-byte internal buffer. Overflow is silently truncated; the wrapped
/// writer still receives the complete input. No allocation, no panic.
pub struct TeeWriter<'a, W: fmt::Write> {
    inner: &'a mut W,
    buf: [u8; TEE_CAPTURE_MAX],
    len: usize,
}

impl<'a, W: fmt::Write> TeeWriter<'a, W> {
    /// Wraps `inner`.
    pub fn new(inner: &'a mut W) -> Self {
        TeeWriter {
            inner,
            buf: [0u8; TEE_CAPTURE_MAX],
            len: 0,
        }
    }

    /// Bytes captured so far (at most [`TEE_CAPTURE_MAX`]).
    #[inline]
    pub fn captured(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Whether the capture buffer overflowed and truncated the input.
    #[inline]
    pub fn truncated(&self) -> bool {
        self.len == TEE_CAPTURE_MAX
    }
}

impl<W: fmt::Write> fmt::Write for TeeWriter<'_, W> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let forwarded = self.inner.write_str(s);

        let remaining = TEE_CAPTURE_MAX.saturating_sub(self.len);
        let n = core::cmp::min(s.len(), remaining);
        if n > 0 {
            self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
            self.len += n;
        }

        forwarded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use core::fmt::Write as _;

    /// The ring is process-global; serialise the tests that mutate it.
    static TEST_LOCK: SpinLock<()> = SpinLock::new(());

    fn chunk() -> [u8; 1024] {
        let mut c = [0u8; 1024];
        for (i, slot) in c.iter_mut().enumerate() {
            *slot = i as u8;
        }
        c
    }

    #[test]
    fn empty_read() {
        let _guard = TEST_LOCK.lock();
        clear();
        let mut buf = [0u8; 16];
        let r = read_at(0, &mut buf);
        assert_eq!(
            r,
            ReadOut {
                copied: 0,
                next: 0,
                lost: 0
            }
        );
    }

    #[test]
    fn append_and_read() {
        let _guard = TEST_LOCK.lock();
        clear();
        push(b"hello");
        let s = stats();
        assert_eq!(s.written, 5);
        assert_eq!(s.oldest, 0);
        assert_eq!(s.dropped, 0);

        let mut buf = [0u8; 16];
        let r = read_at(0, &mut buf);
        assert_eq!(r.copied, 5);
        assert_eq!(r.next, 5);
        assert_eq!(r.lost, 0);
        assert_eq!(&buf[..5], b"hello");

        let r2 = read_at(r.next, &mut buf);
        assert_eq!(r2.copied, 0);
        assert_eq!(r2.next, 5);
    }

    #[test]
    fn wraparound_keeps_newest_window() {
        let _guard = TEST_LOCK.lock();
        clear();

        let block = chunk();
        let total = CAPACITY + 100;
        let mut pushed = 0usize;
        while pushed < total {
            let n = core::cmp::min(block.len(), total - pushed);
            push(&block[..n]);
            pushed += n;
        }

        let s = stats();
        assert_eq!(s.written, total as u64);
        assert_eq!(s.oldest, 100);

        let mut buf = [0u8; 64];
        let r = read_at(s.oldest, &mut buf);
        assert_eq!(r.copied, 64);
        assert_eq!(r.lost, 0);
        for (i, &b) in buf.iter().enumerate() {
            assert_eq!(b, ((s.oldest + i as u64) % 256) as u8);
        }
    }

    #[test]
    fn lost_detection() {
        let _guard = TEST_LOCK.lock();
        clear();

        let block = chunk();
        let total = CAPACITY + 10;
        let mut pushed = 0usize;
        while pushed < total {
            let n = core::cmp::min(block.len(), total - pushed);
            push(&block[..n]);
            pushed += n;
        }

        let mut buf = [0u8; 32];
        let r = read_at(0, &mut buf);
        assert_eq!(r.lost, 10);
        assert_eq!(r.copied, 32);
        assert_eq!(r.next, 42);
    }

    #[test]
    fn cursor_clamping() {
        let _guard = TEST_LOCK.lock();
        clear();
        push(b"abc");

        let mut buf = [0u8; 8];
        let r = read_at(u64::MAX, &mut buf);
        assert_eq!(r.copied, 0);
        assert_eq!(r.next, 3);
        assert_eq!(r.lost, 0);
    }

    #[test]
    fn non_utf8_bytes_round_trip() {
        let _guard = TEST_LOCK.lock();
        clear();
        let payload = [0xFFu8, 0x00, 0x80, 0xC3, 0x28];
        push(&payload);

        let mut buf = [0u8; 8];
        let r = read_at(0, &mut buf);
        assert_eq!(r.copied, payload.len());
        assert_eq!(&buf[..r.copied], &payload);
    }

    #[test]
    fn tee_writer_truncates_capture() {
        let _guard = TEST_LOCK.lock();
        let mut sink = String::new();
        {
            let mut tee = TeeWriter::new(&mut sink);
            let text = alloc::format!("{}", "x".repeat(TEE_CAPTURE_MAX + 64));
            tee.write_str(&text).unwrap();
            assert_eq!(tee.captured().len(), TEE_CAPTURE_MAX);
            assert!(tee.truncated());
            assert!(tee.captured().iter().all(|&b| b == b'x'));
        }
        assert_eq!(sink.len(), TEE_CAPTURE_MAX + 64);
    }
}
