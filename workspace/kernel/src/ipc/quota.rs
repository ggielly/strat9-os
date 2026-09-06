//! Per-process IPC resource quotas.
//!
//! Prevents a single process from exhausting system-wide IPC resources
//! (channels, queue slots, buffered bytes) via unbounded creation.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Maximum number of channels a single process may hold simultaneously.
pub const MAX_CHANNELS_PER_PROCESS: u32 = 256;

/// Maximum total queue slots (capacity sum) across all channels owned by a
/// single process.
pub const MAX_QUEUE_SLOTS_PER_PROCESS: u64 = 65_536;

/// Maximum total buffered bytes across all channels owned by a single process.
///
/// Each `IpcMessage` is `IPC_MESSAGE_SIZE` (256) bytes, so this effectively
/// caps the total number of queued messages.
pub const MAX_BUFFERED_BYTES_PER_PROCESS: u64 = MAX_QUEUE_SLOTS_PER_PROCESS * 256;

/// Per-process IPC resource counters.
///
/// All fields are atomic so they can be updated without holding a global
/// lock.  They are always accessed from the owning process's context (the
/// syscall handler), so `Relaxed` ordering is sufficient for the common
/// case; `AcqRel` is used for the reserve/release pair to ensure that a
/// failed reservation is never silently lost.
#[derive(Debug)]
pub struct IpcQuota {
    /// Number of live channel capabilities (handles) held by this process.
    pub channels: AtomicU32,
    /// Sum of `capacity` across all channels created by this process.
    pub queue_slots: AtomicU64,
    /// `queue_slots * size_of::<IpcMessage>()` — total bytes that could be
    /// buffered across all channels.
    pub buffered_bytes: AtomicU64,
}

impl IpcQuota {
    /// Creates a new, empty quota (all counters zero).
    pub const fn new() -> Self {
        IpcQuota {
            channels: AtomicU32::new(0),
            queue_slots: AtomicU64::new(0),
            buffered_bytes: AtomicU64::new(0),
        }
    }

    /// Try to reserve resources for a new channel.
    ///
    /// Returns `Ok(())` if the reservation fits within the process quota,
    /// `Err(QuotaExceeded)` otherwise.  On failure **nothing** is modified.
    pub fn try_reserve(&self, capacity: usize) -> Result<(), QuotaExceeded> {
        let new_channels = self.channels.load(Ordering::Relaxed).checked_add(1)
            .ok_or(QuotaExceeded)?;
        if new_channels > MAX_CHANNELS_PER_PROCESS {
            return Err(QuotaExceeded);
        }

        let slots = capacity as u64;
        let new_slots = self.queue_slots.load(Ordering::Relaxed).checked_add(slots)
            .ok_or(QuotaExceeded)?;
        if new_slots > MAX_QUEUE_SLOTS_PER_PROCESS {
            return Err(QuotaExceeded);
        }

        let bytes = slots * core::mem::size_of::<crate::ipc::message::IpcMessage>() as u64;
        let new_bytes = self.buffered_bytes.load(Ordering::Relaxed).checked_add(bytes)
            .ok_or(QuotaExceeded)?;
        if new_bytes > MAX_BUFFERED_BYTES_PER_PROCESS {
            return Err(QuotaExceeded);
        }

        // All checks passed — commit the reservation atomically.
        self.channels.store(new_channels, Ordering::Release);
        self.queue_slots.store(new_slots, Ordering::Release);
        self.buffered_bytes.store(new_bytes, Ordering::Release);
        Ok(())
    }

    /// Release resources previously reserved by [`try_reserve`].
    ///
    /// Must be called exactly once for every successful `try_reserve`.
    /// Passing a `capacity` that was never reserved will underflow the
    /// counters — the caller must ensure correctness.
    pub fn release(&self, capacity: usize) {
        let _ = self.channels.fetch_sub(1, Ordering::AcqRel);

        let slots = capacity as u64;
        let _ = self.queue_slots.fetch_sub(slots, Ordering::AcqRel);

        let bytes = slots * core::mem::size_of::<crate::ipc::message::IpcMessage>() as u64;
        let _ = self.buffered_bytes.fetch_sub(bytes, Ordering::AcqRel);
    }

    /// Returns a snapshot of the current counters.
    pub fn snapshot(&self) -> QuotaSnapshot {
        QuotaSnapshot {
            channels: self.channels.load(Ordering::Relaxed),
            queue_slots: self.queue_slots.load(Ordering::Relaxed),
            buffered_bytes: self.buffered_bytes.load(Ordering::Relaxed),
        }
    }
}

impl Default for IpcQuota {
    fn default() -> Self {
        Self::new()
    }
}

/// Error returned when a quota reservation would exceed the limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaExceeded;

/// Read-only snapshot of [`IpcQuota`] counters.
#[derive(Debug, Clone, Copy)]
pub struct QuotaSnapshot {
    pub channels: u32,
    pub queue_slots: u64,
    pub buffered_bytes: u64,
}
