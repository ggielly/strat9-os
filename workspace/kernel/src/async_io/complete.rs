//! Completion routing for async I/O.
//!
//! Provides a [`CompletionRouter`] that maps ring ids to their CQ buffers
//! and pushes [`AsyncCqe`] entries atomically, waking any task waiting
//! on the ring via `SYS_ASYNC_ENTER`.

use super::{
    ops::{AsyncCqe, MAX_IN_FLIGHT},
    ring::find_ring,
};

/// Push a completion event to the ring identified by `ring_id`.
///
/// Returns `true` if a completion was successfully queued.
/// Returns `false` if the ring is not found, destroyed, or its
/// completion queue is full.
pub fn push_completion(ring_id: u64, user_data: u64, result: i32, flags: u32) -> bool {
    let Some(ring_ptr) = find_ring(ring_id) else {
        return false;
    };
    let ring = unsafe { &*ring_ptr };

    // Reject if destroyed
    if ring.destroyed.load(core::sync::atomic::Ordering::Acquire) != 0 {
        return false;
    }

    let _guard = ring.cq_lock.lock();

    let tail = ring
        .cq_meta()
        .tail
        .load(core::sync::atomic::Ordering::Relaxed);
    let head = ring.cq_head();
    let mask = ring
        .cq_meta()
        .mask
        .load(core::sync::atomic::Ordering::Relaxed);

    // Check if CQ is full
    if tail.wrapping_sub(head) >= ring.entries {
        return false; // CQ overflow — userspace needs to drain
    }

    let idx = (tail & mask) as usize;
    unsafe {
        let cqe = ring.cqe_at(idx as u32);
        core::ptr::write_volatile(
            cqe,
            AsyncCqe {
                user_data,
                res: result,
                flags,
            },
        );
    }

    // Decrement the in-flight counter : this operation is now done.
    ring.in_flight
        .fetch_sub(1, core::sync::atomic::Ordering::Relaxed);

    // Advance tail with release ordering so userspace sees the CQE
    ring.cq_advance_tail(1);

    // Wake any task waiting on this ring
    ring.wq.wake_all();

    true
}

/// Drain all pending completions for a ring and return them.
/// Called by `SYS_ASYNC_ENTER` when userspace wants to consume CQEs.
pub fn drain_completions(ring_id: u64, max: u32) -> u32 {
    let Some(ring_ptr) = find_ring(ring_id) else {
        return 0;
    };
    let ring = unsafe { &*ring_ptr };

    let head = ring.cq_head();
    let tail = ring
        .cq_meta()
        .tail
        .load(core::sync::atomic::Ordering::Acquire);
    let mask = ring
        .cq_meta()
        .mask
        .load(core::sync::atomic::Ordering::Relaxed);

    let available = tail.wrapping_sub(head).min(max);
    if available == 0 {
        return 0;
    }

    // No need to copy CQEs — userspace reads them directly from the
    // shared CQ page. We just advance head to acknowledge consumption.
    ring.cq_meta().head.store(
        head.wrapping_add(available),
        core::sync::atomic::Ordering::Release,
    );

    available
}

/// Number of in-flight operations tracked for a ring.
pub fn in_flight_count(ring_id: u64) -> u32 {
    let Some(ring_ptr) = find_ring(ring_id) else {
        return 0;
    };
    let ring = unsafe { &*ring_ptr };
    ring.in_flight.load(core::sync::atomic::Ordering::Relaxed)
}

#[inline]
pub fn inc_in_flight(ring_id: u64) {
    if let Some(ring_ptr) = find_ring(ring_id) {
        let ring = unsafe { &*ring_ptr };
        ring.in_flight
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
}

#[inline]
pub fn dec_in_flight(ring_id: u64) {
    if let Some(ring_ptr) = find_ring(ring_id) {
        let ring = unsafe { &*ring_ptr };
        ring.in_flight
            .fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
    }
}
