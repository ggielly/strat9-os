//! Completion routing for async I/O.
//!
//! Provides a [`CompletionRouter`] that maps ring ids to their CQ buffers
//! and pushes [`AsyncCqe`] entries atomically, waking any task waiting
//! on the ring via `SYS_ASYNC_ENTER`.

use super::{ops::AsyncCqe, ring::find_ring};

fn cq_space_available(ring: &super::ring::Ring) -> u32 {
    let tail = ring
        .cq_meta()
        .tail
        .load(core::sync::atomic::Ordering::Relaxed);
    let head = ring.cq_head();
    ring.entries.saturating_sub(tail.wrapping_sub(head))
}

/// Write a single CQE into the ring's visible CQ and advance tail.
///
/// # Safety : caller must hold `ring.cq_lock`.
fn write_cqe_at_tail(ring: &super::ring::Ring, cqe: AsyncCqe) {
    let tail = ring
        .cq_meta()
        .tail
        .load(core::sync::atomic::Ordering::Relaxed);
    let mask = ring
        .cq_meta()
        .mask
        .load(core::sync::atomic::Ordering::Relaxed);
    let idx = (tail & mask) as usize;
    unsafe {
        let slot = ring.cqe_at(idx as u32);
        core::ptr::write_volatile(slot, cqe);
    }
    ring.cq_advance_tail(1);
}

/// Drain as many entries from the backlog into the visible CQ as space allows.
///
/// # Safety : caller must hold `ring.cq_lock`.
fn flush_backlog_locked(ring: &super::ring::Ring) -> u32 {
    let mut backlog = ring.completion_backlog.lock();
    let flush_count = core::cmp::min(backlog.len(), cq_space_available(ring) as usize);
    if flush_count == 0 {
        return 0;
    }

    for cqe in backlog.drain(..flush_count) {
        write_cqe_at_tail(ring, cqe);
    }

    flush_count as u32
}

// ====  ring-id-based public API  ===============================================================

/// Push a completion event to the ring identified by `ring_id`.
///
/// Returns `true` on success, `false` if the ring was not found or destroyed.
pub fn push_completion(ring_id: u64, user_data: u64, result: i32, flags: u32) -> bool {
    let Some(ring) = find_ring(ring_id) else {
        return false;
    };
    push_completion_for_ring(&ring, user_data, result, flags)
}

/// Variant of [`push_completion`] that takes a resolved `&Ring` to avoid a
/// redundant `find_ring` lookup in the dispatch hot path.
pub fn push_completion_for_ring(
    ring: &super::ring::Ring,
    user_data: u64,
    result: i32,
    flags: u32,
) -> bool {
    // Reject if destroyed
    if ring.destroyed.load(core::sync::atomic::Ordering::Acquire) != 0 {
        return false;
    }

    let _guard = ring.cq_lock.lock();

    let cqe = AsyncCqe {
        user_data,
        res: result,
        flags,
    };

    // Single acquisition of the backlog lock.
    let mut backlog = ring.completion_backlog.lock();

    if !backlog.is_empty() {
        // Backlog already has entries: always append to it.
        backlog.push(cqe);
        drop(backlog);
        flush_backlog_locked(ring);
    } else if cq_space_available(ring) == 0 {
        // CQ visible to userspace is full so push to backlog.
        backlog.push(cqe);
        drop(backlog);
    } else {
        drop(backlog);
        write_cqe_at_tail(ring, cqe);
    }

    // Decrement the in-flight counter
    let _ = ring.in_flight.fetch_update(
        core::sync::atomic::Ordering::Relaxed,
        core::sync::atomic::Ordering::Relaxed,
        |value| value.checked_sub(1),
    );

    // Wake any task waiting on this ring
    ring.wq.wake_all();

    true
}

/// Drain all pending completions for a ring and return them.
/// Called by `SYS_ASYNC_ENTER` when userspace wants to consume CQEs.
pub fn drain_completions(ring_id: u64, max: u32) -> u32 {
    let Some(ring) = find_ring(ring_id) else {
        return 0;
    };

    let _guard = ring.cq_lock.lock();

    let head = ring.cq_head();
    let tail = ring
        .cq_meta()
        .tail
        .load(core::sync::atomic::Ordering::Acquire);
    let available = tail.wrapping_sub(head).min(max);
    if available == 0 {
        return 0;
    }

    // No need to copy CQEs : userspace reads them directly from the
    // shared CQ page. We just advance head to acknowledge consumption.
    ring.cq_meta().head.store(
        head.wrapping_add(available),
        core::sync::atomic::Ordering::Release,
    );

    if flush_backlog_locked(&ring) > 0 {
        ring.wq.wake_all();
    }

    available
}

/// Number of in-flight operations tracked for a ring.
pub fn in_flight_count(ring_id: u64) -> u32 {
    let Some(ring) = find_ring(ring_id) else {
        return 0;
    };
    ring.in_flight.load(core::sync::atomic::Ordering::Relaxed)
}

#[inline]
pub fn inc_in_flight(ring_id: u64) {
    if let Some(ring) = find_ring(ring_id) {
        inc_in_flight_for_ring(&ring);
    }
}

/// Variant of [`inc_in_flight`] that takes a resolved `&Ring`.
#[inline]
pub fn inc_in_flight_for_ring(ring: &super::ring::Ring) {
    ring.in_flight
        .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}

#[inline]
pub fn dec_in_flight(ring_id: u64) {
    if let Some(ring) = find_ring(ring_id) {
        ring.in_flight
            .fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
    }
}
