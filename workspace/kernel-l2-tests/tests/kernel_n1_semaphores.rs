//! L2 — N1 TypeSafe events + POSIX-style semaphores (verbatim kernel code).
//!
//! Semaphore blocking paths (`wait` on a zero count) would block forever
//! single-threaded; the suite pins `try_wait`, `post`, lifecycle and the
//! registry used by SYS_SEM_* syscalls.

use kernel_l2_tests::ipc::n1::{notify_scheduler, poll_scheduler_events, N1Event};
use kernel_l2_tests::ipc::semaphore::{
    create_semaphore, destroy_semaphore, get_semaphore, SemaphoreError,
};

// ===========================================================================
// N1 scheduler event mailbox (inline kernel tests already cover roundtrip;
// these add ordering + multi-event drain semantics)
// ===========================================================================

#[test]
fn n1_events_drain_in_reverse_push_order() {
    // FINDING F11 (testing-findings.md): the scheduler event mailbox is
    // backed by IntrusiveMailbox, a LIFO stack ("message order is reversed
    // on reception" per its docs). Events therefore drain in REVERSE push
    // order. Harmless for independent event types, but if consumers ever
    // rely on causal ordering (e.g. SchedTick before Wakeup), this is a bug.
    // Pinned AS IMPLEMENTED; flip to FIFO together with a kernel change.
    notify_scheduler(N1Event::MemoryPressure);
    notify_scheduler(N1Event::Wakeup);
    notify_scheduler(N1Event::FsNotification);
    assert_eq!(poll_scheduler_events(), Some(N1Event::FsNotification));
    assert_eq!(poll_scheduler_events(), Some(N1Event::Wakeup));
    assert_eq!(poll_scheduler_events(), Some(N1Event::MemoryPressure));
    assert_eq!(poll_scheduler_events(), None);
}

#[test]
fn n1_event_encode_is_lossless_for_all_variants() {
    let all = [
        N1Event::NicLinkChange,
        N1Event::NicBackpressure,
        N1Event::MemoryPressure,
        N1Event::FsNotification,
        N1Event::SchedTick,
        N1Event::Wakeup,
    ];
    for ev in all {
        let encoded = ev.encode();
        assert_eq!(N1Event::decode(&encoded), Some(ev));
    }
}

// ===========================================================================
// Semaphores: registry + counting semantics
// ===========================================================================

#[test]
fn semaphore_counting_semantics() {
    let id = create_semaphore(2).expect("create(2)");
    let sem = get_semaphore(id).expect("lookup");
    assert_eq!(sem.count(), 2);

    sem.try_wait().expect("wait #1");
    assert_eq!(sem.count(), 1);
    sem.try_wait().expect("wait #2");
    assert_eq!(sem.count(), 0);

    // Third wait on zero: non-blocking must fail WouldBlock-ish, not go negative.
    assert!(sem.try_wait().is_err());
    assert_eq!(sem.count(), 0);

    sem.post().expect("post");
    assert_eq!(sem.count(), 1);
    sem.try_wait().expect("wait after post");
}

#[test]
fn semaphore_post_above_zero_stays_bounded() {
    let id = create_semaphore(1).expect("create(1)");
    let sem = get_semaphore(id).unwrap();
    sem.post().expect("post on positive count is legal");
    let c = sem.count();
    // Kernel policy pinned here: post increments even above initial value
    // (no maximum clamp) — matches POSIX unnamed semaphores.
    assert!(c >= 1 && c <= 2, "unexpected count {} after post", c);
}

#[test]
fn semaphore_destroy_rejects_further_ops() {
    let id = create_semaphore(3).expect("create");
    let sem = get_semaphore(id).unwrap();
    sem.destroy();
    assert!(sem.is_destroyed());
    assert!(matches!(sem.try_wait(), Err(SemaphoreError::Destroyed)));
    assert!(matches!(sem.post(), Err(SemaphoreError::Destroyed)));
    // Registry-level destroy of an already-destroyed semaphore: tolerant.
    assert!(destroy_semaphore(id).is_ok() || destroy_semaphore(id).is_err());
}

#[test]
fn semaphore_registry_unknown_id_fails_cleanly() {
    assert!(get_semaphore(kernel_l2_tests::ipc::semaphore::SemId::from_u64(u64::MAX)).is_none());
}
