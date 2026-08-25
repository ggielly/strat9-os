//! L2 — kernel sync primitives (FixedQueue, SpinLock) + namespace table.
//!
//! All code under test is the verbatim kernel source included by the
//! mirror; only IRQ gating is faked (single-threaded host).

use kernel_l2_tests::namespace;
use kernel_l2_tests::sync::{FixedQueue, SpinLock};

// ===========================================================================
// FixedQueue: bounded ring with Result-preserving push
// ===========================================================================

#[test]
fn fixed_queue_push_pop_fifo_order() {
    let mut q: FixedQueue<u32, 4> = FixedQueue::new();
    assert!(q.is_empty());
    assert_eq!(q.len(), 0);

    q.push_back(1).expect("push 1");
    q.push_back(2).expect("push 2");
    q.push_back(3).expect("push 3");
    assert_eq!(q.len(), 3);

    assert_eq!(q.pop_front(), Some(1), "FIFO order violated");
    assert_eq!(q.pop_front(), Some(2));
    assert_eq!(q.pop_front(), Some(3));
    assert_eq!(q.pop_front(), None);
}

#[test]
fn fixed_queue_full_push_returns_value_back() {
    let mut q: FixedQueue<u8, 2> = FixedQueue::new();
    q.push_back(10).unwrap();
    q.push_back(20).unwrap();
    assert!(q.is_full());
    // Overflow must RETURN the value (not panic, not drop it).
    assert_eq!(q.push_back(30), Err(30));
    assert_eq!(q.len(), 2);
    assert_eq!(q.pop_front(), Some(10));
}

#[test]
fn fixed_queue_wraparound_after_pops() {
    let mut q: FixedQueue<usize, 4> = FixedQueue::new();
    for i in 0..4 {
        q.push_back(i).unwrap();
    }
    // Drain two → push two more → internal ring must wrap cleanly.
    assert_eq!(q.pop_front(), Some(0));
    assert_eq!(q.pop_front(), Some(1));
    q.push_back(100).unwrap();
    q.push_back(101).unwrap();
    assert!(q.is_full());
    assert_eq!((&[2, 3, 100, 101].iter().collect::<Vec<_>>()[..]), &q.iter().collect::<Vec<_>>());
}

#[test]
fn fixed_queue_get_and_back() {
    let mut q: FixedQueue<&str, 3> = FixedQueue::new();
    q.push_back("a").unwrap();
    q.push_back("b").unwrap();
    assert_eq!(q.get(0), Some(&"a"));
    assert_eq!(q.get(1), Some(&"b"));
    assert_eq!(q.get(2), None); // beyond len, inside capacity
    assert_eq!(q.back(), Some(&"b"));
    assert_eq!(q.pop_front(), Some("a"));
    assert_eq!(q.back(), Some(&"b"));
}

// ===========================================================================
// SpinLock (real kernel spinlock, IrqDisabled guardian faked at arch level)
// ===========================================================================

#[test]
fn spinlock_lock_unlock_mutates_state() {
    static LOCK: SpinLock<u32> = SpinLock::new(0);
    *LOCK.lock() = 42;
    assert_eq!(*LOCK.lock(), 42);
}

#[test]
fn spinlock_guard_writes_are_visible_after_release() {
    let lock: SpinLock<Vec<u32>> = SpinLock::new(Vec::new());
    for i in 0..16u32 {
        let mut g = lock.lock();
        g.push(i);
        drop(g);
    }
    assert_eq!(lock.lock().len(), 16);
}

// ===========================================================================
// Namespace: Plan-9 style prefix→port binding table
// ===========================================================================

#[test]
fn namespace_bind_resolve_roundtrip() {
    namespace::bind("/net", 7).expect("bind /net");
    let (port, remaining) = namespace::resolve("/net/tcp").expect("resolve /net/tcp");
    assert_eq!(port, 7);
    // resolve() returns (port, remaining-path-after-prefix).
    assert_eq!(remaining, "/tcp");

    // Longest-prefix wins: bind a deeper prefix and check it shadows.
    namespace::bind("/net/tcp", 8).expect("bind /net/tcp");
    let (port2, remaining2) = namespace::resolve("/net/tcp/secure").expect("deep resolve");
    assert_eq!(port2, 8);
    assert_eq!(remaining2, "/secure");
}

#[test]
fn namespace_unbind_removes_binding() {
    namespace::bind("/tmp-test", 99).expect("bind");
    assert!(namespace::unbind("/tmp-test").is_ok());
    assert!(namespace::resolve("/tmp-test").is_none());
    // Unbinding again must fail with BadHandle-like error, not panic.
    assert!(namespace::unbind("/tmp-test").is_err());
}

#[test]
fn namespace_rejects_invalid_paths() {
    assert!(namespace::bind("", 1).is_err(), "empty path accepted");
    assert!(namespace::bind("relative", 1).is_err(), "relative path accepted");
}

#[test]
fn namespace_list_contains_bindings() {
    namespace::bind("/list-probe", 5).expect("bind");
    let all = namespace::list_all_bindings();
    assert!(all.iter().any(|(p, port)| p == "/list-probe" && *port == 5));
}
