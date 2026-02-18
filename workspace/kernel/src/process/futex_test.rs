//! Concurrent futex self-tests for kernel validation.
//!
//! The tests are runtime kernel tasks (not `#[test]`) to match the current
//! no_std boot flow. Scenarios are isolated and share a small common harness.

use core::sync::atomic::{AtomicI32, AtomicIsize, AtomicU32, AtomicU64, Ordering};

use crate::{
    memory::address_space::{VmaFlags, VmaType},
    process::{add_task, Task, TaskPriority},
    syscall::{error::SyscallError, futex},
};

const FUTEX_TIMEOUT_NS: u64 = 2_000_000_000;
const WAIT_LOOPS: usize = 20_000;
const TEST_PAGE_A: u64 = 0x0000_4000_0000;
const TEST_PAGE_B: u64 = 0x0000_4000_1000;

static FUTEX_A_ADDR: AtomicU64 = AtomicU64::new(0);
static FUTEX_B_ADDR: AtomicU64 = AtomicU64::new(0);

// Shared atomics used by scenario tasks.
static SC_DONE: AtomicU32 = AtomicU32::new(0);
static SC_WAIT_RES_1: AtomicIsize = AtomicIsize::new(0);
static SC_WAIT_RES_2: AtomicIsize = AtomicIsize::new(0);
static SC_WAKE_RES_1: AtomicIsize = AtomicIsize::new(0);
static SC_WAKE_RES_2: AtomicIsize = AtomicIsize::new(0);
static SC_PHASE: AtomicI32 = AtomicI32::new(0);

fn encode_result(res: Result<u64, SyscallError>) -> isize {
    match res {
        Ok(v) => v as isize,
        Err(e) => e as i64 as isize,
    }
}

fn wait_done(target: u32) -> bool {
    for _ in 0..WAIT_LOOPS {
        if SC_DONE.load(Ordering::Acquire) >= target {
            return true;
        }
        crate::process::yield_task();
    }
    false
}

fn reset_scenario_state() {
    SC_DONE.store(0, Ordering::Release);
    SC_WAIT_RES_1.store(0, Ordering::Release);
    SC_WAIT_RES_2.store(0, Ordering::Release);
    SC_WAKE_RES_1.store(0, Ordering::Release);
    SC_WAKE_RES_2.store(0, Ordering::Release);
    SC_PHASE.store(0, Ordering::Release);
}

fn spawn_task(entry: extern "C" fn() -> !, name: &'static str) -> bool {
    match Task::new_kernel_task(entry, name, TaskPriority::Normal) {
        Ok(t) => {
            add_task(t);
            true
        }
        Err(e) => {
            crate::serial_println!("[futex-test] failed to spawn {}: {}", name, e);
            false
        }
    }
}

fn map_test_pages() -> bool {
    let aspace = crate::memory::kernel_address_space();
    let flags = VmaFlags {
        readable: true,
        writable: true,
        executable: false,
        user_accessible: true,
    };

    if let Err(e) = aspace.map_region(TEST_PAGE_A, 1, flags, VmaType::Anonymous) {
        crate::serial_println!("[futex-test] map A failed: {}", e);
        return false;
    }
    if let Err(e) = aspace.map_region(TEST_PAGE_B, 1, flags, VmaType::Anonymous) {
        crate::serial_println!("[futex-test] map B failed: {}", e);
        return false;
    }

    FUTEX_A_ADDR.store(TEST_PAGE_A, Ordering::Release);
    FUTEX_B_ADDR.store(TEST_PAGE_B, Ordering::Release);

    // SAFETY: We just mapped these pages writable in the current address space.
    unsafe {
        *(TEST_PAGE_A as *mut u32) = 0;
        *(TEST_PAGE_B as *mut u32) = 0;
    }
    true
}

extern "C" fn waiter_a_1() -> ! {
    SC_PHASE.fetch_add(1, Ordering::AcqRel);
    let addr = FUTEX_A_ADDR.load(Ordering::Acquire);
    let r = encode_result(futex::sys_futex_wait(addr, 0, FUTEX_TIMEOUT_NS));
    SC_WAIT_RES_1.store(r, Ordering::Release);
    SC_DONE.fetch_add(1, Ordering::AcqRel);
    crate::process::scheduler::exit_current_task();
}

extern "C" fn waiter_a_2() -> ! {
    SC_PHASE.fetch_add(1, Ordering::AcqRel);
    let addr = FUTEX_A_ADDR.load(Ordering::Acquire);
    let r = encode_result(futex::sys_futex_wait(addr, 0, FUTEX_TIMEOUT_NS));
    SC_WAIT_RES_2.store(r, Ordering::Release);
    SC_DONE.fetch_add(1, Ordering::AcqRel);
    crate::process::scheduler::exit_current_task();
}

extern "C" fn waiter_b_1() -> ! {
    SC_PHASE.fetch_add(1, Ordering::AcqRel);
    let addr = FUTEX_B_ADDR.load(Ordering::Acquire);
    let r = encode_result(futex::sys_futex_wait(addr, 0, FUTEX_TIMEOUT_NS));
    SC_WAIT_RES_2.store(r, Ordering::Release);
    SC_DONE.fetch_add(1, Ordering::AcqRel);
    crate::process::scheduler::exit_current_task();
}

extern "C" fn wake_loop_a() -> ! {
    let addr = FUTEX_A_ADDR.load(Ordering::Acquire);
    let mut rv = 0isize;
    for _ in 0..WAIT_LOOPS {
        rv = encode_result(futex::sys_futex_wake(addr, 1));
        if rv > 0 {
            break;
        }
        crate::process::yield_task();
    }
    SC_WAKE_RES_1.store(rv, Ordering::Release);
    SC_DONE.fetch_add(1, Ordering::AcqRel);
    crate::process::scheduler::exit_current_task();
}

fn run_wait_wake_scenario() -> bool {
    reset_scenario_state();
    // SAFETY: Test pages are mapped and writable.
    unsafe { *(FUTEX_A_ADDR.load(Ordering::Acquire) as *mut u32) = 0 };

    if !spawn_task(waiter_a_1, "futex-wait-a1") {
        return false;
    }
    if !spawn_task(wake_loop_a, "futex-wake-a") {
        return false;
    }
    if !wait_done(2) {
        crate::serial_println!("[futex-test] wait/wake timeout");
        return false;
    }

    let wait_res = SC_WAIT_RES_1.load(Ordering::Acquire);
    let wake_res = SC_WAKE_RES_1.load(Ordering::Acquire);
    wait_res == 0 && wake_res > 0
}

fn run_cmp_requeue_scenario() -> bool {
    reset_scenario_state();
    let a = FUTEX_A_ADDR.load(Ordering::Acquire);
    let b = FUTEX_B_ADDR.load(Ordering::Acquire);
    // SAFETY: Test pages are mapped and writable.
    unsafe {
        *(a as *mut u32) = 0;
        *(b as *mut u32) = 0;
    }

    if !spawn_task(waiter_a_1, "futex-cmp-a1") {
        return false;
    }
    if !spawn_task(waiter_a_2, "futex-cmp-a2") {
        return false;
    }

    // Let both waiters enter wait path.
    for _ in 0..200 {
        if SC_PHASE.load(Ordering::Acquire) >= 2 {
            break;
        }
        crate::process::yield_task();
    }

    let cmp_res = encode_result(futex::sys_futex_cmp_requeue(a, 1, 1, b, 0));
    if cmp_res < 0 {
        crate::serial_println!("[futex-test] cmp_requeue failed: {}", cmp_res);
        return false;
    }

    let mut wake_b = 0isize;
    for _ in 0..WAIT_LOOPS {
        wake_b = encode_result(futex::sys_futex_wake(b, 2));
        if wake_b > 0 {
            break;
        }
        crate::process::yield_task();
    }
    SC_WAKE_RES_1.store(cmp_res, Ordering::Release);
    SC_WAKE_RES_2.store(wake_b, Ordering::Release);

    if !wait_done(2) {
        crate::serial_println!("[futex-test] cmp_requeue waiters timeout");
        return false;
    }

    let w1 = SC_WAIT_RES_1.load(Ordering::Acquire);
    let w2 = SC_WAIT_RES_2.load(Ordering::Acquire);
    let cmp = SC_WAKE_RES_1.load(Ordering::Acquire);
    let wb = SC_WAKE_RES_2.load(Ordering::Acquire);
    w1 == 0 && w2 == 0 && cmp >= 1 && wb >= 1
}

fn run_cmp_requeue_eagain_scenario() -> bool {
    reset_scenario_state();
    let a = FUTEX_A_ADDR.load(Ordering::Acquire);
    let b = FUTEX_B_ADDR.load(Ordering::Acquire);
    // SAFETY: Test pages are mapped and writable.
    unsafe {
        *(a as *mut u32) = 0;
        *(b as *mut u32) = 0;
    }

    if !spawn_task(waiter_a_1, "futex-cmp-eagain-a1") {
        return false;
    }

    for _ in 0..200 {
        if SC_PHASE.load(Ordering::Acquire) >= 1 {
            break;
        }
        crate::process::yield_task();
    }

    // Expected value mismatch -> EAGAIN, no requeue.
    let cmp_res = encode_result(futex::sys_futex_cmp_requeue(a, 1, 1, b, 1));
    let expect_again = cmp_res == SyscallError::Again as i64 as isize;

    let mut wake_a = 0isize;
    for _ in 0..WAIT_LOOPS {
        wake_a = encode_result(futex::sys_futex_wake(a, 1));
        if wake_a > 0 {
            break;
        }
        crate::process::yield_task();
    }

    if !wait_done(1) {
        crate::serial_println!("[futex-test] cmp_requeue(EAGAIN) waiter timeout");
        return false;
    }

    let w1 = SC_WAIT_RES_1.load(Ordering::Acquire);
    expect_again && wake_a > 0 && w1 == 0
}

fn run_wake_op_scenario() -> bool {
    reset_scenario_state();
    let a = FUTEX_A_ADDR.load(Ordering::Acquire);
    let b = FUTEX_B_ADDR.load(Ordering::Acquire);
    // SAFETY: Test pages are mapped and writable.
    unsafe {
        *(a as *mut u32) = 0;
        *(b as *mut u32) = 0;
    }

    if !spawn_task(waiter_a_1, "futex-op-a1") {
        return false;
    }
    if !spawn_task(waiter_b_1, "futex-op-b1") {
        return false;
    }

    for _ in 0..200 {
        if SC_PHASE.load(Ordering::Acquire) >= 2 {
            break;
        }
        crate::process::yield_task();
    }

    // op=ADD(1), cmp=EQ(0), oparg=1, cmparg=0.
    let wake_op_bits: u32 = (1 << 28) | (1 << 12);
    let op_res = encode_result(futex::sys_futex_wake_op(a, 1, 1, b, wake_op_bits));
    SC_WAKE_RES_1.store(op_res, Ordering::Release);

    if !wait_done(2) {
        crate::serial_println!("[futex-test] wake_op waiters timeout");
        return false;
    }

    // SAFETY: mapped test page.
    let b_val = unsafe { *(b as *const u32) };
    let w1 = SC_WAIT_RES_1.load(Ordering::Acquire);
    let w2 = SC_WAIT_RES_2.load(Ordering::Acquire);
    let op = SC_WAKE_RES_1.load(Ordering::Acquire);
    w1 == 0 && w2 == 0 && op >= 1 && b_val == 1
}

extern "C" fn futex_test_main() -> ! {
    crate::serial_println!("[futex-test] start");

    if !map_test_pages() {
        crate::serial_println!("[futex-test] setup failed");
        crate::process::scheduler::exit_current_task();
    }

    let s1 = run_wait_wake_scenario();
    crate::serial_println!("[futex-test] wait/wake: {}", if s1 { "ok" } else { "FAIL" });

    let s2 = run_cmp_requeue_scenario();
    crate::serial_println!(
        "[futex-test] cmp_requeue: {}",
        if s2 { "ok" } else { "FAIL" }
    );

    let s3 = run_cmp_requeue_eagain_scenario();
    crate::serial_println!(
        "[futex-test] cmp_requeue(EAGAIN): {}",
        if s3 { "ok" } else { "FAIL" }
    );

    let s4 = run_wake_op_scenario();
    crate::serial_println!("[futex-test] wake_op: {}", if s4 { "ok" } else { "FAIL" });

    // Cleanup mapped pages.
    let aspace = crate::memory::kernel_address_space();
    let _ = aspace.unmap_region(TEST_PAGE_A, 1);
    let _ = aspace.unmap_region(TEST_PAGE_B, 1);

    crate::serial_println!(
        "[futex-test] summary: {}",
        if s1 && s2 && s3 && s4 { "PASS" } else { "FAIL" }
    );
    crate::process::scheduler::exit_current_task();
}

/// Create the futex concurrency self-test task.
pub fn create_futex_test_task() {
    if let Ok(task) = Task::new_kernel_task(futex_test_main, "futex-test", TaskPriority::Normal) {
        add_task(task);
    } else {
        crate::serial_println!("[futex-test] failed to create orchestrator task");
    }
}
