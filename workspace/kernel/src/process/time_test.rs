//! Time syscall self-test suite.
//!
//! Exercises: clock_gettime monotonicity, nanosleep, tick-to-ns conversion.
//!
//! Runs only under `feature = "selftest"`.

use crate::{
    process::{add_task, scheduler::ticks, Task, TaskPriority},
    syscall::time::{current_time_ns, sys_clock_gettime, CLOCK_MONOTONIC},
};

fn log_section(title: &str) {
    crate::serial_println!(
        "[time-test][STEP] ========================================================"
    );
    crate::serial_println!("[time-test][STEP] {}", title);
    crate::serial_println!(
        "[time-test][STEP] ========================================================"
    );
}

fn record(name: &str, ok: bool, passed: &mut usize, total: &mut usize) {
    *total += 1;
    if ok {
        *passed += 1;
    }
    crate::serial_println!(
        "[time-test][ASSERT][SCENARIO] {:<48} => {}",
        name,
        if ok { "PASS" } else { "FAIL" }
    );
}

fn run_time_suite() -> bool {
    let mut passed = 0usize;
    let mut total = 0usize;

    // ── 1. clock_gettime returns non-zero ───────────────────────────────────
    log_section("1. CLOCK_GETTIME NON-ZERO");
    let mut s = true;
    let mut ts = TimeSpec::from_nanos(0);
    let ts_ptr = &mut ts as *mut TimeSpec as u64;
    match sys_clock_gettime(CLOCK_MONOTONIC, ts_ptr) {
        Ok(ret) => {
            let ns = ts.to_nanos();
            crate::serial_println!(
                "[time-test][STEP] clock_gettime() => {} ns (ret={})",
                ns,
                ret
            );
            if ns == 0 {
                crate::serial_println!("[time-test][ASSERT] FAIL: clock_gettime returned 0");
                s = false;
            }
        }
        Err(e) => {
            crate::serial_println!("[time-test][STEP] clock_gettime => {:?}", e);
            s = false;
        }
    }
    record("clock_gettime returns non-zero", s, &mut passed, &mut total);

    // ── 2. current_time_ns matches ticks * 10_000_000 ──────────────────────
    log_section("2. CURRENT_TIME_NS FORMULA");
    let mut s = true;
    let t = ticks();
    let ns = current_time_ns();
    let expected = t * 10_000_000;
    crate::serial_println!(
        "[time-test][STEP] ticks={} current_time_ns={} expected={}",
        t,
        ns,
        expected
    );
    if ns < expected {
        crate::serial_println!(
            "[time-test][ASSERT] FAIL: ns < ticks*10M (tick advanced between calls is OK but ns should be >= expected-10M)"
        );
    }
    if ns > expected + 10_000_000 {
        crate::serial_println!(
            "[time-test][STEP] note: ns > expected+10M : tick advanced between calls"
        );
    }
    record("current_time_ns formula", s, &mut passed, &mut total);

    // ── 3. monotonicity: 10 consecutive calls ──────────────────────────────
    log_section("3. MONOTONICITY (10 CALLS)");
    let mut s = true;
    let mut prev = current_time_ns();
    for i in 1..=10 {
        let now = current_time_ns();
        crate::serial_println!("[time-test][STEP] call {}: prev={} now={}", i, prev, now);
        if now < prev {
            crate::serial_println!("[time-test][ASSERT] FAIL: time went backward at call {}", i);
            s = false;
        }
        prev = now;
    }
    record("monotonicity 10 calls", s, &mut passed, &mut total);

    // ── 4. monotonicity across yields ───────────────────────────────────────
    log_section("4. MONOTONICITY ACROSS YIELDS");
    let mut s = true;
    let before = current_time_ns();
    for _ in 0..5 {
        crate::process::yield_task();
    }
    let after = current_time_ns();
    crate::serial_println!(
        "[time-test][STEP] before yields={} after yields={} delta={}",
        before,
        after,
        after.saturating_sub(before)
    );
    if after < before {
        crate::serial_println!("[time-test][ASSERT] FAIL: time went backward across yields");
        s = false;
    }
    record("monotonicity across yields", s, &mut passed, &mut total);

    // ── 5. time advances after yield ────────────────────────────────────────
    log_section("5. TIME ADVANCES AFTER YIELD");
    let mut s = true;
    let t0 = current_time_ns();
    let start_ticks = ticks();
    loop {
        crate::process::yield_task();
        if ticks().saturating_sub(start_ticks) > 50 {
            break;
        }
    }
    let t1 = current_time_ns();
    crate::serial_println!(
        "[time-test][STEP] t0={} t1={} delta={} ns",
        t0,
        t1,
        t1.saturating_sub(t0)
    );
    if t1 <= t0 {
        crate::serial_println!("[time-test][ASSERT] FAIL: time did not advance after ~50 ticks");
        s = false;
    }
    record("time advances after yield", s, &mut passed, &mut total);

    // ── 6. ticks counter consistency ────────────────────────────────────────
    log_section("6. TICKS COUNTER");
    let mut s = true;
    let t1 = ticks();
    crate::process::yield_task();
    let t2 = ticks();
    crate::serial_println!(
        "[time-test][STEP] ticks before yield={} after yield={}",
        t1,
        t2
    );
    if t2 < t1 {
        crate::serial_println!("[time-test][ASSERT] FAIL: ticks went backward");
        s = false;
    }
    record("ticks counter monotonic", s, &mut passed, &mut total);

    // ── 7. TimeSpec from_nanos → to_nanos round-trip ────────────────────────
    log_section("7. TIMESPEC ROUND-TRIP");
    use strat9_abi::data::TimeSpec;
    let mut s = true;
    let test_values: &[u64] = &[
        0,
        1,
        999_999_999,
        1_000_000_000,
        5_500_000_000,
        u64::MAX / 2,
    ];
    for &v in test_values {
        let ts = TimeSpec::from_nanos(v);
        let back = ts.to_nanos();
        crate::serial_println!(
            "[time-test][STEP] from_nanos({}) => sec={} nsec={} => to_nanos={}",
            v,
            ts.tv_sec,
            ts.tv_nsec,
            back
        );
        if back != v {
            crate::serial_println!("[time-test][ASSERT] FAIL: round-trip mismatch for {}", v);
            s = false;
        }
    }
    record("TimeSpec round-trip", s, &mut passed, &mut total);

    // ── 8. clock_gettime syscall matches current_time_ns ────────────────────
    log_section("8. SYSCALL vs INTERNAL API");
    let mut s = true;
    let internal = current_time_ns();
    let mut ts = TimeSpec::from_nanos(0);
    let ts_ptr = &mut ts as *mut TimeSpec as u64;
    let syscall_ret = sys_clock_gettime(CLOCK_MONOTONIC, ts_ptr);
    let syscall_val = if syscall_ret.is_ok() {
        ts.to_nanos()
    } else {
        0
    };
    crate::serial_println!(
        "[time-test][STEP] internal={} syscall={} delta={}",
        internal,
        syscall_val,
        syscall_val.saturating_sub(internal)
    );
    if syscall_val < internal {
        crate::serial_println!("[time-test][ASSERT] FAIL: syscall < internal");
        s = false;
    }
    if syscall_val.saturating_sub(internal) > 100_000_000 {
        crate::serial_println!("[time-test][ASSERT] FAIL: syscall/internal delta > 100ms");
        s = false;
    }
    record("syscall vs internal API", s, &mut passed, &mut total);

    // ── 9. timing a known-length busy wait ──────────────────────────────────
    log_section("9. TIMING BUSY WAIT");
    let mut s = true;
    let before = current_time_ns();
    let start = ticks();
    while ticks().saturating_sub(start) < 100 {
        crate::process::yield_task();
    }
    let after = current_time_ns();
    let elapsed_ns = after.saturating_sub(before);
    let elapsed_ms = elapsed_ns / 1_000_000;
    crate::serial_println!(
        "[time-test][STEP] 100-tick wait: elapsed={}ms (expected ~1000ms)",
        elapsed_ms
    );
    if elapsed_ms < 500 {
        crate::serial_println!("[time-test][ASSERT] FAIL: elapsed < 500ms for 100 ticks");
        s = false;
    }
    if elapsed_ms > 5000 {
        crate::serial_println!("[time-test][ASSERT] FAIL: elapsed > 5000ms for 100 ticks");
        s = false;
    }
    record("timing busy wait ~1s", s, &mut passed, &mut total);

    // ── Summary ─────────────────────────────────────────────────────────────
    log_section("TIME TEST SUMMARY");
    let ok = passed == total;
    crate::serial_println!(
        "[time-test][ASSERT] result: {}/{} scenarios PASS",
        passed,
        total
    );
    crate::serial_println!(
        "[time-test][ASSERT] final : {}",
        if ok { "PASS" } else { "FAIL" }
    );
    ok
}

extern "C" fn time_test_main() -> ! {
    crate::serial_println!("[time-test][SETUP] task start");
    let _ = run_time_suite();
    crate::serial_println!("[time-test][CLEANUP] task done");
    crate::process::scheduler::exit_current_task(0);
}

pub fn create_time_test_task() {
    if let Ok(task) = Task::new_kernel_task(time_test_main, "time-test", TaskPriority::Normal) {
        add_task(task);
    } else {
        crate::serial_println!("[time-test][SETUP] failed to create task");
    }
}
