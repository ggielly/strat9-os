//! Kernel self-test orchestrator.
//!
//! Add new test modules here so a single `selftest` feature controls all
//! runtime validation tasks.

pub fn create_selftest_tasks() {
    crate::process::futex_test::create_futex_test_task();
}

