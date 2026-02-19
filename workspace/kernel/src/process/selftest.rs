//! Kernel self-test orchestrator.
//!
//! Add new test modules here so a single `selftest` feature controls all
//! runtime validation tasks.

pub fn create_selftest_tasks() {
    crate::process::fork_test::create_fork_test_task();
    // Keep fork validation isolated to avoid cross-test interference in the
    // current runtime harness. Re-enable futex/mmap once orchestration is
    // serialized.
    // crate::process::futex_test::create_futex_test_task();
    // crate::process::mmap_test::create_mmap_test_task();
}
