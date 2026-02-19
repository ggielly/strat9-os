//! Runtime self-tests for mmap/munmap/brk syscalls.
//!
//! These tests run only with `feature = "selftest"` (test ISO), never on normal ISO.

use crate::{
    process::{add_task, Task, TaskPriority},
    syscall::{error::SyscallError, mmap},
};

const TEST_MAP_ADDR: u64 = 0x0000_5000_0000;
const PROT_RW: u32 = (1 << 0) | (1 << 1);
const MAP_SHARED: u32 = 1 << 0;
const MAP_PRIVATE: u32 = 1 << 1;
const MAP_FIXED: u32 = 1 << 4;
const MAP_ANONYMOUS: u32 = 1 << 5;
const MAP_FIXED_NOREPLACE: u32 = 1 << 20;

fn is_err(res: &Result<u64, SyscallError>, code: SyscallError) -> bool {
    matches!(res, Err(e) if *e == code)
}

fn test_flags_validation() -> bool {
    // Missing MAP_PRIVATE/MAP_SHARED.
    let r1 = mmap::sys_mmap(0, 4096, PROT_RW, MAP_ANONYMOUS, 0, 0);
    // Both MAP_PRIVATE and MAP_SHARED set.
    let r2 = mmap::sys_mmap(0, 4096, PROT_RW, MAP_ANONYMOUS | MAP_PRIVATE | MAP_SHARED, 0, 0);
    // Unknown flag bit.
    let r3 = mmap::sys_mmap(0, 4096, PROT_RW, MAP_ANONYMOUS | MAP_PRIVATE | (1 << 30), 0, 0);
    is_err(&r1, SyscallError::InvalidArgument)
        && is_err(&r2, SyscallError::InvalidArgument)
        && is_err(&r3, SyscallError::InvalidArgument)
}

fn test_munmap_overflow_guard() -> bool {
    let r = mmap::sys_munmap(TEST_MAP_ADDR, u64::MAX);
    is_err(&r, SyscallError::InvalidArgument)
}

fn test_fixed_noreplace() -> bool {
    let base_flags = MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED;
    let r1 = mmap::sys_mmap(TEST_MAP_ADDR, 4096, PROT_RW, base_flags, 0, 0);
    if r1 != Ok(TEST_MAP_ADDR) {
        crate::serial_println!("[mmap-test] setup map failed: {:?}", r1);
        return false;
    }

    let r2 = mmap::sys_mmap(
        TEST_MAP_ADDR,
        4096,
        PROT_RW,
        base_flags | MAP_FIXED_NOREPLACE,
        0,
        0,
    );
    let _ = mmap::sys_munmap(TEST_MAP_ADDR, 4096);
    is_err(&r2, SyscallError::AlreadyExists)
}

fn test_brk_contract() -> bool {
    let cur = match mmap::sys_brk(0) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let grow_to = cur.saturating_add(4096);
    let rgrow = mmap::sys_brk(grow_to);
    if rgrow != Ok(grow_to) {
        return false;
    }

    // Invalid low break must return unchanged current break (Linux contract).
    let invalid = mmap::sys_brk(mmap::BRK_BASE.saturating_sub(4096));
    if invalid != Ok(grow_to) {
        return false;
    }

    let shrink = mmap::sys_brk(cur);
    shrink == Ok(cur)
}

fn test_oom_rollback() -> bool {
    let aspace = crate::memory::kernel_address_space();
    let before = aspace.has_mapping_in_range(TEST_MAP_ADDR, 4096);
    if before {
        let _ = mmap::sys_munmap(TEST_MAP_ADDR, 4096);
    }

    let (total_pages, allocated_pages) = {
        let lock = crate::memory::buddy::get_allocator();
        let guard = lock.lock();
        let Some(alloc) = guard.as_ref() else {
            return false;
        };
        alloc.page_totals()
    };
    let free_pages = total_pages.saturating_sub(allocated_pages);
    // Ask slightly above currently free pages to force OOM and exercise rollback path.
    let req_pages = free_pages.saturating_add(4096);
    let req_len = (req_pages as u64).saturating_mul(4096);

    let r = mmap::sys_mmap(
        TEST_MAP_ADDR,
        req_len,
        PROT_RW,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
        0,
        0,
    );
    let cleaned = !aspace.has_mapping_in_range(TEST_MAP_ADDR, 4096);
    is_err(&r, SyscallError::OutOfMemory) && cleaned
}

extern "C" fn mmap_test_main() -> ! {
    crate::serial_println!("[mmap-test] start");

    let t1 = test_flags_validation();
    crate::serial_println!("[mmap-test] flags validation: {}", if t1 { "ok" } else { "FAIL" });

    let t2 = test_munmap_overflow_guard();
    crate::serial_println!("[mmap-test] munmap overflow guard: {}", if t2 { "ok" } else { "FAIL" });

    let t3 = test_fixed_noreplace();
    crate::serial_println!("[mmap-test] MAP_FIXED_NOREPLACE: {}", if t3 { "ok" } else { "FAIL" });

    let t4 = test_brk_contract();
    crate::serial_println!("[mmap-test] brk contract: {}", if t4 { "ok" } else { "FAIL" });

    let t5 = test_oom_rollback();
    crate::serial_println!("[mmap-test] OOM rollback: {}", if t5 { "ok" } else { "FAIL" });

    crate::serial_println!(
        "[mmap-test] summary: {}",
        if t1 && t2 && t3 && t4 && t5 { "PASS" } else { "FAIL" }
    );
    crate::process::scheduler::exit_current_task(0);
}

pub fn create_mmap_test_task() {
    if let Ok(task) = Task::new_kernel_task(mmap_test_main, "mmap-test", TaskPriority::Normal) {
        add_task(task);
    } else {
        crate::serial_println!("[mmap-test] failed to create task");
    }
}

