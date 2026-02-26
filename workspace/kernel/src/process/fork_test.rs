//! Runtime self-tests for process syscalls around fork/waitpid/getpid/getppid.
//!
//! Runs only in test ISO (`feature = "selftest"`).

use alloc::{boxed::Box, sync::Arc};

use crate::{
    memory::address_space::{AddressSpace, VmaFlags, VmaType},
    process::{
        current_task_id,
        scheduler::add_task_with_parent,
        task::Task,
        try_wait_child, TaskId, TaskPriority, WaitChildResult,
    },
};

const USER_CODE_ADDR: u64 = 0x0040_0000;
const USER_STACK_ADDR: u64 = 0x0080_0000;
const USER_STACK_TOP: u64 = USER_STACK_ADDR + 0x1000;
const COW_TEST_ADDR: u64 = 0x0000_5000_0000;

#[repr(C)]
struct UserLaunchCtx {
    user_rip: u64,
    user_rsp: u64,
}

extern "C" fn ring3_test_trampoline(ctx_ptr: u64) -> ! {
    use crate::arch::x86_64::gdt;

    let ctx = unsafe { Box::from_raw(ctx_ptr as *mut UserLaunchCtx) };
    let user_rip = ctx.user_rip;
    let user_rsp = ctx.user_rsp;
    let user_cs = gdt::user_code_selector().0 as u64;
    let user_ss = gdt::user_data_selector().0 as u64;
    let user_rflags: u64 = 0x202;

    unsafe {
        core::arch::asm!(
            "push {ss}",
            "push {rsp_val}",
            "push {rflags}",
            "push {cs}",
            "push {rip}",
            "iretq",
            ss = in(reg) user_ss,
            rsp_val = in(reg) user_rsp,
            rflags = in(reg) user_rflags,
            cs = in(reg) user_cs,
            rip = in(reg) user_rip,
            options(noreturn),
        );
    }
}

fn spawn_user_program_task(
    name: &'static str,
    code: &[u8],
    parent: TaskId,
) -> Result<TaskId, &'static str> {
    crate::serial_println!("[fork-test] {}: new user AS", name);
    let user_as = Arc::new(AddressSpace::new_user()?);

    let code_flags = VmaFlags {
        readable: true,
        writable: true,
        executable: true,
        user_accessible: true,
    };

    let stack_flags = VmaFlags {
        readable: true,
        writable: true,
        executable: false,
        user_accessible: true,
    };
    crate::serial_println!("[fork-test] {}: map code", name);
    user_as.map_region(
        USER_CODE_ADDR,
        1,
        code_flags,
        VmaType::Code,
        crate::memory::address_space::VmaPageSize::Small,
    )?;
    crate::serial_println!("[fork-test] {}: map stack", name);
    user_as.map_region(
        USER_STACK_ADDR,
        1,
        stack_flags,
        VmaType::Stack,
        crate::memory::address_space::VmaPageSize::Small,
    )?;

    let code_phys = user_as
        .translate(x86_64::VirtAddr::new(USER_CODE_ADDR))
        .ok_or("Failed to translate user code page")?;
    let code_virt = crate::memory::phys_to_virt(code_phys.as_u64()) as *mut u8;
    unsafe {
        core::ptr::write_bytes(code_virt, 0, 4096);
        core::ptr::copy_nonoverlapping(code.as_ptr(), code_virt, code.len());
    }
    crate::serial_println!("[fork-test] {}: user payload ready", name);

    let task = Task::new_user_task(
        ring3_test_trampoline as u64,
        user_as,
        name,
        TaskPriority::Normal,
    )?;

    let launch = Box::new(UserLaunchCtx {
        user_rip: USER_CODE_ADDR,
        user_rsp: USER_STACK_TOP,
    });
    unsafe {
        let ctx = &mut *task.context.get();
        let frame = ctx.saved_rsp as *mut u64;
        *frame.add(2) = Box::into_raw(launch) as u64;
    }

    let tid = task.id;
    add_task_with_parent(task, parent);
    Ok(tid)
}

fn wait_child_exit(parent: TaskId, child: TaskId) -> Result<i32, &'static str> {
    let start = crate::process::scheduler::ticks();
    const TIMEOUT_TICKS: u64 = 500; // ~5s at 100Hz
    loop {
        match try_wait_child(parent, Some(child)) {
            WaitChildResult::Reaped { status, .. } => return Ok(status),
            WaitChildResult::NoChildren => return Err("child not found"),
            WaitChildResult::StillRunning => {
                let now = crate::process::scheduler::ticks();
                if now.saturating_sub(start) > TIMEOUT_TICKS {
                    let _ = crate::process::kill_task(child);
                    return Err("wait timeout");
                }
                crate::process::block_current_task();
            }
        }
    }
}

fn run_scenario(parent: TaskId, name: &'static str, code: &[u8]) -> bool {
    crate::serial_println!("[fork-test] {}: spawn", name);
    let child = match spawn_user_program_task(name, code, parent) {
        Ok(id) => id,
        Err(e) => {
            crate::serial_println!("[fork-test] {}: spawn failed: {}", name, e);
            return false;
        }
    };
    crate::serial_println!("[fork-test] {}: child={}", name, child.as_u64());
    match wait_child_exit(parent, child) {
        Ok(0) => true,
        Ok(status) => {
            crate::serial_println!("[fork-test] {}: FAIL exit={}", name, status);
            false
        }
        Err(e) => {
            crate::serial_println!("[fork-test] {}: wait failed: {}", name, e);
            false
        }
    }
}

fn cow_test_refcount_unmap() -> bool {
    let aspace = match AddressSpace::new_user() {
        Ok(v) => Arc::new(v),
        Err(e) => {
            crate::serial_println!("[fork-test] cow refcount: new_user failed: {}", e);
            return false;
        }
    };
    let flags = VmaFlags {
        readable: true,
        writable: true,
        executable: false,
        user_accessible: true,
    };
    if let Err(e) = aspace.map_region(
        COW_TEST_ADDR,
        1,
        flags,
        VmaType::Anonymous,
        crate::memory::address_space::VmaPageSize::Small,
    ) {
        crate::serial_println!("[fork-test] cow refcount: map failed: {}", e);
        return false;
    }

    let phys = match aspace.translate(x86_64::VirtAddr::new(COW_TEST_ADDR)) {
        Some(p) => p,
        None => {
            crate::serial_println!("[fork-test] cow refcount: translate parent failed");
            return false;
        }
    };
    let frame = crate::memory::PhysFrame {
        start_address: phys,
    };
    let r1 = crate::memory::cow::frame_get_refcount(frame);
    if r1 != 1 {
        crate::serial_println!("[fork-test] cow refcount: expected 1, got {}", r1);
        return false;
    }

    let child = match aspace.clone_cow() {
        Ok(v) => v,
        Err(e) => {
            crate::serial_println!("[fork-test] cow refcount: clone_cow failed: {}", e);
            return false;
        }
    };
    let r2 = crate::memory::cow::frame_get_refcount(frame);
    if r2 != 2 {
        crate::serial_println!(
            "[fork-test] cow refcount: expected 2 after clone, got {}",
            r2
        );
        return false;
    }

    if let Err(e) = aspace.unmap_region(
        COW_TEST_ADDR,
        1,
        crate::memory::address_space::VmaPageSize::Small,
    ) {
        crate::serial_println!("[fork-test] cow refcount: parent unmap failed: {}", e);
        return false;
    }
    let r3 = crate::memory::cow::frame_get_refcount(frame);
    if r3 != 1 {
        crate::serial_println!(
            "[fork-test] cow refcount: expected 1 after parent unmap, got {}",
            r3
        );
        return false;
    }

    if let Err(e) = child.unmap_region(
        COW_TEST_ADDR,
        1,
        crate::memory::address_space::VmaPageSize::Small,
    ) {
        crate::serial_println!("[fork-test] cow refcount: child unmap failed: {}", e);
        return false;
    }
    let r4 = crate::memory::cow::frame_get_refcount(frame);
    if r4 != 0 {
        crate::serial_println!(
            "[fork-test] cow refcount: expected 0 after child unmap, got {}",
            r4
        );
        return false;
    }

    true
}

fn cow_test_write_fault_copy() -> bool {
    let aspace = match AddressSpace::new_user() {
        Ok(v) => Arc::new(v),
        Err(e) => {
            crate::serial_println!("[fork-test] cow fault: new_user failed: {}", e);
            return false;
        }
    };
    let flags = VmaFlags {
        readable: true,
        writable: true,
        executable: false,
        user_accessible: true,
    };
    if let Err(e) = aspace.map_region(
        COW_TEST_ADDR,
        1,
        flags,
        VmaType::Anonymous,
        crate::memory::address_space::VmaPageSize::Small,
    ) {
        crate::serial_println!("[fork-test] cow fault: map failed: {}", e);
        return false;
    }

    let parent_phys = match aspace.translate(x86_64::VirtAddr::new(COW_TEST_ADDR)) {
        Some(p) => p,
        None => {
            crate::serial_println!("[fork-test] cow fault: translate parent failed");
            return false;
        }
    };
    unsafe {
        *(crate::memory::phys_to_virt(parent_phys.as_u64()) as *mut u8) = 0x11;
    }

    let child = match aspace.clone_cow() {
        Ok(v) => v,
        Err(e) => {
            crate::serial_println!("[fork-test] cow fault: clone_cow failed: {}", e);
            return false;
        }
    };

    if let Err(e) = crate::syscall::fork::handle_cow_fault(COW_TEST_ADDR, &child) {
        crate::serial_println!("[fork-test] cow fault: handler failed: {}", e);
        return false;
    }

    let child_phys = match child.translate(x86_64::VirtAddr::new(COW_TEST_ADDR)) {
        Some(p) => p,
        None => {
            crate::serial_println!("[fork-test] cow fault: translate child failed");
            return false;
        }
    };
    if child_phys == parent_phys {
        crate::serial_println!("[fork-test] cow fault: expected private frame after write fault");
        return false;
    }

    let parent_ptr = crate::memory::phys_to_virt(parent_phys.as_u64()) as *mut u8;
    let child_ptr = crate::memory::phys_to_virt(child_phys.as_u64()) as *mut u8;
    unsafe {
        if *child_ptr != 0x11 {
            crate::serial_println!("[fork-test] cow fault: copied data mismatch");
            return false;
        }
        *child_ptr = 0x22;
        if *parent_ptr != 0x11 {
            crate::serial_println!("[fork-test] cow fault: parent mutated by child write");
            return false;
        }
    }

    let parent_ref = crate::memory::cow::frame_get_refcount(crate::memory::PhysFrame {
        start_address: parent_phys,
    });
    let child_ref = crate::memory::cow::frame_get_refcount(crate::memory::PhysFrame {
        start_address: child_phys,
    });
    if parent_ref != 1 || child_ref != 1 {
        crate::serial_println!(
            "[fork-test] cow fault: refcounts invalid parent={} child={}",
            parent_ref,
            child_ref
        );
        return false;
    }

    let _ = aspace.unmap_region(
        COW_TEST_ADDR,
        1,
        crate::memory::address_space::VmaPageSize::Small,
    );
    let _ = child.unmap_region(
        COW_TEST_ADDR,
        1,
        crate::memory::address_space::VmaPageSize::Small,
    );
    true
}

// Scenario 1:
// - getpid != 0
// - fork works (parent gets pid, child gets 0)
// - child getppid != 0 and exits 42
// - parent waitpid(child) returns child pid and status 42<<8
// - parent getppid != 0
// Exit code: 0 pass, 1 fail.
const PROG_FORK_BASIC: &[u8] = &[
    0x48, 0x83, 0xEC, 0x10, 0x48, 0xC7, 0xC0, 0x34, 0x01, 0x00, 0x00, 0x0F, 0x05, 0x48, 0x85, 0xC0,
    0x74, 0x6E, 0x48, 0xC7, 0xC0, 0x2E, 0x01, 0x00, 0x00, 0x0F, 0x05, 0x48, 0x85, 0xC0, 0x74, 0x42,
    0x48, 0x89, 0xC3, 0x48, 0x89, 0xDF, 0x48, 0x8D, 0x74, 0x24, 0x08, 0x48, 0x31, 0xD2, 0x48, 0xC7,
    0xC0, 0x36, 0x01, 0x00, 0x00, 0x0F, 0x05, 0x48, 0x39, 0xD8, 0x75, 0x44, 0x8B, 0x4C, 0x24, 0x08,
    0x81, 0xF9, 0x00, 0x2A, 0x00, 0x00, 0x75, 0x38, 0x48, 0xC7, 0xC0, 0x35, 0x01, 0x00, 0x00, 0x0F,
    0x05, 0x48, 0x85, 0xC0, 0x74, 0x2A, 0x48, 0x31, 0xFF, 0x48, 0xC7, 0xC0, 0x2C, 0x01, 0x00, 0x00,
    0x0F, 0x05, 0x48, 0xC7, 0xC0, 0x35, 0x01, 0x00, 0x00, 0x0F, 0x05, 0x48, 0x85, 0xC0, 0x74, 0x10,
    0x48, 0xC7, 0xC7, 0x2A, 0x00, 0x00, 0x00, 0x48, 0xC7, 0xC0, 0x2C, 0x01, 0x00, 0x00, 0x0F, 0x05,
    0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00, 0x48, 0xC7, 0xC0, 0x2C, 0x01, 0x00, 0x00, 0x0F, 0x05,
    0xF4, 0xEB, 0xFD,
];

// Scenario 2:
// waitpid(-1, ...) with no child must return -ECHILD.
// Exit code: 0 pass, 2 fail.
const PROG_WAIT_NOCHILD: &[u8] = &[
    0x48, 0x83, 0xEC, 0x10, 0x48, 0xC7, 0xC7, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x8D, 0x74, 0x24, 0x08,
    0x48, 0x31, 0xD2, 0x48, 0xC7, 0xC0, 0x36, 0x01, 0x00, 0x00, 0x0F, 0x05, 0x48, 0x83, 0xF8, 0xF6,
    0x75, 0x0C, 0x48, 0x31, 0xFF, 0x48, 0xC7, 0xC0, 0x2C, 0x01, 0x00, 0x00, 0x0F, 0x05, 0x48, 0xC7,
    0xC7, 0x02, 0x00, 0x00, 0x00, 0x48, 0xC7, 0xC0, 0x2C, 0x01, 0x00, 0x00, 0x0F, 0x05, 0xF4, 0xEB,
    0xFD,
];

// Scenario 3:
// fork + waitpid(WNOHANG):
// - may return 0 if child still running
// - may also reap immediately if child exited fast (valid race)
// then parent verifies status and exits success.
// Child exits with code 7.
// Exit code: 0 pass, 3 fail.
const PROG_WAIT_WNOHANG: &[u8] = &[
    0x48, 0x83, 0xEC, 0x10, 0x48, 0xC7, 0xC0, 0x2E, 0x01, 0x00, 0x00, 0x0F, 0x05, 0x48, 0x85, 0xC0,
    0x74, 0x6E, 0x48, 0x89, 0xC3, 0x48, 0x89, 0xDF, 0x48, 0x8D, 0x74, 0x24, 0x08, 0x48, 0xC7, 0xC2,
    0x01, 0x00, 0x00, 0x00, 0x48, 0xC7, 0xC0, 0x36, 0x01, 0x00, 0x00, 0x0F, 0x05, 0x48, 0x85, 0xC0,
    0x74, 0x1D, 0x48, 0x39, 0xD8, 0x75, 0x62, 0x8B, 0x4C, 0x24, 0x08, 0x81, 0xF9, 0x00, 0x07, 0x00,
    0x00, 0x75, 0x56, 0x48, 0x31, 0xFF, 0x48, 0xC7, 0xC0, 0x2C, 0x01, 0x00, 0x00, 0x0F, 0x05, 0x48,
    0x89, 0xDF, 0x48, 0x8D, 0x74, 0x24, 0x08, 0x48, 0x31, 0xD2, 0x48, 0xC7, 0xC0, 0x36, 0x01, 0x00,
    0x00, 0x0F, 0x05, 0x48, 0x39, 0xD8, 0x75, 0x31, 0x8B, 0x4C, 0x24, 0x08, 0x81, 0xF9, 0x00, 0x07,
    0x00, 0x00, 0x75, 0x25, 0x48, 0x31, 0xFF, 0x48, 0xC7, 0xC0, 0x2C, 0x01, 0x00, 0x00, 0x0F, 0x05,
    0xB9, 0x80, 0x84, 0x1E, 0x00, 0xFF, 0xC9, 0x75, 0xFC, 0x48, 0xC7, 0xC7, 0x07, 0x00, 0x00, 0x00,
    0x48, 0xC7, 0xC0, 0x2C, 0x01, 0x00, 0x00, 0x0F, 0x05, 0x48, 0xC7, 0xC7, 0x03, 0x00, 0x00, 0x00,
    0x48, 0xC7, 0xC0, 0x2C, 0x01, 0x00, 0x00, 0x0F, 0x05, 0xF4, 0xEB, 0xFD,
];

// Scenario 4:
// waitpid(0, ...) must return -EINVAL.
// Exit code: 0 pass, 4 fail.
const PROG_WAIT_INVALID: &[u8] = &[
    0x48, 0x83, 0xEC, 0x10, 0x48, 0x31, 0xFF, 0x48, 0x8D, 0x74, 0x24, 0x08, 0x48, 0x31, 0xD2, 0x48,
    0xC7, 0xC0, 0x36, 0x01, 0x00, 0x00, 0x0F, 0x05, 0x48, 0x83, 0xF8, 0xEA, 0x75, 0x0C, 0x48, 0x31,
    0xFF, 0x48, 0xC7, 0xC0, 0x2C, 0x01, 0x00, 0x00, 0x0F, 0x05, 0x48, 0xC7, 0xC7, 0x04, 0x00, 0x00,
    0x00, 0x48, 0xC7, 0xC0, 0x2C, 0x01, 0x00, 0x00, 0x0F, 0x05, 0xF4, 0xEB, 0xFD,
];

extern "C" fn fork_test_main() -> ! {
    crate::serial_println!("[fork-test] start");

    let parent = match current_task_id() {
        Some(id) => id,
        None => {
            crate::serial_println!("[fork-test] no current task id");
            crate::process::scheduler::exit_current_task(0);
        }
    };

    let s0a = cow_test_refcount_unmap();
    crate::serial_println!(
        "[fork-test] cow refcount/unmap: {}",
        if s0a { "ok" } else { "FAIL" }
    );

    let s0b = cow_test_write_fault_copy();
    crate::serial_println!(
        "[fork-test] cow write fault: {}",
        if s0b { "ok" } else { "FAIL" }
    );

    let s1 = run_scenario(parent, "fork-test-basic", PROG_FORK_BASIC);
    crate::serial_println!("[fork-test] fork basic: {}", if s1 { "ok" } else { "FAIL" });

    let s2 = run_scenario(parent, "fork-test-nochild", PROG_WAIT_NOCHILD);
    crate::serial_println!(
        "[fork-test] wait nochild: {}",
        if s2 { "ok" } else { "FAIL" }
    );

    let s3 = run_scenario(parent, "fork-test-wnohang", PROG_WAIT_WNOHANG);
    crate::serial_println!(
        "[fork-test] wait wnohang: {}",
        if s3 { "ok" } else { "FAIL" }
    );

    let s4 = run_scenario(parent, "fork-test-invalid", PROG_WAIT_INVALID);
    crate::serial_println!(
        "[fork-test] wait invalid: {}",
        if s4 { "ok" } else { "FAIL" }
    );

    crate::serial_println!(
        "[fork-test] summary: {}",
  
        if s0a && s0b && s2 && s4 {
            "PASS"
        } else {
            "FAIL"
        }
    );
    crate::process::scheduler::exit_current_task(0);
}

extern "C" fn fork_test_entry() -> ! {
    fork_test_main()
}

pub fn create_fork_test_task() {
    if let Ok(task) = Task::new_kernel_task_with_stack(
        fork_test_entry,
        "fork-test",
        TaskPriority::Normal,
        64 * 1024,
    ) {
        crate::process::add_task(task);
    } else {
        crate::serial_println!("[fork-test] failed to create orchestrator task");
    }
}
