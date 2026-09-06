//! Thread lifecycle operations shared by the syscall layer and `/thread` VFS scheme.
//!
//! Extracted from `syscall/process.rs` so that both `SYS_THREAD_CREATE/JOIN/EXIT`
//! and the Plan 9 style `/thread/*` scheme forward to the exact same internal
//! implementation (no duplicated WaitQueue, no duplicated validation).
//!
//! Also owns the **kernel-owned user stack** bookkeeping: threads created via
//! `/thread/create` get their user stack allocated and mapped by the kernel,
//! which reclaims it deterministically when the thread dies. Threads created
//! through raw `SYS_THREAD_CREATE` keep providing their own stack and leave
//! the field untouched.

use super::{
    block_current_task, current_task_clone, current_task_id, current_tid, get_child_task_id_by_tid,
    get_task_id_by_tid, kill_task,
    scheduler::add_task_with_parent,
    task::{CpuContext, ExtendedState, KernelStack, SyncUnsafeCell, Task},
    try_wait_child, WaitChildResult,
};
use crate::{
    memory::address_space::{VmaFlags, VmaPageSize, VmaType},
    syscall::{error::SyscallError, SyscallFrame},
};
use alloc::{boxed::Box, sync::Arc};
use core::{
    mem::offset_of,
    sync::atomic::{AtomicU64, Ordering},
};

// ============================================================================
// Kernel-owned user stack accounting (leak-proofing / verification)
// ============================================================================

/// Total number of kernel-owned user stacks ever allocated.
static KERNEL_USER_STACKS_ALLOCATED: AtomicU64 = AtomicU64::new(0);
/// Number of kernel-owned user stacks currently alive (allocated - reclaimed).
static KERNEL_USER_STACKS_ACTIVE: AtomicU64 = AtomicU64::new(0);

/// Snapshot of kernel-owned user stack counters `(allocated_total, active)`.
///
/// Exposed through `/thread/stats` for the zero-leak regression test.
pub fn kernel_user_stack_stats() -> (u64, u64) {
    (
        KERNEL_USER_STACKS_ALLOCATED.load(Ordering::Relaxed),
        KERNEL_USER_STACKS_ACTIVE.load(Ordering::Relaxed),
    )
}

/// Bounds of a kernel-owned user stack request.
pub const THREAD_MIN_STACK_BYTES: u64 = 4 * 1024;
pub const THREAD_MAX_STACK_BYTES: u64 = 16 * 1024 * 1024;
/// Default size when the caller passes `stack_size == 0`.
pub const THREAD_DEFAULT_STACK_BYTES: u64 = 64 * 1024;

#[inline]
const fn page_align_up(addr: u64) -> u64 {
    addr.wrapping_add(4095) & !4095u64
}

/// Allocate and lazily map a user stack in the parent process address space.
///
/// Returns `(vaddr_base, aligned_size)`; the initial RSP is the top of the
/// region. Pages are demand-paged (`reserve_region`) exactly like `sys_mmap`.
fn alloc_kernel_user_stack(parent: &Arc<Task>, requested: u64) -> Result<(u64, u64), SyscallError> {
    let size = if requested == 0 {
        THREAD_DEFAULT_STACK_BYTES
    } else {
        page_align_up(requested.clamp(THREAD_MIN_STACK_BYTES, THREAD_MAX_STACK_BYTES))
    };
    let n_pages = (size / 4096) as usize;

    let addr_space = parent.process.address_space_arc();
    let base = addr_space
        .find_free_vma_range(crate::kaslr::mmap_base(), n_pages, VmaPageSize::Small)
        .ok_or(SyscallError::OutOfMemory)?;
    addr_space
        .reserve_region(
            base,
            n_pages,
            VmaFlags {
                readable: true,
                writable: true,
                executable: false,
                user_accessible: true,
            },
            VmaType::Anonymous,
            VmaPageSize::Small,
        )
        .map_err(|_| SyscallError::OutOfMemory)?;

    // Advance the mmap hint past the new mapping (atomically forward-only).
    let _ = parent
        .process
        .mmap_hint
        .fetch_max(base + n_pages as u64 * 4096, Ordering::Relaxed);

    KERNEL_USER_STACKS_ALLOCATED.fetch_add(1, Ordering::Relaxed);
    KERNEL_USER_STACKS_ACTIVE.fetch_add(1, Ordering::Relaxed);

    Ok((base, size))
}

/// Reclaim the kernel-owned user stack of `task`, if any.
///
/// Idempotent: the mapping is `take()`n from the task so repeated calls from
/// both the exit path and the reap path are safe. Called from
/// `exit_current_task` (normal exit) and `cleanup_task_resources`
/// (forced kills / reaping).
pub fn reclaim_kernel_user_stack(task: &Arc<Task>) {
    let Some((base, size)) = task.take_kernel_stack_user() else {
        return;
    };
    let addr_space = task.process.address_space_arc();
    if !addr_space.is_kernel() {
        // The address space may already be torn down (whole-process exit);
        // unmapping a stale range is harmless, so errors are ignored.
        let _ = addr_space.unmap_range(base, size);
    }
    KERNEL_USER_STACKS_ACTIVE.fetch_sub(1, Ordering::Relaxed);
}

// ============================================================================
// Userspace entry bootstrap (moved verbatim from syscall/process.rs)
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
struct ThreadUserContext {
    entry: u64,
    stack_top: u64,
    arg0: u64,
    user_cs: u64,
    user_rflags: u64,
    user_ss: u64,
}

const THREAD_OFF_ENTRY: usize = offset_of!(ThreadUserContext, entry);
const THREAD_OFF_STACK_TOP: usize = offset_of!(ThreadUserContext, stack_top);
const THREAD_OFF_ARG0: usize = offset_of!(ThreadUserContext, arg0);
const THREAD_OFF_USER_CS: usize = offset_of!(ThreadUserContext, user_cs);
const THREAD_OFF_USER_RFLAGS: usize = offset_of!(ThreadUserContext, user_rflags);
const THREAD_OFF_USER_SS: usize = offset_of!(ThreadUserContext, user_ss);

/// Performs the thread child start operation.
extern "C" fn thread_child_start(ctx_ptr: u64) -> ! {
    // SAFETY: `ctx_ptr` is allocated with Box::into_raw in `build_user_thread_task`
    // and passed as immutable bootstrap data for this task only.
    let boxed = unsafe { Box::from_raw(ctx_ptr as *mut ThreadUserContext) };
    let ctx = *boxed;
    // SAFETY: Assembly routine performs an iretq into userspace with validated context.
    unsafe { thread_iret_from_ctx(&ctx as *const ThreadUserContext) }
}

/// Performs the thread iret from ctx operation.
#[unsafe(naked)]
unsafe extern "C" fn thread_iret_from_ctx(_ctx: *const ThreadUserContext) -> ! {
    core::arch::naked_asm!(
        // Mask IRQs before touching GS. The user RFLAGS frame re-enables IF.
        "cli",
        "mov rsi, rdi",
        // Build iret frame: SS, RSP, RFLAGS, CS, RIP
        "mov r8, [rsi + {off_user_ss}]",
        "push r8",
        "mov r8, [rsi + {off_stack_top}]",
        "push r8",
        "mov r8, [rsi + {off_user_rflags}]",
        "push r8",
        "mov r8, [rsi + {off_user_cs}]",
        "push r8",
        "mov r8, [rsi + {off_entry}]",
        "push r8",
        // Argument convention for userspace entry: rdi = arg0
        "mov rdi, [rsi + {off_arg0}]",
        // Child thread returns 0 if entry routine ever reads rax.
        "xor rax, rax",
        "swapgs",
        "iretq",
        off_entry = const THREAD_OFF_ENTRY,
        off_stack_top = const THREAD_OFF_STACK_TOP,
        off_arg0 = const THREAD_OFF_ARG0,
        off_user_cs = const THREAD_OFF_USER_CS,
        off_user_rflags = const THREAD_OFF_USER_RFLAGS,
        off_user_ss = const THREAD_OFF_USER_SS,
    );
}

/// Caller's userspace segment/flag state used to seed the child iret frame.
#[derive(Debug, Clone, Copy)]
pub struct UserEntryContext {
    pub cs: u64,
    pub rflags: u64,
    pub ss: u64,
}

impl UserEntryContext {
    /// Build the context from a syscall frame (dispatcher path).
    pub fn from_frame(frame: &SyscallFrame) -> Self {
        UserEntryContext {
            cs: frame.iret_cs,
            rflags: frame.iret_rflags,
            ss: frame.iret_ss,
        }
    }

    /// Build a synthetic ring-3 context from the GDT (scheme path, where the
    /// caller's frame is not passed down through the VFS layer).
    pub fn ring3() -> Self {
        UserEntryContext {
            cs: crate::arch::x86_64::gdt::user_code_selector().0 as u64,
            rflags: 0x202, // IF set + reserved bit 1
            ss: crate::arch::x86_64::gdt::user_data_selector().0 as u64,
        }
    }
}

/// Performs the build user thread task operation.
fn build_user_thread_task(
    parent: &Arc<Task>,
    bootstrap_ctx: Box<ThreadUserContext>,
    tls_base: u64,
) -> Result<Arc<Task>, SyscallError> {
    let kernel_stack =
        KernelStack::allocate(Task::DEFAULT_STACK_SIZE).map_err(|_| SyscallError::OutOfMemory)?;
    let context = CpuContext::new(thread_child_start as *const () as u64, &kernel_stack);
    let (pid, tid, _) = Task::allocate_process_ids();

    let parent_fpu = unsafe { &*parent.fpu_state.get() };
    let mut child_fpu = ExtendedState::new();
    child_fpu.copy_from(parent_fpu);
    let interrupt_frame = SyscallFrame {
        r15: 0,
        r14: 0,
        r13: 0,
        r12: 0,
        rbp: 0,
        rbx: 0,
        r11: bootstrap_ctx.user_rflags,
        r10: 0,
        r9: 0,
        r8: 0,
        rsi: 0,
        rdi: bootstrap_ctx.arg0,
        rdx: 0,
        rcx: bootstrap_ctx.entry,
        rax: 0,
        iret_rip: bootstrap_ctx.entry,
        iret_cs: bootstrap_ctx.user_cs,
        iret_rflags: bootstrap_ctx.user_rflags,
        iret_rsp: bootstrap_ctx.stack_top,
        iret_ss: bootstrap_ctx.user_ss,
    };

    let task = Arc::new(Task {
        id: crate::process::TaskId::new(),
        pid,
        tid,
        tgid: parent.tgid,
        pgid: core::sync::atomic::AtomicU32::new(parent.pgid.load(Ordering::Relaxed)),
        sid: core::sync::atomic::AtomicU32::new(parent.sid.load(Ordering::Relaxed)),
        uid: core::sync::atomic::AtomicU32::new(parent.uid.load(Ordering::Relaxed)),
        euid: core::sync::atomic::AtomicU32::new(parent.euid.load(Ordering::Relaxed)),
        gid: core::sync::atomic::AtomicU32::new(parent.gid.load(Ordering::Relaxed)),
        egid: core::sync::atomic::AtomicU32::new(parent.egid.load(Ordering::Relaxed)),
        state: core::sync::atomic::AtomicU8::new(crate::process::TaskState::Ready as u8),
        priority: parent.priority,
        context: SyncUnsafeCell::new(context),
        resume_kind: SyncUnsafeCell::new(crate::process::task::ResumeKind::RetFrame),
        interrupt_rsp: core::sync::atomic::AtomicU64::new(0),
        kernel_stack,
        user_stack: None,
        stack_canary: core::sync::atomic::AtomicU64::new(0),
        stack_canary_addr: core::sync::atomic::AtomicU64::new(0),
        kernel_stack_user: SyncUnsafeCell::new(None),
        name: "user-thread",
        process: parent.process.clone(),
        pending_signals: crate::process::signal::SignalSet::new(),
        blocked_signals: parent.blocked_signals.clone(),
        irq_signal_delivery_blocked: core::sync::atomic::AtomicBool::new(false),
        signal_stack: SyncUnsafeCell::new(None),
        itimers: crate::process::timer::ITimers::new(),
        wake_pending: core::sync::atomic::AtomicBool::new(false),
        wake_deadline_ns: core::sync::atomic::AtomicU64::new(0),
        trampoline_entry: core::sync::atomic::AtomicU64::new(0),
        trampoline_stack_top: core::sync::atomic::AtomicU64::new(0),
        trampoline_arg0: core::sync::atomic::AtomicU64::new(0),
        ticks: core::sync::atomic::AtomicU64::new(0),
        sched_policy: SyncUnsafeCell::new(parent.sched_policy()),
        home_cpu: core::sync::atomic::AtomicUsize::new(usize::MAX),
        vruntime: core::sync::atomic::AtomicU64::new(parent.vruntime()),
        fair_rq_generation: core::sync::atomic::AtomicU64::new(0),
        fair_on_rq: core::sync::atomic::AtomicBool::new(false),
        clear_child_tid: core::sync::atomic::AtomicU64::new(0),
        robust_list_head: core::sync::atomic::AtomicU64::new(0),
        robust_list_len: core::sync::atomic::AtomicUsize::new(0),
        user_fs_base: core::sync::atomic::AtomicU64::new(tls_base),
        fpu_state: SyncUnsafeCell::new(child_fpu),
        xcr0_mask: core::sync::atomic::AtomicU64::new(parent.xcr0_mask.load(Ordering::Relaxed)),
        rt_link: intrusive_collections::LinkedListLink::new(),
    });

    // CpuContext initial stack layout: r15, r14, r13(arg), r12(entry), rbp, rbx, ret
    // Seed r13 with bootstrap context pointer for `thread_child_start`.
    unsafe {
        let ctx = &mut *task.context.get();
        let frame = ctx.saved_rsp as *mut u64;
        *frame.add(2) = Box::into_raw(bootstrap_ctx) as u64;
    }

    task.seed_interrupt_frame(interrupt_frame);

    Ok(task)
}

// ============================================================================
// Public helpers (shared by dispatcher syscalls and the /thread scheme)
// ============================================================================

const USER_TOP_EXCLUSIVE: u64 = 0x0000_8000_0000_0000;

/// Core of `SYS_THREAD_CREATE` and `/thread/create`.
///
/// Validates arguments with the exact same rules as the raw syscall, builds
/// the child task, registers it as a child of the current task, and returns
/// it (the caller decides what to expose: TID via syscall return value, or
/// kernel-owned stack + TID via the scheme).
///
/// `stack_top` is supplied by the caller (raw path). For the scheme path use
/// [`create_user_thread_with_kernel_stack`] instead, which allocates the
/// user stack in the kernel.
pub fn create_user_thread(
    entry_ctx: UserEntryContext,
    entry: u64,
    stack_top: u64,
    arg0: u64,
    flags: u64,
    tls_base: u64,
) -> Result<Arc<Task>, SyscallError> {
    if flags != 0 {
        return Err(SyscallError::InvalidArgument);
    }

    if entry == 0
        || stack_top == 0
        || entry >= USER_TOP_EXCLUSIVE
        || stack_top >= USER_TOP_EXCLUSIVE
        || (stack_top & 0x7) != 0
    // 8-byte alignment (x86_64 entry: 8 mod 16 is valid)
    {
        return Err(SyscallError::InvalidArgument);
    }

    let parent = current_task_clone().ok_or(SyscallError::Fault)?;
    if parent.is_kernel() {
        return Err(SyscallError::PermissionDenied);
    }

    let user_ctx = Box::new(ThreadUserContext {
        entry,
        stack_top,
        arg0,
        user_cs: entry_ctx.cs,
        user_rflags: entry_ctx.rflags | (1 << 9),
        user_ss: entry_ctx.ss,
    });

    let child = build_user_thread_task(&parent, user_ctx, tls_base)?;
    add_task_with_parent(child.clone(), parent.id);
    Ok(child)
}

/// `/thread/create` variant: the kernel allocates and owns the user stack.
///
/// Same validation rules as [`create_user_thread`] except `stack_size` replaces
/// `stack_top`. On success the child carries a `kernel_stack_user` mapping that
/// is reclaimed automatically when the thread dies (making `detach()` free of
/// any userspace cleanup).
pub fn create_user_thread_with_kernel_stack(
    entry_ctx: UserEntryContext,
    entry: u64,
    stack_size: u64,
    arg0: u64,
    tls_base: u64,
) -> Result<Arc<Task>, SyscallError> {
    if entry == 0 || entry >= USER_TOP_EXCLUSIVE {
        return Err(SyscallError::InvalidArgument);
    }
    if arg0 != 0 && arg0 >= USER_TOP_EXCLUSIVE {
        return Err(SyscallError::InvalidArgument);
    }
    if tls_base != 0 && tls_base >= USER_TOP_EXCLUSIVE {
        return Err(SyscallError::InvalidArgument);
    }

    let parent = current_task_clone().ok_or(SyscallError::Fault)?;
    if parent.is_kernel() {
        return Err(SyscallError::PermissionDenied);
    }

    let (stack_base, stack_len) = alloc_kernel_user_stack(&parent, stack_size)?;
    let stack_top = stack_base + stack_len;

    let child = match create_user_thread_inner(&parent, entry_ctx, entry, stack_top, arg0, tls_base)
    {
        Ok(child) => child,
        Err(e) => {
            // Roll back the mapping on failure.
            let _ = parent
                .process
                .address_space_arc()
                .unmap_range(stack_base, stack_len);
            KERNEL_USER_STACKS_ALLOCATED.fetch_sub(1, Ordering::Relaxed);
            KERNEL_USER_STACKS_ACTIVE.fetch_sub(1, Ordering::Relaxed);
            return Err(e);
        }
    };
    child.set_kernel_stack_user(stack_base, stack_len);

    add_task_with_parent(child.clone(), parent.id);
    Ok(child)
}

fn create_user_thread_inner(
    parent: &Arc<Task>,
    entry_ctx: UserEntryContext,
    entry: u64,
    stack_top: u64,
    arg0: u64,
    tls_base: u64,
) -> Result<Arc<Task>, SyscallError> {
    let user_ctx = Box::new(ThreadUserContext {
        entry,
        stack_top,
        arg0,
        user_cs: entry_ctx.cs,
        user_rflags: entry_ctx.rflags | (1 << 9),
        user_ss: entry_ctx.ss,
    });
    build_user_thread_task(parent, user_ctx, tls_base)
}

/// Core of `SYS_THREAD_JOIN` and `/thread/join/<tid>`.
///
/// Blocking reap loop: only children of the calling task can be joined,
/// self-join is `EINVAL`, absent or already-reaped targets yield `ENOENT`.
/// Returns `(tid, exit_code)`.
pub fn join_task(wait_tid: u32) -> Result<(u32, i32), SyscallError> {
    let current = current_task_clone().ok_or(SyscallError::Fault)?;
    if wait_tid == current.tid {
        return Err(SyscallError::InvalidArgument);
    }

    let parent_id = current_task_id().ok_or(SyscallError::Fault)?;
    let child_id = get_child_task_id_by_tid(parent_id, wait_tid).ok_or(SyscallError::NotFound)?;

    loop {
        match try_wait_child(parent_id, Some(child_id)) {
            WaitChildResult::Reaped { status, .. } => return Ok((wait_tid, status)),
            WaitChildResult::NoChildren => return Err(SyscallError::NotFound),
            WaitChildResult::StillRunning => block_current_task(),
        }
    }
}

/// Core of `SYS_THREAD_EXIT` and `/thread/exit`.
///
/// Terminates only the calling thread; never returns.
pub fn exit_current_thread(code: i32) -> ! {
    crate::process::scheduler::exit_current_task(code)
}

/// Kill a thread by TID, restricted to threads of the caller's own process.
///
/// Errors: `ESRCH` when the TID does not exist, `EPERM` when the target lives
/// in another thread group (mirrors the parent/child restriction of join).
pub fn kill_thread(caller_tid: u32, target_tid: u32) -> Result<(), SyscallError> {
    let caller = current_task_clone().ok_or(SyscallError::Fault)?;
    if caller.tid != caller_tid {
        return Err(SyscallError::InvalidArgument);
    }
    if target_tid == caller.tid {
        // Killing yourself is exit(), not kill(): refuse explicitly.
        return Err(SyscallError::InvalidArgument);
    }
    let target_id = get_task_id_by_tid(target_tid).ok_or(SyscallError::NoSuchProcess)?;
    let target = super::get_task_by_id(target_id).ok_or(SyscallError::NoSuchProcess)?;
    if target.tgid != caller.tgid {
        return Err(SyscallError::PermissionDenied);
    }
    if !kill_task(target_id) {
        return Err(SyscallError::NoSuchProcess);
    }
    Ok(())
}

/// Current TID of the calling task (scheme `/thread/current` fast path).
pub fn current_thread_tid() -> Result<u32, SyscallError> {
    current_tid().ok_or(SyscallError::Fault)
}
