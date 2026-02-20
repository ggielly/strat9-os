//! `fork()` syscall implementation (P1): eager address-space copy.
//!
//! This phase intentionally avoids COW and duplicates user mappings eagerly.

use crate::{
    memory::AddressSpace,
    process::{
        current_task_clone,
        scheduler::add_task_with_parent,
        signal::{SigAction, SigStack, SignalSet},
        task::{CpuContext, KernelStack, SyncUnsafeCell, Task},
        TaskId, TaskState,
    },
    syscall::{error::SyscallError, SyscallFrame},
};
use alloc::{boxed::Box, sync::Arc};
use core::{
    mem::offset_of,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

/// Result returned by [`sys_fork`].
pub struct ForkResult {
    pub child_pid: TaskId,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ForkUserContext {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rsi: u64,
    rdi: u64,
    rdx: u64,
    rcx: u64,
    user_rip: u64,
    user_cs: u64,
    user_rflags: u64,
    user_rsp: u64,
    user_ss: u64,
}

const OFF_R15: usize = offset_of!(ForkUserContext, r15);
const OFF_R14: usize = offset_of!(ForkUserContext, r14);
const OFF_R13: usize = offset_of!(ForkUserContext, r13);
const OFF_R12: usize = offset_of!(ForkUserContext, r12);
const OFF_RBP: usize = offset_of!(ForkUserContext, rbp);
const OFF_RBX: usize = offset_of!(ForkUserContext, rbx);
const OFF_R11: usize = offset_of!(ForkUserContext, r11);
const OFF_R10: usize = offset_of!(ForkUserContext, r10);
const OFF_R9: usize = offset_of!(ForkUserContext, r9);
const OFF_R8: usize = offset_of!(ForkUserContext, r8);
const OFF_RSI: usize = offset_of!(ForkUserContext, rsi);
const OFF_RDI: usize = offset_of!(ForkUserContext, rdi);
const OFF_RDX: usize = offset_of!(ForkUserContext, rdx);
const OFF_RCX: usize = offset_of!(ForkUserContext, rcx);
const OFF_USER_RIP: usize = offset_of!(ForkUserContext, user_rip);
const OFF_USER_CS: usize = offset_of!(ForkUserContext, user_cs);
const OFF_USER_RFLAGS: usize = offset_of!(ForkUserContext, user_rflags);
const OFF_USER_RSP: usize = offset_of!(ForkUserContext, user_rsp);
const OFF_USER_SS: usize = offset_of!(ForkUserContext, user_ss);

/// Child bootstrap: restore user register snapshot and enter Ring 3.
extern "C" fn fork_child_start(ctx_ptr: u64) -> ! {
    let boxed = unsafe { Box::from_raw(ctx_ptr as *mut ForkUserContext) };
    let ctx = *boxed;
    unsafe { fork_iret_from_ctx(&ctx as *const ForkUserContext) }
}

#[unsafe(naked)]
unsafe extern "C" fn fork_iret_from_ctx(_ctx: *const ForkUserContext) -> ! {
    core::arch::naked_asm!(
        "mov rsi, rdi",

        // ── Build IRET frame FIRST, using r8 as scratch ──────────────
        // (r8 has not been restored yet, so we can clobber it safely)
        "mov r8, [rsi + {off_user_ss}]",
        "push r8",                            // SS
        "mov r8, [rsi + {off_user_rsp}]",
        "push r8",                            // user RSP
        "mov r8, [rsi + {off_user_rflags}]",
        "push r8",                            // user RFLAGS
        "mov r8, [rsi + {off_user_cs}]",
        "push r8",                            // CS
        "mov r8, [rsi + {off_user_rip}]",
        "push r8",                            // user RIP

        // ── Now restore ALL general-purpose registers ────────────────
        "mov r15, [rsi + {off_r15}]",
        "mov r14, [rsi + {off_r14}]",
        "mov r13, [rsi + {off_r13}]",
        "mov r12, [rsi + {off_r12}]",
        "mov rbp, [rsi + {off_rbp}]",
        "mov rbx, [rsi + {off_rbx}]",
        "mov r11, [rsi + {off_r11}]",
        "mov r10, [rsi + {off_r10}]",
        "mov r9,  [rsi + {off_r9}]",
        "mov r8,  [rsi + {off_r8}]",          // r8 now gets its correct value
        "mov rdx, [rsi + {off_rdx}]",
        "mov rcx, [rsi + {off_rcx}]",
        "mov rdi, [rsi + {off_rdi}]",
        "mov rax, 0",                         // child fork() returns 0
        "mov rsi, [rsi + {off_rsi}]",         // rsi restored last
        "iretq",
        off_r15 = const OFF_R15,
        off_r14 = const OFF_R14,
        off_r13 = const OFF_R13,
        off_r12 = const OFF_R12,
        off_rbp = const OFF_RBP,
        off_rbx = const OFF_RBX,
        off_r11 = const OFF_R11,
        off_r10 = const OFF_R10,
        off_r9 = const OFF_R9,
        off_r8 = const OFF_R8,
        off_rsi = const OFF_RSI,
        off_rdi = const OFF_RDI,
        off_rdx = const OFF_RDX,
        off_rcx = const OFF_RCX,
        off_user_rip = const OFF_USER_RIP,
        off_user_cs = const OFF_USER_CS,
        off_user_rflags = const OFF_USER_RFLAGS,
        off_user_rsp = const OFF_USER_RSP,
        off_user_ss = const OFF_USER_SS,
    );
}

fn copy_signal_set(src: &SignalSet) -> SignalSet {
    SignalSet::from_mask(src.get_mask())
}

fn build_child_task(
    parent: &Arc<Task>,
    child_as: Arc<AddressSpace>,
    bootstrap_ctx_ptr: u64,
) -> Result<Arc<Task>, SyscallError> {
    let kernel_stack =
        KernelStack::allocate(Task::DEFAULT_STACK_SIZE).map_err(|_| SyscallError::OutOfMemory)?;
    let context = CpuContext::new(fork_child_start as *const () as u64, &kernel_stack);

    let parent_caps = unsafe { (&*parent.capabilities.get()).clone() };
    let parent_fd = unsafe { (&*parent.fd_table.get()).clone_for_fork() };
    let parent_blocked = unsafe { copy_signal_set(&*parent.blocked_signals.get()) };
    let parent_actions: [SigAction; 64] = unsafe { *parent.signal_actions.get() };
    let parent_sigstack: Option<SigStack> = unsafe { *parent.signal_stack.get() };

    let task = Arc::new(Task {
        id: TaskId::new(),
        state: SyncUnsafeCell::new(TaskState::Ready),
        priority: parent.priority,
        context: SyncUnsafeCell::new(context),
        kernel_stack,
        user_stack: None,
        name: "fork-child",
        capabilities: SyncUnsafeCell::new(parent_caps),
        address_space: child_as,
        fd_table: SyncUnsafeCell::new(parent_fd),
        pending_signals: SyncUnsafeCell::new(SignalSet::new()),
        blocked_signals: SyncUnsafeCell::new(parent_blocked),
        signal_actions: SyncUnsafeCell::new(parent_actions),
        signal_stack: SyncUnsafeCell::new(parent_sigstack),
        itimers: crate::process::timer::ITimers::new(),
        wake_pending: AtomicBool::new(false),
        wake_deadline_ns: AtomicU64::new(0),
        brk: AtomicU64::new(parent.brk.load(Ordering::Relaxed)),
        mmap_hint: AtomicU64::new(parent.mmap_hint.load(Ordering::Relaxed)),
        ticks: AtomicU64::new(0),
    });

    // CpuContext initial stack layout: r15, r14, r13(arg), r12(entry), rbp, rbx, ret
    unsafe {
        let ctx = &mut *task.context.get();
        let frame = ctx.saved_rsp as *mut u64;
        *frame.add(2) = bootstrap_ctx_ptr;
    }

    Ok(task)
}

/// SYS_PROC_FORK (302): eager fork (no COW yet).
pub fn sys_fork(frame: &SyscallFrame) -> Result<ForkResult, SyscallError> {
    let parent = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    if parent.address_space.is_kernel() {
        return Err(SyscallError::PermissionDenied);
    }

    let child_as = parent
        .address_space
        .clone_for_fork_eager()
        .map_err(|_| SyscallError::OutOfMemory)?;

    let child_user_ctx = Box::new(ForkUserContext {
        r15: frame.r15,
        r14: frame.r14,
        r13: frame.r13,
        r12: frame.r12,
        rbp: frame.rbp,
        rbx: frame.rbx,
        r11: frame.r11,
        r10: frame.r10,
        r9: frame.r9,
        r8: frame.r8,
        rsi: frame.rsi,
        rdi: frame.rdi,
        rdx: frame.rdx,
        rcx: frame.rcx,
        user_rip: frame.iret_rip,
        user_cs: frame.iret_cs,
        user_rflags: frame.iret_rflags,
        user_rsp: frame.iret_rsp,
        user_ss: frame.iret_ss,
    });

    let child_task = build_child_task(&parent, child_as, Box::into_raw(child_user_ctx) as u64)?;
    let child_pid = child_task.id;
    add_task_with_parent(child_task, parent.id);

    Ok(ForkResult { child_pid })
}

/// Try to resolve a COW write fault.
///
/// P1 fork is eager-copy, so this path remains disabled.
pub fn handle_cow_fault(
    _virt_addr: u64,
    _address_space: &crate::memory::AddressSpace,
) -> Result<(), &'static str> {
    Err("COW not implemented")
}
