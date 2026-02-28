//! `fork()` syscall implementation with copy-on-write (COW).

use crate::{
    memory::{AddressSpace, FrameAllocator as _},
    process::{
        current_task_clone,
        scheduler::add_task_with_parent,
        signal::{SigActionData, SigStack, SignalSet},
        task::{CpuContext, KernelStack, Pid, SyncUnsafeCell, Task},
        TaskId, TaskState,
    },
    syscall::{error::SyscallError, SyscallFrame},
};
use alloc::{boxed::Box, string::String, sync::Arc};
use core::{
    mem::offset_of,
    sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
};
use x86_64::structures::paging::{mapper::TranslateResult, FrameAllocator}; // Required for allocate_frame

/// Result returned by [`sys_fork`].
pub struct ForkResult {
    pub child_pid: Pid,
}

#[inline]
fn local_invlpg(vaddr: u64) {
    // Local TLB invalidation is sufficient here: this kernel currently runs
    // one task per user address space (no shared user CR3 across CPUs).
    unsafe {
        core::arch::asm!("invlpg [{}]", in(reg) vaddr, options(nostack, preserves_flags));
    }
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

        // ===== Build IRET frame FIRST, using r8 as scratch ===========
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

        // ===== Now restore ALL general-purpose registers============
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


fn build_child_task(
    parent: &Arc<Task>,
    child_as: Arc<AddressSpace>,
    bootstrap_ctx: Box<ForkUserContext>,
) -> Result<Arc<Task>, SyscallError> {
    let kernel_stack =
        KernelStack::allocate(Task::DEFAULT_STACK_SIZE).map_err(|_| SyscallError::OutOfMemory)?;
    let context = CpuContext::new(fork_child_start as *const () as u64, &kernel_stack);

    let parent_caps = unsafe { (&*parent.process.capabilities.get()).clone() };
    let parent_fd = unsafe { (&*parent.process.fd_table.get()).clone_for_fork() };
    let parent_blocked = parent.blocked_signals.clone();
    let parent_actions: [SigActionData; 64] = unsafe { *parent.process.signal_actions.get() };
    let parent_sigstack: Option<SigStack> = unsafe { *parent.signal_stack.get() };

    let (pid, tid, tgid) = Task::allocate_process_ids();
    let task = Arc::new(Task {
        id: TaskId::new(),
        pid,
        tid,
        tgid,
        pgid: AtomicU32::new(parent.pgid.load(Ordering::Relaxed)),
        sid: AtomicU32::new(parent.sid.load(Ordering::Relaxed)),
        uid: AtomicU32::new(parent.uid.load(Ordering::Relaxed)),
        euid: AtomicU32::new(parent.euid.load(Ordering::Relaxed)),
        gid: AtomicU32::new(parent.gid.load(Ordering::Relaxed)),
        egid: AtomicU32::new(parent.egid.load(Ordering::Relaxed)),
        state: SyncUnsafeCell::new(TaskState::Ready),
        priority: parent.priority,
        context: SyncUnsafeCell::new(context),
        kernel_stack,
        user_stack: None,

        name: "fork-child",
        process: alloc::sync::Arc::new(crate::process::process::Process {
            pid,
            address_space: crate::process::task::SyncUnsafeCell::new(child_as),
            fd_table: crate::process::task::SyncUnsafeCell::new(parent_fd),
            capabilities: crate::process::task::SyncUnsafeCell::new(parent_caps),
            signal_actions: crate::process::task::SyncUnsafeCell::new(parent_actions),
            brk: core::sync::atomic::AtomicU64::new(parent.process.brk.load(core::sync::atomic::Ordering::Relaxed)),
            mmap_hint: core::sync::atomic::AtomicU64::new(parent.process.mmap_hint.load(core::sync::atomic::Ordering::Relaxed)),
            cwd: crate::process::task::SyncUnsafeCell::new(unsafe { &*parent.process.cwd.get() }.clone()),
            umask: core::sync::atomic::AtomicU32::new(parent.process.umask.load(core::sync::atomic::Ordering::Relaxed)),
        }),
        // POSIX: pending signals are NOT inherited by the child.

        pending_signals: SignalSet::new(),
        // POSIX: signal mask IS inherited.
        blocked_signals: parent_blocked,
        signal_stack: SyncUnsafeCell::new(parent_sigstack),
        itimers: crate::process::timer::ITimers::new(),
        wake_pending: AtomicBool::new(false),
        wake_deadline_ns: AtomicU64::new(0),
        trampoline_entry: AtomicU64::new(0),
        trampoline_stack_top: AtomicU64::new(0),
        trampoline_arg0: AtomicU64::new(0),
        ticks: AtomicU64::new(0),
        sched_policy: SyncUnsafeCell::new(parent.sched_policy()),
        vruntime: AtomicU64::new(parent.vruntime()),
        // POSIX: clear_child_tid is NOT inherited — child starts with 0.
        clear_child_tid: AtomicU64::new(0),
        // POSIX: cwd IS inherited.
        // POSIX: umask IS inherited.
        // FS.base: child starts with 0 (its own TLS not yet set up).
        user_fs_base: AtomicU64::new(0),
        // FPU state: child inherits parent's FPU state.
        fpu_state: {
            let parent_fpu = unsafe { &*parent.fpu_state.get() };
            let mut child_fpu = crate::process::task::FpuState::new();
            child_fpu.data.copy_from_slice(&parent_fpu.data);
            SyncUnsafeCell::new(child_fpu)
        },
    });

    // CpuContext initial stack layout: r15, r14, r13(arg), r12(entry), rbp, rbx, ret
    unsafe {
        let ctx = &mut *task.context.get();
        let frame = ctx.saved_rsp as *mut u64;
        *frame.add(2) = Box::into_raw(bootstrap_ctx) as u64;
    }

    Ok(task)
}

/// SYS_PROC_FORK (302): fork with copy-on-write address-space cloning.
pub fn sys_fork(frame: &SyscallFrame) -> Result<ForkResult, SyscallError> {
    let parent = current_task_clone().ok_or(SyscallError::PermissionDenied)?;

    // 1. Sanity check: cannot fork a kernel thread.
    if parent.is_kernel() {
        log::warn!("fork: attempt to fork kernel thread '{}'", parent.name);
        return Err(SyscallError::PermissionDenied);
    }

    // 2. Capability check: check if task is restricted from forking.
    // For now, we allow fork for all user processes unless restricted.
    // TODO: implement ResourceType::Process/Task restricted capabilities.

    let parent_as = unsafe { &*parent.process.address_space.get() };

    // 3. Memory check: ensure parent has actual user-space mappings.
    if !parent_as.has_user_mappings() {
        log::warn!(
            "fork: attempt to fork task '{}' with no user mappings",
            parent.name
        );
        return Err(SyscallError::InvalidArgument);
    }

    let child_as = parent_as
        .clone_cow()
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

    let child_task = build_child_task(&parent, child_as, child_user_ctx)?;
    let child_pid = child_task.pid;
    add_task_with_parent(child_task, parent.id);

    Ok(ForkResult { child_pid })
}

/// Called from the page fault handler when a write fault occurs on a present page.
/// Returns Ok(()) if the fault was successfully handled (COW resolution),
/// or Err if it wasn't a COW fault (real access violation).
pub fn handle_cow_fault(virt_addr: u64, address_space: &AddressSpace) -> Result<(), &'static str> {
    use crate::memory::paging::BuddyFrameAllocator;
    use x86_64::{
        structures::paging::{Mapper, Page, PageTableFlags, Size4KiB, Translate},
        VirtAddr,
    };

    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(virt_addr));

    // SAFETY: we are in an exception handler, address space is active.
    let mut mapper = unsafe { address_space.mapper() };

    //Check if page is mapped and has COW flag
    let (phys_frame, flags): (
        x86_64::structures::paging::PhysFrame<Size4KiB>,
        PageTableFlags,
    ) = match mapper.translate(VirtAddr::new(virt_addr)) {
        TranslateResult::Mapped {
            frame: x86_64::structures::paging::mapper::MappedFrame::Size4KiB(frame),
            offset: _,
            flags,
        } => (frame, flags),
        _ => return Err("Page not mapped or huge page"),
    };

    // We use BIT_9 as software COW flag
    const COW_BIT: PageTableFlags = PageTableFlags::BIT_9;

    if !flags.contains(COW_BIT) {
        return Err("Not a COW page");
    }

    let old_frame = crate::memory::PhysFrame {
        start_address: phys_frame.start_address(),
    };

    let refcount = crate::memory::cow::frame_get_refcount(old_frame);

    if refcount == 1 {
        // Case 1: we are the sole owner. Just make it writable.
        let new_flags = (flags | PageTableFlags::WRITABLE) & !COW_BIT;

        unsafe {
            mapper
                .update_flags(page, new_flags)
                .map_err(|_| "Failed to update flags")?
                .flush();
        }
        // Only the current CPU can hold this CR3 in the current design.
        local_invlpg(virt_addr);
        return Ok(());
    }

    // Case 2: shared page. Copy to new frame.
    let mut frame_allocator = BuddyFrameAllocator;

    let new_frame = frame_allocator
        .allocate_frame()
        .ok_or("OOM during COW copy")?;

    // Copy content
    unsafe {
        let src = crate::memory::phys_to_virt(old_frame.start_address.as_u64()) as *const u8;
        let dst = crate::memory::phys_to_virt(new_frame.start_address().as_u64()) as *mut u8;
        core::ptr::copy_nonoverlapping(src, dst, 4096);
    }

    // Update mapping to new frame, Writable, no COW
    let new_flags = (flags | PageTableFlags::WRITABLE) & !COW_BIT;

    // Replace existing mapping (present+COW) by the private writable mapping.
    let old_unmapped = mapper
        .unmap(page)
        .map_err(|_| "Failed to unmap old COW frame")?
        .0;
    debug_assert_eq!(old_unmapped.start_address(), old_frame.start_address);

    let remap_res = unsafe { mapper.map_to(page, new_frame, new_flags, &mut frame_allocator) };
    if remap_res.is_err() {
        unsafe {
            let _ = mapper.map_to(page, phys_frame, flags, &mut frame_allocator);
        }
        let lock = crate::memory::get_allocator();
        let mut guard = lock.lock();
        if let Some(allocator) = guard.as_mut() {
            allocator.free(
                crate::memory::PhysFrame {
                    start_address: new_frame.start_address(),
                },
                0,
            );
        }
        return Err("Failed to map new COW frame");
    }
    match remap_res {
        Ok(flush) => flush.flush(),
        Err(_) => unreachable!("checked remap result above"),
    }

    crate::memory::cow::frame_inc_ref(crate::memory::PhysFrame {
        start_address: new_frame.start_address(),
    });

    // Only the current CPU can hold this CR3 in the current design.
    local_invlpg(virt_addr);

    // Decrement refcount of old frame after the new mapping is installed.
    crate::memory::cow::frame_dec_ref(old_frame);

    Ok(())
}
