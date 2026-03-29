//! `fork()` syscall implementation with copy-on-write (COW).
//!
//! This module implements the `fork()` syscall, which creates a new child process by cloning the
//! calling process. The child gets a copy of the parent's address space, but the actual physical
//! memory is shared between parent and child until either of them writes to it, at which point
//! the kernel transparently creates a private copy for the writing process (copy-on-write).
//!
//! The main entry point is `sys_fork`, which performs the necessary checks, clones the address space
//! with COW semantics, and creates a new `Task` for the child process. The
//! `handle_cow_fault` function is called from the page fault handler when a write fault occurs on a COW page, and it resolves the fault by either making the page writable (if the faulting process is the sole owner) or by copying the page to a new frame and updating the mapping.
//!
//! Source : https://man7.org/linux/man2/fork.2.html
//!          https://man7.org/linux/man2/vfork.2.html
//!          https://man7.org/linux/man2/clone.2.html
//!
//! TODO: implement `vfork()` and `clone()` with more fine-grained control over sharing.
//!
//! COW :
//!   https://en.wikipedia.org/wiki/Copy-on-write
//!   https://lwn.net/Articles/531114/
//!   
//!   
//!   
//!

use crate::{
    memory::{resolve_handle, AddressSpace, EffectiveMapping, VmaPageSize},
    process::{
        current_task_clone,
        scheduler::add_task_with_parent,
        signal::{SigActionData, SigStack, SignalSet},
        task::{CpuContext, KernelStack, Pid, SyncUnsafeCell, Task},
        TaskId, TaskState,
    },
    syscall::{error::SyscallError, SyscallFrame},
};
use alloc::{boxed::Box, sync::Arc};
use core::{
    mem::offset_of,
    sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
};
use x86_64::structures::paging::mapper::TranslateResult;

/// Result returned by [`sys_fork`].
pub struct ForkResult {
    pub child_pid: Pid,
}

/// Performs the local invlpg operation.
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

/// Performs the fork iret from ctx operation.
#[unsafe(naked)]
unsafe extern "C" fn fork_iret_from_ctx(_ctx: *const ForkUserContext) -> ! {
    core::arch::naked_asm!(
        // Mask IRQs before touching GS. The user RFLAGS frame re-enables IF.
        "cli",
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
        "swapgs",
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

/// Performs the build child task operation.
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
    let interrupt_frame = crate::syscall::SyscallFrame {
        r15: bootstrap_ctx.r15,
        r14: bootstrap_ctx.r14,
        r13: bootstrap_ctx.r13,
        r12: bootstrap_ctx.r12,
        rbp: bootstrap_ctx.rbp,
        rbx: bootstrap_ctx.rbx,
        r11: bootstrap_ctx.r11,
        r10: bootstrap_ctx.r10,
        r9: bootstrap_ctx.r9,
        r8: bootstrap_ctx.r8,
        rsi: bootstrap_ctx.rsi,
        rdi: bootstrap_ctx.rdi,
        rdx: bootstrap_ctx.rdx,
        rcx: bootstrap_ctx.rcx,
        rax: 0,
        iret_rip: bootstrap_ctx.user_rip,
        iret_cs: bootstrap_ctx.user_cs,
        iret_rflags: bootstrap_ctx.user_rflags,
        iret_rsp: bootstrap_ctx.user_rsp,
        iret_ss: bootstrap_ctx.user_ss,
    };

    let (pid, tid, tgid) = Task::allocate_process_ids();
    child_as.set_owner_pid(pid);
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
        state: core::sync::atomic::AtomicU8::new(TaskState::Ready as u8),
        priority: parent.priority,
        context: SyncUnsafeCell::new(context),
        resume_kind: SyncUnsafeCell::new(crate::process::task::ResumeKind::RetFrame),
        interrupt_rsp: AtomicU64::new(0),
        kernel_stack,
        user_stack: None,

        name: "fork-child",
        process: alloc::sync::Arc::new(crate::process::process::Process {
            pid,
            address_space: crate::process::task::SyncUnsafeCell::new(child_as),
            address_space_lock: crate::sync::SpinLock::new(()),
            fd_table: crate::process::task::SyncUnsafeCell::new(parent_fd),
            capabilities: crate::process::task::SyncUnsafeCell::new(parent_caps),
            signal_actions: crate::process::task::SyncUnsafeCell::new(parent_actions),
            brk: core::sync::atomic::AtomicU64::new(
                parent
                    .process
                    .brk
                    .load(core::sync::atomic::Ordering::Relaxed),
            ),
            mmap_hint: core::sync::atomic::AtomicU64::new(
                parent
                    .process
                    .mmap_hint
                    .load(core::sync::atomic::Ordering::Relaxed),
            ),
            cwd: crate::process::task::SyncUnsafeCell::new(
                unsafe { &*parent.process.cwd.get() }.clone(),
            ),
            umask: core::sync::atomic::AtomicU32::new(
                parent
                    .process
                    .umask
                    .load(core::sync::atomic::Ordering::Relaxed),
            ),
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
        fair_rq_generation: AtomicU64::new(0),
        fair_on_rq: AtomicBool::new(false),
        // POSIX: clear_child_tid is NOT inherited — child starts with 0.
        clear_child_tid: AtomicU64::new(0),
        // POSIX: cwd IS inherited.
        // POSIX: umask IS inherited.
        // FS.base: child starts with 0 (its own TLS not yet set up).
        user_fs_base: AtomicU64::new(0),
        fpu_state: {
            let parent_fpu = unsafe { &*parent.fpu_state.get() };
            let mut child_fpu = crate::process::task::ExtendedState::new();
            child_fpu.copy_from(parent_fpu);
            SyncUnsafeCell::new(child_fpu)
        },
        xcr0_mask: AtomicU64::new(parent.xcr0_mask.load(core::sync::atomic::Ordering::Relaxed)),
    });

    // CpuContext initial stack layout: r15, r14, r13(arg), r12(entry), rbp, rbx, ret
    unsafe {
        let ctx = &mut *task.context.get();
        let frame = ctx.saved_rsp as *mut u64;
        *frame.add(2) = Box::into_raw(bootstrap_ctx) as u64;
    }

    task.seed_interrupt_frame(interrupt_frame);

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

    let parent_as = parent.process.address_space_arc();

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
        structures::paging::{Mapper, Page, PageTableFlags, Size2MiB, Size4KiB, Translate},
        VirtAddr,
    };

    let mapping = address_space
        .effective_mapping_containing(virt_addr)
        .ok_or("Page not mapped")?;
    let page_start = mapping.start;
    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(page_start));

    // SAFETY: we are in an exception handler, address space is active.
    let mut mapper = unsafe { address_space.mapper() };

    // Check if page is mapped and has COW flag.
    let (phys_frame_addr, flags) = match mapper.translate(VirtAddr::new(page_start)) {
        TranslateResult::Mapped {
            frame,
            offset: _,
            flags,
        } => (frame.start_address(), flags),
        _ => return Err("Page not mapped"),
    };

    // We use BIT_9 as software COW flag
    const COW_BIT: PageTableFlags = PageTableFlags::BIT_9;

    if !flags.contains(COW_BIT) {
        return Err("Not a COW page");
    }

    let old_handle = mapping.handle;
    let refcount = crate::memory::cow::handle_get_refcount(old_handle);

    if refcount == 1 {
        // Case 1: we are the sole owner. Just make it writable.
        let new_flags = (flags | PageTableFlags::WRITABLE) & !COW_BIT;

        unsafe {
            match mapping.page_size {
                VmaPageSize::Small => mapper
                    .update_flags(page, new_flags)
                    .map_err(|_| "Failed to update 4K flags")?
                    .flush(),
                VmaPageSize::Huge => mapper
                    .update_flags(
                        Page::<Size2MiB>::containing_address(VirtAddr::new(page_start)),
                        new_flags | PageTableFlags::HUGE_PAGE,
                    )
                    .map_err(|_| "Failed to update 2M flags")?
                    .flush(),
            }
        }
        let tracked_flags = match mapping.page_size {
            VmaPageSize::Small => new_flags,
            VmaPageSize::Huge => new_flags | PageTableFlags::HUGE_PAGE,
        };
        let _ = address_space.update_effective_mapping_flags(page_start, tracked_flags);
        // Only the current CPU can hold this CR3 in the current design.
        local_invlpg(virt_addr);
        return Ok(());
    }

    // Case 2: shared page. Copy to new frame.
    let mut frame_allocator = BuddyFrameAllocator;
    let order = match mapping.page_size {
        VmaPageSize::Small => 0,
        VmaPageSize::Huge => 9,
    };
    let copy_bytes = mapping.page_size.bytes() as usize;
    let new_frame = crate::sync::with_irqs_disabled(|token| {
        if order == 0 {
            crate::memory::allocate_frame(token)
        } else {
            crate::memory::allocate_frames(token, order)
        }
    })
    .map_err(|_| "OOM during COW copy")?;

    // Copy content
    unsafe {
        let src = crate::memory::phys_to_virt(phys_frame_addr.as_u64()) as *const u8;
        let dst = crate::memory::phys_to_virt(new_frame.start_address.as_u64()) as *mut u8;
        core::ptr::copy_nonoverlapping(src, dst, copy_bytes);
    }

    // Update mapping to new frame, Writable, no COW
    let new_flags = (flags | PageTableFlags::WRITABLE) & !COW_BIT;
    let tracked_flags = match mapping.page_size {
        VmaPageSize::Small => new_flags,
        VmaPageSize::Huge => new_flags | PageTableFlags::HUGE_PAGE,
    };
    let new_handle = resolve_handle(new_frame.start_address);

    // Replace existing mapping (present+COW) by the private writable mapping.
    let remap_res: Result<(), &'static str> = match mapping.page_size {
        VmaPageSize::Small => {
            let old_unmapped = mapper
                .unmap(page)
                .map_err(|_| "Failed to unmap old 4K COW frame")?
                .0;
            debug_assert_eq!(old_unmapped.start_address(), phys_frame_addr);
            unsafe {
                mapper.map_to(
                    page,
                    x86_64::structures::paging::PhysFrame::<Size4KiB>::containing_address(
                        new_frame.start_address,
                    ),
                    new_flags,
                    &mut frame_allocator,
                )
            }
            .map(|flush| flush.flush())
            .map_err(|_| "Failed to map new 4K COW frame")
        }
        VmaPageSize::Huge => {
            let huge_page = Page::<Size2MiB>::containing_address(VirtAddr::new(page_start));
            let old_unmapped = mapper
                .unmap(huge_page)
                .map_err(|_| "Failed to unmap old 2M COW frame")?
                .0;
            debug_assert_eq!(old_unmapped.start_address(), phys_frame_addr);
            unsafe {
                mapper.map_to(
                    huge_page,
                    x86_64::structures::paging::PhysFrame::<Size2MiB>::containing_address(
                        new_frame.start_address,
                    ),
                    tracked_flags,
                    &mut frame_allocator,
                )
            }
            .map(|flush| flush.flush())
            .map_err(|_| "Failed to map new 2M COW frame")
        }
    };
    if remap_res.is_err() {
        match mapping.page_size {
            VmaPageSize::Small => unsafe {
                let _ = mapper.map_to(
                    page,
                    x86_64::structures::paging::PhysFrame::<Size4KiB>::containing_address(
                        phys_frame_addr,
                    ),
                    flags,
                    &mut frame_allocator,
                );
            },
            VmaPageSize::Huge => unsafe {
                let huge_page = Page::<Size2MiB>::containing_address(VirtAddr::new(page_start));
                let _ = mapper.map_to(
                    huge_page,
                    x86_64::structures::paging::PhysFrame::<Size2MiB>::containing_address(
                        phys_frame_addr,
                    ),
                    flags,
                    &mut frame_allocator,
                );
            },
        }
        crate::sync::with_irqs_disabled(|token| {
            crate::memory::free_frames(token, new_frame, order);
        });
        return Err(remap_res.err().unwrap_or("Failed to map new COW frame"));
    }

    // The new private frame is the sole owner; set refcount=1 directly.
    // BuddyFrameAllocator returns a raw frame (refcount still REFCOUNT_UNUSED).
    // frame_inc_ref would wrap REFCOUNT_UNUSED to 0 — use set_refcount instead.
    crate::memory::cow::handle_init_ref(new_handle);

    if address_space
        .register_effective_mapping(EffectiveMapping {
            start: page_start,
            cap_id: mapping.cap_id,
            handle: new_handle,
            flags: tracked_flags,
            page_size: mapping.page_size,
        })
        .is_err()
    {
        match mapping.page_size {
            VmaPageSize::Small => {
                let _ = mapper.unmap(page);
                let _ = unsafe {
                    mapper.map_to(
                        page,
                        x86_64::structures::paging::PhysFrame::<Size4KiB>::containing_address(
                            phys_frame_addr,
                        ),
                        flags,
                        &mut frame_allocator,
                    )
                }
                .map(|flush| flush.flush());
            }
            VmaPageSize::Huge => {
                let huge_page = Page::<Size2MiB>::containing_address(VirtAddr::new(page_start));
                let _ = mapper.unmap(huge_page);
                let _ = unsafe {
                    mapper.map_to(
                        huge_page,
                        x86_64::structures::paging::PhysFrame::<Size2MiB>::containing_address(
                            phys_frame_addr,
                        ),
                        flags,
                        &mut frame_allocator,
                    )
                }
                .map(|flush| flush.flush());
            }
        }
        crate::sync::with_irqs_disabled(|token| {
            crate::memory::free_frames(token, new_frame, order);
        });
        return Err("Failed to track new COW mapping");
    }

    // Only the current CPU can hold this CR3 in the current design.
    local_invlpg(virt_addr);

    // Replacing the effective mapping at the same address already unregisters
    // the previous mapping identity for old_handle. There is no transient pin
    // to drop in this path.

    Ok(())
}
