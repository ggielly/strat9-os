//! `fork()` syscall implementation with copy-on-write (COW).

use crate::{
    memory::{AddressSpace, FrameAllocator as _},
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
use x86_64::structures::paging::{mapper::TranslateResult, FrameAllocator}; // Required for allocate_frame

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

fn copy_signal_set(src: &SignalSet) -> SignalSet {
    SignalSet::from_mask(src.get_mask())
}

fn build_child_task(
    parent: &Arc<Task>,
    child_as: Arc<AddressSpace>,
    bootstrap_ctx: Box<ForkUserContext>,
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
        address_space: SyncUnsafeCell::new(child_as),
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
        *frame.add(2) = Box::into_raw(bootstrap_ctx) as u64;
    }

    Ok(task)
}

/// SYS_PROC_FORK (302): fork with copy-on-write address-space cloning.
pub fn sys_fork(frame: &SyscallFrame) -> Result<ForkResult, SyscallError> {
    let parent = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let parent_as = unsafe { &*parent.address_space.get() };
    if parent_as.is_kernel() {
        return Err(SyscallError::PermissionDenied);
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
    let child_pid = child_task.id;
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
                .ignore();
        }
        // Invalidate TLB on all CPUs (SMP-safe).
        crate::arch::x86_64::tlb::shootdown_page(VirtAddr::new(virt_addr));
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
        Ok(flush) => flush.ignore(),
        Err(_) => unreachable!("checked remap result above"),
    }

    crate::memory::cow::frame_inc_ref(crate::memory::PhysFrame {
        start_address: new_frame.start_address(),
    });

    // Invalidate TLB on all CPUs (SMP-safe).
    crate::arch::x86_64::tlb::shootdown_page(VirtAddr::new(virt_addr));

    // Decrement refcount of old frame after the new mapping is installed.
    crate::memory::cow::frame_dec_ref(old_frame);

    Ok(())
}
