//! Task Management
//!
//! Defines the Task structure and related types for the Strat9-OS scheduler.

use crate::memory::AddressSpace;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use x86_64::{PhysAddr, VirtAddr};

/// POSIX process ID.
pub type Pid = u32;
/// POSIX thread ID.
pub type Tid = u32;

/// Performs the next pid operation.
#[inline]
fn next_pid() -> Pid {
    static NEXT_PID: AtomicU32 = AtomicU32::new(1);
    NEXT_PID.fetch_add(1, Ordering::SeqCst)
}

/// Performs the next tid operation.
#[inline]
fn next_tid() -> Tid {
    static NEXT_TID: AtomicU32 = AtomicU32::new(1);
    NEXT_TID.fetch_add(1, Ordering::SeqCst)
}

/// Unique identifier for a task
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaskId(u64);

impl TaskId {
    /// Generate a new unique task ID
    pub fn new() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        TaskId(NEXT_ID.fetch_add(1, Ordering::SeqCst))
    }

    /// Get the raw u64 value
    pub fn as_u64(self) -> u64 {
        self.0
    }

    /// Create a TaskId from a raw u64 (for IPC reply routing).
    pub fn from_u64(raw: u64) -> Self {
        TaskId(raw)
    }
}

impl core::fmt::Display for TaskId {
    /// Performs the fmt operation.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Priority levels for tasks
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskPriority {
    Idle = 0,
    Low = 1,
    Normal = 2,
    High = 3,
    Realtime = 4,
}

/// State of a task in the scheduler
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    /// Task is ready to be scheduled
    Ready = 0,
    /// Task is currently running
    Running = 1,
    /// Task is blocked waiting for an event
    Blocked = 2,
    /// Task has exited
    Dead = 3,
}

/// How this task must be resumed the next time the scheduler selects it.
///
/// - `RetFrame`: legacy kernel-only context switch using `ret`
/// - `IretFrame`: interrupt/syscall-like frame restored with `iretq`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeKind {
    RetFrame,
    IretFrame,
}

use core::cell::UnsafeCell;

/// A wrapper around UnsafeCell that implements Sync for TaskState
pub struct SyncUnsafeCell<T> {
    inner: UnsafeCell<T>,
}

unsafe impl<T> Sync for SyncUnsafeCell<T> {}

impl<T> SyncUnsafeCell<T> {
    /// Creates a new instance.
    pub const fn new(value: T) -> Self {
        Self {
            inner: UnsafeCell::new(value),
        }
    }

    /// Performs the get operation.
    pub fn get(&self) -> *mut T {
        self.inner.get()
    }
}

/// FPU/SSE/AVX extended state, saved and restored on context switch.
///
/// When XSAVE is available, uses `xsave`/`xrstor` with a variable-size area.
/// Falls back to `fxsave`/`fxrstor` (512 bytes) on older CPUs.
#[repr(C, align(64))]
pub struct ExtendedState {
    pub data: [u8; Self::MAX_XSAVE_SIZE],
    pub size: usize,
    pub uses_xsave: bool,
    pub xcr0_mask: u64,
}

impl core::fmt::Debug for ExtendedState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExtendedState")
            .field("size", &self.size)
            .field("uses_xsave", &self.uses_xsave)
            .field("xcr0_mask", &self.xcr0_mask)
            .finish()
    }
}

impl ExtendedState {
    pub const FXSAVE_SIZE: usize = 512;
    pub const MAX_XSAVE_SIZE: usize = 2688;

    /// Create a new default state using the host's maximum capabilities.
    pub fn new() -> Self {
        crate::serial_println!("[trace][fpu] ExtendedState::new enter");
        let (uses_xsave, size, default_xcr0) = if crate::arch::x86_64::cpuid::host_uses_xsave() {
            crate::serial_println!("[trace][fpu] ExtendedState::new host_uses_xsave=true");
            let xcr0 = crate::arch::x86_64::cpuid::host_default_xcr0();
            crate::serial_println!(
                "[trace][fpu] ExtendedState::new host_default_xcr0={:#x}",
                xcr0
            );
            let sz =
                crate::arch::x86_64::cpuid::xsave_size_for_xcr0(xcr0).min(Self::MAX_XSAVE_SIZE);
            crate::serial_println!("[trace][fpu] ExtendedState::new xsave_size={}", sz);
            (true, sz, xcr0)
        } else {
            crate::serial_println!("[trace][fpu] ExtendedState::new host_uses_xsave=false");
            (false, Self::FXSAVE_SIZE, 0x3)
        };

        crate::serial_println!(
            "[trace][fpu] ExtendedState::new build state uses_xsave={} size={} xcr0={:#x}",
            uses_xsave,
            size,
            default_xcr0
        );
        let mut state = Self {
            data: [0u8; Self::MAX_XSAVE_SIZE],
            size,
            uses_xsave,
            xcr0_mask: default_xcr0,
        };
        crate::serial_println!("[trace][fpu] ExtendedState::new state allocated");
        state.set_defaults();
        crate::serial_println!("[trace][fpu] ExtendedState::new defaults set");
        state
    }

    /// Create a state for a specific XCR0 mask (per-silo feature restriction).
    pub fn for_xcr0(xcr0: u64) -> Self {
        let uses_xsave = crate::arch::x86_64::cpuid::host_uses_xsave();
        let size = if uses_xsave {
            crate::arch::x86_64::cpuid::xsave_size_for_xcr0(xcr0).min(Self::MAX_XSAVE_SIZE)
        } else {
            Self::FXSAVE_SIZE
        };

        let mut state = Self {
            data: [0u8; Self::MAX_XSAVE_SIZE],
            size,
            uses_xsave,
            xcr0_mask: xcr0,
        };
        state.set_defaults();
        state
    }

    fn set_defaults(&mut self) {
        // x87 FCW = 0x037F
        self.data[0] = 0x7F;
        self.data[1] = 0x03;
        // MXCSR = 0x1F80
        self.data[24] = 0x80;
        self.data[25] = 0x1F;
    }

    /// Copy the state from another `ExtendedState`.
    pub fn copy_from(&mut self, other: &ExtendedState) {
        let len = other.size.min(self.size);
        self.data[..len].copy_from_slice(&other.data[..len]);
    }
}

/// Represents a single task/thread in the system
pub struct Task {
    /// Unique identifier for this task
    pub id: TaskId,
    /// Process identifier visible to userspace.
    pub pid: Pid,
    /// Thread identifier visible to userspace.
    pub tid: Tid,
    /// Thread-group identifier (equals process leader PID).
    pub tgid: Pid,
    /// Process group id (job-control group).
    pub pgid: AtomicU32,
    /// Session id.
    pub sid: AtomicU32,
    /// real user id.
    pub uid: AtomicU32,
    /// effective user id.
    pub euid: AtomicU32,
    /// real group id.
    pub gid: AtomicU32,
    /// effective group id.
    pub egid: AtomicU32,
    /// Current state of the task. Stored as AtomicU8 for lock-free cross-CPU visibility.
    /// Use `get_state()` / `set_state()` for typed access.
    pub state: AtomicU8,
    /// Priority level of the task
    pub priority: TaskPriority,
    /// Saved CPU context for this task (just the stack pointer)
    pub context: SyncUnsafeCell<CpuContext>,
    /// Resume convention for this task's saved kernel stack frame.
    pub resume_kind: SyncUnsafeCell<ResumeKind>,
    /// Saved interrupt/syscall-compatible frame pointer for `iretq`-based resume.
    pub interrupt_rsp: AtomicU64,
    /// Kernel stack for this task
    pub kernel_stack: KernelStack,
    /// User stack for this task (if applicable)
    pub user_stack: Option<UserStack>,
    /// Task name for debugging purposes
    pub name: &'static str,
    /// Capabilities granted to this task
    /// Address space for this task (kernel tasks share the kernel AS)
    pub process: Arc<crate::process::process::Process>,
    /// File descriptor table for this task
    /// Pending signals for this task
    pub pending_signals: super::signal::SignalSet,
    /// Blocked signals mask for this task
    pub blocked_signals: super::signal::SignalSet,
    /// Signal actions (handlers) for this task
    /// Signal alternate stack for this task
    pub signal_stack: SyncUnsafeCell<Option<super::signal::SigStack>>,
    /// Interval timers (ITIMER_REAL, ITIMER_VIRTUAL, ITIMER_PROF)
    pub itimers: super::timer::ITimers,
    /// Pending wakeup flag: set by `wake_task()` when the task is not yet
    /// in `blocked_tasks` (it is still transitioning to Blocked state).
    /// Checked by `block_current_task()` — if set, the task skips blocking
    /// and continues execution, preventing a lost-wakeup race.
    pub wake_pending: AtomicBool,
    /// Sleep deadline in nanoseconds (monotonic). If non-zero, the task
    /// is sleeping until this time. Checked by the scheduler to auto-wake.
    pub wake_deadline_ns: AtomicU64,
    /// Program break (end of heap), in bytes. 0 = not yet initialised.
    /// Lazily set to `BRK_BASE` on the first `sys_brk` call.
    /// mmap_hint: next candidate virtual address for anonymous mmap allocations
    /// User-space entry point for ring3 trampoline (ELF tasks only, 0 otherwise).
    pub trampoline_entry: AtomicU64,
    /// User-space stack top for ring3 trampoline (ELF tasks only, 0 otherwise).
    pub trampoline_stack_top: AtomicU64,
    /// First argument (RDI) passed to the user process on entry (e.g. bootstrap cap handle).
    pub trampoline_arg0: AtomicU64,
    /// Total CPU ticks consumed by this task
    pub ticks: AtomicU64,
    /// Scheduling policy (Fair, RealTime, Idle)
    pub sched_policy: SyncUnsafeCell<crate::process::sched::SchedPolicy>,
    /// Virtual runtime for CFS
    pub vruntime: AtomicU64,
    /// TID address for futex-based thread join (set_tid_address).
    /// The kernel writes 0 here when the thread exits, then futex_wake.
    pub clear_child_tid: AtomicU64,
    /// Current working directory (POSIX, inherited by children).
    /// File creation mask (inherited by children, NOT reset by exec).
    /// User-space FS.base (TLS on x86_64, set via arch_prctl ARCH_SET_FS).
    /// Saved/restored across context switches.
    pub user_fs_base: AtomicU64,
    /// FPU/SSE/AVX extended state saved during context switch.
    pub fpu_state: SyncUnsafeCell<ExtendedState>,
    /// XCR0 mask for this task (inherited from its silo).
    pub xcr0_mask: AtomicU64,
}

impl Task {
    /// Leave this much headroom above the synthetic `SyscallFrame`.
    ///
    /// The raw IRQ switch path does `mov rsp, next_rsp` and then `call
    /// finish_interrupt_switch`, so `next_rsp` must be close to the top of the
    /// kernel stack to preserve downward growth room for the call chain.
    const BOOTSTRAP_INTERRUPT_FRAME_TOP_HEADROOM: usize = 0x1000;

    /// Canary placed below the interrupt frame to detect stack underflow
    /// (interrupt handler overflowing downward past the frame)
    const STACK_UNDERFLOW_CANARY_OFFSET: usize = 0x100; // 256 bytes from base

    /// Performs the default sched policy operation.
    pub fn default_sched_policy(priority: TaskPriority) -> crate::process::sched::SchedPolicy {
        use crate::process::sched::{nice::Nice, real_time::RealTimePriority, SchedPolicy};
        match priority {
            TaskPriority::Idle => SchedPolicy::Idle,
            TaskPriority::Realtime => SchedPolicy::RealTimeRR {
                prio: RealTimePriority::new(50),
            },
            TaskPriority::High => SchedPolicy::Fair(Nice::new(-10)),
            TaskPriority::Low => SchedPolicy::Fair(Nice::new(10)),
            TaskPriority::Normal => SchedPolicy::Fair(Nice::default()),
        }
    }

    /// Get the current scheduling policy of the task
    pub fn sched_policy(&self) -> crate::process::sched::SchedPolicy {
        unsafe { *self.sched_policy.get() }
    }

    /// Set the scheduling policy of the task
    pub fn set_sched_policy(&self, policy: crate::process::sched::SchedPolicy) {
        unsafe {
            *self.sched_policy.get() = policy;
        }
    }

    /// Returns the current resume convention for this task.
    pub fn resume_kind(&self) -> ResumeKind {
        unsafe { *self.resume_kind.get() }
    }

    /// Sets the resume convention for this task.
    pub fn set_resume_kind(&self, kind: ResumeKind) {
        unsafe {
            *self.resume_kind.get() = kind;
        }
    }

    /// Returns the saved `iretq`-compatible frame pointer for this task.
    pub fn interrupt_rsp(&self) -> u64 {
        self.interrupt_rsp.load(Ordering::Acquire)
    }

    /// Updates the saved `iretq`-compatible frame pointer for this task.
    pub fn set_interrupt_rsp(&self, rsp: u64) {
        self.interrupt_rsp.store(rsp, Ordering::Release);
    }

    /// Seed a synthetic interrupt frame for tasks that have not yet been
    /// preempted from an IRQ path but must still be resumable via `iretq`.
    pub fn seed_interrupt_frame(&self, frame: crate::syscall::SyscallFrame) {
        let stack_base = self.kernel_stack.virt_base.as_u64();
        let stack_top = stack_base + self.kernel_stack.size as u64;
        let frame_size = core::mem::size_of::<crate::syscall::SyscallFrame>() as u64;
        let raw_frame_addr = stack_top
            .saturating_sub(Self::BOOTSTRAP_INTERRUPT_FRAME_TOP_HEADROOM as u64)
            .saturating_sub(frame_size);
        let frame_addr = raw_frame_addr & !0xF;
        let frame_end = frame_addr + core::mem::size_of::<crate::syscall::SyscallFrame>() as u64;
        assert!(
            frame_addr >= stack_base && frame_end <= stack_top,
            "kernel stack too small for bootstrap interrupt frame"
        );
        unsafe {
            (frame_addr as *mut crate::syscall::SyscallFrame).write(frame);

            // Place underflow canary below the frame (at lower address)
            // This detects if interrupt handler overflows downward past expected range
            let canary_addr = stack_base + Self::STACK_UNDERFLOW_CANARY_OFFSET as u64;
            *(canary_addr as *mut u64) = 0xBAD57ACBAD57AC;
        }
        self.set_interrupt_rsp(frame_addr);
    }

    /// Seed an `iretq`-compatible frame from the legacy `CpuContext` bootstrap
    /// layout used by kernel tasks (`ret` into `task_entry_trampoline`).
    ///
    /// The synthesised frame always sets IF=1 so that IRQ-driven resumes keep
    /// receiving timer interrupts. First-launch tasks still enter through the
    /// legacy `ret` trampoline and must explicitly re-enable interrupts in
    /// `task_post_switch_enter`.
    pub fn seed_kernel_interrupt_frame_from_context(&self) {
        let stack_base = self.kernel_stack.virt_base.as_u64();
        let stack_top = stack_base + self.kernel_stack.size as u64;
        let saved_rsp = unsafe { (*self.context.get()).saved_rsp as *const u64 };
        let saved_rsp_val = saved_rsp as u64;
        debug_assert!(
            saved_rsp_val >= stack_base && saved_rsp_val.saturating_add(7 * 8) <= stack_top,
            "saved_rsp outside kernel stack while seeding interrupt frame"
        );
        let ret_target = unsafe { *saved_rsp.add(6) };
        // Always set IF=1 (bit 9) so IRQ-driven resumes keep interrupts enabled.
        // First-launch tasks still need an explicit sti() in
        // task_post_switch_enter because the legacy bootstrap path reaches the
        // entry point through a plain ret, not an iretq restoring RFLAGS.
        let rflags = 0x202u64; // bit 9 = IF, bit 1 = reserved (always 1)
        let frame = unsafe {
            crate::syscall::SyscallFrame {
                r15: *saved_rsp.add(0),
                r14: *saved_rsp.add(1),
                r13: *saved_rsp.add(2),
                r12: *saved_rsp.add(3),
                rbp: *saved_rsp.add(4),
                rbx: *saved_rsp.add(5),
                r11: 0,
                r10: 0,
                r9: 0,
                r8: 0,
                rsi: 0,
                rdi: 0,
                rdx: 0,
                rcx: 0,
                rax: 0,
                iret_rip: ret_target,
                iret_cs: crate::arch::x86_64::gdt::kernel_code_selector().0 as u64,
                iret_rflags: rflags,
                iret_rsp: self.kernel_stack.virt_base.as_u64() + self.kernel_stack.size as u64,
                iret_ss: crate::arch::x86_64::gdt::kernel_data_selector().0 as u64,
            }
        };
        self.seed_interrupt_frame(frame);
    }

    /// Get virtual runtime
    pub fn vruntime(&self) -> u64 {
        self.vruntime.load(Ordering::Relaxed)
    }

    /// Set virtual runtime
    pub fn set_vruntime(&self, vruntime: u64) {
        self.vruntime.store(vruntime, Ordering::Relaxed);
    }

    /// Read the current task state atomically.
    #[inline]
    pub fn get_state(&self) -> TaskState {
        let raw = self.state.load(Ordering::Acquire);
        debug_assert!(
            raw <= TaskState::Dead as u8,
            "get_state: invalid TaskState discriminant {:#x}",
            raw
        );
        // SAFETY: `raw` is always one of the four valid `#[repr(u8)]`
        // discriminants (0..=3); the only writer is `set_state` which stores
        // a cast from the same enum.
        unsafe { core::mem::transmute(raw) }
    }

    /// Write the task state atomically. Uses Release ordering so the new state
    /// is visible to any CPU that subsequently does an Acquire load.
    #[inline]
    pub fn set_state(&self, new_state: TaskState) {
        self.state.store(new_state as u8, Ordering::Release);
    }
}

/// CPU context saved/restored during context switches.
///
/// Only stores the saved RSP. All callee-saved registers (rbx, rbp, r12-r15)
/// are pushed onto the task's kernel stack by `switch_context()`.
#[repr(C)]
pub struct CpuContext {
    /// Saved stack pointer (points into the task's kernel stack)
    pub saved_rsp: u64,
}

impl CpuContext {
    /// Create a new CPU context for a task starting at the given entry point.
    ///
    /// Sets up a fake stack frame on the kernel stack that looks like
    /// `switch_context()` just pushed callee-saved registers. When
    /// `switch_context()` or `restore_first_task()` pops them and does `ret`,
    /// it will jump to `task_entry_trampoline`, which enables interrupts
    /// and jumps to the real entry point (stored in r12).
    ///
    /// Stack layout (growing downward):
    /// ```text
    /// [stack_top]
    ///   0xDEADBEEFCAFEBABE      <- stack canary
    ///   task_entry_trampoline   <- ret target
    ///   0  (r15)
    ///   0  (r14)
    ///   0  (r13)
    ///   entry_point (r12)      <- trampoline reads this
    ///   0  (rbp)
    ///   0  (rbx)
    ///   <- saved_rsp points here
    /// ```
    pub fn new(entry_point: u64, kernel_stack: &KernelStack) -> Self {
        let stack_top = kernel_stack.virt_base.as_u64() + kernel_stack.size as u64;

        // Reserve space for the stack canary before building the fake frame.
        const STACK_CANARY: u64 = 0xDEADBEEFCAFEBABE;
        let canary_addr = stack_top - 8;
        let initial_rsp = canary_addr - 7 * 8;

        // SAFETY: We own this stack memory and it's properly allocated and zeroed.
        // The stack region [virt_base, virt_base + size) is valid.
        unsafe {
            let stack = initial_rsp as *mut u64;
            // Push order must match switch_context pops (LIFO, but we write linearly from RSP up):
            // [RSP+0]  = r15
            // [RSP+8]  = r14
            // [RSP+16] = r13
            // [RSP+24] = r12 (entry point)
            // [RSP+32] = rbp
            // [RSP+40] = rbx
            // [RSP+48] = ret (trampoline)
            *stack.add(0) = 0; // r15
            *stack.add(1) = 0; // r14
            *stack.add(2) = 0; // r13
            *stack.add(3) = entry_point; // r12 (trampoline target)
            *stack.add(4) = 0; // rbp
            *stack.add(5) = 0; // rbx
            *stack.add(6) = task_entry_trampoline as *const () as u64; // ret address
        }

        // Add stack canary at the very top (leave the frame below it so `ret` still points
        // to `task_entry_trampoline`). The canary slot must be reserved before writing the
        // frame to avoid overwriting the trampoline address.
        unsafe {
            let canary_ptr = canary_addr as *mut u64;
            *canary_ptr = STACK_CANARY;
        }

        // Verify canary is still intact
        unsafe {
            let canary_ptr = canary_addr as *const u64;
            let canary = *canary_ptr;
            if canary != STACK_CANARY {
                crate::serial_force_println!(
                    "[PANIC] Stack canary corrupted at setup! entry_point={:#x} canary={:#x}",
                    entry_point,
                    canary
                );
            }
        }

        // Debug: verify entire stack frame
        unsafe {
            let stack = initial_rsp as *const u64;
            crate::serial_println!(
                "[CpuContext] frame verify: r15={:#x} r14={:#x} r13={:#x} r12={:#x} rbp={:#x} rbx={:#x} ret={:#x}",
                *stack.add(0),
                *stack.add(1),
                *stack.add(2),
                *stack.add(3),
                *stack.add(4),
                *stack.add(5),
                *stack.add(6)
            );
            // Verify canary one more time
            let canary_ptr = canary_addr as *const u64;
            let canary = *canary_ptr;
            if canary != STACK_CANARY {
                crate::serial_force_println!(
                    "[CpuContext] CANARY CORRUPTED AFTER FRAME SETUP! canary={:#x}",
                    canary
                );
            }

            // Debug: check if stack memory overlaps with another task
            crate::serial_println!(
                "[CpuContext] stack range: base={:#x} top={:#x} initial_rsp={:#x}",
                kernel_stack.virt_base.as_u64(),
                stack_top,
                initial_rsp
            );
        }

        CpuContext {
            saved_rsp: initial_rsp,
        }
    }
}

/// Trampoline for newly created tasks.
///
/// When a new task is first scheduled, `switch_context()` pops the fake
/// callee-saved registers and `ret`s here, then tail-jumps into the actual
/// post-switch entry helper.
#[unsafe(naked)]
pub unsafe extern "C" fn task_entry_trampoline() -> ! {
    core::arch::naked_asm!(
        "mov al, 'T'",
        "out 0xe9, al",
        "call {finish_switch}",
        "mov al, '1'",
        "out 0xe9, al",
        "mov rdi, r12", // entry_point
        "mov rsi, r13", // arg0
        "and rsp, -16",
        "sub rsp, 8",
        "jmp {post_switch_enter}",
        finish_switch = sym crate::process::scheduler::finish_switch,
        post_switch_enter = sym task_post_switch_enter,
    );
}

fn task_post_switch_enter(entry: u64, arg0: u64) -> ! {
    // E9 breadcrumb: 'P' = reached post_switch_enter (no serial lock needed).
    unsafe {
        core::arch::asm!("out 0xe9, al", in("al") b'P', options(nomem, nostack));
    }

    crate::arch::x86_64::percpu::mark_tlb_ready_current();

    let cpu = crate::arch::x86_64::percpu::current_cpu_index();

    let is_user_entry = crate::process::scheduler::current_task_clone_try()
        .map(|task| task.trampoline_entry.load(Ordering::Relaxed) != 0)
        .unwrap_or(false);

    // Single diagnostic print (IF may be 0 or 1 depending on RFLAGS seed; either
    // way E9 is IRQ-safe and this is the LAST trace call before entry_fn).
    if let Some(task) = crate::process::scheduler::current_task_clone_try() {
        crate::e9_println!(
            "[pse] cpu={} tid={} user={} entry={:#x}",
            cpu,
            task.id.as_u64(),
            is_user_entry,
            entry
        );
    }

    // First-launch tasks arrive here via the legacy `ret` bootstrap path, which
    // does not restore RFLAGS. Re-enable interrupts now that `finish_switch()`
    // has completed and the task is running on its own stack.
    crate::arch::x86_64::sti();

    // User tasks still transition to Ring 3 via iretq later and will restore
    // their own RFLAGS there.

    let entry_fn: extern "C" fn(u64) -> ! = unsafe { core::mem::transmute(entry as usize) };
    entry_fn(arg0)
}

/// Kernel stack for a task
pub struct KernelStack {
    /// Physical address of the stack
    pub base: PhysAddr,
    /// Virtual address of the stack
    pub virt_base: VirtAddr,
    /// Size of the stack
    pub size: usize,
}

impl KernelStack {
    /// Allocate a new kernel stack using the buddy allocator
    pub fn allocate(size: usize) -> Result<Self, &'static str> {
        // Calculate number of pages needed (round up)
        let pages = (size + 4095) / 4096;
        let order = pages.next_power_of_two().trailing_zeros() as u8;

        crate::serial_println!("[trace][task] kstack allocate begin size={}", size);
        crate::serial_println!(
            "[trace][task] kstack allocate pages={} order={}",
            pages,
            order
        );

        crate::serial_println!(
            "[trace][task] kstack allocate calling allocate_frames order={}",
            order
        );
        let frame =
            crate::sync::with_irqs_disabled(|token| crate::memory::allocate_frames(token, order))
                .map_err(|_| "Failed to allocate kernel stack")?;
        crate::serial_println!(
            "[trace][task] kstack allocate frame phys={:#x}",
            frame.start_address.as_u64()
        );

        let phys_base = frame.start_address;
        let virt_base = VirtAddr::new(crate::memory::phys_to_virt(phys_base.as_u64()));
        crate::serial_println!(
            "[trace][task] kstack allocate virt_base={:#x}",
            virt_base.as_u64()
        );

        // Zero out the stack for safety
        unsafe {
            core::ptr::write_bytes(virt_base.as_mut_ptr::<u8>(), 0, size);
        }
        crate::serial_println!("[trace][task] kstack allocate memset done");

        // Debug: verify zeroing worked
        unsafe {
            let first_word = *(virt_base.as_ptr::<u64>());
            let mid_offset = size / 2;
            let mid_word = *((virt_base.as_u64() + mid_offset as u64) as *const u64);
            let last_offset = size - 8;
            let last_word = *((virt_base.as_u64() + last_offset as u64) as *const u64);
            if first_word != 0 || mid_word != 0 || last_word != 0 {
                crate::serial_force_println!(
                    "[WARN] kstack zeroing failed! first={:#x} mid={:#x} last={:#x}",
                    first_word,
                    mid_word,
                    last_word
                );
            }
        }

        Ok(KernelStack {
            base: phys_base,
            virt_base,
            size,
        })
    }

    /// Debug: check if this stack overlaps with another range
    pub fn overlaps(&self, other_base: u64, other_size: usize) -> bool {
        let self_end = self.virt_base.as_u64() + self.size as u64;
        let other_end = other_base + other_size as u64;
        !(self_end <= other_base || other_end <= self.virt_base.as_u64())
    }
}

impl Drop for KernelStack {
    /// Performs the drop operation.
    fn drop(&mut self) {
        use crate::memory::frame::PhysFrame;

        let pages = (self.size + 4095) / 4096;
        let order = pages.next_power_of_two().trailing_zeros() as u8;
        let frame = PhysFrame {
            start_address: self.base,
        };

        crate::sync::with_irqs_disabled(|token| {
            crate::memory::free_frames(token, frame, order);
        });
    }
}

/// User stack for a task (when running in userspace)
pub struct UserStack {
    /// Virtual address of the user stack
    pub virt_base: VirtAddr,
    /// Size of the stack
    pub size: usize,
}

impl Task {
    /// Default kernel stack size (64 KB - increased from 16KB due to overflow)
    pub const DEFAULT_STACK_SIZE: usize = 65536;

    /// Create a new kernel task with a real allocated stack
    pub fn new_kernel_task(
        entry_point: extern "C" fn() -> !,
        name: &'static str,
        priority: TaskPriority,
    ) -> Result<Arc<Self>, &'static str> {
        Self::new_kernel_task_with_stack(entry_point, name, priority, Self::DEFAULT_STACK_SIZE)
    }

    /// Create a new kernel task with a custom kernel stack size.
    pub fn new_kernel_task_with_stack(
        entry_point: extern "C" fn() -> !,
        name: &'static str,
        priority: TaskPriority,
        stack_size: usize,
    ) -> Result<Arc<Self>, &'static str> {
        crate::serial_println!(
            "[trace][task] new_kernel_task_with_stack begin name={} stack_size={}",
            name,
            stack_size
        );
        // Allocate a real kernel stack
        let kernel_stack = KernelStack::allocate(stack_size)?;
        crate::serial_println!("[trace][task] new_kernel_task_with_stack kstack done");

        // Create CPU context with the allocated stack
        let context = CpuContext::new(entry_point as *const () as u64, &kernel_stack);
        crate::serial_println!("[trace][task] new_kernel_task_with_stack context done");
        let id = TaskId::new();
        let (pid, tid, tgid) = Self::allocate_process_ids();
        crate::serial_println!(
            "[trace][task] new_kernel_task_with_stack ids done id={} pid={} tid={} tgid={}",
            id.as_u64(),
            pid,
            tid,
            tgid
        );
        let fpu_state = ExtendedState::new();
        let xcr0_mask = fpu_state.xcr0_mask;

        let process = Arc::new(crate::process::process::Process::new(
            pid,
            crate::memory::kernel_address_space().clone(),
        ));
        crate::serial_println!("[trace][task] new_kernel_task_with_stack process done");

        log::debug!(
            "[task][create] name={} id={} pid={} tid={} kstack={:?} kstack_kib={}",
            name,
            id.as_u64(),
            pid,
            tid,
            kernel_stack.virt_base,
            kernel_stack.size / 1024
        );

        let task = Arc::new(Task {
            id,
            pid,
            tid,
            tgid,
            pgid: AtomicU32::new(pid),
            sid: AtomicU32::new(pid),
            uid: AtomicU32::new(0),
            euid: AtomicU32::new(0),
            gid: AtomicU32::new(0),
            egid: AtomicU32::new(0),
            state: AtomicU8::new(TaskState::Ready as u8),
            priority,
            context: SyncUnsafeCell::new(context),
            resume_kind: SyncUnsafeCell::new(ResumeKind::RetFrame),
            interrupt_rsp: AtomicU64::new(0),
            kernel_stack,
            user_stack: None,
            name,
            process,
            pending_signals: super::signal::SignalSet::new(),
            blocked_signals: super::signal::SignalSet::new(),
            signal_stack: SyncUnsafeCell::new(None),
            itimers: super::timer::ITimers::new(),
            wake_pending: AtomicBool::new(false),
            wake_deadline_ns: AtomicU64::new(0),
            trampoline_entry: AtomicU64::new(0),
            trampoline_stack_top: AtomicU64::new(0),
            trampoline_arg0: AtomicU64::new(0),
            ticks: AtomicU64::new(0),
            sched_policy: SyncUnsafeCell::new(Self::default_sched_policy(priority)),
            vruntime: AtomicU64::new(0),
            clear_child_tid: AtomicU64::new(0),
            user_fs_base: AtomicU64::new(0),
            fpu_state: SyncUnsafeCell::new(fpu_state),
            xcr0_mask: AtomicU64::new(xcr0_mask),
        });
        task.seed_kernel_interrupt_frame_from_context();
        Ok(task)
    }

    /// Create a new user task with its own address space (stub for future use).
    ///
    /// The entry point and user stack must already be mapped in the given address space.
    pub fn new_user_task(
        entry_point: u64,
        address_space: Arc<AddressSpace>,
        name: &'static str,
        priority: TaskPriority,
    ) -> Result<Arc<Self>, &'static str> {
        let kernel_stack = KernelStack::allocate(Self::DEFAULT_STACK_SIZE)?;
        let context = CpuContext::new(entry_point, &kernel_stack);
        let id = TaskId::new();
        let (pid, tid, tgid) = Self::allocate_process_ids();
        let fpu_state = ExtendedState::new();
        let xcr0_mask = fpu_state.xcr0_mask;

        log::debug!(
            "[task][create] name={} id={} pid={} tid={} user_as_cr3={:#x}",
            name,
            id.as_u64(),
            pid,
            tid,
            address_space.cr3().as_u64()
        );

        Ok(Arc::new(Task {
            id,
            pid,
            tid,
            tgid,
            pgid: AtomicU32::new(pid),
            sid: AtomicU32::new(pid),
            uid: AtomicU32::new(0),
            euid: AtomicU32::new(0),
            gid: AtomicU32::new(0),
            egid: AtomicU32::new(0),
            state: AtomicU8::new(TaskState::Ready as u8),
            priority,
            context: SyncUnsafeCell::new(context),
            resume_kind: SyncUnsafeCell::new(ResumeKind::RetFrame),
            interrupt_rsp: AtomicU64::new(0),
            kernel_stack,
            user_stack: None,
            name,
            process: Arc::new(crate::process::process::Process::new(pid, address_space)),
            pending_signals: super::signal::SignalSet::new(),
            blocked_signals: super::signal::SignalSet::new(),
            signal_stack: SyncUnsafeCell::new(None),
            itimers: super::timer::ITimers::new(),
            wake_pending: AtomicBool::new(false),
            wake_deadline_ns: AtomicU64::new(0),
            trampoline_entry: AtomicU64::new(0),
            trampoline_stack_top: AtomicU64::new(0),
            trampoline_arg0: AtomicU64::new(0),
            ticks: AtomicU64::new(0),
            sched_policy: SyncUnsafeCell::new(Self::default_sched_policy(priority)),
            vruntime: AtomicU64::new(0),
            clear_child_tid: AtomicU64::new(0),
            user_fs_base: AtomicU64::new(0),
            fpu_state: SyncUnsafeCell::new(fpu_state),
            xcr0_mask: AtomicU64::new(xcr0_mask),
        }))
    }

    /// Reset signal handlers during execve.
    ///
    /// POSIX requires handlers installed by userspace to revert to SIG_DFL on
    /// exec, while dispositions already set to SIG_IGN remain ignored.
    pub fn reset_signals(&self) {
        // SAFETY: We have a valid reference to the task.
        unsafe {
            let actions = &mut *self.process.signal_actions.get();
            for action in actions.iter_mut() {
                if !action.is_ignore() {
                    *action = super::signal::SigActionData::default();
                }
            }
        }
    }

    /// Returns true if this is a kernel task (shares the kernel address space).
    pub fn is_kernel(&self) -> bool {
        // SAFETY: address_space is immutable for the lifetime of the Arc?
        // Actually we just updated it to SyncUnsafeCell.
        unsafe { (*self.process.address_space.get()).is_kernel() }
    }

    /// Allocate POSIX identifiers for a new process leader.
    pub fn allocate_process_ids() -> (Pid, Tid, Pid) {
        let pid = next_pid();
        let tid = next_tid();
        (pid, tid, pid)
    }

    /// Print the memory layout of Task and Process structs for debugging.
    ///
    /// Computes field offsets at runtime using addr_of! so the output is
    /// accurate regardless of Rust's struct reordering decisions.
    /// Call this early in kernel init to validate the crash-site offset analysis.
    pub fn debug_print_layout() {
        use core::mem;
        crate::serial_println!("[layout] === Struct Layout Debug ===");
        crate::serial_println!(
            "[layout] sizeof(Task)          = {}",
            mem::size_of::<Task>()
        );
        crate::serial_println!(
            "[layout] sizeof(ExtendedState) = {}",
            mem::size_of::<ExtendedState>()
        );
        crate::serial_println!(
            "[layout] alignof(ExtendedState)= {}",
            mem::align_of::<ExtendedState>()
        );
        crate::serial_println!(
            "[layout] sizeof(CpuContext)    = {}",
            mem::size_of::<CpuContext>()
        );
        crate::serial_println!(
            "[layout] sizeof(KernelStack)   = {}",
            mem::size_of::<KernelStack>()
        );
        crate::serial_println!(
            "[layout] sizeof(Process)       = {}",
            mem::size_of::<crate::process::process::Process>()
        );
        crate::serial_println!(
            "[layout] sizeof(FileDescriptorTable) = {}",
            mem::size_of::<crate::vfs::fd::FileDescriptorTable>()
        );
        crate::serial_println!(
            "[layout] sizeof(CapabilityTable)     = {}",
            mem::size_of::<crate::capability::CapabilityTable>()
        );
        crate::serial_println!(
            "[layout] sizeof(SigActionData)       = {}",
            mem::size_of::<crate::process::signal::SigActionData>()
        );

        // Use heap-allocated MaybeUninit to avoid stack overflow from the ~3 KiB
        // ExtendedState embedded in Task. We only take *addresses* (addr_of!),
        // never read the uninitialized data itself, so this is sound.
        let task_box: alloc::boxed::Box<core::mem::MaybeUninit<Task>> =
            alloc::boxed::Box::new_uninit();
        // Cast to *const Task — we never read Task data, only compute field addresses.
        let task_ptr = task_box.as_ptr() as *const Task;
        let base = task_ptr as u64;
        // SAFETY: We only take addresses via addr_of!, no uninitialized reads.
        unsafe {
            let off_id = core::ptr::addr_of!((*task_ptr).id) as u64 - base;
            let off_pid = core::ptr::addr_of!((*task_ptr).pid) as u64 - base;
            let off_context = core::ptr::addr_of!((*task_ptr).context) as u64 - base;
            let off_kstack = core::ptr::addr_of!((*task_ptr).kernel_stack) as u64 - base;
            let off_process = core::ptr::addr_of!((*task_ptr).process) as u64 - base;
            let off_fpu = core::ptr::addr_of!((*task_ptr).fpu_state) as u64 - base;
            let off_xcr0 = core::ptr::addr_of!((*task_ptr).xcr0_mask) as u64 - base;
            let off_ticks = core::ptr::addr_of!((*task_ptr).ticks) as u64 - base;
            let off_name = core::ptr::addr_of!((*task_ptr).name) as u64 - base;
            let off_vruntime = core::ptr::addr_of!((*task_ptr).vruntime) as u64 - base;
            crate::serial_println!("[layout] Task field offsets (byte offset from Task data ptr):");
            crate::serial_println!("[layout]   id           @ +{:#x}", off_id);
            crate::serial_println!("[layout]   pid          @ +{:#x}", off_pid);
            crate::serial_println!("[layout]   context      @ +{:#x}", off_context);
            crate::serial_println!("[layout]   kernel_stack @ +{:#x}", off_kstack);
            crate::serial_println!("[layout]   process      @ +{:#x}", off_process);
            crate::serial_println!("[layout]   fpu_state    @ +{:#x}", off_fpu);
            crate::serial_println!("[layout]   xcr0_mask    @ +{:#x}", off_xcr0);
            crate::serial_println!("[layout]   ticks        @ +{:#x}", off_ticks);
            crate::serial_println!("[layout]   name         @ +{:#x}", off_name);
            crate::serial_println!("[layout]   vruntime     @ +{:#x}", off_vruntime);
        }
        // Arc<T> ArcInner overhead: strong(8)+weak(8)+data = data at offset 16.
        // So the crash at [ArcInner<Task>+0xbf8] means Task.process is at offset
        // 0xbf8 - 16 = 0xbe8 inside Task data. Check against off_process above.
        crate::serial_println!(
            "[layout] Expected task.process crash offset from Task data: {:#x}",
            0xbf8u64.saturating_sub(16)
        );

        // Process field offsets
        let proc_box: alloc::boxed::Box<core::mem::MaybeUninit<crate::process::process::Process>> =
            alloc::boxed::Box::new_uninit();
        #[allow(unused_variables)]
        let proc_ptr = proc_box.as_ptr() as *const crate::process::process::Process;
        let proc_base = proc_ptr as u64;
        unsafe {
            let off_pid = core::ptr::addr_of!((*proc_ptr).pid) as u64 - proc_base;
            let off_as = core::ptr::addr_of!((*proc_ptr).address_space) as u64 - proc_base;
            let off_fd = core::ptr::addr_of!((*proc_ptr).fd_table) as u64 - proc_base;
            let off_caps = core::ptr::addr_of!((*proc_ptr).capabilities) as u64 - proc_base;
            let off_sigs = core::ptr::addr_of!((*proc_ptr).signal_actions) as u64 - proc_base;
            let off_brk = core::ptr::addr_of!((*proc_ptr).brk) as u64 - proc_base;
            crate::serial_println!(
                "[layout] Process field offsets (byte offset from Process data ptr):"
            );
            crate::serial_println!("[layout]   pid            @ +{:#x}", off_pid);
            crate::serial_println!("[layout]   address_space  @ +{:#x}", off_as);
            crate::serial_println!("[layout]   fd_table       @ +{:#x}", off_fd);
            crate::serial_println!("[layout]   capabilities   @ +{:#x}", off_caps);
            crate::serial_println!("[layout]   signal_actions @ +{:#x}", off_sigs);
            crate::serial_println!("[layout]   brk            @ +{:#x}", off_brk);
        }
        // The crash reads [ArcInner<Process>+0x830].
        // ArcInner<Process>.data is at ArcInner+16, so Process offset is 0x830-16 = 0x820.
        crate::serial_println!(
            "[layout] Expected process field crash offset from Process data: {:#x}",
            0x830u64.saturating_sub(16)
        );
        crate::serial_println!("[layout] ===========================");
    }
}

/// Context switch dispatcher. Picks the xsave or fxsave path based on host
/// capabilities, then performs the full save/swap/restore sequence.
///
/// # Safety
/// Caller must ensure all pointers in `target` are valid and interrupts are disabled.
pub(super) unsafe fn do_switch_context(target: &super::scheduler::SwitchTarget) {
    // Temporary safety mode: force legacy FXSAVE/FXRSTOR path.
    // This avoids XSAVE/XRSTOR state-size mismatches that can corrupt task memory.
    //
    // TODO : re-enable XSAVE only after the kernel has a proven-stable end-to-end path
    // for:
    //     (1) xsave area sizing/allocation,
    //     (2) XCR0 transitions per task,
    //     (3) save/restore across scheduler, syscall, and interrupt returns.
    //
    // Until then old_xcr0/new_xcr0 stay intentionally unused in this path.
    let _ = target.old_xcr0;
    let _ = target.new_xcr0;
    switch_context_fxsave(
        target.old_rsp_ptr,
        target.new_rsp_ptr,
        target.old_fpu_ptr,
        target.new_fpu_ptr,
    );
}

/// First-task restore dispatcher. Like `do_switch_context` but without
/// saving old state (there is no previous task).
///
/// # Safety
/// Caller must ensure pointers are valid and interrupts are disabled. Never returns.
pub(super) unsafe fn do_restore_first_task(
    frame_ptr: *const u64, // Points to the stack frame (r15, r14, r13, r12, rbp, rbx, ret)
    fpu_ptr: *const u8,
    xcr0: u64,
) -> ! {
    // Debug: verify frame pointer
    crate::serial_force_println!(
        "[task] do_restore_first_task frame_ptr={:#x} fpu_ptr={:#x}",
        frame_ptr as u64,
        fpu_ptr as u64
    );

    // Verify the stack frame contains expected values
    crate::serial_force_println!(
        "[task] do_restore_first_task stack frame: r15={:#x} r14={:#x} r13={:#x} r12={:#x} rbp={:#x} rbx={:#x} ret={:#x}",
        *frame_ptr.add(0),
        *frame_ptr.add(1),
        *frame_ptr.add(2),
        *frame_ptr.add(3),
        *frame_ptr.add(4),
        *frame_ptr.add(5),
        *frame_ptr.add(6)
    );

    // Verify canary immediately above the fake frame (frame is 7 words long).
    let canary_addr = frame_ptr as u64 + 56;
    let canary = *(canary_addr as *const u64);
    crate::serial_force_println!(
        "[task] do_restore_first_task canary at {:#x} = {:#x} (expected 0xdeadbeefcafebabe)",
        canary_addr,
        canary
    );

    let _ = xcr0;
    restore_first_task_fxsave(frame_ptr, fpu_ptr);
}

// ── FXSAVE path (legacy, no XSAVE support) ──

/// rdi=old_rsp, rsi=new_rsp, rdx=old_fpu, rcx=new_fpu
#[unsafe(naked)]
unsafe extern "C" fn switch_context_fxsave(
    _old_rsp_ptr: *mut u64,
    _new_rsp_ptr: *const u64,
    _old_fpu_ptr: *mut u8,
    _new_fpu_ptr: *const u8,
) {
    core::arch::naked_asm!(
        "fxsave [rdx]",
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov [rdi], rsp",
        "mov rsp, [rsi]",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "fxrstor [rcx]",
        "ret",
    );
}

/// rdi=frame_ptr, rsi=fpu_ptr
#[unsafe(naked)]
unsafe extern "C" fn restore_first_task_fxsave(_rsp_ptr: *const u64, _fpu_ptr: *const u8) -> ! {
    // Debug: output pointers before restore (will be last serial output)
    // We can't use serial_println in naked functions, so this is just a marker
    // The actual debug output is in do_restore_first_task
    core::arch::naked_asm!(
        // `do_restore_first_task` passes the frame address directly.
        "mov rsp, rdi",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "fxrstor [rsi]",
        "ret",
    );
}

// ── XSAVE path (with XCR0 switching per-silo) ──

/// rdi=old_rsp, rsi=new_rsp, rdx=old_fpu, rcx=new_fpu, r8=new_xcr0, r9=old_xcr0
#[unsafe(naked)]
unsafe extern "C" fn switch_context_xsave(
    _old_rsp_ptr: *mut u64,
    _new_rsp_ptr: *const u64,
    _old_fpu_ptr: *mut u8,
    _new_fpu_ptr: *const u8,
    _new_xcr0: u64,
    _old_xcr0: u64,
) {
    core::arch::naked_asm!(
        "mov r10, rdx",
        "mov r11, r8",
        "test r11, r11",
        "jnz 10f",
        "mov r11, 3",
        "10:",
        "test r9, r9",
        "jnz 11f",
        "mov r9, 3",
        "11:",
        "mov eax, r9d",
        "shr r9, 32",
        "mov edx, r9d",
        "xsave [r10]",
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov [rdi], rsp",
        "mov rsp, [rsi]",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "push rcx",
        "mov ecx, 0",
        "mov eax, r11d",
        "mov r8, r11",
        "shr r8, 32",
        "mov edx, r8d",
        "xsetbv",
        "pop rcx",
        "mov eax, r11d",
        "mov r8, r11",
        "shr r8, 32",
        "mov edx, r8d",
        "xrstor [rcx]",
        "ret",
    );
}

/// rdi=frame_ptr, rsi=fpu_ptr, rdx=xcr0
#[unsafe(naked)]
unsafe extern "C" fn restore_first_task_xsave(
    _rsp_ptr: *const u64,
    _fpu_ptr: *const u8,
    _xcr0: u64,
) -> ! {
    core::arch::naked_asm!(
        // `do_restore_first_task` passes the frame address directly.
        "mov rsp, rdi",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "mov r8, rdx",
        "test r8, r8",
        "jnz 10f",
        "mov r8, 3",
        "10:",
        "mov r9, r8",
        "push rsi",
        "mov ecx, 0",
        "mov eax, r8d",
        "shr r8, 32",
        "mov edx, r8d",
        "xsetbv",
        "pop rsi",
        "mov eax, r9d",
        "shr r9, 32",
        "mov edx, r9d",
        "xrstor [rsi]",
        "ret",
    );
}
