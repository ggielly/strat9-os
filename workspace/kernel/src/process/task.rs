//! Task Management
//!
//! Defines the Task structure and related types for the Strat9-OS scheduler.

use crate::{capability::CapabilityTable, memory::AddressSpace, vfs::FileDescriptorTable};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use x86_64::{PhysAddr, VirtAddr};

/// POSIX process ID.
pub type Pid = u32;
/// POSIX thread ID.
pub type Tid = u32;

#[inline]
fn next_pid() -> Pid {
    static NEXT_PID: AtomicU32 = AtomicU32::new(1);
    NEXT_PID.fetch_add(1, Ordering::SeqCst)
}

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    /// Task is ready to be scheduled
    Ready,
    /// Task is currently running
    Running,
    /// Task is blocked waiting for an event
    Blocked,
    /// Task has exited
    Dead,
}

use core::cell::UnsafeCell;

/// A wrapper around UnsafeCell that implements Sync for TaskState
pub struct SyncUnsafeCell<T> {
    inner: UnsafeCell<T>,
}

unsafe impl<T> Sync for SyncUnsafeCell<T> {}

impl<T> SyncUnsafeCell<T> {
    pub const fn new(value: T) -> Self {
        Self {
            inner: UnsafeCell::new(value),
        }
    }

    pub fn get(&self) -> *mut T {
        self.inner.get()
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
    /// Current state of the task
    pub state: SyncUnsafeCell<TaskState>,
    /// Priority level of the task
    pub priority: TaskPriority,
    /// Saved CPU context for this task (just the stack pointer)
    pub context: SyncUnsafeCell<CpuContext>,
    /// Kernel stack for this task
    pub kernel_stack: KernelStack,
    /// User stack for this task (if applicable)
    pub user_stack: Option<UserStack>,
    /// Task name for debugging purposes
    pub name: &'static str,
    /// Capabilities granted to this task
    pub capabilities: SyncUnsafeCell<CapabilityTable>,
    /// Address space for this task (kernel tasks share the kernel AS)
    pub address_space: SyncUnsafeCell<Arc<AddressSpace>>,
    /// File descriptor table for this task
    pub fd_table: SyncUnsafeCell<FileDescriptorTable>,
    /// Pending signals for this task
    pub pending_signals: SyncUnsafeCell<super::signal::SignalSet>,
    /// Blocked signals mask for this task
    pub blocked_signals: SyncUnsafeCell<super::signal::SignalSet>,
    /// Signal actions (handlers) for this task
    pub signal_actions: SyncUnsafeCell<[super::signal::SigAction; 64]>,
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
    pub brk: AtomicU64,
    /// mmap_hint: next candidate virtual address for anonymous mmap allocations
    pub mmap_hint: AtomicU64,
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
}

impl Task {
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
        unsafe { *self.sched_policy.get() = policy; }
    }

    /// Get virtual runtime
    pub fn vruntime(&self) -> u64 {
        self.vruntime.load(Ordering::Relaxed)
    }

    /// Set virtual runtime
    pub fn set_vruntime(&self, vruntime: u64) {
        self.vruntime.store(vruntime, Ordering::Relaxed);
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

        // We need to push 7 values (each 8 bytes) onto the stack
        let initial_rsp = stack_top - 7 * 8;

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

        CpuContext {
            saved_rsp: initial_rsp,
        }
    }
}

/// Trampoline for newly created tasks.
///
/// When a new task is first scheduled, `switch_context()` pops the fake
/// callee-saved registers and `ret`s here. We enable interrupts (the new
/// task starts with IF=0 because the scheduler disables interrupts) and
/// jump to the real entry point stored in r12.
#[unsafe(naked)]
unsafe extern "C" fn task_entry_trampoline() {
    core::arch::naked_asm!(
        "call {finish_switch}",
        "sti",          // Enable interrupts for the new task
        "call {mark_tlb_ready}",
        "mov rdi, r13", // Bootstrap arg (seeded cap handle)
        "jmp r12",      // Jump to real entry point (loaded from initial stack frame)
        finish_switch = sym crate::process::scheduler::finish_switch,
        mark_tlb_ready = sym crate::arch::x86_64::percpu::mark_tlb_ready_current,
    );
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
        use crate::memory::{get_allocator, FrameAllocator};

        // Calculate number of pages needed (round up)
        let pages = (size + 4095) / 4096;
        let order = pages.next_power_of_two().trailing_zeros() as u8;

        // Allocate physical frames from buddy allocator
        let mut lock = get_allocator().lock();
        let allocator = lock.as_mut().ok_or("Allocator not initialized")?;
        let frame = allocator
            .alloc(order)
            .map_err(|_| "Failed to allocate kernel stack")?;
        drop(lock);

        let phys_base = frame.start_address;
        let virt_base = VirtAddr::new(crate::memory::phys_to_virt(phys_base.as_u64()));

        // Zero out the stack for safety
        unsafe {
            core::ptr::write_bytes(virt_base.as_mut_ptr::<u8>(), 0, size);
        }

        Ok(KernelStack {
            base: phys_base,
            virt_base,
            size,
        })
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
    /// Default kernel stack size (16 KB)
    pub const DEFAULT_STACK_SIZE: usize = 16384;

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
        // Allocate a real kernel stack
        let kernel_stack = KernelStack::allocate(stack_size)?;

        // Create CPU context with the allocated stack
        let context = CpuContext::new(entry_point as *const () as u64, &kernel_stack);
        let id = TaskId::new();
        let (pid, tid, tgid) = Self::allocate_process_ids();

        log::debug!(
            "Created task '{}' (id={:?}, pid={}, tid={}) with stack @ {:?} (size={}KB)",
            name,
            id,
            pid,
            tid,
            kernel_stack.virt_base,
            kernel_stack.size / 1024
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
            state: SyncUnsafeCell::new(TaskState::Ready),
            priority,
            context: SyncUnsafeCell::new(context),
            kernel_stack,
            user_stack: None,
            name,
            capabilities: SyncUnsafeCell::new(CapabilityTable::new()),
            address_space: SyncUnsafeCell::new(crate::memory::kernel_address_space().clone()),
            fd_table: SyncUnsafeCell::new(FileDescriptorTable::new()),
            pending_signals: SyncUnsafeCell::new(super::signal::SignalSet::new()),
            blocked_signals: SyncUnsafeCell::new(super::signal::SignalSet::new()),
            signal_actions: SyncUnsafeCell::new([super::signal::SigAction::Default; 64]),
            signal_stack: SyncUnsafeCell::new(None),
            itimers: super::timer::ITimers::new(),
            wake_pending: AtomicBool::new(false),
            wake_deadline_ns: AtomicU64::new(0),
            brk: AtomicU64::new(0),
            mmap_hint: AtomicU64::new(0x0000_0000_6000_0000),
            trampoline_entry: AtomicU64::new(0),
            trampoline_stack_top: AtomicU64::new(0),
            trampoline_arg0: AtomicU64::new(0),
            ticks: AtomicU64::new(0),
            sched_policy: SyncUnsafeCell::new(Self::default_sched_policy(priority)),
            vruntime: AtomicU64::new(0),
        }))
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

        log::debug!(
            "Created user task '{}' (id={:?}, pid={}, tid={}) with CR3={:#x}",
            name,
            id,
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
            state: SyncUnsafeCell::new(TaskState::Ready),
            priority,
            context: SyncUnsafeCell::new(context),
            kernel_stack,
            user_stack: None,
            name,
            capabilities: SyncUnsafeCell::new(CapabilityTable::new()),
            address_space: SyncUnsafeCell::new(address_space),
            fd_table: SyncUnsafeCell::new(FileDescriptorTable::new()),
            pending_signals: SyncUnsafeCell::new(super::signal::SignalSet::new()),
            blocked_signals: SyncUnsafeCell::new(super::signal::SignalSet::new()),
            signal_actions: SyncUnsafeCell::new([super::signal::SigAction::Default; 64]),
            signal_stack: SyncUnsafeCell::new(None),
            itimers: super::timer::ITimers::new(),
            wake_pending: AtomicBool::new(false),
            wake_deadline_ns: AtomicU64::new(0),
            brk: AtomicU64::new(0),
            mmap_hint: AtomicU64::new(0x0000_0000_6000_0000),
            trampoline_entry: AtomicU64::new(0),
            trampoline_stack_top: AtomicU64::new(0),
            trampoline_arg0: AtomicU64::new(0),
            ticks: AtomicU64::new(0),
            sched_policy: SyncUnsafeCell::new(Self::default_sched_policy(priority)),
            vruntime: AtomicU64::new(0),
        }))
    }

    /// Reset all signal handlers to SIG_DFL (default).
    ///
    /// Called during execve to reset signal handlers as per POSIX:
    /// handlers set to catch signals are reset to SIG_DFL, but SIG_IGN
    /// remains ignored (implementation simplification: we reset all).
    pub fn reset_signals(&self) {
        // SAFETY: We have a valid reference to the task.
        unsafe {
            let actions = &mut *self.signal_actions.get();
            for action in actions.iter_mut() {
                *action = super::signal::SigAction::Default;
            }
        }
    }

    /// Returns true if this is a kernel task (shares the kernel address space).
    pub fn is_kernel(&self) -> bool {
        // SAFETY: address_space is immutable for the lifetime of the Arc?
        // Actually we just updated it to SyncUnsafeCell.
        unsafe { (*self.address_space.get()).is_kernel() }
    }

    /// Allocate POSIX identifiers for a new process leader.
    pub fn allocate_process_ids() -> (Pid, Tid, Pid) {
        let pid = next_pid();
        let tid = next_tid();
        (pid, tid, pid)
    }
}

/// Low-level context switch: save callee-saved registers on current stack,
/// swap RSP, restore callee-saved registers from new stack, and `ret`.
///
/// Arguments (x86-64 SysV ABI):
/// - rdi = pointer to old task's `saved_rsp` field
/// - rsi = pointer to new task's `saved_rsp` field
///
/// The caller (scheduler) has already handled TSS.rsp0 and CR3 switching.
#[unsafe(naked)]
pub(super) unsafe extern "C" fn switch_context(_old_rsp_ptr: *mut u64, _new_rsp_ptr: *const u64) {
    core::arch::naked_asm!(
        // Save callee-saved registers on current stack
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        // Save current RSP into old context
        "mov [rdi], rsp",
        // Load new RSP from new context
        "mov rsp, [rsi]",
        // Restore callee-saved registers from new stack
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        // Return to wherever the new task left off
        // (or to task_entry_trampoline for new tasks)
        "ret",
    );
}

/// Restore context for the very first task (no old context to save).
///
/// Argument (x86-64 SysV ABI):
/// - rdi = pointer to the first task's `saved_rsp` field
#[unsafe(naked)]
pub(super) unsafe extern "C" fn restore_first_task(_rsp_ptr: *const u64) {
    core::arch::naked_asm!(
        // Load RSP from context
        "mov rsp, [rdi]",
        // Restore callee-saved registers
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        // Jump to task_entry_trampoline -> real entry point
        "ret",
    );
}
