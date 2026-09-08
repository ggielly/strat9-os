//! Scheduler implementation
//!
//! Implements a per-CPU, multi-class, SMP scheduler for Strat9-OS with support
//! for cooperative and preemptive multitasking.
//!
//! ## Scheduler locking contract — mandatory total order
//!
//! ```text
//!   GLOBAL_SCHED_STATE                        (rank 1)
//!     -> SCHED_IDENTITY write                 (rank 2)
//!       -> BLOCKED_TASKS                      (rank 3)
//!         -> LOCAL_SCHEDULERS[cpu]            (rank 4)
//!           -> Task/Process internal lock     (rank 5)
//! ```
//!
//! `SCHED_IDENTITY` read is observational only:
//! - do not acquire any scheduler lock while holding it;
//! - copy the result, release it, then begin a mutating operation.
//!
//! ### Forbidden
//! - Acquiring GLOBAL, IDENTITY, BLOCKED, or another LOCAL while holding LOCAL.
//! - Holding two LOCAL locks simultaneously.
//! - Allocating, logging, VFS access, IPI sends, or context switching while
//!   any scheduler spinlock is held.
//! - Any transition from Blocked directly to Running (must go through Runnable).
//!
//! ### Cross-CPU operations
//! Use a two-phase protocol: detach under the source local lock, release it,
//! then attach under the destination local lock.
//!
//! ### Task ownership invariant
//! A non-idle task is in exactly one scheduling ownership state:
//! New, Runnable(cpu), Running(cpu), Blocked, Zombie, or Reaped.
//!
//! ## Canonical state machine
//!
//! ```text
//!   New -> Runnable(cpu)
//!   Runnable(cpu) -> Running(cpu)     [selection / preempt]
//!   Running(cpu) -> Runnable(cpu)     [tick / yield / preempt]
//!   Running(cpu) -> Blocked           [block_current]
//!   Blocked -> Runnable(cpu)          [wake_task]
//!   Running/Runnable/Blocked -> Zombie [exit / kill]
//!   Zombie -> Reaped                  [waitpid / reap]
//! ```
//!
//! Each transition has a single owner (the function performing it) and a
//! defined transaction: which locks are taken, which containers lose the task,
//! which containers receive it, and when `taskcpu` becomes visible.
//!
//! ## Metrics
//! All counters (FORCE_RESCHED_HINT, RESCHED_IPI_PENDING, ticks, etc.) are
//! lock-free atomics and must never be used to drive state transitions.

use super::task::{Pid, Task, TaskId, TaskPriority, TaskState, Tid};
use crate::{
    arch::{apic, percpu, restore_flags, save_flags_and_cli, timer, timer::NS_PER_TICK},
    sync::SpinLock,
};
use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::RwLock as SpinRwLock;

// ---------------------------------------------------------------------------
// Scheduler state machine
// ---------------------------------------------------------------------------

/// Formal scheduling state of a task, encoding ownership unambiguously.
///
/// Each state identifies the *exclusive owner* of the task:
///
/// | State             | Owner                | Present in                  |
/// |-------------------|----------------------|-----------------------------|
/// | New               | creator / global     | alltasks only, no queue     |
/// | Runnable { cpu }  | LOCAL_SCHEDULERS[cpu]| exactly one class queue     |
/// | Running { cpu }   | LOCAL_SCHEDULERS[cpu]| exactly currenttask on cpu  |
/// | Blocked           | BLOCKED_TASKS        | exactly BLOCKED_TASKS       |
/// | Zombie            | GLOBAL_SCHED_STATE   | zombies + alltasks          |
/// | Reaped            | nobody               | removed from all structures |
///
/// `alltasks` may retain a reference for all states except Reaped, but must
/// **never** be used to determine schedulability.  The source of truth is the
/// `SchedState` and its owning container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedState {
    /// Task constructed but not yet visible to the scheduler.
    New,
    /// Enqueued on `cpu`'s local run queue, awaiting selection.
    Runnable { cpu: usize },
    /// Currently executing on `cpu`.
    Running { cpu: usize },
    /// Waiting for an event; entry must exist in `BLOCKED_TASKS`.
    Blocked,
    /// Exited; waiting to be reaped by parent's `waitpid`.
    Zombie,
    /// Fully removed from all scheduler and identity structures.
    Reaped,
}

impl SchedState {
    /// Returns `true` if the task is in a scheduling-eligible state.
    #[inline]
    pub fn is_runnable_like(self) -> bool {
        matches!(self, SchedState::Runnable { .. } | SchedState::Running { .. })
    }
}

// ---------------------------------------------------------------------------
// Lockdep debug instrumentation
// ---------------------------------------------------------------------------

/// Lock ranks matching the total order documented in the module header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum LockRank {
    /// GLOBAL_SCHED_STATE — rank 1.
    Global = 1,
    /// SCHED_IDENTITY write — rank 2.
    IdentityW = 2,
    /// SCHED_IDENTITY read — rank 2R (must not chain to scheduler locks).
    IdentityR = 3,
    /// BLOCKED_TASKS — rank 3.
    Blocked = 4,
    /// LOCAL_SCHEDULERS[cpu] — rank 4.
    Local = 5,
    /// Task/Process internal — rank 5.
    TaskInternal = 6,
}

/// Per-CPU lockdep state, active only under `cfg(debug_assertions)`.
#[cfg(debug_assertions)]
#[allow(dead_code)]
pub(crate) struct LockdepState {
    depth: usize,
    held: [HeldLock; 6],
}

#[cfg(debug_assertions)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct HeldLock {
    rank: LockRank,
    /// Optional CPU index for LOCAL locks.
    cpu: Option<usize>,
    /// Caller return address (for diagnostics).
    caller: usize,
}

#[cfg(debug_assertions)]
impl LockdepState {
    pub(crate) const fn new() -> Self {
        Self {
            depth: 0,
            held: [
                HeldLock { rank: LockRank::Global, cpu: None, caller: 0 };
                6
            ],
        }
    }

    /// Record a lock acquisition.  Panics in debug if ordering is violated.
    pub(crate) fn acquire(&mut self, rank: LockRank, cpu: Option<usize>, caller: usize) {
        if self.depth > 0 {
            let top = self.held[self.depth - 1];
            // SCHED_IDENTITY read (rank 3) must not chain to any scheduler lock.
            if top.rank == LockRank::IdentityR {
                panic!(
                    "lockdep: SCHED_IDENTITY read held at depth {}, cannot acquire {:?} \
                     (read path must not chain to scheduler locks)",
                    self.depth - 1, rank
                );
            }
            // LOCAL must never be held while acquiring another LOCAL.
            if rank == LockRank::Local && cpu.is_some() {
                for i in 0..self.depth {
                    if self.held[i].rank == LockRank::Local {
                        panic!(
                            "lockdep: two LOCAL locks simultaneously (held {:?} at depth {}, \
                             acquiring LOCAL[{}] at depth {})",
                            self.held[i], i, cpu.unwrap(), self.depth
                        );
                    }
                }
            }
            // General rank check: new rank must be strictly greater than current top.
            if (rank as u8) <= (top.rank as u8) {
                panic!(
                    "lockdep: lock order violation at depth {}: held {:?}, acquiring {:?}",
                    self.depth - 1, top, rank
                );
            }
        }
        if self.depth < self.held.len() {
            self.held[self.depth] = HeldLock { rank, cpu, caller };
        }
        self.depth += 1;
    }

    /// Record a lock release.  Asserts LIFO order.
    pub(crate) fn release(&mut self, rank: LockRank) {
        if self.depth == 0 {
            panic!("lockdep: release underflow for {:?}", rank);
        }
        self.depth -= 1;
        let was = self.held[self.depth];
        if was.rank != rank {
            panic!(
                "lockdep: releasing {:?} but top of stack is {:?} (depth {})",
                rank, was, self.depth
            );
        }
    }

    /// Assert that no scheduler lock is held.
    pub(crate) fn assert_no_scheduler_locks(&self) {
        if self.depth > 0 {
            panic!(
                "lockdep: asserting no scheduler locks but depth={}, top={:?}",
                self.depth, self.held[self.depth - 1]
            );
        }
    }

    /// Assert that a specific rank is currently held.
    pub(crate) fn assert_held(&self, rank: LockRank) {
        for i in 0..self.depth {
            if self.held[i].rank == rank {
                return;
            }
        }
        panic!("lockdep: expected {:?} to be held, but depth={}", rank, self.depth);
    }

    /// Return the current depth.
    pub(crate) fn current_depth(&self) -> usize {
        self.depth
    }
}

/// Per-CPU lockdep state.  Each CPU tracks its own stack of held scheduler locks.
/// SAFETY: accessed only from the owning CPU with IRQs disabled (no concurrent access).
#[cfg(debug_assertions)]
static mut LOCKDEP: [LockdepState; crate::arch::percpu::MAX_CPUS] =
    [const { LockdepState::new() }; crate::arch::percpu::MAX_CPUS];

/// Record a lock acquisition in the per-CPU lockdep state.
#[cfg(debug_assertions)]
#[inline]
#[track_caller]
pub(crate) fn lockdep_acquire(rank: LockRank, cpu: Option<usize>) {
    let caller = core::panic::Location::caller();
    let addr = caller as *const core::panic::Location<'static> as usize;
    unsafe { LOCKDEP[current_cpu_index()].acquire(rank, cpu, addr) };
}

/// Record a lock release in the per-CPU lockdep state.
#[cfg(debug_assertions)]
#[inline]
pub(crate) fn lockdep_release(rank: LockRank) {
    unsafe { LOCKDEP[current_cpu_index()].release(rank) };
}

/// Assert that no scheduler locks are held on this CPU.
#[cfg(debug_assertions)]
#[inline]
pub(crate) fn lockdep_assert_no_locks() {
    unsafe { LOCKDEP[current_cpu_index()].assert_no_scheduler_locks() };
}

/// Assert that a specific rank is currently held on this CPU.
#[cfg(debug_assertions)]
#[inline]
pub(crate) fn lockdep_assert_held(rank: LockRank) {
    unsafe { LOCKDEP[current_cpu_index()].assert_held(rank) };
}

// No-op stubs for release builds
#[cfg(not(debug_assertions))]
#[inline]
pub(crate) fn lockdep_acquire(_rank: LockRank, _cpu: Option<usize>) {}
#[cfg(not(debug_assertions))]
#[inline]
pub(crate) fn lockdep_release(_rank: LockRank) {}
#[cfg(not(debug_assertions))]
#[inline]
pub(crate) fn lockdep_assert_no_locks() {}
#[cfg(not(debug_assertions))]
#[inline]
pub(crate) fn lockdep_assert_held(_rank: LockRank) {}

/// Per-CPU scheduler tick counters used for CPU usage estimation.
///
/// - `CPU_TOTAL_TICKS[cpu]`: all timer ticks observed on `cpu`.
/// - `CPU_IDLE_TICKS[cpu]`: ticks where the idle task was running on `cpu`.
///
/// CPU usage over a time window:
/// `usage = 1 - (delta_idle / delta_total)`.
static CPU_TOTAL_TICKS: [AtomicU64; crate::arch::percpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::arch::percpu::MAX_CPUS];
static CPU_IDLE_TICKS: [AtomicU64; crate::arch::percpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::arch::percpu::MAX_CPUS];
static CPU_RT_RUNTIME_TICKS: [AtomicU64; crate::arch::percpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::arch::percpu::MAX_CPUS];
static CPU_FAIR_RUNTIME_TICKS: [AtomicU64; crate::arch::percpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::arch::percpu::MAX_CPUS];
static CPU_SWITCH_COUNT: [AtomicU64; crate::arch::percpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::arch::percpu::MAX_CPUS];
static CPU_PREEMPT_COUNT: [AtomicU64; crate::arch::percpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::arch::percpu::MAX_CPUS];
static CPU_STEAL_IN_COUNT: [AtomicU64; crate::arch::percpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::arch::percpu::MAX_CPUS];
static CPU_STEAL_OUT_COUNT: [AtomicU64; crate::arch::percpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::arch::percpu::MAX_CPUS];
static CPU_TRY_LOCK_FAIL_COUNT: [AtomicU64; crate::arch::percpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::arch::percpu::MAX_CPUS];
static RESCHED_IPI_PENDING: [AtomicBool; crate::arch::percpu::MAX_CPUS] =
    [const { AtomicBool::new(false) }; crate::arch::percpu::MAX_CPUS];
static IPI_SEND_TRACE_BUDGET: AtomicU64 = AtomicU64::new(64);
/// Lock-free per-CPU hint: request a local preemption as soon as maybe_preempt
/// can observe scheduler state. Written from IRQ paths without touching
/// `GLOBAL_SCHED_STATE`, consumed under scheduler lock in `maybe_preempt`.
static FORCE_RESCHED_HINT: [AtomicBool; crate::arch::percpu::MAX_CPUS] =
    [const { AtomicBool::new(false) }; crate::arch::percpu::MAX_CPUS];
static LAST_STEAL_TICK: [AtomicU64; crate::arch::percpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::arch::percpu::MAX_CPUS];
/// One-shot flag per CPU: set to true after the first preemption is logged.
/// Prevents flooding the serial port with a preempt trace on every tick.
pub(crate) static FIRST_PREEMPT_LOGGED: [AtomicBool; crate::arch::percpu::MAX_CPUS] =
    [const { AtomicBool::new(false) }; crate::arch::percpu::MAX_CPUS];

const STEAL_IMBALANCE_MIN: usize = 2;
const STEAL_COOLDOWN_TICKS: u64 = 2;

/// Performs the active cpu count operation.
#[inline]
pub(crate) fn active_cpu_count() -> usize {
    crate::arch::smp::cpu_count()
        .max(1)
        .min(crate::arch::percpu::MAX_CPUS)
}

/// Performs the cpu is valid operation.
#[inline]
fn cpu_is_valid(cpu: usize) -> bool {
    cpu < crate::arch::percpu::MAX_CPUS
}

#[derive(Clone, Copy)]
pub struct CpuUsageSnapshot {
    pub cpu_count: usize,
    pub total_ticks: [u64; crate::arch::percpu::MAX_CPUS],
    pub idle_ticks: [u64; crate::arch::percpu::MAX_CPUS],
}

#[derive(Clone, Copy)]
pub struct SchedulerMetricsSnapshot {
    pub cpu_count: usize,
    pub rt_runtime_ticks: [u64; crate::arch::percpu::MAX_CPUS],
    pub fair_runtime_ticks: [u64; crate::arch::percpu::MAX_CPUS],
    pub idle_runtime_ticks: [u64; crate::arch::percpu::MAX_CPUS],
    pub switch_count: [u64; crate::arch::percpu::MAX_CPUS],
    pub preempt_count: [u64; crate::arch::percpu::MAX_CPUS],
    pub steal_in_count: [u64; crate::arch::percpu::MAX_CPUS],
    pub steal_out_count: [u64; crate::arch::percpu::MAX_CPUS],
    pub try_lock_fail_count: [u64; crate::arch::percpu::MAX_CPUS],
}

#[derive(Clone, Copy)]
pub struct SchedulerStateSnapshot {
    pub initialized: bool,
    pub boot_phase: u8,
    pub cpu_count: usize,
    pub pick_order: [crate::process::sched::SchedClassId; 3],
    pub steal_order: [crate::process::sched::SchedClassId; 2],
    pub blocked_tasks: usize,
    pub current_task: [u64; crate::arch::percpu::MAX_CPUS],
    pub rq_rt: [usize; crate::arch::percpu::MAX_CPUS],
    pub rq_fair: [usize; crate::arch::percpu::MAX_CPUS],
    pub rq_idle: [usize; crate::arch::percpu::MAX_CPUS],
    pub need_resched: [bool; crate::arch::percpu::MAX_CPUS],
}

/// Performs the cpu usage snapshot operation.
pub fn cpu_usage_snapshot() -> CpuUsageSnapshot {
    let cpu_count = active_cpu_count();
    let mut total_ticks = [0u64; crate::arch::percpu::MAX_CPUS];
    let mut idle_ticks = [0u64; crate::arch::percpu::MAX_CPUS];
    for i in 0..cpu_count {
        total_ticks[i] = CPU_TOTAL_TICKS[i].load(Ordering::Relaxed);
        idle_ticks[i] = CPU_IDLE_TICKS[i].load(Ordering::Relaxed);
    }
    CpuUsageSnapshot {
        cpu_count,
        total_ticks,
        idle_ticks,
    }
}

/// Performs the scheduler metrics snapshot operation.
pub fn scheduler_metrics_snapshot() -> SchedulerMetricsSnapshot {
    let cpu_count = active_cpu_count();
    let mut rt_runtime_ticks = [0u64; crate::arch::percpu::MAX_CPUS];
    let mut fair_runtime_ticks = [0u64; crate::arch::percpu::MAX_CPUS];
    let mut idle_runtime_ticks = [0u64; crate::arch::percpu::MAX_CPUS];
    let mut switch_count = [0u64; crate::arch::percpu::MAX_CPUS];
    let mut preempt_count = [0u64; crate::arch::percpu::MAX_CPUS];
    let mut steal_in_count = [0u64; crate::arch::percpu::MAX_CPUS];
    let mut steal_out_count = [0u64; crate::arch::percpu::MAX_CPUS];
    let mut try_lock_fail_count = [0u64; crate::arch::percpu::MAX_CPUS];
    for i in 0..cpu_count {
        rt_runtime_ticks[i] = CPU_RT_RUNTIME_TICKS[i].load(Ordering::Relaxed);
        fair_runtime_ticks[i] = CPU_FAIR_RUNTIME_TICKS[i].load(Ordering::Relaxed);
        idle_runtime_ticks[i] = CPU_IDLE_TICKS[i].load(Ordering::Relaxed);
        switch_count[i] = CPU_SWITCH_COUNT[i].load(Ordering::Relaxed);
        preempt_count[i] = CPU_PREEMPT_COUNT[i].load(Ordering::Relaxed);
        steal_in_count[i] = CPU_STEAL_IN_COUNT[i].load(Ordering::Relaxed);
        steal_out_count[i] = CPU_STEAL_OUT_COUNT[i].load(Ordering::Relaxed);
        try_lock_fail_count[i] = CPU_TRY_LOCK_FAIL_COUNT[i].load(Ordering::Relaxed);
    }
    SchedulerMetricsSnapshot {
        cpu_count,
        rt_runtime_ticks,
        fair_runtime_ticks,
        idle_runtime_ticks,
        switch_count,
        preempt_count,
        steal_in_count,
        steal_out_count,
        try_lock_fail_count,
    }
}

/// Performs the reset scheduler metrics operation.
pub fn reset_scheduler_metrics() {
    let cpu_count = active_cpu_count();
    for i in 0..cpu_count {
        CPU_RT_RUNTIME_TICKS[i].store(0, Ordering::Relaxed);
        CPU_FAIR_RUNTIME_TICKS[i].store(0, Ordering::Relaxed);
        CPU_IDLE_TICKS[i].store(0, Ordering::Relaxed);
        CPU_SWITCH_COUNT[i].store(0, Ordering::Relaxed);
        CPU_PREEMPT_COUNT[i].store(0, Ordering::Relaxed);
        CPU_STEAL_IN_COUNT[i].store(0, Ordering::Relaxed);
        CPU_STEAL_OUT_COUNT[i].store(0, Ordering::Relaxed);
        CPU_TRY_LOCK_FAIL_COUNT[i].store(0, Ordering::Relaxed);
    }
}

/// Performs the note try lock fail on cpu operation.
#[inline]
pub(crate) fn note_try_lock_fail_on_cpu(cpu: usize) {
    if cpu_is_valid(cpu) {
        CPU_TRY_LOCK_FAIL_COUNT[cpu].fetch_add(1, Ordering::Relaxed);
    }
}

/// Performs the note try lock fail operation.
#[inline]
pub fn note_try_lock_fail() {
    note_try_lock_fail_on_cpu(current_cpu_index());
}

// ========== Cross-CPU IPI helpers ===============================================

/// Send a reschedule IPI to `cpu_index`.
/// No-op if APIC is not initialized, or if `cpu_index` is the current CPU
/// (the caller already handles the local-CPU case via `yield_cpu`).
fn send_resched_ipi_to_cpu(cpu_index: usize) {
    if !cpu_is_valid(cpu_index) {
        return;
    }
    if !apic::is_initialized() {
        return;
    }
    let my_cpu = current_cpu_index();
    let should_trace = IPI_SEND_TRACE_BUDGET
        .try_update(Ordering::AcqRel, Ordering::Relaxed, |budget| {
            budget.checked_sub(1)
        })
        .is_ok();
    if let Some(target_apic) = percpu::apic_id_by_cpu_index(cpu_index) {
        if let Some(my_apic) = percpu::apic_id_by_cpu_index(my_cpu) {
            if target_apic != my_apic {
                if RESCHED_IPI_PENDING[cpu_index].swap(true, Ordering::AcqRel) {
                    if should_trace {
                        crate::e9_println!(
                            "[ipi-send-skip] from_cpu={} to_cpu={} to_apic={:#x} pending=1",
                            my_cpu,
                            cpu_index,
                            target_apic
                        );
                    }
                    return;
                }
                if should_trace {
                    crate::e9_println!(
                        "[ipi-send] from_cpu={} from_apic={:#x} to_cpu={} to_apic={:#x}",
                        my_cpu,
                        my_apic,
                        cpu_index,
                        target_apic
                    );
                }
                apic::send_resched_ipi(target_apic);
            }
        }
    }
}

/// Request a local force-reschedule hint for `cpu`.
#[inline]
pub(crate) fn request_force_resched_hint(cpu: usize) {
    if cpu_is_valid(cpu) {
        FORCE_RESCHED_HINT[cpu].store(true, Ordering::Release);
    }
}

/// Consume and clear the local force-reschedule hint for `cpu`.
#[inline]
pub(crate) fn take_force_resched_hint(cpu: usize) -> bool {
    if cpu_is_valid(cpu) {
        FORCE_RESCHED_HINT[cpu].swap(false, Ordering::AcqRel)
    } else {
        false
    }
}

/// Global scheduler state — rank 1 (root) in the total lock order.
///
/// This is the root lock.  It may precede all other scheduler locks but must
/// **never** be acquired from a path that already holds a LOCAL, BLOCKED, or
/// IDENTITY lock.
///
/// Protects: `all_tasks`, `task_cpu`, `zombies`, `wake_deadlines`, and the
/// global `class_table`.  Per-CPU run queues and current-task tracking live
/// in `LOCAL_SCHEDULERS` (rank 4).  Blocked tasks are in `BLOCKED_TASKS`
/// (rank 3).  Identity maps are in `SCHED_IDENTITY` (rank 2).
pub(crate) static GLOBAL_SCHED_STATE: SpinLock<Option<GlobalSchedState>> = SpinLock::new(None);

/// Returns the scheduler lock address for deadlock tracing.
pub fn debug_scheduler_lock_addr() -> usize {
    &GLOBAL_SCHED_STATE as *const _ as usize
}

/// Global tick counter (safe to increment from interrupt context)
static TICK_COUNT: AtomicU64 = AtomicU64::new(0);
/// Verbose scheduler trace switch.
static SCHED_VERBOSE: AtomicBool = AtomicBool::new(false);

/// Performs the sched trace operation.
#[inline]
fn sched_trace(args: core::fmt::Arguments<'_>) {
    if SCHED_VERBOSE.load(Ordering::Relaxed) {
        log::debug!("[sched] {}", args);
    }
}

/// Information needed to perform a context switch after releasing the lock.
///
/// # Safety invariants
///
/// `SwitchTarget` contains raw pointers into `Arc<Task>` objects.  All five
/// invariants below must hold at the moment `do_switch_context` / `switch_context`
/// reads them.  They are established by `yield_cpu_local` under the LOCAL lock
/// and consumed before any other CPU can observe the pointed-to memory.
///
/// 1. **`old_rsp_ptr`** points to `(*source.context.get()).saved_rsp`.
///    The `source` Arc<Task> is kept alive by `cpu.current_task` or
///    `cpu.task_to_requeue` for the duration of the switch; no migration,
///    reap, or exit can invalidate it while the lock is held.
///
/// 2. **`new_rsp_ptr`** points to `(*target.context.get()).saved_rsp`.
///    Same lifetime guarantee as above: `target` is in `cpu.current_task`.
///
/// 3. **`old_fpu_ptr` / `new_fpu_ptr`** point into the FPU state areas of
///    the source / target tasks respectively.  These areas sit inside the
///    kernel stack and are valid as long as the owning `Arc<Task>` is alive.
///    FPU state is never modified concurrently: the switch context owns it
///    exclusively between the save and restore.
///
/// 4. **`old_xcr0` / `new_xcr0`** are the XCR0 masks of source and target,
///    read atomically from `task.xcr0_mask`.  They are only consumed by the
///    switch assembly which toggles XCR0 around xsave/xrstor.
///
/// 5. **Lifetime**: `SwitchTarget` must not outlive the LOCAL lock that
///    protected its construction.  It is consumed by `do_switch_context`
///    immediately after the lock is released, before any allocation, IPI,
///    or scheduler operation.
///
/// # Debug checks
///
/// Under `cfg(debug_assertions)`, `prepare_switch_target` validates that
/// `old_rsp` / `new_rsp` fall within their respective kernel stacks before
/// returning this struct.
pub(super) struct SwitchTarget {
    pub(super) old_rsp_ptr: *mut u64,
    pub(super) new_rsp_ptr: *const u64,
    pub(super) old_fpu_ptr: *mut u8,
    pub(super) new_fpu_ptr: *const u8,
    pub(super) old_xcr0: u64,
    pub(super) new_xcr0: u64,
}

// SAFETY: SwitchTarget is only constructed under LOCAL lock on the owning CPU
// and consumed by do_switch_context before any other CPU can observe the
// pointed-to memory.  The Arc<Task> objects are kept alive by current_task /
// task_to_requeue for the full duration.  No concurrent modification of the
// pointed-to context or FPU state occurs between construction and consumption.
unsafe impl Send for SwitchTarget {}

/// Result of a non-blocking wait on child exit.
pub enum WaitChildResult {
    Reaped {
        child: TaskId,
        pid: Pid,
        status: i32,
    },
    NoChildren,
    StillRunning,
}

/// Performs the current cpu index operation.
fn current_cpu_index() -> usize {
    crate::arch::percpu::current_cpu_index()
}

struct PerCpuClassRqSet {
    real_time: crate::process::sched::real_time::RealTimeClassRq,
    fair: crate::process::sched::fair::FairClassRq,
    idle: crate::process::sched::idle::IdleClassRq,
}

impl PerCpuClassRqSet {
    /// Creates a new instance.
    fn new() -> Self {
        Self {
            real_time: crate::process::sched::real_time::RealTimeClassRq::new(),
            fair: crate::process::sched::fair::FairClassRq::new(),
            idle: crate::process::sched::idle::IdleClassRq::new(),
        }
    }

    /// Performs the enqueue operation.
    fn enqueue(&mut self, class: crate::process::sched::SchedClassId, task: Arc<Task>) {
        use crate::process::sched::SchedClassRq;
        match class {
            crate::process::sched::SchedClassId::Fair => self.fair.enqueue(task),
            crate::process::sched::SchedClassId::RealTime => self.real_time.enqueue(task),
            crate::process::sched::SchedClassId::Idle => self.idle.enqueue(task),
        }
    }

    /// Performs the len by class operation.
    fn len_by_class(&self, class: crate::process::sched::SchedClassId) -> usize {
        use crate::process::sched::SchedClassRq;
        match class {
            crate::process::sched::SchedClassId::Fair => self.fair.len(),
            crate::process::sched::SchedClassId::RealTime => self.real_time.len(),
            crate::process::sched::SchedClassId::Idle => self.idle.len(),
        }
    }

    /// Performs the runnable len operation.
    fn runnable_len(&self) -> usize {
        self.len_by_class(crate::process::sched::SchedClassId::RealTime)
            + self.len_by_class(crate::process::sched::SchedClassId::Fair)
    }

    /// Performs the pick next by class operation.
    fn pick_next_by_class(
        &mut self,
        class: crate::process::sched::SchedClassId,
    ) -> Option<Arc<Task>> {
        use crate::process::sched::SchedClassRq;
        match class {
            crate::process::sched::SchedClassId::Fair => self.fair.pick_next(),
            crate::process::sched::SchedClassId::RealTime => self.real_time.pick_next(),
            crate::process::sched::SchedClassId::Idle => self.idle.pick_next(),
        }
    }

    /// Performs the pick next operation.
    fn pick_next(&mut self, table: &crate::process::sched::SchedClassTable) -> Option<Arc<Task>> {
        for class in table.pick_order().iter().copied() {
            if let Some(task) = self.pick_next_by_class(class) {
                return Some(task);
            }
        }
        None
    }

    /// Updates current.
    fn update_current(
        &mut self,
        rt: &crate::process::sched::CurrentRuntime,
        task: &Task,
        is_yield: bool,
        table: &crate::process::sched::SchedClassTable,
    ) -> bool {
        use crate::process::sched::SchedClassRq;
        let should_preempt = match table.class_for_task(task) {
            crate::process::sched::SchedClassId::Fair => {
                self.fair.update_current(rt, task, is_yield)
            }
            crate::process::sched::SchedClassId::RealTime => {
                self.real_time.update_current(rt, task, is_yield)
            }
            crate::process::sched::SchedClassId::Idle => {
                self.idle.update_current(rt, task, is_yield)
            }
        };
        // Always preempt idle task if there are other tasks ready
        let any_ready = !self.real_time.is_empty() || !self.fair.is_empty();
        should_preempt
            || (table.class_for_task(task) == crate::process::sched::SchedClassId::Idle
                && any_ready)
    }

    /// Performs the remove operation.
    fn remove(&mut self, task_id: crate::process::TaskId) -> bool {
        use crate::process::sched::SchedClassRq;
        self.real_time.remove(task_id) || self.fair.remove(task_id) || self.idle.remove(task_id)
    }

    /// Called once per timer tick.  Increments wait-time counters for all
    /// queued tasks across all classes.  Used for Fair starvation detection.
    fn tick_update_wait(&mut self) {
        use crate::process::sched::SchedClassRq;
        self.fair.tick_update_wait();
    }

    /// Performs the steal candidate operation.
    fn steal_candidate(
        &mut self,
        table: &crate::process::sched::SchedClassTable,
    ) -> Option<Arc<Task>> {
        for class in table.steal_order().iter().copied() {
            if let Some(task) = self.pick_next_by_class(class) {
                return Some(task);
            }
        }
        None
    }
}

/// Per-CPU scheduler state
struct SchedulerCpu {
    /// Multi-class priority queues
    class_rqs: PerCpuClassRqSet,
    /// Currently running task
    current_task: Option<Arc<Task>>,
    /// Current runtime accounting
    current_runtime: crate::process::sched::CurrentRuntime,
    /// Idle task to run when no other tasks are ready
    idle_task: Arc<Task>,
    /// Task that was just preempted and needs to be re-queued
    task_to_requeue: Option<Arc<Task>>,
    /// Task that is dying or blocked, to drop outside the scheduler lock
    task_to_drop: Option<Arc<Task>>,
    /// Flag indicating if the current task's time slice has expired
    need_resched: bool,
    /// Local copy of the class table for hot-path use without GLOBAL lock.
    /// Updated atomically when the global class table changes.
    class_table: crate::process::sched::SchedClassTable,
}

/// Per-CPU local scheduler locks — rank 4 in the total lock order.
///
/// Acquired after `GLOBAL_SCHED_STATE`, `SCHED_IDENTITY`, and `BLOCKED_TASKS`.
/// **Never** hold two LOCAL locks simultaneously.
/// Cross-CPU operations use a two-phase protocol: detach under source LOCAL,
/// release, then attach under destination LOCAL.
#[allow(dead_code)]
pub(crate) static LOCAL_SCHEDULERS: [SpinLock<Option<SchedulerCpu>>;
    crate::arch::percpu::MAX_CPUS] =
    [const { SpinLock::new(None) }; crate::arch::percpu::MAX_CPUS];

/// Blocked tasks registry — rank 3 in the total lock order.
///
/// `BLOCKED_TASKS` must be acquired **after** `GLOBAL_SCHED_STATE` and
/// `SCHED_IDENTITY` (write), and **before** `LOCAL_SCHEDULERS[cpu]`.
/// It is **never** acquired from a path that already holds a LOCAL lock.
///
/// A task appears here if and only if its `SchedState` is `Blocked`.
pub(crate) static BLOCKED_TASKS: SpinLock<BTreeMap<TaskId, Arc<Task>>> =
    SpinLock::new(BTreeMap::new());

/// Identity maps — rank 2 (write) / 2R (read) in the total lock order.
///
/// `SCHED_IDENTITY` write is acquired after `GLOBAL_SCHED_STATE` and before
/// `BLOCKED_TASKS` or `LOCAL_SCHEDULERS[cpu]`.
///
/// `SCHED_IDENTITY` read is **observational only**: copy the result, release,
/// then begin any mutating operation.  No scheduler lock may be acquired
/// while holding the read guard.
///
/// Upgraded to `RwLock` so that concurrent readers (`getpid`, `getpgid`,
/// `get_task_by_pid`) do not serialize.
pub(crate) static SCHED_IDENTITY: SpinRwLock<SchedIdentity> = SpinRwLock::new(SchedIdentity::new());

/// Identity maps for the scheduler: PID/TID routing, process groups,
/// session membership, and parent/child relationships.
///
/// Lives behind the `SCHED_IDENTITY` lock, separate from `GLOBAL_SCHED_STATE`
/// so that syscall lookups (`getpid`, `getpgid`, `setpgid`, `setsid`, etc.)
/// never contend with fork/exit or block/wake paths.
pub struct SchedIdentity {
    /// Map userspace PID -> internal TaskId (process leader in current model).
    pub pid_to_task: BTreeMap<Pid, TaskId>,
    /// Map userspace TID -> internal TaskId (fast thread lookup).
    pub tid_to_task: BTreeMap<Tid, TaskId>,
    /// Map PID -> process group id.
    pub pid_to_pgid: BTreeMap<Pid, Pid>,
    /// Map PID -> session id.
    pub pid_to_sid: BTreeMap<Pid, Pid>,
    /// Group membership index: pgid -> task ids.
    pub pgid_members: BTreeMap<Pid, alloc::vec::Vec<TaskId>>,
    /// Session membership index: sid -> task ids.
    pub sid_members: BTreeMap<Pid, alloc::vec::Vec<TaskId>>,
    /// Parent relationship: child -> parent
    pub parent_of: BTreeMap<TaskId, TaskId>,
    /// Children list: parent -> children
    pub children_of: BTreeMap<TaskId, alloc::vec::Vec<TaskId>>,
}

impl SchedIdentity {
    /// Creates a new empty identity registry.
    pub const fn new() -> Self {
        Self {
            pid_to_task: BTreeMap::new(),
            tid_to_task: BTreeMap::new(),
            pid_to_pgid: BTreeMap::new(),
            pid_to_sid: BTreeMap::new(),
            pgid_members: BTreeMap::new(),
            sid_members: BTreeMap::new(),
            parent_of: BTreeMap::new(),
            children_of: BTreeMap::new(),
        }
    }
}

/// Global task registry : cold path: fork, exit, all_tasks scan.
///
/// Lock order: acquire GLOBAL_SCHED_STATE before LOCAL when both are needed.
/// Per-CPU runqueues and current-task tracking live in `LOCAL_SCHEDULERS`.
/// Blocked tasks are tracked in `BLOCKED_TASKS` (separate lock).
/// Identity maps (PID/TID, pgid, sid, parent/child) are in `SCHED_IDENTITY` (separate lock).
/// This struct holds only data that is accessed by cold paths (fork, exit,
/// all_tasks scan, zombie management, wake deadlines) and is protected by the
/// `GLOBAL_SCHED_STATE` lock.
pub struct GlobalSchedState {
    /// All tasks in the system (for lookup by TaskId)
    pub(crate) all_tasks: BTreeMap<TaskId, Arc<Task>>,
    /// Map TaskId -> CPU index (for wake/resume routing)
    task_cpu: BTreeMap<TaskId, usize>,
    /// Deadline -> task ids map for sleeping tasks (ordered wakeups).
    #[allow(dead_code)]
    wake_deadlines: BTreeMap<u64, alloc::vec::Vec<TaskId>>,
    /// Task -> deadline reverse index.
    #[allow(dead_code)]
    wake_deadline_of: BTreeMap<TaskId, u64>,
    /// Zombie exit statuses: child -> (exit_code, pid)
    zombies: BTreeMap<TaskId, (i32, Pid)>,
    /// Scheduler class table (pick order, steal order, class metadata)
    class_table: crate::process::sched::SchedClassTable,
}

/// Performs the validate task context operation.
fn validate_task_context(task: &Arc<Task>) -> Result<(), &'static str> {
    let saved_rsp = unsafe { (*task.context.get()).saved_rsp };
    let stack_base = task.kernel_stack.virt_base.as_u64();
    let stack_top = stack_base.saturating_add(task.kernel_stack.size as u64);

    if saved_rsp < stack_base || saved_rsp.saturating_add(56) > stack_top {
        return Err("saved_rsp outside kernel stack bounds");
    }

    // ABI alignment: saved_rsp must be 8-byte aligned (x86-64 ABI requirement).
    if saved_rsp & 7 != 0 {
        return Err("saved_rsp not 8-byte aligned");
    }

    // Return IP is at [saved_rsp + 48] in our switch frame layout.
    let ret_ip = unsafe { core::ptr::read_unaligned((saved_rsp + 48) as *const u64) };
    if ret_ip == 0 {
        return Err("null return IP in switch frame");
    }

    // Return IP must be a canonical userspace or kernel address (not in the
    // non-canonical hole 0x0000_8000_0000_0000..0xFFFF_7FFF_FFFF_FFFF).
    let canonical = ret_ip < 0x0000_8000_0000_0000 || ret_ip >= 0xFFFF_8000_0000_0000;
    if !canonical {
        return Err("non-canonical return IP");
    }

    // FPU area must be within the kernel stack (it sits below saved_rsp).
    let fpu_size = core::mem::size_of::<crate::process::task::ExtendedState>() as u64;
    let fpu_ptr = task.fpu_state.get() as u64;
    if fpu_ptr != 0 && (fpu_ptr < stack_base || fpu_ptr.saturating_add(fpu_size) > stack_top) {
        return Err("FPU state outside kernel stack bounds");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Debug invariant validator
// ---------------------------------------------------------------------------

/// Validate scheduler-wide invariants in debug builds.
///
/// Uses `try_lock` everywhere so it can be called from `finish_switch` without
/// blocking.  Silently skips if any lock is contended.
///
/// Panics with a diagnostic message on the first invariant violation.
#[cfg(debug_assertions)]
#[allow(dead_code)]
pub(crate) fn validate_scheduler_invariants() {
    let n = active_cpu_count();
    let mut seen_current: alloc::collections::BTreeSet<TaskId> =
        alloc::collections::BTreeSet::new();

    // 1. Each CPU has at most one current_task; no task is current on two CPUs.
    for cpu_idx in 0..n {
        let guard = match LOCAL_SCHEDULERS[cpu_idx].try_lock() {
            Some(g) => g,
            None => return, // Lock contended, skip validation.
        };
        if let Some(ref cpu) = *guard {
            if let Some(ref current) = cpu.current_task {
                let tid = current.id;
                if !Arc::ptr_eq(current, &cpu.idle_task) {
                    assert!(
                        seen_current.insert(tid),
                        "scheduler invariant: task {} is current on multiple CPUs (cpu={})",
                        tid.as_u64(), cpu_idx
                    );
                }
            }
        }
    }

    // 2. task_cpu consistency + zombie isolation.
    {
        let sched_guard = match GLOBAL_SCHED_STATE.try_lock() {
            Some(g) => g,
            None => return,
        };
        if let Some(ref sched) = *sched_guard {
            for (tid, &cpu_idx) in sched.task_cpu.iter() {
                let state = sched.all_tasks.get(tid).map(|t| t.get_state());
                match state {
                    Some(TaskState::Ready) | Some(TaskState::Running) => {
                        assert!(
                            cpu_idx < n,
                            "scheduler invariant: task_cpu[{}] = {} but cpu_count = {}",
                            tid.as_u64(), cpu_idx, n
                        );
                    }
                    _ => {}
                }
            }
            for (tid, _) in sched.zombies.iter() {
                assert!(
                    !seen_current.contains(tid),
                    "scheduler invariant: zombie task {} is current on a CPU",
                    tid.as_u64()
                );
            }
        }
    }
}

#[cfg(not(debug_assertions))]
#[inline]
pub(crate) fn validate_scheduler_invariants() {}

/// Check that `SCHED_IDENTITY` read is not held (observational-only contract).
#[cfg(debug_assertions)]
#[allow(dead_code)]
pub(crate) fn assert_no_identity_read_held() {
    lockdep_assert_no_locks();
}

mod core_impl;
pub mod perf_counters;
mod runtime_ops;
mod task_ops;
mod timer_ops;

pub use runtime_ops::*;
pub use task_ops::*;
pub use timer_ops::*;
