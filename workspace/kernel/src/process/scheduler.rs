//! Scheduler implementation
//!
//! Implements a per-CPU round-robin scheduler for Strat9-OS with support for
//! cooperative and preemptive multitasking.
//!
//! ## Preemption design
//!
//! The timer interrupt (100Hz) calls `maybe_preempt()` which picks the next
//! task and performs a context switch. Interrupts are disabled while the
//! scheduler lock is held to prevent deadlock on single-core systems:
//!
//! - `yield_task()`: CLI → lock → pick next → TSS/CR3 → unlock → switch_context → restore IF
//! - Timer handler: CPU already cleared IF → lock → pick next → TSS/CR3 → unlock → switch_context
//!
//! Each task has its own 16KB kernel stack. Callee-saved registers are
//! pushed/popped by `switch_context()`. `CpuContext` only stores `saved_rsp`.
//!
//! TODO(v3 scheduler):
//! - API stabilization before adding more features:
//!   - freeze scheduler command syntax.
//!   - add a small machine-friendly output format (key=value) for scripts/debug.
//! - observability v2:
//!   - per-class latency/wait histograms.
//!   - one structured dump format (instead of free-form text logs) for top/debug.
//! - targeted scheduler tests (high priority):
//!   - config validation/reject paths (class/policy map).
//!   - ready-task migration on class-table updates.
//!   - SMP steal/preempt non-regression.
//! - only then: CPU affinity (first truly useful advanced scheduler feature).
//!
//! Legacy backlog:
//! - class registry v2:
//!   - dynamic add/remove/reorder with validation and safe reject path.
//!   - policy->class mapping as runtime registry (not only static enum mapping).
//! - atomic class-table migration:
//!   - RCU/STW swap + migration of queued tasks across classes.
//!   - preserve per-task accounting (vruntime, rt budget, wake deadlines).
//! - balancing v2:
//!   - dedicated balancer module, per-class steal policy, CPU affinity masks.
//!   - NUMA-aware placement (future) and stronger anti-thrashing controls.
//! - SMP hardening:
//!   - explicit lock hierarchy doc + assertions.
//!   - improved resched IPI batching/coalescing policy tuning.
//! - observability v2:
//!   - latency/wait-time histograms per class + structured trace dump.
//!   - shell/top integration over stable snapshot API.
//! - tests:
//!   - deterministic migration/policy-remap/SMP-steal suites.
//!   - fairness/starvation long-run regression in test ISO.
//!
//! Optimization roadmap (stability-first, incremental):
//! 1) Lock contention reduction (highest ROI, low risk)
//!    - keep scheduler critical sections minimal: compute decisions under lock,
//!      execute expensive side effects (IPI, signal delivery, cleanup) after unlock.
//!    - split hot paths into tiny helpers with explicit "lock held / lock free" contract.
//!    - add/track contention counters in every try_lock fallback path.
//! 2) Wakeup path scalability (only after strong guards)
//!    - re-introduce deadline index behind a runtime feature flag (default OFF).
//!    - enforce single writer API for wake deadlines (no direct field stores in syscalls).
//!    - add strict invariants:
//!      - if task has deadline != 0, index contains task exactly once.
//!      - on wake/kill/exit/resume, deadline is removed from index and field cleared.
//!    - keep safe fallback scan path available and switchable at runtime.
//! 3) Scheduler observability for regressions
//!    - keep stable key=value output for scripts (`scheduler metrics kv`, `scheduler dump kv`).
//!    - expose blocked-task ids and per-cpu preempt causes to diagnose stalls quickly.
//!    - include boot-phase and lock-miss counters in all dump modes.
//! 4) Balancing/pick optimizations
//!    - tune steal hysteresis/cooldown with metrics, avoid ping-pong migration.
//!    - avoid counting idle task as runnable load for CPU selection.
//!    - add bounded per-tick work budgets to prevent long interrupt latency tails.
//! 5) Safety rails before each optimization lands
//!    - ship each optimization in one isolated patchset with rollback switch.
//!    - validate with targeted scenarios:
//!      - boot + shell responsiveness,
//!      - timeout-heavy workload (poll/futex/nanosleep),
//!      - SMP preempt/steal stress.
//!    - if any regression appears, disable feature first, debug second.

use super::task::{Pid, Task, TaskId, TaskPriority, TaskState, Tid};
use crate::{
    arch::x86_64::{apic, percpu, restore_flags, save_flags_and_cli, timer, timer::NS_PER_TICK},
    sync::SpinLock,
};
use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::RwLock as SpinRwLock;

/// Per-CPU scheduler tick counters used for CPU usage estimation.
///
/// - `CPU_TOTAL_TICKS[cpu]`: all timer ticks observed on `cpu`.
/// - `CPU_IDLE_TICKS[cpu]`: ticks where the idle task was running on `cpu`.
///
/// CPU usage over a time window:
/// `usage = 1 - (delta_idle / delta_total)`.
static CPU_TOTAL_TICKS: [AtomicU64; crate::arch::x86_64::percpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::arch::x86_64::percpu::MAX_CPUS];
static CPU_IDLE_TICKS: [AtomicU64; crate::arch::x86_64::percpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::arch::x86_64::percpu::MAX_CPUS];
static CPU_RT_RUNTIME_TICKS: [AtomicU64; crate::arch::x86_64::percpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::arch::x86_64::percpu::MAX_CPUS];
static CPU_FAIR_RUNTIME_TICKS: [AtomicU64; crate::arch::x86_64::percpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::arch::x86_64::percpu::MAX_CPUS];
static CPU_SWITCH_COUNT: [AtomicU64; crate::arch::x86_64::percpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::arch::x86_64::percpu::MAX_CPUS];
static CPU_PREEMPT_COUNT: [AtomicU64; crate::arch::x86_64::percpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::arch::x86_64::percpu::MAX_CPUS];
static CPU_STEAL_IN_COUNT: [AtomicU64; crate::arch::x86_64::percpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::arch::x86_64::percpu::MAX_CPUS];
static CPU_STEAL_OUT_COUNT: [AtomicU64; crate::arch::x86_64::percpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::arch::x86_64::percpu::MAX_CPUS];
static CPU_TRY_LOCK_FAIL_COUNT: [AtomicU64; crate::arch::x86_64::percpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::arch::x86_64::percpu::MAX_CPUS];
static RESCHED_IPI_PENDING: [AtomicBool; crate::arch::x86_64::percpu::MAX_CPUS] =
    [const { AtomicBool::new(false) }; crate::arch::x86_64::percpu::MAX_CPUS];
static IPI_SEND_TRACE_BUDGET: AtomicU64 = AtomicU64::new(64);
/// Lock-free per-CPU hint: request a local preemption as soon as maybe_preempt
/// can observe scheduler state. Written from IRQ paths without touching
/// `GLOBAL_SCHED_STATE`, consumed under scheduler lock in `maybe_preempt`.
static FORCE_RESCHED_HINT: [AtomicBool; crate::arch::x86_64::percpu::MAX_CPUS] =
    [const { AtomicBool::new(false) }; crate::arch::x86_64::percpu::MAX_CPUS];
static LAST_STEAL_TICK: [AtomicU64; crate::arch::x86_64::percpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::arch::x86_64::percpu::MAX_CPUS];
/// One-shot flag per CPU: set to true after the first preemption is logged.
/// Prevents flooding the serial port with a preempt trace on every tick.
pub(crate) static FIRST_PREEMPT_LOGGED: [AtomicBool; crate::arch::x86_64::percpu::MAX_CPUS] =
    [const { AtomicBool::new(false) }; crate::arch::x86_64::percpu::MAX_CPUS];

const STEAL_IMBALANCE_MIN: usize = 2;
const STEAL_COOLDOWN_TICKS: u64 = 2;

/// Performs the active cpu count operation.
#[inline]
fn active_cpu_count() -> usize {
    crate::arch::x86_64::smp::cpu_count()
        .max(1)
        .min(crate::arch::x86_64::percpu::MAX_CPUS)
}

/// Performs the cpu is valid operation.
#[inline]
fn cpu_is_valid(cpu: usize) -> bool {
    cpu < crate::arch::x86_64::percpu::MAX_CPUS
}

#[derive(Clone, Copy)]
pub struct CpuUsageSnapshot {
    pub cpu_count: usize,
    pub total_ticks: [u64; crate::arch::x86_64::percpu::MAX_CPUS],
    pub idle_ticks: [u64; crate::arch::x86_64::percpu::MAX_CPUS],
}

#[derive(Clone, Copy)]
pub struct SchedulerMetricsSnapshot {
    pub cpu_count: usize,
    pub rt_runtime_ticks: [u64; crate::arch::x86_64::percpu::MAX_CPUS],
    pub fair_runtime_ticks: [u64; crate::arch::x86_64::percpu::MAX_CPUS],
    pub idle_runtime_ticks: [u64; crate::arch::x86_64::percpu::MAX_CPUS],
    pub switch_count: [u64; crate::arch::x86_64::percpu::MAX_CPUS],
    pub preempt_count: [u64; crate::arch::x86_64::percpu::MAX_CPUS],
    pub steal_in_count: [u64; crate::arch::x86_64::percpu::MAX_CPUS],
    pub steal_out_count: [u64; crate::arch::x86_64::percpu::MAX_CPUS],
    pub try_lock_fail_count: [u64; crate::arch::x86_64::percpu::MAX_CPUS],
}

#[derive(Clone, Copy)]
pub struct SchedulerStateSnapshot {
    pub initialized: bool,
    pub boot_phase: u8,
    pub cpu_count: usize,
    pub pick_order: [crate::process::sched::SchedClassId; 3],
    pub steal_order: [crate::process::sched::SchedClassId; 2],
    pub blocked_tasks: usize,
    pub current_task: [u64; crate::arch::x86_64::percpu::MAX_CPUS],
    pub rq_rt: [usize; crate::arch::x86_64::percpu::MAX_CPUS],
    pub rq_fair: [usize; crate::arch::x86_64::percpu::MAX_CPUS],
    pub rq_idle: [usize; crate::arch::x86_64::percpu::MAX_CPUS],
    pub need_resched: [bool; crate::arch::x86_64::percpu::MAX_CPUS],
}

/// Performs the cpu usage snapshot operation.
pub fn cpu_usage_snapshot() -> CpuUsageSnapshot {
    let cpu_count = active_cpu_count();
    let mut total_ticks = [0u64; crate::arch::x86_64::percpu::MAX_CPUS];
    let mut idle_ticks = [0u64; crate::arch::x86_64::percpu::MAX_CPUS];
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
    let mut rt_runtime_ticks = [0u64; crate::arch::x86_64::percpu::MAX_CPUS];
    let mut fair_runtime_ticks = [0u64; crate::arch::x86_64::percpu::MAX_CPUS];
    let mut idle_runtime_ticks = [0u64; crate::arch::x86_64::percpu::MAX_CPUS];
    let mut switch_count = [0u64; crate::arch::x86_64::percpu::MAX_CPUS];
    let mut preempt_count = [0u64; crate::arch::x86_64::percpu::MAX_CPUS];
    let mut steal_in_count = [0u64; crate::arch::x86_64::percpu::MAX_CPUS];
    let mut steal_out_count = [0u64; crate::arch::x86_64::percpu::MAX_CPUS];
    let mut try_lock_fail_count = [0u64; crate::arch::x86_64::percpu::MAX_CPUS];
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

// ========== Cross-CPU IPI helpers ==========================================================================================================================================================================─

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
        .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |budget| {
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

/// Global scheduler state : cold path: fork, exit, wake, block.
///
/// Lock order: acquire `GLOBAL_SCHED_STATE` before `LOCAL_SCHEDULERS[n]`
/// when both are needed. Never hold a LOCAL lock and then block-acquire GLOBAL.
///
/// When both `GLOBAL_SCHED_STATE` and `SCHED_IDENTITY` are needed, always take
/// `GLOBAL_SCHED_STATE` first, then `SCHED_IDENTITY`. Paths that reversed this
/// order deadlocked with `kill_task` / `try_reap_child_locked` during shutdown.
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
pub(super) struct SwitchTarget {
    pub(super) old_rsp_ptr: *mut u64,
    pub(super) new_rsp_ptr: *const u64,
    pub(super) old_fpu_ptr: *mut u8,
    pub(super) new_fpu_ptr: *const u8,
    pub(super) old_xcr0: u64,
    pub(super) new_xcr0: u64,
}

// SAFETY: The pointers in SwitchTarget point into Arc<Task> objects
// that are kept alive by the scheduler. The scheduler lock ensures
// exclusive access when computing these pointers.
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
    crate::arch::x86_64::percpu::current_cpu_index()
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
        unsafe { core::arch::asm!("mov al, 'q'; out 0xe9, al", out("al") _) };
        match class {
            crate::process::sched::SchedClassId::Fair => {
                unsafe { core::arch::asm!("mov al, 'f'; out 0xe9, al", out("al") _) };
                self.fair.enqueue(task);
            }
            crate::process::sched::SchedClassId::RealTime => {
                unsafe { core::arch::asm!("mov al, 'r'; out 0xe9, al", out("al") _) };
                self.real_time.enqueue(task);
            }
            crate::process::sched::SchedClassId::Idle => {
                unsafe { core::arch::asm!("mov al, 'i'; out 0xe9, al", out("al") _) };
                self.idle.enqueue(task);
            }
        }
        unsafe { core::arch::asm!("mov al, 'Q'; out 0xe9, al", out("al") _) };
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

/// Per-CPU local scheduler locks : hot path: timer tick, preemption, yield.
///
/// Lock order: LOCAL before nothing; never hold two LOCAL locks simultaneously
/// (use `try_lock` when touching a sibling CPU).
#[allow(dead_code)]
pub(crate) static LOCAL_SCHEDULERS: [SpinLock<Option<SchedulerCpu>>;
    crate::arch::x86_64::percpu::MAX_CPUS] =
    [const { SpinLock::new(None) }; crate::arch::x86_64::percpu::MAX_CPUS];

/// Blocked tasks registry : hot path: block/wake.
///
/// This lock is **independent** of `GLOBAL_SCHED_STATE`. The block and wake
/// paths acquire only this lock + the target CPU's `LOCAL_SCHEDULERS[cpu]`
/// lock, avoiding contention with cold-path operations (fork, exit, kill).
///
/// Lock order: BLOCKED_TASKS before LOCAL (never the reverse).
pub(crate) static BLOCKED_TASKS: SpinLock<BTreeMap<TaskId, Arc<Task>>> =
    SpinLock::new(BTreeMap::new());

/// Identity maps : cold path: PID/TID lookups, process groups, sessions, parent/child.
///
/// Separate from `GLOBAL_SCHED_STATE` so that identity lookups (getpid, getpgid,
/// setpgid, etc.) never contend with fork/exit/zombie management.
///
/// Upgraded to an `RwLock` so that concurrent readers (`getpid`, `gettid`,
/// `getppid`, `getpgid`, `getsid`, `get_task_by_pid`) do not serialize on
/// each other.  Only writers (`fork`, `exit`, `setpgid`, `setsid`, `kill`)
/// acquire the exclusive write lock.
///
/// Lock order: SCHED_IDENTITY before LOCAL (never the reverse).
/// SCHED_IDENTITY and BLOCKED_TASKS are independent : never hold both.
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
    /// Flat task snapshot used by IRQ-safe scans such as `tick_all_timers`.
    ///
    /// Unlike `BTreeMap::iter()`, iterating a contiguous `Vec<Arc<Task>>` avoids
    /// tree-walk pointer chasing in hard-IRQ context. The authoritative storage
    /// remains `all_tasks`; this mirror is updated under the same scheduler lock.
    pub(crate) all_tasks_scan: Vec<Arc<Task>>,
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
    let ptr = Arc::as_ptr(task);
    if ptr.is_null() {
        return Err("null Task pointer in Arc");
    }
    let saved_rsp = unsafe { (*task.context.get()).saved_rsp };
    let stack_base = task.kernel_stack.virt_base.as_u64();
    let stack_top = stack_base.saturating_add(task.kernel_stack.size as u64);

    if saved_rsp < stack_base || saved_rsp.saturating_add(56) > stack_top {
        return Err("saved_rsp outside kernel stack bounds");
    }

    // For our switch frame layout, return IP is at [saved_rsp + 48].
    // Use read_unaligned: saved_rsp is only guaranteed to be within the stack
    // bounds, not necessarily aligned to 8 bytes at this offset.
    let ret_ip = unsafe { core::ptr::read_unaligned((saved_rsp + 48) as *const u64) };
    if ret_ip == 0 {
        return Err("null return IP in switch frame");
    }

    Ok(())
}

mod core_impl;
pub mod perf_counters;
mod runtime_ops;
mod task_ops;
mod timer_ops;

pub use runtime_ops::*;
pub use task_ops::*;
pub use timer_ops::*;
