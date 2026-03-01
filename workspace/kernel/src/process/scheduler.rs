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

use super::task::{
    restore_first_task, switch_context, Pid, Task, TaskId, TaskPriority, TaskState, Tid,
};
use crate::{
    arch::x86_64::{apic, percpu, restore_flags, save_flags_and_cli, timer},
    arch::x86_64::timer::NS_PER_TICK,
    sync::SpinLock,
};
use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

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
static RESCHED_IPI_PENDING: [AtomicBool; crate::arch::x86_64::percpu::MAX_CPUS] =
    [const { AtomicBool::new(false) }; crate::arch::x86_64::percpu::MAX_CPUS];
static LAST_STEAL_TICK: [AtomicU64; crate::arch::x86_64::percpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::arch::x86_64::percpu::MAX_CPUS];

const STEAL_IMBALANCE_MIN: usize = 2;
const STEAL_COOLDOWN_TICKS: u64 = 2;

#[inline]
fn active_cpu_count() -> usize {
    percpu::cpu_count()
        .max(1)
        .min(crate::arch::x86_64::percpu::MAX_CPUS)
}

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
}

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

pub fn scheduler_metrics_snapshot() -> SchedulerMetricsSnapshot {
    let cpu_count = active_cpu_count();
    let mut rt_runtime_ticks = [0u64; crate::arch::x86_64::percpu::MAX_CPUS];
    let mut fair_runtime_ticks = [0u64; crate::arch::x86_64::percpu::MAX_CPUS];
    let mut idle_runtime_ticks = [0u64; crate::arch::x86_64::percpu::MAX_CPUS];
    let mut switch_count = [0u64; crate::arch::x86_64::percpu::MAX_CPUS];
    let mut preempt_count = [0u64; crate::arch::x86_64::percpu::MAX_CPUS];
    let mut steal_in_count = [0u64; crate::arch::x86_64::percpu::MAX_CPUS];
    let mut steal_out_count = [0u64; crate::arch::x86_64::percpu::MAX_CPUS];
    for i in 0..cpu_count {
        rt_runtime_ticks[i] = CPU_RT_RUNTIME_TICKS[i].load(Ordering::Relaxed);
        fair_runtime_ticks[i] = CPU_FAIR_RUNTIME_TICKS[i].load(Ordering::Relaxed);
        idle_runtime_ticks[i] = CPU_IDLE_TICKS[i].load(Ordering::Relaxed);
        switch_count[i] = CPU_SWITCH_COUNT[i].load(Ordering::Relaxed);
        preempt_count[i] = CPU_PREEMPT_COUNT[i].load(Ordering::Relaxed);
        steal_in_count[i] = CPU_STEAL_IN_COUNT[i].load(Ordering::Relaxed);
        steal_out_count[i] = CPU_STEAL_OUT_COUNT[i].load(Ordering::Relaxed);
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
    }
}

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
    }
}

// ─── Cross-CPU IPI helpers ────────────────────────────────────────────────────

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
    let my_apic = apic::lapic_id();
    if let Some(target_apic) = percpu::apic_id_by_cpu_index(cpu_index) {
        if target_apic != my_apic {
            if RESCHED_IPI_PENDING[cpu_index].swap(true, Ordering::AcqRel) {
                return;
            }
            apic::send_resched_ipi(target_apic);
        }
    }
}

/// The global scheduler instance
pub(crate) static SCHEDULER: SpinLock<Option<Scheduler>> = SpinLock::new(None);

/// Global tick counter (safe to increment from interrupt context)
static TICK_COUNT: AtomicU64 = AtomicU64::new(0);
/// Verbose scheduler trace switch.
static SCHED_VERBOSE: AtomicBool = AtomicBool::new(false);

#[inline]
fn sched_trace(args: core::fmt::Arguments<'_>) {
    if SCHED_VERBOSE.load(Ordering::Relaxed) {
        log::debug!("[sched] {}", args);
    }
}

/// Information needed to perform a context switch after releasing the lock.
struct SwitchTarget {
    /// Pointer to old task's saved_rsp (in CpuContext)
    old_rsp_ptr: *mut u64,
    /// Pointer to new task's saved_rsp (in CpuContext)
    new_rsp_ptr: *const u64,
    /// Pointer to old task's FPU state
    old_fpu_ptr: *mut crate::process::task::FpuState,
    /// Pointer to new task's FPU state
    new_fpu_ptr: *const crate::process::task::FpuState,
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

fn current_cpu_index() -> usize {
    if apic::is_initialized() {
        let apic_id = apic::lapic_id();
        percpu::cpu_index_by_apic(apic_id).unwrap_or(0)
    } else {
        0
    }
}

struct PerCpuClassRqSet {
    real_time: crate::process::sched::real_time::RealTimeClassRq,
    fair: crate::process::sched::fair::FairClassRq,
    idle: crate::process::sched::idle::IdleClassRq,
}

impl PerCpuClassRqSet {
    fn new() -> Self {
        Self {
            real_time: crate::process::sched::real_time::RealTimeClassRq::new(),
            fair: crate::process::sched::fair::FairClassRq::new(),
            idle: crate::process::sched::idle::IdleClassRq::new(),
        }
    }

    fn enqueue(&mut self, class: crate::process::sched::SchedClassId, task: Arc<Task>) {
        use crate::process::sched::SchedClassRq;
        match class {
            crate::process::sched::SchedClassId::Fair => self.fair.enqueue(task),
            crate::process::sched::SchedClassId::RealTime => self.real_time.enqueue(task),
            crate::process::sched::SchedClassId::Idle => self.idle.enqueue(task),
        }
    }

    fn len_by_class(&self, class: crate::process::sched::SchedClassId) -> usize {
        use crate::process::sched::SchedClassRq;
        match class {
            crate::process::sched::SchedClassId::Fair => self.fair.len(),
            crate::process::sched::SchedClassId::RealTime => self.real_time.len(),
            crate::process::sched::SchedClassId::Idle => self.idle.len(),
        }
    }

    fn runnable_len(&self) -> usize {
        self.len_by_class(crate::process::sched::SchedClassId::RealTime)
            + self.len_by_class(crate::process::sched::SchedClassId::Fair)
    }

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

    fn pick_next(&mut self, table: &crate::process::sched::SchedClassTable) -> Option<Arc<Task>> {
        for class in table.pick_order().iter().copied() {
            if let Some(task) = self.pick_next_by_class(class) {
                return Some(task);
            }
        }
        None
    }

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

    fn remove(&mut self, task_id: crate::process::TaskId) -> bool {
        use crate::process::sched::SchedClassRq;
        self.real_time.remove(task_id) || self.fair.remove(task_id) || self.idle.remove(task_id)
    }

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
}

/// The round-robin scheduler (per-CPU queues)
pub struct Scheduler {
    /// Per-CPU scheduler state
    cpus: alloc::vec::Vec<SchedulerCpu>,
    /// Tasks blocked waiting for an event (keyed by TaskId for O(log n) wake)
    blocked_tasks: BTreeMap<TaskId, Arc<Task>>,
    /// All tasks in the system (for lookup by TaskId)
    pub(crate) all_tasks: BTreeMap<TaskId, Arc<Task>>,
    /// Map TaskId -> CPU index (for wake/resume routing)
    task_cpu: BTreeMap<TaskId, usize>,
    /// Map userspace PID -> internal TaskId (process leader in current model).
    pid_to_task: BTreeMap<Pid, TaskId>,
    /// Parent relationship: child -> parent
    parent_of: BTreeMap<TaskId, TaskId>,
    /// Children list: parent -> children
    children_of: BTreeMap<TaskId, alloc::vec::Vec<TaskId>>,
    /// Zombie exit statuses: child -> (exit_code, pid)
    zombies: BTreeMap<TaskId, (i32, Pid)>,
    /// Scheduler class table (pick order, steal order, class metadata)
    class_table: crate::process::sched::SchedClassTable,
}

fn validate_task_context(task: &Arc<Task>) -> Result<(), &'static str> {
    let saved_rsp = unsafe { (*task.context.get()).saved_rsp };
    let stack_base = task.kernel_stack.virt_base.as_u64();
    let stack_top = stack_base.saturating_add(task.kernel_stack.size as u64);

    if saved_rsp < stack_base || saved_rsp.saturating_add(56) > stack_top {
        return Err("saved_rsp outside kernel stack bounds");
    }

    // For our switch frame layout, return IP is at [saved_rsp + 48].
    let ret_ip = unsafe { core::ptr::read((saved_rsp + 48) as *const u64) };
    if ret_ip == 0 {
        return Err("null return IP in switch frame");
    }

    Ok(())
}

mod core_impl;
mod runtime_ops;
mod task_ops;
mod timer_ops;

pub use runtime_ops::*;
pub use task_ops::*;
pub use timer_ops::*;
