//! Deferred work queue — softirq-equivalent for Strat9-OS.
//!
//! Moves heavy tick processing out of the hardirq handler into safe
//! execution contexts (post-switch, idle loop, syscall return).
//!
//! # Design
//!
//! Each CPU has a lock-free `AtomicU32` bitmask of pending work items.
//! The hardirq timer handler calls `raise_deferred_work()` which sets bits
//! atomically — no locks, no allocation, O(1) cost.
//!
//! Processing happens at safe points where IRQs may be re-enabled and
//! scheduler locks can be acquired without deadlock:
//!
//! - `finish_switch()` — after cooperative context switch completes
//! - `finish_interrupt_switch()` — after interrupt-driven switch completes
//! - `idle_task_main()` — idle loop before HLT
//! - `maybe_preempt()` — at preemption entry (for work raised during IRQ)
//!
//! # What stays in hardirq
//!
//! - TICK_COUNT, CPU_TOTAL_TICKS, CPU_LOCAL_TICKS increments (lock-free)
//! - FORCE_RESCHED_HINT setting (lock-free)
//! - speaker_tick, n3_watchdog_tick (minimal)
//! - EOI (must be immediate)
//!
//! # What moves to deferred
//!
//! - `tick_all_timers()` — interval timer processing
//! - `check_wake_deadlines()` — deadline-based wakeups
//! - Per-task Fair class accounting (runnable_len, tick_update_wait)

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// Work item types that can be deferred from hardirq context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DeferredWork {
    /// Process interval timers (ITIMER_REAL, ITIMER_VIRTUAL, ITIMER_PROF).
    IntervalTimers = 1 << 0,
    /// Check wake deadlines and wake expired tasks.
    WakeDeadlines = 1 << 1,
    /// Per-task Fair class accounting (runnable_len, tick_update_wait).
    PerTaskAccounting = 1 << 2,
}

impl DeferredWork {
    /// All work items combined.
    const ALL: u32 = Self::IntervalTimers as u32 | Self::WakeDeadlines as u32 | Self::PerTaskAccounting as u32;
}

/// Per-CPU deferred work state.
struct DeferredWorkCpu {
    /// Pending work bitmask (set by raise, cleared by process).
    pending: AtomicU32,
    /// Whether processing is currently in progress (prevents re-entrance).
    processing: AtomicBool,
    /// Total work items raised (for metrics).
    raised_count: AtomicU32,
    /// Total work items processed (for metrics).
    processed_count: AtomicU32,
}

impl DeferredWorkCpu {
    const fn new() -> Self {
        Self {
            pending: AtomicU32::new(0),
            processing: AtomicBool::new(false),
            raised_count: AtomicU32::new(0),
            processed_count: AtomicU32::new(0),
        }
    }
}

/// Per-CPU deferred work queues.
static DEFERRED_WORK: [DeferredWorkCpu; crate::arch::percpu::MAX_CPUS] =
    [const { DeferredWorkCpu::new() }; crate::arch::percpu::MAX_CPUS];

// ---------------------------------------------------------------------------
// Raise (called from hardirq context)
// ---------------------------------------------------------------------------

/// Raise deferred work items for the current CPU.
///
/// Called from the timer interrupt handler to signal that heavy processing
/// should happen at the next safe point. This is lock-free and O(1).
///
/// # Safety
///
/// Safe to call from any context (including hardirq with interrupts disabled).
pub fn raise_deferred_work(work: DeferredWork) {
    let cpu = crate::arch::percpu::current_cpu_index();
    if cpu >= crate::arch::percpu::MAX_CPUS {
        return;
    }
    DEFERRED_WORK[cpu].pending.fetch_or(work as u32, Ordering::Release);
    DEFERRED_WORK[cpu].raised_count.fetch_add(1, Ordering::Relaxed);
}

/// Raise all tick-related deferred work items for the current CPU.
///
/// Convenience function called from `timer_tick()` to defer all heavy
/// processing that was previously done inline in hardirq.
pub fn raise_tick_deferred_work() {
    raise_deferred_work(DeferredWork::IntervalTimers);
    raise_deferred_work(DeferredWork::WakeDeadlines);
    raise_deferred_work(DeferredWork::PerTaskAccounting);
}

// ---------------------------------------------------------------------------
// Process (called from safe context)
// ---------------------------------------------------------------------------

/// Process deferred work items for the current CPU.
///
/// Called from safe contexts: finish_switch, finish_interrupt_switch,
/// idle loop entry, etc. Drains the pending bitmask and executes each
/// work item with interrupts potentially re-enabled.
///
/// Returns `true` if any work was processed.
pub fn process_deferred_work() -> bool {
    let cpu = crate::arch::percpu::current_cpu_index();
    if cpu >= crate::arch::percpu::MAX_CPUS {
        return false;
    }

    let work_cpu = &DEFERRED_WORK[cpu];

    // Fast path: nothing pending.
    let pending = work_cpu.pending.swap(0, Ordering::AcqRel);
    if pending == 0 {
        return false;
    }

    // Only measure actual work processing, not the fast-path no-op.
    let _perf = super::perf_counters::PerfScope::new(
        &super::perf_counters::DEFERRED_WORK_TSC,
        &super::perf_counters::DEFERRED_WORK_COUNT,
    );

    // Prevent re-entrance (e.g., if a work item triggers a reschedule
    // that re-enters this path).
    if work_cpu.processing.swap(true, Ordering::AcqRel) {
        // Re-raise the items we couldn't process.
        work_cpu.pending.fetch_or(pending, Ordering::Release);
        work_cpu.processing.store(false, Ordering::Release);
        return false;
    }

    work_cpu.processed_count.fetch_add(1, Ordering::Relaxed);

    // Process each pending work item.
    // These acquire scheduler locks internally via try_lock, so they
    // are safe to call from most kernel contexts.
    if pending & DeferredWork::IntervalTimers as u32 != 0 {
        let tick = super::ticks();
        let current_time_ns = tick * crate::arch::timer::NS_PER_TICK;
        crate::process::timer::tick_all_timers(current_time_ns);
    }

    if pending & DeferredWork::WakeDeadlines as u32 != 0 {
        let tick = super::ticks();
        let current_time_ns = tick * crate::arch::timer::NS_PER_TICK;
        super::timer_ops::check_wake_deadlines(current_time_ns);
    }

    if pending & DeferredWork::PerTaskAccounting as u32 != 0 {
        process_per_task_accounting();
    }

    work_cpu.processing.store(false, Ordering::Release);
    true
}

/// Process per-task Fair class accounting for the current CPU.
///
/// This is the deferred version of the per-task block that was previously
/// inline in `timer_tick()`. Acquires LOCAL_SCHEDULERS[cpu] via try_lock.
fn process_per_task_accounting() {
    use super::{CPU_FAIR_RUNTIME_TICKS, CPU_IDLE_TICKS, CPU_RT_RUNTIME_TICKS, LOCAL_SCHEDULERS};
    use crate::process::sched::SchedClassId;

    let cpu_idx = crate::arch::percpu::current_cpu_index();
    if !super::cpu_is_valid(cpu_idx) {
        return;
    }

    const TICK_LOCK_RETRIES: usize = 3;
    for attempt in 0..TICK_LOCK_RETRIES {
        if let Some(mut guard) = LOCAL_SCHEDULERS[cpu_idx].try_lock_no_irqsave() {
            if let Some(ref mut cpu) = *guard {
                let should_resched = if let Some(ref current_task) = cpu.current_task {
                    let class = cpu.class_table.class_for_task(current_task);
                    match class {
                        SchedClassId::RealTime => {
                            CPU_RT_RUNTIME_TICKS[cpu_idx].fetch_add(1, Ordering::Relaxed);
                        }
                        SchedClassId::Fair => {
                            CPU_FAIR_RUNTIME_TICKS[cpu_idx].fetch_add(1, Ordering::Relaxed);
                        }
                        SchedClassId::Idle => {
                            CPU_IDLE_TICKS[cpu_idx].fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    current_task.ticks.fetch_add(1, Ordering::Relaxed);
                    cpu.current_runtime.update();
                    cpu.class_rqs.update_current(
                        &cpu.current_runtime,
                        current_task,
                        false,
                        &cpu.class_table,
                    )
                } else {
                    false
                };
                // Increment Fair starvation counters for all queued tasks.
                cpu.class_rqs.tick_update_wait();
                if should_resched {
                    cpu.need_resched = true;
                }
            }
            return;
        }
        if attempt == TICK_LOCK_RETRIES - 1 {
            super::note_try_lock_fail_on_cpu(cpu_idx);
        }
    }
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

/// Snapshot of deferred work metrics across all CPUs.
pub struct DeferredWorkMetrics {
    pub cpu_count: usize,
    pub raised: [u32; crate::arch::percpu::MAX_CPUS],
    pub processed: [u32; crate::arch::percpu::MAX_CPUS],
    pub pending: [u32; crate::arch::percpu::MAX_CPUS],
}

/// Take a snapshot of deferred work metrics.
pub fn metrics_snapshot() -> DeferredWorkMetrics {
    let n = super::active_cpu_count();
    let mut raised = [0u32; crate::arch::percpu::MAX_CPUS];
    let mut processed = [0u32; crate::arch::percpu::MAX_CPUS];
    let mut pending = [0u32; crate::arch::percpu::MAX_CPUS];
    for i in 0..n {
        raised[i] = DEFERRED_WORK[i].raised_count.load(Ordering::Relaxed);
        processed[i] = DEFERRED_WORK[i].processed_count.load(Ordering::Relaxed);
        pending[i] = DEFERRED_WORK[i].pending.load(Ordering::Relaxed);
    }
    DeferredWorkMetrics {
        cpu_count: n,
        raised,
        processed,
        pending,
    }
}

/// Reset deferred work metrics.
pub fn reset_metrics() {
    let n = super::active_cpu_count();
    for i in 0..n {
        DEFERRED_WORK[i].raised_count.store(0, Ordering::Relaxed);
        DEFERRED_WORK[i].processed_count.store(0, Ordering::Relaxed);
    }
}

/// Check if there is pending deferred work on the current CPU.
#[inline]
pub fn has_pending() -> bool {
    let cpu = crate::arch::percpu::current_cpu_index();
    if cpu >= crate::arch::percpu::MAX_CPUS {
        return false;
    }
    DEFERRED_WORK[cpu].pending.load(Ordering::Acquire) != 0
}
