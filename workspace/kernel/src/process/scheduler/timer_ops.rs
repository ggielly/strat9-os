use super::*;
use core::sync::atomic::AtomicBool;

// One-shot bootstrap nudge: ensure each CPU requests at least one preemption
// after entering Ring 3. This breaks "first task runs forever" scenarios when
// class accounting has not yet accumulated enough runtime to trigger resched.
static FIRST_TICK_FORCE_RESCHED: [AtomicBool; crate::arch::x86_64::percpu::MAX_CPUS] =
    [const { AtomicBool::new(false) }; crate::arch::x86_64::percpu::MAX_CPUS];

/// Timer interrupt handler - called from interrupt context.
///
/// Increments the global tick counter unconditionally on BSP so wall-clock
/// time never drifts even when the scheduler lock is contended. Secondary
/// bookkeeping (interval timers, wake deadlines, per-task accounting) is
/// deferred when the lock is unavailable.
///
/// Lock discipline: `tick_all_timers` and `check_wake_deadlines` each acquire
/// the scheduler lock themselves via `try_lock`. The per-task block below uses
/// its own `try_lock`. These are separate acquisitions by design - the inner
/// functions must not be called while the outer lock is held (that would deadlock).
pub fn timer_tick() {
    crate::e9_println!("TA cpu_idx?");                    // E9-A: very start, before any GS access
    let cpu_idx = crate::arch::x86_64::percpu::current_cpu_index();
    crate::e9_println!("TB cpu={}", cpu_idx);             // E9-B: current_cpu_index() survived

    if cpu_is_valid(cpu_idx) {
        CPU_TOTAL_TICKS[cpu_idx].fetch_add(1, Ordering::Relaxed);
    }

    // BSP wall-clock: ALWAYS advance, regardless of any lock state.
    if cpu_idx == 0 {
        TICK_COUNT.fetch_add(1, Ordering::Relaxed);
    }
    crate::e9_println!("TC cpu={}", cpu_idx);             // E9-C: tick counters updated

    // Lock-free bootstrap nudge: first local timer tick requests one resched
    // without touching SCHEDULER. This avoids pathological boot windows where
    // another CPU holds SCHEDULER and this CPU would otherwise defer the first
    // `need_resched` update indefinitely.
    if cpu_is_valid(cpu_idx)
        && !FIRST_TICK_FORCE_RESCHED[cpu_idx].swap(true, Ordering::AcqRel)
    {
        request_force_resched_hint(cpu_idx);
        crate::e9_println!("TI first-tick hint cpu={}", cpu_idx);
    }

    // BSP-only secondary bookkeeping: interval timers and sleep wakeups.
    // NS_PER_TICK = 1_000_000_000 / TIMER_HZ (10_000_000 ns at 100 Hz).
    // Both helpers acquire the scheduler lock internally via try_lock and
    // skip silently when contended - no probe needed.
    if cpu_idx == 0 {
        let tick = TICK_COUNT.load(Ordering::Relaxed);
        let current_time_ns = tick * NS_PER_TICK;
        crate::e9_println!("TD tick_all_timers enter cpu={}", cpu_idx); // E9-D
        crate::process::timer::tick_all_timers(current_time_ns);
        crate::e9_println!("TE tick_all_timers done cpu={}", cpu_idx);  // E9-E
        check_wake_deadlines(current_time_ns);
        crate::e9_println!("TF check_wake_deadlines done cpu={}", cpu_idx); // E9-F
    }

    crate::e9_println!("TG sched try_lock cpu={}", cpu_idx); // E9-G: about to acquire scheduler
    // Per-task accounting on this CPU.
    if let Some(mut guard) = SCHEDULER.try_lock_no_irqsave() {
        crate::e9_println!("TH sched locked cpu={}", cpu_idx); // E9-H: lock acquired
        if let Some(ref mut sched) = *guard {
            if let Some(cpu) = sched.cpus.get_mut(cpu_idx) {
                let should_resched = if let Some(ref current_task) = cpu.current_task {
                    crate::e9_println!("TI0 cpu={} task={}", cpu_idx, current_task.id.as_u64());
                    let class = sched.class_table.class_for_task(current_task);
                    crate::e9_println!("TI1 cpu={} class={:?}", cpu_idx, class);
                    if cpu_is_valid(cpu_idx) {
                        match class {
                            crate::process::sched::SchedClassId::RealTime => {
                                CPU_RT_RUNTIME_TICKS[cpu_idx].fetch_add(1, Ordering::Relaxed);
                            }
                            crate::process::sched::SchedClassId::Fair => {
                                CPU_FAIR_RUNTIME_TICKS[cpu_idx].fetch_add(1, Ordering::Relaxed);
                            }
                            crate::process::sched::SchedClassId::Idle => {
                                CPU_IDLE_TICKS[cpu_idx].fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    current_task.ticks.fetch_add(1, Ordering::Relaxed);
                    crate::e9_println!("TI2 cpu={} task_ticks", cpu_idx);
                    cpu.current_runtime.update();
                    crate::e9_println!(
                        "TI3 cpu={} delta={} period={}",
                        cpu_idx,
                        cpu.current_runtime.delta_ticks,
                        cpu.current_runtime.period_delta_ticks
                    );
                    let should = cpu.class_rqs.update_current(
                        &cpu.current_runtime,
                        current_task,
                        false,
                        &sched.class_table,
                    );
                    crate::e9_println!("TI4 cpu={} should={}", cpu_idx, should);
                    should
                } else {
                    crate::e9_println!("TI0 cpu={} no-current", cpu_idx);
                    false
                };
                if should_resched {
                    cpu.need_resched = true;
                    crate::e9_println!("TI5 cpu={} set-need-resched", cpu_idx);
                }
            }
        }
    } else {
        note_try_lock_fail_on_cpu(cpu_idx);
    }
}

/// Check wake deadlines for all tasks and wake up those whose sleep has expired.
///
/// Called from timer_tick() with interrupts disabled.
/// Uses try_lock() to avoid deadlock if called while scheduler lock is held.
///
/// # Lock discipline
///
/// The SCHEDULER lock is held **only** during the scan + re-enqueue phase.
/// The lock is explicitly dropped before sending IPIs (which may acquire
/// per-CPU data) and before any `Arc<Task>` drop (which reaches
/// `KernelStack::drop → free_frames → buddy_alloc.lock()`).
///
/// To guarantee this, every `Arc<Task>` removed from `blocked_tasks` is
/// moved into the `deferred_drops` array. Those Arcs are dropped after the
/// guard goes out of scope, ensuring `free_frames` is never called while the
/// scheduler lock is held.
fn check_wake_deadlines(current_time_ns: u64) {
    let mut ipi_targets = [false; crate::arch::x86_64::percpu::MAX_CPUS];
    let my_cpu = current_cpu_index();

    // Stack-allocated storage for tasks whose Arc must be dropped outside the
    // scheduler lock. Sized to the same batch limit used for the scan so that
    // we never need a heap allocation here.
    const BATCH: usize = 128;
    let mut deferred_drops: [Option<Arc<Task>>; BATCH] = [const { None }; BATCH];
    let mut drop_count = 0usize;

    {
        // --- begin critical section (SCHEDULER lock held) ---
        let mut scheduler = match SCHEDULER.try_lock_no_irqsave() {
            Some(guard) => guard,
            None => return,
        };

        if let Some(ref mut sched) = *scheduler {
            let mut to_wake = [TaskId::from_u64(0); BATCH];
            let mut count = 0usize;
            for (id, task) in sched.blocked_tasks.iter() {
                let deadline = task.wake_deadline_ns.load(Ordering::Relaxed);
                if deadline != 0 && current_time_ns >= deadline {
                    if count < BATCH {
                        to_wake[count] = *id;
                        count += 1;
                    } else {
                        break;
                    }
                }
            }

            for id in to_wake.iter().copied().take(count) {
                if let Some(blocked_task) = sched.blocked_tasks.remove(&id) {
                    blocked_task.wake_deadline_ns.store(0, Ordering::Relaxed);
                    // SAFETY: scheduler lock held.
                    unsafe { *blocked_task.state.get() = TaskState::Ready };
                    let cpu = sched.task_cpu.get(&id).copied().unwrap_or(0);
                    let class = sched.class_table.class_for_task(&blocked_task);
                    if let Some(cpu_sched) = sched.cpus.get_mut(cpu) {
                        // `enqueue` moves the Arc into the run-queue, so no
                        // drop occurs here; the Arc is alive in class_rqs.
                        cpu_sched.class_rqs.enqueue(class, blocked_task);
                        cpu_sched.need_resched = true;
                        if cpu != my_cpu && cpu_is_valid(cpu) {
                            ipi_targets[cpu] = true;
                        }
                    } else {
                        // No valid CPU slot: stash for drop outside the lock.
                        // This is the only path where an Arc<Task> can be the
                        // last reference and trigger KernelStack::drop.
                        if drop_count < BATCH {
                            deferred_drops[drop_count] = Some(blocked_task);
                            drop_count += 1;
                        }
                        // If deferred_drops is full the task Arc is dropped here,
                        // still under the lock — but that case means we already
                        // have 128 orphaned tasks with no valid CPU, which is a
                        // bug elsewhere; emit a trace and accept the latency hit.
                    }
                }
            }
        }
        // `scheduler` guard drops here — SCHEDULER lock released BEFORE any
        // Arc<Task> drop and BEFORE send_resched_ipi_to_cpu.
        // --- end critical section ---
    }

    // Drop orphaned task Arcs outside the scheduler lock so that
    // KernelStack::drop → free_frames → buddy_alloc.lock() does not race
    // with any other SCHEDULER lock acquisition on this or another CPU.
    for slot in deferred_drops[..drop_count].iter_mut() {
        drop(slot.take());
    }

    for (cpu, send) in ipi_targets.iter().copied().enumerate() {
        if send {
            send_resched_ipi_to_cpu(cpu);
        }
    }
}

/// Get the current tick count
pub fn ticks() -> u64 {
    TICK_COUNT.load(Ordering::Relaxed)
}

/// Get a list of all tasks in the system (for timer checking).
/// Returns None if scheduler is not initialized or currently locked.
pub fn get_all_tasks() -> Option<alloc::vec::Vec<Arc<Task>>> {
    use alloc::vec::Vec;
    let scheduler = match SCHEDULER.try_lock() {
        Some(guard) => guard,
        None => {
            note_try_lock_fail();
            return None;
        }
    };
    if let Some(ref sched) = *scheduler {
        let mut tasks = Vec::with_capacity(sched.all_tasks.len());
        for (_, task) in sched.all_tasks.iter() {
            tasks.push(task.clone());
        }
        Some(tasks)
    } else {
        None
    }
}
