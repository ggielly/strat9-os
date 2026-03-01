use super::*;

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
    let cpu_idx = if let Some(idx) = percpu::cpu_index_from_gs() {
        idx
    } else if apic::is_initialized() {
        let apic_id = apic::lapic_id();
        match percpu::cpu_index_by_apic(apic_id) {
            Some(idx) => idx,
            None => {
                log::trace!("timer_tick: unmapped LAPIC id {}", apic_id);
                return;
            }
        }
    } else {
        return;
    };

    if cpu_is_valid(cpu_idx) {
        CPU_TOTAL_TICKS[cpu_idx].fetch_add(1, Ordering::Relaxed);
    }

    // BSP wall-clock: ALWAYS advance, regardless of any lock state.
    if cpu_idx == 0 {
        TICK_COUNT.fetch_add(1, Ordering::Relaxed);
    }

    // BSP-only secondary bookkeeping: interval timers and sleep wakeups.
    // NS_PER_TICK = 1_000_000_000 / TIMER_HZ (10_000_000 ns at 100 Hz).
    // Both helpers acquire the scheduler lock internally via try_lock and
    // skip silently when contended - no probe needed.
    if cpu_idx == 0 {
        let tick = TICK_COUNT.load(Ordering::Relaxed);
        let current_time_ns = tick * NS_PER_TICK;
        crate::process::timer::tick_all_timers(current_time_ns);
        check_wake_deadlines(current_time_ns);
    }

    // Per-task accounting on this CPU.
    if let Some(mut guard) = SCHEDULER.try_lock() {
        if let Some(ref mut sched) = *guard {
            if let Some(cpu) = sched.cpus.get_mut(cpu_idx) {
                let should_resched = if let Some(ref current_task) = cpu.current_task {
                    if cpu_is_valid(cpu_idx) {
                        match sched.class_table.class_for_task(current_task) {
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
                    cpu.current_runtime.update();
                    cpu.class_rqs.update_current(
                        &cpu.current_runtime,
                        current_task,
                        false,
                        &sched.class_table,
                    )
                } else {
                    false
                };
                if should_resched {
                    cpu.need_resched = true;
                }
            }
        }
    }
}

/// Check wake deadlines for all tasks and wake up those whose sleep has expired.
///
/// Called from timer_tick() with interrupts disabled.
/// Uses try_lock() to avoid deadlock if called while scheduler lock is held.
fn check_wake_deadlines(current_time_ns: u64) {
    let mut ipi_targets = [false; crate::arch::x86_64::percpu::MAX_CPUS];
    let my_cpu = current_cpu_index();
    let mut scheduler = match SCHEDULER.try_lock() {
        Some(guard) => guard,
        None => return,
    };

    if let Some(ref mut sched) = *scheduler {
        const BATCH: usize = 64;
        let mut to_wake = [TaskId::from_u64(0); BATCH];

        loop {
            let mut count = 0;
            for (id, task) in sched.all_tasks.iter() {
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

            if count == 0 {
                break;
            }

            for id in to_wake.iter().copied().take(count) {
                if let Some(task) = sched.all_tasks.get(&id) {
                    task.wake_deadline_ns.store(0, Ordering::Relaxed);
                    if let Some(blocked_task) = sched.blocked_tasks.remove(&id) {
                        unsafe { *blocked_task.state.get() = TaskState::Ready };
                        let cpu = sched.task_cpu.get(&id).copied().unwrap_or(0);
                        let class = sched.class_table.class_for_task(&blocked_task);
                        if let Some(cpu_sched) = sched.cpus.get_mut(cpu) {
                            cpu_sched.class_rqs.enqueue(class, blocked_task);
                            cpu_sched.need_resched = true;
                            if cpu != my_cpu && cpu_is_valid(cpu) {
                                ipi_targets[cpu] = true;
                            }
                        }
                    }
                }
            }

            if count < BATCH {
                break;
            }
        }
    }

    drop(scheduler);
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
    let scheduler = SCHEDULER.try_lock()?;
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
