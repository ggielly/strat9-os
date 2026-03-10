use super::*;

/// Initialize the scheduler
pub fn init_scheduler() {
    let cpu_count = percpu::cpu_count().max(1);
    crate::serial_println!(
        "[trace][sched] init_scheduler enter cpu_count={}",
        cpu_count
    );
    // Build the scheduler outside the global scheduler lock to avoid
    // lock-order inversions (`SCHEDULER -> allocator`) during task/stack
    // allocation in `Scheduler::new`.
    let new_sched = Scheduler::new(cpu_count);
    crate::serial_println!("[trace][sched] init_scheduler new() done");

    let mut scheduler = SCHEDULER.lock();
    *scheduler = Some(new_sched);
    drop(scheduler); // Release the lock

    // Only initialize legacy PIT if APIC timer is not active
    if !timer::is_apic_timer_active() {
        timer::init_pit(100); // 100Hz = 10ms interval for quantum
        log::info!("Scheduler: using legacy PIT timer (100Hz)");
    } else {
        log::info!("Scheduler: using APIC timer (100Hz)");
    }
    crate::serial_println!("[trace][sched] init_scheduler exit");
}

/// Add a task to the scheduler
pub fn add_task(task: Arc<Task>) {
    let tid = task.id;
    crate::serial_force_println!(
        "[trace][sched] add_task enter tid={} name={}",
        tid.as_u64(),
        task.name
    );
    crate::serial_force_println!(
        "[trace][sched] lock addrs sched={:#x} slab={:#x} buddy={:#x}",
        crate::process::scheduler::debug_scheduler_lock_addr(),
        crate::memory::heap::debug_slab_lock_addr(),
        crate::memory::buddy::debug_buddy_lock_addr()
    );
    let mut spins = 0usize;
    let mut scheduler = loop {
        if let Some(guard) = SCHEDULER.try_lock() {
            break guard;
        }
        spins = spins.saturating_add(1);
        if spins == 2_000_000 {
            crate::serial_force_println!(
                "[trace][sched] add_task waiting lock tid={} owner_cpu={}",
                tid.as_u64(),
                SCHEDULER.owner_cpu()
            );
            spins = 0;
        }
        core::hint::spin_loop();
    };
    crate::serial_force_println!("[trace][sched] add_task lock acquired tid={}", tid.as_u64());
    let ipi_to_cpu = if let Some(ref mut sched) = *scheduler {
        crate::serial_force_println!(
            "[trace][sched] add_task scheduler present tid={}",
            tid.as_u64()
        );
        let ipi = sched.add_task(task);
        crate::serial_force_println!("[trace][sched] add_task done tid={}", tid.as_u64());
        ipi
    } else {
        crate::serial_force_println!(
            "[trace][sched] add_task scheduler missing tid={}",
            tid.as_u64()
        );
        None
    };
    drop(scheduler);
    if let Some(ci) = ipi_to_cpu {
        send_resched_ipi_to_cpu(ci);
    }
}

/// Add a task and register a parent/child relation.
pub fn add_task_with_parent(task: Arc<Task>, parent: TaskId) {
    let ipi_to_cpu = {
        let mut scheduler = SCHEDULER.lock();
        if let Some(ref mut sched) = *scheduler {
            sched.add_task_with_parent(task, parent)
        } else {
            None
        }
    };
    if let Some(ci) = ipi_to_cpu {
        send_resched_ipi_to_cpu(ci);
    }
}

/// Start the scheduler (called from kernel_main)
///
/// Picks the first task and starts running it. Never returns.
pub fn schedule() -> ! {
    let cpu_index = current_cpu_index();
    schedule_on_cpu(cpu_index)
}

/// Performs the schedule on cpu operation.
pub fn schedule_on_cpu(cpu_index: usize) -> ! {
    // Disable interrupts for the entire critical section.
    //
    // On the BSP, IF may be 1 (interrupts were enabled in Phase 9).
    // Without CLI, a timer interrupt between `pick_next_task` (which sets
    // `current_task`) and `restore_first_task` would let `maybe_preempt()`
    // call `switch_context` on the *init stack*, corrupting the task's
    // `saved_rsp` and creating an infinite loop.
    //
    // APs already arrive here with IF=0 (from the trampoline), but the
    // explicit CLI makes the contract clear for all callers.
    //
    // `task_entry_trampoline` executes `sti` when the first task starts,
    // so interrupts are re-enabled at exactly the right moment.
    crate::arch::x86_64::cli();

    // APs may arrive here before the BSP has called init_scheduler().
    // Spin-wait (releasing the lock each iteration) until the scheduler
    // is initialized, then pick the first task.
    let first_task = loop {
        let mut scheduler = SCHEDULER.lock();
        if let Some(ref mut sched) = *scheduler {
            let idx = if cpu_index < sched.cpus.len() {
                cpu_index
            } else {
                0
            };
            break sched.pick_next_task(idx);
        }
        // Drop lock before spinning so the BSP can initialize the scheduler.
        drop(scheduler);
        core::hint::spin_loop();
    }; // Lock is released here before jumping to first task
    super::task_ops::flush_deferred_silo_cleanups();

    crate::serial_force_println!(
        "[trace][sched] schedule_on_cpu first_task cpu={} tid={} name={} rsp={:#x} kstack=[{:#x}..{:#x}]",
        cpu_index,
        first_task.id.as_u64(),
        first_task.name,
        unsafe { (*first_task.context.get()).saved_rsp },
        first_task.kernel_stack.virt_base.as_u64(),
        first_task.kernel_stack.virt_base.as_u64() + first_task.kernel_stack.size as u64,
    );

    // Set TSS.rsp0 and SYSCALL kernel RSP for the first task
    {
        let stack_top =
            first_task.kernel_stack.virt_base.as_u64() + first_task.kernel_stack.size as u64;
        crate::arch::x86_64::tss::set_kernel_stack(x86_64::VirtAddr::new(stack_top));
        crate::arch::x86_64::syscall::set_kernel_rsp(stack_top);
        crate::serial_force_println!(
            "[trace][sched] schedule_on_cpu stacks set cpu={} rsp0={:#x}",
            cpu_index,
            stack_top
        );
    }

    // Switch to the first task's address space (no-op for kernel tasks)
    // SAFETY: The first task's address space is valid (kernel AS at boot).
    if let Err(e) = validate_task_context(&first_task) {
        panic!(
            "scheduler: invalid first task '{}' (id={:?}): {}",
            first_task.name, first_task.id, e
        );
    }
    crate::serial_force_println!(
        "[trace][sched] schedule_on_cpu first_task ctx valid cpu={} tid={}",
        cpu_index,
        first_task.id.as_u64()
    );
    unsafe {
        (*first_task.process.address_space.get()).switch_to();
    }
    crate::serial_force_println!(
        "[trace][sched] schedule_on_cpu switch_to done cpu={} tid={}",
        cpu_index,
        first_task.id.as_u64()
    );

    // Jump to the first task (never returns)
    // SAFETY: The context was set up by CpuContext::new with a valid stack frame.
    // Interrupts are disabled; the trampoline's `sti` re-enables them.
    crate::serial_force_println!(
        "[trace][sched] schedule_on_cpu restore_first_task cpu={} tid={}",
        cpu_index,
        first_task.id.as_u64()
    );
    unsafe {
        crate::process::task::do_restore_first_task(
            &raw const (*first_task.context.get()).saved_rsp,
            first_task.fpu_state.get() as *const u8,
            first_task
                .xcr0_mask
                .load(core::sync::atomic::Ordering::Relaxed),
        );
    }
}

/// Called immediately after a context switch completes (in the new task's context).
/// This safely re-queues the previously running task now that its state is fully saved.
pub fn finish_switch() {
    let cpu_index = current_cpu_index();
    crate::serial_force_println!("[trace][sched] finish_switch enter cpu={}", cpu_index);
    let mut task_to_drop = None;
    {
        crate::serial_force_println!(
            "[trace][sched] finish_switch before lock cpu={} sched_lock={:#x}",
            cpu_index,
            crate::process::scheduler::debug_scheduler_lock_addr()
        );
        let mut spins = 0usize;
        let mut scheduler = loop {
            if let Some(guard) = SCHEDULER.try_lock() {
                break guard;
            }
            spins = spins.saturating_add(1);
            if spins == 2_000_000 {
                crate::serial_force_println!(
                    "[trace][sched] finish_switch waiting lock cpu={} owner_cpu={}",
                    cpu_index,
                    SCHEDULER.owner_cpu()
                );
                spins = 0;
            }
            core::hint::spin_loop();
        };
        crate::serial_force_println!(
            "[trace][sched] finish_switch lock acquired cpu={}",
            cpu_index
        );
        if let Some(ref mut sched) = *scheduler {
            let mut requeue_task = None;
            if let Some(cpu) = sched.cpus.get_mut(cpu_index) {
                task_to_drop = cpu.task_to_drop.take();
                requeue_task = cpu.task_to_requeue.take();
            }
            if let Some(task) = requeue_task {
                crate::serial_force_println!(
                    "[trace][sched] finish_switch requeue cpu={} tid={}",
                    cpu_index,
                    task.id.as_u64()
                );
                let class = sched.class_table.class_for_task(&task);
                if let Some(cpu) = sched.cpus.get_mut(cpu_index) {
                    cpu.class_rqs.enqueue(class, task);
                }
            }
        }
    }
    crate::serial_force_println!(
        "[trace][sched] finish_switch after lock cpu={} drop={}",
        cpu_index,
        task_to_drop.is_some()
    );
    super::task_ops::flush_deferred_silo_cleanups();

    // Drop the previous task outside the scheduler lock (if it was the last ref).
    // This is safe because we are fully switched to the new task's stack and CR3.
    drop(task_to_drop);

    // Temporary safety mode: skip FS.base restore in finish_switch.
    // This avoids cloning current_task() on a path that currently trips
    // an Arc refcount invariant under heavy early context-switch churn.
}

/// Yield the current task to allow other tasks to run (cooperative).
///
/// Disables interrupts around the scheduler lock to prevent deadlock
/// with the timer handler's `maybe_preempt()`.
///
/// Returns immediately (no-op) if preemption is disabled on this CPU.
pub fn yield_task() {
    // Respect the preemption guard: if a `PreemptGuard` is held, do nothing.
    if !percpu::is_preemptible() {
        return;
    }

    // Save RFLAGS and disable interrupts to prevent timer from
    // trying to lock the scheduler while we hold it
    let saved_flags = save_flags_and_cli();
    let cpu_index = current_cpu_index();

    let switch_target = {
        let mut scheduler = SCHEDULER.lock();
        if let Some(ref mut sched) = *scheduler {
            if cpu_index < sched.cpus.len() {
                sched.yield_cpu(cpu_index)
            } else {
                None
            }
        } else {
            None
        }
    }; // Lock released here, before the actual context switch

    if let Some(ref target) = switch_target {
        // SAFETY: Pointers are valid (they point into Arc<Task> contexts
        // kept alive by the scheduler). Interrupts are disabled.
        unsafe {
            crate::process::task::do_switch_context(target);
        }
        finish_switch();
    }

    restore_flags(saved_flags);
}

/// Called from the timer interrupt handler (or a resched IPI) to potentially
/// preempt the current task.
///
/// This is safe to call from interrupt context because:
/// 1. IF is already cleared by the CPU when entering the interrupt.
/// 2. We use `try_lock()` - if the scheduler is already locked
///    (e.g., `yield_task()` is in progress), we simply skip preemption
///    for this tick.
/// 3. We honour the `PreemptGuard`: if preemption is disabled, we return.
pub fn maybe_preempt() {
    let cpu_index = current_cpu_index();
    if cpu_is_valid(cpu_index) {
        RESCHED_IPI_PENDING[cpu_index].store(false, Ordering::Release);
    }

    // Honour the preemption guard - never preempt a section that asked for it.
    if !percpu::is_preemptible() {
        return;
    }

    // Try to lock the scheduler. If it's already locked (yield_task in
    // progress), just skip this tick - we'll preempt on the next one.
    let switch_target = {
        let mut scheduler = match SCHEDULER.try_lock() {
            Some(guard) => guard,
            None => {
                note_try_lock_fail_on_cpu(cpu_index);
                return;
            } // Lock contended, skip this tick
        };

        if let Some(ref mut sched) = *scheduler {
            // Skip if no task is running yet (during early boot)
            let cpu = match sched.cpus.get_mut(cpu_index) {
                Some(cpu) => cpu,
                None => return,
            };
            if cpu.current_task.is_none() {
                return;
            }
            if !cpu.need_resched {
                return;
            }
            if let Some(current) = cpu.current_task.as_ref() {
                sched_trace(format_args!(
                    "cpu={} preempt request task={} rt_delta={}",
                    cpu_index,
                    current.id.as_u64(),
                    cpu.current_runtime.period_delta_ticks
                ));
            }
            cpu.need_resched = false;
            sched.yield_cpu(cpu_index)
        } else {
            None
        }
    }; // Lock released here

    if let Some(ref target) = switch_target {
        if cpu_is_valid(cpu_index) {
            CPU_PREEMPT_COUNT[cpu_index].fetch_add(1, Ordering::Relaxed);
        }
        unsafe {
            crate::process::task::do_switch_context(target);
        }
        finish_switch();
    }
}

/// Enable or disable verbose scheduler tracing.
pub fn set_verbose(enabled: bool) {
    SCHED_VERBOSE.store(enabled, Ordering::Relaxed);
    log::info!(
        "[sched][trace] verbose={}",
        if enabled { "on" } else { "off" }
    );
}

/// Return current verbose tracing state.
pub fn verbose_enabled() -> bool {
    SCHED_VERBOSE.load(Ordering::Relaxed)
}

/// Return the scheduler class-table currently in use.
pub fn class_table() -> crate::process::sched::SchedClassTable {
    let saved_flags = save_flags_and_cli();
    let out = {
        let scheduler = SCHEDULER.lock();
        if let Some(ref sched) = *scheduler {
            sched.class_table
        } else {
            crate::process::sched::SchedClassTable::default()
        }
    };
    restore_flags(saved_flags);
    out
}

/// Configure scheduler class pick/steal order at runtime.
pub fn configure_class_table(table: crate::process::sched::SchedClassTable) -> bool {
    if !table.validate() {
        return false;
    }
    let saved_flags = save_flags_and_cli();
    let mut ipi_targets = [false; crate::arch::x86_64::percpu::MAX_CPUS];
    let my_cpu = current_cpu_index();
    let applied = {
        let mut scheduler = SCHEDULER.lock();
        if let Some(ref mut sched) = *scheduler {
            let prev = sched.class_table;
            sched.class_table = table;
            if prev.policy_map() != sched.class_table.policy_map() {
                sched.migrate_ready_tasks_for_new_class_table();
            }
            for (cpu_idx, cpu) in sched.cpus.iter_mut().enumerate() {
                cpu.need_resched = true;
                if cpu_idx != my_cpu && cpu_is_valid(cpu_idx) {
                    ipi_targets[cpu_idx] = true;
                }
            }
            true
        } else {
            false
        }
    };
    restore_flags(saved_flags);
    for (cpu, send) in ipi_targets.iter().copied().enumerate() {
        if send {
            send_resched_ipi_to_cpu(cpu);
        }
    }
    applied
}

/// Dump per-cpu scheduler queues for tracing/debug.
pub fn log_state(label: &str) {
    let saved_flags = save_flags_and_cli();
    let scheduler = SCHEDULER.lock();
    if let Some(ref sched) = *scheduler {
        let pick = sched.class_table.pick_order();
        let steal = sched.class_table.steal_order();
        log::info!(
            "[sched][state] label={} class_table.pick=[{},{},{}] class_table.steal=[{},{}]",
            label,
            pick[0].as_str(),
            pick[1].as_str(),
            pick[2].as_str(),
            steal[0].as_str(),
            steal[1].as_str()
        );
        for (cpu_id, cpu) in sched.cpus.iter().enumerate() {
            use crate::process::sched::SchedClassRq;
            let current = cpu
                .current_task
                .as_ref()
                .map(|t| t.id.as_u64())
                .unwrap_or(u64::MAX);
            log::info!(
                "[sched][state] label={} cpu={} current={} rq_rt={} rq_fair={} rq_idle={} blocked={} need_resched={}",
                label,
                cpu_id,
                current,
                cpu.class_rqs.real_time.len(),
                cpu.class_rqs.fair.len(),
                cpu.class_rqs.idle.len(),
                sched.blocked_tasks.len(),
                cpu.need_resched
            );
        }
    }
    drop(scheduler);
    restore_flags(saved_flags);
}

/// Structured scheduler state snapshot for shell/top/debug tooling.
pub fn state_snapshot() -> SchedulerStateSnapshot {
    let mut out = SchedulerStateSnapshot {
        initialized: false,
        boot_phase: 0,
        cpu_count: 0,
        pick_order: [
            crate::process::sched::SchedClassId::RealTime,
            crate::process::sched::SchedClassId::Fair,
            crate::process::sched::SchedClassId::Idle,
        ],
        steal_order: [
            crate::process::sched::SchedClassId::Fair,
            crate::process::sched::SchedClassId::RealTime,
        ],
        blocked_tasks: 0,
        current_task: [u64::MAX; crate::arch::x86_64::percpu::MAX_CPUS],
        rq_rt: [0; crate::arch::x86_64::percpu::MAX_CPUS],
        rq_fair: [0; crate::arch::x86_64::percpu::MAX_CPUS],
        rq_idle: [0; crate::arch::x86_64::percpu::MAX_CPUS],
        need_resched: [false; crate::arch::x86_64::percpu::MAX_CPUS],
    };

    let saved_flags = save_flags_and_cli();
    {
        let scheduler = SCHEDULER.lock();
        if let Some(ref sched) = *scheduler {
            use crate::process::sched::SchedClassRq;
            let cpu_count = sched.cpus.len().min(crate::arch::x86_64::percpu::MAX_CPUS);
            out.initialized = true;
            out.boot_phase = if cpu_count > 0 { 2 } else { 1 };
            out.cpu_count = cpu_count;
            out.pick_order = *sched.class_table.pick_order();
            out.steal_order = *sched.class_table.steal_order();
            out.blocked_tasks = sched.blocked_tasks.len();
            for i in 0..cpu_count {
                let cpu = &sched.cpus[i];
                out.current_task[i] = cpu
                    .current_task
                    .as_ref()
                    .map(|t| t.id.as_u64())
                    .unwrap_or(u64::MAX);
                out.rq_rt[i] = cpu.class_rqs.real_time.len();
                out.rq_fair[i] = cpu.class_rqs.fair.len();
                out.rq_idle[i] = cpu.class_rqs.idle.len();
                out.need_resched[i] = cpu.need_resched;
            }
        }
    }
    restore_flags(saved_flags);
    out
}

/// The main function for the idle task
pub(super) extern "C" fn idle_task_main() -> ! {
    log::info!("[sched][idle] started");
    loop {
        // Be explicit on SMP: never rely on inherited IF state.
        // If IF=0, HLT can deadlock that CPU forever.
        crate::arch::x86_64::sti();

        // Halt until next interrupt (saves power, timer will wake us)
        crate::arch::x86_64::hlt();
    }
}
