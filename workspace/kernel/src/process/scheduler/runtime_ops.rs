use super::*;

static FINISH_INTERRUPT_TRACE_BUDGET: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(32);

/// Initialize the scheduler
pub fn init_scheduler() {
    // Build scheduler state only for CPUs that are actually online. Using the
    // registered per-CPU count here can strand runnable tasks on AP slots that
    // never reached the scheduler gate.
    let cpu_count = crate::arch::x86_64::smp::cpu_count().max(1);
    crate::serial_println!(
        "[trace][sched] init_scheduler enter cpu_count={}",
        cpu_count
    );
    // Build the scheduler outside the global scheduler lock to avoid
    // lock-order inversions (`GLOBAL_SCHED_STATE -> allocator`) during task/stack
    // allocation in `GlobalSchedState::new`.
    let new_sched = GlobalSchedState::new();
    // Initialize per-CPU scheduler state for each active CPU.
    for i in 0..cpu_count {
        let cpu_sched = super::core_impl::create_cpu_scheduler(i);
        *LOCAL_SCHEDULERS[i].lock() = Some(cpu_sched);
    }
    crate::serial_println!("[trace][sched] init_scheduler new() done");

    // Race/corruption diagnostic: register scheduler lock for E9 LOCK-A/LOCK-R traces.
    crate::sync::debug_set_trace_lock_addr(debug_scheduler_lock_addr());

    let mut scheduler = GLOBAL_SCHED_STATE.lock();
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
        if let Some(guard) = GLOBAL_SCHED_STATE.try_lock() {
            break guard;
        }
        spins = spins.saturating_add(1);
        if spins == 2_000_000 {
            crate::serial_force_println!(
                "[trace][sched] add_task waiting lock tid={} owner_cpu={}",
                tid.as_u64(),
                GLOBAL_SCHED_STATE.owner_cpu()
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
        let mut scheduler = GLOBAL_SCHED_STATE.lock();
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
    crate::e9_println!("BD-ENTER cpu={}", cpu_index);
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
    // Interrupts are re-enabled by the RFLAGS seed (0x202, IF=1) stored in
    // each task's bootstrap interrupt frame, so no explicit sti() is needed.
    crate::arch::x86_64::cli();

    // APs may arrive here before the BSP has called init_scheduler().
    // Spin-wait (releasing the lock each iteration) until the scheduler
    // is initialized, then pick the first task.
    let mut wait_iters: u64 = 0;
    let first_task = loop {
        let scheduler = GLOBAL_SCHED_STATE.lock();
        if let Some(ref _sched) = *scheduler {
            if wait_iters > 0 {
                crate::e9_println!("BD first_task cpu={} waited={}", cpu_index, wait_iters);
            }
            drop(scheduler);
            // Pick first task via LOCAL per-CPU state.
            let idx = if cpu_index < active_cpu_count() {
                cpu_index
            } else {
                0
            };
            let mut local = LOCAL_SCHEDULERS[idx].lock();
            if let Some(ref mut cpu) = *local {
                break super::core_impl::pick_next_task_local(cpu, idx);
            }
            // LOCAL not ready yet — drop and spin.
            drop(local);
            wait_iters = wait_iters.saturating_add(1);
            if wait_iters == 1 || (wait_iters % 1_000_000 == 0 && wait_iters > 0) {
                crate::e9_println!("BD-WAIT-LOCAL cpu={} iters={}", cpu_index, wait_iters);
            }
            core::hint::spin_loop();
            continue;
        }
        // Drop lock before spinning so the BSP can initialize the scheduler.
        drop(scheduler);
        wait_iters = wait_iters.saturating_add(1);
        if wait_iters == 1 || (wait_iters % 1_000_000 == 0 && wait_iters > 0) {
            crate::e9_println!("BD-WAIT cpu={} iters={}", cpu_index, wait_iters);
        }
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
        first_task.process.address_space_arc().switch_to();
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
    crate::serial_force_println!(
        "[trace][sched] schedule_on_cpu calling do_restore_first_task cpu={} tid={} rsp={:#x}",
        cpu_index,
        first_task.id.as_u64(),
        unsafe { (*first_task.context.get()).saved_rsp }
    );
    unsafe {
        // Pass the stack frame pointer (saved_rsp points TO the frame, not the context struct)
        let frame_ptr = (*first_task.context.get()).saved_rsp as *const u64;
        crate::process::task::do_restore_first_task(
            frame_ptr,
            first_task.fpu_state.get() as *const u8,
            first_task
                .xcr0_mask
                .load(core::sync::atomic::Ordering::Relaxed),
        );
    }
    // Should never reach here
    crate::serial_force_println!(
        "[PANIC] restore_first_task returned! cpu={} tid={}",
        cpu_index,
        first_task.id.as_u64()
    );
}

/// Called immediately after a context switch completes (in the new task's context).
/// This safely re-queues the previously running task now that its state is fully saved.
///
/// Mirrors Redox switch_finish_hook: minimal work, no serial (avoids lock contention).
pub fn finish_switch() {
    let _perf = super::perf_counters::PerfScope::new(
        &super::perf_counters::CTX_SWITCH_TSC,
        &super::perf_counters::CTX_SWITCH_COUNT,
    );
    let cpu_index = current_cpu_index();
    let mut task_to_drop = None;
    {
        // Use LOCAL lock — no spinning on GLOBAL_SCHED_STATE needed.
        let mut spins = 0usize;
        let mut guard = loop {
            if let Some(g) = LOCAL_SCHEDULERS[cpu_index].try_lock_no_irqsave() {
                break g;
            }
            spins = spins.saturating_add(1);
            if spins % 1_000_000 == 0 {
                unsafe { core::arch::asm!("mov al, 'W'; out 0xe9, al", out("al") _) };
            }
            core::hint::spin_loop();
        };
        if let Some(ref mut cpu) = *guard {
            // Activate the address space for the current task on this CPU.
            if let Some(ref task) = cpu.current_task {
                unsafe { task.process.address_space_arc().switch_to() };
            }
            task_to_drop = super::core_impl::drain_post_switch_local(cpu, true);
        }
    }

    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    super::task_ops::flush_deferred_silo_cleanups();
    drop(task_to_drop);
}

/// Finalize a preemption-driven switch once the raw timer stub has already
/// moved onto the next task's kernel stack.
///
/// This mirrors Redox's `switch_finish_hook` and Maestro's `switch_finish`:
/// requeue/drop of the old task happens only after the architectural switch is
/// complete, so another CPU cannot steal the old task while its FPU/stack state
/// is still in flight.
pub fn finish_interrupt_switch() {
    let _perf = super::perf_counters::PerfScope::new(
        &super::perf_counters::CTX_SWITCH_TSC,
        &super::perf_counters::CTX_SWITCH_COUNT,
    );
    let cpu_index = current_cpu_index();
    let should_trace = FINISH_INTERRUPT_TRACE_BUDGET
        .fetch_update(
            core::sync::atomic::Ordering::AcqRel,
            core::sync::atomic::Ordering::Relaxed,
            |budget| budget.checked_sub(1),
        )
        .is_ok();
    let entry_rsp0 = crate::arch::x86_64::tss::kernel_stack_for(cpu_index)
        .map(|addr| addr.as_u64())
        .unwrap_or(0);
    if should_trace {
        crate::e9_println!("[ifs-enter] cpu={} rsp0={:#x}", cpu_index, entry_rsp0);
    }

    // Spin until GLOBAL_SCHED_STATE is available (released by maybe_preempt_from_interrupt
    // before returning to this assembly stub).  We must not block with IRQs enabled
    // because we are still inside the timer interrupt handler.  try_lock_no_irqsave
    // requires IRQs already disabled, which is guaranteed here.
    //
    // The spin is bounded: if the lock is not released within MAX_IFS_SPINS
    // iterations something is fundamentally broken (holder deadlocked, or
    // lock corruption).  Panic so we get a stack trace instead of a silent
    // hang.
    // This is around few seconds on recent CPU.

    // Use LOCAL lock — no spinning on GLOBAL_SCHED_STATE. The LOCAL lock for this CPU
    // is released quickly by maybe_preempt_from_interrupt before we get here.
    const MAX_IFS_SPINS: usize = 50_000_000;
    let mut task_to_drop = None;
    let mut spins = 0usize;
    loop {
        if let Some(mut guard) = LOCAL_SCHEDULERS[cpu_index].try_lock_no_irqsave() {
            if let Some(ref mut cpu) = *guard {
                // REQUEUE OLD TASK FIRST (while current AS is still active/stable)
                task_to_drop = super::core_impl::drain_post_switch_local(cpu, false);

                // NOW SWITCH TO NEW ADDRESS SPACE
                if let Some(ref task) = cpu.current_task {
                    let task_stack_top =
                        task.kernel_stack.virt_base.as_u64() + task.kernel_stack.size as u64;
                    if should_trace {
                        crate::e9_println!(
                            "[ifs-task] cpu={} tid={} rsp0={:#x} expected={:#x}",
                            cpu_index,
                            task.id.as_u64(),
                            entry_rsp0,
                            task_stack_top
                        );
                    }
                    if should_trace && entry_rsp0 != 0 && entry_rsp0 != task_stack_top {
                        crate::e9_println!(
                            "[ifs-rsp0-mismatch] cpu={} tid={} rsp0={:#x} expected={:#x}",
                            cpu_index,
                            task.id.as_u64(),
                            entry_rsp0,
                            task_stack_top
                        );
                    }
                    unsafe { task.process.address_space_arc().switch_to() };
                }
            }
            break;
        }
        spins = spins.saturating_add(1);
        if spins >= MAX_IFS_SPINS {
            crate::e9_println!(
                "[BUG] finish_interrupt_switch: LOCAL lock not released after {} spins, cpu={}",
                spins,
                cpu_index
            );
            panic!(
                "finish_interrupt_switch: LOCAL lock stuck after {} spins on cpu {}",
                spins, cpu_index
            );
        }
        core::hint::spin_loop();
    }
    let _ = task_to_drop;
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
    let _perf = super::perf_counters::PerfScope::new(
        &super::perf_counters::SCHED_YIELD_TSC,
        &super::perf_counters::SCHED_YIELD_COUNT,
    );

    // Save RFLAGS and disable interrupts to prevent timer from
    // trying to lock the scheduler while we hold it
    let saved_flags = save_flags_and_cli();
    let cpu_index = current_cpu_index();

    let switch_target = {
        let mut local = LOCAL_SCHEDULERS[cpu_index].lock();
        if let Some(ref mut cpu) = *local {
            super::core_impl::yield_cpu_local(cpu, cpu_index)
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

/// Force a context switch away from the current task, unconditionally.
///
/// Unlike [`yield_task`], this function **ignores the preemption guard**.
/// It must only be called from [`super::task_ops::exit_current_task`] after:
///
/// 1. The task has been marked [`TaskState::Dead`].
/// 2. All scheduler locks have been released.
/// 3. No spinlock-guarded per-CPU data is being accessed by this task.
///
/// At that point the preempt_count is irrelevant — the task will never run
/// again, so bypassing the guard is both safe and necessary to prevent the
/// dead task from spinning in a `hlt()` loop.
pub fn yield_dead_task() {
    let saved_flags = save_flags_and_cli();
    let cpu_index = current_cpu_index();

    let switch_target = {
        let mut local = LOCAL_SCHEDULERS[cpu_index].lock();
        if let Some(ref mut cpu) = *local {
            super::core_impl::yield_cpu_local(cpu, cpu_index)
        } else {
            None
        }
    }; // Lock released before the context switch.

    if let Some(ref target) = switch_target {
        // SAFETY: Pointers are valid (Arc<Task> contexts kept alive by the
        // scheduler).  Interrupts are disabled via save_flags_and_cli().
        unsafe {
            crate::process::task::do_switch_context(target);
        }
        finish_switch();
    }

    restore_flags(saved_flags);
}

#[inline]
fn interrupt_frame_fits(task: &Arc<Task>, rsp: u64) -> bool {
    let stack_base = task.kernel_stack.virt_base.as_u64();
    let stack_top = stack_base + task.kernel_stack.size as u64;
    let frame_size = core::mem::size_of::<crate::syscall::SyscallFrame>() as u64;
    rsp >= stack_base && rsp.saturating_add(frame_size) <= stack_top
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
    let _perf = super::perf_counters::PerfScope::new(
        &super::perf_counters::SCHED_PREEMPT_TSC,
        &super::perf_counters::SCHED_PREEMPT_COUNT,
    );
    let cpu_index = current_cpu_index();
    if cpu_is_valid(cpu_index) {
        RESCHED_IPI_PENDING[cpu_index].store(false, Ordering::Release);
    }

    // Honour the preemption guard - never preempt a section that asked for it.
    if !percpu::is_preemptible() {
        return;
    }

    // Use the per-CPU LOCAL lock — never blocked by another CPU's cold-path
    // operations (fork, exit, wake) that hold GLOBAL_SCHED_STATE.
    let switch_target = {
        let mut guard = match LOCAL_SCHEDULERS[cpu_index].try_lock_no_irqsave() {
            Some(g) => g,
            None => {
                note_try_lock_fail_on_cpu(cpu_index);
                return;
            }
        };
        let cpu = match guard.as_mut() {
            Some(c) => c,
            None => return,
        };
        if take_force_resched_hint(cpu_index) {
            cpu.need_resched = true;
        }
        if cpu.current_task.is_none() || !cpu.need_resched {
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
        super::core_impl::yield_cpu_local(cpu, cpu_index)
    }; // LOCAL lock released here

    if let Some(ref target) = switch_target {
        if cpu_is_valid(cpu_index) {
            // One-shot per-CPU: trace the very first real preemption.
            // NOTE: do NOT acquire GLOBAL_SCHED_STATE here — we are between the lock
            // release (end of the block above) and do_switch_context. A
            // nested try_lock in this window re-enters the guardian (CLI +
            // CAS) on a CPU that is about to switch stacks, producing a
            // spurious second "locked_raw=true" observation in finish_switch
            // diagnostics and, if the lock happens to be free, a redundant
            // owner_cpu store on the wrong context.
            if !FIRST_PREEMPT_LOGGED[cpu_index].swap(true, Ordering::Relaxed) {
                let _preempt_n = CPU_PREEMPT_COUNT[cpu_index].load(Ordering::Relaxed);
            }
            CPU_PREEMPT_COUNT[cpu_index].fetch_add(1, Ordering::Relaxed);
        }
        unsafe {
            crate::process::task::do_switch_context(target);
        }
        finish_switch();
    }
}

/// Interrupt-aware preemption path.
///
/// Unlike the legacy `ret`-based scheduler path, the full interrupted user
/// context is already materialized as a `SyscallFrame` on the current kernel
/// stack. This lets us save the outgoing task immediately, select the next
/// runnable task under the scheduler lock, and return an `iretq`-compatible
/// frame pointer for the raw timer stub.
pub fn maybe_preempt_from_interrupt(
    cpu_index: usize,
    current_frame: &mut crate::syscall::SyscallFrame,
) -> Option<crate::arch::x86_64::idt::InterruptReturnDecision> {
    if cpu_is_valid(cpu_index) {
        RESCHED_IPI_PENDING[cpu_index].store(false, Ordering::Release);
    }

    if !percpu::is_preemptible() {
        return None;
    }

    let current_frame_rsp = current_frame as *mut crate::syscall::SyscallFrame as u64;
    let mut _task_to_drop: Option<Arc<Task>> = None;

    let decision = {
        // Use per-CPU LOCAL lock — not blocked by cold-path global operations.
        let mut guard = match LOCAL_SCHEDULERS[cpu_index].try_lock_no_irqsave() {
            Some(g) => g,
            None => {
                note_try_lock_fail_on_cpu(cpu_index);
                return None;
            }
        };
        let cpu = match guard.as_mut() {
            Some(c) => c,
            None => return None,
        };

        if take_force_resched_hint(cpu_index) {
            cpu.need_resched = true;
        }
        if cpu.current_task.is_none() || !cpu.need_resched {
            return None;
        }

        unsafe { core::arch::asm!("mov al, '1'; out 0xe9, al", out("al") _) };
        let current = match cpu.current_task.as_ref() {
            Some(t) => t.clone(),
            None => {
                unsafe { core::arch::asm!("mov al, 'X'; out 0xe9, al", out("al") _) };
                return None;
            }
        };
        unsafe { core::arch::asm!("mov al, '2'; out 0xe9, al", out("al") _) };
        current.set_resume_kind(crate::process::task::ResumeKind::IretFrame);
        current.set_interrupt_rsp(current_frame_rsp);

        let next = super::core_impl::pick_next_task_local(cpu, cpu_index);

        if Arc::ptr_eq(&current, &next) {
            cpu.need_resched = false;
            _task_to_drop = cpu.task_to_drop.take();
            // No context switch: return current task's FPU area for save/restore.
            let current_fpu = current.fpu_state.get() as *mut u8;
            Some(crate::arch::x86_64::idt::InterruptReturnDecision {
                next_rsp: 0,
                old_fpu: current_fpu,
                new_fpu: current_fpu,
            })
        } else {
            let mut next_rsp = next.interrupt_rsp();
            if next.resume_kind() == crate::process::task::ResumeKind::RetFrame {
                // All tasks (kernel and ELF user tasks) start their first execution
                // in Ring 0 via the task_entry_trampoline. We must seed a kernel
                // interrupt frame so that the interrupt return path (iretq) can
                // safely jump to the trampoline.
                next.seed_kernel_interrupt_frame_from_context();
                next_rsp = next.interrupt_rsp();
            }
            let fits = interrupt_frame_fits(&next, next_rsp);
            if next_rsp == 0 || !fits {
                unsafe { core::arch::asm!("mov al, 'A'; out 0xe9, al", out("al") _) };
                let is_idle_fallback = Arc::ptr_eq(&next, &cpu.idle_task);
                _task_to_drop = cpu.task_to_drop.take();

                if let Some(prev) = cpu.task_to_requeue.take() {
                    prev.set_state(TaskState::Running);
                    cpu.current_task = Some(prev);
                } else {
                    current.set_state(TaskState::Running);
                    cpu.current_task = Some(current.clone());
                }

                if !is_idle_fallback {
                    next.set_state(TaskState::Ready);
                    let class = cpu.class_table.class_for_task(&next);
                    cpu.class_rqs.enqueue(class, next);
                }
                // Abort switch: return current task's FPU area for save/restore.
                let current_fpu = current.fpu_state.get() as *mut u8;
                return Some(crate::arch::x86_64::idt::InterruptReturnDecision {
                    next_rsp: 0,
                    old_fpu: current_fpu,
                    new_fpu: current_fpu,
                });
            } else {
                next.set_resume_kind(crate::process::task::ResumeKind::IretFrame);
                cpu.need_resched = false;
                // Do NOT drain `task_to_requeue` / `task_to_drop` here.
                // The raw timer stub still has to save the outgoing FPU state and
                // pivot onto the next task's stack. Defer that finalization to
                // `finish_interrupt_switch()` on the new stack.

                let stack_top =
                    next.kernel_stack.virt_base.as_u64() + next.kernel_stack.size as u64;

                crate::arch::x86_64::tss::set_kernel_stack(x86_64::VirtAddr::new(stack_top));
                crate::arch::x86_64::syscall::set_kernel_rsp(stack_top);

                let old_fpu = current.fpu_state.get() as *mut u8;
                let new_fpu = next.fpu_state.get() as *const u8;

                Some(crate::arch::x86_64::idt::InterruptReturnDecision {
                    next_rsp,
                    old_fpu,
                    new_fpu,
                })
            }
        }
    }; // LOCAL lock released here

    if decision.is_some() && cpu_is_valid(cpu_index) {
        CPU_PREEMPT_COUNT[cpu_index].fetch_add(1, Ordering::Relaxed);
    }

    decision
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
        let scheduler = GLOBAL_SCHED_STATE.lock();
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
        let mut scheduler = GLOBAL_SCHED_STATE.lock();
        if let Some(ref mut sched) = *scheduler {
            let prev = sched.class_table;
            sched.class_table = table;
            let n = active_cpu_count();
            // Propagate the new class table to every LOCAL and set need_resched
            // in a single pass to avoid locking each LOCAL multiple times.
            for cpu_idx in 0..n {
                if let Some(ref mut local_cpu) = *LOCAL_SCHEDULERS[cpu_idx].lock() {
                    local_cpu.class_table = table;
                    local_cpu.need_resched = true;
                }
                if cpu_idx != my_cpu && cpu_is_valid(cpu_idx) {
                    ipi_targets[cpu_idx] = true;
                }
            }
            if prev.policy_map() != sched.class_table.policy_map() {
                sched.migrate_ready_tasks_for_new_class_table();
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
    let scheduler = GLOBAL_SCHED_STATE.lock();
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
        let n = active_cpu_count();
        for cpu_id in 0..n {
            use crate::process::sched::SchedClassRq;
            let local_guard = LOCAL_SCHEDULERS[cpu_id].lock();
            if let Some(ref cpu) = *local_guard {
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
        let scheduler = GLOBAL_SCHED_STATE.lock();
        if let Some(ref sched) = *scheduler {
            use crate::process::sched::SchedClassRq;
            let cpu_count = active_cpu_count().min(crate::arch::x86_64::percpu::MAX_CPUS);
            out.initialized = true;
            out.boot_phase = if cpu_count > 0 { 2 } else { 1 };
            out.cpu_count = cpu_count;
            out.pick_order = *sched.class_table.pick_order();
            out.steal_order = *sched.class_table.steal_order();
            out.blocked_tasks = sched.blocked_tasks.len();
            for i in 0..cpu_count {
                let local_guard = LOCAL_SCHEDULERS[i].lock();
                if let Some(ref cpu) = *local_guard {
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
    }
    restore_flags(saved_flags);
    out
}

/// The main function for the idle task
pub(super) extern "C" fn idle_task_main() -> ! {
    let cpu = crate::arch::x86_64::percpu::current_cpu_index();
    crate::serial_force_println!("[trace][sched] idle_task_main start cpu={}", cpu);
    loop {
        // Be explicit on SMP: never rely on inherited IF state.
        // If IF=0, HLT can deadlock that CPU forever.
        crate::arch::x86_64::sti();

        // Halt until next interrupt (saves power, timer will wake us)
        crate::arch::x86_64::hlt();
    }
}
