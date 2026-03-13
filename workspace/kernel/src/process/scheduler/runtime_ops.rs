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
        // E9: check if lock is already held before attempting acquire
        let lock_is_held = SCHEDULER.owner_cpu() != usize::MAX;
        crate::e9_println!("FS0 cpu={} lock_held={} locked_raw={}", cpu_index, lock_is_held, {
            let addr = crate::process::scheduler::debug_scheduler_lock_addr() as *const core::sync::atomic::AtomicBool;
            // SAFETY: address is the locked field of SCHEDULER (first field, offset 0)
            unsafe { (*addr).load(core::sync::atomic::Ordering::Relaxed) }
        });
        let mut spins = 0usize;
        let mut scheduler = loop {
            crate::e9_println!("FS1 cpu={} spin={}", cpu_index, spins);
            if let Some(guard) = SCHEDULER.try_lock() {
                crate::e9_println!("FS2 cpu={} acquired", cpu_index);
                break guard;
            }
            crate::e9_println!("FS3 cpu={} try failed", cpu_index);
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
            task_to_drop = drain_post_switch_locked(sched, cpu_index, true, true);
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

fn drain_post_switch_locked(
    sched: &mut Scheduler,
    cpu_index: usize,
    verbose_trace: bool,
    take_drop: bool,
) -> Option<Arc<Task>> {
    let mut task_to_drop = None;
    let mut requeue_task = None;
    if let Some(cpu) = sched.cpus.get_mut(cpu_index) {
        if take_drop {
            task_to_drop = cpu.task_to_drop.take();
        }
        requeue_task = cpu.task_to_requeue.take();
    }
    if let Some(task) = requeue_task {
        if verbose_trace {
            crate::serial_force_println!(
                "[trace][sched] finish_switch requeue cpu={} tid={}",
                cpu_index,
                task.id.as_u64()
            );
        } else {
            crate::e9_println!("IFSQ cpu={} tid={}", cpu_index, task.id.as_u64());
        }
        let class = sched.class_table.class_for_task(&task);
        if !verbose_trace {
            crate::e9_println!("IFSC cpu={} class={:?}", cpu_index, class);
        }
        if let Some(cpu) = sched.cpus.get_mut(cpu_index) {
            cpu.class_rqs.enqueue(class, task);
            if !verbose_trace {
                crate::e9_println!("IFSE cpu={} enqueued", cpu_index);
            }
        }
    }
    task_to_drop
}

/// Finalize a preemption-driven switch once the raw timer stub has already
/// moved onto the next task's kernel stack.
///
/// This mirrors Redox's `switch_finish_hook` and Maestro's `switch_finish`:
/// requeue/drop of the old task happens only after the architectural switch is
/// complete, so another CPU cannot steal the old task while its FPU/stack state
/// is still in flight.
pub fn finish_interrupt_switch() {
    // Debug: track call depth
    static FINISH_SWITCH_DEPTH: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
    let depth = FINISH_SWITCH_DEPTH.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    if depth > 5 {
        crate::serial_force_println!("[PANIC] finish_interrupt_switch depth={} - infinite recursion?", depth);
    }
    
    let cpu_index = current_cpu_index();
    crate::e9_println!("IFS0 cpu={} depth={}", cpu_index, depth);

    // Debug: check IRQ state
    let irq_enabled = crate::arch::x86_64::interrupts_enabled();
    crate::e9_println!("IFS0-irq cpu={} irq_enabled={}", cpu_index, irq_enabled);

    // Debug: check lock state
    let lock_addr = &SCHEDULER as *const _ as usize;
    crate::e9_println!("IFS0-lock cpu={} lock_addr={:#x}", cpu_index, lock_addr);
    
    // Debug: validate current task state
    if let Some(current) = current_task_clone_try() {
        let state = unsafe { *current.state.get() };
        let stack_base = current.kernel_stack.virt_base.as_u64();
        let stack_size = current.kernel_stack.size;
        let stack_top = stack_base + stack_size as u64;
        
        // Estimate stack usage by scanning for non-zero values
        let mut stack_used = 0usize;
        unsafe {
            let stack_ptr = stack_top as *const u64;
            for i in 0..(stack_size / 8) {
                if *stack_ptr.offset(-(i as isize)) != 0 {
                    stack_used = (i + 1) * 8;
                }
            }
        }
        
        crate::e9_println!(
            "IFS0-task cpu={} tid={} state={:?} stack={:#x}+{} used={}",
            cpu_index,
            current.id.as_u64(),
            state,
            stack_base,
            stack_size,
            stack_used
        );
        
        // Warn if stack usage exceeds 50%
        if stack_used > stack_size / 2 {
            crate::serial_force_println!(
                "IFS0-STACK-WARNING cpu={} tid={} used={}/{} ({}%)",
                cpu_index,
                current.id.as_u64(),
                stack_used,
                stack_size,
                stack_used * 100 / stack_size
            );
        }
        
        // Check stack canary (placed at stack_top - 8 in CpuContext::new)
        let canary_addr = stack_top - 8;
        let canary = unsafe { *(canary_addr as *const u64) };
        const STACK_CANARY: u64 = 0xDEADBEEFCAFEBABE;
        if canary != STACK_CANARY {
            // Also check nearby locations
            let canary_below = unsafe { *(canary_addr as *const u64).offset(-1) };
            let canary_at = unsafe { *(canary_addr as *const u64) };
            let canary_above = unsafe { *(stack_top as *const u64) };
            crate::serial_force_println!(
                "IFS0-STACK-CORRUPT cpu={} tid={} canary={:#x} expected={:#x} used={}/{} addr={:#x}",
                cpu_index,
                current.id.as_u64(),
                canary,
                STACK_CANARY,
                stack_used,
                stack_size,
                canary_addr
            );
            crate::serial_force_println!(
                "IFS0-STACK-DEBUG cpu={} below={:#x} at={:#x} top={:#x}",
                cpu_index,
                canary_below,
                canary_at,
                canary_above
            );
        }
        
        // Check underflow canary (placed at stack_base + 256 in seed_interrupt_frame)
        let underflow_canary_addr = stack_base + 256;
        let underflow_canary = unsafe { *(underflow_canary_addr as *const u64) };
        const UNDERFLOW_CANARY: u64 = 0xBAD57ACBAD57AC;
        if underflow_canary != UNDERFLOW_CANARY {
            crate::serial_force_println!(
                "IFS0-STACK-UNDERFLOW cpu={} tid={} canary={:#x} expected={:#x} addr={:#x}",
                cpu_index,
                current.id.as_u64(),
                underflow_canary,
                UNDERFLOW_CANARY,
                underflow_canary_addr
            );
        }
        
        // Also check a few bytes below stack_top for overflow
        let overflow_check = unsafe { *(stack_top as *const u64).offset(-1) };
        if overflow_check != 0 && overflow_check != STACK_CANARY {
            crate::serial_force_println!(
                "IFS0-STACK-OVERFLOW cpu={} tid={} overflow_val={:#x}",
                cpu_index,
                current.id.as_u64(),
                overflow_check
            );
        }
    }

    let mut task_to_drop = None;
    let mut spins = 0usize;
    let mut max_spins = 100_000_000; // Limit spins to detect hang
    loop {
        // Debug: check IRQ state on each iteration
        if spins % 10_000_000 == 0 && spins > 0 {
            let irq = crate::arch::x86_64::interrupts_enabled();
            crate::e9_println!("IFS1-spin cpu={} spins={} irq={}", cpu_index, spins, irq);
        }

        if let Some(mut scheduler) = SCHEDULER.try_lock_no_irqsave() {
            crate::e9_println!("IFS1 cpu={} acquired", cpu_index);
            if let Some(ref mut sched) = *scheduler {
                task_to_drop = drain_post_switch_locked(sched, cpu_index, false, false);
            }
            break;
        }
        spins = spins.saturating_add(1);
        if spins >= max_spins {
            crate::serial_force_println!("IFS1-HANG cpu={} spins={} irq={}", cpu_index, spins, crate::arch::x86_64::interrupts_enabled());
            // Debug: try to get lock state
            unsafe {
                let lock_ptr = &SCHEDULER as *const _ as *const u8;
                let locked = core::ptr::read_volatile(lock_ptr.add(0x10) as *const bool);
                let owner = core::ptr::read_volatile(lock_ptr.add(0x11) as *const usize);
                crate::serial_force_println!("IFS1-DEBUG cpu={} locked={} owner={}", cpu_index, locked, owner);
            }
            panic!("IFS1 hang detected - scheduler lock unavailable");
        }
        core::hint::spin_loop();
    }
    let _ = task_to_drop;
    crate::e9_println!("IFS2 cpu={} done", cpu_index);
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
        let mut scheduler = match SCHEDULER.try_lock_no_irqsave() {
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
            if take_force_resched_hint(cpu_index) {
                cpu.need_resched = true;
                crate::e9_println!("MP force-resched hint cpu={}", cpu_index);
            }
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
            // One-shot per-CPU: trace the very first real preemption.
            // NOTE: do NOT acquire SCHEDULER here — we are between the lock
            // release (end of the block above) and do_switch_context. A
            // nested try_lock in this window re-enters the guardian (CLI +
            // CAS) on a CPU that is about to switch stacks, producing a
            // spurious second "locked_raw=true" observation in finish_switch
            // diagnostics and, if the lock happens to be free, a redundant
            // owner_cpu store on the wrong context.
            if !FIRST_PREEMPT_LOGGED[cpu_index].swap(true, Ordering::Relaxed) {
                let preempt_n = CPU_PREEMPT_COUNT[cpu_index].load(Ordering::Relaxed);
                crate::e9_println!(
                    "FIRST_PREEMPT cpu={} count={}",
                    cpu_index,
                    preempt_n,
                );
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
        crate::e9_println!("IRQNP cpu={}", cpu_index);
        return None;
    }

    let current_frame_rsp = current_frame as *mut crate::syscall::SyscallFrame as u64;
    let mut task_to_drop: Option<Arc<Task>> = None;

    let decision = {
        let mut scheduler = match SCHEDULER.try_lock_no_irqsave() {
            Some(guard) => guard,
            None => {
                note_try_lock_fail_on_cpu(cpu_index);
                return None;
            }
        };

        let Some(ref mut sched) = *scheduler else {
            return None;
        };

        {
            let cpu = match sched.cpus.get_mut(cpu_index) {
                Some(cpu) => cpu,
                None => return None,
            };
            if take_force_resched_hint(cpu_index) {
                cpu.need_resched = true;
                crate::e9_println!("MPI force-resched hint cpu={}", cpu_index);
            }
            if cpu.current_task.is_none() || !cpu.need_resched {
                crate::e9_println!(
                    "IRQSKIP cpu={} current={} need={}",
                    cpu_index,
                    cpu.current_task
                        .as_ref()
                        .map(|t| t.id.as_u64())
                        .unwrap_or(0),
                    cpu.need_resched
                );
                return None;
            }
            if let Some(current) = cpu.current_task.as_ref() {
                sched_trace(format_args!(
                    "cpu={} irq-preempt request task={} rt_delta={}",
                    cpu_index,
                    current.id.as_u64(),
                    cpu.current_runtime.period_delta_ticks
                ));
            }
        }

        let current = sched.cpus[cpu_index]
            .current_task
            .as_ref()
            .cloned()
            .expect("irq-preempt current_task disappeared");
        current.set_resume_kind(crate::process::task::ResumeKind::IretFrame);
        current.set_interrupt_rsp(current_frame_rsp);
        crate::e9_println!(
            "IRQSAVE cpu={} tid={} rsp={:#x}",
            cpu_index,
            current.id.as_u64(),
            current_frame_rsp
        );

        let next = sched.pick_next_task(cpu_index);

        if Arc::ptr_eq(&current, &next) {
            if let Some(cpu) = sched.cpus.get_mut(cpu_index) {
                cpu.need_resched = false;
            }
            task_to_drop = sched.cpus[cpu_index].task_to_drop.take();
            crate::e9_println!("IRQNOSW cpu={} tid={}", cpu_index, current.id.as_u64());
            None
        } else {
            let mut next_rsp = next.interrupt_rsp();
            if next.resume_kind() == crate::process::task::ResumeKind::RetFrame {
                if next.is_kernel() {
                    next.seed_kernel_interrupt_frame_from_context();
                    next_rsp = next.interrupt_rsp();
                    let seed_rip = unsafe {
                        let saved_rsp = (*next.context.get()).saved_rsp as *const u64;
                        *saved_rsp.add(6)
                    };
                    crate::e9_println!(
                        "IRQSEED cpu={} tid={} rip={:#x}",
                        cpu_index,
                        next.id.as_u64(),
                        seed_rip
                    );
                } else {
                    crate::e9_println!(
                        "IRQMISS cpu={} tid={} kind={:?}",
                        cpu_index,
                        next.id.as_u64(),
                        next.resume_kind()
                    );
                }
            }
            if next_rsp == 0 || !interrupt_frame_fits(&next, next_rsp) {
                let is_idle_fallback = Arc::ptr_eq(&next, &sched.cpus[cpu_index].idle_task);
                task_to_drop = sched.cpus[cpu_index].task_to_drop.take();

                if let Some(prev) = sched.cpus[cpu_index].task_to_requeue.take() {
                    unsafe {
                        *prev.state.get() = TaskState::Running;
                    }
                    sched.cpus[cpu_index].current_task = Some(prev);
                } else {
                    unsafe {
                        *current.state.get() = TaskState::Running;
                    }
                    sched.cpus[cpu_index].current_task = Some(current.clone());
                }

                if !is_idle_fallback {
                    unsafe {
                        *next.state.get() = TaskState::Ready;
                    }
                    let class = sched.class_table.class_for_task(&next);
                    sched.cpus[cpu_index].class_rqs.enqueue(class, next);
                }
                crate::e9_println!("IRQABORT cpu={} prev={}", cpu_index, current.id.as_u64());
                None
            } else {
                next.set_resume_kind(crate::process::task::ResumeKind::IretFrame);
                if let Some(cpu) = sched.cpus.get_mut(cpu_index) {
                    cpu.need_resched = false;
                }
                // Do NOT drain `task_to_requeue` / `task_to_drop` here.
                // The raw timer stub still has to save the outgoing FPU state and
                // pivot onto the next task's stack. Defer that finalization to
                // `finish_interrupt_switch()` on the new stack, matching the
                // post-switch hooks used by Redox and Maestro.

                let stack_top = next.kernel_stack.virt_base.as_u64() + next.kernel_stack.size as u64;
                let stack_base = next.kernel_stack.virt_base.as_u64();

                // Debug: validate next_rsp is within stack bounds
                if next_rsp < stack_base || next_rsp > stack_top {
                    crate::serial_force_println!(
                        "IRQSW-STACK-BOUNDS cpu={} next_rsp={:#x} base={:#x} top={:#x} size={}",
                        cpu_index,
                        next_rsp,
                        stack_base,
                        stack_top,
                        next.kernel_stack.size
                    );
                }

                // Extract frame info before switch
                let (next_cs, next_rip) = unsafe {
                    let frame = &*(next_rsp as *const crate::syscall::SyscallFrame);
                    (frame.iret_cs, frame.iret_rip)
                };

                // Debug: check distance from stack top
                let dist_from_top = stack_top - next_rsp;
                crate::e9_println!(
                    "IRQSW cpu={} prev={} next={} rsp={:#x} cs={:#x} rip={:#x} stack_base={:#x} dist_from_top={}",
                    cpu_index,
                    current.id.as_u64(),
                    next.id.as_u64(),
                    next_rsp,
                    next_cs,
                    next_rip,
                    stack_base,
                    dist_from_top
                );

                crate::arch::x86_64::tss::set_kernel_stack(x86_64::VirtAddr::new(stack_top));
                crate::arch::x86_64::syscall::set_kernel_rsp(stack_top);
                unsafe {
                    (*next.process.address_space.get()).switch_to();
                }

                // Debug: validate FPU pointers before switch
                let old_fpu_ptr = current.fpu_state.get();
                let new_fpu_ptr = next.fpu_state.get();
                let old_fpu = old_fpu_ptr as *mut u8;
                let new_fpu = new_fpu_ptr as *const u8;
                let old_fpu_aligned = (old_fpu as usize) & 0x3F;  // 64-byte alignment
                let new_fpu_aligned = (new_fpu as usize) & 0x3F;
                
                // Get ExtendedState metadata
                let old_size = unsafe { (*old_fpu_ptr).size };
                let new_size = unsafe { (*new_fpu_ptr).size };
                let old_uses_xsave = unsafe { (*old_fpu_ptr).uses_xsave };
                let new_uses_xsave = unsafe { (*new_fpu_ptr).uses_xsave };
                
                crate::e9_println!(
                    "IRQFPU cpu={} old={:#x}(align={},size={},xsave={}) new={:#x}(align={},size={},xsave={})",
                    cpu_index,
                    old_fpu as usize,
                    old_fpu_aligned,
                    old_size,
                    old_uses_xsave,
                    new_fpu as usize,
                    new_fpu_aligned,
                    new_size,
                    new_uses_xsave
                );
                
                // Validate pointers are non-null and aligned for FXSAVE (16-byte min)
                if old_fpu.is_null() || new_fpu.is_null() {
                    crate::serial_force_println!(
                        "IRQFPU-NULL cpu={} old_null={} new_null={}",
                        cpu_index,
                        old_fpu.is_null(),
                        new_fpu.is_null()
                    );
                }
                if (old_fpu as usize) & 0xF != 0 || (new_fpu as usize) & 0xF != 0 {
                    crate::serial_force_println!(
                        "IRQFPU-MISALIGN-16 cpu={} old_align={} new_align={}",
                        cpu_index,
                        (old_fpu as usize) & 0xF,
                        (new_fpu as usize) & 0xF
                    );
                }
                if old_fpu_aligned != 0 || new_fpu_aligned != 0 {
                    crate::serial_force_println!(
                        "IRQFPU-MISALIGN-64 cpu={} old_align={} new_align={}",
                        cpu_index,
                        old_fpu_aligned,
                        new_fpu_aligned
                    );
                }

                Some(crate::arch::x86_64::idt::InterruptReturnDecision {
                    next_rsp,
                    old_fpu,
                    new_fpu,
                })
            }
        }
    };  // <- scheduler guard dropped here

    // Debug: confirm lock was released
    if decision.is_some() {
        crate::e9_println!("MPI-unlock cpu={} decision=SWITCH", cpu_index);
    }

    drop(task_to_drop);

    if decision.is_some() && cpu_is_valid(cpu_index) {
        if !FIRST_PREEMPT_LOGGED[cpu_index].swap(true, Ordering::Relaxed) {
            let preempt_n = CPU_PREEMPT_COUNT[cpu_index].load(Ordering::Relaxed);
            crate::e9_println!("FIRST_IRQ_PREEMPT cpu={} count={}", cpu_index, preempt_n);
        }
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
