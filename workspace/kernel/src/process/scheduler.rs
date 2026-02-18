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

use super::task::{restore_first_task, switch_context, Task, TaskId, TaskPriority, TaskState};
use crate::{
    arch::x86_64::{apic, percpu, restore_flags, save_flags_and_cli, timer},
    capability::get_capability_manager,
    serial_println,
    sync::SpinLock,
    vga_println,
};
use alloc::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};
use core::sync::atomic::{AtomicU64, Ordering};

// ─── Cross-CPU IPI helpers ────────────────────────────────────────────────────

/// Send a reschedule IPI to `cpu_index`.
/// No-op if APIC is not initialized, or if `cpu_index` is the current CPU
/// (the caller already handles the local-CPU case via `yield_cpu`).
fn send_resched_ipi_to_cpu(cpu_index: usize) {
    if !apic::is_initialized() {
        return;
    }
    let my_apic = apic::lapic_id();
    if let Some(target_apic) = percpu::apic_id_by_cpu_index(cpu_index) {
        if target_apic != my_apic {
            apic::send_resched_ipi(target_apic);
        }
    }
}

/// The global scheduler instance
static SCHEDULER: SpinLock<Option<Scheduler>> = SpinLock::new(None);

/// Global tick counter (safe to increment from interrupt context)
static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Information needed to perform a context switch after releasing the lock.
struct SwitchTarget {
    /// Pointer to old task's saved_rsp (in CpuContext)
    old_rsp_ptr: *mut u64,
    /// Pointer to new task's saved_rsp (in CpuContext)
    new_rsp_ptr: *const u64,
}

// SAFETY: The pointers in SwitchTarget point into Arc<Task> objects
// that are kept alive by the scheduler. The scheduler lock ensures
// exclusive access when computing these pointers.
unsafe impl Send for SwitchTarget {}

fn current_cpu_index() -> usize {
    if apic::is_initialized() {
        let apic_id = apic::lapic_id();
        percpu::cpu_index_by_apic(apic_id).unwrap_or(0)
    } else {
        0
    }
}

/// Per-CPU scheduler state
struct SchedulerCpu {
    /// Queue of ready tasks
    ready_queue: VecDeque<Arc<Task>>,
    /// Currently running task
    current_task: Option<Arc<Task>>,
    /// Idle task to run when no other tasks are ready
    idle_task: Arc<Task>,
}

/// The round-robin scheduler (per-CPU queues)
pub struct Scheduler {
    /// Per-CPU scheduler state
    cpus: alloc::vec::Vec<SchedulerCpu>,
    /// Tasks blocked waiting for an event (keyed by TaskId for O(log n) wake)
    blocked_tasks: BTreeMap<TaskId, Arc<Task>>,
    /// All tasks in the system (for lookup by TaskId)
    all_tasks: BTreeMap<TaskId, Arc<Task>>,
    /// Map TaskId -> CPU index (for wake/resume routing)
    task_cpu: BTreeMap<TaskId, usize>,
    /// Timer interval for preemption (in milliseconds)
    quantum_ms: u64,
}

impl Scheduler {
    /// Create a new scheduler instance
    pub fn new(cpu_count: usize) -> Self {
        let mut cpus = alloc::vec::Vec::new();
        for _ in 0..cpu_count {
            let idle_task = Task::new_kernel_task(idle_task_main, "idle", TaskPriority::Idle)
                .expect("Failed to create idle task");
            cpus.push(SchedulerCpu {
                ready_queue: VecDeque::new(),
                current_task: None,
                idle_task,
            });
        }

        Scheduler {
            cpus,
            blocked_tasks: BTreeMap::new(),
            all_tasks: BTreeMap::new(),
            task_cpu: BTreeMap::new(),
            quantum_ms: 10, // 10ms time slice
        }
    }

    /// Add a task to the scheduler
    pub fn add_task(&mut self, task: Arc<Task>) {
        let cpu_index = self.select_cpu_for_task();
        self.add_task_on_cpu(task, cpu_index);
    }

    fn add_task_on_cpu(&mut self, task: Arc<Task>, cpu_index: usize) {
        // SAFETY: We have exclusive access via the scheduler lock
        unsafe {
            *task.state.get() = TaskState::Ready;
        }

        self.all_tasks.insert(task.id, task.clone());
        self.task_cpu.insert(task.id, cpu_index);
        if let Some(cpu) = self.cpus.get_mut(cpu_index) {
            cpu.ready_queue.push_back(task);
        }
    }

    /// Pick the next task to run on `cpu_index`.
    ///
    /// 1. Re-queues the current Running task (round-robin).
    /// 2. Pops from the local ready queue.
    /// 3. Falls back to **work-stealing** from the busiest other CPU.
    /// 4. Falls back to the per-CPU idle task.
    fn pick_next_task(&mut self, cpu_index: usize) -> Arc<Task> {
        // Step 1: take current task and re-queue it if still alive.
        let current_task = self.cpus[cpu_index].current_task.take();
        if let Some(task) = current_task {
            // SAFETY: scheduler lock held; we have exclusive access to state.
            let task_state = unsafe { *task.state.get() };
            if task_state == TaskState::Running {
                unsafe {
                    *task.state.get() = TaskState::Ready;
                }
                self.cpus[cpu_index].ready_queue.push_back(task);
            }
        }

        // Step 2: local queue, then work-steal, then idle.
        let next_task = if let Some(task) = self.cpus[cpu_index].ready_queue.pop_front() {
            task
        } else if let Some(task) = self.steal_task(cpu_index) {
            task
        } else {
            self.cpus[cpu_index].idle_task.clone()
        };

        // SAFETY: scheduler lock held.
        unsafe {
            *next_task.state.get() = TaskState::Running;
        }
        self.cpus[cpu_index].current_task = Some(next_task.clone());
        next_task
    }

    /// Try to steal one task from the most-loaded other CPU.
    ///
    /// We steal from the **back** of the source queue (the task added most
    /// recently — least likely to have warm cache data on that CPU).
    /// We only steal when the source has ≥ 2 tasks, so it keeps at least one.
    fn steal_task(&mut self, dst_cpu: usize) -> Option<Arc<Task>> {
        // Find the busiest CPU that isn't ourselves.
        let best_src = (0..self.cpus.len())
            .filter(|&i| i != dst_cpu)
            .max_by_key(|&i| self.cpus[i].ready_queue.len())?;

        // Only steal if source will still have work left.
        if self.cpus[best_src].ready_queue.len() < 2 {
            return None;
        }

        let task = self.cpus[best_src].ready_queue.pop_back()?;
        // Update the task→CPU mapping so wake/resume route correctly.
        self.task_cpu.insert(task.id, dst_cpu);
        log::trace!(
            "WS: CPU {} stole task {:?} from CPU {} (src had {} tasks)",
            dst_cpu,
            task.id,
            best_src,
            self.cpus[best_src].ready_queue.len() + 1
        );
        Some(task)
    }

    /// Prepare a context switch: pick next task, update TSS and CR3,
    /// return raw pointers for `switch_context()`.
    ///
    /// Returns `None` if there's nothing to switch to (same task selected,
    /// or no current task).
    fn yield_cpu(&mut self, cpu_index: usize) -> Option<SwitchTarget> {
        // Must have a current task to yield from
        let current = self.cpus[cpu_index].current_task.as_ref()?.clone();

        // Pick the next task
        let next = self.pick_next_task(cpu_index);

        // Don't switch to ourselves
        if Arc::ptr_eq(&current, &next) {
            return None;
        }

        // Update TSS.rsp0 for the new task (needed for Ring 3 → Ring 0 transitions)
        let stack_top = next.kernel_stack.virt_base.as_u64() + next.kernel_stack.size as u64;
        crate::arch::x86_64::tss::set_kernel_stack(x86_64::VirtAddr::new(stack_top));

        // Update SYSCALL kernel RSP for the new task
        crate::arch::x86_64::syscall::set_kernel_rsp(stack_top);

        // Switch CR3 if the new task has a different address space
        // SAFETY: The new task's address space has a valid PML4 with the kernel half mapped.
        unsafe {
            next.address_space.switch_to();
        }

        // Return raw pointers for switch_context
        Some(SwitchTarget {
            old_rsp_ptr: unsafe { &raw mut (*current.context.get()).saved_rsp },
            new_rsp_ptr: unsafe { &raw const (*next.context.get()).saved_rsp },
        })
    }

    fn select_cpu_for_task(&self) -> usize {
        let mut best = 0usize;
        let mut best_load = usize::MAX;
        for (idx, cpu) in self.cpus.iter().enumerate() {
            let mut load = cpu.ready_queue.len();
            if cpu.current_task.is_some() {
                load += 1;
            }
            if load < best_load {
                best = idx;
                best_load = load;
            }
        }
        best
    }
}

/// Initialize the scheduler
pub fn init_scheduler() {
    let cpu_count = percpu::cpu_count().max(1);
    let mut scheduler = SCHEDULER.lock();
    *scheduler = Some(Scheduler::new(cpu_count));
    drop(scheduler); // Release the lock

    // Only initialize legacy PIT if APIC timer is not active
    if !timer::is_apic_timer_active() {
        timer::init_pit(100); // 100Hz = 10ms interval for quantum
        log::info!("Scheduler: using legacy PIT timer (100Hz)");
    } else {
        log::info!("Scheduler: using APIC timer (100Hz)");
    }
}

/// Add a task to the scheduler
pub fn add_task(task: Arc<Task>) {
    let mut scheduler = SCHEDULER.lock();
    if let Some(ref mut sched) = *scheduler {
        sched.add_task(task);
    }
}

/// Start the scheduler (called from kernel_main)
///
/// Picks the first task and starts running it. Never returns.
pub fn schedule() -> ! {
    let cpu_index = current_cpu_index();
    schedule_on_cpu(cpu_index)
}

pub fn schedule_on_cpu(cpu_index: usize) -> ! {
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

    // Set TSS.rsp0 and SYSCALL kernel RSP for the first task
    {
        let stack_top =
            first_task.kernel_stack.virt_base.as_u64() + first_task.kernel_stack.size as u64;
        crate::arch::x86_64::tss::set_kernel_stack(x86_64::VirtAddr::new(stack_top));
        crate::arch::x86_64::syscall::set_kernel_rsp(stack_top);
    }

    // Switch to the first task's address space (no-op for kernel tasks)
    // SAFETY: The first task's address space is valid (kernel AS at boot).
    unsafe {
        first_task.address_space.switch_to();
    }

    // Jump to the first task (never returns)
    // SAFETY: The context was set up by CpuContext::new with a valid stack frame.
    unsafe {
        restore_first_task(&raw const (*first_task.context.get()).saved_rsp);
        core::hint::unreachable_unchecked()
    }
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
            sched.yield_cpu(cpu_index)
        } else {
            None
        }
    }; // Lock released here, before the actual context switch

    if let Some(target) = switch_target {
        // SAFETY: Pointers are valid (they point into Arc<Task> contexts
        // kept alive by the scheduler). Interrupts are disabled.
        unsafe {
            switch_context(target.old_rsp_ptr, target.new_rsp_ptr);
        }
        // We return here when this task is rescheduled in the future.
        // The task that switched back to us may have had different flags,
        // so restore our own saved flags.
    }

    // Restore interrupt state (re-enables IF if it was enabled before)
    restore_flags(saved_flags);
}

/// Called from the timer interrupt handler (or a resched IPI) to potentially
/// preempt the current task.
///
/// This is safe to call from interrupt context because:
/// 1. IF is already cleared by the CPU when entering the interrupt.
/// 2. We use `try_lock()` — if the scheduler is already locked
///    (e.g., `yield_task()` is in progress), we simply skip preemption
///    for this tick.
/// 3. We honour the `PreemptGuard`: if preemption is disabled, we return.
pub fn maybe_preempt() {
    // Honour the preemption guard — never preempt a section that asked for it.
    if !percpu::is_preemptible() {
        return;
    }

    let cpu_index = current_cpu_index();
    // Try to lock the scheduler. If it's already locked (yield_task in
    // progress), just skip this tick — we'll preempt on the next one.
    let switch_target = {
        let mut scheduler = match SCHEDULER.try_lock() {
            Some(guard) => guard,
            None => return, // Lock contended, skip this tick
        };

        if let Some(ref mut sched) = *scheduler {
            // Skip if no task is running yet (during early boot)
            if sched
                .cpus
                .get(cpu_index)
                .and_then(|c| c.current_task.as_ref())
                .is_none()
            {
                return;
            }
            sched.yield_cpu(cpu_index)
        } else {
            None
        }
    }; // Lock released here

    if let Some(target) = switch_target {
        // SAFETY: Pointers are valid. IF is cleared by the CPU on interrupt entry.
        // When the new task resumes from its last switch_context call, it will
        // eventually return through its own interrupt handler → iretq (if preempted)
        // or through yield_task → restore_flags (if it yielded cooperatively).
        unsafe {
            switch_context(target.old_rsp_ptr, target.new_rsp_ptr);
        }
        // When we return here, this task was rescheduled. We're back in
        // the timer handler context, which will return via iretq and
        // restore the original RFLAGS (including IF=1).
    }
}

/// The main function for the idle task
extern "C" fn idle_task_main() -> ! {
    log::info!("Idle task started");
    loop {
        // Halt until next interrupt (saves power, timer will wake us)
        crate::arch::x86_64::hlt();
    }
}

/// Mark the current task as Dead and yield to the scheduler.
///
/// Called by SYS_PROC_EXIT. The task will not be re-queued because
/// `pick_next_task()` only re-queues tasks in `Running` state.
/// This function does not return.
pub fn exit_current_task() -> ! {
    let cpu_index = current_cpu_index();
    {
        let saved_flags = save_flags_and_cli();
        let mut scheduler = SCHEDULER.lock();
        if let Some(ref mut sched) = *scheduler {
            if let Some(ref current) = sched.cpus[cpu_index].current_task {
                // SAFETY: We hold the scheduler lock and interrupts are disabled.
                unsafe {
                    *current.state.get() = TaskState::Dead;
                }
                cleanup_task_resources(current);
                sched.all_tasks.remove(&current.id);
                sched.task_cpu.remove(&current.id);
            }
        }
        drop(scheduler);
        restore_flags(saved_flags);
    }

    // Yield to pick the next task. Since we're Dead, we won't come back.
    yield_task();

    // Safety net — should never reach here
    loop {
        crate::arch::x86_64::hlt();
    }
}

/// Get the current task's ID (if any task is running).
pub fn current_task_id() -> Option<TaskId> {
    let saved_flags = save_flags_and_cli();
    let cpu_index = current_cpu_index();
    let id = {
        let scheduler = SCHEDULER.lock();
        if let Some(ref sched) = *scheduler {
            sched
                .cpus
                .get(cpu_index)
                .and_then(|cpu| cpu.current_task.as_ref().map(|t| t.id))
        } else {
            None
        }
    };
    restore_flags(saved_flags);
    id
}

/// Get the current task (cloned Arc), if any.
pub fn current_task_clone() -> Option<Arc<Task>> {
    let saved_flags = save_flags_and_cli();
    let cpu_index = current_cpu_index();
    let task = {
        let scheduler = SCHEDULER.lock();
        if let Some(ref sched) = *scheduler {
            sched
                .cpus
                .get(cpu_index)
                .and_then(|cpu| cpu.current_task.clone())
        } else {
            None
        }
    };
    restore_flags(saved_flags);
    task
}

/// Get a task by its TaskId (if still registered).
pub fn get_task_by_id(id: TaskId) -> Option<Arc<Task>> {
    let saved_flags = save_flags_and_cli();
    let task = {
        let scheduler = SCHEDULER.lock();
        if let Some(ref sched) = *scheduler {
            sched.all_tasks.get(&id).cloned()
        } else {
            None
        }
    };
    restore_flags(saved_flags);
    task
}

/// Block the current task and yield to the scheduler.
///
/// The current task is moved from Running to Blocked state and placed
/// in the `blocked_tasks` map. It will not be re-scheduled until
/// `wake_task(id)` is called.
///
/// ## Lost-wakeup prevention
///
/// Before actually blocking, this function checks the task's `wake_pending`
/// flag. If a concurrent `wake_task()` fired between the moment the task
/// added itself to a `WaitQueue` and this call, the flag will be set and
/// the function returns immediately without blocking.
///
/// Must NOT be called with interrupts disabled or while holding the
/// scheduler lock (this function acquires both).
pub fn block_current_task() {
    let saved_flags = save_flags_and_cli();
    let cpu_index = current_cpu_index();

    let switch_target = {
        let mut scheduler = SCHEDULER.lock();
        if let Some(ref mut sched) = *scheduler {
            if let Some(ref current) = sched.cpus[cpu_index].current_task {
                // Check for a pending wakeup that raced with us before we
                // entered the scheduler lock.  If set, clear it and skip
                // blocking — the task carries on as if it was woken normally.
                // SAFETY: AtomicBool::swap is safe to call from any context.
                if current
                    .wake_pending
                    .swap(false, core::sync::atomic::Ordering::AcqRel)
                {
                    // Pending wakeup consumed — do not block.
                    return;
                }

                // SAFETY: We hold the scheduler lock and interrupts are disabled.
                unsafe {
                    *current.state.get() = TaskState::Blocked;
                }
                // Move it to the blocked map
                sched.blocked_tasks.insert(current.id, current.clone());
            }
            // Now pick the next task (the blocked task won't be re-queued
            // because pick_next_task only re-queues Running tasks)
            sched.yield_cpu(cpu_index)
        } else {
            None
        }
    }; // Lock released

    if let Some(target) = switch_target {
        // SAFETY: Pointers are valid. Interrupts are disabled.
        unsafe {
            switch_context(target.old_rsp_ptr, target.new_rsp_ptr);
        }
        // We return here when woken and rescheduled.
    }

    restore_flags(saved_flags);
}

/// Wake a blocked task by its ID.
///
/// Moves the task from `blocked_tasks` to the ready queue and sets its
/// state to Ready. Returns `true` if the task was found and woken.
///
/// ## Lost-wakeup prevention
///
/// If the task is not yet in `blocked_tasks` (it is still transitioning
/// from Ready → Blocked inside `block_current_task()`), this function sets
/// the task's `wake_pending` flag so that `block_current_task()` will see
/// the pending wakeup and return immediately without actually blocking.
pub fn wake_task(id: TaskId) -> bool {
    let saved_flags = save_flags_and_cli();
    let woken = {
        let mut scheduler = SCHEDULER.lock();
        if let Some(ref mut sched) = *scheduler {
            if let Some(task) = sched.blocked_tasks.remove(&id) {
                // SAFETY: We hold the scheduler lock.
                unsafe {
                    *task.state.get() = TaskState::Ready;
                }
                let cpu_index = sched.task_cpu.get(&id).copied().unwrap_or(0);
                if let Some(cpu) = sched.cpus.get_mut(cpu_index) {
                    cpu.ready_queue.push_back(task);
                }
                true
            } else {
                // Task is not blocked yet (race: it is between adding itself
                // to the WaitQueue waiter list and calling block_current_task).
                // Set wake_pending so block_current_task() will abort the block.
                if let Some(task) = sched.all_tasks.get(&id) {
                    task.wake_pending
                        .store(true, core::sync::atomic::Ordering::Release);
                    true
                } else {
                    false
                }
            }
        } else {
            false
        }
    };
    restore_flags(saved_flags);
    woken
}

/// Suspend a task by ID (best-effort).
///
/// Moves the task to the blocked map and marks it Blocked.
/// - If the task is the *current* task on *this* CPU, a context switch is
///   performed immediately.
/// - If the task is the *current* task on *another* CPU, an IPI is sent to
///   trigger preemption on that CPU. The task will not be re-queued at the
///   next tick because its state is Blocked.
pub fn suspend_task(id: TaskId) -> bool {
    let saved_flags = save_flags_and_cli();

    let mut switch_target: Option<SwitchTarget> = None;
    let mut suspended = false;
    let mut ipi_to_cpu: Option<usize> = None;

    {
        let mut scheduler = SCHEDULER.lock();
        if let Some(ref mut sched) = *scheduler {
            let my_cpu = current_cpu_index();

            // Check if the task is the current task on any CPU.
            for (ci, cpu) in sched.cpus.iter_mut().enumerate() {
                if let Some(ref current) = cpu.current_task {
                    if current.id == id {
                        unsafe {
                            *current.state.get() = TaskState::Blocked;
                        }
                        sched.blocked_tasks.insert(current.id, current.clone());
                        suspended = true;
                        if ci == my_cpu {
                            switch_target = sched.yield_cpu(ci);
                        } else {
                            // Cross-CPU: IPI will make the remote CPU preempt.
                            ipi_to_cpu = Some(ci);
                        }
                        break;
                    }
                }
            }

            // Remove from ready queues (task was not running anywhere).
            if !suspended {
                for cpu in &mut sched.cpus {
                    let mut new_queue = VecDeque::new();
                    while let Some(task) = cpu.ready_queue.pop_front() {
                        if task.id == id {
                            unsafe {
                                *task.state.get() = TaskState::Blocked;
                            }
                            sched.blocked_tasks.insert(task.id, task.clone());
                            suspended = true;
                        } else {
                            new_queue.push_back(task);
                        }
                    }
                    cpu.ready_queue = new_queue;
                }
            }

            // Already blocked.
            if !suspended && sched.blocked_tasks.contains_key(&id) {
                suspended = true;
            }
        }
    } // scheduler lock released before IPI and context switch

    if let Some(target) = switch_target {
        // SAFETY: pointers valid. Interrupts disabled.
        unsafe {
            switch_context(target.old_rsp_ptr, target.new_rsp_ptr);
        }
    }

    // Send IPI after releasing the lock to avoid lock inversion.
    if let Some(ci) = ipi_to_cpu {
        send_resched_ipi_to_cpu(ci);
    }

    restore_flags(saved_flags);
    suspended
}

/// Resume a previously suspended task by ID.
///
/// Moves the task from blocked to ready queue and marks it Ready.
pub fn resume_task(id: TaskId) -> bool {
    let saved_flags = save_flags_and_cli();
    let resumed = {
        let mut scheduler = SCHEDULER.lock();
        if let Some(ref mut sched) = *scheduler {
            if let Some(task) = sched.blocked_tasks.remove(&id) {
                // SAFETY: scheduler lock held.
                unsafe {
                    *task.state.get() = TaskState::Ready;
                }
                let cpu_index = sched.task_cpu.get(&id).copied().unwrap_or(0);
                if let Some(cpu) = sched.cpus.get_mut(cpu_index) {
                    cpu.ready_queue.push_back(task);
                }
                true
            } else {
                false
            }
        } else {
            false
        }
    };
    restore_flags(saved_flags);
    resumed
}

/// Kill a task by ID (best-effort).
///
/// - Ready / blocked tasks are removed and marked Dead immediately.
/// - If the task is the *current* task on *this* CPU, a context switch is
///   performed immediately.
/// - If the task is the *current* task on *another* CPU, an IPI triggers
///   preemption on that CPU; the task will not be re-queued because its
///   state is Dead.
///
/// Returns `true` if the task was found and killed.
pub fn kill_task(id: TaskId) -> bool {
    let saved_flags = save_flags_and_cli();

    let mut switch_target: Option<SwitchTarget> = None;
    let mut killed = false;
    let mut ipi_to_cpu: Option<usize> = None;

    {
        let mut scheduler = SCHEDULER.lock();
        if let Some(ref mut sched) = *scheduler {
            let my_cpu = current_cpu_index();

            // Check if the task is the current task on any CPU.
            for (ci, cpu) in sched.cpus.iter_mut().enumerate() {
                if let Some(ref current) = cpu.current_task {
                    if current.id == id {
                        unsafe {
                            *current.state.get() = TaskState::Dead;
                        }
                        cleanup_task_resources(current);
                        sched.all_tasks.remove(&id);
                        sched.task_cpu.remove(&id);
                        killed = true;
                        if ci == my_cpu {
                            switch_target = sched.yield_cpu(ci);
                        } else {
                            // Cross-CPU: IPI makes the remote CPU preempt.
                            ipi_to_cpu = Some(ci);
                        }
                        break;
                    }
                }
            }

            // Remove from ready queues.
            if !killed {
                for cpu in &mut sched.cpus {
                    let mut new_queue = VecDeque::new();
                    while let Some(task) = cpu.ready_queue.pop_front() {
                        if task.id == id {
                            unsafe {
                                *task.state.get() = TaskState::Dead;
                            }
                            cleanup_task_resources(&task);
                            sched.all_tasks.remove(&id);
                            sched.task_cpu.remove(&id);
                            killed = true;
                        } else {
                            new_queue.push_back(task);
                        }
                    }
                    cpu.ready_queue = new_queue;
                }
            }

            // Remove from blocked map.
            if !killed {
                if let Some(task) = sched.blocked_tasks.remove(&id) {
                    // SAFETY: scheduler lock held.
                    unsafe {
                        *task.state.get() = TaskState::Dead;
                    }
                    cleanup_task_resources(&task);
                    sched.all_tasks.remove(&id);
                    sched.task_cpu.remove(&id);
                    killed = true;
                }
            }
        }
    } // scheduler lock released before IPI and context switch

    if let Some(target) = switch_target {
        // SAFETY: pointers valid. Interrupts disabled.
        unsafe {
            switch_context(target.old_rsp_ptr, target.new_rsp_ptr);
        }
    }

    // Send IPI after releasing the lock to avoid lock inversion.
    if let Some(ci) = ipi_to_cpu {
        send_resched_ipi_to_cpu(ci);
    }

    restore_flags(saved_flags);
    killed
}

fn cleanup_task_resources(task: &Arc<Task>) {
    crate::silo::on_task_terminated(task.id);

    // Revoke all capabilities for this task.
    let caps = unsafe { (&mut *task.capabilities.get()).take_all() };
    for cap in caps {
        let _ = get_capability_manager().revoke_capability(cap.id);
    }

    // Best-effort cleanup of user address space if uniquely owned.
    if !task.address_space.is_kernel() && Arc::strong_count(&task.address_space) == 1 {
        task.address_space.unmap_all_user_regions();
    }
}

/// Timer interrupt handler — called from interrupt context.
///
/// Increments the global tick counter. Preemption is handled separately
/// by `maybe_preempt()` which is called after EOI in the timer handler.
/// Also checks interval timers for expiration and wake deadlines for sleep.
pub fn timer_tick() {
    // Early return if scheduler is not initialized yet
    // This can happen during AP boot before schedule() is called
    let scheduler_check = SCHEDULER.try_lock();
    if scheduler_check.is_none() {
        // Scheduler is locked (being initialized or in use), skip this tick
        return;
    }
    drop(scheduler_check); // Release immediately, just checking

    let tick = TICK_COUNT.fetch_add(1, Ordering::Relaxed);

    // Assume 100Hz timer (10ms per tick)
    // Convert ticks to nanoseconds
    let current_time_ns = tick * 10_000_000; // 10ms = 10,000,000 ns

    // Check interval timers for all tasks
    super::timer::tick_all_timers(current_time_ns);

    // Check wake deadlines for sleeping tasks
    check_wake_deadlines(current_time_ns);
}

/// Check wake deadlines for all tasks and wake up those whose sleep has expired.
///
/// Called from timer_tick() with interrupts disabled.
///
/// Uses try_lock() to avoid deadlock if called while scheduler lock is held.
fn check_wake_deadlines(current_time_ns: u64) {
    // Use try_lock to avoid deadlock - if scheduler is already locked,
    // we'll check wake deadlines on the next timer tick.
    let mut scheduler = match SCHEDULER.try_lock() {
        Some(guard) => guard,
        None => return, // Scheduler locked, skip this tick
    };

    if let Some(ref mut sched) = *scheduler {
        // Collect IDs of tasks to wake (to avoid borrow issues)
        let mut to_wake = alloc::vec::Vec::new();

        for (id, task) in sched.all_tasks.iter() {
            let deadline = task.wake_deadline_ns.load(Ordering::Relaxed);
            if deadline != 0 && current_time_ns >= deadline {
                to_wake.push(*id);
            }
        }

        // Wake up tasks whose deadline has passed
        for id in to_wake {
            if let Some(task) = sched.all_tasks.get(&id) {
                // Clear the deadline
                task.wake_deadline_ns.store(0, Ordering::Relaxed);

                // If task is blocked on sleep, wake it up
                if let Some(blocked_task) = sched.blocked_tasks.remove(&id) {
                    // SAFETY: scheduler lock held
                    unsafe {
                        *blocked_task.state.get() = TaskState::Ready;
                    }
                    let cpu = sched.task_cpu.get(&id).copied().unwrap_or(0);
                    if let Some(cpu_sched) = sched.cpus.get_mut(cpu) {
                        cpu_sched.ready_queue.push_back(blocked_task);
                    }
                }
            }
        }
    }
    // Lock released when scheduler goes out of scope
}

/// Get the current tick count
pub fn ticks() -> u64 {
    TICK_COUNT.load(Ordering::Relaxed)
}

/// Get a list of all tasks in the system (for timer checking).
/// Returns None if scheduler is not initialized or currently locked.
pub fn get_all_tasks() -> Option<alloc::vec::Vec<Arc<Task>>> {
    use alloc::vec::Vec;
    // Use try_lock to avoid deadlock in interrupt context
    let scheduler = SCHEDULER.try_lock()?;
    if let Some(ref sched) = *scheduler {
        let mut tasks = Vec::new();
        for (_, task) in sched.all_tasks.iter() {
            tasks.push(task.clone());
        }
        Some(tasks)
    } else {
        None
    }
}
