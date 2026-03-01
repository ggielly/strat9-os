use super::*;
use super::runtime_ops::idle_task_main;

impl Scheduler {
    /// Create a new scheduler instance
    pub fn new(cpu_count: usize) -> Self {
        let mut cpus = alloc::vec::Vec::new();
        for _ in 0..cpu_count {
            let idle_task = Task::new_kernel_task(idle_task_main, "idle", TaskPriority::Idle)
                .expect("Failed to create idle task");
            idle_task.set_sched_policy(crate::process::sched::SchedPolicy::Idle);
            let mut class_rqs = PerCpuClassRqSet::new();
            class_rqs.enqueue(crate::process::sched::SchedClassId::Idle, idle_task.clone());
            cpus.push(SchedulerCpu {
                class_rqs,
                current_task: None,
                current_runtime: crate::process::sched::CurrentRuntime::new(),
                idle_task,
                task_to_requeue: None,
                task_to_drop: None,
                need_resched: false,
            });
        }

        Scheduler {
            cpus,
            blocked_tasks: BTreeMap::new(),
            all_tasks: BTreeMap::new(),
            task_cpu: BTreeMap::new(),
            pid_to_task: BTreeMap::new(),
            parent_of: BTreeMap::new(),
            children_of: BTreeMap::new(),
            zombies: BTreeMap::new(),
            class_table: crate::process::sched::SchedClassTable::default(),
        }
    }

    /// Add a task to the scheduler
    pub fn add_task(&mut self, task: Arc<Task>) {
        let cpu_index = self.select_cpu_for_task();
        self.add_task_on_cpu(task, cpu_index);
    }

    pub fn add_task_with_parent(&mut self, task: Arc<Task>, parent: TaskId) {
        let child = task.id;
        let cpu_index = self.select_cpu_for_task();
        self.add_task_on_cpu(task, cpu_index);
        self.parent_of.insert(child, parent);
        self.children_of.entry(parent).or_default().push(child);
    }

    fn add_task_on_cpu(&mut self, task: Arc<Task>, cpu_index: usize) {
        let task_id = task.id;
        // SAFETY: We have exclusive access via the scheduler lock
        unsafe {
            *task.state.get() = TaskState::Ready;
        }

        self.all_tasks.insert(task_id, task.clone());
        self.task_cpu.insert(task_id, cpu_index);
        self.pid_to_task.insert(task.pid, task_id);
        if let Some(cpu) = self.cpus.get_mut(cpu_index) {
            let class = self.class_table.class_for_task(&task);
            cpu.class_rqs.enqueue(class, task);
            cpu.need_resched = true;
        }
        sched_trace(format_args!(
            "enqueue task={} cpu={}",
            task_id.as_u64(),
            cpu_index
        ));
        if cpu_index != current_cpu_index() {
            send_resched_ipi_to_cpu(cpu_index);
        }
    }

    pub fn wake_task_locked(&mut self, id: TaskId) -> bool {
        if let Some(task) = self.blocked_tasks.remove(&id) {
            // SAFETY: scheduler lock held.
            unsafe {
                *task.state.get() = TaskState::Ready;
            }
            let cpu_index = self.task_cpu.get(&id).copied().unwrap_or(0);
            if let Some(cpu) = self.cpus.get_mut(cpu_index) {
                let class = self.class_table.class_for_task(&task);
                cpu.class_rqs.enqueue(class, task);
                cpu.need_resched = true;
            }
            if cpu_index != current_cpu_index() {
                send_resched_ipi_to_cpu(cpu_index);
            }
            true
        } else if let Some(task) = self.all_tasks.get(&id) {
            task.wake_pending
                .store(true, core::sync::atomic::Ordering::Release);
            true
        } else {
            false
        }
    }

    pub fn try_reap_child_locked(
        &mut self,
        parent: TaskId,
        target: Option<TaskId>,
    ) -> WaitChildResult {
        let Some(children) = self.children_of.get_mut(&parent) else {
            return WaitChildResult::NoChildren;
        };

        if children.is_empty() {
            return WaitChildResult::NoChildren;
        }

        if let Some(target_id) = target {
            if !children.iter().any(|&id| id == target_id) {
                return WaitChildResult::NoChildren;
            }
        }

        let zombie = children
            .iter()
            .copied()
            .find(|id| target.map_or(true, |t| t == *id) && self.zombies.contains_key(id));

        if let Some(child) = zombie {
            let (status, child_pid) = self.zombies.remove(&child).unwrap_or((0, 0));
            if child_pid != 0 {
                self.pid_to_task.remove(&child_pid);
            }
            children.retain(|&id| id != child);
            self.parent_of.remove(&child);
            if children.is_empty() {
                self.children_of.remove(&parent);
            }
            return WaitChildResult::Reaped {
                child,
                pid: child_pid,
                status,
            };
        }

        WaitChildResult::StillRunning
    }

    /// Pick the next task to run on `cpu_index`.
    ///
    /// 1. Re-queues the current Running task (round-robin).
    ///    The **idle task is never re-queued** — it is always available
    ///    as the last-resort fallback.  Keeping it out of the ready queue
    ///    ensures the queue becomes truly empty when there is no real work,
    ///    which lets work-stealing kick in on other CPUs.
    /// 2. Pops from the local ready queue.
    /// 3. Falls back to **work-stealing** from the busiest other CPU.
    /// 4. Falls back to the per-CPU idle task.
    pub fn pick_next_task(&mut self, cpu_index: usize) -> Arc<Task> {
        // Step 1: take current task and re-queue it if still alive.
        let current_task = self.cpus[cpu_index].current_task.take();
        if let Some(task) = current_task {
            // SAFETY: scheduler lock held; we have exclusive access to state.
            let task_state = unsafe { *task.state.get() };
            if task_state == TaskState::Running {
                unsafe {
                    *task.state.get() = TaskState::Ready;
                }
                // Never re-queue the per-CPU idle task.  It lives in
                // `cpus[cpu_index].idle_task` and is cloned as a fallback
                // below.  Putting it in the ready queue prevents it from
                // ever being empty, which breaks work-stealing.
                if !Arc::ptr_eq(&task, &self.cpus[cpu_index].idle_task) {
                    // DO NOT push to ready_queue yet!
                    // Another CPU could steal it before its context is saved.
                    self.cpus[cpu_index].task_to_requeue = Some(task);
                }
            } else {
                // Task is Dead or Blocked. Prevent it from dropping right here
                // by deferring the drop to finish_switch().
                self.cpus[cpu_index].task_to_drop = Some(task);
            }
        }

        // Step 2: local queue, then work-steal, then idle.
        let next_task = if let Some(task) =
            self.cpus[cpu_index].class_rqs.pick_next(&self.class_table)
        {
            task
        } else if let Some(task) = self.steal_task(cpu_index, TICK_COUNT.load(Ordering::Relaxed)) {
            task
        } else {
            self.cpus[cpu_index].idle_task.clone()
        };

        // SAFETY: scheduler lock held.
        unsafe {
            *next_task.state.get() = TaskState::Running;
        }
        self.cpus[cpu_index].current_task = Some(next_task.clone());
        // Reset the runtime accounting for the new task
        self.cpus[cpu_index].current_runtime = crate::process::sched::CurrentRuntime::new();
        sched_trace(format_args!(
            "cpu={} pick_next task={} policy={:?}",
            cpu_index,
            next_task.id.as_u64(),
            next_task.sched_policy()
        ));
        next_task
    }

    /// Try to steal one task from the most-loaded other CPU.
    ///
    /// We steal from the **back** of the source queue (the task added most
    /// recently — least likely to have warm cache data on that CPU).
    /// We only steal when the source has ≥ 2 tasks, so it keeps at least one.
    pub fn steal_task(&mut self, dst_cpu: usize, now_tick: u64) -> Option<Arc<Task>> {
        if !cpu_is_valid(dst_cpu) {
            return None;
        }
        let last = LAST_STEAL_TICK[dst_cpu].load(Ordering::Relaxed);
        if now_tick.saturating_sub(last) < STEAL_COOLDOWN_TICKS {
            return None;
        }

        let dst_load = {
            let cpu = &self.cpus[dst_cpu];
            cpu.class_rqs.runnable_len() + usize::from(cpu.current_task.is_some())
        };

        // Find the busiest CPU that isn't ourselves.
        let (best_src, best_src_load) = (0..self.cpus.len())
            .filter(|&i| i != dst_cpu)
            .map(|i| {
                let cpu = &self.cpus[i];
                let load = cpu.class_rqs.runnable_len() + usize::from(cpu.current_task.is_some());
                (i, load)
            })
            .max_by_key(|(_, load)| *load)?;

        if best_src_load < dst_load.saturating_add(STEAL_IMBALANCE_MIN) {
            return None;
        }

        // Only steal if source will still have work left.
        if self.cpus[best_src].class_rqs.runnable_len() < 2 {
            return None;
        }

        let task = self.cpus[best_src]
            .class_rqs
            .steal_candidate(&self.class_table)?;
        // Update the task->CPU mapping so wake/resume route correctly.
        self.task_cpu.insert(task.id, dst_cpu);
        log::trace!(
            "WS: CPU {} stole task {:?} from CPU {} (src had {} tasks)",
            dst_cpu,
            task.id,
            best_src,
            self.cpus[best_src].class_rqs.runnable_len() + 1
        );
        sched_trace(format_args!(
            "work-steal dst_cpu={} src_cpu={} task={}",
            dst_cpu,
            best_src,
            task.id.as_u64()
        ));
        if cpu_is_valid(dst_cpu) {
            CPU_STEAL_IN_COUNT[dst_cpu].fetch_add(1, Ordering::Relaxed);
        }
        if cpu_is_valid(best_src) {
            CPU_STEAL_OUT_COUNT[best_src].fetch_add(1, Ordering::Relaxed);
        }
        LAST_STEAL_TICK[dst_cpu].store(now_tick, Ordering::Relaxed);
        Some(task)
    }

    /// Prepare a context switch: pick next task, update TSS and CR3,
    /// return raw pointers for `switch_context()`.
    ///
    /// Returns `None` if there's nothing to switch to (same task selected,
    /// or no current task).
    pub fn yield_cpu(&mut self, cpu_index: usize) -> Option<SwitchTarget> {
        // Must have a current task to yield from
        let current = self.cpus[cpu_index].current_task.as_ref()?.clone();

        // Pick the next task
        let next = self.pick_next_task(cpu_index);

        // Don't switch to ourselves
        if Arc::ptr_eq(&current, &next) {
            return None;
        }
        if cpu_is_valid(cpu_index) {
            CPU_SWITCH_COUNT[cpu_index].fetch_add(1, Ordering::Relaxed);
        }

        if let Err(e) = validate_task_context(&next) {
            panic!(
                "scheduler: refusing to switch to invalid task '{}' (id={:?}): {}",
                next.name, next.id, e
            );
        }

        // Update TSS.rsp0 for the new task (needed for Ring 3 -> Ring 0 transitions)
        let stack_top = next.kernel_stack.virt_base.as_u64() + next.kernel_stack.size as u64;
        crate::arch::x86_64::tss::set_kernel_stack(x86_64::VirtAddr::new(stack_top));

        // Update SYSCALL kernel RSP for the new task
        crate::arch::x86_64::syscall::set_kernel_rsp(stack_top);

        // Switch CR3 if the new task has a different address space
        // SAFETY: The new task's address space has a valid PML4 with the kernel half mapped.
        unsafe {
            (*next.process.address_space.get()).switch_to();
        }

        // Return raw pointers for switch_context
        Some(SwitchTarget {
            old_rsp_ptr: unsafe { &raw mut (*current.context.get()).saved_rsp },
            new_rsp_ptr: unsafe { &raw const (*next.context.get()).saved_rsp },
            old_fpu_ptr: current.fpu_state.get(),
            new_fpu_ptr: next.fpu_state.get(),
        })
    }

    fn select_cpu_for_task(&self) -> usize {
        let mut best = 0usize;
        let mut best_load = usize::MAX;
        for (idx, cpu) in self.cpus.iter().enumerate() {
            let mut load = cpu.class_rqs.runnable_len();
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

    pub fn migrate_ready_tasks_for_new_class_table(&mut self) {
        let mut ready: Vec<(TaskId, Arc<Task>, usize)> = Vec::new();
        for (id, task) in self.all_tasks.iter() {
            // SAFETY: scheduler lock is held by caller; task state is synchronized by scheduler.
            let state = unsafe { *task.state.get() };
            if state != TaskState::Ready {
                continue;
            }
            let cpu = self.task_cpu.get(id).copied().unwrap_or(0);
            ready.push((*id, task.clone(), cpu));
        }

        for (id, task, cpu_idx) in ready {
            let Some(cpu) = self.cpus.get_mut(cpu_idx) else {
                continue;
            };
            if cpu.class_rqs.remove(id) {
                let class = self.class_table.class_for_task(&task);
                cpu.class_rqs.enqueue(class, task);
                cpu.need_resched = true;
            }
        }
    }
}
