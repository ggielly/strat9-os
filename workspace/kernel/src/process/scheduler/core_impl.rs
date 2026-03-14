use super::{runtime_ops::idle_task_main, *};

impl Scheduler {
    /// Create a new scheduler instance
    pub fn new(cpu_count: usize) -> Self {
        crate::serial_println!(
            "[trace][sched] Scheduler::new enter cpu_count={}",
            cpu_count
        );
        let mut cpus = alloc::vec::Vec::new();
        for cpu_idx in 0..cpu_count {
            crate::serial_println!(
                "[trace][sched] Scheduler::new cpu={} create idle begin",
                cpu_idx
            );
            let idle_task = Task::new_kernel_task(idle_task_main, "idle", TaskPriority::Idle)
                .expect("Failed to create idle task");
            crate::serial_println!(
                "[trace][sched] Scheduler::new cpu={} create idle done id={}",
                cpu_idx,
                idle_task.id.as_u64()
            );
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
            crate::serial_println!("[trace][sched] Scheduler::new cpu={} push done", cpu_idx);
        }
        crate::serial_println!(
            "[trace][sched] Scheduler::new cpus ready len={}",
            cpus.len()
        );

        Scheduler {
            cpus,
            blocked_tasks: BTreeMap::new(),
            all_tasks: BTreeMap::new(),
            all_tasks_scan: Vec::new(),
            task_cpu: BTreeMap::new(),
            pid_to_task: BTreeMap::new(),
            tid_to_task: BTreeMap::new(),
            pid_to_pgid: BTreeMap::new(),
            pid_to_sid: BTreeMap::new(),
            pgid_members: BTreeMap::new(),
            sid_members: BTreeMap::new(),
            wake_deadlines: BTreeMap::new(),
            wake_deadline_of: BTreeMap::new(),
            parent_of: BTreeMap::new(),
            children_of: BTreeMap::new(),
            zombies: BTreeMap::new(),
            class_table: crate::process::sched::SchedClassTable::default(),
        }
    }

    /// Performs the member add operation.
    pub(crate) fn member_add(
        map: &mut BTreeMap<Pid, alloc::vec::Vec<TaskId>>,
        key: Pid,
        task_id: TaskId,
    ) {
        crate::serial_println!(
            "[trace][sched] member_add enter key={} tid={}",
            key,
            task_id.as_u64()
        );
        let members = map.entry(key).or_default();
        crate::serial_println!(
            "[trace][sched] member_add entry key={} len={}",
            key,
            members.len()
        );
        if !members.iter().any(|id| *id == task_id) {
            members.push(task_id);
            crate::serial_println!(
                "[trace][sched] member_add pushed key={} tid={}",
                key,
                task_id.as_u64()
            );
        }
    }

    /// Performs the member remove operation.
    pub(crate) fn member_remove(
        map: &mut BTreeMap<Pid, alloc::vec::Vec<TaskId>>,
        key: Pid,
        task_id: TaskId,
    ) {
        let mut clear = false;
        if let Some(members) = map.get_mut(&key) {
            members.retain(|id| *id != task_id);
            clear = members.is_empty();
        }
        if clear {
            map.remove(&key);
        }
    }

    /// Performs the register identity locked operation.
    pub(crate) fn register_identity_locked(&mut self, task: &Arc<Task>) {
        let task_id = task.id;
        let pid = task.pid;
        let pgid = task.pgid.load(Ordering::Relaxed);
        let sid = task.sid.load(Ordering::Relaxed);
        crate::serial_println!(
            "[trace][sched] register_identity enter tid={} pid={} pgid={} sid={}",
            task_id.as_u64(),
            pid,
            pgid,
            sid
        );
        self.pid_to_pgid.insert(pid, pgid);
        crate::serial_println!(
            "[trace][sched] register_identity pid_to_pgid inserted pid={}",
            pid
        );
        self.pid_to_sid.insert(pid, sid);
        crate::serial_println!(
            "[trace][sched] register_identity pid_to_sid inserted pid={}",
            pid
        );
        Self::member_add(&mut self.pgid_members, pgid, task_id);
        Self::member_add(&mut self.sid_members, sid, task_id);
        crate::serial_println!(
            "[trace][sched] register_identity done tid={}",
            task_id.as_u64()
        );
    }

    /// Performs the unregister identity locked operation.
    pub(crate) fn unregister_identity_locked(&mut self, task_id: TaskId, pid: Pid, tid: Tid) {
        self.pid_to_task.remove(&pid);
        self.tid_to_task.remove(&tid);
        if let Some(pgid) = self.pid_to_pgid.remove(&pid) {
            Self::member_remove(&mut self.pgid_members, pgid, task_id);
        }
        if let Some(sid) = self.pid_to_sid.remove(&pid) {
            Self::member_remove(&mut self.sid_members, sid, task_id);
        }
    }

    /// Add a task to the scheduler
    pub fn add_task(&mut self, task: Arc<Task>) -> Option<usize> {
        let cpu_index = self.select_cpu_for_task();
        self.add_task_on_cpu(task, cpu_index)
    }

    /// Performs the add task with parent operation.
    pub fn add_task_with_parent(&mut self, task: Arc<Task>, parent: TaskId) -> Option<usize> {
        let child = task.id;
        let cpu_index = self.select_cpu_for_task();
        let ipi = self.add_task_on_cpu(task, cpu_index);
        self.parent_of.insert(child, parent);
        self.children_of.entry(parent).or_default().push(child);
        ipi
    }

    /// Performs the add task on cpu operation.
    fn add_task_on_cpu(&mut self, task: Arc<Task>, cpu_index: usize) -> Option<usize> {
        let task_id = task.id;
        crate::serial_println!(
            "[trace][sched] add_task_on_cpu enter tid={} cpu={}",
            task_id.as_u64(),
            cpu_index
        );
        // SAFETY: We have exclusive access via the scheduler lock
        unsafe {
            *task.state.get() = TaskState::Ready;
        }
        crate::serial_println!(
            "[trace][sched] add_task_on_cpu state ready tid={}",
            task_id.as_u64()
        );

        crate::serial_println!(
            "[trace][sched] add_task_on_cpu before clone tid={} all_tasks_len={}",
            task_id.as_u64(),
            self.all_tasks.len()
        );
        let task_clone = task.clone();
        crate::serial_println!(
            "[trace][sched] add_task_on_cpu before all_tasks.insert tid={}",
            task_id.as_u64()
        );
        self.insert_all_task_locked(task_id, task_clone);
        crate::serial_println!(
            "[trace][sched] add_task_on_cpu all_tasks inserted tid={}",
            task_id.as_u64()
        );
        self.task_cpu.insert(task_id, cpu_index);
        crate::serial_println!(
            "[trace][sched] add_task_on_cpu task_cpu inserted tid={}",
            task_id.as_u64()
        );
        self.pid_to_task.insert(task.pid, task_id);
        crate::serial_println!(
            "[trace][sched] add_task_on_cpu pid map inserted tid={}",
            task_id.as_u64()
        );
        self.tid_to_task.insert(task.tid, task_id);
        crate::serial_println!(
            "[trace][sched] add_task_on_cpu tid map inserted tid={}",
            task_id.as_u64()
        );
        self.register_identity_locked(&task);
        crate::serial_println!(
            "[trace][sched] add_task_on_cpu identity registered tid={}",
            task_id.as_u64()
        );
        if let Some(cpu) = self.cpus.get_mut(cpu_index) {
            let class = self.class_table.class_for_task(&task);
            cpu.class_rqs.enqueue(class, task);
            cpu.need_resched = true;
            crate::serial_println!(
                "[trace][sched] add_task_on_cpu enqueued tid={} cpu={}",
                task_id.as_u64(),
                cpu_index
            );
        }
        sched_trace(format_args!(
            "enqueue task={} cpu={}",
            task_id.as_u64(),
            cpu_index
        ));
        if cpu_index != current_cpu_index() {
            Some(cpu_index)
        } else {
            None
        }
    }

    pub(super) fn insert_all_task_locked(&mut self, task_id: TaskId, task: Arc<Task>) {
        self.all_tasks.insert(task_id, task.clone());
        self.all_tasks_scan.push(task);
        // Race/corruption diagnostic: all_tasks and all_tasks_scan must stay in sync.
        let bt_len = self.all_tasks.len();
        let scan_len = self.all_tasks_scan.len();
        if bt_len != scan_len {
            crate::e9_println!(
                "RC-BAD cpu={} tid={} all_tasks={} all_tasks_scan={} MISMATCH",
                crate::arch::x86_64::percpu::current_cpu_index(),
                task_id.as_u64(),
                bt_len,
                scan_len
            );
            crate::serial_force_println!(
                "[RACE] insert_all_task_locked: all_tasks={} != all_tasks_scan={} tid={}",
                bt_len,
                scan_len,
                task_id.as_u64()
            );
        }
    }

    pub(super) fn remove_all_task_locked(&mut self, task_id: TaskId) -> Option<Arc<Task>> {
        let removed = self.all_tasks.remove(&task_id);
        if removed.is_some() {
            if let Some(idx) = self
                .all_tasks_scan
                .iter()
                .position(|task| task.id == task_id)
            {
                self.all_tasks_scan.swap_remove(idx);
            } else {
                crate::e9_println!(
                    "RC-RMV-NF cpu={} tid={} task not in all_tasks_scan",
                    crate::arch::x86_64::percpu::current_cpu_index(),
                    task_id.as_u64()
                );
                crate::serial_force_println!(
                    "[RACE] remove_all_task_locked: tid={} in all_tasks but NOT in all_tasks_scan",
                    task_id.as_u64()
                );
            }
        }
        let bt_len = self.all_tasks.len();
        let scan_len = self.all_tasks_scan.len();
        if bt_len != scan_len {
            crate::e9_println!(
                "RC-BAD cpu={} tid={} all_tasks={} all_tasks_scan={} MISMATCH",
                crate::arch::x86_64::percpu::current_cpu_index(),
                task_id.as_u64(),
                bt_len,
                scan_len
            );
            crate::serial_force_println!(
                "[RACE] remove_all_task_locked: all_tasks={} != all_tasks_scan={} tid={}",
                bt_len,
                scan_len,
                task_id.as_u64()
            );
        }
        removed
    }

    /// Performs the clear task wake deadline locked operation.
    pub fn clear_task_wake_deadline_locked(&mut self, id: TaskId) -> bool {
        if let Some(task) = self.all_tasks.get(&id) {
            task.wake_deadline_ns.store(0, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Sets task wake deadline locked.
    pub fn set_task_wake_deadline_locked(&mut self, id: TaskId, deadline: u64) -> bool {
        if deadline == 0 {
            return self.clear_task_wake_deadline_locked(id);
        }
        if let Some(task) = self.all_tasks.get(&id) {
            task.wake_deadline_ns.store(deadline, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Performs the wake task locked operation.
    ///
    /// Returns `(was_woken, ipi_cpu)`. The caller must send a resched IPI to
    /// `ipi_cpu` after releasing the scheduler lock.
    pub fn wake_task_locked(&mut self, id: TaskId) -> (bool, Option<usize>) {
        self.clear_task_wake_deadline_locked(id);
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
            let ipi = if cpu_index != current_cpu_index() {
                Some(cpu_index)
            } else {
                None
            };
            (true, ipi)
        } else if let Some(task) = self.all_tasks.get(&id) {
            task.wake_pending
                .store(true, core::sync::atomic::Ordering::Release);
            (true, None)
        } else {
            (false, None)
        }
    }

    /// Attempts to reap child locked.
    pub fn try_reap_child_locked(
        &mut self,
        parent: TaskId,
        target: Option<TaskId>,
    ) -> WaitChildResult {
        let Some(children_view) = self.children_of.get(&parent) else {
            return WaitChildResult::NoChildren;
        };

        if children_view.is_empty() {
            return WaitChildResult::NoChildren;
        }

        if let Some(target_id) = target {
            if !children_view.iter().any(|&id| id == target_id) {
                return WaitChildResult::NoChildren;
            }
        }

        let zombie = children_view
            .iter()
            .copied()
            .find(|id| target.map_or(true, |t| t == *id) && self.zombies.contains_key(id));

        if let Some(child) = zombie {
            let (status, child_pid) = self.zombies.remove(&child).unwrap_or((0, 0));
            // Remove from all_tasks now so that pick_next_task (if it races with
            // reaping) will see was_registered=false and skip cleanup_task_resources.
            let reaped_task = self.remove_all_task_locked(child);
            let child_tid = reaped_task.as_ref().map(|t| t.tid);
            if child_pid != 0 {
                if let Some(tid) = child_tid {
                    self.unregister_identity_locked(child, child_pid, tid);
                }
            }
            if let Some(children) = self.children_of.get_mut(&parent) {
                children.retain(|&id| id != child);
                if children.is_empty() {
                    self.children_of.remove(&parent);
                }
            }
            self.parent_of.remove(&child);
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
            } else if task_state == TaskState::Dead {
                let task_id = task.id;
                let task_pid = task.pid;
                let task_tid = task.tid;

                // Remove from global maps. `try_reap_child_locked` may have
                // already removed the task; in that case `remove` is a no-op
                // and we must skip `cleanup_task_resources` to avoid running
                // port/silo teardown twice.
                let was_registered = self.remove_all_task_locked(task_id).is_some();
                self.task_cpu.remove(&task_id);
                self.unregister_identity_locked(task_id, task_pid, task_tid);

                if was_registered {
                    // SAFETY: scheduler lock held, task is no longer accessible
                    super::task_ops::cleanup_task_resources(&task);
                }

                // Defer the actual Arc drop to finish_switch()
                self.cpus[cpu_index].task_to_drop = Some(task);
            } else {
                // Blocked task: leave bookkeeping intact; blocked_tasks holds the ref.
                // Dropping the Arc here is fine; the blocked map keeps the task alive.
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
        let cloned = next_task.clone();
        let strong_after = Arc::strong_count(&cloned);
        // Race/corruption diagnostic: validate Arc after pick.
        if strong_after == 0 || strong_after > (isize::MAX as usize) {
            crate::e9_println!(
                "PICK-ARC-BAD cpu={} tid={} strong={} CORRUPT",
                cpu_index,
                next_task.id.as_u64(),
                strong_after
            );
            crate::serial_force_println!(
                "[RACE] pick_next_task: corrupt Arc tid={} strong_count={}",
                next_task.id.as_u64(),
                strong_after
            );
        }
        self.cpus[cpu_index].current_task = Some(cloned);
        // Reset the runtime accounting for the new task
        self.cpus[cpu_index].current_runtime = crate::process::sched::CurrentRuntime::new();
        sched_trace(format_args!(
            "cpu={} pick_next task={} policy={:?} strong={}",
            cpu_index,
            next_task.id.as_u64(),
            next_task.sched_policy(),
            strong_after,
        ));
        next_task
    }

    /// Try to steal one task from the most-loaded other CPU.
    ///
    /// We steal from the **back** of the source queue (the task added most
    /// recently — least likely to have warm cache data on that CPU).
    /// We only steal when the source has ≥ 2 tasks, so it keeps at least one.
    pub fn steal_task(&mut self, dst_cpu: usize, now_tick: u64) -> Option<Arc<Task>> {
        if !cpu_is_valid(dst_cpu) || dst_cpu >= self.cpus.len() {
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
    pub(super) fn yield_cpu(&mut self, cpu_index: usize) -> Option<SwitchTarget> {
        if cpu_index >= self.cpus.len() {
            return None;
        }
        // Must have a current task to yield from
        let current_ref = self.cpus[cpu_index].current_task.as_ref()?;
        let strong_before = Arc::strong_count(current_ref);
        if strong_before == 0 || strong_before > (isize::MAX as usize) {
            log::error!(
                "[sched] CORRUPT Arc in yield_cpu before clone! cpu={} strong={:#x} task={} ptr={:p}",
                cpu_index, strong_before,
                current_ref.id.as_u64(),
                Arc::as_ptr(current_ref) as *const u8,
            );
            return None;
        }
        let current = current_ref.clone();

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
            // Do NOT panic here — the scheduler lock is held, which would
            // deadlock the panic hook (current_task_clone → SCHEDULER.lock()).
            let bad_rsp = unsafe { (*next.context.get()).saved_rsp };
            let stk_base = next.kernel_stack.virt_base.as_u64();
            let stk_top = stk_base + next.kernel_stack.size as u64;
            crate::serial_println!(
                "[sched] WARN: invalid ctx for task '{}' (id={}) cpu={}: {} \
                 rsp={:#x} stack=[{:#x}..{:#x}] - restoring current task",
                next.name,
                next.id.as_u64(),
                cpu_index,
                e,
                bad_rsp,
                stk_base,
                stk_top,
            );
            log::error!(
                "[sched] invalid context for task '{}' (id={:?}) cpu={}: {} \
                 rsp={:#x} stack=[{:#x}..{:#x}]",
                next.name,
                next.id,
                cpu_index,
                e,
                bad_rsp,
                stk_base,
                stk_top,
            );

            // ── Restore scheduler invariants ────────────────────────────────────────
            // `pick_next_task` already mutated state before we reached this point:
            //   1. Took `current_task`, set its state to Ready, placed it in
            //      `task_to_requeue` (non-idle tasks only).
            //   2. Set `current_task = Some(next_clone)` with next.state = Running.
            //
            // We are NOT performing the actual context switch. Both mutations must be
            // undone so the truly running task stays scheduled and no Arc reference
            // is silently lost (which would lead to corrupted saved_rsp on the next
            // timer tick when the scheduler tries to save context for the wrong task).

            // (a) Is `next` the per-CPU idle fallback (accessed via clone, never in
            //     class_rqs)?  We need this before any borrow of self.cpus.
            let is_idle_fallback = Arc::ptr_eq(&next, &self.cpus[cpu_index].idle_task);

            // (b) If pick_next_task moved a Dead task into task_to_drop, we are NOT
            //     performing the switch so finish_switch() will never run.  Drop the
            //     Arc here (inside the lock) as a last resort.  cleanup_task_resources
            //     was already called by pick_next_task, so the only allocation cost is
            //     the final Arc refcount decrement + deallocation of the Task struct.
            drop(self.cpus[cpu_index].task_to_drop.take());

            // (c) Restore the old running task as current_task.
            //     Non-idle current was placed in task_to_requeue by pick_next_task.
            //     Idle current was not (it is accessed via idle_task.clone()), so use
            //     the `current` Arc cloned at the start of yield_cpu.
            if let Some(prev) = self.cpus[cpu_index].task_to_requeue.take() {
                // SAFETY: scheduler lock held; exclusive access to task state.
                unsafe {
                    *prev.state.get() = TaskState::Running;
                }
                self.cpus[cpu_index].current_task = Some(prev);
            } else {
                // SAFETY: scheduler lock held.
                unsafe {
                    *current.state.get() = TaskState::Running;
                }
                self.cpus[cpu_index].current_task = Some(current.clone());
            }

            // (d) If `next` came from the class run queue (non-idle), re-enqueue it
            //     so it can be retried on the next tick.  Its context may be
            //     transiently invalid (e.g. stack not yet committed by a new task);
            //     it will be validated again when next picked.
            if !is_idle_fallback {
                // SAFETY: scheduler lock held.
                unsafe {
                    *next.state.get() = TaskState::Ready;
                }
                let class = self.class_table.class_for_task(&next);
                if let Some(cpu) = self.cpus.get_mut(cpu_index) {
                    cpu.class_rqs.enqueue(class, next);
                }
            }
            // For the idle fallback: state was set to Running by pick_next_task but the
            // idle task lives in idle_task.clone() not in class_rqs, so no re-enqueue
            // is needed.  The next pick_next_task will reset its state correctly.

            return None;
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

        Some(SwitchTarget {
            old_rsp_ptr: unsafe { &raw mut (*current.context.get()).saved_rsp },
            new_rsp_ptr: unsafe { &raw const (*next.context.get()).saved_rsp },
            old_fpu_ptr: current.fpu_state.get() as *mut u8,
            new_fpu_ptr: next.fpu_state.get() as *const u8,
            old_xcr0: current
                .xcr0_mask
                .load(core::sync::atomic::Ordering::Relaxed),
            new_xcr0: next.xcr0_mask.load(core::sync::atomic::Ordering::Relaxed),
        })
    }

    /// Performs the select cpu for task operation.
    fn select_cpu_for_task(&self) -> usize {
        if (self as *const Self).is_null() {
            return 0;
        }
        let mut best = 0usize;
        let mut best_load = usize::MAX;
        for (idx, cpu) in self.cpus.iter().enumerate() {
            let mut load = cpu.class_rqs.runnable_len();
            if let Some(current) = cpu.current_task.as_ref() {
                if self.class_table.class_for_task(current)
                    != crate::process::sched::SchedClassId::Idle
                {
                    load += 1;
                }
            }
            if load < best_load {
                best = idx;
                best_load = load;
            }
        }
        crate::serial_println!(
            "[trace][sched] select_cpu_for_task best={} load={}",
            best,
            best_load
        );
        best
    }

    /// Performs the migrate ready tasks for new class table operation.
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
