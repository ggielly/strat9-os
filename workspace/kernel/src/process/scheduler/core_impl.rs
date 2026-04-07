use super::{runtime_ops::idle_task_main, *};

/// Create a `SchedulerCpu` for the given CPU index (creates its idle task).
pub(super) fn create_cpu_scheduler(cpu_idx: usize) -> SchedulerCpu {
    crate::serial_println!(
        "[trace][sched] create_cpu_scheduler cpu={} create idle begin",
        cpu_idx
    );
    let idle_task = Task::new_kernel_task(idle_task_main, "idle", TaskPriority::Idle)
        .expect("Failed to create idle task");
    crate::serial_println!(
        "[trace][sched] create_cpu_scheduler cpu={} create idle done id={}",
        cpu_idx,
        idle_task.id.as_u64()
    );
    idle_task.set_sched_policy(crate::process::sched::SchedPolicy::Idle);
    let mut class_rqs = PerCpuClassRqSet::new();
    class_rqs.enqueue(crate::process::sched::SchedClassId::Idle, idle_task.clone());
    SchedulerCpu {
        class_rqs,
        current_task: None,
        current_runtime: crate::process::sched::CurrentRuntime::new(),
        idle_task,
        task_to_requeue: None,
        task_to_drop: None,
        need_resched: false,
        class_table: crate::process::sched::SchedClassTable::default(),
    }
}

impl GlobalSchedState {
    /// Create a new global scheduler state (no per-CPU runqueues — those live in LOCAL_SCHEDULERS).
    pub fn new() -> Self {
        crate::serial_println!("[trace][sched] GlobalSchedState::new enter");
        GlobalSchedState {
            all_tasks: BTreeMap::new(),
            all_tasks_scan: Vec::new(),
            task_cpu: BTreeMap::new(),
            wake_deadlines: BTreeMap::new(),
            wake_deadline_of: BTreeMap::new(),
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
        let members = map.entry(key).or_default();
        if !members.iter().any(|id| *id == task_id) {
            members.push(task_id);
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
    pub(crate) fn register_identity_locked(identity: &mut SchedIdentity, task: &Arc<Task>) {
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
        identity.pid_to_pgid.insert(pid, pgid);
        crate::serial_println!(
            "[trace][sched] register_identity pid_to_pgid inserted pid={}",
            pid
        );
        identity.pid_to_sid.insert(pid, sid);
        crate::serial_println!(
            "[trace][sched] register_identity pid_to_sid inserted pid={}",
            pid
        );
        Self::member_add(&mut identity.pgid_members, pgid, task_id);
        Self::member_add(&mut identity.sid_members, sid, task_id);
        crate::serial_println!(
            "[trace][sched] register_identity done tid={}",
            task_id.as_u64()
        );
    }

    /// Performs the unregister identity locked operation.
    pub(crate) fn unregister_identity_locked(
        identity: &mut SchedIdentity,
        task_id: TaskId,
        pid: Pid,
        tid: Tid,
    ) {
        identity.pid_to_task.remove(&pid);
        identity.tid_to_task.remove(&tid);
        if let Some(pgid) = identity.pid_to_pgid.remove(&pid) {
            Self::member_remove(&mut identity.pgid_members, pgid, task_id);
        }
        if let Some(sid) = identity.pid_to_sid.remove(&pid) {
            Self::member_remove(&mut identity.sid_members, sid, task_id);
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
        {
            let mut identity = SCHED_IDENTITY.lock();
            identity.parent_of.insert(child, parent);
            identity.children_of.entry(parent).or_default().push(child);
        }
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
        task.set_state(TaskState::Ready);
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
        task.home_cpu
            .store(cpu_index, core::sync::atomic::Ordering::Relaxed);
        crate::serial_println!(
            "[trace][sched] add_task_on_cpu task_cpu inserted tid={}",
            task_id.as_u64()
        );
        {
            let mut identity = SCHED_IDENTITY.lock();
            identity.pid_to_task.insert(task.pid, task_id);
            crate::serial_println!(
                "[trace][sched] add_task_on_cpu pid map inserted tid={}",
                task_id.as_u64()
            );
            identity.tid_to_task.insert(task.tid, task_id);
            crate::serial_println!(
                "[trace][sched] add_task_on_cpu tid map inserted tid={}",
                task_id.as_u64()
            );
            Self::register_identity_locked(&mut identity, &task);
            crate::serial_println!(
                "[trace][sched] add_task_on_cpu identity registered tid={}",
                task_id.as_u64()
            );
        }
        {
            let class = self.class_table.class_for_task(&task);
            if let Some(ref mut local_cpu) = *LOCAL_SCHEDULERS[cpu_index].lock() {
                local_cpu.class_rqs.enqueue(class, task);
                local_cpu.need_resched = true;
                crate::serial_println!(
                    "[trace][sched] add_task_on_cpu enqueued tid={} cpu={}",
                    task_id.as_u64(),
                    cpu_index
                );
            }
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
        assert_eq!(
            task.id,
            task_id,
            "scheduler corruption: insert_all_task_locked task.id={} != task_id={}",
            task.id.as_u64(),
            task_id.as_u64()
        );
        if self.all_tasks.contains_key(&task_id) {
            unsafe {
                core::arch::asm!("mov al, 'D'; out 0xe9, al", out("al") _);
            }
            crate::serial_force_println!(
                "[RACE] insert_all_task_locked: duplicate tid={} all_tasks={} all_tasks_scan={}",
                task_id.as_u64(),
                self.all_tasks.len(),
                self.all_tasks_scan.len()
            );
            panic!(
                "scheduler corruption: duplicate insert_all_task_locked tid={}",
                task_id.as_u64()
            );
        }
        self.all_tasks.insert(task_id, task.clone());
        self.all_tasks_scan.push(task);
        // Race/corruption diagnostic: all_tasks and all_tasks_scan must stay in sync.
        let bt_len = self.all_tasks.len();
        let scan_len = self.all_tasks_scan.len();
        if bt_len != scan_len {
            unsafe {
                core::arch::asm!("mov al, 'X'; out 0xe9, al", out("al") _);
            }
            crate::serial_force_println!(
                "[RACE] insert_all_task_locked: all_tasks={} != all_tasks_scan={} tid={}",
                bt_len,
                scan_len,
                task_id.as_u64()
            );
            panic!(
                "scheduler corruption: insert_all_task_locked len mismatch all_tasks={} all_tasks_scan={} tid={}",
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
                unsafe { core::arch::asm!("mov al, 'Z'; out 0xe9, al", out("al") _) };
                crate::serial_force_println!(
                    "[RACE] remove_all_task_locked: tid={} in all_tasks but NOT in all_tasks_scan",
                    task_id.as_u64()
                );
                panic!(
                    "scheduler corruption: remove_all_task_locked missing scan entry tid={}",
                    task_id.as_u64()
                );
            }
        }
        let bt_len = self.all_tasks.len();
        let scan_len = self.all_tasks_scan.len();
        if bt_len != scan_len {
            unsafe {
                core::arch::asm!("mov al, 'X'; out 0xe9, al", out("al") _);
            }
            crate::serial_force_println!(
                "[RACE] remove_all_task_locked: all_tasks={} != all_tasks_scan={} tid={}",
                bt_len,
                scan_len,
                task_id.as_u64()
            );
            panic!(
                "scheduler corruption: remove_all_task_locked len mismatch all_tasks={} all_tasks_scan={} tid={}",
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
    ///
    /// NOTE: `blocked_tasks` lives in the separate `BLOCKED_TASKS` lock.
    /// This method now only handles the fallback path (task not yet blocked,
    /// set `wake_pending`). The primary wake path is in `wake_task()`.
    pub fn wake_task_locked(&mut self, id: TaskId) -> (bool, Option<usize>) {
        self.clear_task_wake_deadline_locked(id);
        // Fallback: task is not yet in BLOCKED_TASKS (still transitioning to
        // Blocked). Set wake_pending so block_current_task will skip blocking.
        if let Some(task) = self.all_tasks.get(&id) {
            task.wake_pending
                .store(true, core::sync::atomic::Ordering::Release);
            (true, None)
        } else {
            (false, None)
        }
    }

    /// Attempts to reap child locked.
    /// If `target` is `Some(tid)`, only reaps that child; otherwise, reaps any child.
    /// Returns `WaitChildResult` indicating the outcome.
    /// Must be called with the scheduler lock held.
    ///
    pub fn try_reap_child_locked(
        &mut self,
        parent: TaskId,
        target: Option<TaskId>,
    ) -> WaitChildResult {
        // First, check children under SCHED_IDENTITY lock.
        let target_is_child = {
            let identity = SCHED_IDENTITY.lock();
            let Some(children_view) = identity.children_of.get(&parent) else {
                return WaitChildResult::NoChildren;
            };

            if children_view.is_empty() {
                return WaitChildResult::NoChildren;
            }

            let target_is_child = if let Some(target_id) = target {
                children_view.iter().any(|&id| id == target_id)
            } else {
                true
            };
            target_is_child
        };

        if !target_is_child {
            return WaitChildResult::NoChildren;
        }

        // Find the zombie child — re-check children under SCHED_IDENTITY.
        let zombie = {
            let identity = SCHED_IDENTITY.lock();
            let children = match identity.children_of.get(&parent) {
                Some(c) => c.clone(),
                None => return WaitChildResult::NoChildren,
            };
            children
                .iter()
                .copied()
                .find(|id| target.map_or(true, |t| t == *id) && self.zombies.contains_key(id))
        };

        if let Some(child) = zombie {
            let (status, child_pid) = self.zombies.remove(&child).unwrap_or((0, 0));
            // Remove from all_tasks now so that pick_next_task (if it races with
            // reaping) will see was_registered=false and skip cleanup_task_resources.
            let reaped_task = self.remove_all_task_locked(child);
            if let Some(task) = reaped_task.as_ref() {
                super::task_ops::cleanup_task_resources(task);
            }
            let child_tid = reaped_task.as_ref().map(|t| t.tid);
            if child_pid != 0 {
                if let Some(tid) = child_tid {
                    let mut identity = SCHED_IDENTITY.lock();
                    Self::unregister_identity_locked(&mut identity, child, child_pid, tid);
                }
            }
            {
                let mut identity = SCHED_IDENTITY.lock();
                if let Some(children) = identity.children_of.get_mut(&parent) {
                    children.retain(|&id| id != child);
                    if children.is_empty() {
                        identity.children_of.remove(&parent);
                    }
                }
                identity.parent_of.remove(&child);
            }
            return WaitChildResult::Reaped {
                child,
                pid: child_pid,
                status,
            };
        }

        WaitChildResult::StillRunning
    }

    /// Select the least-loaded CPU for a newly created task.
    ///
    /// Uses **blocking** `LOCAL_SCHEDULERS[i].lock()` for each CPU while
    /// `GLOBAL_SCHED_STATE` is already held by the caller.  This is safe because the
    /// hot-path only ever does `try_lock_no_irqsave` on `GLOBAL_SCHED_STATE` (so it
    /// cannot deadlock with us), but it may briefly stall behind a timer tick
    /// that holds a LOCAL lock.  The stall is bounded by one tick period.
    fn select_cpu_for_task(&self) -> usize {
        // Early boot: before the first real task is running, keep all new tasks
        // on the BSP. Spreading init/shell/status across CPUs at this point can
        // strand boot-critical work on AP scheduler instances that have not yet
        // entered their steady-state scheduling loop.
        let n = active_cpu_count();
        let all_idle = (0..n).all(|i| {
            LOCAL_SCHEDULERS[i]
                .lock()
                .as_ref()
                .map(|cpu| cpu.current_task.is_none())
                .unwrap_or(true)
        });
        if all_idle {
            crate::serial_println!("[trace][sched] select_cpu_for_task early-boot best=0");
            return 0;
        }
        let mut best = 0usize;
        let mut best_load = usize::MAX;
        for idx in 0..n {
            let load = {
                let guard = LOCAL_SCHEDULERS[idx].lock();
                if let Some(ref cpu) = *guard {
                    let mut l = cpu.class_rqs.runnable_len();
                    if let Some(current) = cpu.current_task.as_ref() {
                        if self.class_table.class_for_task(current)
                            != crate::process::sched::SchedClassId::Idle
                        {
                            l += 1;
                        }
                    }
                    l
                } else {
                    0
                }
            };
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
            let state = task.get_state();
            if state != TaskState::Ready {
                continue;
            }
            let cpu = self.task_cpu.get(id).copied().unwrap_or(0);
            ready.push((*id, task.clone(), cpu));
        }

        for (id, task, cpu_idx) in ready {
            let mut guard = LOCAL_SCHEDULERS[cpu_idx].lock();
            let Some(ref mut cpu) = *guard else {
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

//  Per-CPU hot-path helpers
//
// These functions operate primarily on `SchedulerCpu` (acquired via
// `LOCAL_SCHEDULERS[cpu_index]`).  Most never touch the global `SCHEDULER`
// lock.  The one exception is `steal_task_local`, which does a **non-blocking**
// `GLOBAL_SCHED_STATE.try_lock_no_irqsave()` to update `task_cpu` after a successful
// steal.  This is an intentional lock-order inversion (LOCAL held, then GLOBAL
// attempted) that is safe because the try-lock never blocks — if GLOBAL_SCHED_STATE is
// contended, we simply skip stealing.
//
// Lock order for steal: own LOCAL held → try_lock GLOBAL → try_lock sibling
// LOCALs.  Never blocking-wait, so no deadlock possible.

/// Steal a task from the busiest sibling CPU using per-CPU LOCAL locks.
///
/// Called with `cpu` borrowed from `LOCAL_SCHEDULERS[cpu_index]` (our own
/// LOCAL lock already held). Uses `try_lock_no_irqsave` on sibling entries —
/// if a sibling or the global scheduler state is contended, we skip stealing
/// rather than waiting.
pub(super) fn steal_task_local(cpu: &mut SchedulerCpu, cpu_index: usize) -> Option<Arc<Task>> {
    let now_tick = TICK_COUNT.load(Ordering::Relaxed);
    if now_tick < LAST_STEAL_TICK[cpu_index].load(Ordering::Relaxed) + STEAL_COOLDOWN_TICKS {
        return None;
    }

    // Best-effort only: if a cold path is holding the global scheduler, skip
    // stealing instead of blocking the hot path.
    let mut scheduler = GLOBAL_SCHED_STATE.try_lock_no_irqsave()?;
    let sched = scheduler.as_mut()?;

    let n = active_cpu_count();
    let my_load = cpu.class_rqs.runnable_len();

    let mut best_cpu = None;
    let mut best_load = 0usize;

    for i in 0..n {
        if i == cpu_index {
            continue;
        }
        // try_lock_no_irqsave: returns immediately if contended (no deadlock).
        if let Some(guard) = LOCAL_SCHEDULERS[i].try_lock_no_irqsave() {
            if let Some(ref sib) = *guard {
                let load = sib.class_rqs.runnable_len();
                if load > best_load {
                    best_load = load;
                    best_cpu = Some(i);
                }
            }
        }
    }

    if best_load < my_load.saturating_add(STEAL_IMBALANCE_MIN) {
        return None;
    }
    let steal_from = best_cpu?;

    // Re-acquire the sibling lock to perform the steal.
    if let Some(mut guard) = LOCAL_SCHEDULERS[steal_from].try_lock_no_irqsave() {
        if let Some(ref mut sib) = *guard {
            if sib.class_rqs.runnable_len() < 2 {
                return None;
            }
            if let Some(task) = sib.class_rqs.steal_candidate(&sib.class_table) {
                sched.task_cpu.insert(task.id, cpu_index);
                task.home_cpu
                    .store(cpu_index, core::sync::atomic::Ordering::Relaxed);
                if cpu_is_valid(cpu_index) {
                    CPU_STEAL_IN_COUNT[cpu_index].fetch_add(1, Ordering::Relaxed);
                }
                if cpu_is_valid(steal_from) {
                    CPU_STEAL_OUT_COUNT[steal_from].fetch_add(1, Ordering::Relaxed);
                }
                LAST_STEAL_TICK[cpu_index].store(now_tick, Ordering::Relaxed);
                return Some(task);
            }
        }
    }
    None
}

/// Pick the next task using only per-CPU LOCAL state.
///
/// Handles current task disposition (re-queue, drop-for-cleanup, or ignore if
/// Blocked), then picks from the local class_rqs, falls back to work-stealing,
/// and finally returns the idle task.
///
/// **Dead tasks**: if the current task is Dead, it goes into `task_to_drop`.
/// Global map cleanup (`all_tasks`, `task_cpu`, etc.) must have been performed
/// by the caller (e.g., `exit_current_task`) BEFORE reaching this point.
pub(super) fn pick_next_task_local(cpu: &mut SchedulerCpu, cpu_index: usize) -> Arc<Task> {
    // Step 1: dispose of the current task.
    if let Some(task) = cpu.current_task.take() {
        match task.get_state() {
            TaskState::Running => {
                task.set_state(TaskState::Ready);
                if !Arc::ptr_eq(&task, &cpu.idle_task) {
                    // Defer re-queue to finish_switch (not yet safe to enqueue —
                    // another CPU could steal it before our context is saved).
                    cpu.task_to_requeue = Some(task);
                }
            }
            TaskState::Dead => {
                // Global maps already cleaned by exit_current_task / kill_task.
                // Defer the Arc drop so KernelStack::drop → buddy_alloc runs
                // outside any lock.
                cpu.task_to_drop = Some(task);
            }
            TaskState::Blocked | TaskState::Ready => {
                // Blocked: moved to blocked_tasks by block_current_task — do nothing.
                // Ready: shouldn't normally occur for current_task; safe to ignore.
            }
        }
    }

    // Step 2: pick from local class_rqs.
    let next = if let Some(next) = cpu.class_rqs.pick_next(&cpu.class_table) {
        next
    } else if let Some(stolen) = steal_task_local(cpu, cpu_index) {
        // Step 3: try work-stealing from a sibling CPU.
        stolen
    } else {
        // Step 4: idle fallback.
        cpu.idle_task.clone()
    };

    next.set_state(TaskState::Running);
    cpu.current_task = Some(next.clone());
    cpu.current_runtime = crate::process::sched::CurrentRuntime::new();
    next
}

/// Prepare a LOCAL-only context switch.
///
/// Updates the TSS, SYSCALL RSP, and CR3 for the next task. Returns the
/// raw pointer pair needed by `do_switch_context`.
///
/// Returns `None` if there is no task to switch to (same task or invalid context).
pub(super) fn yield_cpu_local(cpu: &mut SchedulerCpu, cpu_index: usize) -> Option<SwitchTarget> {
    let current = cpu.current_task.as_ref()?.clone();

    let next = pick_next_task_local(cpu, cpu_index);

    if Arc::ptr_eq(&current, &next) {
        return None;
    }
    if cpu_is_valid(cpu_index) {
        CPU_SWITCH_COUNT[cpu_index].fetch_add(1, Ordering::Relaxed);
    }

    if let Err(e) = validate_task_context(&next) {
        let bad_rsp = unsafe { (*next.context.get()).saved_rsp };
        let stk_base = next.kernel_stack.virt_base.as_u64();
        let stk_top = stk_base + next.kernel_stack.size as u64;
        crate::serial_println!(
            "[sched-local] WARN: invalid ctx task='{}' id={} cpu={}: {} \
             rsp={:#x} stack=[{:#x}..{:#x}] — restoring current",
            next.name,
            next.id.as_u64(),
            cpu_index,
            e,
            bad_rsp,
            stk_base,
            stk_top,
        );

        // Restore invariants: undo what pick_next_task_local mutated.
        let is_idle = Arc::ptr_eq(&next, &cpu.idle_task);
        drop(cpu.task_to_drop.take());
        if let Some(prev) = cpu.task_to_requeue.take() {
            prev.set_state(TaskState::Running);
            cpu.current_task = Some(prev);
        } else {
            current.set_state(TaskState::Running);
            cpu.current_task = Some(current.clone());
        }
        if !is_idle {
            next.set_state(TaskState::Ready);
            let class = cpu.class_table.class_for_task(&next);
            cpu.class_rqs.enqueue(class, next);
        }
        return None;
    }

    // Update TSS.rsp0 and SYSCALL kernel RSP for the new task.
    let stack_top = next.kernel_stack.virt_base.as_u64() + next.kernel_stack.size as u64;
    crate::arch::x86_64::tss::set_kernel_stack(x86_64::VirtAddr::new(stack_top));
    crate::arch::x86_64::syscall::set_kernel_rsp(stack_top);

    // Switch CR3 if the new task has a different address space.
    // SAFETY: The new task's address space has a valid PML4 with the kernel half mapped.
    unsafe {
        next.process.address_space_arc().switch_to();
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

/// Post-switch cleanup using only LOCAL state: re-enqueue the previous task
/// and optionally extract the task-to-drop for deferred deallocation.
pub(super) fn drain_post_switch_local(
    cpu: &mut SchedulerCpu,
    take_drop: bool,
) -> Option<Arc<Task>> {
    let task_to_drop = if take_drop {
        cpu.task_to_drop.take()
    } else {
        None
    };
    if let Some(task) = cpu.task_to_requeue.take() {
        let class = cpu.class_table.class_for_task(&task);
        cpu.class_rqs.enqueue(class, task);
    }
    task_to_drop
}
