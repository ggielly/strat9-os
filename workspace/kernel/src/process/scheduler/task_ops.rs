use super::{runtime_ops::finish_switch, *};
use crate::memory::UserSliceWrite;

static PENDING_SILO_CLEANUPS: SpinLock<Vec<TaskId>> = SpinLock::new(Vec::new());

/// Mark the current task as Dead and yield to the scheduler.
///
/// Called by SYS_PROC_EXIT. The task will not be re-queued because
/// `pick_next_task()` only re-queues tasks in `Running` state.
/// This function does not return.
pub fn exit_current_task(exit_code: i32) -> ! {
    // -- clear_child_tid (POSIX pthread join) --
    // Must happen BEFORE we drop the address space - write 0 to the TID pointer
    // and do a futex_wake so any waiting pthread_join() can proceed.
    if let Some(task) = current_task_clone() {
        let tidptr = task
            .clear_child_tid
            .load(core::sync::atomic::Ordering::Relaxed);
        if tidptr != 0 {
            let zero = 0u32.to_ne_bytes();
            // POSIX clear_child_tid targets a userspace u32; keep the existing
            // alignment check for futex semantics, but validate the mapping via
            // UserSliceWrite instead of dereferencing the raw userspace pointer.
            if (tidptr & 3) == 0 {
                if let Ok(user) = UserSliceWrite::new(tidptr, zero.len()) {
                    user.copy_from(&zero);
                }
                // Futex wake: wake all threads waiting on this address (e.g. pthread_join).
                let _ = crate::syscall::futex::sys_futex_wake(tidptr, u32::MAX);
            }
        }
    }

    let cpu_index = current_cpu_index();
    let mut parent_to_signal: Option<TaskId> = None;
    let mut ipi_to_cpu: Option<usize> = None;
    {
        let saved_flags = save_flags_and_cli();
        let mut scheduler = GLOBAL_SCHED_STATE.lock();
        let current = {
            let local = LOCAL_SCHEDULERS[cpu_index].lock();
            local.as_ref().and_then(|cpu| cpu.current_task.clone())
        };
        if let Some(ref mut sched) = *scheduler {
            if let Some(current) = current {
                let current_id = current.id;
                let current_pid = current.pid;
                let parent = sched.parent_of.get(&current_id).copied();
                let _ = sched.clear_task_wake_deadline_locked(current_id);
                current.set_state(TaskState::Dead);
                // Do NOT call cleanup_task_resources or all_tasks.remove() here!
                // The task is still in current_task[cpu_index], and an interrupt
                // could access it. Instead, mark it Dead and let pick_next_task
                // handle the cleanup when it moves the task to task_to_drop.
                // We only remove task_cpu and identity mappings to prevent
                // lookups while the task is dying.
                sched.task_cpu.remove(&current_id);
                sched.unregister_identity_locked(current_id, current_pid, current.tid);
                sched.parent_of.remove(&current_id);

                ipi_to_cpu = reparent_children(sched, current_id);

                if parent.is_some() {
                    sched.zombies.insert(current_id, (exit_code, current_pid));
                }
                if let Some(parent_id) = parent {
                    let (_, ipi_wake) = sched.wake_task_locked(parent_id);
                    if ipi_to_cpu.is_none() {
                        ipi_to_cpu = ipi_wake;
                    }
                    parent_to_signal = Some(parent_id);
                }
            }
        }
        drop(scheduler);
        restore_flags(saved_flags);
    }
    if let Some(ci) = ipi_to_cpu {
        send_resched_ipi_to_cpu(ci);
    }

    if let Some(parent_id) = parent_to_signal {
        // Must happen outside scheduler lock to avoid lock recursion.
        let _ =
            crate::process::signal::send_signal(parent_id, crate::process::signal::Signal::SIGCHLD);
    }

    // Yield to pick the next task. Since we're Dead, we won't come back.
    yield_task();

    // Safety net - should never reach here
    loop {
        crate::arch::x86_64::hlt();
    }
}

/// Get the current task's ID (if any task is running).
pub fn current_task_id() -> Option<TaskId> {
    let saved_flags = save_flags_and_cli();
    let cpu_index = current_cpu_index();
    let id = LOCAL_SCHEDULERS[cpu_index]
        .lock()
        .as_ref()
        .and_then(|cpu| cpu.current_task.as_ref().map(|t| t.id));
    restore_flags(saved_flags);
    id
}

/// Get the current task's ID without blocking (safe for exceptions).
pub fn current_task_id_try() -> Option<TaskId> {
    let saved_flags = save_flags_and_cli();
    let cpu_index = current_cpu_index();
    let id = LOCAL_SCHEDULERS[cpu_index]
        .try_lock_no_irqsave()
        .and_then(|guard| {
            guard
                .as_ref()
                .and_then(|cpu| cpu.current_task.as_ref().map(|t| t.id))
        });
    restore_flags(saved_flags);
    id
}

/// Get the current process ID (POSIX pid).
pub fn current_pid() -> Option<Pid> {
    current_task_clone().map(|t| t.pid)
}

/// Get the current thread ID (POSIX tid).
pub fn current_tid() -> Option<Tid> {
    current_task_clone().map(|t| t.tid)
}

/// Get the current process group id.
pub fn current_pgid() -> Option<Pid> {
    current_task_clone().map(|t| t.pgid.load(Ordering::Relaxed))
}

/// Get the current session id.
pub fn current_sid() -> Option<Pid> {
    current_task_clone().map(|t| t.sid.load(Ordering::Relaxed))
}

/// Get the current task (cloned Arc), if any.
#[track_caller]
pub fn current_task_clone() -> Option<Arc<Task>> {
    let saved_flags = save_flags_and_cli();
    let cpu_index = current_cpu_index();
    let caller = core::panic::Location::caller();
    let task = LOCAL_SCHEDULERS[cpu_index].lock().as_ref().and_then(|cpu| {
        let arc = cpu.current_task.as_ref()?;
        let strong = Arc::strong_count(arc);
        // Heuristic only: keep the warning, but do not mutate scheduler state here.
        if strong == 0 || strong > (isize::MAX as usize) / 2 {
            let ptr = Arc::as_ptr(arc) as *const u8;
            crate::serial_println!(
                "[sched] CORRUPT Arc refcount! cpu={} strong={:#x} ptr={:p} caller={}:{}",
                cpu_index,
                strong,
                ptr,
                caller.file(),
                caller.line(),
            );
        }
        Some(arc.clone())
    });
    restore_flags(saved_flags);
    task
}

/// Best-effort, non-blocking variant of [`current_task_clone`].
///
/// Returns `None` when the scheduler lock is contended.
/// Useful in cleanup paths where blocking on `GLOBAL_SCHED_STATE.lock()` could deadlock.
#[track_caller]
pub fn current_task_clone_try() -> Option<Arc<Task>> {
    let saved_flags = save_flags_and_cli();
    let cpu_index = current_cpu_index();
    let caller = core::panic::Location::caller();
    let task = LOCAL_SCHEDULERS[cpu_index]
        .try_lock_no_irqsave()
        .and_then(|guard| {
            guard.as_ref().and_then(|cpu| {
                let arc = cpu.current_task.as_ref()?;
                let strong = Arc::strong_count(arc);
                // Heuristic only: keep the warning, but do not mutate scheduler state here.
                if strong == 0 || strong > (isize::MAX as usize) / 2 {
                    let ptr = Arc::as_ptr(arc) as *const u8;
                    crate::serial_println!(
                        "[sched] CORRUPT Arc refcount! cpu={} strong={:#x} ptr={:p} caller={}:{}",
                        cpu_index,
                        strong,
                        ptr,
                        caller.file(),
                        caller.line(),
                    );
                }
                Some(arc.clone())
            })
        });
    restore_flags(saved_flags);
    task
}

/// Debug-only blocking variant used to diagnose early ring3 entry stalls.
///
/// Spins with `try_lock()` so we can emit progress logs instead of blocking
/// silently on `GLOBAL_SCHED_STATE.lock()`.
pub fn current_task_clone_spin_debug(trace_label: &str) -> Option<Arc<Task>> {
    let saved_flags = save_flags_and_cli();
    let cpu_index = current_cpu_index();
    let mut spins = 0usize;
    let result = loop {
        if let Some(guard) = LOCAL_SCHEDULERS[cpu_index].try_lock_no_irqsave() {
            break guard.as_ref().and_then(|cpu| {
                if cpu.current_task.is_none() {
                    unsafe { core::arch::asm!("mov al, 'N'; out 0xe9, al", out("al") _) };
                    return None;
                }
                let arc = cpu.current_task.as_ref().unwrap();
                let strong = Arc::strong_count(arc);
                // Racy, pifometric diagnostic only: strong_count can move
                // concurrently, so this is a heuristic for suspicious
                // scheduler state, not a formal corruption proof.
                if strong == 0 || strong > (isize::MAX as usize) / 2 {
                    let ptr = Arc::as_ptr(arc) as *const u8;
                    crate::serial_force_println!(
                        "[trace][sched] {} suspicious current_task heuristic cpu={} strong={:#x} ptr={:p}",
                        trace_label,
                        cpu_index,
                        strong,
                        ptr,
                    );
                }
                Some(arc.clone())
            });
        }

        spins = spins.saturating_add(1);
        if spins == 2_000_000 {
            crate::serial_force_println!(
                "[trace][sched] {} waiting current_task cpu={} owner_cpu={}",
                trace_label,
                cpu_index,
                GLOBAL_SCHED_STATE.owner_cpu()
            );
            spins = 0;
        }
        core::hint::spin_loop();
    };
    restore_flags(saved_flags);
    result
}

/// Resolve a POSIX pid to internal TaskId.
pub fn get_task_id_by_pid(pid: Pid) -> Option<TaskId> {
    let saved_flags = save_flags_and_cli();
    let out = {
        let scheduler = GLOBAL_SCHED_STATE.lock();
        if let Some(ref sched) = *scheduler {
            sched.pid_to_task.get(&pid).copied()
        } else {
            None
        }
    };
    restore_flags(saved_flags);
    out
}

/// Resolve a POSIX pid to the corresponding task.
pub fn get_task_by_pid(pid: Pid) -> Option<Arc<Task>> {
    let tid = get_task_id_by_pid(pid)?;
    get_task_by_id(tid)
}

/// Resolve a direct child of `parent` by POSIX pid.
///
/// Unlike the global pid index, this remains valid after the child has called
/// exit and before it is reaped, because the task object stays in `all_tasks`
/// until waitpid consumes the zombie.
pub fn get_child_task_id_by_pid(parent: TaskId, pid: Pid) -> Option<TaskId> {
    let saved_flags = save_flags_and_cli();
    let out = {
        let scheduler = GLOBAL_SCHED_STATE.lock();
        if let Some(ref sched) = *scheduler {
            sched.children_of.get(&parent).and_then(|children| {
                children.iter().copied().find(|child_id| {
                    sched
                        .all_tasks
                        .get(child_id)
                        .map(|task| task.pid == pid)
                        .unwrap_or(false)
                })
            })
        } else {
            None
        }
    };
    restore_flags(saved_flags);
    out
}

/// Resolve a POSIX tid to the corresponding internal task id.
pub fn get_task_id_by_tid(tid: Tid) -> Option<TaskId> {
    let saved_flags = save_flags_and_cli();
    let out = {
        let scheduler = GLOBAL_SCHED_STATE.lock();
        if let Some(ref sched) = *scheduler {
            sched
                .tid_to_task
                .get(&tid)
                .copied()
                .or_else(|| sched.pid_to_task.get(&(tid as Pid)).copied())
        } else {
            None
        }
    };
    restore_flags(saved_flags);
    out
}

/// Resolve a direct child of `parent` by POSIX tid.
///
/// This remains valid for dead-but-not-yet-reaped threads because it scans the
/// caller's child set and the retained task object instead of relying on the
/// global tid index removed during exit.
pub fn get_child_task_id_by_tid(parent: TaskId, tid: Tid) -> Option<TaskId> {
    let saved_flags = save_flags_and_cli();
    let out = {
        let scheduler = GLOBAL_SCHED_STATE.lock();
        if let Some(ref sched) = *scheduler {
            sched.children_of.get(&parent).and_then(|children| {
                children.iter().copied().find(|child_id| {
                    sched
                        .all_tasks
                        .get(child_id)
                        .map(|task| task.tid == tid)
                        .unwrap_or(false)
                })
            })
        } else {
            None
        }
    };
    restore_flags(saved_flags);
    out
}

/// Resolve a PID to the current process group id.
pub fn get_pgid_by_pid(pid: Pid) -> Option<Pid> {
    let saved_flags = save_flags_and_cli();
    let out = {
        let scheduler = GLOBAL_SCHED_STATE.lock();
        if let Some(ref sched) = *scheduler {
            sched.pid_to_pgid.get(&pid).copied()
        } else {
            None
        }
    };
    restore_flags(saved_flags);
    out
}

/// Resolve a PID to the current session id.
pub fn get_sid_by_pid(pid: Pid) -> Option<Pid> {
    let saved_flags = save_flags_and_cli();
    let out = {
        let scheduler = GLOBAL_SCHED_STATE.lock();
        if let Some(ref sched) = *scheduler {
            sched.pid_to_sid.get(&pid).copied()
        } else {
            None
        }
    };
    restore_flags(saved_flags);
    out
}

/// Collect task IDs that currently belong to process group `pgid`.
pub fn get_task_ids_in_pgid(pgid: Pid) -> alloc::vec::Vec<TaskId> {
    use alloc::vec::Vec;
    let saved_flags = save_flags_and_cli();
    let out = {
        let scheduler = GLOBAL_SCHED_STATE.lock();
        if let Some(ref sched) = *scheduler {
            sched
                .pgid_members
                .get(&pgid)
                .cloned()
                .unwrap_or_else(Vec::new)
        } else {
            Vec::new()
        }
    };
    restore_flags(saved_flags);
    out
}

/// Collect task IDs that currently belong to thread group `tgid`.
pub fn get_task_ids_in_tgid(tgid: Pid) -> alloc::vec::Vec<TaskId> {
    use alloc::vec::Vec;
    let saved_flags = save_flags_and_cli();
    let out = {
        let scheduler = GLOBAL_SCHED_STATE.lock();
        if let Some(ref sched) = *scheduler {
            sched
                .all_tasks
                .values()
                .filter(|task| task.tgid == tgid)
                .map(|task| task.id)
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        }
    };
    restore_flags(saved_flags);
    out
}

/// Set process group id for `target_pid` (or current if `None`).
pub fn set_process_group(
    requester: TaskId,
    target_pid: Option<Pid>,
    new_pgid: Option<Pid>,
) -> Result<Pid, crate::syscall::error::SyscallError> {
    use crate::syscall::error::SyscallError;

    let saved_flags = save_flags_and_cli();
    let result = (|| -> Result<Pid, SyscallError> {
        let mut scheduler = GLOBAL_SCHED_STATE.lock();
        let sched = scheduler.as_mut().ok_or(SyscallError::Fault)?;

        let requester_task = sched
            .all_tasks
            .get(&requester)
            .cloned()
            .ok_or(SyscallError::Fault)?;
        let requester_sid = requester_task.sid.load(Ordering::Relaxed);

        let target_id = match target_pid {
            None => requester,
            Some(pid) => sched
                .pid_to_task
                .get(&pid)
                .copied()
                .ok_or(SyscallError::NotFound)?,
        };

        if target_id != requester {
            let is_child = sched
                .children_of
                .get(&requester)
                .map(|children| children.iter().any(|child| *child == target_id))
                .unwrap_or(false);
            if !is_child {
                return Err(SyscallError::PermissionDenied);
            }
        }

        let target_task = sched
            .all_tasks
            .get(&target_id)
            .cloned()
            .ok_or(SyscallError::NotFound)?;
        let target_pid_value = target_task.pid;
        let target_sid = target_task.sid.load(Ordering::Relaxed);

        if target_sid != requester_sid {
            return Err(SyscallError::PermissionDenied);
        }

        if target_pid_value == target_sid {
            return Err(SyscallError::PermissionDenied);
        }

        let desired_pgid = new_pgid.unwrap_or(target_pid_value);
        if desired_pgid != target_pid_value {
            let group_leader_tid = sched
                .pid_to_task
                .get(&desired_pgid)
                .copied()
                .ok_or(SyscallError::NotFound)?;
            let group_leader = sched
                .all_tasks
                .get(&group_leader_tid)
                .ok_or(SyscallError::NotFound)?;
            if group_leader.sid.load(Ordering::Relaxed) != target_sid {
                return Err(SyscallError::PermissionDenied);
            }
        }

        let old_pgid = target_task.pgid.load(Ordering::Relaxed);
        target_task.pgid.store(desired_pgid, Ordering::Relaxed);
        if old_pgid != desired_pgid {
            GlobalSchedState::member_remove(&mut sched.pgid_members, old_pgid, target_id);
            GlobalSchedState::member_add(&mut sched.pgid_members, desired_pgid, target_id);
            sched.pid_to_pgid.insert(target_pid_value, desired_pgid);
        }
        Ok(desired_pgid)
    })();
    restore_flags(saved_flags);
    result
}

/// Create a new session for the calling task.
pub fn create_session(requester: TaskId) -> Result<Pid, crate::syscall::error::SyscallError> {
    use crate::syscall::error::SyscallError;

    let saved_flags = save_flags_and_cli();
    let result = (|| -> Result<Pid, SyscallError> {
        let mut scheduler = GLOBAL_SCHED_STATE.lock();
        let sched = scheduler.as_mut().ok_or(SyscallError::Fault)?;

        let requester_task = sched
            .all_tasks
            .get(&requester)
            .cloned()
            .ok_or(SyscallError::Fault)?;
        let pid = requester_task.pid;
        if requester_task.pgid.load(Ordering::Relaxed) == pid {
            return Err(SyscallError::PermissionDenied);
        }

        let old_sid = requester_task.sid.load(Ordering::Relaxed);
        let old_pgid = requester_task.pgid.load(Ordering::Relaxed);
        requester_task.sid.store(pid, Ordering::Relaxed);
        requester_task.pgid.store(pid, Ordering::Relaxed);
        GlobalSchedState::member_remove(&mut sched.sid_members, old_sid, requester);
        GlobalSchedState::member_remove(&mut sched.pgid_members, old_pgid, requester);
        GlobalSchedState::member_add(&mut sched.sid_members, pid, requester);
        GlobalSchedState::member_add(&mut sched.pgid_members, pid, requester);
        sched.pid_to_sid.insert(pid, pid);
        sched.pid_to_pgid.insert(pid, pid);
        Ok(pid)
    })();
    restore_flags(saved_flags);
    result
}

/// Get a task by its TaskId (if still registered).
pub fn get_task_by_id(id: TaskId) -> Option<Arc<Task>> {
    let saved_flags = save_flags_and_cli();
    let task = {
        let scheduler = GLOBAL_SCHED_STATE.lock();
        if let Some(ref sched) = *scheduler {
            sched.all_tasks.get(&id).cloned()
        } else {
            None
        }
    };
    restore_flags(saved_flags);
    task
}

/// Update a task scheduling policy and requeue if needed.
pub fn set_task_sched_policy(id: TaskId, policy: crate::process::sched::SchedPolicy) -> bool {
    let saved_flags = save_flags_and_cli();
    let mut ipi_to_cpu: Option<usize> = None;
    let updated = {
        let mut scheduler = GLOBAL_SCHED_STATE.lock();
        if let Some(ref mut sched) = *scheduler {
            let cpu_index = sched.task_cpu.get(&id).copied().unwrap_or(0);
            let task = match sched.all_tasks.get(&id).cloned() {
                Some(t) => t,
                None => return false,
            };
            task.set_sched_policy(policy);
            let class = sched.class_table.class_for_task(&task);

            if let Some(ref mut local_cpu) = *LOCAL_SCHEDULERS[cpu_index].lock() {
                // If task is queued in ready classes, migrate it to the new class.
                if local_cpu.class_rqs.remove(id) {
                    local_cpu.class_rqs.enqueue(class, task.clone());
                }
                local_cpu.need_resched = true;
            }
            if cpu_index != current_cpu_index() {
                ipi_to_cpu = Some(cpu_index);
            }
            sched_trace(format_args!(
                "set_policy task={} cpu={} policy={:?}",
                id.as_u64(),
                cpu_index,
                policy
            ));
            true
        } else {
            false
        }
    };
    if let Some(ci) = ipi_to_cpu {
        send_resched_ipi_to_cpu(ci);
    }
    restore_flags(saved_flags);
    updated
}

/// Get parent task ID for a child task.
pub fn get_parent_id(child: TaskId) -> Option<TaskId> {
    let saved_flags = save_flags_and_cli();
    let parent = {
        let scheduler = GLOBAL_SCHED_STATE.lock();
        if let Some(ref sched) = *scheduler {
            sched.parent_of.get(&child).copied()
        } else {
            None
        }
    };
    restore_flags(saved_flags);
    parent
}

/// Get parent process ID for a child task.
pub fn get_parent_pid(child: TaskId) -> Option<Pid> {
    let parent_tid = get_parent_id(child)?;
    let parent = get_task_by_id(parent_tid)?;
    Some(parent.pid)
}

/// Try to reap a zombie child.
///
/// `target=None` means "any child".
pub fn try_wait_child(parent: TaskId, target: Option<TaskId>) -> WaitChildResult {
    let saved_flags = save_flags_and_cli();
    let result = {
        let mut scheduler = GLOBAL_SCHED_STATE.lock();
        if let Some(ref mut sched) = *scheduler {
            sched.try_reap_child_locked(parent, target)
        } else {
            WaitChildResult::NoChildren
        }
    };
    restore_flags(saved_flags);
    result
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
        // Hold GLOBAL and LOCAL together through the state transition and task
        // selection so a concurrent wake cannot observe the task as blocked,
        // requeue it, and race with us tearing down current_task.
        let mut scheduler = GLOBAL_SCHED_STATE.lock();
        let mut local = LOCAL_SCHEDULERS[cpu_index].lock();
        let out = if let Some(ref mut sched) = *scheduler {
            if let Some(ref mut cpu) = *local {
                if let Some(ref current) = cpu.current_task {
                    if current
                        .wake_pending
                        .swap(false, core::sync::atomic::Ordering::AcqRel)
                    {
                        // Pending wakeup consumed - do not block.
                        None
                    } else {
                        current.set_state(TaskState::Blocked);
                        sched.blocked_tasks.insert(current.id, current.clone());
                        super::core_impl::yield_cpu_local(cpu, cpu_index)
                    }
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };
        drop(local);
        drop(scheduler);
        out
    }; // Lock released

    if let Some(ref target) = switch_target {
        unsafe {
            crate::process::task::do_switch_context(target);
        }
        finish_switch();
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
/// from Ready -> Blocked inside `block_current_task()`), this function sets
/// the task's `wake_pending` flag so that `block_current_task()` will see
/// the pending wakeup and return immediately without actually blocking.
pub fn wake_task(id: TaskId) -> bool {
    let saved_flags = save_flags_and_cli();
    let (woken, ipi_cpu) = {
        let mut scheduler = GLOBAL_SCHED_STATE.lock();
        if let Some(ref mut sched) = *scheduler {
            sched.wake_task_locked(id)
        } else {
            (false, None)
        }
    };
    if let Some(ci) = ipi_cpu {
        send_resched_ipi_to_cpu(ci);
    }
    restore_flags(saved_flags);
    woken
}

/// Sets task wake deadline.
pub fn set_task_wake_deadline(id: TaskId, deadline_ns: u64) -> bool {
    let saved_flags = save_flags_and_cli();
    let out = {
        let mut scheduler = GLOBAL_SCHED_STATE.lock();
        if let Some(ref mut sched) = *scheduler {
            sched.set_task_wake_deadline_locked(id, deadline_ns)
        } else {
            false
        }
    };
    restore_flags(saved_flags);
    out
}

/// Performs the clear task wake deadline operation.
pub fn clear_task_wake_deadline(id: TaskId) -> bool {
    set_task_wake_deadline(id, 0)
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
        let mut scheduler = GLOBAL_SCHED_STATE.lock();
        if let Some(ref mut sched) = *scheduler {
            let my_cpu = current_cpu_index();
            let n = active_cpu_count();

            // Check if the task is the current task on any CPU.
            for ci in 0..n {
                let task_id_on_cpu = LOCAL_SCHEDULERS[ci]
                    .lock()
                    .as_ref()
                    .and_then(|cpu| cpu.current_task.as_ref().map(|t| (t.id, t.clone())));
                if let Some((tid, current)) = task_id_on_cpu {
                    if tid == id {
                        current.set_state(TaskState::Blocked);
                        sched.blocked_tasks.insert(current.id, current.clone());
                        suspended = true;
                        if ci == my_cpu {
                            // Re-acquire LOCAL to yield.  The gap between the
                            // probe above and this lock is safe because IRQs
                            // are disabled (save_flags_and_cli), so no timer
                            // tick can preempt us or mutate current_task.
                            let mut local = LOCAL_SCHEDULERS[ci].lock();
                            if let Some(ref mut cpu) = *local {
                                switch_target = super::core_impl::yield_cpu_local(cpu, ci);
                            }
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
                for ci in 0..n {
                    let removed = {
                        let mut local = LOCAL_SCHEDULERS[ci].lock();
                        if let Some(ref mut cpu) = *local {
                            cpu.class_rqs.remove(id)
                        } else {
                            false
                        }
                    };
                    if removed {
                        if let Some(task) = sched.all_tasks.get(&id) {
                            task.set_state(TaskState::Blocked);
                            sched.blocked_tasks.insert(task.id, task.clone());
                        }
                        suspended = true;
                        break;
                    }
                }
            }

            // Already blocked.
            if !suspended && sched.blocked_tasks.contains_key(&id) {
                suspended = true;
            }
        }
    } // scheduler lock released before IPI and context switch

    if let Some(ref target) = switch_target {
        unsafe {
            crate::process::task::do_switch_context(target);
        }
        finish_switch();
    }

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
    let mut ipi_to_cpu: Option<usize> = None;
    let resumed = {
        let mut scheduler = GLOBAL_SCHED_STATE.lock();
        if let Some(ref mut sched) = *scheduler {
            if let Some(task) = sched.blocked_tasks.remove(&id) {
                let _ = sched.clear_task_wake_deadline_locked(id);
                task.set_state(TaskState::Ready);
                let cpu_index = sched.task_cpu.get(&id).copied().unwrap_or(0);
                let class = sched.class_table.class_for_task(&task);
                if let Some(ref mut local_cpu) = *LOCAL_SCHEDULERS[cpu_index].lock() {
                    local_cpu.class_rqs.enqueue(class, task);
                    local_cpu.need_resched = true;
                }
                if cpu_index != current_cpu_index() {
                    ipi_to_cpu = Some(cpu_index);
                }
                true
            } else {
                false
            }
        } else {
            false
        }
    };
    if let Some(ci) = ipi_to_cpu {
        send_resched_ipi_to_cpu(ci);
    }
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
    let pid = crate::process::get_task_by_id(id)
        .map(|t| t.pid)
        .unwrap_or(0);
    crate::audit::log(
        crate::audit::AuditCategory::Process,
        pid,
        crate::silo::task_silo_id(id).unwrap_or(0),
        alloc::format!("kill_task tid={}", id.as_u64()),
    );
    let saved_flags = save_flags_and_cli();

    let mut switch_target: Option<SwitchTarget> = None;
    let mut killed = false;
    let mut ipi_to_cpu: Option<usize> = None;
    let mut parent_to_signal: Option<TaskId> = None;

    {
        let mut scheduler = GLOBAL_SCHED_STATE.lock();
        if let Some(ref mut sched) = *scheduler {
            // Keep parent/waitpid semantics even for forced termination paths.
            // A killed child must still become a zombie until reaped by waitpid().
            const FORCED_KILL_EXIT_CODE: i32 = 1;
            let my_cpu = current_cpu_index();

            // Check if the task is the current task on any CPU.
            let n = active_cpu_count();
            let mut running_hit: Option<(usize, Arc<Task>)> = None;
            for ci in 0..n {
                let hit = LOCAL_SCHEDULERS[ci].lock().as_ref().and_then(|cpu| {
                    cpu.current_task
                        .as_ref()
                        .map(|t| (t.id, t.get_state(), t.clone()))
                });
                if let Some((tid, state, current)) = hit {
                    if tid == id {
                        // Check if already marked Dead by a previous kill attempt
                        if state != TaskState::Dead {
                            running_hit = Some((ci, current));
                        }
                        break;
                    }
                }
            }
            if let Some((ci, current)) = running_hit {
                let task_pid = current.pid;
                let _ = sched.clear_task_wake_deadline_locked(id);
                current.set_state(TaskState::Dead);
                // Do NOT call cleanup_task_resources or all_tasks.remove() here!
                // The task is still in current_task[ci], and an interrupt could
                // access it. Instead, mark it Dead and let pick_next_task handle
                // the cleanup when it moves the task to task_to_drop.
                sched.task_cpu.remove(&id);
                sched.unregister_identity_locked(id, task_pid, current.tid);
                let (parent, ipi_death) =
                    finalize_forced_death(sched, id, FORCED_KILL_EXIT_CODE, task_pid);
                parent_to_signal = parent;
                killed = true;
                if ci == my_cpu {
                    let mut local = LOCAL_SCHEDULERS[ci].lock();
                    if let Some(ref mut cpu) = *local {
                        switch_target = super::core_impl::yield_cpu_local(cpu, ci);
                    }
                } else {
                    ipi_to_cpu = Some(ci);
                }
                if ipi_to_cpu.is_none() {
                    ipi_to_cpu = ipi_death;
                }
            }

            // Remove from ready queues.
            if !killed {
                let mut removed_from_ready = false;
                for ci in 0..n {
                    let removed = {
                        let mut local = LOCAL_SCHEDULERS[ci].lock();
                        if let Some(ref mut cpu) = *local {
                            cpu.class_rqs.remove(id)
                        } else {
                            false
                        }
                    };
                    if removed {
                        removed_from_ready = true;
                        break;
                    }
                }
                if removed_from_ready {
                    let _ = sched.clear_task_wake_deadline_locked(id);
                    if let Some(task) = sched.remove_all_task_locked(id) {
                        let task_pid = task.pid;
                        task.set_state(TaskState::Dead);
                        cleanup_task_resources(&task);
                        sched.task_cpu.remove(&id);
                        sched.unregister_identity_locked(id, task_pid, task.tid);
                        let (parent, ipi_death) =
                            finalize_forced_death(sched, id, FORCED_KILL_EXIT_CODE, task_pid);
                        parent_to_signal = parent;
                        if ipi_to_cpu.is_none() {
                            ipi_to_cpu = ipi_death;
                        }
                    }
                    killed = true;
                }
            }

            // Remove from blocked map.
            if !killed {
                if let Some(task) = sched.blocked_tasks.remove(&id) {
                    let task_pid = task.pid;
                    let _ = sched.clear_task_wake_deadline_locked(id);
                    task.set_state(TaskState::Dead);
                    cleanup_task_resources(&task);
                    let _ = sched.remove_all_task_locked(id);
                    sched.task_cpu.remove(&id);
                    sched.unregister_identity_locked(id, task_pid, task.tid);
                    let (parent, ipi_death) =
                        finalize_forced_death(sched, id, FORCED_KILL_EXIT_CODE, task_pid);
                    parent_to_signal = parent;
                    if ipi_to_cpu.is_none() {
                        ipi_to_cpu = ipi_death;
                    }
                    killed = true;
                }
            }
        }
    } // scheduler lock released before IPI and context switch

    if let Some(ref target) = switch_target {
        unsafe {
            crate::process::task::do_switch_context(target);
        }
        finish_switch();
    }

    if let Some(ci) = ipi_to_cpu {
        send_resched_ipi_to_cpu(ci);
    }

    if let Some(parent_id) = parent_to_signal {
        // Must happen outside scheduler lock to avoid lock recursion.
        let _ =
            crate::process::signal::send_signal(parent_id, crate::process::signal::Signal::SIGCHLD);
    }

    restore_flags(saved_flags);
    killed
}

/// Performs the finalize forced death operation.
fn finalize_forced_death(
    sched: &mut GlobalSchedState,
    task_id: TaskId,
    exit_code: i32,
    task_pid: Pid,
) -> (Option<TaskId>, Option<usize>) {
    let ipi_reparent = reparent_children(sched, task_id);
    let parent = sched.parent_of.remove(&task_id);
    if let Some(parent_id) = parent {
        sched.zombies.insert(task_id, (exit_code, task_pid));
        let (_, ipi_wake) = sched.wake_task_locked(parent_id);
        (Some(parent_id), ipi_reparent.or(ipi_wake))
    } else {
        (None, ipi_reparent)
    }
}

/// Performs the reparent children operation.
fn reparent_children(sched: &mut GlobalSchedState, dying: TaskId) -> Option<usize> {
    let children = match sched.children_of.remove(&dying) {
        Some(c) => c,
        None => return None,
    };
    let init_id = sched
        .pid_to_task
        .get(&1)
        .copied()
        .or_else(|| sched.all_tasks.keys().next().copied());
    let Some(init_id) = init_id else {
        for child in &children {
            sched.parent_of.remove(child);
        }
        return None;
    };
    if init_id == dying {
        for child in &children {
            sched.parent_of.remove(child);
        }
        return None;
    }
    let mut has_zombie = false;
    let init_children = sched.children_of.entry(init_id).or_default();
    for child in children {
        if !has_zombie && sched.zombies.contains_key(&child) {
            has_zombie = true;
        }
        sched.parent_of.insert(child, init_id);
        init_children.push(child);
    }
    if has_zombie {
        let (_, ipi) = sched.wake_task_locked(init_id);
        ipi
    } else {
        None
    }
}

/// Performs the cleanup task resources operation.
///
/// Called when a task exits or is killed to release ports, capabilities,
/// and user address space mappings.
///
/// # Safety
/// Must be called with the scheduler lock held and the task no longer
/// accessible from any global map (all_tasks, current_task, etc.).
fn queue_silo_cleanup(task_id: TaskId) {
    let mut guard = PENDING_SILO_CLEANUPS.lock();
    guard.push(task_id);
}

pub fn flush_deferred_silo_cleanups() {
    let mut guard = match PENDING_SILO_CLEANUPS.try_lock() {
        Some(g) => g,
        None => return, // Lock held by preempted task or other CPU, skip safely
    };
    if guard.is_empty() {
        return;
    }
    let mut drained = Vec::new();
    drained.append(&mut *guard);
    drop(guard);
    for task_id in drained {
        crate::silo::on_task_terminated(task_id);
    }
}

pub(crate) fn cleanup_task_resources(task: &Arc<Task>) {
    crate::ipc::port::cleanup_ports_for_task(task.id);
    queue_silo_cleanup(task.id);

    // SAFETY: strong_count is racy (a concurrent get_task_by_id may temporarily
    // hold an extra Arc ref). Worst case: cleanup is deferred until the last ref
    // drops elsewhere - no resource leak, just delayed release.
    let is_last_process_ref = Arc::strong_count(&task.process) == 1;
    if !is_last_process_ref {
        return;
    }

    unsafe {
        (&mut *task.process.fd_table.get()).close_all();
        let capabilities = (&mut *task.process.capabilities.get()).take_all();
        for capability in &capabilities {
            crate::capability::release_capability(capability, Some(task.id));
        }
    }

    let as_ref = unsafe { &*task.process.address_space.get() };
    if !as_ref.is_kernel() && Arc::strong_count(as_ref) == 1 {
        as_ref.unmap_all_user_regions();
    }
}
