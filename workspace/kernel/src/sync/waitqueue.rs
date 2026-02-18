//! Wait queue for blocking/waking tasks.
//!
//! A `WaitQueue` holds a FIFO list of task IDs that are waiting for an event.
//! When a task calls `wait()`, it is blocked (removed from the scheduler's
//! ready queue) and its ID is appended to the wait queue. When another task
//! calls `wake_one()` or `wake_all()`, the blocked tasks are moved back to
//! the ready queue.

use crate::{
    process::{block_current_task, current_task_id, wake_task, TaskId},
    sync::SpinLock,
};
use alloc::collections::VecDeque;

/// A queue of tasks waiting for an event.
pub struct WaitQueue {
    waiters: SpinLock<VecDeque<TaskId>>,
}

impl WaitQueue {
    /// Create a new empty wait queue.
    pub const fn new() -> Self {
        WaitQueue {
            waiters: SpinLock::new(VecDeque::new()),
        }
    }

    /// Block the calling task until woken.
    ///
    /// Adds the current task's ID to the waiter list, then calls
    /// `block_current_task()` which sets the task to Blocked state and
    /// yields to the scheduler.
    ///
    /// # Panics
    ///
    /// Panics if called outside of a task context (no current task).
    pub fn wait(&self) {
        let id = current_task_id().expect("WaitQueue::wait called with no current task");

        // Add ourselves to the waiter list *before* blocking, so that a
        // concurrent `wake_one()` can find us.
        {
            let mut waiters = self.waiters.lock();
            waiters.push_back(id);
        }

        // Block — the scheduler will not reschedule us until wake_task(id).
        block_current_task();
    }

    /// Wake one waiting task (FIFO order).
    ///
    /// Returns `true` if a task was woken, `false` if the queue was empty.
    pub fn wake_one(&self) -> bool {
        let id = {
            let mut waiters = self.waiters.lock();
            waiters.pop_front()
        };

        if let Some(id) = id {
            wake_task(id)
        } else {
            false
        }
    }

    /// Wake all waiting tasks.
    ///
    /// Returns the number of tasks woken.
    pub fn wake_all(&self) -> usize {
        let ids: VecDeque<TaskId> = {
            let mut waiters = self.waiters.lock();
            core::mem::take(&mut *waiters)
        };

        let mut count = 0;
        for id in ids {
            if wake_task(id) {
                count += 1;
            }
        }
        count
    }

    /// Returns the number of tasks currently waiting.
    pub fn waiter_count(&self) -> usize {
        self.waiters.lock().len()
    }
}
