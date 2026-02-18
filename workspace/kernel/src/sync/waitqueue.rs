//! Wait queue and condition variable for blocking/waking tasks.
//!
//! ## Overview
//!
//! A [`WaitQueue`] holds a FIFO list of [`TaskId`]s waiting for an event.
//! When a task calls [`WaitQueue::wait`], it is blocked (removed from the
//! scheduler's ready queue) until another task calls [`WaitQueue::wake_one`]
//! or [`WaitQueue::wake_all`].
//!
//! [`WaitQueue::wait_until`] is the preferred primitive: it atomically checks
//! a caller-supplied condition before blocking, preventing the classical
//! lost-wakeup race:
//!
//! ```text
//! Incorrect (racy) pattern:
//!   if !condition() { queue.wait(); }   ← wakeup between check and wait is lost
//!
//! Correct pattern (what wait_until does internally):
//!   loop {
//!       hold waiters lock
//!       check condition → return if true
//!       push self to waiters (lock still held)
//!       release waiters lock
//!       block_current_task()            ← wake_pending flag handles late wakeups
//!       // woken → re-check condition
//!   }
//! ```
//!
//! ## Lost-wakeup guarantee
//!
//! Even the simple [`WaitQueue::wait`] is safe: the scheduler's `wake_pending`
//! flag (set by `wake_task()` when the target is not yet in `blocked_tasks`)
//! ensures that a `wake_one()` that races with the transition to Blocked state
//! is never silently dropped.
//!
//! ## [`WaitCondition`]
//!
//! A higher-level wrapper that stores the condition closure alongside the
//! queue, inspired by Theseus's `wait_condition` crate. Useful when the
//! same condition is shared across multiple call sites.

use crate::{
    process::{block_current_task, current_task_id, wake_task, TaskId},
    sync::SpinLock,
};
use alloc::collections::VecDeque;

// ── WaitQueue ────────────────────────────────────────────────────────────────

/// A FIFO queue of tasks waiting for an event.
///
/// See the [module documentation](self) for usage notes and the lost-wakeup
/// guarantee.
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

    /// Block the calling task until explicitly woken.
    ///
    /// Prefer [`wait_until`](Self::wait_until) when you have a condition to
    /// test, to avoid spurious-wakeup loops and to benefit from the
    /// compile-time condition guarantee.
    ///
    /// # Panics
    ///
    /// Panics if called outside of a task context (no current task).
    pub fn wait(&self) {
        let id = current_task_id().expect("WaitQueue::wait called with no current task");

        // Add ourselves to the waiter list *before* blocking.
        // A concurrent wake_one() that pops our id will call wake_task(id);
        // the wake_pending flag in the scheduler handles the case where
        // block_current_task() has not been reached yet.
        {
            let mut waiters = self.waiters.lock();
            waiters.push_back(id);
        }

        // Block — returns when wake_task(id) is called (or immediately if
        // wake_pending was already set by a racing wake_one()).
        block_current_task();
    }

    /// Block the calling task until `condition()` returns `Some(T)`.
    ///
    /// The condition is checked under the waiters lock, then the task is
    /// inserted into the queue (still under the lock) before blocking.
    /// This makes the check-then-block sequence atomic with respect to
    /// concurrent `wake_one()` / `wake_all()` calls.
    ///
    /// The task is re-woken for every notification and re-evaluates the
    /// condition; spurious wakeups are impossible because the condition is
    /// always re-checked before the next sleep.
    ///
    /// # Panics
    ///
    /// Panics if called outside of a task context (no current task).
    pub fn wait_until<F, T>(&self, mut condition: F) -> T
    where
        F: FnMut() -> Option<T>,
    {
        let id = current_task_id().expect("WaitQueue::wait_until called with no current task");

        loop {
            // Hold the waiters lock while evaluating the condition so that a
            // concurrent wake_one() either:
            //   (a) finds us in the waiter list and calls wake_task() — which
            //       sets wake_pending if we haven't blocked yet, or unblocks us
            //       if we already have, or
            //   (b) runs before we push ourselves — in which case it won't pop
            //       us, but the condition will be true on the next evaluation.
            {
                let mut waiters = self.waiters.lock();

                if let Some(value) = condition() {
                    return value;
                }

                // Condition not yet met: register ourselves as a waiter while
                // the lock is still held, preventing a wakeup from being missed.
                waiters.push_back(id);
            } // waiters lock released here

            // Sleep until woken.  If wake_task() already fired (racing with
            // the lock drop above), the scheduler's wake_pending flag ensures
            // block_current_task() returns immediately.
            block_current_task();

            // Woken — re-evaluate the condition at the top of the loop.
        }
    }

    /// Wake the first waiting task (FIFO order).
    ///
    /// Returns `true` if a task was successfully woken, `false` if the queue
    /// was empty.
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
    /// Returns the number of tasks that were woken.
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

    /// Returns the number of tasks currently registered in this queue.
    pub fn waiter_count(&self) -> usize {
        self.waiters.lock().len()
    }
}

// ── WaitCondition ────────────────────────────────────────────────────────────

/// A named condition variable backed by a [`WaitQueue`].
///
/// Stores a reusable condition closure alongside the queue. Multiple tasks
/// can wait on the same `WaitCondition`; they are all woken when
/// [`notify_all`](Self::notify_all) is called, and each re-checks the stored
/// condition before returning.
///
/// Inspired by Theseus OS `wait_condition` crate. Wrap in an `Arc` to share
/// across tasks.
///
/// # Example
///
/// ```rust,ignore
/// static FLAG: AtomicBool = AtomicBool::new(false);
/// static COND: WaitCondition<_> = WaitCondition::new(|| FLAG.load(Ordering::Acquire));
///
/// // Waiter task:
/// COND.wait();
///
/// // Notifier task:
/// FLAG.store(true, Ordering::Release);
/// COND.notify_all();
/// ```
pub struct WaitCondition<F>
where
    F: Fn() -> bool,
{
    condition: F,
    queue: WaitQueue,
}

impl<F: Fn() -> bool> WaitCondition<F> {
    /// Create a new `WaitCondition` with the given condition function.
    pub fn new(condition: F) -> Self {
        WaitCondition {
            condition,
            queue: WaitQueue::new(),
        }
    }

    /// Block the current task until the stored condition returns `true`.
    ///
    /// Returns immediately (without blocking) if the condition is already true.
    /// Spurious wakeups are impossible.
    ///
    /// # Panics
    ///
    /// Panics if called outside of a task context.
    pub fn wait(&self) {
        self.queue.wait_until(|| {
            if (self.condition)() {
                Some(())
            } else {
                None
            }
        })
    }

    /// Wake one task waiting on this condition.
    ///
    /// The woken task will re-check the condition before returning from
    /// [`wait`](Self::wait). Returns `true` if a task was woken.
    pub fn notify_one(&self) -> bool {
        self.queue.wake_one()
    }

    /// Wake all tasks waiting on this condition.
    ///
    /// Each woken task will re-check the condition independently. Returns the
    /// number of tasks that were moved back to the ready queue.
    pub fn notify_all(&self) -> usize {
        self.queue.wake_all()
    }
}
