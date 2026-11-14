/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

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
//!       check condition => return if true
//!       push self to waiters (lock still held)
//!       release waiters lock
//!       block_current_task()            ← wake_pending flag handles late wakeups
//!       // woken => re-check condition
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
//!
//! ## Phase 0 notes
//!
//! Waiters are stored in an unbounded [`Vec`] rather than a fixed-capacity
//! queue, so a userspace-reachable waiter count can never trigger a panic.
//! Registration (`Vec::push`) may allocate under the waiters lock, but only
//! in task context : never in an IRQ : and `wake_one`/`wake_all` never
//! allocate. Externally woken waiters are removed by their own `retain` on
//! return and `wake_one` skips stale (already-unblocked) entries.
//!
//! Timeouts: [`WaitQueue::wait_until_deadline`] arms the task's
//! `wake_deadline_ns` (the mechanism `nanosleep` uses); the timer tick wakes
//! the task once the deadline passes. Resolution is one scheduler tick.

use crate::{
    process::{block_current_task, current_task_id, wake_task, TaskId},
    sync::SpinLock,
};
use alloc::vec::Vec;

/// Monotonic time on the clock `check_wake_deadlines` compares against.
///
/// Deadlines passed to [`WaitQueue::wait_until_deadline`] must be expressed on
/// this clock, otherwise the timer wake and the expiry check disagree.
#[inline]
pub fn scheduler_clock_ns() -> u64 {
    crate::process::scheduler::ticks().saturating_mul(crate::arch::timer::NS_PER_TICK)
}

//  WaitQueue ========================================

/// A FIFO queue of tasks waiting for an event.
///
/// See the [module documentation](self) for usage notes and the lost-wakeup
/// guarantee.
pub struct WaitQueue {
    waiters: SpinLock<Vec<TaskId>>,
}

impl WaitQueue {
    /// Create a new empty wait queue.
    pub const fn new() -> Self {
        WaitQueue {
            waiters: SpinLock::new(Vec::new()),
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
            if !waiters.contains(&id) {
                waiters.push(id);
            }
        }

        // Block : returns when wake_task(id) is called (or immediately if
        // wake_pending was already set by a racing wake_one()).
        block_current_task();

        // Remove ourselves: we may have been woken externally (signal, direct
        // wake_task, timeout) without having been popped by wake_one/wake_all,
        // which would otherwise leave a stale entry.
        self.waiters.lock().retain(|&w| w != id);
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
    pub fn wait_until<F, T>(&self, condition: F) -> T
    where
        F: FnMut() -> Option<T>,
    {
        match self.wait_until_deadline(None, condition) {
            Some(value) => value,
            // `wait_until_deadline` only returns `None` when a deadline is set.
            None => unreachable!("wait_until_deadline(None, ..) timed out"),
        }
    }

    /// Like [`wait_until`](Self::wait_until), but gives up at `deadline_ns`.
    ///
    /// `deadline_ns` is absolute, on the scheduler clock
    /// (`ticks() * NS_PER_TICK`, the clock `check_wake_deadlines` compares
    /// against). `None` waits forever.
    ///
    /// Returns `Some(value)` as soon as `condition()` yields a value, or
    /// `None` once the deadline has passed. The condition is always evaluated
    /// one last time after the deadline, under the waiters lock, so an event
    /// that raced with the timeout is never lost: a caller that gets `None`
    /// knows the condition was still false at expiry.
    ///
    /// The timeout reuses the scheduler's `wake_deadline_ns` mechanism (the
    /// one `nanosleep` relies on): the timer tick wakes blocked tasks whose
    /// deadline has passed, so resolution is one scheduler tick.
    ///
    /// # Panics
    ///
    /// Panics if called outside of a task context (no current task).
    pub fn wait_until_deadline<F, T>(&self, deadline_ns: Option<u64>, mut condition: F) -> Option<T>
    where
        F: FnMut() -> Option<T>,
    {
        let id = current_task_id().expect("WaitQueue::wait_until called with no current task");
        // Only needed to arm the deadline; looked up once.
        let task = match deadline_ns {
            Some(_) => crate::process::current_task_clone(),
            None => None,
        };

        let outcome = loop {
            // Hold the waiters lock while evaluating the condition so that a
            // concurrent wake_one() either:
            //   (a) finds us in the waiter list and calls wake_task() : which
            //       sets wake_pending if we haven't blocked yet, or unblocks us
            //       if we already have, or
            //   (b) runs before we push ourselves : in which case it won't pop
            //       us, but the condition will be true on the next evaluation.
            {
                let mut waiters = self.waiters.lock();

                if let Some(value) = condition() {
                    // Drop any registration left from a previous iteration.
                    waiters.retain(|&w| w != id);
                    break Some(value);
                }

                // Deadline passed and the condition is still false (checked
                // just above, under the lock): time out.
                if let Some(deadline) = deadline_ns {
                    if scheduler_clock_ns() >= deadline {
                        waiters.retain(|&w| w != id);
                        break None;
                    }
                }

                // Condition not yet met: register ourselves as a waiter while
                // the lock is still held, preventing a wakeup from being missed.
                // Dedupe to survive spurious wakeups.
                if !waiters.contains(&id) {
                    waiters.push(id);
                }
            } // waiters lock released here

            // Arm the timer wake before every sleep: any wake (wake_task,
            // timer expiry) clears `wake_deadline_ns`. If the timer scan runs
            // before we are in BLOCKED_TASKS it misses us, but the next tick
            // finds the already-expired deadline and wakes us then.
            if let (Some(deadline), Some(task)) = (deadline_ns, task.as_ref()) {
                task.wake_deadline_ns
                    .store(deadline, core::sync::atomic::Ordering::Relaxed);
            }

            // Sleep until woken.  If wake_task() already fired (racing with
            // the lock drop above), the scheduler's wake_pending flag ensures
            // block_current_task() returns immediately.
            block_current_task();

            // Remove ourselves in case we were woken externally rather than
            // popped by wake_one/wake_all, then re-evaluate the condition.
            self.waiters.lock().retain(|&w| w != id);
        };

        // Never leave a stale deadline armed for an unrelated later block.
        if let Some(task) = task.as_ref() {
            task.wake_deadline_ns
                .store(0, core::sync::atomic::Ordering::Relaxed);
        }
        outcome
    }

    /// Wake the first waiting task (FIFO order).
    ///
    /// Returns `true` if a task was successfully woken, `false` if the queue
    /// was empty or contained only stale entries. Stale entries (tasks that
    /// were already unblocked externally) are skipped rather than consuming a
    /// wakeup.
    pub fn wake_one(&self) -> bool {
        loop {
            let id = {
                let mut waiters = self.waiters.lock();
                if waiters.is_empty() {
                    return false;
                }
                waiters.remove(0)
            };

            if wake_task(id) {
                return true;
            }
            // Stale / no longer blocked: try the next entry.
        }
    }

    /// Wake all waiting tasks.
    ///
    /// Returns the number of tasks that were actually woken.
    pub fn wake_all(&self) -> usize {
        let mut count = 0;
        loop {
            let id = {
                let mut waiters = self.waiters.lock();
                if waiters.is_empty() {
                    break;
                }
                waiters.remove(0)
            };

            if wake_task(id) {
                count += 1;
            }
        }
        count
    }

    /// Remove `id` from the waiter list if present.
    ///
    /// Used for external cancellation (signal, timeout, direct wake) so a
    /// task that never re-enters `wait`/`wait_until` does not leave a stale
    /// entry behind.
    pub fn remove(&self, id: TaskId) {
        self.waiters.lock().retain(|&w| w != id);
    }

    /// Returns the number of tasks currently registered in this queue.
    pub fn waiter_count(&self) -> usize {
        self.waiters.lock().len()
    }
}

//  WaitCondition ====================

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
        self.queue
            .wait_until(|| if (self.condition)() { Some(()) } else { None })
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
