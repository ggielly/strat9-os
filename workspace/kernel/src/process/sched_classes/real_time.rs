// SPDX-License-Identifier: MPL-2.0

use super::{CurrentRuntime, SchedClassRq};
use crate::{arch::timer::TIMER_HZ, process::task::Task};
use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use intrusive_collections::{intrusive_adapter, LinkedList, LinkedListLink};

/// RT Round-Robin quantum in ticks.
///
/// POSIX specifies a minimum of 100ms for SCHED_RR (Linux default: 100ms).
/// At TIMER_HZ=100: 10 ticks x 10 ms/tick = 100 ms.
const RT_RR_QUANTUM_TICKS: u64 = TIMER_HZ / 10;

/// RT budget per period in ticks.
///
/// An RT task that consumes this many ticks within a single budget period
/// is temporarily degraded to Fair class until the period expires.  This
/// prevents a single RT task from permanently starving Fair tasks.
///
/// At TIMER_HZ=100: 100 ticks = 1 second of wall-clock time.
const RT_BUDGET_TICKS: u64 = 100;

/// RT budget period in ticks.
///
/// After this many ticks the budget resets.  Must be >= RT_BUDGET_TICKS.
/// At TIMER_HZ=100: 500 ticks = 5 seconds.
const RT_BUDGET_PERIOD_TICKS: u64 = 500;

/// Real-time priority (0-99). Higher value means higher priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RealTimePriority(u8);

impl RealTimePriority {
    pub const MIN: Self = Self(0);
    pub const MAX: Self = Self(99);

    /// Creates a new instance.
    pub fn new(prio: u8) -> Self {
        Self(prio.clamp(Self::MIN.0, Self::MAX.0))
    }

    /// Performs the get operation.
    pub fn get(self) -> u8 {
        self.0
    }
}

// Intrusive adapter: the list owns Arc<Task> references and navigates via
// the `rt_link` field embedded directly in the Task control block.
// Zero heap allocation on enqueue or dequeue; no fixed capacity limit.
intrusive_adapter!(pub RtTaskAdapter = Arc<Task>: Task { rt_link: LinkedListLink });

/// Single-priority FIFO backed by an intrusive doubly-linked list.
struct RtPrioQueue {
    list: LinkedList<RtTaskAdapter>,
    len: usize,
}

impl RtPrioQueue {
    fn new() -> Self {
        Self {
            list: LinkedList::new(RtTaskAdapter::new()),
            len: 0,
        }
    }

    fn push_back(&mut self, task: Arc<Task>) {
        self.list.push_back(task);
        self.len += 1;
    }

    fn pop_front(&mut self) -> Option<Arc<Task>> {
        let task = self.list.pop_front()?;
        self.len -= 1;
        Some(task)
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Remove the first task with `task_id`. Returns true when found.
    fn remove_by_id(&mut self, task_id: crate::process::TaskId) -> bool {
        let mut cursor = self.list.front_mut();
        loop {
            match cursor.get() {
                None => return false,
                Some(task) if task.id == task_id => {
                    let _ = cursor.remove();
                    self.len -= 1;
                    return true;
                }
                Some(_) => cursor.move_next(),
            }
        }
    }
}

pub struct RealTimeClassRq {
    queues: [RtPrioQueue; 100],
    bitmap: u128,
}

impl RealTimeClassRq {
    pub fn new() -> Self {
        Self {
            queues: core::array::from_fn(|_| RtPrioQueue::new()),
            bitmap: 0,
        }
    }

    fn set_bit(&mut self, prio: u8) {
        self.bitmap |= 1u128 << prio;
    }

    fn clear_bit(&mut self, prio: u8) {
        self.bitmap &= !(1u128 << prio);
    }

    /// Check if an RT task's budget has expired and the period has not yet
    /// elapsed.  Returns `true` if the task should be skipped (degraded).
    fn is_budget_exhausted(task: &Task, now: u64) -> bool {
        if !task.rt_degraded.load(Ordering::Relaxed) {
            return false;
        }
        let period_start = task.rt_budget_period_start.load(Ordering::Relaxed);
        now.saturating_sub(period_start) < RT_BUDGET_PERIOD_TICKS
    }

    /// Reset the RT budget for a task.  Called when the period has expired
    /// or when the task is first enqueued.
    fn reset_budget(task: &Task, now: u64) {
        task.rt_budget_remaining
            .store(RT_BUDGET_TICKS, Ordering::Relaxed);
        task.rt_budget_period_start
            .store(now, Ordering::Relaxed);
        task.rt_degraded.store(false, Ordering::Relaxed);
    }

    /// Check if the front task of a priority queue is degraded.
    fn front_is_degraded(q: &RtPrioQueue, now: u64) -> bool {
        if let Some(task) = q.list.front().get() {
            Self::is_budget_exhausted(task, now)
        } else {
            false
        }
    }
}

impl SchedClassRq for RealTimeClassRq {
    fn enqueue(&mut self, task: Arc<Task>) {
        let prio = match task.sched_policy() {
            super::SchedPolicy::RealTimeRR { prio } => prio.get(),
            super::SchedPolicy::RealTimeFifo { prio } => prio.get(),
            _ => return,
        };

        // If the task was degraded and its period has expired, reset budget.
        let now = crate::process::scheduler::ticks();
        if task.rt_degraded.load(Ordering::Relaxed) {
            let period_start = task.rt_budget_period_start.load(Ordering::Relaxed);
            if now.saturating_sub(period_start) >= RT_BUDGET_PERIOD_TICKS {
                Self::reset_budget(&task, now);
            }
        } else if task.rt_budget_remaining.load(Ordering::Relaxed) == 0 {
            // First enqueue or budget was never initialized.
            Self::reset_budget(&task, now);
        }

        self.queues[prio as usize].push_back(task);
        self.set_bit(prio);
    }

    fn len(&self) -> usize {
        self.queues.iter().map(|q| q.len).sum()
    }

    fn pick_next(&mut self) -> Option<Arc<Task>> {
        if self.bitmap == 0 {
            return None;
        }

        let now = crate::process::scheduler::ticks();

        // Scan from highest to lowest priority, skipping degraded tasks.
        let mut scan_bitmap = self.bitmap;
        while scan_bitmap != 0 {
            let prio = 127 - scan_bitmap.leading_zeros() as u8;
            let q = &mut self.queues[prio as usize];

            if Self::front_is_degraded(q, now) {
                // Rotate: pop front, push back so others at same priority run.
                if let Some(task) = q.pop_front() {
                    q.push_back(task);
                }
                if q.is_empty() {
                    self.clear_bit(prio);
                }
                scan_bitmap &= !(1u128 << prio);
                continue;
            }

            let task = q.pop_front()?;
            if q.is_empty() {
                self.clear_bit(prio);
            }
            return Some(task);
        }

        // All RT tasks degraded — let Fair class handle scheduling.
        None
    }

    fn update_current(&mut self, rt: &CurrentRuntime, task: &Task, is_yield: bool) -> bool {
        if is_yield {
            return true;
        }

        // Consume budget.
        let remaining = task.rt_budget_remaining.load(Ordering::Relaxed);
        let consumed = rt.delta_ticks.min(remaining);
        let new_remaining = remaining.saturating_sub(consumed);
        task.rt_budget_remaining
            .store(new_remaining, Ordering::Relaxed);

        // If budget exhausted, mark degraded.  The task will be skipped
        // in pick_next until its period expires.
        if new_remaining == 0 && consumed > 0 {
            task.rt_degraded.store(true, Ordering::Relaxed);
            return true; // Preempt immediately.
        }

        match task.sched_policy() {
            super::SchedPolicy::RealTimeRR { .. } => {
                // Round Robin: preempt after RT_RR_QUANTUM_TICKS.
                rt.period_delta_ticks >= RT_RR_QUANTUM_TICKS
            }
            super::SchedPolicy::RealTimeFifo { .. } => {
                // FIFO: run until blocked, yielded, or budget exhausted.
                false
            }
            _ => false,
        }
    }

    fn remove(&mut self, task_id: crate::process::TaskId) -> bool {
        let mut bits = self.bitmap;
        while bits != 0 {
            let i = bits.trailing_zeros() as usize;
            if self.queues[i].remove_by_id(task_id) {
                if self.queues[i].is_empty() {
                    self.clear_bit(i as u8);
                }
                return true;
            }
            bits &= !(1u128 << i);
        }
        false
    }
}
