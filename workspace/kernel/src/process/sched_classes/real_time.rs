// SPDX-License-Identifier: MPL-2.0

use super::{CurrentRuntime, SchedClassRq};
use crate::{arch::x86_64::timer::TIMER_HZ, process::task::Task};
use alloc::sync::Arc;
use intrusive_collections::{intrusive_adapter, LinkedList, LinkedListLink};

/// RT Round-Robin quantum in ticks.
///
/// POSIX specifies a minimum of 100ms for SCHED_RR (Linux default: 100ms).
/// At TIMER_HZ=100: 10 ticks x 10 ms/tick = 100 ms.
const RT_RR_QUANTUM_TICKS: u64 = TIMER_HZ / 10;

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
    ///
    /// O(n) scan, but no allocation.  In practice each priority queue is short
    /// (a handful of RT threads), so the scan terminates quickly.
    fn remove_by_id(&mut self, task_id: crate::process::TaskId) -> bool {
        let mut cursor = self.list.front_mut();
        loop {
            match cursor.get() {
                None => return false,
                Some(task) if task.id == task_id => {
                    // remove() advances cursor to the successor; the returned
                    // Arc is dropped here, decrementing the task refcount.
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
    bitmap: u128, // 100 bits needed (0..=99)
}

impl RealTimeClassRq {
    /// Creates a new instance.
    pub fn new() -> Self {
        Self {
            queues: core::array::from_fn(|_| RtPrioQueue::new()),
            bitmap: 0,
        }
    }

    /// Sets bit.
    fn set_bit(&mut self, prio: u8) {
        self.bitmap |= 1u128 << prio;
    }

    /// Performs the clear bit operation.
    fn clear_bit(&mut self, prio: u8) {
        self.bitmap &= !(1u128 << prio);
    }
}

impl SchedClassRq for RealTimeClassRq {
    /// Performs the enqueue operation.
    fn enqueue(&mut self, task: Arc<Task>) {
        let prio = match task.sched_policy() {
            super::SchedPolicy::RealTimeRR { prio } => prio.get(),
            super::SchedPolicy::RealTimeFifo { prio } => prio.get(),
            _ => return, // Ignore tasks that shouldn't be here
        };
        self.queues[prio as usize].push_back(task);
        self.set_bit(prio);
    }

    /// Performs the len operation.
    fn len(&self) -> usize {
        self.queues.iter().map(|q| q.len).sum()
    }

    /// Performs the pick next operation.
    fn pick_next(&mut self) -> Option<Arc<Task>> {
        if self.bitmap == 0 {
            return None;
        }
        // Highest priority first (99 down to 0).
        let highest = 127 - self.bitmap.leading_zeros() as u8;
        let q = &mut self.queues[highest as usize];
        let task = q.pop_front()?;
        if q.is_empty() {
            self.clear_bit(highest);
        }
        Some(task)
    }

    /// Updates current.
    fn update_current(&mut self, rt: &CurrentRuntime, task: &Task, is_yield: bool) -> bool {
        if is_yield {
            return true;
        }
        match task.sched_policy() {
            super::SchedPolicy::RealTimeRR { .. } => {
                // Round Robin: preempt after RT_RR_QUANTUM_TICKS (POSIX >= 100 ms).
                rt.period_delta_ticks >= RT_RR_QUANTUM_TICKS
            }
            super::SchedPolicy::RealTimeFifo { .. } => {
                // FIFO: run until blocked or yielded.
                false
            }
            _ => false,
        }
    }

    /// Performs the remove operation.
    fn remove(&mut self, task_id: crate::process::TaskId) -> bool {
        let mut bits = self.bitmap;
        while bits != 0 {
            let i = bits.trailing_zeros() as usize;
            if self.queues[i].remove_by_id(task_id) {
                if self.queues[i].is_empty() {
                    self.clear_bit(i as u8);
                }
                // task_id is unique : stop scanning once found.
                return true;
            }
            bits &= !(1u128 << i);
        }
        false
    }
}
