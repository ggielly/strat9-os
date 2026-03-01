// SPDX-License-Identifier: MPL-2.0

use super::{CurrentRuntime, SchedClassRq};
use crate::{arch::x86_64::timer::TIMER_HZ, process::task::Task};
use alloc::{collections::VecDeque, sync::Arc};

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

    pub fn new(prio: u8) -> Self {
        Self(prio.clamp(Self::MIN.0, Self::MAX.0))
    }

    pub fn get(self) -> u8 {
        self.0
    }
}

pub struct RealTimeClassRq {
    queues: [VecDeque<Arc<Task>>; 100],
    bitmap: u128, // 100 bits needed (0..=99)
}

impl RealTimeClassRq {
    pub fn new() -> Self {
        const EMPTY: VecDeque<Arc<Task>> = VecDeque::new();
        Self {
            queues: [EMPTY; 100],
            bitmap: 0,
        }
    }

    fn set_bit(&mut self, prio: u8) {
        self.bitmap |= 1u128 << prio;
    }

    fn clear_bit(&mut self, prio: u8) {
        self.bitmap &= !(1u128 << prio);
    }
}

impl SchedClassRq for RealTimeClassRq {
    fn enqueue(&mut self, task: Arc<Task>) {
        let prio = match task.sched_policy() {
            super::SchedPolicy::RealTimeRR { prio } => prio.get(),
            super::SchedPolicy::RealTimeFifo { prio } => prio.get(),
            _ => return, // Ignore tasks that shouldn't be here
        };
        self.queues[prio as usize].push_back(task);
        self.set_bit(prio);
    }

    fn len(&self) -> usize {
        self.queues.iter().map(|q| q.len()).sum()
    }

    fn pick_next(&mut self) -> Option<Arc<Task>> {
        if self.bitmap == 0 {
            return None;
        }
        // Highest priority first (99 down to 0)
        let highest = 127 - self.bitmap.leading_zeros() as u8;
        let q = &mut self.queues[highest as usize];
        let task = q.pop_front()?;
        if q.is_empty() {
            self.clear_bit(highest);
        }
        Some(task)
    }

    fn update_current(&mut self, rt: &CurrentRuntime, task: &Task, is_yield: bool) -> bool {
        if is_yield {
            return true;
        }
        let policy = task.sched_policy();
        match policy {
            super::SchedPolicy::RealTimeRR { .. } => {
                // Round Robin: preempt after RT_RR_QUANTUM_TICKS (POSIX >= 100 ms).
                rt.period_delta_ticks >= RT_RR_QUANTUM_TICKS
            }
            super::SchedPolicy::RealTimeFifo { .. } => {
                // FIFO: Run until blocked or yielded
                false
            }
            _ => false,
        }
    }

    fn remove(&mut self, task_id: crate::process::TaskId) -> bool {
        let mut removed = false;
        let mut bits = self.bitmap;
        while bits != 0 {
            let i = bits.trailing_zeros() as usize;
            let q = &mut self.queues[i];
            let old_len = q.len();
            q.retain(|t| t.id != task_id);
            if q.len() < old_len {
                removed = true;
                if q.is_empty() {
                    self.clear_bit(i as u8);
                }
            }
            bits &= !(1u128 << i);
        }
        removed
    }
}
