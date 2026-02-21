//! Scheduling Policies and Classes
//!
//! Adapted from Asterinas.

pub mod fair;
pub mod nice;
pub mod real_time;
pub mod idle;

use alloc::sync::Arc;
use crate::process::task::Task;

/// The scheduling policy of a task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedPolicy {
    /// Completely Fair Scheduler
    Fair(nice::Nice),
    /// Real-Time Round-Robin
    RealTimeRR { prio: real_time::RealTimePriority },
    /// Real-Time FIFO
    RealTimeFifo { prio: real_time::RealTimePriority },
    /// Idle task (lowest priority)
    Idle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedPolicyKind {
    Fair,
    RealTime,
    Idle,
}

impl SchedPolicy {
    pub fn kind(&self) -> SchedPolicyKind {
        match self {
            Self::Fair(_) => SchedPolicyKind::Fair,
            Self::RealTimeRR { .. } | Self::RealTimeFifo { .. } => SchedPolicyKind::RealTime,
            Self::Idle => SchedPolicyKind::Idle,
        }
    }
}

pub struct CurrentRuntime {
    pub start_ticks: u64,
    pub delta_ticks: u64,
    pub period_delta_ticks: u64,
}

impl CurrentRuntime {
    pub fn new() -> Self {
        Self {
            start_ticks: crate::process::scheduler::ticks(),
            delta_ticks: 0,
            period_delta_ticks: 0,
        }
    }

    pub fn update(&mut self) {
        let now = crate::process::scheduler::ticks();
        self.delta_ticks = now.saturating_sub(core::mem::replace(&mut self.start_ticks, now));
        self.period_delta_ticks += self.delta_ticks;
    }
}

pub trait SchedClassRq {
    fn enqueue(&mut self, task: Arc<Task>);
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool { self.len() == 0 }
    fn pick_next(&mut self) -> Option<Arc<Task>>;
    fn update_current(&mut self, rt: &CurrentRuntime, task: &Task, is_yield: bool) -> bool;
    fn remove(&mut self, task_id: crate::process::TaskId) -> bool;
}

