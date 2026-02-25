//! Scheduling Policies and Classes
//!
//! Adapted from Asterinas.

pub mod fair;
pub mod idle;
pub mod nice;
pub mod real_time;

use crate::process::task::Task;
use alloc::sync::Arc;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedClassId {
    RealTime,
    Fair,
    Idle,
}

impl SchedClassId {
    pub const ALL: [Self; 3] = [Self::RealTime, Self::Fair, Self::Idle];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RealTime => "rt",
            Self::Fair => "fair",
            Self::Idle => "idle",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SchedClassEntry {
    pub id: SchedClassId,
    pub name: &'static str,
    pub rank: u8,
}

#[derive(Debug, Clone, Copy)]
pub struct SchedClassTable {
    entries: [SchedClassEntry; 3],
    pick_order: [SchedClassId; 3],
    steal_order: [SchedClassId; 2],
}

impl Default for SchedClassTable {
    fn default() -> Self {
        Self {
            entries: [
                SchedClassEntry {
                    id: SchedClassId::RealTime,
                    name: "real-time",
                    rank: 0,
                },
                SchedClassEntry {
                    id: SchedClassId::Fair,
                    name: "fair",
                    rank: 1,
                },
                SchedClassEntry {
                    id: SchedClassId::Idle,
                    name: "idle",
                    rank: 2,
                },
            ],
            pick_order: [
                SchedClassId::RealTime,
                SchedClassId::Fair,
                SchedClassId::Idle,
            ],
            steal_order: [SchedClassId::Fair, SchedClassId::RealTime],
        }
    }
}

impl SchedClassTable {
    pub fn new(pick_order: [SchedClassId; 3], steal_order: [SchedClassId; 2]) -> Self {
        let mut out = Self::default();
        out.pick_order = pick_order;
        out.steal_order = steal_order;
        out
    }

    pub fn entries(&self) -> &[SchedClassEntry; 3] {
        &self.entries
    }

    pub fn pick_order(&self) -> &[SchedClassId; 3] {
        &self.pick_order
    }

    pub fn steal_order(&self) -> &[SchedClassId; 2] {
        &self.steal_order
    }

    pub fn class_for_policy(&self, policy: SchedPolicy) -> SchedClassId {
        match policy.kind() {
            SchedPolicyKind::Fair => SchedClassId::Fair,
            SchedPolicyKind::RealTime => SchedClassId::RealTime,
            SchedPolicyKind::Idle => SchedClassId::Idle,
        }
    }

    pub fn class_for_task(&self, task: &Task) -> SchedClassId {
        self.class_for_policy(task.sched_policy())
    }
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
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn pick_next(&mut self) -> Option<Arc<Task>>;
    fn update_current(&mut self, rt: &CurrentRuntime, task: &Task, is_yield: bool) -> bool;
    fn remove(&mut self, task_id: crate::process::TaskId) -> bool;
}
