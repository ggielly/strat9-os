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

    pub fn parse(s: &str) -> Option<Self> {
        if s.eq_ignore_ascii_case("rt")
            || s.eq_ignore_ascii_case("real-time")
            || s.eq_ignore_ascii_case("realtime")
        {
            Some(Self::RealTime)
        } else if s.eq_ignore_ascii_case("fair") {
            Some(Self::Fair)
        } else if s.eq_ignore_ascii_case("idle") {
            Some(Self::Idle)
        } else {
            None
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
    policy_map: [SchedClassId; 3], // index by SchedPolicyKind
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
            policy_map: [
                SchedClassId::Fair,
                SchedClassId::RealTime,
                SchedClassId::Idle,
            ],
        }
    }
}

impl SchedClassTable {
    pub fn new(pick_order: [SchedClassId; 3], steal_order: [SchedClassId; 2]) -> Self {
        let mut out = Self::default();
        let _ = out.set_pick_order(pick_order);
        let _ = out.set_steal_order(steal_order);
        out
    }

    fn kind_index(kind: SchedPolicyKind) -> usize {
        match kind {
            SchedPolicyKind::Fair => 0,
            SchedPolicyKind::RealTime => 1,
            SchedPolicyKind::Idle => 2,
        }
    }

    fn class_index(class: SchedClassId) -> usize {
        match class {
            SchedClassId::RealTime => 0,
            SchedClassId::Fair => 1,
            SchedClassId::Idle => 2,
        }
    }

    fn refresh_ranks(&mut self) {
        for entry in self.entries.iter_mut() {
            entry.rank = match entry.id {
                SchedClassId::RealTime => 255,
                SchedClassId::Fair => 255,
                SchedClassId::Idle => 255,
            };
        }
        for (idx, class) in self.pick_order.iter().copied().enumerate() {
            for entry in self.entries.iter_mut() {
                if entry.id == class {
                    entry.rank = idx as u8;
                    break;
                }
            }
        }
    }

    pub fn validate(&self) -> bool {
        let mut seen = [false; 3];
        for class in self.pick_order.iter().copied() {
            seen[Self::class_index(class)] = true;
        }
        for class in SchedClassId::ALL.iter().copied() {
            if !seen[Self::class_index(class)] {
                return false;
            }
        }

        if self.steal_order[0] == self.steal_order[1] {
            return false;
        }
        if self.steal_order.iter().any(|c| *c == SchedClassId::Idle) {
            return false;
        }

        if self.policy_map[Self::kind_index(SchedPolicyKind::Idle)] != SchedClassId::Idle {
            return false;
        }
        if self.policy_map[Self::kind_index(SchedPolicyKind::Fair)] == SchedClassId::Idle {
            return false;
        }
        if self.policy_map[Self::kind_index(SchedPolicyKind::RealTime)] == SchedClassId::Idle {
            return false;
        }
        true
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

    pub fn policy_class(&self, kind: SchedPolicyKind) -> SchedClassId {
        self.policy_map[Self::kind_index(kind)]
    }

    pub fn policy_map(&self) -> &[SchedClassId; 3] {
        &self.policy_map
    }

    pub fn set_pick_order(&mut self, pick_order: [SchedClassId; 3]) -> bool {
        let prev = self.pick_order;
        self.pick_order = pick_order;
        if !self.validate() {
            self.pick_order = prev;
            return false;
        }
        self.refresh_ranks();
        true
    }

    pub fn set_steal_order(&mut self, steal_order: [SchedClassId; 2]) -> bool {
        let prev = self.steal_order;
        self.steal_order = steal_order;
        if !self.validate() {
            self.steal_order = prev;
            return false;
        }
        true
    }

    pub fn set_policy_class(&mut self, kind: SchedPolicyKind, class: SchedClassId) -> bool {
        let idx = Self::kind_index(kind);
        let prev = self.policy_map[idx];
        self.policy_map[idx] = class;
        if !self.validate() {
            self.policy_map[idx] = prev;
            return false;
        }
        true
    }

    pub fn class_for_policy(&self, policy: SchedPolicy) -> SchedClassId {
        self.policy_class(policy.kind())
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

impl SchedPolicyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fair => "fair",
            Self::RealTime => "rt",
            Self::Idle => "idle",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        if s.eq_ignore_ascii_case("fair") {
            Some(Self::Fair)
        } else if s.eq_ignore_ascii_case("rt")
            || s.eq_ignore_ascii_case("realtime")
            || s.eq_ignore_ascii_case("real-time")
        {
            Some(Self::RealTime)
        } else if s.eq_ignore_ascii_case("idle") {
            Some(Self::Idle)
        } else {
            None
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
