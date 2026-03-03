// SPDX-License-Identifier: MPL-2.0

use super::{CurrentRuntime, SchedClassRq};
use crate::process::task::Task;
use alloc::sync::Arc;

pub struct IdleClassRq {
    idle_task: Option<Arc<Task>>,
}

impl IdleClassRq {
    /// Creates a new instance.
    pub fn new() -> Self {
        Self { idle_task: None }
    }
}

impl SchedClassRq for IdleClassRq {
    /// Performs the enqueue operation.
    fn enqueue(&mut self, task: Arc<Task>) {
        if let super::SchedPolicy::Idle = task.sched_policy() {
            self.idle_task = Some(task);
        }
    }

    /// Performs the len operation.
    fn len(&self) -> usize {
        if self.idle_task.is_some() { 1 } else { 0 }
    }

    /// Performs the pick next operation.
    fn pick_next(&mut self) -> Option<Arc<Task>> {
        self.idle_task.clone()
    }

    /// Updates current.
    fn update_current(&mut self, _rt: &CurrentRuntime, _task: &Task, is_yield: bool) -> bool {
        is_yield
    }

    /// Performs the remove operation.
    fn remove(&mut self, task_id: crate::process::TaskId) -> bool {
        if let Some(task) = &self.idle_task {
            if task.id == task_id {
                self.idle_task = None;
                return true;
            }
        }
        false
    }
}
