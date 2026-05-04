// SPDX-License-Identifier: MPL-2.0

use super::{CurrentRuntime, SchedClassRq};
use crate::process::task::Task;
use alloc::{collections::BTreeMap, sync::Arc};

const WEIGHT_0: u64 = 1024;

/// Base time slice per task in ticks for the CFS fair scheduler.
///
/// At TIMER_HZ=100 (10 ms/tick):
///   BASE_SLICE_TICKS = 1 -> 1 tick = 10 ms per task (matches `quantum_ms: 10`)
///
/// Previously this was mistakenly 10, giving 10 ticks = 100 ms slices and
/// effectively disabling preemption for lightly loaded workloads.
///
/// Derivation: target_ms = 10 ms, tick_ms = 1000 / TIMER_HZ = 10 ms -> 1 tick.
const BASE_SLICE_TICKS: u64 = 1;

/// Performs the nice to weight operation.
pub const fn nice_to_weight(nice: super::nice::Nice) -> u64 {
    const FACTOR_NUMERATOR: u64 = 5;
    const FACTOR_DENOMINATOR: u64 = 4;

    const NICE_TO_WEIGHT: [u64; 40] = const {
        let mut ret = [0; 40];
        let mut index = 0;
        let mut nice = super::nice::NiceValue::MIN.get();
        while nice <= super::nice::NiceValue::MAX.get() {
            ret[index] = match nice {
                0 => WEIGHT_0,
                nice @ 1.. => {
                    let numerator = FACTOR_DENOMINATOR.pow(nice as u32);
                    let denominator = FACTOR_NUMERATOR.pow(nice as u32);
                    WEIGHT_0 * numerator / denominator
                }
                nice => {
                    let numerator = FACTOR_NUMERATOR.pow((-nice) as u32);
                    let denominator = FACTOR_DENOMINATOR.pow((-nice) as u32);
                    WEIGHT_0 * numerator / denominator
                }
            };
            index += 1;
            nice += 1;
        }
        ret
    };

    NICE_TO_WEIGHT[(nice.value().get() + 20) as usize]
}

/// Per-CPU run queue for the Completely Fair Scheduler.
///
/// Uses two `BTreeMap`s for O(log n) operations without allocation on the
/// fast paths (`pick_next`, `remove`):
///
/// - `entities`: primary map keyed by `(vruntime, task_id)` : the minimum
///   entry is always the next task to schedule.
/// - `by_id`: reverse index mapping `task_id → primary key` : enables O(log n)
///   removal by task ID in `remove()` without scanning `entities`.
///
/// This replaces the previous `BinaryHeap`-based design which used *lazy
/// deletion* (O(n) `remove()` scan, phantom entries, generation counters).
/// The `BTreeMap` approach gives:
///
/// | Operation   | Complexity | Allocates?                              |
/// |-------------|------------|-----------------------------------------|
/// | `enqueue`   | O(log n)   | yes : 2 BTreeMap nodes (wakeup path)    |
/// | `pick_next` | O(log n)   | no  : removes 2 nodes                   |
/// | `remove`    | O(log n)   | no  : removes 2 nodes                   |
///
/// No phantom entries means no generation counter, no `prune_stale_head()`,
/// and no per-entry liveness checks.  The BTreeMap pair is the authoritative
/// record of which tasks are currently on the run queue.
pub struct FairClassRq {
    /// Primary index: `(vruntime, task_id)` → `(Arc<Task>, weight)`.
    /// Ordered so `pop_first()` yields the task with the smallest vruntime.
    /// `task_id` is part of the key to ensure uniqueness when two tasks share
    /// the same vruntime.
    entities: BTreeMap<(u64, u64), (Arc<Task>, u64)>,
    /// Reverse index: `task_id` → primary key.
    /// Allows `remove(task_id)` to locate and delete the `entities` entry in
    /// O(log n) without scanning the primary map.
    by_id: BTreeMap<u64, (u64, u64)>,
    min_vruntime: u64,
    total_weight: u64,
    runnable_count: usize,
}

impl FairClassRq {
    /// Creates a new instance.
    pub fn new() -> Self {
        Self {
            entities: BTreeMap::new(),
            by_id: BTreeMap::new(),
            min_vruntime: 0,
            total_weight: 0,
            runnable_count: 0,
        }
    }

    /// Total scheduling period in ticks.
    ///
    /// `BASE_SLICE_TICKS * (nr_runnable + 1)` : each runnable task gets at
    /// least one full `BASE_SLICE_TICKS` per round.  `+1` accounts for the
    /// currently-running task that is not counted in `runnable_count`.
    fn period(&self) -> u64 {
        let count = (self.runnable_count + 1) as u64;
        (BASE_SLICE_TICKS * count).max(BASE_SLICE_TICKS)
    }

    /// Virtual-time slice: the vruntime budget for the current task.
    fn vtime_slice(&self) -> u64 {
        self.period() / (self.runnable_count + 1) as u64
    }

    /// Wall-clock time slice scaled by `cur_weight` relative to total weight.
    fn time_slice(&self, cur_weight: u64) -> u64 {
        let denom = self.total_weight + cur_weight;
        if denom == 0 {
            return self.period();
        }
        self.period() * cur_weight / denom
    }
}

impl SchedClassRq for FairClassRq {
    /// Enqueues a task onto the run queue.
    ///
    /// Clamps `vruntime` to `min_vruntime` so waking tasks do not receive an
    /// unfair head start over tasks that have been waiting.  O(log n);
    /// allocates two BTreeMap nodes.
    fn enqueue(&mut self, task: Arc<Task>) {
        if let super::SchedPolicy::Fair(nice) = task.sched_policy() {
            let task_id = task.id.as_u64();

            // Guard against double-enqueue: `by_id` is the authoritative
            // membership record.  This should not occur in normal operation.
            if self.by_id.contains_key(&task_id) {
                return;
            }

            let weight = nice_to_weight(nice);
            let mut vruntime = task.vruntime();
            if vruntime < self.min_vruntime {
                vruntime = self.min_vruntime;
            }
            task.set_vruntime(vruntime);
            // Keep the task-side `fair_on_rq` flag consistent with external
            // observers.  The generation return value is unused in this design.
            task.fair_prepare_enqueue();

            let key = (vruntime, task_id);
            self.entities.insert(key, (task, weight));
            self.by_id.insert(task_id, key);
            self.total_weight += weight;
            self.runnable_count += 1;
        }
    }

    /// Returns the number of tasks currently on the run queue.
    fn len(&self) -> usize {
        self.runnable_count
    }

    /// Picks the next task to run: the one with the smallest vruntime.
    ///
    /// O(log n), allocation-free.
    fn pick_next(&mut self) -> Option<Arc<Task>> {
        let ((_, task_id), (task, weight)) = self.entities.pop_first()?;
        self.by_id.remove(&task_id);
        task.fair_mark_dequeued();
        self.total_weight = self.total_weight.saturating_sub(weight);
        self.runnable_count = self.runnable_count.saturating_sub(1);
        Some(task)
    }

    /// Updates the vruntime of the currently-running task and decides whether
    /// it should be preempted.
    ///
    /// Returns `true` if the task has exhausted its time slice or its vruntime
    /// has overtaken the leftmost task's vruntime by more than `vtime_slice`.
    fn update_current(&mut self, rt: &CurrentRuntime, task: &Task, is_yield: bool) -> bool {
        if is_yield {
            return true;
        }
        if let super::SchedPolicy::Fair(nice) = task.sched_policy() {
            let weight = nice_to_weight(nice);
            let delta_vruntime = if weight == 0 {
                0
            } else {
                rt.delta_ticks * WEIGHT_0 / weight
            };
            let vruntime = task.vruntime() + delta_vruntime;
            task.set_vruntime(vruntime);

            // The leftmost entry is O(log n) to peek on a BTreeMap.
            let leftmost_vruntime = self.entities.keys().next().map(|&(v, _)| v);
            self.min_vruntime = match leftmost_vruntime {
                Some(lv) => vruntime.min(lv),
                None => vruntime,
            };

            // No other runnable task : keep running.
            if leftmost_vruntime.is_none() {
                return false;
            }

            rt.period_delta_ticks > self.time_slice(weight)
                || vruntime > self.min_vruntime + self.vtime_slice()
        } else {
            false
        }
    }

    /// Removes the task identified by `task_id` from the run queue.
    ///
    /// Uses the `by_id` reverse index for O(log n) lookup, then removes both
    /// entries.  Allocation-free.  Returns `true` if the task was present.
    fn remove(&mut self, task_id: crate::process::TaskId) -> bool {
        let Some(key) = self.by_id.remove(&task_id.as_u64()) else {
            return false;
        };
        if let Some((task, weight)) = self.entities.remove(&key) {
            task.fair_invalidate_rq_entry();
            self.total_weight = self.total_weight.saturating_sub(weight);
            self.runnable_count = self.runnable_count.saturating_sub(1);
            true
        } else {
            // `by_id` and `entities` are kept in sync on every mutation path;
            // reaching here indicates a bug in this module.
            debug_assert!(
                false,
                "FairClassRq: by_id/entities out of sync for task {:?}",
                task_id
            );
            false
        }
    }
}
