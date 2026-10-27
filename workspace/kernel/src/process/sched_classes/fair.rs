// SPDX-License-Identifier: MPL-2.0

use super::{CurrentRuntime, SchedClassRq};
use crate::process::task::Task;
use alloc::{collections::BTreeMap, sync::Arc};
use core::sync::atomic::Ordering;

const WEIGHT_0: u64 = 1024;

/// Base time slice per task in ticks for the CFS fair scheduler.
///
/// At TIMER_HZ=100 (10 ms/tick):
///   BASE_SLICE_TICKS = 1 -> 1 tick = 10 ms per task (matches `quantum_ms: 10`)
const BASE_SLICE_TICKS: u64 = 1;

/// Fair starvation threshold in ticks.
///
/// A Fair task that has waited this many ticks without being selected is
/// boosted to the front of its vruntime position.  At TIMER_HZ=100:
/// 100 ticks = 1 second.  This prevents indefinite starvation when RT
/// tasks consume most of the CPU.
const FAIR_STARVATION_THRESHOLD_TICKS: u64 = 100;

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
/// - `by_id`: reverse index mapping `task_id => primary key` : enables O(log n)
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
    /// Primary index: `(vruntime, task_id)` => `(Arc<Task>, weight)`.
    /// Ordered so `pop_first()` yields the task with the smallest vruntime.
    /// `task_id` is part of the key to ensure uniqueness when two tasks share
    /// the same vruntime.
    entities: BTreeMap<(u64, u64), (Arc<Task>, u64)>,
    /// Reverse index: `task_id` => primary key.
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

            if self.by_id.contains_key(&task_id) {
                return;
            }

            let weight = nice_to_weight(nice);
            let mut vruntime = task.vruntime();
            if vruntime < self.min_vruntime {
                vruntime = self.min_vruntime;
            }
            task.set_vruntime(vruntime);
            task.fair_prepare_enqueue();
            // Reset starvation counter: task just arrived, hasn't waited yet.
            task.fair_wait_ticks.store(0, Ordering::Relaxed);

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

    /// Picks the next task to run: the one with the smallest vruntime,
    /// unless a starved task exists (waited > threshold), in which case
    /// the starved task is boosted ahead.
    ///
    /// O(n) starvation scan + O(log n) normal pick.  The scan is bounded
    /// by the number of Fair tasks (typically small).
    fn pick_next(&mut self) -> Option<Arc<Task>> {
        // Check for starved tasks: any task with fair_wait_ticks >= threshold
        // is boosted ahead of normal vruntime ordering.
        let mut starved_key: Option<(u64, u64)> = None;
        let mut starved_wait: u64 = 0;
        for (&key, (task, _)) in self.entities.iter() {
            let wait = task.fair_wait_ticks.load(Ordering::Relaxed);
            if wait >= FAIR_STARVATION_THRESHOLD_TICKS && wait > starved_wait {
                starved_key = Some(key);
                starved_wait = wait;
            }
        }

        let key = if let Some(sk) = starved_key {
            sk
        } else {
            // Normal path: pick minimum vruntime.
            let (&k, _) = self.entities.iter().next()?;
            k
        };

        let (task, weight) = self.entities.remove(&key)?;
        self.by_id.remove(&key.1);
        task.fair_mark_dequeued();
        task.fair_wait_ticks.store(0, Ordering::Relaxed);
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
            debug_assert!(
                false,
                "FairClassRq: by_id/entities out of sync for task {:?}",
                task_id
            );
            false
        }
    }

    /// Increment `fair_wait_ticks` for every queued task.  Called once per
    /// timer tick from the LOCAL lock handler.
    fn tick_update_wait(&mut self) {
        for ((_, task_id), (task, _)) in self.entities.iter() {
            let _ = task_id; // suppress unused warning
            task.fair_wait_ticks.fetch_add(1, Ordering::Relaxed);
        }
    }
}
