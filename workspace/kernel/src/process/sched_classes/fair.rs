// SPDX-License-Identifier: MPL-2.0

use super::{CurrentRuntime, SchedClassRq};
use crate::process::task::Task;
use alloc::{collections::BinaryHeap, sync::Arc};
use core::cmp::{self, Reverse};

const WEIGHT_0: u64 = 1024;
const FAIR_PREALLOC_SLOTS: usize = 64;

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

struct FairQueueItem {
    task: Arc<Task>,
    vruntime: u64,
    weight: u64,
    generation: u64,
}

impl FairQueueItem {
    /// Performs the key operation.
    fn key(&self) -> u64 {
        self.vruntime
    }

    /// Returns whether this heap node still represents the live FAIR entry.
    fn is_live(&self) -> bool {
        self.task.fair_is_on_rq() && self.task.fair_generation() == self.generation
    }
}

impl core::fmt::Debug for FairQueueItem {
    /// Performs the fmt operation.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "id={} vruntime={} gen={}",
            self.task.id.as_u64(),
            self.vruntime,
            self.generation
        )
    }
}

impl PartialEq for FairQueueItem {
    /// Performs the eq operation.
    fn eq(&self, other: &Self) -> bool {
        self.key().eq(&other.key())
            && self.task.id == other.task.id
            && self.weight == other.weight
            && self.generation == other.generation
    }
}
impl Eq for FairQueueItem {}

impl PartialOrd for FairQueueItem {
    /// Performs the partial cmp operation.
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FairQueueItem {
    /// Performs the cmp operation.
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.key()
            .cmp(&other.key())
            .then_with(|| self.task.id.as_u64().cmp(&other.task.id.as_u64()))
            .then_with(|| self.generation.cmp(&other.generation))
    }
}

pub struct FairClassRq {
    entities: BinaryHeap<Reverse<FairQueueItem>>,
    min_vruntime: u64,
    total_weight: u64,
    runnable_count: usize,
}

impl FairClassRq {
    /// Creates a new instance.
    pub fn new() -> Self {
        let mut entities = BinaryHeap::new();
        // Keep the timer/preemption fast path allocation-free: once tasks are
        // in circulation, requeueing a preempted FAIR task must not grow the
        // heap from IRQ context.
        entities.reserve(FAIR_PREALLOC_SLOTS);
        Self {
            entities,
            min_vruntime: 0,
            total_weight: 0,
            runnable_count: 0,
        }
    }

    /// Drop stale heap nodes from the top until the minimum is live.
    fn prune_stale_head(&mut self) {
        while let Some(Reverse(item)) = self.entities.peek() {
            if item.is_live() {
                break;
            }
            let _ = self.entities.pop();
        }
    }

    /// Performs the period operation.
    fn period(&self) -> u64 {
        // Total scheduling period (ticks) = BASE_SLICE_TICKS * nr_runnable.
        // Ensures each runnable task gets at least BASE_SLICE_TICKS per round.
        // Minimum = BASE_SLICE_TICKS to avoid division-by-zero in time_slice().
        let count = (self.runnable_count + 1) as u64;
        (BASE_SLICE_TICKS * count).max(BASE_SLICE_TICKS)
    }

    /// Performs the vtime slice operation.
    fn vtime_slice(&self) -> u64 {
        self.period() / (self.runnable_count + 1) as u64
    }

    /// Performs the time slice operation.
    fn time_slice(&self, cur_weight: u64) -> u64 {
        if self.total_weight + cur_weight == 0 {
            return self.period();
        }
        self.period() * cur_weight / (self.total_weight + cur_weight)
    }
}

impl SchedClassRq for FairClassRq {
    /// Performs the enqueue operation.
    fn enqueue(&mut self, task: Arc<Task>) {
        if let super::SchedPolicy::Fair(nice) = task.sched_policy() {
            let weight = nice_to_weight(nice);
            let mut vruntime = task.vruntime();
            // Start at min_vruntime if hasn't run yet or blocked heavily
            if vruntime < self.min_vruntime {
                vruntime = self.min_vruntime;
            }
            task.set_vruntime(vruntime);
            let (generation, was_queued) = task.fair_prepare_enqueue();
            if !was_queued {
                self.total_weight += weight;
                self.runnable_count += 1;
            }
            self.entities.push(Reverse(FairQueueItem {
                task,
                vruntime,
                weight,
                generation,
            }));
        }
    }

    /// Performs the len operation.
    fn len(&self) -> usize {
        self.runnable_count
    }

    /// Performs the pick next operation.
    fn pick_next(&mut self) -> Option<Arc<Task>> {
        self.prune_stale_head();

        while let Some(Reverse(item)) = self.entities.pop() {
            if !item.is_live() {
                continue;
            }

            let task = item.task;
            let was_queued = task.fair_mark_dequeued();
            if !was_queued {
                continue;
            }
            self.total_weight = self.total_weight.saturating_sub(item.weight);
            self.runnable_count = self.runnable_count.saturating_sub(1);
            return Some(task);
        }

        None
    }

    /// Updates current.
    fn update_current(&mut self, rt: &CurrentRuntime, task: &Task, is_yield: bool) -> bool {
        if is_yield {
            return true;
        }
        self.prune_stale_head();
        if let super::SchedPolicy::Fair(nice) = task.sched_policy() {
            let weight = nice_to_weight(nice);
            let delta_vruntime = if weight == 0 {
                0
            } else {
                rt.delta_ticks * WEIGHT_0 / weight
            };
            let vruntime = task.vruntime() + delta_vruntime;
            task.set_vruntime(vruntime);

            let leftmost = self.entities.peek();
            self.min_vruntime = match leftmost {
                Some(Reverse(leftmost)) => vruntime.min(leftmost.key()),
                None => vruntime,
            };

            if leftmost.is_none() {
                return false;
            }

            rt.period_delta_ticks > self.time_slice(weight)
                || vruntime > self.min_vruntime + self.vtime_slice()
        } else {
            false
        }
    }

    /// Performs the remove operation.
    fn remove(&mut self, task_id: crate::process::TaskId) -> bool {
        let found = self
            .entities
            .iter()
            .any(|Reverse(item)| item.task.id == task_id && item.is_live());
        if !found {
            return false;
        }

        let Some((task, weight)) = self.entities.iter().find_map(|Reverse(item)| {
            if item.task.id == task_id && item.is_live() {
                Some((item.task.clone(), item.weight))
            } else {
                None
            }
        }) else {
            return false;
        };

        if !task.fair_invalidate_rq_entry() {
            return false;
        }

        self.total_weight = self.total_weight.saturating_sub(weight);
        self.runnable_count = self.runnable_count.saturating_sub(1);
        true
    }
}
