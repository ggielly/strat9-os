// SPDX-License-Identifier: MPL-2.0

use super::{CurrentRuntime, SchedClassRq};
use crate::process::task::Task;
use alloc::{collections::BinaryHeap, sync::Arc};
use core::cmp::{self, Reverse};

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

struct FairQueueItem(Arc<Task>, u64); // Task, vruntime

impl FairQueueItem {
    fn key(&self) -> u64 {
        self.1
    }
}

impl core::fmt::Debug for FairQueueItem {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.key())
    }
}

impl PartialEq for FairQueueItem {
    fn eq(&self, other: &Self) -> bool {
        self.key().eq(&other.key())
    }
}
impl Eq for FairQueueItem {}

impl PartialOrd for FairQueueItem {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FairQueueItem {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.key().cmp(&other.key())
    }
}

pub struct FairClassRq {
    entities: BinaryHeap<Reverse<FairQueueItem>>,
    min_vruntime: u64,
    total_weight: u64,
}

impl FairClassRq {
    pub fn new() -> Self {
        Self {
            entities: BinaryHeap::new(),
            min_vruntime: 0,
            total_weight: 0,
        }
    }

    fn period(&self) -> u64 {
        // Total scheduling period (ticks) = BASE_SLICE_TICKS * nr_runnable.
        // Ensures each runnable task gets at least BASE_SLICE_TICKS per round.
        // Minimum = BASE_SLICE_TICKS to avoid division-by-zero in time_slice().
        let count = (self.entities.len() + 1) as u64;
        (BASE_SLICE_TICKS * count).max(BASE_SLICE_TICKS)
    }

    fn vtime_slice(&self) -> u64 {
        self.period() / (self.entities.len() + 1) as u64
    }

    fn time_slice(&self, cur_weight: u64) -> u64 {
        if self.total_weight + cur_weight == 0 {
            return self.period();
        }
        self.period() * cur_weight / (self.total_weight + cur_weight)
    }
}

impl SchedClassRq for FairClassRq {
    fn enqueue(&mut self, task: Arc<Task>) {
        if let super::SchedPolicy::Fair(nice) = task.sched_policy() {
            let weight = nice_to_weight(nice);
            let mut vruntime = task.vruntime();
            // Start at min_vruntime if hasn't run yet or blocked heavily
            if vruntime < self.min_vruntime {
                vruntime = self.min_vruntime;
            }
            task.set_vruntime(vruntime);
            self.total_weight += weight;
            self.entities.push(Reverse(FairQueueItem(task, vruntime)));
        }
    }

    fn len(&self) -> usize {
        self.entities.len()
    }

    fn pick_next(&mut self) -> Option<Arc<Task>> {
        let Reverse(FairQueueItem(task, _)) = self.entities.pop()?;
        if let super::SchedPolicy::Fair(nice) = task.sched_policy() {
            let weight = nice_to_weight(nice);
            self.total_weight -= weight;
        }
        Some(task)
    }

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

    fn remove(&mut self, task_id: crate::process::TaskId) -> bool {
        let mut vec = self.entities.drain().collect::<alloc::vec::Vec<_>>();
        let old_len = vec.len();
        let mut removed_weight = 0u64;
        vec.retain(|Reverse(item)| {
            if item.0.id == task_id {
                if let super::SchedPolicy::Fair(nice) = item.0.sched_policy() {
                    removed_weight += nice_to_weight(nice);
                }
                false
            } else {
                true
            }
        });
        let removed = vec.len() < old_len;
        if removed {
            self.total_weight = self.total_weight.saturating_sub(removed_weight);
        }
        self.entities = alloc::collections::BinaryHeap::from(vec);
        removed
    }
}
