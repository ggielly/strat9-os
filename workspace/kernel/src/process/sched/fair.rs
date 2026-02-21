// SPDX-License-Identifier: MPL-2.0

use alloc::{collections::BinaryHeap, sync::Arc};
use core::cmp::{self, Reverse};
use crate::process::task::Task;
use super::{CurrentRuntime, SchedClassRq};

const WEIGHT_0: u64 = 1024;

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
    fn key(&self) -> u64 { self.1 }
}

impl core::fmt::Debug for FairQueueItem {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.key())
    }
}

impl PartialEq for FairQueueItem {
    fn eq(&self, other: &Self) -> bool { self.key().eq(&other.key()) }
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
        // 10ms base slice, minimum 1ms
        let base_slice: u64 = 10;
        let min_period: u64 = 1;
        let count = (self.entities.len() + 1) as u64;
        let period_single: u64 = (base_slice * count).max(min_period);
        // Simplified: ignore CPU count for single core mostly
        period_single
    }

    fn vtime_slice(&self) -> u64 {
        self.period() / (self.entities.len() + 1) as u64
    }

    fn time_slice(&self, cur_weight: u64) -> u64 {
        if self.total_weight + cur_weight == 0 { return self.period(); }
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
        if is_yield { return true; }
        if let super::SchedPolicy::Fair(nice) = task.sched_policy() {
            let weight = nice_to_weight(nice);
            let delta_vruntime = if weight == 0 { 0 } else { rt.delta_ticks * WEIGHT_0 / weight };
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
        vec.retain(|Reverse(item)| item.0.id != task_id);
        let removed = vec.len() < old_len;
        if removed {
            self.total_weight = 0;
            for Reverse(item) in &vec {
                if let super::SchedPolicy::Fair(nice) = item.0.sched_policy() {
                    self.total_weight += nice_to_weight(nice);
                }
            }
        }
        self.entities = alloc::collections::BinaryHeap::from(vec);
        removed
    }
}
