/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

//! Scheduling syscalls (`SYS_SCHED_*`, block 345-349).
//!
//! Before this module, a userspace task could not change its policy, its
//! priority or its CPU affinity: all three were fixed at creation from the
//! silo configuration. The kernel already implements every scheduling class
//! (`SchedPolicy`), so this is an exposure layer, not a scheduler rewrite.
//!
//! Scope is deliberately limited to the calling task. Becoming real-time is
//! gated on silo-admin capability until a dedicated scheduling capability
//! resource exists (tracked as security work R11); dropping to Fair/Idle is
//! always allowed so a task can never trap itself in an unschedulable state.

use super::error::SyscallError;
use crate::{
    memory::UserSliceWrite,
    process::{
        current_task_clone,
        sched::{nice::Nice, real_time::RealTimePriority, SchedPolicy},
        set_task_sched_policy, Task, TaskPriority,
    },
};

use strat9_abi::{
    data::{SchedInfo, SCHED_INFO_FLAG_RT_DEGRADED},
    syscall::{SCHED_POLICY_FAIR, SCHED_POLICY_FIFO, SCHED_POLICY_IDLE, SCHED_POLICY_RR},
};

/// Decode an ABI policy/priority pair into a kernel [`SchedPolicy`].
///
/// The priority travels in the low 32 bits of the argument and is
/// interpreted as a signed `i32` so that Nice values below zero survive the
/// register-width round trip. The upper 32 bits must be a valid sign
/// extension, otherwise the caller is guessing and gets `EINVAL`.
fn decode_policy(policy: u32, priority: u64) -> Result<SchedPolicy, SyscallError> {
    let high = priority >> 32;
    if high != 0 && high != u32::MAX as u64 {
        return Err(SyscallError::InvalidArgument);
    }
    let priority = priority as u32 as i32;

    match policy {
        SCHED_POLICY_FAIR => {
            if !(-20..=19).contains(&priority) {
                return Err(SyscallError::InvalidArgument);
            }
            Ok(SchedPolicy::Fair(Nice::new(priority as i8)))
        }
        SCHED_POLICY_RR | SCHED_POLICY_FIFO => {
            if !(0..=99).contains(&priority) {
                return Err(SyscallError::InvalidArgument);
            }
            let prio = RealTimePriority::new(priority as u8);
            if policy == SCHED_POLICY_RR {
                Ok(SchedPolicy::RealTimeRR { prio })
            } else {
                Ok(SchedPolicy::RealTimeFifo { prio })
            }
        }
        SCHED_POLICY_IDLE => Ok(SchedPolicy::Idle),
        _ => Err(SyscallError::InvalidArgument),
    }
}

/// Whether `new` gives more CPU entitlement than the task was created with.
///
/// The creation [`TaskPriority`] is the delegation ceiling: a task may lower
/// itself freely (longer Nice, Idle, lower RT priority) but needs an
/// administrative capability to go above it. This closes the `Nice -20`
/// starvation hole without trapping a task that temporarily lowered itself:
/// it can always return to its ceiling.
fn exceeds_priority_ceiling(base: TaskPriority, new: SchedPolicy) -> bool {
    use SchedPolicy::*;
    match (Task::default_sched_policy(base), new) {
        // Idle is always a downgrade.
        (_, Idle) => false,
        // Real-time created tasks may use any Fair value or lower RT prio.
        (RealTimeRR { .. } | RealTimeFifo { .. }, Fair(_)) => false,
        (
            RealTimeRR { prio: b } | RealTimeFifo { prio: b },
            RealTimeRR { prio: n } | RealTimeFifo { prio: n },
        ) => n.get() > b.get(),
        // Fair tasks may move to a greater (lower-priority) Nice value only.
        (Fair(b), Fair(n)) => n.value().get() < b.value().get(),
        (Fair(_), RealTimeRR { .. } | RealTimeFifo { .. }) => true,
        // Idle-created tasks need a capability to become Fair or RT.
        (Idle, Fair(_) | RealTimeRR { .. } | RealTimeFifo { .. }) => true,
    }
}

/// Encode a kernel [`SchedPolicy`] back into the `(policy, priority)` wire
/// representation used by `SYS_SCHED_GET`.
fn encode_policy(policy: SchedPolicy) -> (u32, i32) {
    match policy {
        SchedPolicy::Fair(nice) => (SCHED_POLICY_FAIR, nice.value().get() as i32),
        SchedPolicy::RealTimeRR { prio } => (SCHED_POLICY_RR, prio.get() as i32),
        SchedPolicy::RealTimeFifo { prio } => (SCHED_POLICY_FIFO, prio.get() as i32),
        SchedPolicy::Idle => (SCHED_POLICY_IDLE, 0),
    }
}

/// `SYS_SCHED_SET(345)`: change the calling task's policy and priority.
pub fn sys_sched_set(policy: u64, priority: u64) -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let policy = u32::try_from(policy).map_err(|_| SyscallError::InvalidArgument)?;
    let new_policy = decode_policy(policy, priority)?;

    // The creation priority is the delegation ceiling. Raising above it —
    // including any negative Nice value or a higher RT priority — requires
    // an administrative capability until a dedicated scheduling capability
    // resource exists.
    if exceeds_priority_ceiling(task.priority, new_policy) {
        crate::silo::require_silo_admin()?;
    }

    if !set_task_sched_policy(task.id, new_policy) {
        return Err(SyscallError::NoSuchProcess);
    }

    // Apply the new class immediately instead of waiting for the next tick:
    // a task switching to RT should not keep running behind Fair work.
    crate::process::yield_task();
    Ok(0)
}

/// `SYS_SCHED_GET(346)`: read the calling task's policy and priority.
///
/// Returns `(policy as u32) | (priority_byte << 32)`. For Fair, the byte is
/// Nice offset by 20 (`0` = -20, `20` = 0, `39` = 19); for RT it is the
/// priority (`0..=99`); Idle reports `0`. Keeping the sign out of bit 63
/// means the packed return can never be mistaken for an errno by a generic
/// syscall wrapper.
pub fn sys_sched_get() -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let (policy, priority) = encode_policy(task.sched_policy());
    let priority_byte = if policy == SCHED_POLICY_FAIR {
        (priority + 20) as u8
    } else {
        priority as u8
    };
    Ok((policy as u64) | ((priority_byte as u64) << 32))
}

/// The mask of CPUs currently online, as a 64-bit affinity mask.
fn online_cpu_mask() -> u64 {
    let mut online = [0usize; crate::arch::percpu::MAX_CPUS];
    let n = crate::arch::percpu::online_cpu_indices(&mut online);
    online[..n].iter().fold(0u64, |mask, &cpu| {
        if cpu < u64::BITS as usize {
            mask | (1u64 << cpu)
        } else {
            mask
        }
    })
}

/// `SYS_SCHED_SETAFFINITY(347)`: replace the calling task's soft CPU mask.
///
/// `0` restores the silo default (or "all CPUs" for a task outside a silo).
///
/// The request is checked against the online CPU mask and against the silo's
/// configured partition: a task can narrow its affinity but cannot widen it
/// beyond what the silo was granted.
pub fn sys_sched_setaffinity(mask: u64) -> Result<u64, SyscallError> {
    let online = online_cpu_mask();
    if mask != 0 && (mask & !online != 0 || mask & online == 0) {
        return Err(SyscallError::InvalidArgument);
    }

    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let allowed = crate::silo::allowed_cpu_affinity_for_task(task.id);
    let effective = if allowed == 0 {
        mask
    } else if mask == 0 {
        // Clearing within a partitioned silo means "silo default", never
        // "every CPU".
        allowed
    } else if mask & !allowed != 0 {
        return Err(SyscallError::PermissionDenied);
    } else {
        mask
    };

    task.affinity_mask
        .store(effective, core::sync::atomic::Ordering::Release);
    Ok(0)
}

/// `SYS_SCHED_GETAFFINITY(348)`: read the calling task's soft CPU mask.
pub fn sys_sched_getaffinity() -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    Ok(task
        .affinity_mask
        .load(core::sync::atomic::Ordering::Acquire))
}

/// `SYS_SCHED_INFO(349)`: fill a [`SchedInfo`] for the calling task.
pub fn sys_sched_info(out_ptr: u64) -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let out = UserSliceWrite::new(out_ptr, core::mem::size_of::<SchedInfo>())?;

    let (policy, priority) = encode_policy(task.sched_policy());
    let ticks = task.ticks.load(core::sync::atomic::Ordering::Relaxed);
    let run_time_ns = ticks.saturating_mul(crate::arch::timer::NS_PER_TICK);
    let blocked_time_ns = task
        .blocked_ns_total
        .load(core::sync::atomic::Ordering::Relaxed);
    let now = crate::sync::scheduler_clock_ns();
    let ready_time_ns = now
        .saturating_sub(task.created_ns)
        .saturating_sub(run_time_ns)
        .saturating_sub(blocked_time_ns);
    let mut info = SchedInfo {
        policy,
        state: task.state.load(core::sync::atomic::Ordering::Relaxed) as u32,
        priority,
        flags: 0,
        affinity_mask: task
            .affinity_mask
            .load(core::sync::atomic::Ordering::Relaxed),
        run_time_ns,
        ticks,
        vruntime: task.vruntime.load(core::sync::atomic::Ordering::Relaxed),
        rt_budget_remaining: task
            .rt_budget_remaining
            .load(core::sync::atomic::Ordering::Relaxed),
        rt_overruns: task.rt_overruns.load(core::sync::atomic::Ordering::Relaxed),
        fair_wait_ticks: task
            .fair_wait_ticks
            .load(core::sync::atomic::Ordering::Relaxed),
        wake_deadline_ns: task
            .wake_deadline_ns
            .load(core::sync::atomic::Ordering::Relaxed),
        blocked_time_ns,
        ready_time_ns,
    };
    if task.rt_degraded.load(core::sync::atomic::Ordering::Relaxed) {
        info.flags |= SCHED_INFO_FLAG_RT_DEGRADED;
    }

    let raw = unsafe {
        core::slice::from_raw_parts(
            &info as *const SchedInfo as *const u8,
            core::mem::size_of::<SchedInfo>(),
        )
    };
    if out.copy_from(raw) != raw.len() {
        return Err(SyscallError::Fault);
    }
    Ok(0)
}
