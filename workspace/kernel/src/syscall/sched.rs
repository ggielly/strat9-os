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
        set_task_sched_policy,
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
/// register-width round trip.
fn decode_policy(policy: u32, priority: i32) -> Result<SchedPolicy, SyscallError> {
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
    let priority = priority as u32 as i32;
    let new_policy = decode_policy(policy, priority)?;

    // Elevating to real time is privileged until a dedicated capability
    // resource exists (R11). Staying at or dropping to a lower class is
    // always permitted.
    let already_rt = matches!(
        task.sched_policy(),
        SchedPolicy::RealTimeRR { .. } | SchedPolicy::RealTimeFifo { .. }
    );
    if matches!(
        new_policy,
        SchedPolicy::RealTimeRR { .. } | SchedPolicy::RealTimeFifo { .. }
    ) && !already_rt
    {
        crate::silo::require_silo_admin()?;
    }

    if !set_task_sched_policy(task.id, new_policy) {
        return Err(SyscallError::NotFound);
    }
    Ok(0)
}

/// `SYS_SCHED_GET(346)`: read the calling task's policy and priority.
///
/// Returns `(policy as u32) | ((priority as i32 as u32 as u64) << 32)`.
pub fn sys_sched_get() -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let (policy, priority) = encode_policy(task.sched_policy());
    Ok((policy as u64) | ((priority as u32 as u64) << 32))
}

/// `SYS_SCHED_SETAFFINITY(347)`: replace the calling task's soft CPU mask.
///
/// `0` clears the restriction (all CPUs allowed). Bits outside the platform
/// CPU range are rejected rather than silently truncated.
pub fn sys_sched_setaffinity(mask: u64) -> Result<u64, SyscallError> {
    let max_cpus = crate::arch::percpu::MAX_CPUS;
    if max_cpus < 64 && (mask >> max_cpus) != 0 {
        return Err(SyscallError::InvalidArgument);
    }

    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    task.affinity_mask
        .store(mask, core::sync::atomic::Ordering::Release);
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
    let mut info = SchedInfo {
        policy,
        state: task.state.load(core::sync::atomic::Ordering::Relaxed) as u32,
        priority,
        flags: 0,
        affinity_mask: task
            .affinity_mask
            .load(core::sync::atomic::Ordering::Relaxed),
        run_time_ns: ticks.saturating_mul(crate::arch::timer::NS_PER_TICK),
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
