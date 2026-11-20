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

//! Kernel trace control (`SYS_TRACE_CTL`, `SYS_TRACE_READ`).
//!
//! The per-CPU trace rings already existed for memory events; these syscalls
//! expose the IPC/scheduling/syscall/IRQ categories to a userspace tracing
//! daemon. Everything is gated on silo-admin capability because records
//! contain kernel instruction pointers, task ids and wake deadlines.
//!
//! Cost when tracing is disabled is a single relaxed mask load per hook:
//! the same `enabled()` check that the memory trace already pays.

use super::error::SyscallError;
use crate::{arch::percpu, memory::UserSliceWrite, silo};
use alloc::vec::Vec;
use strat9_abi::{
    data::{TraceRecord, TraceStats},
    syscall::{TRACE_CTL_CLEAR, TRACE_CTL_GET_MASK, TRACE_CTL_SET_MASK, TRACE_CTL_STATS},
};

/// Upper bound on records returned by one `SYS_TRACE_READ` call.
///
/// 4096 records is 384 KiB; larger dumps should be paged by the caller so a
/// single syscall cannot force a large kernel allocation.
const TRACE_READ_MAX: u64 = 4096;

/// `SYS_TRACE_CTL(602)`: configure the trace subsystem.
pub fn sys_trace_ctl(cmd: u64, arg: u64) -> Result<u64, SyscallError> {
    silo::require_silo_admin()?;
    let cmd = u32::try_from(cmd).map_err(|_| SyscallError::InvalidArgument)?;
    match cmd {
        TRACE_CTL_SET_MASK => {
            let old = crate::trace::mask();
            crate::trace::set_mask(arg);
            Ok(old)
        }
        TRACE_CTL_GET_MASK => Ok(crate::trace::mask()),
        TRACE_CTL_CLEAR => {
            crate::trace::clear_all();
            Ok(0)
        }
        TRACE_CTL_STATS => {
            let stats = crate::trace::stats();
            let out = UserSliceWrite::new(arg, core::mem::size_of::<TraceStats>())?;
            let abi = TraceStats {
                stored: stats.stored,
                dropped: stats.dropped,
            };
            let raw = unsafe {
                core::slice::from_raw_parts(
                    &abi as *const TraceStats as *const u8,
                    core::mem::size_of::<TraceStats>(),
                )
            };
            if out.copy_from(raw) != raw.len() {
                return Err(SyscallError::Fault);
            }
            Ok(0)
        }
        _ => Err(SyscallError::InvalidArgument),
    }
}

/// `SYS_TRACE_READ(603)`: copy trace records to userspace.
pub fn sys_trace_read(out_ptr: u64, max_records: u64, flags: u64) -> Result<u64, SyscallError> {
    silo::require_silo_admin()?;
    if flags != 0 {
        return Err(SyscallError::InvalidArgument);
    }

    let max = max_records.min(TRACE_READ_MAX) as usize;
    if max == 0 {
        return Ok(0);
    }

    let record_size = core::mem::size_of::<TraceRecord>();
    let out = UserSliceWrite::new(out_ptr, max * record_size)?;

    // Bound the total allocation: ask each CPU for a fair share, then truncate
    // to the caller's capacity after the global sequence sort.
    let mut online = [0usize; percpu::MAX_CPUS];
    let online_count = percpu::online_cpu_indices(&mut online).max(1);
    let per_cpu = (max / online_count).max(1);

    let events = crate::trace::snapshot_all(per_cpu);
    let count = events.len().min(max);
    if count == 0 {
        return Ok(0);
    }

    let mut raw: Vec<u8> = Vec::with_capacity(count * record_size);
    for event in events.into_iter().take(count) {
        let record = TraceRecord {
            seq: event.seq,
            ticks: event.ticks,
            cpu: event.cpu,
            kind: event.kind,
            reserved: 0,
            category: event.category,
            flags: event.flags,
            task_id: event.task_id,
            pid: event.pid,
            tid: event.tid,
            cr3: event.cr3,
            rip: event.rip,
            vaddr: event.vaddr,
            arg0: event.arg0,
            arg1: event.arg1,
        };
        // SAFETY: `TraceRecord` is `repr(C)` with no padding (static-asserted
        // in the ABI crate) and `record` is a fully initialised value.
        let bytes = unsafe {
            core::slice::from_raw_parts(&record as *const TraceRecord as *const u8, record_size)
        };
        raw.extend_from_slice(bytes);
    }

    if out.copy_from(&raw) != raw.len() {
        return Err(SyscallError::Fault);
    }
    Ok(count as u64)
}
