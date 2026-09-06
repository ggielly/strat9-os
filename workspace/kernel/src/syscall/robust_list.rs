//! Robust list syscalls: set_robust_list, get_robust_list
//!
//! Robust lists allow the kernel to clean up held futex-based mutexes when a
//! thread dies, preventing deadlocks.
//!
//! Linux ABI (robust_list_head in userspace):
//!   offset 0: struct robust_list list       (next pointer, 8 bytes)
//!   offset 8: long futex_offset              (offset from list entry to futex int)
//!   offset 16: struct robust_list *list_op_pending  (pending operation)
//!
//! Total: 24 bytes on x86_64.

use crate::{
    memory::userslice::{UserSliceRead, UserSliceWrite},
    process::current_task_clone,
    syscall::error::SyscallError,
};

/// Maximum number of entries to walk in a robust list (Linux uses 4096).
const ROBUST_LIST_LIMIT: u32 = 4096;

/// Futex value bit: the owner has died.
const FUTEX_OWNER_DIED: u32 = 0x4000_0000;

/// Mask for the TID portion of a futex value.
const TID_MASK: u32 = 0x3FFF_FFFF;

/// SYS_SET_ROBUST_LIST (610): Register the robust list head for the current task.
///
/// # Arguments
/// * `head` - Pointer to a userspace robust_list_head structure
/// * `len`  - Size of the robust_list_head structure (must be >= 24 on x86_64)
///
/// # Returns
/// * 0 on success
/// * -EINVAL if len is invalid
pub fn sys_set_robust_list(head: u64, len: usize) -> Result<u64, SyscallError> {
    // On x86_64, robust_list_head is 24 bytes. Accept any len >= 24.
    if head != 0 && len < 24 {
        return Err(SyscallError::InvalidArgument);
    }

    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    task.robust_list_head
        .store(head, core::sync::atomic::Ordering::Relaxed);
    task.robust_list_len
        .store(len, core::sync::atomic::Ordering::Relaxed);
    Ok(0)
}

/// SYS_GET_ROBUST_LIST (611): Get the robust list head for a task.
///
/// # Arguments
/// * `pid`       - PID of the task to query (0 = current task)
/// * `head_ptr`  - Output pointer for the robust_list_head pointer
/// * `len_ptr`   - Output pointer for the size
///
/// # Returns
/// * 0 on success
/// * -EINVAL if pid is invalid
/// * -EFAULT if head_ptr or len_ptr are invalid
/// * -EPERM if not permitted to access the task
pub fn sys_get_robust_list(pid: i64, head_ptr: u64, len_ptr: u64) -> Result<u64, SyscallError> {
    let task = if pid == 0 {
        current_task_clone().ok_or(SyscallError::PermissionDenied)?
    } else {
        let pid_u = pid as u32;
        crate::process::get_task_by_pid(pid_u.into()).ok_or(SyscallError::NotFound)?
    };

    let head = task
        .robust_list_head
        .load(core::sync::atomic::Ordering::Relaxed);
    let len = task
        .robust_list_len
        .load(core::sync::atomic::Ordering::Relaxed);

    if head_ptr != 0 {
        let user = UserSliceWrite::new(head_ptr, core::mem::size_of::<u64>())?;
        user.copy_from(&head.to_ne_bytes());
    }
    if len_ptr != 0 {
        let user = UserSliceWrite::new(len_ptr, core::mem::size_of::<usize>())?;
        user.copy_from(&len.to_ne_bytes());
    }

    Ok(0)
}

/// Walk the robust list for a dying task and mark owned futexes as "owner died".
///
/// Called from `exit_current_task()` before the task's address space is torn down.
///
/// # Safety
/// Reads userspace memory at `robust_list_head`. The address space must still be
/// valid (not yet freed).
pub fn cleanup_robust_list(task: &crate::process::Task) {
    let head_ptr = task
        .robust_list_head
        .load(core::sync::atomic::Ordering::Relaxed);
    if head_ptr == 0 {
        return;
    }

    let tid = task.tid;

    // Read the robust_list_head fields from userspace via read_u64:
    //   offset 0: list.next (first entry pointer, u64)
    //   offset 8: futex_offset (i64, read as u64 then cast)
    //   offset 16: list_op_pending (u64)
    let head_slice = match UserSliceRead::new(head_ptr, 24) {
        Ok(s) => s,
        Err(_) => return,
    };

    let first_entry = match head_slice.read_u64(0) {
        Ok(v) => v,
        Err(_) => return,
    };
    let futex_offset = match head_slice.read_u64(8) {
        Ok(v) => v as i64,
        Err(_) => return,
    };
    let pending = match head_slice.read_u64(16) {
        Ok(v) => v,
        Err(_) => return,
    };

    // Handle the pending entry first (it may not be in the list yet)
    if pending != 0 && pending != head_ptr {
        mark_futex_owner_died(pending, futex_offset, tid);
    }

    // Walk the linked list
    let mut entry = first_entry;
    let mut count = 0u32;

    while entry != head_ptr && count < ROBUST_LIST_LIMIT {
        // Read the next pointer from this entry (offset 0 = list.next)
        let next_ptr = match UserSliceRead::new(entry, 8) {
            Ok(s) => match s.read_u64(0) {
                Ok(v) => v,
                Err(_) => break,
            },
            Err(_) => break,
        };

        // Mark the futex as owner-died if this task still holds it
        mark_futex_owner_died(entry, futex_offset, tid);

        entry = next_ptr;
        count += 1;
    }
}

/// Mark a futex as owner-died if the current thread still holds it.
///
/// Reads the futex value at (entry + futex_offset). If the lower 30 bits
/// match `tid`, sets bit 30 (FUTEX_OWNER_DIED) and does a FUTEX_WAKE.
fn mark_futex_owner_died(entry: u64, futex_offset: i64, tid: u32) {
    let futex_addr = (entry as i64 + futex_offset) as u64;

    // Read the futex word (u32) by reading 4 bytes
    let futex_val = match read_u32_from_user(futex_addr) {
        Some(v) => v,
        None => return,
    };

    // Check if this task still holds the futex (lower 30 bits == tid)
    if (futex_val & TID_MASK) != tid {
        return; // Not held by this task
    }

    // Set the owner-died bit
    let new_val = futex_val | FUTEX_OWNER_DIED;

    // Write the new value to userspace
    if let Ok(user) = UserSliceWrite::new(futex_addr, 4) {
        user.copy_from(&new_val.to_ne_bytes());
    }

    // Wake all waiters on this futex
    let _ = crate::syscall::futex::sys_futex_wake(futex_addr, u32::MAX);
}

/// Read a u32 from userspace memory at the given address.
fn read_u32_from_user(addr: u64) -> Option<u32> {
    let slice = UserSliceRead::new(addr, 4).ok()?;
    let b0 = slice.read_u8(0).ok()? as u32;
    let b1 = slice.read_u8(1).ok()? as u32;
    let b2 = slice.read_u8(2).ok()? as u32;
    let b3 = slice.read_u8(3).ok()? as u32;
    Some(b0 | (b1 << 8) | (b2 << 16) | (b3 << 24))
}
