//! Strat9-OS syscall dispatcher.
//!
//! Routes syscall numbers to handler functions and converts results to RAX values.
//! Called from the naked `syscall_entry` assembly with a pointer to `SyscallFrame`.
use super::{
    error::SyscallError, exec::sys_execve, fork::sys_fork, numbers::*, process as proc_sys,
    sys_clock_gettime, sys_nanosleep, SyscallFrame,
};
use crate::{
    capability::{get_capability_manager, CapId, CapPermissions, ResourceType},
    drivers::virtio::block::{self, BlockDevice, SECTOR_SIZE},
    ipc::{
        channel::{self, ChanId},
        message::IpcMessage,
        port::{self, PortId},
        reply,
    },
    memory::{UserSliceRead, UserSliceWrite},
    process::current_task_clone,
    silo,
};
use alloc::{sync::Arc, vec};

/// Main dispatch function called from `syscall_entry` assembly.
///
/// # Arguments
/// * `frame` - Pointer to the SyscallFrame on the kernel stack.
///
/// # Returns
/// The value to place in RAX (positive = success, negative = error).
///
/// # Safety
/// Called from naked assembly. `frame` must be a valid pointer to a
/// `SyscallFrame` on the current kernel stack.
#[no_mangle]
pub extern "C" fn __strat9_syscall_dispatch(frame: &mut SyscallFrame) -> u64 {
    let syscall_num = frame.rax;
    let arg1 = frame.rdi;
    let arg2 = frame.rsi;
    let arg3 = frame.rdx;
    let arg4 = frame.r10;
    let _arg5 = frame.r8;
    let _arg6 = frame.r9;

    let result = match syscall_num {
        SYS_NULL => sys_null(),
        SYS_HANDLE_DUPLICATE => sys_handle_duplicate(arg1),
        SYS_HANDLE_CLOSE => sys_handle_close(arg1),

        // Memory management (block 100-199)
        SYS_MMAP => super::mmap::sys_mmap(arg1, arg2, arg3 as u32, arg4 as u32, frame.r8, frame.r9),
        SYS_MUNMAP => super::mmap::sys_munmap(arg1, arg2),
        SYS_BRK => super::mmap::sys_brk(arg1),

        SYS_PROC_EXIT => sys_proc_exit(arg1),
        SYS_PROC_YIELD => sys_proc_yield(),
        SYS_PROC_FORK => sys_fork(frame).map(|result| result.child_pid as u64),
        SYS_PROC_GETPID | SYS_GETPID => proc_sys::sys_getpid(),
        SYS_PROC_GETPPID | SYS_GETPPID => proc_sys::sys_getppid(),
        SYS_GETTID => proc_sys::sys_gettid(),
        SYS_PROC_WAITPID => {
            super::wait::sys_waitpid(arg1 as i64, arg2, arg3 as u32).map(|pid| pid as u64)
        }
        SYS_PROC_WAIT => super::wait::sys_wait(arg1),
        SYS_PROC_EXECVE => sys_execve(frame, arg1, arg2, arg3),
        SYS_FCNTL => super::fcntl::sys_fcntl(arg1, arg2, arg3),
        SYS_SETPGID => proc_sys::sys_setpgid(arg1 as i64, arg2 as i64),
        SYS_GETPGID => proc_sys::sys_getpgid(arg1 as i64),
        SYS_SETSID => proc_sys::sys_setsid(),
        SYS_GETPGRP => proc_sys::sys_getpgrp(),
        SYS_GETSID => proc_sys::sys_getsid(arg1 as i64),
        SYS_FUTEX_WAIT => super::futex::sys_futex_wait(arg1, arg2 as u32, arg3),
        SYS_FUTEX_WAKE => super::futex::sys_futex_wake(arg1, arg2 as u32),
        SYS_FUTEX_REQUEUE => super::futex::sys_futex_requeue(arg1, arg2 as u32, arg3 as u32, arg4),
        SYS_FUTEX_CMP_REQUEUE => super::futex::sys_futex_cmp_requeue(
            arg1,
            arg2 as u32,
            arg3 as u32,
            arg4,
            frame.r8 as u32,
        ),
        SYS_FUTEX_WAKE_OP => {
            super::futex::sys_futex_wake_op(arg1, arg2 as u32, arg3 as u32, arg4, frame.r8 as u32)
        }
        SYS_KILL => super::signal::sys_kill(arg1 as i64, arg2 as u32),
        SYS_SIGPROCMASK => sys_sigprocmask(arg1 as i32, arg2, arg3),
        SYS_SIGACTION => super::signal::sys_sigaction(arg1, arg2, arg3),
        SYS_SIGALTSTACK => super::signal::sys_sigaltstack(arg1, arg2),
        SYS_SIGPENDING => super::signal::sys_sigpending(arg1),
        SYS_SIGSUSPEND => super::signal::sys_sigsuspend(arg1),
        SYS_SIGTIMEDWAIT => super::signal::sys_sigtimedwait(arg1, arg2, arg3),
        SYS_SIGQUEUE => super::signal::sys_sigqueue(arg1 as i64, arg2 as u32, arg3),
        SYS_KILLPG => super::signal::sys_killpg(arg1, arg2 as u32),
        SYS_GETITIMER => super::signal::sys_getitimer(arg1 as u32, arg2),
        SYS_SETITIMER => super::signal::sys_setitimer(arg1 as u32, arg2, arg3),
        SYS_IPC_CREATE_PORT => sys_ipc_create_port(arg1),
        SYS_IPC_SEND => sys_ipc_send(arg1, arg2),
        SYS_IPC_RECV => sys_ipc_recv(arg1, arg2),
        SYS_IPC_TRY_RECV => sys_ipc_try_recv(arg1, arg2),
        SYS_IPC_CALL => sys_ipc_call(arg1, arg2),
        SYS_IPC_REPLY => sys_ipc_reply(arg1),
        SYS_IPC_BIND_PORT => sys_ipc_bind_port(arg1, arg2, arg3),
        SYS_IPC_UNBIND_PORT => sys_ipc_unbind_port(arg1, arg2),
        SYS_IPC_RING_CREATE => sys_ipc_ring_create(arg1),
        SYS_IPC_RING_MAP => sys_ipc_ring_map(arg1, arg2),

        // Typed MPMC sync-channel (IPC-02)
        SYS_CHAN_CREATE => sys_chan_create(arg1),
        SYS_CHAN_SEND => sys_chan_send(arg1, arg2),
        SYS_CHAN_RECV => sys_chan_recv(arg1, arg2),
        SYS_CHAN_TRY_RECV => sys_chan_try_recv(arg1, arg2),
        SYS_CHAN_CLOSE => sys_chan_close(arg1),
        SYS_MODULE_LOAD => silo::sys_module_load(arg1, arg2),
        SYS_MODULE_UNLOAD => silo::sys_module_unload(arg1),
        SYS_MODULE_GET_SYMBOL => silo::sys_module_get_symbol(arg1, arg2),
        SYS_MODULE_QUERY => silo::sys_module_query(arg1, arg2),
        SYS_OPEN => sys_open(arg1, arg2, arg3),
        SYS_WRITE => sys_write(arg1, arg2, arg3),
        SYS_READ => sys_read(arg1, arg2, arg3),
        SYS_CLOSE => sys_close(arg1),
        SYS_LSEEK => sys_lseek(arg1, arg2, arg3),
        SYS_FSTAT => sys_fstat(arg1, arg2),
        SYS_STAT => sys_stat(arg1, arg2, arg3),
        SYS_GETDENTS => sys_getdents(arg1, arg2, arg3),
        SYS_PIPE => sys_pipe(arg1),
        SYS_DUP => sys_dup(arg1),
        SYS_DUP2 => sys_dup2(arg1, arg2),

        // Network
        SYS_NET_RECV => sys_net_recv(arg1, arg2),
        SYS_NET_SEND => sys_net_send(arg1, arg2),
        SYS_NET_INFO => sys_net_info(arg1, arg2),

        SYS_VOLUME_READ => sys_volume_read(arg1, arg2, arg3, arg4),
        SYS_VOLUME_WRITE => sys_volume_write(arg1, arg2, arg3, arg4),
        SYS_VOLUME_INFO => sys_volume_info(arg1),
        SYS_CLOCK_GETTIME => sys_clock_gettime(),
        SYS_NANOSLEEP => sys_nanosleep(arg1, arg2),
        SYS_DEBUG_LOG => sys_debug_log(arg1, arg2),
        SYS_SILO_CREATE => silo::sys_silo_create(arg1),
        SYS_SILO_CONFIG => silo::sys_silo_config(arg1, arg2),
        SYS_SILO_ATTACH_MODULE => silo::sys_silo_attach_module(arg1, arg2),
        SYS_SILO_START => silo::sys_silo_start(arg1),
        SYS_SILO_STOP => silo::sys_silo_stop(arg1),
        SYS_SILO_KILL => silo::sys_silo_kill(arg1),
        SYS_SILO_EVENT_NEXT => silo::sys_silo_event_next(arg1),
        SYS_SILO_SUSPEND => silo::sys_silo_suspend(arg1),
        SYS_SILO_RESUME => silo::sys_silo_resume(arg1),
        _ => {
            log::warn!("Unknown syscall: {} (0x{:x})", syscall_num, syscall_num);
            Err(SyscallError::NotImplemented)
        }
    };

    match result {
        Ok(val) => {
            if syscall_num == SYS_PROC_FORK {
                crate::serial_println!("[syscall] FORK returning Ok({})", val);
            } else if syscall_num == SYS_PROC_WAITPID {
                crate::serial_println!("[syscall] WAITPID returning Ok({})", val);
            }
            val
        }
        Err(e) => {
            if syscall_num == SYS_PROC_FORK {
                crate::serial_println!("[syscall] FORK returning err");
            } else if syscall_num == SYS_PROC_WAITPID {
                crate::serial_println!("[syscall] WAITPID returning err {:?}", e);
            }
            e.to_raw()
        }
    }
}

/// Alias used by the `call {dispatch}` in syscall_entry.
/// Re-exports `__strat9_syscall_dispatch` under the symbol the assembly expects.
#[no_mangle]
pub extern "C" fn dispatch(frame: &mut SyscallFrame) -> u64 {
    __strat9_syscall_dispatch(frame)
}

// ============================================================
// Syscall handlers
// ============================================================

/// SYS_NULL (0): Ping/test syscall. Returns magic value 0x57A79 ("STRAT9").
fn sys_null() -> Result<u64, SyscallError> {
    Ok(0x57A79)
}

/// SYS_HANDLE_CLOSE (2): Close a handle. Stub — always succeeds.
fn sys_handle_close(_handle: u64) -> Result<u64, SyscallError> {
    crate::silo::enforce_cap_for_current_task(_handle)?;
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let caps = unsafe { &mut *task.capabilities.get() };
    if let Some(cap) = caps.remove(CapId::from_raw(_handle)) {
        if cap.resource_type == ResourceType::File {
            if let Ok(fd) = u32::try_from(cap.resource) {
                let _ = crate::vfs::close(fd);
            }
        }
        log::trace!("syscall: HANDLE_CLOSE({})", _handle);
        Ok(0)
    } else {
        Err(SyscallError::BadHandle)
    }
}

/// SYS_HANDLE_DUPLICATE (1): Duplicate a handle (grant required).
fn sys_handle_duplicate(handle: u64) -> Result<u64, SyscallError> {
    crate::silo::enforce_cap_for_current_task(handle)?;
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let caps = unsafe { &mut *task.capabilities.get() };
    let dup = caps
        .duplicate(CapId::from_raw(handle))
        .ok_or(SyscallError::PermissionDenied)?;
    let id = caps.insert(dup);
    Ok(id.as_u64())
}

/// SYS_PROC_EXIT (300): Exit the current task.
///
/// Marks the task as Dead and yields. This function never returns to the caller.
fn sys_proc_exit(exit_code: u64) -> Result<u64, SyscallError> {
    log::info!("syscall: PROC_EXIT(code={})", exit_code);

    // Mark current task as Dead and yield. The scheduler won't re-queue dead tasks.
    // exit_current_task() diverges (-> !), so this function never returns.
    crate::process::scheduler::exit_current_task(exit_code as i32)
}

/// SYS_PROC_YIELD (301): Yield the current time slice.
fn sys_proc_yield() -> Result<u64, SyscallError> {
    crate::process::yield_task();
    Ok(0)
}

/// SYS_SIGPROCMASK (321): Examine and change blocked signals.
///
/// arg1 = how (0=BLOCK, 1=UNBLOCK, 2=SETMASK), arg2 = set_ptr (new mask), arg3 = oldset_ptr (old mask out)
fn sys_sigprocmask(how: i32, set_ptr: u64, oldset_ptr: u64) -> Result<u64, SyscallError> {
    use crate::process::current_task_clone;

    const SIG_BLOCK: i32 = 0;
    const SIG_UNBLOCK: i32 = 1;
    const SIG_SETMASK: i32 = 2;

    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;

    // SAFETY: We have a reference to the task.
    unsafe {
        let blocked = &*task.blocked_signals.get();

        // If oldset_ptr is not null, write the old mask.
        if oldset_ptr != 0 {
            let old_mask = blocked.get_mask();
            let user = UserSliceWrite::new(oldset_ptr, 8)?;
            user.copy_from(&old_mask.to_ne_bytes());
        }

        // If set_ptr is not null, update the mask.
        if set_ptr != 0 {
            let user = UserSliceRead::new(set_ptr, 8)?;
            let mut buf = [0u8; 8];
            user.copy_to(&mut buf);
            let new_mask = u64::from_ne_bytes(buf);

            let old_mask = blocked.get_mask();
            let updated_mask = match how {
                SIG_BLOCK => old_mask | new_mask,
                SIG_UNBLOCK => old_mask & !new_mask,
                SIG_SETMASK => new_mask,
                _ => return Err(SyscallError::InvalidArgument),
            };

            blocked.set_mask(updated_mask);
        }
    }

    Ok(0)
}

/// SYS_WRITE (404): Write bytes to a file descriptor.
fn sys_write(fd: u64, buf_ptr: u64, buf_len: u64) -> Result<u64, SyscallError> {
    crate::vfs::sys_write(fd as u32, buf_ptr, buf_len)
}

/// SYS_OPEN (403): Open a path from the minimal in-kernel namespace.
fn sys_open(path_ptr: u64, path_len: u64, flags: u64) -> Result<u64, SyscallError> {
    crate::vfs::sys_open(path_ptr, path_len, flags)
}

/// SYS_READ (405): Read bytes from a handle.
fn sys_read(fd: u64, buf_ptr: u64, buf_len: u64) -> Result<u64, SyscallError> {
    crate::vfs::sys_read(fd as u32, buf_ptr, buf_len)
}

/// SYS_CLOSE (406): Close a handle (fd).
fn sys_close(fd: u64) -> Result<u64, SyscallError> {
    crate::vfs::sys_close(fd as u32)
}

/// SYS_LSEEK (407): Seek in a file.
fn sys_lseek(fd: u64, offset: u64, whence: u64) -> Result<u64, SyscallError> {
    crate::vfs::sys_lseek(fd as u32, offset as i64, whence as u32)
}

/// SYS_FSTAT (408): Get metadata of an open file.
fn sys_fstat(fd: u64, stat_ptr: u64) -> Result<u64, SyscallError> {
    crate::vfs::sys_fstat(fd as u32, stat_ptr)
}

/// SYS_STAT (409): Get metadata by path.
fn sys_stat(path_ptr: u64, path_len: u64, stat_ptr: u64) -> Result<u64, SyscallError> {
    crate::vfs::sys_stat(path_ptr, path_len, stat_ptr)
}

/// SYS_GETDENTS (430): Read directory entries.
fn sys_getdents(fd: u64, buf_ptr: u64, buf_len: u64) -> Result<u64, SyscallError> {
    crate::vfs::sys_getdents(fd as u32, buf_ptr, buf_len)
}

/// SYS_PIPE (431): Create a pipe pair.
fn sys_pipe(fds_ptr: u64) -> Result<u64, SyscallError> {
    crate::vfs::sys_pipe(fds_ptr)
}

/// SYS_DUP (432): Duplicate a file descriptor.
fn sys_dup(old_fd: u64) -> Result<u64, SyscallError> {
    crate::vfs::sys_dup(old_fd as u32)
}

/// SYS_DUP2 (433): Duplicate fd to a specific number.
fn sys_dup2(old_fd: u64, new_fd: u64) -> Result<u64, SyscallError> {
    crate::vfs::sys_dup2(old_fd as u32, new_fd as u32)
}

// ============================================================
// Volume / Block device syscalls (VirtIO blk)
// ============================================================

const MAX_SECTORS_PER_CALL: u64 = 256;

fn resolve_volume_device(
    handle: u64,
    required: CapPermissions,
) -> Result<&'static block::VirtioBlockDevice, SyscallError> {
    crate::silo::enforce_cap_for_current_task(handle)?;
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let caps = unsafe { &*task.capabilities.get() };
    let cap = caps
        .get_with_permissions(CapId::from_raw(handle), required)
        .ok_or(SyscallError::PermissionDenied)?;
    if cap.resource_type != ResourceType::Volume {
        return Err(SyscallError::BadHandle);
    }

    let device = block::get_device().ok_or(SyscallError::BadHandle)?;
    let device_ptr = device as *const block::VirtioBlockDevice as usize;
    if cap.resource != device_ptr {
        return Err(SyscallError::BadHandle);
    }

    Ok(device)
}



fn sys_volume_read(
    handle: u64,
    sector: u64,
    buf_ptr: u64,
    sector_count: u64,
) -> Result<u64, SyscallError> {
    if sector_count == 0 {
        return Ok(0);
    }
    if sector_count > MAX_SECTORS_PER_CALL {
        return Err(SyscallError::InvalidArgument);
    }

    let required = CapPermissions {
        read: true,
        write: false,
        execute: false,
        grant: false,
        revoke: false,
    };
    let device = resolve_volume_device(handle, required)?;
    let total_sectors = BlockDevice::sector_count(device);
    if sector >= total_sectors || sector.saturating_add(sector_count) > total_sectors {
        return Err(SyscallError::InvalidArgument);
    }

    let mut kbuf = [0u8; SECTOR_SIZE];
    for i in 0..sector_count {
        let cur_sector = sector.checked_add(i).ok_or(SyscallError::InvalidArgument)?;
        BlockDevice::read_sector(device, cur_sector, &mut kbuf).map_err(SyscallError::from)?;
        let offset = (i as usize)
            .checked_mul(SECTOR_SIZE)
            .ok_or(SyscallError::InvalidArgument)?;
        let ptr = buf_ptr
            .checked_add(offset as u64)
            .ok_or(SyscallError::Fault)?;
        let user = UserSliceWrite::new(ptr, SECTOR_SIZE)?;
        user.copy_from(&kbuf);
    }

    Ok(sector_count)
}

fn sys_volume_write(
    handle: u64,
    sector: u64,
    buf_ptr: u64,
    sector_count: u64,
) -> Result<u64, SyscallError> {
    if sector_count == 0 {
        return Ok(0);
    }
    if sector_count > MAX_SECTORS_PER_CALL {
        return Err(SyscallError::InvalidArgument);
    }

    let required = CapPermissions {
        read: false,
        write: true,
        execute: false,
        grant: false,
        revoke: false,
    };
    let device = resolve_volume_device(handle, required)?;
    let total_sectors = BlockDevice::sector_count(device);
    if sector >= total_sectors || sector.saturating_add(sector_count) > total_sectors {
        return Err(SyscallError::InvalidArgument);
    }

    let mut kbuf = [0u8; SECTOR_SIZE];
    for i in 0..sector_count {
        let cur_sector = sector.checked_add(i).ok_or(SyscallError::InvalidArgument)?;
        let offset = (i as usize)
            .checked_mul(SECTOR_SIZE)
            .ok_or(SyscallError::InvalidArgument)?;
        let ptr = buf_ptr
            .checked_add(offset as u64)
            .ok_or(SyscallError::Fault)?;
        let user = UserSliceRead::new(ptr, SECTOR_SIZE)?;
        let data = user.read_to_vec();
        if data.len() != SECTOR_SIZE {
            return Err(SyscallError::InvalidArgument);
        }
        kbuf.copy_from_slice(&data);
        BlockDevice::write_sector(device, cur_sector, &kbuf).map_err(SyscallError::from)?;
    }

    Ok(sector_count)
}

fn sys_volume_info(handle: u64) -> Result<u64, SyscallError> {
    let required = CapPermissions {
        read: true,
        write: false,
        execute: false,
        grant: false,
        revoke: false,
    };
    let device = resolve_volume_device(handle, required)?;
    Ok(BlockDevice::sector_count(device))
}

/// SYS_DEBUG_LOG (600): Write a debug message to serial output.
///
/// arg1 = buffer pointer, arg2 = buffer length.
fn sys_debug_log(buf_ptr: u64, buf_len: u64) -> Result<u64, SyscallError> {
    if buf_len == 0 {
        return Ok(0);
    }

    // Restrict debug logging to admin or console-capable tasks.
    crate::silo::enforce_console_access()?;

    let len = core::cmp::min(buf_len as usize, 4096);

    // Validate the user buffer via UserSlice
    let user_buf = UserSliceRead::new(buf_ptr, len)?;

    // Copy into kernel buffer
    let mut kbuf = [0u8; 4096];
    let copied = user_buf.copy_to(&mut kbuf);

    // Write to serial with a prefix
    crate::serial_print!("[user-debug] ");
    for &byte in &kbuf[..copied] {
        crate::serial_print!("{}", byte as char);
    }
    crate::serial_println!();

    Ok(copied as u64)
}

// ============================================================
// Network syscalls
// ============================================================

pub fn sys_net_recv(buf_ptr: u64, buf_len: u64) -> Result<u64, SyscallError> {
    let device = crate::drivers::net::get_default_device().ok_or(SyscallError::NotImplemented)?;
    let mut kbuf = vec![0u8; buf_len as usize];

    let n = device.receive(&mut kbuf).map_err(SyscallError::from)?;

    let user = UserSliceWrite::new(buf_ptr, n)?;
    user.copy_from(&kbuf[..n]);
    Ok(n as u64)
}

pub fn sys_net_send(buf_ptr: u64, buf_len: u64) -> Result<u64, SyscallError> {
    let device = crate::drivers::net::get_default_device().ok_or(SyscallError::NotImplemented)?;
    let user = UserSliceRead::new(buf_ptr, buf_len as usize)?;
    let kbuf = user.read_to_vec();

    device.transmit(&kbuf).map_err(SyscallError::from)?;

    Ok(buf_len)
}

pub fn sys_net_info(info_type: u64, buf_ptr: u64) -> Result<u64, SyscallError> {
    let device = crate::drivers::net::get_default_device().ok_or(SyscallError::NotImplemented)?;

    match info_type {
        0 => {
            let mac = device.mac_address();
            let user = UserSliceWrite::new(buf_ptr, 6)?;
            user.copy_from(&mac);
            Ok(6)
        }
        _ => Err(SyscallError::InvalidArgument),
    }
}

// ============================================================
// IPC syscalls (with capability enforcement)
// ============================================================

fn sys_ipc_create_port(_flags: u64) -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let port_id = port::create_port(task.id);
    let cap = get_capability_manager().create_capability(
        ResourceType::IpcPort,
        port_id.as_u64() as usize,
        CapPermissions::all(),
    );
    let cap_id = unsafe { (&mut *task.capabilities.get()).insert(cap) };
    Ok(cap_id.as_u64())
}

fn sys_ipc_send(port: u64, _msg_ptr: u64) -> Result<u64, SyscallError> {
    crate::silo::enforce_cap_for_current_task(port)?;
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let caps = unsafe { &*task.capabilities.get() };
    let required = CapPermissions {
        read: false,
        write: true,
        execute: false,
        grant: false,
        revoke: false,
    };
    let cap = caps
        .get_with_permissions(CapId::from_raw(port), required)
        .ok_or(SyscallError::PermissionDenied)?;
    if cap.resource_type != ResourceType::IpcPort {
        return Err(SyscallError::BadHandle);
    }

    const MSG_SIZE: usize = core::mem::size_of::<IpcMessage>();
    let user = UserSliceRead::new(_msg_ptr, MSG_SIZE)?;
    let mut buf = [0u8; MSG_SIZE];
    user.copy_to(&mut buf);
    let mut msg = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const IpcMessage) };
    msg.sender = task.id.as_u64();
    if msg.flags != 0 {
        let transfer_required = CapPermissions {
            read: false,
            write: false,
            execute: false,
            grant: true,
            revoke: false,
        };
        if caps
            .get_with_permissions(CapId::from_raw(msg.flags as u64), transfer_required)
            .is_none()
        {
            return Err(SyscallError::PermissionDenied);
        }
    }

    let port_id = PortId::from_u64(cap.resource as u64);
    let port = port::get_port(port_id).ok_or(SyscallError::BadHandle)?;
    port.send(msg).map_err(SyscallError::from)?;
    Ok(0)
}

fn sys_ipc_recv(port: u64, _msg_ptr: u64) -> Result<u64, SyscallError> {
    crate::silo::enforce_cap_for_current_task(port)?;
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let caps = unsafe { &*task.capabilities.get() };
    let required = CapPermissions {
        read: true,
        write: false,
        execute: false,
        grant: false,
        revoke: false,
    };
    let cap = caps
        .get_with_permissions(CapId::from_raw(port), required)
        .ok_or(SyscallError::PermissionDenied)?;
    if cap.resource_type != ResourceType::IpcPort {
        return Err(SyscallError::BadHandle);
    }

    let port_id = PortId::from_u64(cap.resource as u64);
    let port = port::get_port(port_id).ok_or(SyscallError::BadHandle)?;
    let mut msg = port.recv().map_err(SyscallError::from)?;

    // Handle transfer (optional): msg.flags contains a handle in the sender table.
    if msg.flags != 0 {
        let sender_id = crate::process::TaskId::from_u64(msg.sender);
        let sender = crate::process::get_task_by_id(sender_id).ok_or(SyscallError::BadHandle)?;
        let sender_caps = unsafe { &mut *sender.capabilities.get() };
        let dup = sender_caps
            .duplicate(CapId::from_raw(msg.flags as u64))
            .ok_or(SyscallError::PermissionDenied)?;

        let receiver = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
        let receiver_caps = unsafe { &mut *receiver.capabilities.get() };
        let new_id = receiver_caps.insert(dup);
        if new_id.as_u64() > u32::MAX as u64 {
            return Err(SyscallError::InvalidArgument);
        }
        msg.flags = new_id.as_u64() as u32;
    }

    const MSG_SIZE: usize = core::mem::size_of::<IpcMessage>();
    let mut buf = [0u8; MSG_SIZE];
    // SAFETY: buf is exactly the size of IpcMessage.
    unsafe {
        msg.to_raw(buf.as_mut_ptr());
    }
    let user = UserSliceWrite::new(_msg_ptr, MSG_SIZE)?;
    user.copy_from(&buf);
    Ok(0)
}

fn sys_ipc_try_recv(port: u64, _msg_ptr: u64) -> Result<u64, SyscallError> {
    crate::silo::enforce_cap_for_current_task(port)?;
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let caps = unsafe { &*task.capabilities.get() };
    let required = CapPermissions {
        read: true,
        write: false,
        execute: false,
        grant: false,
        revoke: false,
    };
    let cap = caps
        .get_with_permissions(CapId::from_raw(port), required)
        .ok_or(SyscallError::PermissionDenied)?;
    if cap.resource_type != ResourceType::IpcPort {
        return Err(SyscallError::BadHandle);
    }

    let port_id = PortId::from_u64(cap.resource as u64);
    let port = port::get_port(port_id).ok_or(SyscallError::BadHandle)?;
    let msg_opt = port.try_recv().map_err(SyscallError::from)?;

    let mut msg = match msg_opt {
        Some(m) => m,
        None => return Err(SyscallError::Again),
    };

    // Handle transfer (optional): msg.flags contains a handle in the sender table.
    if msg.flags != 0 {
        let sender_id = crate::process::TaskId::from_u64(msg.sender);
        let sender = crate::process::get_task_by_id(sender_id).ok_or(SyscallError::BadHandle)?;
        let sender_caps = unsafe { &mut *sender.capabilities.get() };
        let dup = sender_caps
            .duplicate(CapId::from_raw(msg.flags as u64))
            .ok_or(SyscallError::PermissionDenied)?;

        let receiver = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
        let receiver_caps = unsafe { &mut *receiver.capabilities.get() };
        let new_id = receiver_caps.insert(dup);
        if new_id.as_u64() > u32::MAX as u64 {
            return Err(SyscallError::InvalidArgument);
        }
        msg.flags = new_id.as_u64() as u32;
    }

    const MSG_SIZE: usize = core::mem::size_of::<IpcMessage>();
    let mut buf = [0u8; MSG_SIZE];
    // SAFETY: buf is exactly the size of IpcMessage.
    unsafe {
        msg.to_raw(buf.as_mut_ptr());
    }
    let user = UserSliceWrite::new(_msg_ptr, MSG_SIZE)?;
    user.copy_from(&buf);
    Ok(0)
}

fn sys_ipc_call(port: u64, _msg_ptr: u64) -> Result<u64, SyscallError> {
    crate::silo::enforce_cap_for_current_task(port)?;
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let caps = unsafe { &*task.capabilities.get() };
    let required = CapPermissions {
        read: false,
        write: true,
        execute: false,
        grant: false,
        revoke: false,
    };
    let cap = caps
        .get_with_permissions(CapId::from_raw(port), required)
        .ok_or(SyscallError::PermissionDenied)?;
    if cap.resource_type != ResourceType::IpcPort {
        return Err(SyscallError::BadHandle);
    }

    const MSG_SIZE: usize = core::mem::size_of::<IpcMessage>();
    let user = UserSliceRead::new(_msg_ptr, MSG_SIZE)?;
    let mut buf = [0u8; MSG_SIZE];
    user.copy_to(&mut buf);
    let mut msg = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const IpcMessage) };
    msg.sender = task.id.as_u64();
    if msg.flags != 0 {
        let transfer_required = CapPermissions {
            read: false,
            write: false,
            execute: false,
            grant: true,
            revoke: false,
        };
        if caps
            .get_with_permissions(CapId::from_raw(msg.flags as u64), transfer_required)
            .is_none()
        {
            return Err(SyscallError::PermissionDenied);
        }
    }

    let port_id = PortId::from_u64(cap.resource as u64);
    let port = port::get_port(port_id).ok_or(SyscallError::BadHandle)?;
    port.send(msg).map_err(SyscallError::from)?;

    let reply_msg = reply::wait_for_reply(task.id);
    let mut out_buf = [0u8; MSG_SIZE];
    unsafe {
        reply_msg.to_raw(out_buf.as_mut_ptr());
    }
    let user = UserSliceWrite::new(_msg_ptr, MSG_SIZE)?;
    user.copy_from(&out_buf);
    Ok(0)
}

fn sys_ipc_reply(_msg_ptr: u64) -> Result<u64, SyscallError> {
    if _msg_ptr == 0 {
        return Err(SyscallError::Fault);
    }
    const MSG_SIZE: usize = core::mem::size_of::<IpcMessage>();
    let user = UserSliceRead::new(_msg_ptr, MSG_SIZE)?;
    let mut buf = [0u8; MSG_SIZE];
    user.copy_to(&mut buf);
    let msg = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const IpcMessage) };

    let target = crate::process::TaskId::from_u64(msg.sender);
    let mut msg = msg;
    if msg.flags != 0 {
        let sender = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
        let sender_caps = unsafe { &mut *sender.capabilities.get() };
        let dup = sender_caps
            .duplicate(CapId::from_raw(msg.flags as u64))
            .ok_or(SyscallError::PermissionDenied)?;

        let receiver = crate::process::get_task_by_id(target).ok_or(SyscallError::BadHandle)?;
        let receiver_caps = unsafe { &mut *receiver.capabilities.get() };
        let new_id = receiver_caps.insert(dup);
        if new_id.as_u64() > u32::MAX as u64 {
            return Err(SyscallError::InvalidArgument);
        }
        msg.flags = new_id.as_u64() as u32;
    }

    reply::deliver_reply(target, msg).map_err(|_| SyscallError::BadHandle)?;
    Ok(0)
}

fn sys_ipc_bind_port(port: u64, _path_ptr: u64, _path_len: u64) -> Result<u64, SyscallError> {
    crate::silo::require_silo_admin()?;
    crate::silo::enforce_cap_for_current_task(port)?;
    if _path_ptr == 0 || _path_len == 0 {
        return Err(SyscallError::Fault);
    }
    const MAX_PATH_LEN: usize = 4096;
    if _path_len as usize > MAX_PATH_LEN {
        return Err(SyscallError::InvalidArgument);
    }
    let user = UserSliceRead::new(_path_ptr, _path_len as usize)?;
    let bytes = user.read_to_vec();
    let path = core::str::from_utf8(&bytes).map_err(SyscallError::from)?;

    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let caps = unsafe { &*task.capabilities.get() };
    let cap = caps
        .get_with_permissions(
            CapId::from_raw(port),
            CapPermissions {
                read: true,
                write: true,
                execute: false,
                grant: true,
                revoke: false,
            },
        )
        .ok_or(SyscallError::PermissionDenied)?;
    if cap.resource_type != ResourceType::IpcPort {
        return Err(SyscallError::BadHandle);
    }

    crate::vfs::mount(
        path,
        Arc::new(crate::vfs::IpcScheme::new(PortId::from_u64(
            cap.resource as u64,
        ))),
    )?;

    // Bootstrap convenience: if a privileged userspace server binds root `/`,
    // seed it with the primary volume capability so it can mount storage
    // without waiting for an explicit bootstrap message.
    if path == "/" || path == "/fs/ext4" {
        if let Some(device) = crate::drivers::virtio::block::get_device() {
            let volume_cap = crate::capability::get_capability_manager().create_capability(
                ResourceType::Volume,
                device as *const _ as usize,
                CapPermissions {
                    read: true,
                    write: true,
                    execute: false,
                    grant: true,
                    revoke: true,
                },
            );
            let task_caps = unsafe { &mut *task.capabilities.get() };
            let id = task_caps.insert(volume_cap);
            log::info!(
                "ipc_bind_port('/'): seeded volume capability handle={} for task {:?}",
                id.as_u64(),
                task.id
            );

            // Send a bootstrap message to the just-bound root filesystem server.
            // The server expects msg_type=0x10 and handle in flags.
            const BOOTSTRAP_MSG_TYPE: u32 = 0x10;
            if id.as_u64() <= u32::MAX as u64 {
                let mut boot_msg = IpcMessage::new(BOOTSTRAP_MSG_TYPE);
                // Use the bound task as sender so capability transfer path can
                // duplicate `flags` from a valid capability table.
                boot_msg.sender = task.id.as_u64();
                boot_msg.flags = id.as_u64() as u32;

                let port_id = PortId::from_u64(cap.resource as u64);
                if let Some(p) = port::get_port(port_id) {
                    if p.send(boot_msg).is_ok() {
                        log::info!(
                            "ipc_bind_port('/'): queued bootstrap message (handle={})",
                            id.as_u64()
                        );
                    } else {
                        log::warn!("ipc_bind_port('/'): failed to queue bootstrap message");
                    }
                } else {
                    log::warn!("ipc_bind_port('/'): bound port disappeared before bootstrap");
                }
            }
        }
    }
    Ok(0)
}

fn sys_ipc_unbind_port(path_ptr: u64, path_len: u64) -> Result<u64, SyscallError> {
    crate::silo::require_silo_admin()?;
    if path_ptr == 0 || path_len == 0 {
        return Err(SyscallError::Fault);
    }
    const MAX_PATH_LEN: usize = 4096;
    if path_len as usize > MAX_PATH_LEN {
        return Err(SyscallError::InvalidArgument);
    }
    let user = UserSliceRead::new(path_ptr, path_len as usize)?;
    let bytes = user.read_to_vec();
    let path = core::str::from_utf8(&bytes).map_err(SyscallError::from)?;
    crate::vfs::unmount(path)?;
    Ok(0)
}

fn sys_ipc_ring_create(_size: u64) -> Result<u64, SyscallError> {
    Err(SyscallError::NotImplemented)
}

fn sys_ipc_ring_map(ring: u64, _out_ptr: u64) -> Result<u64, SyscallError> {
    crate::silo::enforce_cap_for_current_task(ring)?;
    Err(SyscallError::NotImplemented)
}

// ── Typed MPMC sync-channel syscall handlers (IPC-02) ─────────────────────────

/// SYS_CHAN_CREATE (220): create a bounded sync-channel.
///
/// arg1 = capacity (clamped to [1, 1024]).
/// Returns a capability handle whose `resource` field encodes the `ChanId`.
fn sys_chan_create(capacity: u64) -> Result<u64, SyscallError> {
    let cap = capacity.clamp(1, 1024) as usize;
    let chan_id = channel::create_channel(cap);

    // Register a Channel capability in the current task's capability table.
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let caps = unsafe { &mut *task.capabilities.get() };
    let cap_id = caps.insert(crate::capability::Capability {
        id: crate::capability::CapId::new(),
        permissions: crate::capability::CapPermissions {
            read: true,
            write: true,
            execute: false,
            grant: true,
            revoke: false,
        },
        resource_type: ResourceType::Channel,
        resource: chan_id.as_u64() as usize,
    });

    log::debug!(
        "syscall: CHAN_CREATE(cap={}) → chan={} handle={}",
        cap,
        chan_id,
        cap_id.as_u64()
    );
    Ok(cap_id.as_u64())
}

/// SYS_CHAN_SEND (221): send one `IpcMessage` to a channel, blocking if full.
///
/// arg1 = channel handle (CapId), arg2 = user pointer to 64-byte IpcMessage.
fn sys_chan_send(handle: u64, msg_ptr: u64) -> Result<u64, SyscallError> {
    crate::silo::enforce_cap_for_current_task(handle)?;

    // Validate and copy the message from userspace.
    let user_slice = UserSliceRead::new(msg_ptr, 64).map_err(SyscallError::from)?;
    let mut msg = IpcMessage::new(0);
    // SAFETY: IpcMessage is repr(C), 64 bytes, fully initialised above.
    let n = user_slice.copy_to(unsafe {
        core::slice::from_raw_parts_mut(&mut msg as *mut IpcMessage as *mut u8, 64)
    });
    if n != 64 {
        return Err(SyscallError::Fault);
    }

    // Fill in the sender task ID.
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    msg.sender = task.id.as_u64();

    // Look up the channel capability.
    let caps = unsafe { &*task.capabilities.get() };
    let cap = caps
        .get(crate::capability::CapId::from_raw(handle))
        .ok_or(SyscallError::BadHandle)?;
    if cap.resource_type != ResourceType::Channel || !cap.permissions.write {
        return Err(SyscallError::PermissionDenied);
    }
    let chan_id = ChanId::from_u64(cap.resource as u64);

    let chan = channel::get_channel(chan_id).ok_or(SyscallError::BadHandle)?;
    chan.send(msg).map_err(SyscallError::from)?;

    Ok(0)
}

/// SYS_CHAN_RECV (222): receive one `IpcMessage` from a channel, blocking if empty.
///
/// arg1 = channel handle (CapId), arg2 = user pointer to 64-byte output buffer.
fn sys_chan_recv(handle: u64, msg_ptr: u64) -> Result<u64, SyscallError> {
    crate::silo::enforce_cap_for_current_task(handle)?;

    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let caps = unsafe { &*task.capabilities.get() };
    let cap = caps
        .get(crate::capability::CapId::from_raw(handle))
        .ok_or(SyscallError::BadHandle)?;
    if cap.resource_type != ResourceType::Channel || !cap.permissions.read {
        return Err(SyscallError::PermissionDenied);
    }
    let chan_id = ChanId::from_u64(cap.resource as u64);

    let chan = channel::get_channel(chan_id).ok_or(SyscallError::BadHandle)?;
    let msg = chan.recv().map_err(SyscallError::from)?;

    // Write the received message to userspace.
    let user_slice = UserSliceWrite::new(msg_ptr, 64).map_err(SyscallError::from)?;
    // SAFETY: IpcMessage is repr(C), 64 bytes.
    let n = user_slice.copy_from(unsafe {
        core::slice::from_raw_parts(&msg as *const IpcMessage as *const u8, 64)
    });
    if n != 64 {
        return Err(SyscallError::Fault);
    }

    Ok(0)
}

/// SYS_CHAN_TRY_RECV (223): non-blocking receive.
///
/// Returns 0 if a message was delivered, -EWOULDBLOCK if the channel is empty.
fn sys_chan_try_recv(handle: u64, msg_ptr: u64) -> Result<u64, SyscallError> {
    crate::silo::enforce_cap_for_current_task(handle)?;

    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let caps = unsafe { &*task.capabilities.get() };
    let cap = caps
        .get(crate::capability::CapId::from_raw(handle))
        .ok_or(SyscallError::BadHandle)?;
    if cap.resource_type != ResourceType::Channel || !cap.permissions.read {
        return Err(SyscallError::PermissionDenied);
    }
    let chan_id = ChanId::from_u64(cap.resource as u64);

    let chan = channel::get_channel(chan_id).ok_or(SyscallError::BadHandle)?;
    match chan.try_recv() {
        Ok(msg) => {
            let user_slice = UserSliceWrite::new(msg_ptr, 64).map_err(SyscallError::from)?;
            // SAFETY: IpcMessage is repr(C), 64 bytes.
            let n = user_slice.copy_from(unsafe {
                core::slice::from_raw_parts(&msg as *const IpcMessage as *const u8, 64)
            });
            if n != 64 {
                return Err(SyscallError::Fault);
            }
            Ok(0)
        }
        Err(e) => Err(SyscallError::from(e)),
    }
}

/// SYS_CHAN_CLOSE (224): destroy a channel and remove it from the registry.
///
/// Wakes all tasks blocked on this channel with `Disconnected`.
fn sys_chan_close(handle: u64) -> Result<u64, SyscallError> {
    crate::silo::enforce_cap_for_current_task(handle)?;

    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let caps = unsafe { &mut *task.capabilities.get() };
    let cap = caps
        .remove(crate::capability::CapId::from_raw(handle))
        .ok_or(SyscallError::BadHandle)?;
    if cap.resource_type != ResourceType::Channel {
        return Err(SyscallError::BadHandle);
    }
    let chan_id = ChanId::from_u64(cap.resource as u64);
    channel::destroy_channel(chan_id).map_err(SyscallError::from)?;

    log::debug!("syscall: CHAN_CLOSE(handle={}) → chan={}", handle, chan_id);
    Ok(0)
}
