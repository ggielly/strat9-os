//! Strat9-OS syscall dispatcher
//!
//! Routes syscall numbers to handler functions and converts results to RAX values.
//! Called from the naked `syscall_entry` assembly with a pointer to `SyscallFrame`.
//!
//! The main dispatch function is `__strat9_syscall_dispatch`, which matches on
//! the syscall number and calls the appropriate handler. Each handler returns a
//! `Result<u64, SyscallError>`, which is converted to a raw value in RAX.
//!
//! Handler implementations live in sibling modules (`net`, `volume`, `ipc_port`,
//! `ipc_ring`, `semaphore`, `pci`, `chan`, `debug`, etc.). Only the routing
//! logic and a handful of capability / process / file-io helpers remain here.
//
//

use crate::ipc::{channel, port, semaphore, shared_ring, ChanId, PortId, RingId, SemId};

use super::{
    chan, debug, error::SyscallError, exec::sys_execve, fork::sys_fork, ipc_port, ipc_ring, net,
    numbers::*, pci, process as proc_sys, semaphore as sem_handler, transport, volume,
    SyscallFrame,
};
use crate::{
    async_io::syscall as async_sys,
    capability::{release_capability, CapId, CapPermissions, ResourceType},
    memory::{UserSliceRead, UserSliceWrite},
    process::current_task_clone,
    silo,
};
use core::sync::atomic::Ordering;
/// One-shot diagnostic flag to confirm syscalls reach the dispatcher.
static SYSCALL_DIAG_DONE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Rate-limit counter for the per-syscall ENTER trace (avoid flooding FORCE_LOCK under SMP).
/// Prints first 20 dispatches unconditionally, then every 10 000.
static SYSCALL_TRACE_COUNT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

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
    let syscall_num = frame.rax as usize;
    let arg1 = frame.rdi;
    let arg2 = frame.rsi;
    let arg3 = frame.rdx;

    // One-shot diagnostic: confirm first syscall reaches the dispatcher.
    if !SYSCALL_DIAG_DONE.swap(true, core::sync::atomic::Ordering::Relaxed) {
        crate::e9_println!(
            "[syscall-FIRST] nr={} rip={:#x} tid={:?}",
            syscall_num,
            frame.rcx,
            crate::process::current_task_id().map(|t| t.as_u64())
        );
    }
    let arg4 = frame.r10;
    let arg5 = frame.r8;
    let _arg6 = frame.r9;

    // Rate-limited trace with relaxed-count optimisation.
    //
    // Most syscalls never log. We avoid the expensive `lock xadd` (atomic
    // RMW) by only doing it near sampling points. In the common case we use
    // a plain `store(Relaxed)`.
    // The count drifts slightly under SMP, but I think
    // for diagnostic sampling that is perfectly acceptable...
    // TODO : need review and refactor here. Not happy with the state
    //
    // First 20 calls logged unconditionally, then one sample every 10 000.
    {
        let n = SYSCALL_TRACE_COUNT.load(core::sync::atomic::Ordering::Relaxed);
        if n < 20 || n % 10_000 == 0 || n == u64::MAX {
            // Near a sampling point: synchronise with an accurate RMW.
            let n = SYSCALL_TRACE_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            if n < 20 || n % 10_000 == 0 {
                if let Some(tid) = crate::process::current_task_id() {
                    crate::e9_println!(
                        "[syscall] ENTER n={} tid={} nr={} arg1={:#x} arg2={:#x} rip={:#x} cpu={}",
                        n,
                        tid,
                        syscall_num,
                        arg1,
                        arg2,
                        frame.rcx,
                        crate::arch::percpu::current_cpu_index()
                    );
                }
            }
        } else {
            // Fast path: relaxed store avoids the `lock` bus stall entirely.
            // A race between cores may lose an increment. Harmless for sampling.
            SYSCALL_TRACE_COUNT.store(n + 1, core::sync::atomic::Ordering::Relaxed);
        }
    }

    let result = match syscall_num {
        SYS_NULL => sys_null(),
        SYS_HANDLE_DUPLICATE => sys_handle_duplicate(arg1),
        SYS_HANDLE_CLOSE => sys_handle_close(arg1),
        SYS_HANDLE_WAIT => sys_handle_wait(arg1, arg2),
        SYS_HANDLE_GRANT => sys_handle_grant(arg1, arg2),
        SYS_HANDLE_REVOKE => sys_handle_revoke(arg1),
        SYS_HANDLE_INFO => sys_handle_info(arg1, arg2),

        // Memory management (block 100-199)
        SYS_MMAP => super::mmap::sys_mmap(arg1, arg2, arg3 as u32, arg4 as u32, frame.r8, frame.r9),
        SYS_MUNMAP => super::mmap::sys_munmap(arg1, arg2),
        SYS_BRK => super::mmap::sys_brk(arg1),
        SYS_MREMAP => super::mmap::sys_mremap(arg1, arg2, arg3, arg4),
        SYS_MPROTECT => super::mmap::sys_mprotect(arg1, arg2, arg3),
        SYS_MEM_REGION_EXPORT => super::mmap::sys_mem_region_export(arg1),
        SYS_MEM_REGION_MAP => super::mmap::sys_mem_region_map(arg1, arg2, arg3),
        SYS_MEM_REGION_INFO => super::mmap::sys_mem_region_info(arg1, arg2),

        // Process management (block 300-399)
        SYS_PROC_EXIT => sys_proc_exit(arg1),
        SYS_PROC_YIELD => sys_proc_yield(),
        SYS_PROC_FORK => sys_fork(frame).map(|result| result.child_pid as u64),
        SYS_PROC_GETPID | SYS_GETPID => proc_sys::sys_getpid(),
        SYS_PROC_GETPPID => proc_sys::sys_getppid(),
        SYS_GETTID => proc_sys::sys_gettid(),
        SYS_PROC_WAITPID => {
            super::wait::sys_waitpid(arg1 as i64, arg2, arg3 as u32).map(|pid| pid as u64)
        }
        SYS_PROC_WAIT => super::wait::sys_wait(arg1),
        SYS_PROC_EXECVE => sys_execve(frame, arg1, arg2, arg3),

        // File I/O (block 400-499)
        SYS_FCNTL => super::fcntl::sys_fcntl(arg1, arg2, arg3),
        SYS_SETPGID => proc_sys::sys_setpgid(arg1 as i64, arg2 as i64),
        SYS_GETPGID => proc_sys::sys_getpgid(arg1 as i64),
        SYS_SETSID => proc_sys::sys_setsid(),
        SYS_GETPGRP => proc_sys::sys_getpgrp(),
        SYS_GETSID => proc_sys::sys_getsid(arg1 as i64),

        SYS_GETUID => proc_sys::sys_getuid(),
        SYS_GETEUID => proc_sys::sys_geteuid(),
        SYS_GETGID => proc_sys::sys_getgid(),
        SYS_GETEGID => proc_sys::sys_getegid(),
        SYS_SETUID => proc_sys::sys_setuid(arg1),
        SYS_SETGID => proc_sys::sys_setgid(arg1),
        SYS_THREAD_CREATE => proc_sys::sys_thread_create(frame, arg1, arg2, arg3, arg4, frame.r8),
        SYS_THREAD_JOIN => proc_sys::sys_thread_join(arg1, arg2, arg3),
        SYS_THREAD_EXIT => proc_sys::sys_thread_exit(arg1),
        SYS_UNAME => sys_uname(arg1),
        //  Thread lifecycle (333-334) ===========================================
        SYS_SET_TID_ADDRESS => proc_sys::sys_set_tid_address(arg1),
        SYS_EXIT_GROUP => proc_sys::sys_exit_group(arg1),
        //  Architecture-specific (350) ==========================================
        SYS_ARCH_PRCTL => proc_sys::sys_arch_prctl(arg1, arg2),

        //  tgkill (352) =========================================
        SYS_TGKILL => proc_sys::sys_tgkill(arg1, arg2, arg3),
        SYS_RT_SIGRETURN => super::signal::sys_rt_sigreturn(frame),
        // Futex syscalls (400-409) ========================================
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

        // IPC port syscalls ================================================
        SYS_IPC_CREATE_PORT => ipc_port::sys_ipc_create_port(arg1),
        SYS_IPC_SEND => ipc_port::sys_ipc_send(arg1, arg2),
        SYS_IPC_RECV => ipc_port::sys_ipc_recv(arg1, arg2),
        SYS_IPC_TRY_RECV => ipc_port::sys_ipc_try_recv(arg1, arg2),
        SYS_IPC_CONNECT => ipc_port::sys_ipc_connect(arg1, arg2),
        SYS_IPC_CALL => ipc_port::sys_ipc_call(arg1, arg2),
        SYS_IPC_REPLY => ipc_port::sys_ipc_reply(arg1),
        SYS_IPC_BIND_PORT => ipc_port::sys_ipc_bind_port(arg1, arg2, arg3),
        SYS_IPC_UNBIND_PORT => ipc_port::sys_ipc_unbind_port(arg1, arg2),

        // IPC ring-buffer syscalls ==========================================
        SYS_IPC_RING_CREATE => ipc_ring::sys_ipc_ring_create(arg1),
        SYS_IPC_RING_MAP => ipc_ring::sys_ipc_ring_map(arg1, arg2),

        // Semaphore syscalls ================================================
        SYS_SEM_CREATE => sem_handler::sys_sem_create(arg1),
        SYS_SEM_WAIT => sem_handler::sys_sem_wait(arg1),
        SYS_SEM_TRYWAIT => sem_handler::sys_sem_trywait(arg1),
        SYS_SEM_POST => sem_handler::sys_sem_post(arg1),
        SYS_SEM_CLOSE => sem_handler::sys_sem_close(arg1),

        // Async I/O syscalls (250-254) ======================================
        SYS_ASYNC_SETUP => async_sys::sys_async_setup(arg1, arg2),
        SYS_ASYNC_ENTER => async_sys::sys_async_enter(arg1, arg2, arg3, arg4),
        SYS_ASYNC_CANCEL => async_sys::sys_async_cancel(arg1, arg2, arg3),
        SYS_ASYNC_MAP => async_sys::sys_async_map(arg1, arg2),
        SYS_ASYNC_DESTROY => async_sys::sys_async_destroy(arg1, arg2),

        // Transport syscalls (260-264) ======================================
        SYS_TRANSPORT_CREATE => transport::sys_transport_create(arg1, arg2),
        SYS_TRANSPORT_SEND => transport::sys_transport_send(arg1, arg2, arg3),
        SYS_TRANSPORT_RECV => transport::sys_transport_recv(arg1, arg2, arg3),
        SYS_TRANSPORT_CLOSE => transport::sys_transport_close(arg1),
        SYS_TRANSPORT_INFO => transport::sys_transport_info(arg1, arg2),

        // PCI syscalls ======================================================
        SYS_PCI_ENUM => pci::sys_pci_enum(arg1, arg2, arg3),
        SYS_PCI_CFG_READ => pci::sys_pci_cfg_read(arg1, arg2, arg3),
        SYS_PCI_CFG_WRITE => pci::sys_pci_cfg_write(arg1, arg2, arg3, arg4),

        // Typed MPMC sync-channel (IPC-02) ==================================
        SYS_CHAN_CREATE => chan::sys_chan_create(arg1),
        SYS_CHAN_SEND => chan::sys_chan_send(arg1, arg2),
        SYS_CHAN_RECV => chan::sys_chan_recv(arg1, arg2),
        SYS_CHAN_TRY_RECV => chan::sys_chan_try_recv(arg1, arg2),
        SYS_CHAN_CLOSE => chan::sys_chan_close(arg1),
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
        SYS_ACCESS => crate::vfs::sys_access(arg1, arg2, arg3),
        SYS_GETDENTS => sys_getdents(arg1, arg2, arg3),
        SYS_PIPE => sys_pipe(arg1),
        SYS_DUP => sys_dup(arg1),
        SYS_DUP2 => sys_dup2(arg1, arg2),

        // VFS syscalls (440-455)  ========================================
        SYS_CHDIR => crate::vfs::sys_chdir(arg1, arg2),
        SYS_FCHDIR => crate::vfs::sys_fchdir(arg1 as u32),
        SYS_GETCWD => crate::vfs::sys_getcwd(arg1, arg2),
        SYS_IOCTL => crate::vfs::sys_ioctl(arg1 as u32, arg2, arg3),
        SYS_UMASK => crate::vfs::sys_umask(arg1),
        SYS_UNLINK => crate::vfs::sys_unlink(arg1, arg2),
        SYS_RMDIR => crate::vfs::sys_rmdir(arg1, arg2),
        SYS_MKDIR => crate::vfs::sys_mkdir(arg1, arg2, arg3),
        SYS_RENAME => crate::vfs::sys_rename(arg1, arg2, arg3, arg4),
        SYS_LINK => crate::vfs::sys_link(arg1, arg2, arg3, arg4),
        SYS_SYMLINK => crate::vfs::sys_symlink(arg1, arg2, arg3, arg4),
        SYS_READLINK => crate::vfs::sys_readlink(arg1, arg2, arg3, arg4),
        SYS_CHMOD => crate::vfs::sys_chmod(arg1, arg2, arg3),
        SYS_FCHMOD => crate::vfs::sys_fchmod(arg1 as u32, arg2),
        SYS_TRUNCATE => crate::vfs::sys_truncate(arg1, arg2, arg3),
        SYS_FTRUNCATE => crate::vfs::sys_ftruncate(arg1 as u32, arg2),
        SYS_PREAD => crate::vfs::sys_pread(arg1 as u32, arg2, arg3, arg4),
        SYS_PWRITE => crate::vfs::sys_pwrite(arg1 as u32, arg2, arg3, arg4),
        SYS_POLL => super::poll::sys_poll(arg1, arg2, arg3),
        SYS_PPOLL => super::poll::sys_poll(arg1, arg2, 0),

        // *at() syscalls : FD-relative path resolution ======================
        SYS_OPENAT => crate::vfs::sys_openat(arg1, arg2, arg3, arg4),
        SYS_FSTATAT => crate::vfs::sys_fstatat(arg1, arg2, arg3, arg5),
        SYS_FACCESSAT => crate::vfs::sys_faccessat(arg1, arg2, arg3, arg4, frame.r8),

        // Network syscalls (500-599) ========================================
        SYS_NET_RECV => net::sys_net_recv(arg1, arg2),
        SYS_NET_SEND => net::sys_net_send(arg1, arg2),
        SYS_NET_INFO => net::sys_net_info(arg1, arg2),
        SYS_NET_REGISTER => net::sys_net_register(),

        // Storage syscalls (600-699) ========================================
        SYS_VOLUME_READ => volume::sys_volume_read(arg1, arg2, arg3, arg4),
        SYS_VOLUME_WRITE => volume::sys_volume_write(arg1, arg2, arg3, arg4),
        SYS_VOLUME_INFO => volume::sys_volume_info(arg1),
        SYS_CLOCK_GETTIME => super::time::sys_clock_gettime(arg1 as u32, arg2),
        SYS_NANOSLEEP => super::time::sys_nanosleep(arg1, arg2),
        SYS_CLOCK_NANOSLEEP => {
            super::time::sys_clock_nanosleep(arg1 as u32, arg2 as i32, arg3, arg4)
        }
        SYS_DEBUG_LOG => debug::sys_debug_log(arg1, arg2),
        SYS_GETRANDOM => super::random::sys_getrandom(arg1, arg2 as usize, arg3 as u32),
        SYS_SET_ROBUST_LIST => super::robust_list::sys_set_robust_list(arg1, arg2 as usize),
        SYS_GET_ROBUST_LIST => super::robust_list::sys_get_robust_list(arg1 as i64, arg2, arg3),

        // Silo management (700-799) ========================================
        SYS_SILO_CREATE => silo::sys_silo_create(arg1),
        SYS_SILO_CONFIG => silo::sys_silo_config(arg1, arg2),
        SYS_SILO_ATTACH_MODULE => silo::sys_silo_attach_module(arg1, arg2),
        SYS_SILO_START => silo::sys_silo_start(arg1),
        SYS_SILO_STOP => silo::sys_silo_stop(arg1),
        SYS_SILO_KILL => silo::sys_silo_kill(arg1),
        SYS_SILO_EVENT_NEXT => silo::sys_silo_event_next(arg1),
        SYS_SILO_SUSPEND => silo::sys_silo_suspend(arg1),
        SYS_SILO_RESUME => silo::sys_silo_resume(arg1),
        SYS_SILO_PLEDGE => silo::sys_silo_pledge(arg1),
        SYS_SILO_UNVEIL => silo::sys_silo_unveil(arg1, arg2, arg3),
        SYS_SILO_ENTER_SANDBOX => silo::sys_silo_enter_sandbox(),
        SYS_SILO_RENAME => silo::sys_silo_rename(arg1, arg2, arg3),

        // Architecture-specific (900-999) =========================================
        SYS_ABI_VERSION => {
            Ok(((strat9_abi::ABI_VERSION_MAJOR as u64) << 16)
                | (strat9_abi::ABI_VERSION_MINOR as u64))
        }
        _ => {
            log::warn!("Unknown syscall: {} (0x{:x})", syscall_num, syscall_num);
            Err(SyscallError::NotImplemented)
        }
    };
    //=============================================================================================================================

    match result {
        Ok(val) => {
            if syscall_num == SYS_PROC_FORK {
                crate::serial_println!("[syscall] FORK returning Ok({})", val);
            }
            frame.rax = val;
        }
        Err(e) => {
            if syscall_num == SYS_PROC_FORK {
                crate::serial_println!("[syscall] FORK returning err");
            }
            frame.rax = e.to_raw();
        }
    }

    // Fast signal-pending hint: check the per-CPU flag set by `send_signal`
    // when a signal targets the task currently running on this CPU. This
    // avoids the expensive scheduler lock + Arc::clone when no signal is
    // pending (the common case : +99.99% of syscalls).
    //
    // Cross-CPU signals (rare) are handled on the target's next syscall, or
    // by the explicit `has_pending_signals()` check in blocking syscalls.
    if crate::arch::percpu::test_and_clear_signal_pending_current() {
        crate::process::signal::deliver_pending_signal(frame);
    }

    frame.rax
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

/// SYS_HANDLE_CLOSE (2): Close a handle. Stub : always succeeds.
fn sys_handle_close(_handle: u64) -> Result<u64, SyscallError> {
    crate::silo::enforce_cap_for_current_task(_handle)?;
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let caps = unsafe { &mut *task.process.capabilities.get() };
    if let Some(cap) = caps.remove(CapId::from_raw(_handle)) {
        release_capability(&cap, Some(task.id));
        log::trace!("syscall: HANDLE_CLOSE({})", _handle);
        Ok(0)
    } else {
        Err(SyscallError::BadHandle)
    }
}

pub(crate) fn insert_capability_with_retention(
    caps: &mut crate::capability::CapabilityTable,
    cap: crate::capability::Capability,
) -> Result<CapId, SyscallError> {
    let id = caps.insert(cap);
    if let Some(inserted) = caps.get(id) {
        if inserted.resource_type == ResourceType::MemoryRegion {
            if let Err(error) =
                crate::memory::memory_region_registry().retain_handle(inserted.resource as u64, id)
            {
                let _ = caps.remove(id);
                return Err(match error {
                    crate::memory::RegionCapError::NotFound => SyscallError::BadHandle,
                    crate::memory::RegionCapError::InvalidRegion
                    | crate::memory::RegionCapError::IncompleteRegion
                    | crate::memory::RegionCapError::InvalidAddress => {
                        SyscallError::InvalidArgument
                    }
                    crate::memory::RegionCapError::PermissionDenied => {
                        SyscallError::PermissionDenied
                    }
                    crate::memory::RegionCapError::OutOfMemory => SyscallError::OutOfMemory,
                    crate::memory::RegionCapError::InconsistentState => SyscallError::IoError,
                });
            }
        }
    }
    Ok(id)
}

/// SYS_HANDLE_DUPLICATE (1): duplicate a handle (grant required).
fn sys_handle_duplicate(handle: u64) -> Result<u64, SyscallError> {
    crate::silo::enforce_cap_for_current_task(handle)?;
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let caps = unsafe { &mut *task.process.capabilities.get() };
    let dup = caps
        .duplicate(CapId::from_raw(handle))
        .ok_or(SyscallError::PermissionDenied)?;
    let id = insert_capability_with_retention(caps, dup)?;
    Ok(id.as_u64())
}

const HANDLE_EVENT_READABLE: u64 = 1 << 0;
const HANDLE_EVENT_WRITABLE: u64 = 1 << 1;

/// Performs the poll handle events operation.
fn poll_handle_events(handle: u64) -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let caps = unsafe { &*task.process.capabilities.get() };
    let cap = caps
        .get(CapId::from_raw(handle))
        .ok_or(SyscallError::BadHandle)?;

    match cap.resource_type {
        ResourceType::Semaphore => {
            if !cap.permissions.read {
                return Err(SyscallError::PermissionDenied);
            }
            let sem = semaphore::get_semaphore(SemId::from_u64(cap.resource as u64))
                .ok_or(SyscallError::BadHandle)?;
            if sem.is_destroyed() {
                return Err(SyscallError::Pipe);
            }
            if sem.count() > 0 {
                Ok(HANDLE_EVENT_READABLE)
            } else {
                Ok(0)
            }
        }
        ResourceType::IpcPort => {
            let port = port::get_port(PortId::from_u64(cap.resource as u64))
                .ok_or(SyscallError::BadHandle)?;
            if port.is_destroyed() {
                return Err(SyscallError::Pipe);
            }
            let mut events = 0u64;
            if cap.permissions.read && port.has_messages() {
                events |= HANDLE_EVENT_READABLE;
            }
            if cap.permissions.write && port.can_send() {
                events |= HANDLE_EVENT_WRITABLE;
            }
            if events == 0 && !cap.permissions.read && !cap.permissions.write {
                return Err(SyscallError::PermissionDenied);
            }
            Ok(events)
        }
        ResourceType::Channel => {
            let chan = channel::get_channel(ChanId::from_u64(cap.resource as u64))
                .ok_or(SyscallError::BadHandle)?;
            if chan.is_destroyed() {
                return Err(SyscallError::Pipe);
            }
            let mut events = 0u64;
            if cap.permissions.read && !chan.is_empty() {
                events |= HANDLE_EVENT_READABLE;
            }
            if cap.permissions.write && chan.can_send() {
                events |= HANDLE_EVENT_WRITABLE;
            }
            if events == 0 && !cap.permissions.read && !cap.permissions.write {
                return Err(SyscallError::PermissionDenied);
            }
            Ok(events)
        }
        ResourceType::SharedRing => {
            let _ = shared_ring::get_ring(RingId::from_u64(cap.resource as u64))
                .ok_or(SyscallError::BadHandle)?;
            let mut events = 0u64;
            if cap.permissions.read {
                events |= HANDLE_EVENT_READABLE;
            }
            if cap.permissions.write {
                events |= HANDLE_EVENT_WRITABLE;
            }
            if events == 0 {
                return Err(SyscallError::PermissionDenied);
            }
            Ok(events)
        }
        ResourceType::IpcTransport => {
            let tid = crate::ipc::transport::TransportId::from_u64(cap.resource as u64);
            let endpoint = crate::syscall::transport::TRANSPORT_MANAGER
                .get_endpoint(tid)
                .ok_or(SyscallError::BadHandle)?;
            let mut events = 0u64;
            if cap.permissions.read && endpoint.has_data() {
                events |= HANDLE_EVENT_READABLE;
            }
            if cap.permissions.write && endpoint.has_space() {
                events |= HANDLE_EVENT_WRITABLE;
            }
            if events == 0 && !cap.permissions.read && !cap.permissions.write {
                return Err(SyscallError::PermissionDenied);
            }
            Ok(events)
        }
        _ => Err(SyscallError::NotSupported),
    }
}

/// Performs the sys handle wait operation.
fn sys_handle_wait(handle: u64, timeout_ns: u64) -> Result<u64, SyscallError> {
    crate::silo::enforce_cap_for_current_task(handle)?;

    let check_ready = || -> Result<u64, SyscallError> {
        let events = poll_handle_events(handle)?;
        if events != 0 {
            Ok(events)
        } else {
            Err(SyscallError::Again)
        }
    };

    if timeout_ns == 0 {
        return check_ready();
    }

    let deadline = if timeout_ns == u64::MAX {
        None
    } else {
        Some(crate::syscall::time::current_time_ns().saturating_add(timeout_ns))
    };

    loop {
        if let Ok(events) = check_ready() {
            return Ok(events);
        }

        if crate::process::has_pending_signals() {
            return Err(SyscallError::Interrupted);
        }

        let now = crate::syscall::time::current_time_ns();
        let wake_ns = if let Some(deadline_ns) = deadline {
            if now >= deadline_ns {
                return Err(SyscallError::TimedOut);
            }
            core::cmp::min(deadline_ns, now.saturating_add(10_000_000))
        } else {
            now.saturating_add(10_000_000)
        };

        if let Some(task) = current_task_clone() {
            task.wake_deadline_ns.store(wake_ns, Ordering::Relaxed);
        }
        crate::process::block_current_task();
        if let Some(task) = current_task_clone() {
            task.wake_deadline_ns.store(0, Ordering::Relaxed);
        }
    }
}

/// Performs the sys handle grant operation.
fn sys_handle_grant(handle: u64, target_pid: u64) -> Result<u64, SyscallError> {
    crate::silo::enforce_cap_for_current_task(handle)?;
    crate::silo::enforce_silo_may_grant()?;
    let pid = u32::try_from(target_pid).map_err(|_| SyscallError::InvalidArgument)?;

    let source = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let granted = {
        let source_caps = unsafe { &*source.process.capabilities.get() };
        let cap = source_caps
            .get(CapId::from_raw(handle))
            .ok_or(SyscallError::BadHandle)?;
        if !cap.permissions.grant {
            return Err(SyscallError::PermissionDenied);
        }
        let mut dup = cap.clone();
        dup.id = CapId::new();
        dup
    };

    let target = crate::process::get_task_by_pid(pid).ok_or(SyscallError::NotFound)?;
    let target_caps = unsafe { &mut *target.process.capabilities.get() };
    let new_id = insert_capability_with_retention(target_caps, granted)?;
    Ok(new_id.as_u64())
}

/// Performs the sys handle revoke operation.
fn sys_handle_revoke(handle: u64) -> Result<u64, SyscallError> {
    crate::silo::enforce_cap_for_current_task(handle)?;
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let caps = unsafe { &mut *task.process.capabilities.get() };

    {
        let cap = caps
            .get(CapId::from_raw(handle))
            .ok_or(SyscallError::BadHandle)?;
        if !cap.permissions.revoke {
            return Err(SyscallError::PermissionDenied);
        }
    }

    let cap = caps
        .remove(CapId::from_raw(handle))
        .ok_or(SyscallError::BadHandle)?;
    release_capability(&cap, Some(task.id));
    Ok(0)
}

use strat9_abi::data::HandleInfo as HandleInfoAbi;

/// Performs the cap perm bits operation.
fn cap_perm_bits(p: CapPermissions) -> u32 {
    (if p.read { 1 } else { 0 })
        | (if p.write { 1 << 1 } else { 0 })
        | (if p.execute { 1 << 2 } else { 0 })
        | (if p.grant { 1 << 3 } else { 0 })
        | (if p.revoke { 1 << 4 } else { 0 })
}

/// Performs the resource type code operation.
fn resource_type_code(rt: ResourceType) -> u32 {
    match rt {
        ResourceType::MemoryRegion => 1,
        ResourceType::IoPortRange => 2,
        ResourceType::InterruptLine => 3,
        ResourceType::IpcPort => 4,
        ResourceType::Channel => 5,
        ResourceType::SharedRing => 6,
        ResourceType::Semaphore => 7,
        ResourceType::Device => 8,
        ResourceType::AddressSpace => 9,
        ResourceType::Silo => 10,
        ResourceType::Module => 11,
        ResourceType::File => 12,
        ResourceType::Nic => 13,
        ResourceType::FileSystem => 14,
        ResourceType::Console => 15,
        ResourceType::Keyboard => 16,
        ResourceType::Volume => 17,
        ResourceType::Namespace => 18,
        ResourceType::IpcTransport => 19,
    }
}

/// Performs the sys handle info operation.
fn sys_handle_info(handle: u64, out_ptr: u64) -> Result<u64, SyscallError> {
    crate::silo::enforce_cap_for_current_task(handle)?;
    if out_ptr == 0 {
        return Err(SyscallError::Fault);
    }
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let caps = unsafe { &*task.process.capabilities.get() };
    let cap = caps
        .get(CapId::from_raw(handle))
        .ok_or(SyscallError::BadHandle)?;

    let info = HandleInfoAbi {
        resource_type: resource_type_code(cap.resource_type),
        permissions: cap_perm_bits(cap.permissions),
        resource: cap.resource as u64,
    };
    let user = UserSliceWrite::new(out_ptr, core::mem::size_of::<HandleInfoAbi>())?;
    let bytes = unsafe {
        core::slice::from_raw_parts(
            &info as *const HandleInfoAbi as *const u8,
            core::mem::size_of::<HandleInfoAbi>(),
        )
    };
    user.copy_from(bytes);
    Ok(0)
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

    let blocked = &task.blocked_signals;

    if oldset_ptr != 0 {
        let old_mask = blocked.get_mask();
        let user = UserSliceWrite::new(oldset_ptr, 8)?;
        user.copy_from(&old_mask.to_ne_bytes());
    }

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

    Ok(0)
}

/// Performs the sys uname operation.
fn sys_uname(uts_ptr: u64) -> Result<u64, SyscallError> {
    const UTS_FIELD_LEN: usize = 65;
    const UTS_TOTAL_LEN: usize = UTS_FIELD_LEN * 6;

    if uts_ptr == 0 {
        return Err(SyscallError::Fault);
    }

    /// Writes field.
    fn write_field(dst: &mut [u8], src: &[u8]) {
        let n = core::cmp::min(src.len(), dst.len().saturating_sub(1));
        if n > 0 {
            dst[..n].copy_from_slice(&src[..n]);
        }
        dst[n] = 0;
    }

    let mut uts = [0u8; UTS_TOTAL_LEN];
    write_field(&mut uts[..UTS_FIELD_LEN], b"Strat9");
    write_field(&mut uts[1 * UTS_FIELD_LEN..2 * UTS_FIELD_LEN], b"localhost");
    write_field(&mut uts[2 * UTS_FIELD_LEN..3 * UTS_FIELD_LEN], b"0.1.0");
    write_field(&mut uts[3 * UTS_FIELD_LEN..4 * UTS_FIELD_LEN], b"Strat9-OS");
    write_field(&mut uts[4 * UTS_FIELD_LEN..5 * UTS_FIELD_LEN], b"x86_64");
    write_field(
        &mut uts[5 * UTS_FIELD_LEN..6 * UTS_FIELD_LEN],
        b"localdomain",
    );

    let user = UserSliceWrite::new(uts_ptr, UTS_TOTAL_LEN)?;
    user.copy_from(&uts);
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
