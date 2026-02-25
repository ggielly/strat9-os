//! Strat9-OS ABI syscall number constants.
//!
//! Organized in blocks of 100 per the ABI spec in `docs/ABI_STRAT9-OS_DESIGN.md`.

// ============================================================
// Block 0-99: capabilities / handle management
// ============================================================

/// Null syscall — ping/test. Returns magic 0x57A79 ("STRAT9").
pub const SYS_NULL: u64 = 0;

/// Duplicate a handle (grant permission required).
pub const SYS_HANDLE_DUPLICATE: u64 = 1;

/// Close a handle.
pub const SYS_HANDLE_CLOSE: u64 = 2;

/// Wait on a handle for an event.
pub const SYS_HANDLE_WAIT: u64 = 3;

// ============================================================
// Block 100-199: memory management
// ============================================================

/// Map anonymous virtual memory.
/// arg1=addr, arg2=len, arg3=prot, arg4=flags, arg5=fd, arg6=offset
pub const SYS_MMAP: u64 = 100;

/// Unmap a virtual memory range.
/// arg1=addr, arg2=len
pub const SYS_MUNMAP: u64 = 101;

/// Set the program break (heap top).
/// arg1=addr (0 = query). Returns new break on success, unchanged break on failure.
pub const SYS_BRK: u64 = 102;

/// Remap a virtual memory region (reserved — not yet implemented).
pub const SYS_MREMAP: u64 = 103;

/// Change protection of a virtual memory region (reserved — not yet implemented).
pub const SYS_MPROTECT: u64 = 104;

// ============================================================
// Block 200-299: IPC
// ============================================================

/// Create an IPC port. arg1 = flags. Returns port handle.
pub const SYS_IPC_CREATE_PORT: u64 = 200;

/// Send a message to port. arg1 = port handle, arg2 = msg_ptr (64 bytes).
/// Blocks if the port queue is full.
pub const SYS_IPC_SEND: u64 = 201;

/// Receive a message from port. arg1 = port handle, arg2 = msg_ptr (64 bytes out).
/// Blocks if the port queue is empty.
pub const SYS_IPC_RECV: u64 = 202;

/// Call (send+recv). arg1 = port handle, arg2 = msg_ptr
pub const SYS_IPC_CALL: u64 = 203;

/// Reply to an IPC call. arg1 = msg_ptr
pub const SYS_IPC_REPLY: u64 = 204;

/// Bind a port to namespace. arg1 = port handle, arg2 = path_ptr, arg3 = path_len
pub const SYS_IPC_BIND_PORT: u64 = 205;

/// Unbind a namespace path. arg1 = path_ptr, arg2 = path_len
pub const SYS_IPC_UNBIND_PORT: u64 = 206;

/// Try to receive a message from port without blocking.
/// arg1 = port handle, arg2 = msg_ptr (64 bytes out).
/// Returns 0 on success, negative error if empty or invalid.
pub const SYS_IPC_TRY_RECV: u64 = 207;

/// Create a shared ring buffer. arg1 = size
pub const SYS_IPC_RING_CREATE: u64 = 210;

/// Map a ring buffer. arg1 = ring handle, arg2 = out_ptr
pub const SYS_IPC_RING_MAP: u64 = 211;

/// create a typed sync-channel.
/// arg1 = capacity (number of IpcMessages). Returns channel handle.
pub const SYS_CHAN_CREATE: u64 = 220;

/// Send a message to a channel, blocking if full.
/// arg1 = channel handle, arg2 = msg_ptr (64 bytes).
pub const SYS_CHAN_SEND: u64 = 221;

/// Receive a message from a channel, blocking if empty.
/// arg1 = channel handle, arg2 = msg_ptr (64 bytes out).
pub const SYS_CHAN_RECV: u64 = 222;

/// Try to receive without blocking.
/// arg1 = channel handle, arg2 = msg_ptr. Returns 0 ok, -EWOULDBLOCK if empty.
pub const SYS_CHAN_TRY_RECV: u64 = 223;

/// Close / destroy a channel handle.
/// arg1 = channel handle.
pub const SYS_CHAN_CLOSE: u64 = 224;

// ============================================================
// Block 300-399: process / thread
// ============================================================

/// Exit the current task. arg1 = exit code.
pub const SYS_PROC_EXIT: u64 = 300;

/// Yield the current time slice.
pub const SYS_PROC_YIELD: u64 = 301;

/// Fork the current process (COW). Returns child PID in parent, 0 in child.
pub const SYS_PROC_FORK: u64 = 302;

/// Return current process ID (pid).
pub const SYS_PROC_GETPID: u64 = 308;

/// Return parent process ID (pid), or 0 if none.
pub const SYS_PROC_GETPPID: u64 = 309;

/// Wait for a child to change state (currently: exit only).
/// arg1=pid (-1 any child), arg2=status_ptr (nullable), arg3=options (WNOHANG=1 supported)
pub const SYS_PROC_WAITPID: u64 = 310;

/// Return current process ID (getpid).
pub const SYS_GETPID: u64 = 311;

/// Return current thread ID (gettid).
pub const SYS_GETTID: u64 = 312;

/// Return parent process ID (getppid).
pub const SYS_GETPPID: u64 = 313;

/// Plan 9-style wait: block until any child exits, write Waitmsg.
/// arg1=waitmsg_ptr (*Waitmsg, 80 bytes, nullable). Returns child pid.
pub const SYS_PROC_WAIT: u64 = 314;

/// Execute a new program.
/// arg1=path_ptr, arg2=argv_ptr, arg3=envp_ptr
pub const SYS_PROC_EXECVE: u64 = 315;

/// Manipulate file descriptor (fcntl).
pub const SYS_FCNTL: u64 = 316;

/// Set process group id. arg1=pid (0=self), arg2=pgid (0=pid).
pub const SYS_SETPGID: u64 = 317;

/// Get process group id. arg1=pid (0=self).
pub const SYS_GETPGID: u64 = 318;

/// Create a new session (setsid). Returns new sid (caller pid).
pub const SYS_SETSID: u64 = 319;

// Futex wait. arg1=uaddr (*u32), arg2=expected_val, arg3=timeout_ns
pub const SYS_FUTEX_WAIT: u64 = 303;

// Futex wake. arg1=uaddr (*u32), arg2=max_wakers
pub const SYS_FUTEX_WAKE: u64 = 304;

// Futex requeue. arg1=uaddr1, arg2=max_wake, arg3=max_requeue, arg4=uaddr2
pub const SYS_FUTEX_REQUEUE: u64 = 305;

// Futex cmp_requeue. arg1=uaddr1, arg2=max_wake, arg3=max_requeue, arg4=uaddr2, arg5=expected_val
pub const SYS_FUTEX_CMP_REQUEUE: u64 = 306;

// Futex wake_op. arg1=uaddr1, arg2=max_wake1, arg3=max_wake2, arg4=uaddr2, arg5=op
pub const SYS_FUTEX_WAKE_OP: u64 = 307;

// ============================================================
// Block 320-329: signal handling
// ============================================================

/// Send a signal with POSIX kill semantics. arg1=pid, arg2=signal_number
pub const SYS_KILL: u64 = 320;

/// Examine and change blocked signals. arg1=how, arg2=set_ptr, arg3=oldset_ptr
pub const SYS_SIGPROCMASK: u64 = 321;

/// Set up a signal handler. arg1=signum, arg2=act_ptr, arg3=oact_ptr
pub const SYS_SIGACTION: u64 = 322;

/// Set/get signal alternate stack. arg1=ss_ptr, arg2=old_ss_ptr
pub const SYS_SIGALTSTACK: u64 = 323;

/// Check for pending signals. arg1=set_ptr
pub const SYS_SIGPENDING: u64 = 324;

/// Wait for signals. arg1=mask_ptr
pub const SYS_SIGSUSPEND: u64 = 325;

/// Wait for signals with timeout. arg1=set_ptr, arg2=siginfo_ptr, arg3=timeout_ptr
pub const SYS_SIGTIMEDWAIT: u64 = 326;

/// Send signal with value. arg1=task_id, arg2=signum, arg3=sigval_ptr
pub const SYS_SIGQUEUE: u64 = 327;

/// Send signal to process group. arg1=pgrp, arg2=signum
pub const SYS_KILLPG: u64 = 328;

/// Get interval timer value. arg1=which, arg2=value_ptr
pub const SYS_GETITIMER: u64 = 329;

/// Set interval timer value. arg1=which, arg2=new_value_ptr, arg3=old_value_ptr
pub const SYS_SETITIMER: u64 = 330;

/// Get process group id of current process (getpgrp).
pub const SYS_GETPGRP: u64 = 331;

/// Get session id. arg1=pid (0=self).
pub const SYS_GETSID: u64 = 332;

/// Set TID address for futex-based thread join (pthread).
/// arg1 = tidptr (*u32). Kernel writes 0 there on thread exit, then futex_wake.
/// Returns current TID.
pub const SYS_SET_TID_ADDRESS: u64 = 333;

/// Exit all threads in the thread group (C library _exit / exit_group).
/// arg1 = exit_code.
pub const SYS_EXIT_GROUP: u64 = 334;

/// Return real user id.
pub const SYS_GETUID: u64 = 335;

/// Return effective user id.
pub const SYS_GETEUID: u64 = 336;

/// Return real group id.
pub const SYS_GETGID: u64 = 337;

/// Return effective group id.
pub const SYS_GETEGID: u64 = 338;

/// Set real user id. arg1 = uid.
pub const SYS_SETUID: u64 = 339;

/// Set real group id. arg1 = gid.
pub const SYS_SETGID: u64 = 340;

/// Architecture-specific process info (x86_64: FS/GS base).
/// arg1 = code (ARCH_SET_FS=0x1002, ARCH_GET_FS=0x1003, etc.), arg2 = addr.
pub const SYS_ARCH_PRCTL: u64 = 350;

/// Send signal to a specific thread in a thread group.
/// arg1 = tgid, arg2 = tid, arg3 = signal_number.
pub const SYS_TGKILL: u64 = 352;

// ============================================================
// Block 400-499: filesystem / VFS
// ============================================================

/// Open a path. arg1=path_ptr, arg2=path_len, arg3=flags
pub const SYS_OPEN: u64 = 403;

/// Read bytes from a handle (fd). arg1=fd, arg2=buf_ptr, arg3=buf_len.
pub const SYS_READ: u64 = 405;

/// Write bytes to a handle (fd). arg1=fd, arg2=buf_ptr, arg3=buf_len.
/// For now, fd=1 (stdout) and fd=2 (stderr) write to serial.
pub const SYS_WRITE: u64 = 404;

/// Close a handle (fd). arg1=fd.
pub const SYS_CLOSE: u64 = 406;

/// Seek in a file. arg1=fd, arg2=offset(i64), arg3=whence (0=SET,1=CUR,2=END).
pub const SYS_LSEEK: u64 = 407;

/// Get metadata of an open file. arg1=fd, arg2=stat_ptr.
pub const SYS_FSTAT: u64 = 408;

/// Get metadata by path. arg1=path_ptr, arg2=path_len, arg3=stat_ptr.
pub const SYS_STAT: u64 = 409;

/// Read directory entries. arg1=fd, arg2=buf_ptr, arg3=buf_len.
pub const SYS_GETDENTS: u64 = 430;

/// Create a pipe. arg1=fds_ptr (writes [read_fd, write_fd] to user).
pub const SYS_PIPE: u64 = 431;

/// Duplicate a file descriptor. arg1=old_fd. Returns new fd.
pub const SYS_DUP: u64 = 432;

/// Duplicate a file descriptor to a specific number. arg1=old_fd, arg2=new_fd.
pub const SYS_DUP2: u64 = 433;

/// Change current working directory. arg1=path_ptr, arg2=path_len.
pub const SYS_CHDIR: u64 = 440;

/// Change current working directory (fd variant). arg1=fd.
pub const SYS_FCHDIR: u64 = 441;

/// Get current working directory. arg1=buf_ptr, arg2=buf_len. Returns bytes written.
pub const SYS_GETCWD: u64 = 442;

/// I/O control. arg1=fd, arg2=request, arg3=arg.
pub const SYS_IOCTL: u64 = 443;

/// Set and get file creation mask. arg1=mask. Returns old mask.
pub const SYS_UMASK: u64 = 444;

/// Remove a file. arg1=path_ptr, arg2=path_len.
pub const SYS_UNLINK: u64 = 445;

/// Remove a directory. arg1=path_ptr, arg2=path_len.
pub const SYS_RMDIR: u64 = 446;

/// Create directory. arg1=path_ptr, arg2=path_len, arg3=mode.
pub const SYS_MKDIR: u64 = 447;

/// Rename a file. arg1=old_ptr, arg2=old_len, arg3=new_ptr, arg4=new_len.
pub const SYS_RENAME: u64 = 448;

/// Create a hard link. arg1=old_ptr, arg2=old_len, arg3=new_ptr, arg4=new_len.
pub const SYS_LINK: u64 = 449;

/// Create a symbolic link. arg1=target_ptr, arg2=target_len, arg3=linkpath_ptr, arg4=linkpath_len.
pub const SYS_SYMLINK: u64 = 450;

/// Read a symbolic link. arg1=path_ptr, arg2=path_len, arg3=buf_ptr, arg4=buf_len.
pub const SYS_READLINK: u64 = 451;

/// Change file permissions. arg1=path_ptr, arg2=path_len, arg3=mode.
pub const SYS_CHMOD: u64 = 452;

/// Change file permissions on open fd. arg1=fd, arg2=mode.
pub const SYS_FCHMOD: u64 = 453;

/// Truncate file to length. arg1=path_ptr, arg2=path_len, arg3=length.
pub const SYS_TRUNCATE: u64 = 454;

/// Truncate open fd to length. arg1=fd, arg2=length.
pub const SYS_FTRUNCATE: u64 = 455;

// ============================================================
// Block 410-419: network
// ============================================================

/// Receive a network packet. arg1=buf_ptr, arg2=buf_len.
pub const SYS_NET_RECV: u64 = 410;

/// Send a network packet. arg1=buf_ptr, arg2=buf_len.
pub const SYS_NET_SEND: u64 = 411;
pub const SYS_NET_INFO: u64 = 412;

// ============================================================
// Block 420-429: volumes / block devices
// ============================================================

/// Read sectors from a volume. arg1=handle, arg2=sector, arg3=buf_ptr, arg4=sector_count
pub const SYS_VOLUME_READ: u64 = 420;

/// Write sectors to a volume. arg1=handle, arg2=sector, arg3=buf_ptr, arg4=sector_count
pub const SYS_VOLUME_WRITE: u64 = 421;

/// Query volume size (sector count). arg1=handle
pub const SYS_VOLUME_INFO: u64 = 422;

// ============================================================
// Block 500-599: time / alarms
// ============================================================

/// Get current monotonic tick count. Returns tick count in rax.
pub const SYS_CLOCK_GETTIME: u64 = 500;

/// Sleep for a specified duration. arg1=timespec_ptr (request), arg2=timespec_ptr (remain, optional)
/// Returns 0 on success, -EINTR if interrupted by signal.
pub const SYS_NANOSLEEP: u64 = 501;

// ============================================================
// Block 600-699: debug / profiling
// ============================================================

/// Debug log: write bytes to serial. arg1=buf_ptr, arg2=buf_len.
pub const SYS_DEBUG_LOG: u64 = 600;

// ============================================================
// Block 700-799: module management (.cmod)
// ============================================================

/// Load a module (.cmod). arg1 = fd (open file handle)
pub const SYS_MODULE_LOAD: u64 = 700;

/// Unload a module. arg1 = module handle
pub const SYS_MODULE_UNLOAD: u64 = 701;

/// Resolve a module export. arg1 = module handle, arg2 = ordinal
pub const SYS_MODULE_GET_SYMBOL: u64 = 702;

/// Query module info. arg1 = module handle, arg2 = *ModuleInfo
pub const SYS_MODULE_QUERY: u64 = 703;

// ============================================================
// Block 800-899:  silo manager
// ============================================================

/// Create a new silo. arg1 = flags
pub const SYS_SILO_CREATE: u64 = 800;

/// Configure resources. arg1 = silo handle, arg2 = *SiloConfig
pub const SYS_SILO_CONFIG: u64 = 801;

/// Attach module as entry point. arg1 = silo handle, arg2 = module handle
pub const SYS_SILO_ATTACH_MODULE: u64 = 802;

/// Start a silo. arg1 = silo handle
pub const SYS_SILO_START: u64 = 803;

/// Stop a silo. arg1 = silo handle
pub const SYS_SILO_STOP: u64 = 804;

/// Kill a silo. arg1 = silo handle
pub const SYS_SILO_KILL: u64 = 805;

/// Read next silo event. arg1 = *SiloEvent
pub const SYS_SILO_EVENT_NEXT: u64 = 806;

/// Suspend a silo. arg1 = silo handle
pub const SYS_SILO_SUSPEND: u64 = 807;

/// Resume a silo. arg1 = silo handle
pub const SYS_SILO_RESUME: u64 = 808;
