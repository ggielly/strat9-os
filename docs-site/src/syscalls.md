# Syscall Reference

Complete reference for all Strat9 OS syscalls. Syscalls are invoked via the `syscall` instruction (x86_64). Arguments are passed in registers; the return value is in RAX.

**ABI convention:** Success returns a non-negative value. Errors return a negative errno value (two's complement). Userspace checks `if result > 0xFFFF_F000` to detect errors, then applies `!result + 1` to get the errno number.

---

## Handle operations

| # | Syscall | Parameters | Return | Description |
|---|---------|-----------|--------|-------------|
| 0 | `SYS_NULL` | : | 0 | No-op (used for benchmarking) |
| 1 | `SYS_HANDLE_DUPLICATE` | `handle: u64` | new handle | Duplicate a capability handle |
| 2 | `SYS_HANDLE_CLOSE` | `handle: u64` | 0 | Close a capability handle |
| 3 | `SYS_HANDLE_WAIT` | `handle: u64, timeout_ns: u64` | 0 | Wait on a handle (blocks until ready or timeout) |
| 4 | `SYS_HANDLE_GRANT` | `handle: u64, target_pid: u64` | 0 | Grant a capability to another process |
| 5 | `SYS_HANDLE_REVOKE` | `handle: u64` | 0 | Revoke a capability (all holders lose access) |
| 6 | `SYS_HANDLE_INFO` | `handle: u64, out_ptr: u64` | 0 | Query capability info (writes `HandleInfo` struct) |

**Errors:** `EBADF` (invalid handle), `EPERM` (no grant permission), `ESRCH` (target process not found)

---

## Memory management

| # | Syscall | Parameters | Return | Description |
|---|---------|-----------|--------|-------------|
| 100 | `SYS_MMAP` | `addr: u64, len: u64, prot: u64, flags: u64, fd: u64, offset: u64` | mapped address | Map a memory region |
| 101 | `SYS_MUNMAP` | `addr: u64, len: u64` | 0 | Unmap a memory region |
| 102 | `SYS_BRK` | `addr: u64` | new break | Set/clear the data break |
| 103 | `SYS_MREMAP` | `old_addr: u64, old_len: u64, new_len: u64, flags: u64, new_addr: u64` | new address | Remap a memory region |
| 104 | `SYS_MPROTECT` | `addr: u64, len: u64, prot: u64` | 0 | Change memory protection flags |
| 105 | `SYS_MEM_REGION_EXPORT` | `addr: u64, len: u64` | region handle | Export a memory region as a shareable handle |
| 106 | `SYS_MEM_REGION_MAP` | `region_handle: u64, addr: u64, len: u64` | mapped address | Map an exported memory region |
| 107 | `SYS_MEM_REGION_INFO` | `region_handle: u64, out_ptr: u64` | 0 | Query region metadata |

**Prot flags:** `PROT_READ (1)`, `PROT_WRITE (2)`, `PROT_EXEC (4)`

**Errors:** `EINVAL` (bad alignment/flags), `ENOMEM` (out of memory), `EACCES` (permission denied), `EEXIST` (region already mapped)

---

## IPC : Ports

| # | Syscall | Parameters | Return | Description |
|---|---------|-----------|--------|-------------|
| 200 | `SYS_IPC_CREATE_PORT` | : | port handle | Create a new IPC port |
| 201 | `SYS_IPC_SEND` | `port_handle: u64, msg_ptr: u64, msg_len: u64` | 0 | Send a message to a port |
| 202 | `SYS_IPC_RECV` | `port_handle: u64, buf_ptr: u64, buf_len: u64` | bytes received | Receive a message (blocks) |
| 203 | `SYS_IPC_CALL` | `port_handle: u64, msg_ptr: u64, msg_len: u64` | bytes received | Synchronous RPC (send + wait for reply) |
| 204 | `SYS_IPC_REPLY` | `msg_ptr: u64, msg_len: u64` | 0 | Reply to the current IPC call |
| 205 | `SYS_IPC_BIND_PORT` | `port_handle: u64` | 0 | Bind a port as a listener |
| 206 | `SYS_IPC_UNBIND_PORT` | `port_handle: u64` | 0 | Unbind a listening port |
| 207 | `SYS_IPC_TRY_RECV` | `port_handle: u64, buf_ptr: u64, buf_len: u64` | bytes received (0 if empty) | Non-blocking receive |
| 208 | `SYS_IPC_CONNECT` | `port_handle: u64` | 0 | Connect to a bound port |
| 210 | `SYS_IPC_RING_CREATE` | `size_log2: u64` | ring handle | Create a shared ring buffer |
| 211 | `SYS_IPC_RING_MAP` | `ring_handle: u64, addr: u64` | 0 | Map a shared ring into address space |

**Errors:** `EBADF` (invalid handle), `ENOSPC` (ring full), `EAGAIN` (non-blocking, nothing available), `ETIMEDOUT` (timeout exceeded)

---

## IPC : Channels (typed MPMC)

| # | Syscall | Parameters | Return | Description |
|---|---------|-----------|--------|-------------|
| 220 | `SYS_CHAN_CREATE` | `capacity: u64` | channel handle | Create a typed channel |
| 221 | `SYS_CHAN_SEND` | `handle: u64, msg_ptr: u64` | 0 | Send a message (blocks if full) |
| 222 | `SYS_CHAN_RECV` | `handle: u64, msg_ptr: u64` | 0 | Receive a message (blocks if empty) |
| 223 | `SYS_CHAN_TRY_RECV` | `handle: u64, msg_ptr: u64` | 1 if received, 0 if empty | Non-blocking receive |
| 224 | `SYS_CHAN_CLOSE` | `handle: u64` | 0 | Close channel handle |

**Errors:** `EBADF` (invalid handle), `EPIPE` (all endpoints disconnected), `EAGAIN` (try_recv on empty channel)

---

## IPC : Semaphores

| # | Syscall | Parameters | Return | Description |
|---|---------|-----------|--------|-------------|
| 230 | `SYS_SEM_CREATE` | `initial_value: u64` | semaphore handle | Create a counting semaphore |
| 231 | `SYS_SEM_WAIT` | `handle: u64` | 0 | Decrement (blocks if zero) |
| 232 | `SYS_SEM_TRYWAIT` | `handle: u64` | 1 if acquired, 0 if would block | Non-blocking decrement |
| 233 | `SYS_SEM_POST` | `handle: u64` | 0 | Increment (wake a waiter) |
| 234 | `SYS_SEM_CLOSE` | `handle: u64` | 0 | Close semaphore handle |

**Errors:** `EBADF` (invalid handle), `EAGAIN` (try_wait on zero semaphore)

---

## PCI

| # | Syscall | Parameters | Return | Description |
|---|---------|-----------|--------|-------------|
| 240 | `SYS_PCI_ENUM` | `criteria_ptr: u64, out_ptr: u64, max_count: u64` | device count | Enumerate PCI devices matching criteria |
| 241 | `SYS_PCI_CFG_READ` | `addr_ptr: u64, offset: u64, width: u64` | config value | Read PCI configuration register |
| 242 | `SYS_PCI_CFG_WRITE` | `addr_ptr: u64, offset: u64, width: u64, value: u64` | 0 | Write PCI configuration register |

**Errors:** `EINVAL` (invalid width/offset), `EACCES` (no PCI capability)

---

## Async I/O

| # | Syscall | Parameters | Return | Description |
|---|---------|-----------|--------|-------------|
| 250 | `SYS_ASYNC_SETUP` | `handle: u64, event_mask: u64` | async context | Set up async notification on a handle |
| 251 | `SYS_ASYNC_ENTER` | `ctx: u64` | 0 | Enter async wait (yields until event) |
| 252 | `SYS_ASYNC_CANCEL` | `ctx: u64` | 0 | Cancel pending async wait |
| 253 | `SYS_ASYNC_MAP` | `ctx: u64, ring_handle: u64` | 0 | Map an event ring to the async context |
| 254 | `SYS_ASYNC_DESTROY` | `ctx: u64` | 0 | Destroy async context |

---

## Process management

| # | Syscall | Parameters | Return | Description |
|---|---------|-----------|--------|-------------|
| 300 | `SYS_PROC_EXIT` | `exit_code: u64` | : (never returns) | Terminate current process |
| 301 | `SYS_PROC_YIELD` | : | 0 | Yield CPU to scheduler |
| 302 | `SYS_PROC_FORK` | `frame: &SyscallFrame` | child PID (parent), 0 (child) | Fork the current process (COW) |
| 308 | `SYS_PROC_GETPID` | : | process ID | Get current process ID |
| 309 | `SYS_PROC_GETPPID` | : | parent PID | Get parent process ID |
| 310 | `SYS_PROC_WAITPID` | `pid: i64, status_ptr: u64, options: u64` | child PID | Wait for a child process |
| 311 | `SYS_GETPID` | : | process ID | Alias for SYS_PROC_GETPID |
| 312 | `SYS_GETTID` | : | thread ID | Get current thread ID |
| 314 | `SYS_PROC_WAIT` | : | : | Wait for any child |
| 315 | `SYS_PROC_EXECVE` | `path_ptr: u64, path_len: u64, argv_ptr: u64, envp_ptr: u64` | : (replaces image) | Execute a new program |
| 341 | `SYS_THREAD_CREATE` | `entry: u64, stack: u64, arg: u64` | thread ID | Create a new thread |
| 342 | `SYS_THREAD_JOIN` | `tid: u64, status_ptr: u64` | 0 | Wait for thread to exit |
| 343 | `SYS_THREAD_EXIT` | `status: u64` | : (never returns) | Terminate current thread |

**Errors:** `ECHILD` (no child processes), `EAGAIN` (thread creation failed), `ENOMEM` (out of memory)

---

## Futex

| # | Syscall | Parameters | Return | Description |
|---|---------|-----------|--------|-------------|
| 303 | `SYS_FUTEX_WAIT` | `addr: u64, val: u32, timeout_ns: u64` | 0 | Sleep if `*addr == val` |
| 304 | `SYS_FUTEX_WAKE` | `addr: u64, max_wake: u32` | woken count | Wake up to N waiters |
| 305 | `SYS_FUTEX_REQUEUE` | `addr: u64, max_wake: u32, addr2: u64, max_requeue: u32` | woken count | Wake + requeue to addr2 |
| 306 | `SYS_FUTEX_CMP_REQUEUE` | `addr: u64, max_wake: u32, addr2: u64, max_requeue: u32, cmp_val: u32` | woken count | Conditional requeue |
| 307 | `SYS_FUTEX_WAKE_OP` | `addr: u64, max_wake: u32, addr2: u64, max_requeue: u32, wake_op: u32` | woken count | Atomic op + wake |

**Errors:** `EAGAIN` (value mismatch in WAIT), `ETIMEDOUT` (timeout expired), `EFAULT` (invalid address)

---

## Signals

| # | Syscall | Parameters | Return | Description |
|---|---------|-----------|--------|-------------|
| 320 | `SYS_KILL` | `pid: i64, signum: u32` | 0 | Send signal to a process |
| 321 | `SYS_SIGPROCMASK` | `how: i32, set_ptr: u64, oldset_ptr: u64` | 0 | Get/set signal mask |
| 322 | `SYS_SIGACTION` | `signum: u64, act_ptr: u64, oact_ptr: u64` | 0 | Set signal handler |
| 323 | `SYS_SIGALTSTACK` | `ss_ptr: u64, old_ss_ptr: u64` | 0 | Set alternate signal stack |
| 324 | `SYS_SIGPENDING` | `set_ptr: u64` | 0 | Get pending signals |
| 325 | `SYS_SIGSUSPEND` | `mask_ptr: u64` | : (restarted on signal) | Suspend until signal |
| 326 | `SYS_SIGTIMEDWAIT` | `set_ptr: u64, info_ptr: u64, timeout_ptr: u64` | signal number | Wait for specific signal |
| 327 | `SYS_SIGQUEUE` | `pid: i64, signum: u32, sigval_ptr: u64` | 0 | Queue a signal with data |
| 328 | `SYS_KILLPG` | `pgrp: u64, signum: u32` | 0 | Send signal to process group |
| 352 | `SYS_TGKILL` | `tgid: u64, tid: u64, signum: u32` | 0 | Send signal to specific thread |
| 353 | `SYS_RT_SIGRETURN` | : | : | Return from signal handler |

---

## Process groups & sessions

| # | Syscall | Parameters | Return | Description |
|---|---------|-----------|--------|-------------|
| 316 | `SYS_FCNTL` | `fd: u64, cmd: u64, arg: u64` | depends on cmd | File control operations |
| 317 | `SYS_SETPGID` | `pid: u64, pgid: u64` | 0 | Set process group ID |
| 318 | `SYS_GETPGID` | `pid: u64` | pgid | Get process group ID |
| 319 | `SYS_SETSID` | : | session ID | Create new session |
| 329 | `SYS_GETITIMER` | `which: u64, out_ptr: u64` | 0 | Get interval timer |
| 330 | `SYS_SETITIMER` | `which: u64, in_ptr: u64, out_ptr: u64` | 0 | Set interval timer |
| 331 | `SYS_GETPGRP` | : | pgrp | Get current process group |
| 332 | `SYS_GETSID` | `pid: u64` | sid | Get session ID |
| 333 | `SYS_SET_TID_ADDRESS` | `tidptr: u64` | 0 | Set clear-on-exit TID address |
| 334 | `SYS_EXIT_GROUP` | `exit_code: u64` | : (never returns) | Exit all threads in process |

---

## User/group IDs

| # | Syscall | Parameters | Return | Description |
|---|---------|-----------|--------|-------------|
| 335 | `SYS_GETUID` | : | uid | Get real user ID |
| 336 | `SYS_GETEUID` | : | euid | Get effective user ID |
| 337 | `SYS_GETGID` | : | gid | Get real group ID |
| 338 | `SYS_GETEGID` | : | egid | Get effective group ID |
| 339 | `SYS_SETUID` | `uid: u64` | 0 | Set user ID |
| 340 | `SYS_SETGID` | `gid: u64` | 0 | Set group ID |

---

## Misc process

| # | Syscall | Parameters | Return | Description |
|---|---------|-----------|--------|-------------|
| 344 | `SYS_UNAME` | `uts_ptr: u64` | 0 | Get system information (name, release, etc.) |
| 350 | `SYS_ARCH_PRCTL` | `code: u64, addr: u64` | 0 | Architecture-specific process control |

---

## File I/O

| # | Syscall | Parameters | Return | Description |
|---|---------|-----------|--------|-------------|
| 403 | `SYS_OPEN` | `path_ptr: u64, path_len: u64, flags: u64` | file descriptor | Open a file |
| 404 | `SYS_WRITE` | `fd: u64, buf_ptr: u64, buf_len: u64` | bytes written | Write to a file descriptor |
| 405 | `SYS_READ` | `fd: u64, buf_ptr: u64, buf_len: u64` | bytes read | Read from a file descriptor |
| 406 | `SYS_CLOSE` | `fd: u64` | 0 | Close a file descriptor |
| 407 | `SYS_LSEEK` | `fd: u64, offset: u64, whence: u64` | new position | Seek in a file |
| 408 | `SYS_FSTAT` | `fd: u64, stat_ptr: u64` | 0 | Get file status (fstat) |
| 409 | `SYS_STAT` | `path_ptr: u64, path_len: u64, stat_ptr: u64` | 0 | Get file status by path |
| 413 | `SYS_ACCESS` | `path_ptr: u64, path_len: u64, mode: u64` | 0 | Check file accessibility |
| 430 | `SYS_GETDENTS` | `fd: u64, buf_ptr: u64, buf_len: u64` | bytes read | Read directory entries |
| 431 | `SYS_PIPE` | `fds_ptr: u64` | 0 | Create a pipe pair |
| 432 | `SYS_DUP` | `old_fd: u64` | new fd | Duplicate file descriptor |
| 433 | `SYS_DUP2` | `old_fd: u64, new_fd: u64` | new fd | Duplicate to specific fd |
| 456 | `SYS_PREAD` | `fd: u64, buf_ptr: u64, buf_len: u64, offset: u64` | bytes read | Pread at offset |
| 457 | `SYS_PWRITE` | `fd: u64, buf_ptr: u64, buf_len: u64, offset: u64` | bytes written | Pwrite at offset |

**Open flags:** `O_RDONLY (0)`, `O_WRONLY (1)`, `O_RDWR (2)`, `O_CREAT (0x40)`, `O_TRUNC (0x200)`, `O_APPEND (0x400)`, `O_EXCL (0x800)`

**Errors:** `ENOENT` (file not found), `EACCES` (permission denied), `EBADF` (bad fd), `ENOTDIR` (not a directory), `EISDIR` (is a directory), `ENOSPC` (disk full), `EIO` (I/O error)

---

## File system operations

| # | Syscall | Parameters | Return | Description |
|---|---------|-----------|--------|-------------|
| 440 | `SYS_CHDIR` | `path_ptr: u64, path_len: u64` | 0 | Change working directory |
| 441 | `SYS_FCHDIR` | `fd: u64` | 0 | Change working directory by fd |
| 442 | `SYS_GETCWD` | `buf_ptr: u64, buf_len: u64` | bytes written | Get current working directory |
| 443 | `SYS_IOCTL` | `fd: u64, cmd: u64, arg: u64` | depends on cmd | Device I/O control |
| 444 | `SYS_UMASK` | `mask: u64` | old mask | Set file mode creation mask |
| 445 | `SYS_UNLINK` | `path_ptr: u64, path_len: u64` | 0 | Delete a file |
| 446 | `SYS_RMDIR` | `path_ptr: u64, path_len: u64` | 0 | Remove a directory |
| 447 | `SYS_MKDIR` | `path_ptr: u64, path_len: u64, mode: u64` | 0 | Create a directory |
| 448 | `SYS_RENAME` | `old_ptr: u64, old_len: u64, new_ptr: u64, new_len: u64` | 0 | Rename a file |
| 449 | `SYS_LINK` | `old_ptr: u64, old_len: u64, new_ptr: u64, new_len: u64` | 0 | Create a hard link |
| 450 | `SYS_SYMLINK` | `target_ptr: u64, target_len: u64, link_ptr: u64, link_len: u64` | 0 | Create a symbolic link |
| 451 | `SYS_READLINK` | `path_ptr: u64, path_len: u64, buf_ptr: u64, buf_len: u64` | bytes read | Read symbolic link target |
| 452 | `SYS_CHMOD` | `path_ptr: u64, path_len: u64, mode: u64` | 0 | Change file permissions |
| 453 | `SYS_FCHMOD` | `fd: u64, mode: u64` | 0 | Change file permissions by fd |
| 454 | `SYS_TRUNCATE` | `path_ptr: u64, path_len: u64, len: u64` | 0 | Truncate a file |
| 455 | `SYS_FTRUNCATE` | `fd: u64, len: u64` | 0 | Truncate a file by fd |

---

## `*at` variants (relative to directory fd)

| # | Syscall | Parameters | Return | Description |
|---|---------|-----------|--------|-------------|
| 462 | `SYS_OPENAT` | `dirfd: u64, path_ptr: u64, path_len: u64, flags: u64` | file descriptor | Open relative to dirfd |
| 463 | `SYS_FSTATAT` | `dirfd: u64, path_ptr: u64, path_len: u64, stat_ptr: u64, flags: u64` | 0 | Stat relative to dirfd |
| 464 | `SYS_UNLINKAT` | `dirfd: u64, path_ptr: u64, path_len: u64, flags: u64` | 0 | Unlink relative to dirfd |
| 465 | `SYS_RENAMEAT` | `olddirfd: u64, old_ptr: u64, old_len: u64, newdirfd: u64, new_ptr: u64, new_len: u64` | 0 | Rename relative to dirfds |
| 466 | `SYS_MKDIRAT` | `dirfd: u64, path_ptr: u64, path_len: u64, mode: u64` | 0 | Create directory relative to dirfd |
| 467 | `SYS_READLINKAT` | `dirfd: u64, path_ptr: u64, path_len: u64, buf_ptr: u64, buf_len: u64` | bytes read | Readlink relative to dirfd |
| 468 | `SYS_FACCESSAT` | `dirfd: u64, path_ptr: u64, path_len: u64, mode: u64, flags: u64` | 0 | Check accessibility relative to dirfd |

---

## Poll / I/O multiplexing

| # | Syscall | Parameters | Return | Description |
|---|---------|-----------|--------|-------------|
| 460 | `SYS_POLL` | `fds_ptr: u64, nfds: u64, timeout_ms: i64` | ready count | Poll file descriptors |
| 461 | `SYS_PPOLL` | `fds_ptr: u64, nfds: u64, timeout_ptr: u64, sigmask_ptr: u64` | ready count | Ppoll with signal mask |

---

## Network

| # | Syscall | Parameters | Return | Description |
|---|---------|-----------|--------|-------------|
| 410 | `SYS_NET_RECV` | `buf_ptr: u64, buf_len: u64` | bytes received | Receive network packet |
| 411 | `SYS_NET_SEND` | `buf_ptr: u64, buf_len: u64` | bytes sent | Send network packet |
| 412 | `SYS_NET_INFO` | `info_type: u64, buf_ptr: u64` | 0 | Query network info (IP, gateway, etc.) |

---

## Volume (block device)

| # | Syscall | Parameters | Return | Description |
|---|---------|-----------|--------|-------------|
| 420 | `SYS_VOLUME_READ` | `handle: u64, offset: u64, buf_ptr: u64, buf_len: u64` | bytes read | Read from volume |
| 421 | `SYS_VOLUME_WRITE` | `handle: u64, offset: u64, buf_ptr: u64, buf_len: u64` | bytes written | Write to volume |
| 422 | `SYS_VOLUME_INFO` | `handle: u64, out_ptr: u64` | 0 | Query volume info |

---

## Time

| # | Syscall | Parameters | Return | Description |
|---|---------|-----------|--------|-------------|
| 500 | `SYS_CLOCK_GETTIME` | `clock_id: u64, tp_ptr: u64` | 0 | Get clock time |
| 501 | `SYS_NANOSLEEP` | `req_ptr: u64, rem_ptr: u64` | 0 | Sleep for a duration |
| 502 | `SYS_CLOCK_NANOSLEEP` | `clock_id: u64, flags: u64, req_ptr: u64, rem_ptr: u64` | 0 | Sleep on a specific clock |

**Clock IDs:** `CLOCK_REALTIME (0)`, `CLOCK_MONOTONIC (1)`, `CLOCK_PROCESS_CPUTIME_ID (2)`, `CLOCK_THREAD_CPUTIME_ID (3)`

---

## Debug & miscellaneous

| # | Syscall | Parameters | Return | Description |
|---|---------|-----------|--------|-------------|
| 600 | `SYS_DEBUG_LOG` | `msg_ptr: u64, msg_len: u64` | 0 | Write a debug message to kernel log |
| 601 | `SYS_GETRANDOM` | `buf: u64, len: usize, flags: u32` | bytes written | Fill buffer with random bytes |
| 610 | `SYS_SET_ROBUST_LIST` | `head: u64, len: usize` | 0 | Set robust futex list head |
| 611 | `SYS_GET_ROBUST_LIST` | `pid: i64, head_ptr: u64, len_ptr: u64` | 0 | Get robust futex list head |

---

## Module management

| # | Syscall | Parameters | Return | Description |
|---|---------|-----------|--------|-------------|
| 700 | `SYS_MODULE_LOAD` | `path_ptr: u64, path_len: u64` | module ID | Load a kernel module |
| 701 | `SYS_MODULE_UNLOAD` | `module_id: u64` | 0 | Unload a kernel module |
| 702 | `SYS_MODULE_GET_SYMBOL` | `module_id: u64, name_ptr: u64, name_len: u64` | symbol address | Look up a symbol in a loaded module |
| 703 | `SYS_MODULE_QUERY` | `out_ptr: u64, max_count: u64` | module count | List loaded modules |

---

## Silo management

| # | Syscall | Parameters | Return | Description |
|---|---------|-----------|--------|-------------|
| 800 | `SYS_SILO_CREATE` | : | silo ID | Create a new silo |
| 801 | `SYS_SILO_CONFIG` | `silo_id: u64, key_ptr: u64, key_len: u64, val_ptr: u64, val_len: u64` | 0 | Configure a silo |
| 802 | `SYS_SILO_ATTACH_MODULE` | `silo_id: u64, module_id: u64` | 0 | Attach a module to a silo |
| 803 | `SYS_SILO_START` | `silo_id: u64` | 0 | Start a silo |
| 804 | `SYS_SILO_STOP` | `silo_id: u64` | 0 | Stop a silo |
| 805 | `SYS_SILO_KILL` | `silo_id: u64` | 0 | Kill a silo (force stop) |
| 806 | `SYS_SILO_EVENT_NEXT` | `silo_id: u64, out_ptr: u64` | 0 | Wait for next silo event |
| 807 | `SYS_SILO_SUSPEND` | `silo_id: u64` | 0 | Suspend a silo |
| 808 | `SYS_SILO_RESUME` | `silo_id: u64` | 0 | Resume a silo |
| 809 | `SYS_SILO_PLEDGE` | `promises_ptr: u64, promises_len: u64` | 0 | Restrict syscalls (pledge) |
| 810 | `SYS_SILO_UNVEIL` | `path_ptr: u64, path_len: u64, perms_ptr: u64, perms_len: u64` | 0 | Restrict filesystem access (unveil) |
| 811 | `SYS_SILO_ENTER_SANDBOX` | : | 0 | Enter sandbox mode (irreversible) |
| 812 | `SYS_SILO_RENAME` | `silo_id: u64, name_ptr: u64, name_len: u64` | 0 | Rename a silo |

---

## ABI version

| # | Syscall | Parameters | Return | Description |
|---|---------|-----------|--------|-------------|
| 900 | `SYS_ABI_VERSION` | : | `(major << 16) \| minor` | Query ABI version |

---

## Common errno values

| Value | Name | Description |
|-------|------|-------------|
| 1 | `EPERM` | Operation not permitted |
| 2 | `ENOENT` | No such file or directory |
| 3 | `ESRCH` | No such process |
| 4 | `EINTR` | Interrupted system call |
| 5 | `EIO` | Input/output error |
| 7 | `E2BIG` | Argument list too long |
| 9 | `EBADF` | Bad file descriptor |
| 10 | `ECHILD` | No child processes |
| 11 | `EAGAIN` | Resource temporarily unavailable |
| 12 | `ENOMEM` | Out of memory |
| 13 | `EACCES` | Permission denied |
| 14 | `EFAULT` | Bad address |
| 17 | `EEXIST` | File exists |
| 20 | `ENOTDIR` | Not a directory |
| 21 | `EISDIR` | Is a directory |
| 22 | `EINVAL` | Invalid argument |
| 28 | `ENOSPC` | No space left on device |
| 32 | `EPIPE` | Broken pipe |
| 38 | `ENOSYS` | Function not implemented |
| 52 | `ENOTSUP` | Not supported |
| 98 | `EADDRINUSE` | Address already in use |
| 110 | `ETIMEDOUT` | Connection timed out |
| 111 | `ECONNREFUSED` | Connection refused |
