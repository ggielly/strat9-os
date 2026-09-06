//! Syscall number definitions for Strat9 OS.
//!
//! Each syscall is identified by a unique `usize` constant. Syscalls are
//! invoked via the `syscall` instruction on x86_64. Arguments are passed in
//! registers (RDI, RSI, RDX, R8, R9, R10); the return value is in RAX.
//!
//! **ABI convention**: Success returns a non-negative value. Errors return a
//! negative errno value (two's complement). Userspace checks
//! `if result > 0xFFFF_F000 { errno = !result + 1; }`.

// ── Block 0-99: Capability / Handle Management ──────────────────────────────

/// No-op syscall. Used for benchmarking syscall overhead.
pub const SYS_NULL: usize = 0;

/// Duplicate a capability handle.
///
/// Returns a new handle pointing to the same underlying resource.
/// The new handle has its own lifetime and must be closed independently.
pub const SYS_HANDLE_DUPLICATE: usize = 1;

/// Close a capability handle.
///
/// After this call, the handle is invalid. If this was the last reference
/// to the underlying resource, the resource is destroyed.
pub const SYS_HANDLE_CLOSE: usize = 2;

/// Wait on a capability handle until it becomes ready or the timeout expires.
///
/// - `handle`: capability handle to wait on
/// - `timeout_ns`: maximum wait time in nanoseconds (0 = infinite)
///
/// Returns `0` on success, `-ETIMEDOUT` if the timeout expired.
pub const SYS_HANDLE_WAIT: usize = 3;

/// Grant a capability handle to another process.
///
/// - `handle`: capability to grant
/// - `target_pid`: PID of the target process
///
/// The target process receives a new handle to the same resource.
/// Returns `0` on success, `-EPERM` if the caller lacks grant permission.
pub const SYS_HANDLE_GRANT: usize = 4;

/// Revoke a capability handle.
///
/// All holders of this handle (including the caller and any granted
/// recipients) lose access. The underlying resource may be destroyed
/// if no other references exist.
pub const SYS_HANDLE_REVOKE: usize = 5;

/// Query information about a capability handle.
///
/// - `handle`: capability to query
/// - `out_ptr`: pointer to a `HandleInfo` struct that receives the result
///
/// Returns `0` on success, `-EBADF` if the handle is invalid.
pub const SYS_HANDLE_INFO: usize = 6;

// ── Block 100-199: Memory Management ────────────────────────────────────────

/// Map a memory region into the process address space.
///
/// - `addr`: desired virtual address (0 = kernel chooses)
/// - `len`: length in bytes (rounded up to page boundary)
/// - `prot`: protection flags (`PROT_READ | PROT_WRITE | PROT_EXEC`)
/// - `flags`: mapping flags (`MAP_SHARED`, `MAP_PRIVATE`, `MAP_ANONYMOUS`, etc.)
/// - `fd`: file descriptor for file-backed mappings (-1 for anonymous)
/// - `offset`: offset into the file (must be page-aligned)
///
/// Returns the mapped virtual address on success, or a negative errno.
pub const SYS_MMAP: usize = 100;

/// Unmap a memory region.
///
/// - `addr`: virtual address of the mapping (must be page-aligned)
/// - `len`: length in bytes (rounded up to page boundary)
///
/// After this call, the region is no longer accessible. Any dirty pages
/// are written back if the mapping was shared.
pub const SYS_MUNMAP: usize = 101;

/// Set or query the program break (data segment end).
///
/// - `addr`: new break address (0 = query current break)
///
/// Returns the current break address. If `addr` is non-zero, the break
/// is moved to `addr` (may allocate or free pages).
pub const SYS_BRK: usize = 102;

/// Remap a memory region to a new address or size.
///
/// - `old_addr`: current virtual address
/// - `old_len`: current length in bytes
/// - `new_len`: desired new length in bytes
/// - `flags`: `MREMAP_MAYMOVE` (1) to allow relocation
/// - `new_addr`: desired new address (only with `MREMAP_MAYMOVE`)
///
/// Returns the new virtual address.
pub const SYS_MREMAP: usize = 103;

/// Change memory protection flags on a mapped region.
///
/// - `addr`: start address (must be page-aligned)
/// - `len`: length in bytes (rounded up to page boundary)
/// - `prot`: new protection flags (`PROT_READ`, `PROT_WRITE`, `PROT_EXEC`)
///
/// Returns `0` on success. Common errors: `-EACCES` (trying to make
/// a mapping executable that wasn't created with PROT_EXEC).
pub const SYS_MPROTECT: usize = 104;

/// Export a memory region as a shareable handle.
///
/// - `addr`: start address of the region
/// - `len`: length in bytes
///
/// Returns a capability handle that can be granted to another process.
/// The other process can then map it with `SYS_MEM_REGION_MAP`.
pub const SYS_MEM_REGION_EXPORT: usize = 105;

/// Map an exported memory region into the current address space.
///
/// - `region_handle`: capability handle from `SYS_MEM_REGION_EXPORT`
/// - `addr`: desired virtual address (0 = kernel chooses)
/// - `len`: length in bytes
///
/// Returns the mapped virtual address.
pub const SYS_MEM_REGION_MAP: usize = 106;

/// Query metadata about an exported memory region.
///
/// - `region_handle`: capability handle from `SYS_MEM_REGION_EXPORT`
/// - `out_ptr`: pointer to a `MemRegionInfo` struct
///
/// Returns `0` on success.
pub const SYS_MEM_REGION_INFO: usize = 107;

// ── Block 200-219: IPC ─────────────────────────────────────────────────────

/// Create a new IPC port.
///
/// Returns a capability handle for the port. The port is owned by the
/// calling process and can receive messages from other processes that
/// hold a handle to it.
pub const SYS_IPC_CREATE_PORT: usize = 200;

/// Send a message to an IPC port.
///
/// - `port_handle`: capability handle of the target port
/// - `msg_ptr`: pointer to the message data
/// - `msg_len`: length of the message in bytes
///
/// Blocks if the port's message queue is full.
pub const SYS_IPC_SEND: usize = 201;

/// Receive a message from an IPC port.
///
/// - `port_handle`: capability handle of the port
/// - `buf_ptr`: buffer to receive the message
/// - `buf_len`: size of the buffer
///
/// Blocks until a message is available. Returns the number of bytes received.
pub const SYS_IPC_RECV: usize = 202;

/// Synchronous RPC: send a message and wait for a reply.
///
/// - `port_handle`: capability handle of the target port
/// - `msg_ptr`: pointer to the request message
/// - `msg_len`: length of the request
///
/// Blocks until the server replies. Returns the number of bytes in the reply.
/// Equivalent to `SYS_IPC_SEND` + `SYS_IPC_RECV` with automatic reply routing.
pub const SYS_IPC_CALL: usize = 203;

/// Reply to the current IPC call.
///
/// - `msg_ptr`: pointer to the reply message
/// - `msg_len`: length of the reply
///
/// Must be called from within an `IPC_CALL` handler. Wakes the waiting caller.
pub const SYS_IPC_REPLY: usize = 204;

/// Bind a port as a listener in the IPC namespace.
///
/// - `port_handle`: capability handle of the port
///
/// After binding, other processes can connect to this port by name.
pub const SYS_IPC_BIND_PORT: usize = 205;

/// Unbind a listening port from the IPC namespace.
///
/// - `port_handle`: capability handle of the port
///
/// The port continues to exist but is no longer discoverable by name.
pub const SYS_IPC_UNBIND_PORT: usize = 206;

/// Non-blocking receive from an IPC port.
///
/// - `port_handle`: capability handle of the port
/// - `buf_ptr`: buffer to receive the message
/// - `buf_len`: size of the buffer
///
/// Returns the number of bytes received, or `0` if no message is available
/// (does not block). Returns `-EAGAIN` if the port is empty.
pub const SYS_IPC_TRY_RECV: usize = 207;

/// Connect to a bound IPC port by name.
///
/// - `port_handle`: capability handle (used for authentication/permissions)
///
/// Returns a new handle to the connected port, or `-ENOENT` if not found.
pub const SYS_IPC_CONNECT: usize = 208;

/// Create a shared ring buffer for zero-copy IPC.
///
/// - `size_log2`: log2 of the ring size in bytes (e.g., 12 = 4096 bytes)
///
/// Returns a capability handle for the ring. The ring can be mapped into
/// another process's address space with `SYS_IPC_RING_MAP`.
pub const SYS_IPC_RING_CREATE: usize = 210;

/// Map a shared ring buffer into the current address space.
///
/// - `ring_handle`: capability handle from `SYS_IPC_RING_CREATE`
/// - `addr`: desired virtual address (0 = kernel chooses)
///
/// Returns the mapped virtual address.
pub const SYS_IPC_RING_MAP: usize = 211;

// ── Block 220-224: Typed Channels (MPMC) ───────────────────────────────────

/// Create a typed MPMC channel.
///
/// - `capacity`: maximum number of messages the channel can hold
///
/// Returns a capability handle for the channel. Both endpoints (sender
/// and receiver) share the same handle; the channel is symmetric.
pub const SYS_CHAN_CREATE: usize = 220;

/// Send a message through a typed channel (blocks if full).
///
/// - `handle`: channel handle
/// - `msg_ptr`: pointer to the message data
///
/// Blocks until space is available in the channel buffer.
pub const SYS_CHAN_SEND: usize = 221;

/// Receive a message from a typed channel (blocks if empty).
///
/// - `handle`: channel handle
/// - `msg_ptr`: buffer to receive the message
///
/// Blocks until a message is available.
pub const SYS_CHAN_RECV: usize = 222;

/// Non-blocking receive from a typed channel.
///
/// - `handle`: channel handle
/// - `msg_ptr`: buffer to receive the message
///
/// Returns `1` if a message was received, `0` if the channel is empty.
pub const SYS_CHAN_TRY_RECV: usize = 223;

/// Close a typed channel handle.
///
/// - `handle`: channel handle
///
/// If this was the last handle, the channel is destroyed and all
/// pending senders/receivers receive `EPIPE`.
pub const SYS_CHAN_CLOSE: usize = 224;

// ── Block 230-234: Semaphores ───────────────────────────────────────────────

/// Create a POSIX counting semaphore.
///
/// - `initial_value`: initial count of the semaphore
///
/// Returns a capability handle for the semaphore.
pub const SYS_SEM_CREATE: usize = 230;

/// Decrement (wait on) a semaphore. Blocks if the count is zero.
///
/// - `handle`: semaphore handle
pub const SYS_SEM_WAIT: usize = 231;

/// Non-blocking decrement (trywait) on a semaphore.
///
/// - `handle`: semaphore handle
///
/// Returns `1` if the semaphore was decremented, `0` if it would block.
pub const SYS_SEM_TRYWAIT: usize = 232;

/// Increment (post) a semaphore, waking a waiter if any.
///
/// - `handle`: semaphore handle
pub const SYS_SEM_POST: usize = 233;

/// Close a semaphore handle.
///
/// - `handle`: semaphore handle
pub const SYS_SEM_CLOSE: usize = 234;

// ── Block 240-249: PCI ──────────────────────────────────────────────────────

/// Enumerate PCI devices matching specified criteria.
///
/// - `criteria_ptr`: pointer to a `PciProbeCriteria` struct (class, subclass, vendor/device ID)
/// - `out_ptr`: buffer to receive `PciDevice` structs
/// - `max_count`: maximum number of devices to return
///
/// Returns the number of matching devices found.
pub const SYS_PCI_ENUM: usize = 240;

/// Read a PCI configuration space register.
///
/// - `addr_ptr`: pointer to a `PciAddress` struct (bus/device/function)
/// - `offset`: register offset within config space
/// - `width`: access width in bytes (1, 2, or 4)
///
/// Returns the register value.
pub const SYS_PCI_CFG_READ: usize = 241;

/// Write a PCI configuration space register.
///
/// - `addr_ptr`: pointer to a `PciAddress` struct
/// - `offset`: register offset within config space
/// - `width`: access width in bytes (1, 2, or 4)
/// - `value`: value to write
pub const SYS_PCI_CFG_WRITE: usize = 242;

// ── Block 250-254: Async I/O ────────────────────────────────────────────────

/// Set up async event notification on a file descriptor.
///
/// - `handle`: file descriptor to monitor
/// - `event_mask`: bitmask of events to watch (`POLLIN`, `POLLOUT`, etc.)
///
/// Returns an async context handle for use with `SYS_ASYNC_ENTER`.
pub const SYS_ASYNC_SETUP: usize = 250;

/// Enter async wait on a previously set up context.
///
/// - `ctx`: async context handle from `SYS_ASYNC_SETUP`
///
/// Yields the current thread until one of the monitored events fires.
/// The event type is returned in RAX.
pub const SYS_ASYNC_ENTER: usize = 251;

/// Cancel a pending async wait.
///
/// - `ctx`: async context handle
///
/// Wakes the thread immediately with `-ECANCELED` as the result.
pub const SYS_ASYNC_CANCEL: usize = 252;

/// Map a shared ring buffer to an async context for event delivery.
///
/// - `ctx`: async context handle
/// - `ring_handle`: capability handle of a shared ring buffer
///
/// Events are delivered as messages in the ring buffer instead of
/// waking the thread directly.
pub const SYS_ASYNC_MAP: usize = 253;

/// Destroy an async context and release its resources.
///
/// - `ctx`: async context handle
pub const SYS_ASYNC_DESTROY: usize = 254;

// ── Block 260-269: IPC Transport Layer ──────────────────────────────────────

/// Create an IPC transport between two silos.
///
/// - `dst_silo`: destination silo ID
/// - `config_flags`: transport configuration (level, ring capacity, etc.)
///
/// Returns a transport capability handle. The transport level is selected
/// automatically based on the silo tiers (TypeSafe / LockFree / MMU).
pub const SYS_TRANSPORT_CREATE: usize = 260;

/// Send a message through an IPC transport.
///
/// - `transport_handle`: transport capability from `SYS_TRANSPORT_CREATE`
/// - `buf_ptr`: pointer to the message data
/// - `buf_len`: length of the message
///
/// Dispatches to the appropriate transport (N1/N2/N3) automatically.
pub const SYS_TRANSPORT_SEND: usize = 261;

/// Receive a message from an IPC transport.
///
/// - `transport_handle`: transport capability
/// - `buf_ptr`: buffer to receive the message
/// - `buf_len`: size of the buffer
///
/// Returns the number of bytes received.
pub const SYS_TRANSPORT_RECV: usize = 262;

/// Close an IPC transport and release its resources.
///
/// - `transport_handle`: transport capability
///
/// All pending messages are discarded. Both endpoints are invalidated.
pub const SYS_TRANSPORT_CLOSE: usize = 263;

/// Query information about an IPC transport.
///
/// - `transport_handle`: transport capability
/// - `out_ptr`: pointer to a `TransportInfo` struct
///
/// Returns the transport level, capacity, and performance statistics.
pub const SYS_TRANSPORT_INFO: usize = 264;

// ── Block 300-399: Process / Thread Management ──────────────────────────────

/// Terminate the current process with an exit code.
///
/// - `exit_code`: process exit status
///
/// This syscall never returns. All threads in the process are terminated.
pub const SYS_PROC_EXIT: usize = 300;

/// Yield the CPU to the scheduler.
///
/// The current thread is placed at the back of the run queue and another
/// thread is scheduled. Returns `0` when the thread is rescheduled.
pub const SYS_PROC_YIELD: usize = 301;

/// Fork the current process (copy-on-write).
///
/// - `frame`: pointer to the `SyscallFrame` to restore in the child
///
/// Returns `0` in the child process, and the child PID in the parent.
/// The child gets a copy of the parent's address space (COW).
pub const SYS_PROC_FORK: usize = 302;

/// Sleep on a futex word. Blocks if `*addr == val`.
///
/// - `addr`: futex word address
/// - `val`: expected value
/// - `timeout_ns`: timeout in nanoseconds (0 = infinite)
///
/// Returns `0` on wakeup, `-EAGAIN` if value mismatch, `-ETIMEDOUT` on timeout.
pub const SYS_FUTEX_WAIT: usize = 303;

/// Wake up to N waiters blocked on a futex word.
///
/// - `addr`: futex word address
/// - `max_wake`: maximum number of waiters to wake
///
/// Returns the number of waiters actually woken.
pub const SYS_FUTEX_WAKE: usize = 304;

/// Wake waiters on `addr` and requeue remaining waiters to `addr2`.
///
/// - `addr`: source futex word
/// - `max_wake`: maximum waiters to wake
/// - `addr2`: destination futex word for requeue
/// - `max_requeue`: maximum waiters to requeue
///
/// Returns the number of waiters woken.
pub const SYS_FUTEX_REQUEUE: usize = 305;

/// Conditional requeue: only requeue if `*addr == cmp_val`.
///
/// - `addr`: source futex word
/// - `max_wake`: maximum waiters to wake
/// - `addr2`: destination futex word for requeue
/// - `max_requeue`: maximum waiters to requeue
/// - `cmp_val`: expected value at `addr`
///
/// Returns the number of waiters woken.
pub const SYS_FUTEX_CMP_REQUEUE: usize = 306;

/// Atomic operation on `addr2` + wake waiters on `addr`.
///
/// - `addr`: source futex word to wake from
/// - `max_wake`: maximum waiters to wake
/// - `addr2`: target futex word for atomic operation
/// - `max_requeue`: maximum waiters to requeue
/// - `wake_op`: encoded atomic operation (op, cmp_op, cmp_val, shift)
///
/// Returns the number of waiters woken.
pub const SYS_FUTEX_WAKE_OP: usize = 307;

/// Get the current process ID (PID).
///
/// Returns the PID of the calling process.
pub const SYS_PROC_GETPID: usize = 308;

/// Get the parent process ID (PPID).
///
/// Returns the PID of the parent process, or 0 if the parent has exited.
pub const SYS_PROC_GETPPID: usize = 309;

/// Wait for a specific child process to change state.
///
/// - `pid`: child PID to wait for (-1 = any child)
/// - `status_ptr`: pointer to receive exit status
/// - `options`: `WNOHANG`, `WUNTRACED`, `WCONTINUED` flags
///
/// Returns the child PID, or `-ECHILD` if no children exist.
pub const SYS_PROC_WAITPID: usize = 310;

/// Get the current process ID (alias for `SYS_PROC_GETPID`).
pub const SYS_GETPID: usize = 311;

/// Get the current thread ID (TID).
///
/// Returns the TID of the calling thread. TIDs are unique per-thread.
pub const SYS_GETTID: usize = 312;

/// Get the parent process ID (alias for `SYS_PROC_GETPPID`).
pub const SYS_GETPPID: usize = SYS_PROC_GETPPID;

/// Wait for any child process to change state.
///
/// Returns the PID of the terminated child, or `-ECHILD` if no children.
pub const SYS_PROC_WAIT: usize = 314;

/// Execute a new program, replacing the current process image.
///
/// - `path_ptr`: pointer to the null-terminated path string
/// - `path_len`: length of the path string
/// - `argv_ptr`: pointer to the argument array
/// - `envp_ptr`: pointer to the environment array
///
/// This syscall never returns on success. The current process image is
/// replaced with the new ELF binary.
pub const SYS_PROC_EXECVE: usize = 315;

/// File control operations (fcntl).
///
/// - `fd`: file descriptor
/// - `cmd`: command (`F_DUPFD`, `F_GETFD`, `F_SETFD`, `F_GETFL`, `F_SETFL`)
/// - `arg`: command-specific argument
///
/// Returns a command-dependent value.
pub const SYS_FCNTL: usize = 316;

/// Set the process group ID of a process.
///
/// - `pid`: target process ID (0 = current process)
/// - `pgid`: desired process group ID
pub const SYS_SETPGID: usize = 317;

/// Get the process group ID of a process.
///
/// - `pid`: target process ID (0 = current process)
///
/// Returns the process group ID.
pub const SYS_GETPGID: usize = 318;

/// Create a new session and set the process group ID.
///
/// Returns the new session ID. The calling process becomes the session
/// leader with a new process group.
pub const SYS_SETSID: usize = 319;

// ── Block 320-353: Signal Handling ──────────────────────────────────────────

/// Send a signal to a process.
///
/// - `pid`: target process ID (negative = send to process group)
/// - `signum`: signal number (1-31)
///
/// Returns `0` on success, `-ESRCH` if process not found.
pub const SYS_KILL: usize = 320;

/// Get or set the signal mask of the current thread.
///
/// - `how`: `SIG_BLOCK` (0), `SIG_UNBLOCK` (1), or `SIG_SETMASK` (2)
/// - `set_ptr`: pointer to signal set to apply
/// - `oldset_ptr`: pointer to receive the previous signal set (0 = ignore)
pub const SYS_SIGPROCMASK: usize = 321;

/// Set the action for a signal.
///
/// - `signum`: signal number
/// - `act_ptr`: pointer to `Sigaction` struct (handler, flags, mask)
/// - `oact_ptr`: pointer to receive the previous action (0 = ignore)
pub const SYS_SIGACTION: usize = 322;

/// Set the alternate signal stack for the current thread.
///
/// - `ss_ptr`: pointer to `Stack` struct (base, size, flags)
/// - `old_ss_ptr`: pointer to receive the previous stack (0 = ignore)
pub const SYS_SIGALTSTACK: usize = 323;

/// Get the set of pending signals for the current thread.
///
/// - `set_ptr`: pointer to receive the signal set
pub const SYS_SIGPENDING: usize = 324;

/// Suspend the current thread until a signal is delivered.
///
/// - `mask_ptr`: pointer to signal set to temporarily unblock
///
/// This syscall does not return normally; it returns when a signal handler runs.
pub const SYS_SIGSUSPEND: usize = 325;

/// Suspend the current thread until a specific signal is delivered.
///
/// - `set_ptr`: pointer to signal set to wait for
/// - `info_ptr`: pointer to receive signal info
/// - `timeout_ptr`: pointer to timeout (0 = infinite)
///
/// Returns the signal number that was delivered.
pub const SYS_SIGTIMEDWAIT: usize = 326;

/// Queue a signal with associated data to a process.
///
/// - `pid`: target process ID
/// - `signum`: signal number
/// - `sigval_ptr`: pointer to `Sigval` union (integer or pointer)
///
/// Unlike `SYS_KILL`, this delivers the signal asynchronously with data.
pub const SYS_SIGQUEUE: usize = 327;

/// Send a signal to all processes in a process group.
///
/// - `pgrp`: process group ID
/// - `signum`: signal number
pub const SYS_KILLPG: usize = 328;

/// Get the current value of an interval timer.
///
/// - `which`: timer type (`ITIMER_REAL`, `ITIMER_VIRTUAL`, `ITIMER_PROF`)
/// - `out_ptr`: pointer to receive the `itimerval` struct
pub const SYS_GETITIMER: usize = 329;

/// Set an interval timer.
///
/// - `which`: timer type
/// - `in_ptr`: pointer to `itimerval` struct (interval + initial value)
/// - `out_ptr`: pointer to receive the previous value (0 = ignore)
pub const SYS_SETITIMER: usize = 330;

/// Get the current process group ID.
///
/// Returns the process group ID of the calling process.
pub const SYS_GETPGRP: usize = 331;

/// Get the session ID of a process.
///
/// - `pid`: target process ID (0 = current process)
///
/// Returns the session ID.
pub const SYS_GETSID: usize = 332;

/// Set the clear-on-exit TID address for the current thread.
///
/// - `tidptr`: pointer to the TID variable (for `CLONE_CHILD_CLEARTID`)
///
/// When the thread exits, the kernel clears the memory at `tidptr` and
/// wakes any futex waiters on that address.
pub const SYS_SET_TID_ADDRESS: usize = 333;

/// Exit all threads in the current process.
///
/// - `exit_code`: process exit status
///
/// This is the multi-threaded equivalent of `SYS_PROC_EXIT`. All threads
/// are terminated, not just the calling thread.
pub const SYS_EXIT_GROUP: usize = 334;

/// Get the real user ID of the calling process.
pub const SYS_GETUID: usize = 335;

/// Get the effective user ID of the calling process.
pub const SYS_GETEUID: usize = 336;

/// Get the real group ID of the calling process.
pub const SYS_GETGID: usize = 337;

/// Get the effective group ID of the calling process.
pub const SYS_GETEGID: usize = 338;

/// Set the real user ID of the calling process.
///
/// - `uid`: new real user ID
///
/// Requires root privileges. Also sets the effective UID.
pub const SYS_SETUID: usize = 339;

/// Set the real group ID of the calling process.
///
/// - `gid`: new real group ID
///
/// Requires root privileges. Also sets the effective GID.
pub const SYS_SETGID: usize = 340;

/// Create a new thread within the current process.
///
/// - `entry`: thread entry point address
/// - `stack`: thread stack base address
/// - `arg`: argument passed to the thread entry point
///
/// Returns the new thread ID (TID).
pub const SYS_THREAD_CREATE: usize = 341;

/// Wait for a thread to exit.
///
/// - `tid`: thread ID to wait for
/// - `status_ptr`: pointer to receive the exit status (0 = ignore)
///
/// Blocks until the thread terminates.
pub const SYS_THREAD_JOIN: usize = 342;

/// Terminate the current thread.
///
/// - `status`: thread exit status
///
/// This syscall never returns. Only the calling thread is terminated;
/// other threads in the process continue running.
pub const SYS_THREAD_EXIT: usize = 343;

/// Get system identification information.
///
/// - `uts_ptr`: pointer to a `Utsname` struct that receives:
///   - `sysname`: OS name ("Strat9")
///   - `nodename`: hostname
///   - `release`: kernel version
///   - `version`: build timestamp
///   - `machine`: architecture ("x86_64")
///
/// Returns `0` on success.
pub const SYS_UNAME: usize = 344;

/// Architecture-specific process control.
///
/// - `code`: operation code (`ARCH_SET_FS` = 0x1001, `ARCH_GET_FS` = 0x1002)
/// - `addr`: address value (for set operations)
///
/// Used primarily to set the FS base for thread-local storage.
pub const SYS_ARCH_PRCTL: usize = 350;

/// Send a signal to a specific thread.
///
/// - `tgid`: thread group ID (process ID)
/// - `tid`: target thread ID
/// - `signum`: signal number
///
/// Unlike `SYS_KILL`, this targets a specific thread within a process.
pub const SYS_TGKILL: usize = 352;

/// Return from a signal handler.
///
/// Restores the signal mask and registers from the signal frame on the
/// user stack. This syscall is invoked implicitly by the kernel when
/// returning from a signal handler trampoline.
pub const SYS_RT_SIGRETURN: usize = 353;

// ── Block 400-499: Filesystem / VFS ─────────────────────────────────────────

/// Open a file by path.
///
/// - `path_ptr`: pointer to the null-terminated path string
/// - `path_len`: length of the path
/// - `flags`: open flags (`O_RDONLY`, `O_WRONLY`, `O_RDWR`, `O_CREAT`, etc.)
///
/// Returns a file descriptor on success.
pub const SYS_OPEN: usize = 403;

/// Write data to a file descriptor.
///
/// - `fd`: file descriptor
/// - `buf_ptr`: pointer to the data buffer
/// - `buf_len`: number of bytes to write
///
/// Returns the number of bytes actually written.
pub const SYS_WRITE: usize = 404;

/// Read data from a file descriptor.
///
/// - `fd`: file descriptor
/// - `buf_ptr`: buffer to receive the data
/// - `buf_len`: maximum number of bytes to read
///
/// Returns the number of bytes actually read (0 = end of file).
pub const SYS_READ: usize = 405;

/// Close a file descriptor.
///
/// - `fd`: file descriptor to close
///
/// After this call, the file descriptor is invalid.
pub const SYS_CLOSE: usize = 406;

/// Set the file position of a file descriptor.
///
/// - `fd`: file descriptor
/// - `offset`: new position offset
/// - `whence`: `SEEK_SET` (0), `SEEK_CUR` (1), or `SEEK_END` (2)
///
/// Returns the new file position.
pub const SYS_LSEEK: usize = 407;

/// Get file status information by file descriptor.
///
/// - `fd`: file descriptor
/// - `stat_ptr`: pointer to a `FileStat` struct to receive the result
///
/// Returns `0` on success.
pub const SYS_FSTAT: usize = 408;

/// Get file status information by path.
///
/// - `path_ptr`: pointer to the path string
/// - `path_len`: length of the path
/// - `stat_ptr`: pointer to a `FileStat` struct
///
/// Returns `0` on success.
pub const SYS_STAT: usize = 409;

// ── Block 410-419: Network ──────────────────────────────────────────────────

/// Receive a network packet.
///
/// - `buf_ptr`: buffer to receive the packet data
/// - `buf_len`: size of the buffer
///
/// Returns the number of bytes received. The packet includes all headers
/// (Ethernet, IP, TCP/UDP).
pub const SYS_NET_RECV: usize = 410;

/// Send a network packet.
///
/// - `buf_ptr`: pointer to the packet data (including all headers)
/// - `buf_len`: length of the packet
///
/// Returns the number of bytes sent.
pub const SYS_NET_SEND: usize = 411;

/// Query network interface information.
///
/// - `info_type`: information type (IP address, MAC, link status, etc.)
/// - `buf_ptr`: buffer to receive the information
///
/// Returns `0` on success.
pub const SYS_NET_INFO: usize = 412;

/// Register the calling task as the strate-net networking silo.
///
/// Called once by strate-net during startup.  The NIC IRQ handler uses
/// this registration to wake the networking task when packets arrive.
///
/// Returns `0` on success.
pub const SYS_NET_REGISTER: usize = 414;

/// Check file accessibility using the real user/group IDs.
///
/// - `path_ptr`: pointer to the path string
/// - `path_len`: length of the path
/// - `mode`: accessibility check (`F_OK`=0, `R_OK`=4, `W_OK`=2, `X_OK`=1)
///
/// Returns `0` if the file is accessible, `-EACCES` or `-ENOENT` otherwise.
/// Prefer `SYS_FACCESSAT` for new code : this syscall is provided for
/// POSIX compatibility.
pub const SYS_ACCESS: usize = 413;

// ── Block 420-429: Volumes / Block Devices ──────────────────────────────────

/// Read data from a block device volume.
///
/// - `handle`: volume capability handle
/// - `offset`: byte offset into the volume
/// - `buf_ptr`: buffer to receive the data
/// - `buf_len`: number of bytes to read
///
/// Returns the number of bytes read.
pub const SYS_VOLUME_READ: usize = 420;

/// Write data to a block device volume.
///
/// - `handle`: volume capability handle
/// - `offset`: byte offset into the volume
/// - `buf_ptr`: pointer to the data buffer
/// - `buf_len`: number of bytes to write
///
/// Returns the number of bytes written.
pub const SYS_VOLUME_WRITE: usize = 421;

/// Query information about a block device volume.
///
/// - `handle`: volume capability handle
/// - `out_ptr`: pointer to a `VolumeInfo` struct (size, block size, etc.)
///
/// Returns `0` on success.
pub const SYS_VOLUME_INFO: usize = 422;

// ── Block 430-461: VFS Extended ─────────────────────────────────────────────

/// Read directory entries from an open directory.
///
/// - `fd`: directory file descriptor
/// - `buf_ptr`: buffer to receive `DirEntry` structs
/// - `buf_len`: size of the buffer
///
/// Returns the number of bytes read. Returns `0` when all entries
/// have been read (end of directory).
pub const SYS_GETDENTS: usize = 430;

/// Create a pipe pair for inter-process communication.
///
/// - `fds_ptr`: pointer to receive two file descriptors (read end, write end)
///
/// Returns `0` on success. The pipe provides unidirectional byte stream IPC.
pub const SYS_PIPE: usize = 431;

/// Duplicate a file descriptor.
///
/// - `old_fd`: file descriptor to duplicate
///
/// Returns the new file descriptor (lowest available).
pub const SYS_DUP: usize = 432;

/// Duplicate a file descriptor to a specific number.
///
/// - `old_fd`: file descriptor to duplicate
/// - `new_fd`: desired new file descriptor number
///
/// If `new_fd` is already open, it is closed first. Returns `new_fd`.
pub const SYS_DUP2: usize = 433;

/// Change the current working directory by path.
///
/// - `path_ptr`: pointer to the new directory path
/// - `path_len`: length of the path
pub const SYS_CHDIR: usize = 440;

/// Change the current working directory by file descriptor.
///
/// - `fd`: file descriptor of an open directory
pub const SYS_FCHDIR: usize = 441;

/// Get the current working directory.
///
/// - `buf_ptr`: buffer to receive the path string
/// - `buf_len`: size of the buffer
///
/// Returns the number of bytes written (excluding null terminator).
pub const SYS_GETCWD: usize = 442;

/// Perform device-specific I/O control operations.
///
/// - `fd`: file descriptor
/// - `cmd`: device-specific command code
/// - `arg`: command-specific argument
///
/// The behavior depends entirely on the device driver.
pub const SYS_IOCTL: usize = 443;

/// Set the file mode creation mask.
///
/// - `mask`: new umask value (e.g., `0o022`)
///
/// Returns the previous umask. New files are created with
/// `mode & ~umask`.
pub const SYS_UMASK: usize = 444;

/// Delete a file by path.
///
/// - `path_ptr`: pointer to the file path
/// - `path_len`: length of the path
pub const SYS_UNLINK: usize = 445;

/// Remove an empty directory by path.
///
/// - `path_ptr`: pointer to the directory path
/// - `path_len`: length of the path
pub const SYS_RMDIR: usize = 446;

/// Create a directory by path.
///
/// - `path_ptr`: pointer to the directory path
/// - `path_len`: length of the path
/// - `mode`: permission mode (e.g., `0o755`)
pub const SYS_MKDIR: usize = 447;

/// Rename or move a file.
///
/// - `old_ptr`: pointer to the old path
/// - `old_len`: length of the old path
/// - `new_ptr`: pointer to the new path
/// - `new_len`: length of the new path
///
/// Atomic operation : either succeeds completely or fails.
pub const SYS_RENAME: usize = 448;

/// Create a hard link to an existing file.
///
/// - `old_ptr`: pointer to the existing file path
/// - `old_len`: length of the existing path
/// - `new_ptr`: pointer to the new link path
/// - `new_len`: length of the new path
pub const SYS_LINK: usize = 449;

/// Create a symbolic link.
///
/// - `target_ptr`: pointer to the target path (what the link points to)
/// - `target_len`: length of the target path
/// - `link_ptr`: pointer to the link path (where the link is created)
/// - `link_len`: length of the link path
pub const SYS_SYMLINK: usize = 450;

/// Read the target of a symbolic link.
///
/// - `path_ptr`: pointer to the symlink path
/// - `path_len`: length of the path
/// - `buf_ptr`: buffer to receive the target path
/// - `buf_len`: size of the buffer
///
/// Returns the number of bytes placed in the buffer.
pub const SYS_READLINK: usize = 451;

/// Change file permissions by path.
///
/// - `path_ptr`: pointer to the file path
/// - `path_len`: length of the path
/// - `mode`: new permission mode (e.g., `0o644`)
pub const SYS_CHMOD: usize = 452;

/// Change file permissions by file descriptor.
///
/// - `fd`: file descriptor
/// - `mode`: new permission mode
pub const SYS_FCHMOD: usize = 453;

/// Truncate a file to a specified length by path.
///
/// - `path_ptr`: pointer to the file path
/// - `path_len`: length of the path
/// - `len`: desired file length in bytes
pub const SYS_TRUNCATE: usize = 454;

/// Truncate a file to a specified length by file descriptor.
///
/// - `fd`: file descriptor
/// - `len`: desired file length in bytes
pub const SYS_FTRUNCATE: usize = 455;

/// Read from a file descriptor at a specific offset.
///
/// - `fd`: file descriptor
/// - `buf_ptr`: buffer to receive the data
/// - `buf_len`: number of bytes to read
/// - `offset`: byte offset in the file
///
/// Returns the number of bytes read. The file position is not changed.
pub const SYS_PREAD: usize = 456;

/// Write to a file descriptor at a specific offset.
///
/// - `fd`: file descriptor
/// - `buf_ptr`: pointer to the data buffer
/// - `buf_len`: number of bytes to write
/// - `offset`: byte offset in the file
///
/// Returns the number of bytes written. The file position is not changed.
pub const SYS_PWRITE: usize = 457;

/// Synchronize a file's in-core state with storage.
///
/// - `fd`: file descriptor
pub const SYS_FSYNC: usize = 458;

/// Synchronize file data (not metadata) with storage.
///
/// - `fd`: file descriptor
pub const SYS_FDATASYNC: usize = 459;

// ── Block 460-461: Poll / I/O Multiplexing ──────────────────────────────────

/// Poll multiple file descriptors for events.
///
/// - `fds_ptr`: pointer to an array of `PollFd` structs
/// - `nfds`: number of file descriptors in the array
/// - `timeout_ms`: maximum wait time in milliseconds (-1 = infinite, 0 = return immediately)
///
/// Returns the number of file descriptors with events, or `0` on timeout.
pub const SYS_POLL: usize = 460;

/// Poll with signal mask (ppoll).
///
/// - `fds_ptr`: pointer to an array of `PollFd` structs
/// - `nfds`: number of file descriptors
/// - `timeout_ptr`: pointer to a `Timespec` struct (0 = return immediately)
/// - `sigmask_ptr`: pointer to signal set to temporarily unblock during poll
///
/// Returns the number of file descriptors with events.
pub const SYS_PPOLL: usize = 461;

// ── Block 462-469: *at() Syscalls (FD-Relative Path Resolution) ─────────────
//
// These syscalls resolve paths relative to a directory file descriptor
// instead of the process CWD. They are the POSIX-standard way to open,
// stat, and manipulate files safely in multi-threaded programs.
//
// Special `dirfd` values:
//   AT_FDCWD (-100) : use the process's current working directory
//   >= 0            : use the opened directory referenced by this fd

/// Base directory for *at() syscalls: use the process CWD.
pub const AT_FDCWD: i64 = -100;

/// Open a file relative to a directory FD.
///
/// - `dirfd`: directory file descriptor (or `AT_FDCWD`)
/// - `path_ptr`: pointer to the path string
/// - `path_len`: length of the path
/// - `flags`: open flags
///
/// Returns a file descriptor. If `path_ptr` is absolute, `dirfd` is ignored.
pub const SYS_OPENAT: usize = 462;

/// Get file status relative to a directory FD.
///
/// - `dirfd`: directory file descriptor (or `AT_FDCWD`)
/// - `path_ptr`: pointer to the path string
/// - `path_len`: length of the path
/// - `stat_ptr`: pointer to a `FileStat` struct
/// - `flags`: flags (`AT_SYMLINK_NOFOLLOW` to not follow symlinks)
///
/// Returns `0` on success.
pub const SYS_FSTATAT: usize = 463;

/// Delete a file relative to a directory FD.
///
/// - `dirfd`: directory file descriptor (or `AT_FDCWD`)
/// - `path_ptr`: pointer to the file path
/// - `path_len`: length of the path
/// - `flags`: flags (`AT_REMOVEDIR` to remove a directory instead of a file)
pub const SYS_UNLINKAT: usize = 464;

/// Rename or move a file between two directory FDs.
///
/// - `olddirfd`: source directory FD (or `AT_FDCWD`)
/// - `old_ptr`: pointer to the source path
/// - `old_len`: length of the source path
/// - `newdirfd`: destination directory FD (or `AT_FDCWD`)
/// - `new_ptr`: pointer to the destination path
/// - `new_len`: length of the destination path
///
/// Source and destination can be on different mount points (atomic if same FS).
pub const SYS_RENAMEAT: usize = 465;

/// Create a directory relative to a directory FD.
///
/// - `dirfd`: directory file descriptor (or `AT_FDCWD`)
/// - `path_ptr`: pointer to the directory path
/// - `path_len`: length of the path
/// - `mode`: permission mode (e.g., `0o755`)
pub const SYS_MKDIRAT: usize = 466;

/// Read the target of a symbolic link relative to a directory FD.
///
/// - `dirfd`: directory file descriptor (or `AT_FDCWD`)
/// - `path_ptr`: pointer to the symlink path
/// - `path_len`: length of the path
/// - `buf_ptr`: buffer to receive the target path
/// - `buf_len`: size of the buffer
///
/// Returns the number of bytes placed in the buffer.
pub const SYS_READLINKAT: usize = 467;

/// Check file accessibility relative to a directory FD.
///
/// - `dirfd`: directory file descriptor (or `AT_FDCWD`)
/// - `path_ptr`: pointer to the path string
/// - `path_len`: length of the path
/// - `mode`: accessibility check (`R_OK`=4, `W_OK`=2, `X_OK`=1, `F_OK`=0)
/// - `flags`: flags (currently unused, pass 0)
///
/// Returns `0` if the file is accessible, `-EACCES` or `-ENOENT` otherwise.
/// This is the preferred way to check file access : it avoids TOCTOU races
/// that `SYS_ACCESS` can have when paths are resolved relative to CWD.
pub const SYS_FACCESSAT: usize = 468;

// ── Block 500-599: Time / Alarms ────────────────────────────────────────────

/// Get the current time of a clock.
///
/// - `clock_id`: clock identifier (`CLOCK_REALTIME`, `CLOCK_MONOTONIC`, etc.)
/// - `tp_ptr`: pointer to a `Timespec` struct to receive the time
///
/// Returns `0` on success.
pub const SYS_CLOCK_GETTIME: usize = 500;

/// Suspend execution for a specified duration.
///
/// - `req_ptr`: pointer to a `Timespec` struct (requested sleep time)
/// - `rem_ptr`: pointer to receive the remaining time (0 = ignore)
///
/// Returns `0` on success. The actual sleep may be shorter due to
/// signal delivery.
pub const SYS_NANOSLEEP: usize = 501;

/// Suspend execution on a specific clock.
///
/// - `clock_id`: clock to use for the sleep
/// - `flags`: `TIMER_ABSTIME` (1) for absolute time, 0 for relative
/// - `req_ptr`: pointer to a `Timespec` struct
/// - `rem_ptr`: pointer to receive the remaining time (0 = ignore)
///
/// Returns `0` on success.
pub const SYS_CLOCK_NANOSLEEP: usize = 502;

// ── Block 600-699: Debug / Profiling / Random / Robust List ────────────────

/// Write a debug message to the kernel log (serial console).
///
/// - `msg_ptr`: pointer to the message string
/// - `msg_len`: length of the message
///
/// The message is written to the serial port and optionally to the
/// VGA framebuffer if debug output is enabled.
pub const SYS_DEBUG_LOG: usize = 600;

/// Fill a buffer with cryptographically secure random bytes.
///
/// - `buf`: pointer to the buffer to fill
/// - `len`: number of random bytes to generate
/// - `flags`: `GRND_RANDOM` (1) for /dev/random behavior, 0 for /dev/urandom
///
/// Returns the number of bytes written. Uses RDRAND/RDSEED when available.
pub const SYS_GETRANDOM: usize = 601;

/// Set the robust futex list head for the current thread.
///
/// - `head`: pointer to the first `RobustListHead` struct
/// - `len`: length of the list in bytes
///
/// The kernel walks this list on thread exit to wake any futex waiters.
pub const SYS_SET_ROBUST_LIST: usize = 610;

/// Get the robust futex list head for a process.
///
/// - `pid`: target process ID (0 = current)
/// - `head_ptr`: pointer to receive the list head address
/// - `len_ptr`: pointer to receive the list length
pub const SYS_GET_ROBUST_LIST: usize = 611;

// ── Block 700-799: Module Management (.cmod) ────────────────────────────────

/// Load a kernel module from a CMOD binary.
///
/// - `path_ptr`: pointer to the module path string
/// - `path_len`: length of the path
///
/// Returns a module ID on success. The module is loaded into the kernel
/// address space and its init function is called.
pub const SYS_MODULE_LOAD: usize = 700;

/// Unload a previously loaded kernel module.
///
/// - `module_id`: module ID from `SYS_MODULE_LOAD`
///
/// Calls the module's cleanup function, then unmaps its memory.
/// Returns `0` on success.
pub const SYS_MODULE_UNLOAD: usize = 701;

/// Look up a symbol address in a loaded kernel module.
///
/// - `module_id`: module ID
/// - `name_ptr`: pointer to the null-terminated symbol name
/// - `name_len`: length of the symbol name
///
/// Returns the virtual address of the symbol, or `0` if not found.
pub const SYS_MODULE_GET_SYMBOL: usize = 702;

/// List all loaded kernel modules.
///
/// - `out_ptr`: buffer to receive `ModuleInfo` structs
/// - `max_count`: maximum number of modules to return
///
/// Returns the number of modules written to the buffer.
pub const SYS_MODULE_QUERY: usize = 703;

// ── Block 800-899: Silo Management ─────────────────────────────────────────

/// Create a new silo (process isolation container).
///
/// Returns a silo ID on success. The silo starts in a stopped state
/// and must be configured and started with subsequent syscalls.
pub const SYS_SILO_CREATE: usize = 800;

/// Configure a silo's properties.
///
/// - `silo_id`: silo to configure
/// - `key_ptr`: pointer to the configuration key string
/// - `key_len`: length of the key
/// - `val_ptr`: pointer to the configuration value string
/// - `val_len`: length of the value
///
/// Configuration keys include: `mode` (OctalMode), `mem_max`, `mem_usage_bytes`.
pub const SYS_SILO_CONFIG: usize = 801;

/// Attach a kernel module to a silo.
///
/// - `silo_id`: target silo
/// - `module_id`: module ID from `SYS_MODULE_LOAD`
///
/// The module runs inside the silo's address space and can be started
/// with `SYS_SILO_START`.
pub const SYS_SILO_ATTACH_MODULE: usize = 802;

/// Start a silo (begin execution of its attached module).
///
/// - `silo_id`: silo to start
///
/// The silo's module init function is called, and the silo enters
/// the running state.
pub const SYS_SILO_START: usize = 803;

/// Stop a silo gracefully (sends SIGTERM, waits for cleanup).
///
/// - `silo_id`: silo to stop
///
/// Returns `0` on success, `-ETIMEDOUT` if the silo doesn't stop in time.
pub const SYS_SILO_STOP: usize = 804;

/// Force-kill a silo immediately (SIGKILL).
///
/// - `silo_id`: silo to kill
///
/// The silo is terminated without cleanup. Use `SYS_SILO_STOP` for
/// graceful shutdown.
pub const SYS_SILO_KILL: usize = 805;

/// Wait for the next event from a silo.
///
/// - `silo_id`: silo to monitor
/// - `out_ptr`: pointer to a `SiloEvent` struct to receive the event
///
/// Events include: state changes, faults, resource usage alerts.
/// Blocks until an event is available.
pub const SYS_SILO_EVENT_NEXT: usize = 806;

/// Suspend a running silo (freeze its threads).
///
/// - `silo_id`: silo to suspend
pub const SYS_SILO_SUSPEND: usize = 807;

/// Resume a suspended silo.
///
/// - `silo_id`: silo to resume
pub const SYS_SILO_RESUME: usize = 808;

/// Restrict syscalls available to a silo (pledge).
///
/// - `promises_ptr`: pointer to the octal mode value string
/// - `promises_len`: length of the string
///
/// The new mode must be a subset of the current mode (monotonic restriction).
/// Once pledged, the silo cannot gain additional capabilities.
pub const SYS_SILO_PLEDGE: usize = 809;

/// Restrict filesystem access for a silo (unveil).
///
/// - `path_ptr`: pointer to the path to reveal
/// - `path_len`: length of the path
/// - `perms_ptr`: pointer to the permissions string (e.g., "rwx")
/// - `perms_len`: length of the permissions string
///
/// Only paths that have been unveiled are accessible. Once a path is
/// unveiled, the silo cannot unveil additional paths (monotonic).
pub const SYS_SILO_UNVEIL: usize = 810;

/// Enter sandbox mode (irreversible).
///
/// After this call, the silo cannot:
/// - Gain new capabilities (pledge is locked)
/// - Access new filesystem paths (unveil is locked)
/// - Execute certain privileged syscalls
///
/// This is a one-way operation : there is no way to exit sandbox mode.
pub const SYS_SILO_ENTER_SANDBOX: usize = 811;

/// Rename a silo.
///
/// - `silo_id`: silo to rename
/// - `name_ptr`: pointer to the new name string
/// - `name_len`: length of the new name
///
/// The name is used for display and debugging purposes.
pub const SYS_SILO_RENAME: usize = 812;

// ── Block 900: ABI Introspection ────────────────────────────────────────────

/// Query the ABI version.
///
/// No parameters.
///
/// Returns `(major << 16) | minor`. For example, version 1.2 returns
/// `0x0001_0002`. Userspace can use this to check for ABI compatibility
/// before making syscalls.
pub const SYS_ABI_VERSION: usize = 900;
