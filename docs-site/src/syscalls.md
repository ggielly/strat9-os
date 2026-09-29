# Syscall Reference

Complete reference for all Strat9 OS syscalls. Syscalls are invoked via the `syscall` instruction (x86_64). Arguments are passed in registers; the return value is in RAX.

**Sources of truth**

| Concern | File |
|---------|------|
| Syscall numbers and their documented intent | [`workspace/abi/src/syscall.rs`](https://git.strat9-os.org/strat9-os/strat9-os/blob/main/workspace/abi/src/syscall.rs) |
| Real argument wiring and implementation status | [`workspace/kernel/src/syscall/dispatcher.rs`](https://git.strat9-os.org/strat9-os/strat9-os/blob/main/workspace/kernel/src/syscall/dispatcher.rs) |
| Error numbering | [`workspace/abi/src/errno.rs`](https://git.strat9-os.org/strat9-os/strat9-os/blob/main/workspace/abi/src/errno.rs) |
| Open / map / unlink flags | [`workspace/abi/src/flag.rs`](https://git.strat9-os.org/strat9-os/strat9-os/blob/main/workspace/abi/src/flag.rs) |

**Register order.** Arguments go in **`RDI, RSI, RDX, R10, R8, R9`**, result in `RAX` — the Linux x86_64 order. The header comment in `workspace/abi/src/syscall.rs` lists them as `RDI, RSI, RDX, R8, R9, R10`, which **transposes the last three**. The dispatcher reads `arg4 = r10` and `arg5 = r8` (`kernel/src/syscall/dispatcher.rs:65-66`), so trust the dispatcher, not the header.

**ABI convention.** Success returns a non-negative value. Errors return a negative errno value (two's complement). Userspace checks `if result > 0xFFFF_F000` to detect errors, then applies `!result + 1` to get the errno number. The threshold is pinned by `workspace/abi/tests/errno_abi.rs`.

**Argument columns in the tables below are the *kernel's* argument list**, taken from the dispatcher, not from the loose prose in the ABI header comments. Where the two disagree, the dispatcher wins — see [Known gaps](#known-gaps--abi-vs-kernel).

**Status column**

| Value | Meaning |
|-------|---------|
| OK | Dispatched and implemented |
| Stub | Handler exists but is a no-op / returns a fixed error |
| **ENOSYS** | Number exists in the ABI but has no dispatcher arm: always returns `-ENOSYS` |

---

## Constants

### `AT_*` — `*at` base directory

Defined in [`syscall.rs`](https://git.strat9-os.org/strat9-os/strat9-os/blob/main/workspace/abi/src/syscall.rs) and re-exported by the VFS.

| Constant | Value | Description |
|----------|-------|-------------|
| `AT_FDCWD` | `-100` | Use the process's current working directory as the base directory |

> **There is no `AT_REMOVEDIR`, `AT_SYMLINK_NOFOLLOW` or `AT_EMPTY_PATH` in the ABI.**
> `AT_REMOVEDIR` exists only as [`UnlinkFlags::REMOVEDIR`](https://git.strat9-os.org/strat9-os/strat9-os/blob/main/workspace/abi/src/flag.rs) = `0o02000000`, and no handler currently consumes it (`SYS_UNLINKAT` is not dispatched). `SYS_FSTATAT` takes a `flags` argument but the kernel handler ignores it. Use `flags = 0`.

### Open flags — `OpenFlags` (Strat9-native, **not** POSIX)

`workspace/abi/src/flag.rs`. These are **bit flags**, not the Linux `O_*` numeric values. The access mode is a 2-bit field, not a 0/1/2 enum. Compatibility layers must call `posix_oflags_to_strat9()` to translate.

| Flag | Bit | Value | Description |
|------|-----|-------|-------------|
| `OpenFlags::READ` | 0 | `0x001` | Open for reading |
| `OpenFlags::WRITE` | 1 | `0x002` | Open for writing |
| `OpenFlags::CREATE` | 2 | `0x004` | Create the file if missing (requires `WRITE`) |
| `OpenFlags::TRUNCATE` | 3 | `0x008` | Truncate to zero length on open |
| `OpenFlags::APPEND` | 4 | `0x010` | Append all writes at end of file |
| `OpenFlags::DIRECTORY` | 5 | `0x020` | Open as a directory |
| `OpenFlags::EXCL` | 6 | `0x040` | Fail if the file exists (with `CREATE`) |
| `OpenFlags::NONBLOCK` | 7 | `0x080` | Non-blocking: return `EAGAIN` instead of blocking |
| `OpenFlags::NOFOLLOW` | 8 | `0x100` | Do not follow a symlink in the final component |
| `OpenFlags::NOCTTY` | 9 | `0x200` | Do not allocate a controlling terminal |
| `OpenFlags::SYNC` | 10 | `0x400` | Synchronous writes |

Derived aliases: `RDONLY = READ` (`0x001`), `WRONLY = WRITE` (`0x002`), `RDWR = READ | WRITE` (`0x003`).

`posix_oflags_to_strat9()` maps the Linux values onto this set, e.g. `O_CREAT (0o100) → CREATE (0x004)`, `O_TRUNC (0o1000) → TRUNCATE (0x008)`, `O_NONBLOCK (0o4000) → NONBLOCK (0x080)`.

### Protection flags — `PROT_*` (mmap)

POSIX-compatible values, defined in `workspace/kernel/src/syscall/mmap.rs`.

| Flag | Value | Description |
|------|-------|-------------|
| `PROT_READ` | `1` | Page can be read |
| `PROT_WRITE` | `2` | Page can be written |
| `PROT_EXEC` | `4` | Page can be executed |

### Memory-map flags — `MAP_*` (mmap)

Defined in `workspace/kernel/src/syscall/mmap.rs`. The kernel rejects any flag outside this set with `EINVAL`.

| Flag | Value | Description |
|------|-------|-------------|
| `MAP_SHARED` | `0x01` | Shared mapping |
| `MAP_PRIVATE` | `0x02` | Private (copy-on-write) mapping |
| `MAP_FIXED` | `0x10` | Place at the exact requested address |
| `MAP_ANONYMOUS` | `0x20` | Not backed by a file |
| `MAP_HUGETLB` | `0x800` | 2 MiB huge pages |
| `MAP_FIXED_NOREPLACE` | `0x100000` | Like `MAP_FIXED` but fails instead of overwriting |

`mremap` also uses `MREMAP_MAYMOVE = 0x1`; any other bit returns `EINVAL`.

> `strat9_abi::flag::MapFlags` additionally declares `MAP_NORESERVE (0x40)`, `MAP_GROWSDOWN (0x100)`, `MAP_LOCKED (0x2000)` and `MAP_POPULATE (0x8000)`. The kernel's `sys_mmap` does **not** accept these bits and returns `EINVAL`. Use the `mmap` table above, not `MapFlags`, when writing a syscall.

### Signal constants

| Constant | Value | Source | Description |
|----------|-------|--------|-------------|
| `SIG_BLOCK` | `0` | `kernel/src/process/signal.rs` | Add signals to the mask |
| `SIG_UNBLOCK` | `1` | `kernel/src/process/signal.rs` | Remove signals from the mask |
| `SIG_SETMASK` | `2` | `kernel/src/process/signal.rs` | Replace the mask |
| `SIG_DFL` | `0` | `kernel/src/process/signal.rs` | Default disposition |
| `SIG_IGN` | `1` | `kernel/src/process/signal.rs` | Ignore the signal |

`SIG_DFL`/`SIG_IGN` are *dispositions* (stored in `Sigaction::handler`); `SIG_BLOCK`/`SIG_UNBLOCK`/`SIG_SETMASK` are *mask operations* (the `how` argument of `SYS_SIGPROCMASK`). They are not interchangeable despite sharing the value range.

### Waitpid options

| Flag | Value | Status |
|------|-------|--------|
| `WNOHANG` | `1` | OK — supported by `sys_waitpid` |
| `WUNTRACED` | `2` | **Rejected** — `sys_waitpid` returns `EINVAL` for any bit outside `WNOHANG` |
| `WCONTINUED` | `4` | **Rejected** — same |

### Clock IDs

| Constant | Value | Description |
|----------|-------|-------------|
| `CLOCK_REALTIME` | `0` | System-wide real-time clock |
| `CLOCK_MONOTONIC` | `1` | Monotonic clock (not affected by adjustments) |
| `CLOCK_PROCESS_CPUTIME_ID` | `2` | Per-process CPU time — **not implemented**, see below |
| `CLOCK_THREAD_CPUTIME_ID` | `3` | Per-thread CPU time — **not implemented**, see below |

`sys_clock_gettime` only recognises `CLOCK_REALTIME` and `CLOCK_MONOTONIC`; any other `clock_id` returns `EINVAL`.

### `SEEK_*` (lseek)

| Constant | Value |
|----------|-------|
| `SEEK_SET` | `0` |
| `SEEK_CUR` | `1` |
| `SEEK_END` | `2` |

### `R_OK` / `W_OK` / `X_OK` / `F_OK` (access check)

| Constant | Value |
|----------|-------|
| `F_OK` | `0` |
| `X_OK` | `1` |
| `W_OK` | `2` |
| `R_OK` | `4` |

### `GRND_*` (getrandom)

| Constant | Value | Description |
|----------|-------|-------------|
| `GRND_RANDOM` | `1` | Accepted but ignored: this implementation uses one pool |

### `TIMER_ABSTIME` (clock_nanosleep)

| Constant | Value | Description |
|----------|-------|-------------|
| `TIMER_ABSTIME` | `1` | `req_ptr` is an absolute deadline instead of a duration |

---

## Handle operations

| # | Syscall | Kernel args | Return | Status | Description |
|---|---------|-------------|--------|--------|-------------|
| 0 | `SYS_NULL` | : | `0x57A79` | OK | Ping / syscall-overhead benchmark. Returns the magic `"STRAT9"` value |
| 1 | `SYS_HANDLE_DUPLICATE` | `handle: u64` | new handle | OK | Duplicate a capability handle |
| 2 | `SYS_HANDLE_CLOSE` | `handle: u64` | `0` | OK | Close a capability handle |
| 3 | `SYS_HANDLE_WAIT` | `handle: u64, timeout_ns: u64` | event bitmask | OK | Block until the handle is ready. `timeout_ns = 0` performs a non-blocking check; `timeout_ns = u64::MAX` waits indefinitely. Polls in 10 ms slices and returns `EINTR` on a pending signal |
| 4 | `SYS_HANDLE_GRANT` | `handle: u64, target_pid: u64` | `0` | OK | Grant a capability to another process |
| 5 | `SYS_HANDLE_REVOKE` | `handle: u64` | `0` | OK | Revoke a capability for all holders |
| 6 | `SYS_HANDLE_INFO` | `handle: u64, out_ptr: u64` | `0` | OK | Write a `HandleInfo` struct to `out_ptr` |

**Errors:** `EBADF` (invalid handle), `EPERM` (no grant permission), `ESRCH` (target process not found), `ETIMEDOUT` (wait expired), `EINTR` (signal delivered while blocked)

### Handle readiness

`SYS_HANDLE_WAIT` reports a bitmask, not a boolean:

| Bit | Name | Set when |
|-----|------|----------|
| `0` | `HANDLE_EVENT_READABLE` | Data is available (semaphore count > 0, port queue non-empty, ring has data, …) |
| `1` | `HANDLE_EVENT_WRITABLE` | The endpoint can accept a message (channel has space, ring is not full) |

Readiness is defined for five resource types: `Semaphore`, `IpcPort`, `Channel`, `SharedRing` and `IpcTransport`. Any other capability type returns `ENOTSUP` from the readiness check.

---

## Memory management

| # | Syscall | Kernel args | Return | Status | Description |
|---|---------|-------------|--------|--------|-------------|
| 100 | `SYS_MMAP` | `addr, len, prot, flags, fd, offset` | mapped address | OK | Map memory. Anonymous and `MAP_PRIVATE` file-backed are supported; file-backed `MAP_SHARED` returns `ENOSYS` |
| 101 | `SYS_MUNMAP` | `addr: u64, len: u64` | `0` | OK | Unmap a range |
| 102 | `SYS_BRK` | `addr: u64` | current/new break | OK | Query (`addr = 0`) or move the program break |
| 103 | `SYS_MREMAP` | `old_addr, old_len, new_len, flags` | new address | OK | Resize or relocate a region. Only `MREMAP_MAYMOVE` is accepted in `flags` |
| 104 | `SYS_MPROTECT` | `addr: u64, len: u64, prot: u64` | `0` | OK | Change `PROT_*` permissions |
| 105 | `SYS_MEM_REGION_EXPORT` | `addr: u64, len: u64` | region handle | OK | Export a region as a shareable capability |
| 106 | `SYS_MEM_REGION_MAP` | `region_handle, addr, len` | mapped address | OK | Map an exported region into this address space |
| 107 | `SYS_MEM_REGION_INFO` | `region_handle: u64, out_ptr: u64` | `0` | OK | Write a `MemoryRegionInfo` struct to `out_ptr` |

> The ABI header lists five arguments for `SYS_MREMAP` (`old_addr, old_len, new_len, flags, new_addr`). The dispatcher forwards only four — `new_addr` is not read.

**Address-layout constants** (`kernel/src/syscall/mmap.rs`):

| Constant | Value | Meaning |
|----------|-------|---------|
| `BRK_BASE` | `0x20_0000_0000` | Base of the `brk`-managed heap (512 MiB) |
| `MMAP_BASE` | `0x60_0000_0000` | Initial hint for anonymous `mmap` (1.5 GiB) |

**Errors:** `EINVAL` (bad alignment/flags, `len = 0`, unknown `MAP_*` bit), `ENOMEM` (out of memory), `EACCES` (permission denied), `EEXIST` (region already mapped), `ENOSYS` (file-backed `MAP_SHARED`)

---

## IPC : ports

Messages are **fixed-size `IpcMessage` values** (`IPC_MESSAGE_SIZE = 256` bytes, 64-byte aligned, 16-byte header, 240-byte payload). The kernel copies exactly `size_of::<IpcMessage>()` bytes in or out — **there is no user-supplied length argument**.

| # | Syscall | Kernel args | Return | Status | Description |
|---|---------|-------------|--------|--------|-------------|
| 200 | `SYS_IPC_CREATE_PORT` | `flags: u64` (ignored) | port handle | OK | Create a port bound to the calling task |
| 201 | `SYS_IPC_SEND` | `port_handle: u64, msg_ptr: u64` | `0` | OK | Send one `IpcMessage`. The sender badge is injected by the kernel |
| 202 | `SYS_IPC_RECV` | `port_handle: u64, msg_ptr: u64` | `0` | OK | Block until a message is available |
| 203 | `SYS_IPC_CALL` | `port_handle: u64, msg_ptr: u64` | `0` | OK | Send and wait for the reply |
| 204 | `SYS_IPC_REPLY` | `msg_ptr: u64` | `0` | OK | Reply to the pending `IPC_CALL` |
| 205 | `SYS_IPC_BIND_PORT` | `port_handle, name_ptr, name_len` | `0` | OK | Bind the port into the IPC namespace under a name |
| 206 | `SYS_IPC_UNBIND_PORT` | `path_ptr: u64, path_len: u64` | `0` | OK | Unbind by **name**, not by handle |
| 207 | `SYS_IPC_TRY_RECV` | `port_handle: u64, msg_ptr: u64` | `0` | OK | Non-blocking receive |
| 208 | `SYS_IPC_CONNECT` | `path_ptr: u64, path_len: u64` | port handle | OK | Connect to a bound port **by name**, not by handle |
| 210 | `SYS_IPC_RING_CREATE` | `size: u64` | ring handle | OK | Create a shared ring buffer. The ABI header calls this `size_log2`, but the handler passes it through as a **byte size** |
| 211 | `SYS_IPC_RING_MAP` | `ring_handle: u64, addr: u64` | mapped address | OK | Map a shared ring into this address space |

> The ABI header documents `msg_len` as a third argument on `SEND`/`RECV`/`TRY_RECV`/`CALL` and a `port_handle` on `CONNECT`/`UNBIND_PORT`. Neither matches the kernel. Callers must pass the pointer only and address ports by name where a name is required.

**Errors:** `EBADF` (invalid handle or wrong resource type), `ENOSPC`, `EAGAIN` (non-blocking, nothing available), `ETIMEDOUT`, `ENOMEM` (per-process IPC quota exhausted)

---

## IPC : typed channels (MPMC)

| # | Syscall | Kernel args | Return | Status | Description |
|---|---------|-------------|--------|--------|-------------|
| 220 | `SYS_CHAN_CREATE` | `capacity: u64` | channel handle | OK | Create a channel. Capacity is clamped to `[1, 1024]` |
| 221 | `SYS_CHAN_SEND` | `handle: u64, msg_ptr: u64` | `0` | OK | Send an `IpcMessage` (blocks if full) |
| 222 | `SYS_CHAN_RECV` | `handle: u64, msg_ptr: u64` | `0` | OK | Receive an `IpcMessage` (blocks if empty) |
| 223 | `SYS_CHAN_TRY_RECV` | `handle: u64, msg_ptr: u64` | `1` received / `0` empty | OK | Non-blocking receive |
| 224 | `SYS_CHAN_CLOSE` | `handle: u64` | `0` | OK | Close the channel handle |

**Errors:** `EBADF`, `EPIPE` (all endpoints disconnected), `EAGAIN` (try_recv on empty), `ENOMEM` (quota)

---

## IPC : semaphores

| # | Syscall | Kernel args | Return | Status | Description |
|---|---------|-------------|--------|--------|-------------|
| 230 | `SYS_SEM_CREATE` | `initial_value: u64` | semaphore handle | OK | Create a counting semaphore |
| 231 | `SYS_SEM_WAIT` | `handle: u64` | `0` | OK | Decrement (blocks if zero) |
| 232 | `SYS_SEM_TRYWAIT` | `handle: u64` | `1` acquired / `0` would block | OK | Non-blocking decrement |
| 233 | `SYS_SEM_POST` | `handle: u64` | `0` | OK | Increment, waking a waiter |
| 234 | `SYS_SEM_CLOSE` | `handle: u64` | `0` | OK | Close the semaphore handle |

**Errors:** `EBADF`, `EAGAIN` (try_wait on a zero semaphore)

---

## IPC : transport (N1/N2/N3)

This block is **implemented and dispatched** — it is not a placeholder. See [IPC Mechanisms](./ipc-mechanisms.md) for the level-selection policy.

| # | Syscall | Kernel args | Return | Status | Description |
|---|---------|-------------|--------|--------|-------------|
| 260 | `SYS_TRANSPORT_CREATE` | `dst_silo: u64, config_flags: u64` | transport handle | OK | Create a transport to another silo; the level is chosen from the silo tiers |
| 261 | `SYS_TRANSPORT_SEND` | `transport_handle, buf_ptr, buf_len` | `0` | OK | Send a message over the transport |
| 262 | `SYS_TRANSPORT_RECV` | `transport_handle, buf_ptr, buf_len` | bytes received | OK | Receive a message |
| 263 | `SYS_TRANSPORT_CLOSE` | `transport_handle: u64` | `0` | OK | Close the transport and release the capability |
| 264 | `SYS_TRANSPORT_INFO` | `transport_handle: u64, out_ptr: u64` | `0` | OK | Write transport metadata to `out_ptr` |

**Errors:** `EBADF` (unknown handle or missing read/write capability), `EPERM` (caller has no silo), `ESRCH` (unknown destination silo)

---

## PCI

| # | Syscall | Kernel args | Return | Status | Description |
|---|---------|-------------|--------|--------|-------------|
| 240 | `SYS_PCI_ENUM` | `criteria_ptr, out_ptr, max_count` | device count | OK | Enumerate devices matching a `PciProbeCriteria` |
| 241 | `SYS_PCI_CFG_READ` | `addr_ptr: u64, offset: u64, width: u64` | register value | OK | Read config space (width 1, 2 or 4) |
| 242 | `SYS_PCI_CFG_WRITE` | `addr_ptr, offset, width, value` | `0` | OK | Write config space |

**Errors:** `EFAULT` (null pointer), `EINVAL` (invalid width/offset), `EACCES` (no PCI capability)

---

## Async I/O (io_uring-style rings)

The ABI header describes event notification on a file descriptor. The kernel implements an **io_uring-style submission/completion ring** instead. The argument lists differ substantially.

| # | Syscall | Kernel args | Return | Status | Description |
|---|---------|-------------|--------|--------|-------------|
| 250 | `SYS_ASYNC_SETUP` | `entries: u64, flags: u64` | ring id | OK | Create a submission/completion ring with `entries` slots |
| 251 | `SYS_ASYNC_ENTER` | `ring_id, to_submit, min_complete, flags` | completed count | OK | Submit entries and block until `min_complete` completions |
| 252 | `SYS_ASYNC_CANCEL` | `ring_id, user_data, flags` | : | **Stub** | Always returns `ENOSYS` |
| 253 | `SYS_ASYNC_MAP` | `ring_id: u64, out_ptr: u64` | `0` | OK | Map the ring into userspace and write its layout to `out_ptr` |
| 254 | `SYS_ASYNC_DESTROY` | `ring_id: u64, flags: u64` | `0` | OK | Destroy the ring |

---

## Process management

| # | Syscall | Kernel args | Return | Status | Description |
|---|---------|-------------|--------|--------|-------------|
| 300 | `SYS_PROC_EXIT` | `exit_code: u64` | : (never returns) | OK | Terminate the current process |
| 301 | `SYS_PROC_YIELD` | : | `0` | OK | Yield the CPU to the scheduler |
| 302 | `SYS_PROC_FORK` | : (frame is implicit) | child PID in parent, `0` in child | OK | Fork with copy-on-write |
| 308 | `SYS_PROC_GETPID` | : | process ID | OK | Current PID |
| 309 | `SYS_PROC_GETPPID` | : | parent PID | OK | Current PPID. `SYS_GETPPID` (alias, same number) |
| 310 | `SYS_PROC_WAITPID` | `pid: i64, status_ptr: u64, options: u32` | child PID | OK | Wait for a child. Only `WNOHANG` is accepted |
| 311 | `SYS_GETPID` | : | process ID | OK | Alias for `SYS_PROC_GETPID` |
| 312 | `SYS_GETTID` | : | thread ID | OK | Current TID |
| 314 | `SYS_PROC_WAIT` | : | child PID | OK | Wait for any child |
| 315 | `SYS_PROC_EXECVE` | `path_ptr, argv_ptr, envp_ptr` | : (replaces image) | OK | Execute a new program. Path is NUL-terminated; **no length argument**. Returns `ENOTSUP` for a multithreaded process |
| 316 | `SYS_FCNTL` | `fd: u64, cmd: u64, arg: u64` | depends on cmd | OK | File control operations |
| 317 | `SYS_SETPGID` | `pid: i64, pgid: i64` | `0` | OK | Set the process group |
| 318 | `SYS_GETPGID` | `pid: i64` | pgid | OK | Get the process group |
| 319 | `SYS_SETSID` | : | session ID | OK | Create a new session |
| 331 | `SYS_GETPGRP` | : | pgrp | OK | Current process group |
| 332 | `SYS_GETSID` | `pid: i64` | sid | OK | Session ID of `pid` |
| 333 | `SYS_SET_TID_ADDRESS` | `tidptr: u64` | `0` | OK | Clear-on-exit TID address |
| 334 | `SYS_EXIT_GROUP` | `exit_code: u64` | : (never returns) | OK | Terminate every thread in the process |
| 341 | `SYS_THREAD_CREATE` | `entry, stack_top, arg0, flags, tls_base` | thread ID | OK | Create a thread |
| 342 | `SYS_THREAD_JOIN` | `tid: u64, status_ptr: u64, flags: u64` | `0` | OK | Wait for a thread to exit |
| 343 | `SYS_THREAD_EXIT` | `status: u64` | : (never returns) | OK | Terminate the current thread |
| 344 | `SYS_UNAME` | `uts_ptr: u64` | `0` | OK | Write 6 fields of 65 bytes each (390 bytes total) |
| 350 | `SYS_ARCH_PRCTL` | `code: u64, addr: u64` | `0` | OK | `ARCH_SET_FS` / `ARCH_GET_FS` for thread-local storage |
| 352 | `SYS_TGKILL` | `tgid: u64, tid: u64, signum: u32` | `0` | OK | Signal a specific thread |
| 353 | `SYS_RT_SIGRETURN` | : | : | OK | Return from a signal handler |

**Errors:** `ECHILD` (no child processes), `EAGAIN` / `ENOMEM` (thread creation failed), `E2BIG` (path longer than 4096 bytes), `ENOTSUP` (exec from a multithreaded process)

---

## Futex

| # | Syscall | Kernel args | Return | Status | Description |
|---|---------|-------------|--------|--------|-------------|
| 303 | `SYS_FUTEX_WAIT` | `addr: u64, val: u32, timeout_ns: u64` | `0` | OK | Sleep if `*addr == val` |
| 304 | `SYS_FUTEX_WAKE` | `addr: u64, max_wake: u32` | woken count | OK | Wake up to N waiters |
| 305 | `SYS_FUTEX_REQUEUE` | `addr, max_wake, addr2, max_requeue` | woken count | OK | Wake, then requeue the rest to `addr2` |
| 306 | `SYS_FUTEX_CMP_REQUEUE` | `addr, max_wake, addr2, max_requeue, cmp_val` | woken count | OK | Conditional requeue |
| 307 | `SYS_FUTEX_WAKE_OP` | `addr, max_wake, addr2, max_requeue, wake_op` | woken count | OK | Atomic op on `addr2` plus wake on `addr` |

**Errors:** `EAGAIN` (value mismatch), `ETIMEDOUT` (timeout expired), `EFAULT` (invalid address)

---

## Signals

| # | Syscall | Kernel args | Return | Status | Description |
|---|---------|-------------|--------|--------|-------------|
| 320 | `SYS_KILL` | `pid: i64, signum: u32` | `0` | OK | Send a signal to a process |
| 321 | `SYS_SIGPROCMASK` | `how: i32, set_ptr: u64, oldset_ptr: u64` | `0` | OK | Get/set the signal mask |
| 322 | `SYS_SIGACTION` | `signum, act_ptr, oact_ptr` | `0` | OK | Set the signal handler |
| 323 | `SYS_SIGALTSTACK` | `ss_ptr: u64, old_ss_ptr: u64` | `0` | OK | Set the alternate signal stack |
| 324 | `SYS_SIGPENDING` | `set_ptr: u64` | `0` | OK | Query pending signals |
| 325 | `SYS_SIGSUSPEND` | `mask_ptr: u64` | : (returns in the handler) | OK | Suspend until a signal arrives |
| 326 | `SYS_SIGTIMEDWAIT` | `set_ptr, info_ptr, timeout_ptr` | signal number | OK | Wait for a specific signal |
| 327 | `SYS_SIGQUEUE` | `pid: i64, signum: u32, sigval_ptr: u64` | `0` | Partial | `sigval_ptr` is **ignored** by the current handler |
| 328 | `SYS_KILLPG` | `pgrp: u64, signum: u32` | `0` | OK | Signal a process group |
| 329 | `SYS_GETITIMER` | `which: u32, out_ptr: u64` | `0` | OK | Read an interval timer |
| 330 | `SYS_SETITIMER` | `which: u32, in_ptr, out_ptr` | `0` | OK | Set an interval timer |

---

## User/group IDs

There is **no user database**. These operate on the numeric IDs stored in the process struct and have no effect on authorization.

| # | Syscall | Kernel args | Return | Status | Description |
|---|---------|-------------|--------|--------|-------------|
| 335 | `SYS_GETUID` | : | uid | OK | Real user ID |
| 336 | `SYS_GETEUID` | : | euid | OK | Effective user ID |
| 337 | `SYS_GETGID` | : | gid | OK | Real group ID |
| 338 | `SYS_GETEGID` | : | egid | OK | Effective group ID |
| 339 | `SYS_SETUID` | `uid: u64` | `0` | OK | Set the real (and effective) user ID |
| 340 | `SYS_SETGID` | `gid: u64` | `0` | OK | Set the real (and effective) group ID |

---

## File I/O

| # | Syscall | Kernel args | Return | Status | Description |
|---|---------|-------------|--------|--------|-------------|
| 403 | `SYS_OPEN` | `path_ptr, path_len, flags` | file descriptor | OK | Open a file (`flags` is an `OpenFlags` bitmask) |
| 404 | `SYS_WRITE` | `fd, buf_ptr, buf_len` | bytes written | OK | Write to a file descriptor |
| 405 | `SYS_READ` | `fd, buf_ptr, buf_len` | bytes read | OK | Read from a file descriptor |
| 406 | `SYS_CLOSE` | `fd: u64` | `0` | OK | Close a file descriptor |
| 407 | `SYS_LSEEK` | `fd, offset: i64, whence: u32` | new position | OK | Reposition the file offset |
| 408 | `SYS_FSTAT` | `fd: u64, stat_ptr: u64` | `0` | OK | Write a `FileStat` for an open fd |
| 409 | `SYS_STAT` | `path_ptr, path_len, stat_ptr` | `0` | OK | Write a `FileStat` for a path |
| 413 | `SYS_ACCESS` | `path_ptr, path_len, mode: u64` | `0` | OK | Check accessibility against the process's **real** UID/GID and the file's owner/group/other bits. Prefer `SYS_FACCESSAT`, which also enforces the silo's unveil rules and avoids a TOCTOU race against the CWD |
| 430 | `SYS_GETDENTS` | `fd, buf_ptr, buf_len` | bytes read | OK | Read directory entries as `DirentHeader` records |
| 431 | `SYS_PIPE` | `fds_ptr: u64` | `0` | OK | Create a pipe pair |
| 432 | `SYS_DUP` | `old_fd: u64` | new fd | OK | Duplicate a descriptor to the lowest free number |
| 433 | `SYS_DUP2` | `old_fd: u64, new_fd: u64` | `new_fd` | OK | Duplicate to a specific number |
| 456 | `SYS_PREAD` | `fd, buf_ptr, buf_len, offset` | bytes read | OK | Positional read; the file offset is unchanged |
| 457 | `SYS_PWRITE` | `fd, buf_ptr, buf_len, offset` | bytes written | OK | Positional write; the file offset is unchanged |

**Errors:** `ENOENT`, `EACCES`, `EBADF`, `ENOTDIR`, `EISDIR`, `ENOSPC`, `EIO`, `EFAULT`, `ENAMETOOLONG`, `ELOOP`

---

## File system operations

Path arguments are always a `(pointer, length)` pair into a userspace buffer. The kernel does **not** read NUL-terminated strings on these entry points.

| # | Syscall | Kernel args | Return | Status | Description |
|---|---------|-------------|--------|--------|-------------|
| 440 | `SYS_CHDIR` | `path_ptr, path_len` | `0` | OK | Change the working directory |
| 441 | `SYS_FCHDIR` | `fd: u32` | `0` | OK | Change the working directory by fd |
| 442 | `SYS_GETCWD` | `buf_ptr, buf_len` | bytes written | OK | Get the working directory |
| 443 | `SYS_IOCTL` | `fd: u32, request: u64, arg: u64` | : | **Stub** | Always returns `ENOTTY`. No TTY/driver ioctl is implemented |
| 444 | `SYS_UMASK` | `mask: u64` | old mask | OK | Set the creation mask (masked with `0o777`) |
| 445 | `SYS_UNLINK` | `path_ptr, path_len` | `0` | OK | Delete a file |
| 446 | `SYS_RMDIR` | `path_ptr, path_len` | `0` | OK | Remove a directory |
| 447 | `SYS_MKDIR` | `path_ptr, path_len, mode` | `0` | OK | Create a directory |
| 448 | `SYS_RENAME` | `old_ptr, old_len, new_ptr, new_len` | `0` | OK | Rename or move |
| 449 | `SYS_LINK` | `old_ptr, old_len, new_ptr, new_len` | `0` | OK | Create a hard link |
| 450 | `SYS_SYMLINK` | `target_ptr, target_len, link_ptr, link_len` | `0` | OK | Create a symbolic link |
| 451 | `SYS_READLINK` | `path_ptr, path_len, buf_ptr, buf_len` | bytes read | OK | Read a symbolic link target |
| 452 | `SYS_CHMOD` | `path_ptr, path_len, mode` | `0` | OK | Change permissions by path |
| 453 | `SYS_FCHMOD` | `fd: u32, mode: u64` | `0` | OK | Change permissions by fd |
| 454 | `SYS_TRUNCATE` | `path_ptr, path_len, len` | `0` | OK | Truncate by path |
| 455 | `SYS_FTRUNCATE` | `fd: u32, len: u64` | `0` | OK | Truncate by fd |
| 458 | `SYS_FSYNC` | `fd` | : | **ENOSYS** | Handler exists in `vfs/mod.rs` but is not wired into the dispatcher |
| 459 | `SYS_FDATASYNC` | `fd` | : | **ENOSYS** | Same |

---

## `*at` variants (relative to a directory fd)

These resolve paths relative to a directory file descriptor instead of the process CWD.

### Special `dirfd` values

| Value | Constant | Meaning |
|-------|----------|---------|
| `-100` | `AT_FDCWD` | Use the process's current working directory |
| `≥ 0` | valid fd | Use the directory referenced by this descriptor |

### Syscall reference

| # | Syscall | Kernel args | Return | Status | Description |
|---|---------|-------------|--------|--------|-------------|
| 462 | `SYS_OPENAT` | `dirfd, path_ptr, path_len, flags` | file descriptor | OK | Open relative to `dirfd`. An absolute path ignores `dirfd` |
| 463 | `SYS_FSTATAT` | `dirfd, path_ptr, path_len, stat_ptr, flags` | `0` | OK | Stat relative to `dirfd`. The handler takes four parameters: `flags` is read from `r10` and **dropped**, and the dispatcher deliberately passes `r8` (`stat_ptr`) in its place |
| 464 | `SYS_UNLINKAT` | `dirfd, path_ptr, path_len, flags` | : | **ENOSYS** | Not dispatched |
| 465 | `SYS_RENAMEAT` | `olddirfd, old_ptr, old_len, newdirfd, new_ptr, new_len` | : | **ENOSYS** | Not dispatched |
| 466 | `SYS_MKDIRAT` | `dirfd, path_ptr, path_len, mode` | : | **ENOSYS** | Not dispatched |
| 467 | `SYS_READLINKAT` | `dirfd, path_ptr, path_len, buf_ptr, buf_len` | : | **ENOSYS** | Not dispatched |
| 468 | `SYS_FACCESSAT` | `dirfd, path_ptr, path_len, mode, flags` | `0` | OK | Check accessibility relative to `dirfd`. `flags` is ignored |

**Errors:** `EBADF` (invalid `dirfd`), `ENOENT`, `EACCES`, `ENOTDIR`, `EEXIST`, `EINVAL`

---

## Poll / I/O multiplexing

| # | Syscall | Kernel args | Return | Status | Description |
|---|---------|-------------|--------|--------|-------------|
| 460 | `SYS_POLL` | `fds_ptr, nfds, timeout_ms` | ready count | **Partial** | Non-blocking snapshot; `timeout_ms` is **ignored** |
| 461 | `SYS_PPOLL` | `fds_ptr, nfds, timeout_ptr, sigmask_ptr` | ready count | **Partial** | Dispatched as `sys_poll(fds_ptr, nfds, 0)`: timeout and sigmask are discarded |

Current behaviour of `sys_poll` (`kernel/src/syscall/poll.rs`):

- Never blocks. The `timeout` argument is named `_timeout_ms` in the implementation.
- For any fd present in the table, reports `POLLIN`/`POLLOUT` according to what the caller *asked for*, not according to actual data availability. Only a closed fd yields `POLLNVAL`.
- `nfds` must be `1..=1024`; `0` returns `0`.
- Operates on an 8-byte `pollfd` record (`i32 fd`, `i16 events`, `i16 revents`).

**Events:** `POLLIN = 0x0001`, `POLLOUT = 0x0004`, `POLLNVAL = 0x0020`

---

## Network

| # | Syscall | Kernel args | Return | Status | Description |
|---|---------|-------------|--------|--------|-------------|
| 410 | `SYS_NET_RECV` | `buf_ptr, buf_len` | bytes received | OK | Receive one raw frame (all headers included) |
| 411 | `SYS_NET_SEND` | `buf_ptr, buf_len` | bytes sent | OK | Send one raw frame |
| 412 | `SYS_NET_INFO` | `info_type: u64, buf_ptr: u64` | `0` | OK | Query interface information |
| 414 | `SYS_NET_REGISTER` | : | `0` | OK | Register the calling task as the networking silo. Called once by `strate-net` at startup so the NIC IRQ handler knows whom to wake |

---

## Volume (block device)

Volumes are addressed in **512-byte sectors**, not byte offsets.

| # | Syscall | Kernel args | Return | Status | Description |
|---|---------|-------------|--------|--------|-------------|
| 420 | `SYS_VOLUME_READ` | `handle, sector, buf_ptr, sector_count` | `0` | OK | Read up to 256 sectors starting at `sector` |
| 421 | `SYS_VOLUME_WRITE` | `handle, sector, buf_ptr, sector_count` | `0` | OK | Write up to 256 sectors starting at `sector` |
| 422 | `SYS_VOLUME_INFO` | `handle: u64` | sector count | OK | Returns the total sector count **in RAX**; there is no `out_ptr` |

---

## Time

| # | Syscall | Kernel args | Return | Status | Description |
|---|---------|-------------|--------|--------|-------------|
| 500 | `SYS_CLOCK_GETTIME` | `clock_id: u32, tp_ptr: u64` | `0` | OK | Read a clock. Only `CLOCK_REALTIME` and `CLOCK_MONOTONIC` are valid |
| 501 | `SYS_NANOSLEEP` | `req_ptr, rem_ptr` | `0` | OK | Sleep for a duration |
| 502 | `SYS_CLOCK_NANOSLEEP` | `clock_id, flags, req_ptr, rem_ptr` | `0` | OK | Sleep on a specific clock. `flags` may carry `TIMER_ABSTIME` |

---

## Debug & miscellaneous

| # | Syscall | Kernel args | Return | Status | Description |
|---|---------|-------------|--------|--------|-------------|
| 600 | `SYS_DEBUG_LOG` | `buf_ptr, buf_len` | `0` | OK | Write a message to the kernel log |
| 601 | `SYS_GETRANDOM` | `buf: u64, len: usize, flags: u32` | bytes written | OK | Fill a buffer with random bytes (`GRND_RANDOM` is accepted and ignored) |
| 610 | `SYS_SET_ROBUST_LIST` | `head: u64, len: usize` | `0` | OK | Set the robust futex list head |
| 611 | `SYS_GET_ROBUST_LIST` | `pid: i64, head_ptr, len_ptr` | `0` | OK | Get the robust futex list head |

---

## Module management

| # | Syscall | Kernel args | Return | Status | Description |
|---|---------|-------------|--------|--------|-------------|
| 700 | `SYS_MODULE_LOAD` | `fd_or_ptr: u64, len: u64` | module id | OK | Load a CMOD binary from a pointer or a file descriptor |
| 701 | `SYS_MODULE_UNLOAD` | `handle: u64` | `0` | OK | Unload a module |
| 702 | `SYS_MODULE_GET_SYMBOL` | `handle: u64, ordinal: u64` | symbol address | OK | Resolve a symbol **by ordinal index**, not by name |
| 703 | `SYS_MODULE_QUERY` | `handle: u64, out_ptr: u64` | `0` | OK | Write module metadata to `out_ptr` |

> The ABI header describes `SYS_MODULE_GET_SYMBOL` as taking a symbol *name* (`name_ptr`, `name_len`) and `SYS_MODULE_QUERY` as taking `(out_ptr, max_count)`. Neither matches the kernel. There is no name-based symbol lookup.

---

## Silo management

| # | Syscall | Kernel args | Return | Status | Description |
|---|---------|-------------|--------|--------|-------------|
| 800 | `SYS_SILO_CREATE` | `config_ptr: u64` | silo handle | OK | Create a silo from a `SiloConfig` struct |
| 801 | `SYS_SILO_CONFIG` | `handle: u64, res_ptr: u64` | `0` | OK | Apply a resource-limit descriptor |
| 802 | `SYS_SILO_ATTACH_MODULE` | `handle: u64, module_handle: u64` | `0` | OK | Attach a loaded module to a silo |
| 803 | `SYS_SILO_START` | `handle: u64` | `0` | OK | Start a silo |
| 804 | `SYS_SILO_STOP` | `handle: u64` | `0` | OK | Graceful stop |
| 805 | `SYS_SILO_KILL` | `handle: u64` | `0` | OK | Force stop |
| 806 | `SYS_SILO_EVENT_NEXT` | `event_ptr: u64` | `0` | OK | Write the next `SiloEvent` to `event_ptr`. Takes **no silo id** — the silo is derived from the caller |
| 807 | `SYS_SILO_SUSPEND` | `handle: u64` | `0` | OK | Suspend a silo |
| 808 | `SYS_SILO_RESUME` | `handle: u64` | `0` | OK | Resume a silo |
| 809 | `SYS_SILO_PLEDGE` | `mode_val: u64` | `0` | OK | Restrict syscalls. Takes the **octal mode value directly**, not a string pointer |
| 810 | `SYS_SILO_UNVEIL` | `path_ptr, path_len, rights_bits` | `0` | OK | Reveal a path. Rights are an `UnveilRights` **bitmask**, not a `"rwx"` string |
| 811 | `SYS_SILO_ENTER_SANDBOX` | : | `0` | OK | Enter sandbox mode (irreversible) |
| 812 | `SYS_SILO_RENAME` | `handle: u64, label_ptr, label_len` | `0` | OK | Rename a silo |

`SYS_SILO_UNVEIL` limits: path ≤ 1024 bytes, at most 128 unveil rules (`ENOBUFS` beyond that). Re-unveiling an existing path only ever **narrows** the rights.

---

## ABI version

| # | Syscall | Kernel args | Return | Status | Description |
|---|---------|-------------|--------|--------|-------------|
| 900 | `SYS_ABI_VERSION` | : | `(major << 16) \| minor` | OK | Returns `0x0000_0001` for the current `0.1` ABI |

---

## Common errno values

Authoritative list: `workspace/abi/src/errno.rs`, pinned by `workspace/abi/tests/errno_abi.rs`. Strat9 reuses Linux x86_64 numbering so musl/relibc map 1:1.

| Value | Name | Description |
|-------|------|-------------|
| 1 | `EPERM` | Operation not permitted |
| 2 | `ENOENT` | No such file or directory |
| 3 | `ESRCH` | No such process |
| 4 | `EINTR` | Interrupted system call |
| 5 | `EIO` | Input/output error |
| 7 | `E2BIG` | Argument list too long |
| 8 | `ENOEXEC` | Exec format error |
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
| 25 | `ENOTTY` | Not a typewriter |
| 28 | `ENOSPC` | No space left on device |
| 32 | `EPIPE` | Broken pipe |
| 34 | `ERANGE` | Result too large |
| 36 | `ENAMETOOLONG` | File name too long |
| 38 | `ENOSYS` | Function not implemented |
| 39 | `ENOTEMPTY` | Directory not empty |
| 40 | `ELOOP` | Too many levels of symbolic links |
| 95 | `ENOTSUP` | Not supported (== `EOPNOTSUPP`) |
| 97 | `EAFNOSUPPORT` | Address family not supported |
| 98 | `EADDRINUSE` | Address already in use |
| 105 | `ENOBUFS` | No buffer space available |
| 110 | `ETIMEDOUT` | Connection timed out |
| 111 | `ECONNREFUSED` | Connection refused |

`EMSGSIZE` (90) is also produced by the kernel's `SyscallError` enum but is not declared in `strat9_abi::errno`.

---

## Known gaps : ABI vs kernel

These are live inconsistencies between the ABI headers and the dispatcher. They are documented rather than fixed here, because the ABI is the compatibility contract and changing either side has userspace consequences.

### Syscalls that return `ENOSYS`

The number is defined in `strat9_abi::syscall` but the dispatcher has no arm for it, so the default branch logs `Unknown syscall` and returns `-ENOSYS`:

| # | Syscall |
|---|---------|
| 458 | `SYS_FSYNC` |
| 459 | `SYS_FDATASYNC` |
| 464 | `SYS_UNLINKAT` |
| 465 | `SYS_RENAMEAT` |
| 466 | `SYS_MKDIRAT` |
| 467 | `SYS_READLINKAT` |

`sys_fsync` / `sys_fdatasync` are implemented in `vfs/mod.rs` but never referenced by the dispatcher, so they are dead code today. The four `*at` variants have no handler at all.

### Argument-list mismatches

| Syscall | ABI header says | Kernel actually takes |
|---------|-----------------|------------------------|
| `SYS_PROC_EXECVE` (315) | `path_ptr, path_len, argv_ptr, envp_ptr` | `path_ptr, argv_ptr, envp_ptr` (path is NUL-terminated) |
| `SYS_MREMAP` (103) | `old_addr, old_len, new_len, flags, new_addr` | `old_addr, old_len, new_len, flags` |
| `SYS_IPC_SEND`/`RECV`/`TRY_RECV`/`CALL` | `+ msg_len` | no length: fixed 256-byte `IpcMessage` |
| `SYS_IPC_REPLY` (204) | `msg_ptr, msg_len` | `msg_ptr` |
| `SYS_IPC_BIND_PORT` (205) | `port_handle` | `port_handle, name_ptr, name_len` |
| `SYS_IPC_CONNECT` (208) | `port_handle` | `path_ptr, path_len` (by name) |
| `SYS_IPC_UNBIND_PORT` (206) | `port_handle` | `path_ptr, path_len` (by name) |
| `SYS_THREAD_CREATE` (341) | `entry, stack, arg` | `entry, stack_top, arg0, flags, tls_base` |
| `SYS_THREAD_JOIN` (342) | `tid, status_ptr` | `tid, status_ptr, flags` |
| `SYS_MODULE_GET_SYMBOL` (702) | `module_id, name_ptr, name_len` | `handle, ordinal` (no name lookup) |
| `SYS_MODULE_QUERY` (703) | `out_ptr, max_count` | `handle, out_ptr` |
| `SYS_SILO_CREATE` (800) | : | `config_ptr` |
| `SYS_SILO_CONFIG` (801) | `silo_id, key_ptr, key_len, val_ptr, val_len` | `handle, res_ptr` |
| `SYS_SILO_PLEDGE` (809) | `promises_ptr, promises_len` | `mode_val` (the octal value itself) |
| `SYS_SILO_UNVEIL` (810) | `path_ptr, path_len, perms_ptr, perms_len` | `path_ptr, path_len, rights_bits` |
| `SYS_SILO_EVENT_NEXT` (806) | `silo_id, out_ptr` | `event_ptr` (silo derived from caller) |
| `SYS_SILO_RENAME` (812) | `silo_id, name_ptr, name_len` | `handle, label_ptr, label_len` |
| `SYS_VOLUME_READ`/`WRITE` (420/421) | `offset` (bytes) | `sector` + `sector_count`, 512-byte sectors |
| `SYS_VOLUME_INFO` (422) | `handle, out_ptr` | `handle` (result in RAX) |
| `SYS_ASYNC_*` (250-254) | fd + event mask + context | io_uring-style ring id + entry counts |
| `SYS_FSTATAT` (463) | documented `AT_SYMLINK_NOFOLLOW` | that constant does not exist; the `flags` argument is dropped |
| `SYS_FACCESSAT` (468) | `flags` | read from `r8` and then ignored |
| `SYS_SIGQUEUE` (327) | `sigval_ptr` | `sigval_ptr` accepted and ignored |

### Behaviour that differs from the documented contract

- **`SYS_POLL` / `SYS_PPOLL`** — `timeout` is ignored in both; the dispatcher maps `SYS_PPOLL` onto `sys_poll(fds_ptr, nfds, 0)`, discarding the timespec and the signal mask.
- **`SYS_IOCTL` (443)** — a stub that always returns `ENOTTY`. No TTY or driver-specific ioctl exists.
- **`SYS_ASYNC_CANCEL` (252)** — always returns `ENOSYS`.
- **`SYS_NULL` (0)** — returns the magic value `0x57A79`, not `0`.
- **`SYS_PROC_EXECVE` (315)** — refuses (`ENOTSUP`) when the calling process has more than one thread.
- **`SYS_PROC_WAITPID` (310)** — accepts only `WNOHANG`; `WUNTRACED` / `WCONTINUED` give `EINVAL`.
- **`SYS_FACCESSAT` (468)** — the `flags` argument is read from `r8` (the 5th syscall register) and then ignored.
- **Register order in the ABI header is wrong** — it documents `RDI, RSI, RDX, R8, R9, R10`, but the dispatcher reads `RDI, RSI, RDX, R10, R8, R9`. Code that follows the header comment will pass arguments 4 and 5 in the wrong registers.
- **`SYS_ACCESS` (413)** — checks the process's **real** UID/GID against the file's owner, group and other permission bits and returns `EACCES` if any requested bit is missing, matching POSIX `access()` semantics. There is no user database behind those IDs, so the practical effect depends on how the file's `st_uid` / `st_gid` were set. `SYS_FACCESSAT` is still preferable: it additionally applies the calling silo's unveil rules before the stat, so it avoids a TOCTOU race against the CWD.

### `ENOTSUP` numbering

`strat9_abi::errno::ENOTSUP` is `95`, aligned with Linux `EOPNOTSUPP`, and the ABI test suite pins that value. The kernel's `SyscallError::NotSupported` in `kernel/src/syscall/error.rs` is still `-52`, so the kernel currently emits a value the ABI does not define. `SyscallError` also lacks entries for `ELOOP`, `EAFNOSUPPORT`, `EADDRINUSE` and `ECONNREFUSED`, which the ABI does define. This affects `SYS_PROC_EXECVE`'s multithreaded rejection and anything else that maps to `NotSupported`.

### `MapFlags` vs the kernel's `MAP_*`

`strat9_abi::flag::MapFlags` declares `MAP_NORESERVE`, `MAP_GROWSDOWN`, `MAP_LOCKED` and `MAP_POPULATE`. `sys_mmap` validates flags against a narrower set and returns `EINVAL` for those bits. Write mmap callers against the table in [Memory-map flags](#memory-map-flags--map-mmap), not against `MapFlags`.

---

## See also

- [Syscall Layer](./syscall.md) — the userspace `strat9-syscall` crate
- [ABI Overview](./abi.md) — where the definitions live
- [ABI Changelog](./abi-changelog.md) — ABI evolution
- [IPC Mechanisms](./ipc-mechanisms.md) — transport levels and selection policy
- [ABI Support Matrix](./abi-matrix.md) — POSIX API coverage
