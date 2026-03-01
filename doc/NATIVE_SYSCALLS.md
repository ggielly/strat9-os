# strat9-os native syscalls reference

Syscall numbers follow the block layout defined in `docs/ABI_STRAT9-OS_DESIGN.md`.
Calling convention: `rax` = syscall number, `rdi`/`rsi`/`rdx`/`r10`/`r8`/`r9` = args 1-6,
return value in `rax`. `rcx` and `r11` are clobbered by the CPU.

Constants are defined in `kernel/src/syscall/numbers.rs`.

---

## Block 0-99: handle / capability management

| # | Name | Args | Description |
|---|------|------|-------------|
| 0 | `SYS_NULL` | none | Ping/test. Returns `0xCA5CAD3`. |
| 1 | `SYS_HANDLE_DUPLICATE` | handle: u32 | Duplicate a handle (grant right required). |
| 2 | `SYS_HANDLE_CLOSE` | handle: u32 | Close a handle. |
| 3 | `SYS_HANDLE_WAIT` | handle: u32, timeout_ns: u64 | Wait on a handle for an event. |
| 4 | `SYS_HANDLE_GRANT` | handle: u32, target_pid: u64 | Grant a handle to another process. |
| 5 | `SYS_HANDLE_REVOKE` | handle: u32 | Revoke a previously granted handle. |
| 6 | `SYS_HANDLE_INFO` | handle: u32, out_ptr: *mut HandleInfo | Query handle type and rights. |

---

## Block 100-199: memory mmanagement

| # | Name | Args | Description |
|---|------|------|-------------|
| 100 | `SYS_MEM_MAP` | addr: u64, size: u64, flags: u32 | Map anonymous pages (mmap-like). |
| 101 | `SYS_MEM_UNMAP` | addr: u64, size: u64 | Unmap a memory region. |
| 102 | `SYS_MEM_PROTECT` | addr: u64, size: u64, flags: u32 | Change page protections. |
<!-- SYS_MEM_ALLOC (brk) removed in v2.1: Libc must map anonymous pages via SYS_MEM_MAP -->
| 104 | `SYS_MEM_GRANT` | addr: u64, size: u64, target_pid: u64 | Grant a memory region to another process via capability. |

---

## Block 200-299: IPC

| # | Name | Args | Description |
|---|------|------|-------------|
| 200 | `SYS_IPC_CREATE_PORT` | flags: u32 | Create an IPC port (returns handle). |
| 201 | `SYS_IPC_SEND` | port_handle: u32, msg_ptr: *const IpcMessage | Send a 64-byte inline message. |
| 202 | `SYS_IPC_RECV` | port_handle: u32, msg_ptr: *mut IpcMessage | Receive a message (blocks if empty). |
| 203 | `SYS_IPC_CALL` | port_handle: u32, msg_ptr: *mut IpcMessage | Send + receive (synchronous RPC). |
| 204 | `SYS_IPC_REPLY` | msg_ptr: *const IpcMessage | Reply to an incoming call. |
| 205 | `SYS_NS_BIND` | scheme_handle: u32, path_ptr: *const u8, len: u64 | Bind a Scheme handle to a namespace path. |
| 206 | `SYS_NS_UNBIND` | path_ptr: *const u8, len: u64 | Remove a binding from the namespace. |
| 210 | `SYS_IPC_RING_CREATE` | size: u64 | Allocate a shared-memory ring buffer (returns handle). |
| 211 | `SYS_IPC_RING_MAP` | ring_handle: u32, out_ptr: *mut u64 | Map a ring buffer into caller's address space. |
| 220 │ `SYS_CHAN_CREATE`  │ Crée un canal, retourne un handle capability |
| 221 │ `SYS_CHAN_SEND`    │ Envoie un IpcMessage (bloquant si plein). |
| 222 │ `SYS_CHAN_RECV`     │ Reçoit un IpcMessage (bloquant si vide)  |
| 223 │ `SYS_CHAN_TRY_RECV` │ Reçoit sans bloquer (EAGAIN si vide)    |
| 224 │ `SYS_CHAN_CLOSE`    │ Détruit le canal, réveille tous les waiters |


---

## Block 300-399: process / thread

| # | Name | Args | Description |
|---|------|------|-------------|
| 300 | `SYS_PROC_EXIT` | exit_code: u64 | Terminate the current process. |
| 301 | `SYS_PROC_YIELD` | none | Yield the current time slice. |
| 302 | `SYS_PROC_CREATE` | elf_handle: u32, flags: u32 | Create a task (low-level). See Block 800 for Silos. |
| 303 | `SYS_PROC_WAIT` | pid: u64 | Wait for a child task. |
| 304 | `SYS_PROC_KILL` | pid: u64, signal: u32 | Send a signal. |

---

## Block 320-330: signal & timer Management

| # | Name | Args | Description |
|---|------|------|-------------|
| 320 | `SYS_KILL` | task_id: u64, signal: u32 | Send a signal to a task. |
| 321 | `SYS_SIGPROCMASK` | how: i32, set_ptr: *const sigset_t, oldset_ptr:*mut sigset_t | Examine and change blocked signals. |
| 322 | `SYS_SIGACTION` | signum: u32, act_ptr: *const sigaction, oact_ptr:*mut sigaction | Set up a signal handler. |
| 323 | `SYS_SIGALTSTACK` | ss_ptr: *const stack_t, old_ss_ptr:*mut stack_t | Set/get signal alternate stack. |
| 324 | `SYS_SIGPENDING` | set_ptr: *mut sigset_t | Check for pending signals. |
| 325 | `SYS_SIGSUSPEND` | mask_ptr: *const sigset_t | Wait for signals. |
| 326 | `SYS_SIGTIMEDWAIT` | set_ptr: *const sigset_t, siginfo_ptr:*mut siginfo_t, timeout_ptr: *const timespec | Wait for signals with timeout. |
| 327 | `SYS_SIGQUEUE` | task_id: u64, signum: u32, sigval_ptr: *const sigval | Send signal with value. |
| 328 | `SYS_KILLPG` | pgrp: u64, signum: u32 | Send signal to process group. |
| 329 | `SYS_GETITIMER` | which: u32, value_ptr: *mut itimerval | Get interval timer value (ITIMER_REAL/VIRTUAL/PROF). |
| 330 | `SYS_SETITIMER` | which: u32, new_value_ptr: *const itimerval, old_value_ptr:*mut itimerval | Set interval timer value. |

---

## Block 400-499: namespace / VFS (resolvers)

| # | Name | Description |
|---|------|-------------|
| 403 | `SYS_OPEN` | Resolve a path to a handle via IPC to VFS/Scheme. |
| 404 | `SYS_WRITE` | Write to a handle (IPC backend). |
| 405 | `SYS_READ` | Read from a handle (IPC backend). |
| 406 | `SYS_CLOSE` | Close a handle (IPC backend). |

---

## Block 420-429: volume / block devices

| # | Name | Args | Description |
|---|------|------|-------------|
| 420 | `SYS_VOLUME_READ` | handle: u32, sector: u64, buf_ptr: *mut u8, sector_count: u64 | Read sectors from a volume handle. |
| 421 | `SYS_VOLUME_WRITE` | handle: u32, sector: u64, buf_ptr: *const u8, sector_count: u64 | Write sectors to a volume handle. |
| 422 | `SYS_VOLUME_INFO` | handle: u32 | Return total sector count for a volume. |

---

---

## Block 500-599: time & alarms <!-- NEW -->

| # | Name | Args | Description |
|---|------|------|-------------|
| 500 | `SYS_TIME_MONOTONIC` | none | Get monotonic time (nanoseconds since boot). |
| 501 | `SYS_TIME_REALTIME` | none | Get wall-clock time (nanoseconds since UNIX epoch). |
| 502 | `SYS_ALARM_SET` | nsecs: u64, event_id: u64 | Wake up/Trigger event after `nsecs`. |
| 503 | `SYS_ALARM_CANCEL` | event_id: u64 | Cancel a pending alarm. |
| 504 | `SYS_YIELD_UNTIL` | nsecs: u64 | Sleep until a specifc monotonic timestamp. |

---

## Block 700-799: module management (.cmod)

| # | Name | Args | Description |
|---|------|------|-------------|
| 700 | `SYS_MODULE_LOAD` | fd: u32 | Load a .cmod from an open file handle. Returns ModuleHandle. |
| 701 | `SYS_MODULE_UNLOAD` | handle: u32 | Unload a module (decrement refcount). |
| 702 | `SYS_MODULE_GET_SYMBOL` | handle: u32, ordinal: u32 | Resolve an export to a Virtual Address. |
| 703 | `SYS_MODULE_QUERY` | handle: u32, out_ptr: *mut ModuleInfo | Query module metadata. |

---

## Block 800-899: silo management (container/isolation)

| # | Name | Args | Description |
|---|------|------|-------------|
| 800 | `SYS_SILO_CREATE` | flags: u32 | Create a new empty Silo. Returns SiloHandle. |
| 801 | `SYS_SILO_CONFIG` | handle: u32, config_ptr: *const SiloConfig | Set resource limits (RAM, CPU). |
| 802 | `SYS_SILO_ATTACH_MODULE` | silo: u32, module: u32 | Set the entry point module for the Silo. |
| 803 | `SYS_SILO_START` | handle: u32 | Transition Silo to `Running`. |
| 804 | `SYS_SILO_STOP` | handle: u32 | Request graceful stop. |
| 805 | `SYS_SILO_KILL` | handle: u32 | Force immediate termination. |
| 806 | `SYS_SILO_EVENT_NEXT` | out_ptr: *mut SiloEvent | Pop the next lifecycle event (Crash, Stop). |
| 807 | `SYS_SILO_SUSPEND` | handle: u32 | Suspend execution (Debug/Migration). |
| 808 | `SYS_SILO_RESUME` | handle: u32 | Resume execution. |

---
