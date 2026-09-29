# ABI Support Matrix

Status of POSIX platform APIs on the Strat9 OS x86_64 target, as implemented by the `musl-compat` shim (`workspace/components/musl-compat/src/lib.rs`) and the kernel dispatcher it targets.

Legend: **OK** = mapped to a working syscall · **Broken** = mapped to a syscall whose kernel handler is missing or stubbed, so the call returns `ENOSYS` at runtime · **Stub** = the shim itself returns `ENOSYS` · **Partial** = reachable but semantically degraded.

> **Read the shim argument lists.** The shim does not pass the same number of arguments as the kernel handler for several calls. A mapping marked **OK** here means "the syscall number is reachable", not "the call is correct". See [Argument-count mismatches](#argument-count-mismatches) below and the [Syscall Reference → Known gaps](./syscalls.md#known-gaps--abi-vs-kernel) page.

## POSIX File I/O

| API | Status | Notes |
|-----|--------|-------|
| open | OK | Via `SYS_OPEN`; `O_*` flags translated by `posix_oflags_to_strat9()` |
| openat | OK | Via `SYS_OPENAT`, same flag translation |
| read / write | OK | Via `SYS_READ` / `SYS_WRITE` |
| close | OK | Via `SYS_CLOSE` |
| lseek | OK | Via `SYS_LSEEK` |
| pread / pwrite | OK | Via `SYS_PREAD` / `SYS_PWRITE` |
| fstat | OK | Via `SYS_FSTAT` |
| stat | **Broken** | Mapped to `SYS_STAT` with 2 args; the handler takes 3 (`path_ptr, path_len, stat_ptr`) |
| lstat | **Broken** | Same call as `stat`, and it deliberately does not follow symlinks |
| newfstatat / fstatat | OK | Via `SYS_FSTATAT`. `AT_SYMLINK_NOFOLLOW` is ignored by the kernel |
| mkdirat | **Broken** | Mapped to `SYS_MKDIRAT`, which has no dispatcher arm |
| unlinkat | **Broken** | Mapped to `SYS_UNLINKAT`, which has no dispatcher arm |
| renameat | **Broken** | Mapped to `SYS_RENAMEAT`, which has no dispatcher arm |
| readlinkat | **Broken** | Mapped to `SYS_READLINKAT`, which has no dispatcher arm |
| faccessat / faccessat2 | OK | Via `SYS_FACCESSAT` |
| access | OK | Via `SYS_ACCESS`. Checks the process's real UID/GID against the file's permission bits |
| dup / dup2 | OK | Via `SYS_DUP` / `SYS_DUP2` |
| pipe | OK | Via `SYS_PIPE`. No `pipe2` |
| fcntl | OK | Via `SYS_FCNTL` |
| getdents | OK | Via `SYS_GETDENTS` |
| poll / ppoll | Partial | Mapped, but `sys_poll` ignores the timeout and reports `POLLIN` for any open fd |
| ioctl | **Broken** | Mapped to `SYS_IOCTL`, which is a stub returning `ENOTTY` for every fd |
| mkdir / unlink / rmdir | **Broken** | Mapped with too few arguments (`SYS_MKDIR` takes 3, `SYS_UNLINK`/`SYS_RMDIR` take 2) |
| rename / link / symlink | **Broken** | Mapped with 2 args; the handlers take 4 |
| readlink | **Broken** | Mapped with 3 args; the handler takes 4 |
| chmod / fchmod | **Broken** / OK | `SYS_CHMOD` is called with 2 args (handler takes 3); `SYS_FCHMOD` is called correctly |
| truncate | **Broken** | Mapped with 2 args; the handler takes 3. `ftruncate` is OK |
| chdir / fchdir | **Broken** / OK | `SYS_CHDIR` is called with 1 arg (handler takes 2); `SYS_FCHDIR` is OK |
| getcwd | OK | Via `SYS_GETCWD` |
| umask | OK | Via `SYS_UMASK` |
| fsync / fdatasync | Stub | The shim returns `ENOSYS`; the kernel handlers exist in `vfs/mod.rs` but are not dispatched |
| flock | Stub | `ENOSYS` |
| chown / fchown / lchown | Stub | `ENOSYS` |
| statvfs / fstatvfs | Stub | `ENOSYS` |
| mknod / mknodat / mkfifoat | Stub | `ENOSYS` |

## Memory management

| API | Status | Notes |
|-----|--------|-------|
| mmap / munmap | OK | Anonymous and `MAP_PRIVATE` file-backed only; file-backed `MAP_SHARED` returns `ENOSYS` |
| mprotect | OK | Via `SYS_MPROTECT` |
| mremap | OK | Mapped, but with 4 args; `new_addr` is not passed through |
| brk | OK | Via `SYS_BRK` |
| mlock / munlock | Stub | `ENOSYS`. `MAP_LOCKED` and `MAP_POPULATE` are rejected by `sys_mmap` |
| madvise | Stub | `ENOSYS` |

## Process management

| API | Status | Notes |
|-----|--------|-------|
| exit | OK | Via `SYS_PROC_EXIT` |
| exit_group | OK | Via `SYS_EXIT_GROUP` |
| fork | OK | Via `SYS_PROC_FORK`; also reached through `clone` without `CLONE_THREAD` |
| clone (threaded) | OK | `CLONE_THREAD` is routed to `SYS_THREAD_CREATE` with 5 arguments; `CLONE_PARENT_SETTID` writes the child TID back to `*ptid` in the shim |
| execve | Partial | Via `SYS_PROC_EXECVE`. Refuses with `ENOTSUP` when the process is multithreaded |
| wait4 | OK | Via `SYS_PROC_WAITPID`; only `WNOHANG` is accepted by the kernel |
| getpid / getppid / gettid | OK | |
| getuid / geteuid / getgid / getegid | Partial | Return the process's stored IDs. There is no user database and no authorization model |
| setuid / setgid | Partial | Same caveat: no privilege model behind them |
| setsid / setpgid / getpgid / getpgrp / getsid | OK | |
| sched_yield | OK | Via `SYS_PROC_YIELD` |
| uname | OK | Via `SYS_UNAME`; writes 6 fixed 65-byte fields |
| nanosleep | OK | Via `SYS_NANOSLEEP` |
| clock_gettime | OK | Only `CLOCK_REALTIME` and `CLOCK_MONOTONIC` are valid; other clock ids give `EINVAL` |
| clock_getres | **Broken** | The shim returns success `0` without writing anything to the caller's `res` pointer |
| clock_nanosleep | OK | Via `SYS_CLOCK_NANOSLEEP`, `TIMER_ABSTIME` supported |
| pause | Partial | Approximated as `SYS_SIGSUSPEND(NULL)` |
| getrandom | OK | Via `SYS_GETRANDOM`; `GRND_RANDOM` is accepted and ignored |
| arch_prctl | OK | `ARCH_SET_FS` / `ARCH_GET_FS`; other codes give `EINVAL` |

## Signals

| API | Status | Notes |
|-----|--------|-------|
| kill | OK | Via `SYS_KILL` |
| tkill / tgkill | OK | Both routed to `SYS_TGKILL` |
| rt_sigaction | OK | Via `SYS_SIGACTION` |
| rt_sigprocmask | OK | Via `SYS_SIGPROCMASK` |
| rt_sigpending | OK | Via `SYS_SIGPENDING` |
| rt_sigsuspend | OK | Via `SYS_SIGSUSPEND` |
| rt_sigtimedwait | OK | Via `SYS_SIGTIMEDWAIT` |
| rt_sigreturn | OK | Via `SYS_RT_SIGRETURN` |
| sigaltstack | OK | Via `SYS_SIGALTSTACK` |
| getitimer / setitimer | OK | Via `SYS_GETITIMER` / `SYS_SETITIMER` |
| sigqueue | Partial | `sigval_ptr` is accepted and then ignored by the kernel handler |

## Thread-local storage

musl's TLS bootstrap needs these, so they are covered explicitly.

| API | Status | Notes |
|-----|--------|-------|
| set_tid_address | OK | Via `SYS_SET_TID_ADDRESS` |
| set_robust_list / get_robust_list | OK | Via `SYS_SET_ROBUST_LIST` / `SYS_GET_ROBUST_LIST` |
| arch_prctl(FS) | OK | Required for `errno` in TLS |

## Network / Sockets

**No BSD socket API exists.** The shim's design comment describes a future Plan 9 `/net/tcp` scheme mapping, but until `strate-net` exposes it every socket entry point returns `ENOSYS`. Networked programs use the `/dev/net` raw-packet scheme or the `strate-net` scheme API instead of sockets.

| API | Status | Notes |
|-----|--------|-------|
| socket | Stub | `ENOSYS` |
| socketpair | Stub | `ENOSYS` — *not* backed by a pipe |
| bind / listen / accept / connect | Stub | `ENOSYS` |
| sendto / recvfrom | Stub | `ENOSYS` — *not* delegated to read/write |
| sendmsg / recvmsg | Stub | `ENOSYS` |
| setsockopt / getsockopt | Stub | `ENOSYS` |
| getsockname / getpeername | Stub | `ENOSYS` |
| shutdown | Stub | `ENOSYS` |

## Epoll

There is no epoll support. The shim has no `LNR_epoll_*` arm, so every entry falls through to the catch-all `ENOSYS` return.

| API | Status | Notes |
|-----|--------|-------|
| epoll_create / epoll_create1 | Stub | `ENOSYS` — *not* backed by a pipe |
| epoll_ctl | Stub | `ENOSYS` |
| epoll_wait / epoll_pwait | Stub | `ENOSYS` |

Use `SYS_POLL` (a non-blocking readiness snapshot) or the async ring (`SYS_ASYNC_*`) instead.

## Argument-count mismatches

These mappings pass fewer arguments than the kernel handler reads, so the handler sees a garbage value in the trailing register(s):

| Shim call | Args passed | Args the handler reads |
|------------|-------------|----------------------|
| `stat` / `lstat` → `SYS_STAT` | 2 | 3 |
| `chdir` → `SYS_CHDIR` | 1 | 2 |
| `unlink` → `SYS_UNLINK` | 1 | 2 |
| `rmdir` → `SYS_RMDIR` | 1 | 2 |
| `mkdir` → `SYS_MKDIR` | 2 | 3 |
| `rename` → `SYS_RENAME` | 2 | 4 |
| `link` → `SYS_LINK` | 2 | 4 |
| `symlink` → `SYS_SYMLINK` | 2 | 4 |
| `readlink` → `SYS_READLINK` | 3 | 4 |
| `chmod` → `SYS_CHMOD` | 2 | 3 |
| `truncate` → `SYS_TRUNCATE` | 2 | 3 |
| `mremap` → `SYS_MREMAP` | 4 | 4 (no `new_addr` — documented, but callers must not expect it to be honoured) |

Additionally, the shim routes `mkdirat`, `unlinkat`, `renameat` and `readlinkat` to syscall numbers the kernel does not dispatch, so they always return `ENOSYS` regardless of argument count.

## See also

- [Syscall Reference](./syscalls.md) — numbers, kernel argument lists, and the full gap list
- [Syscall Layer](./syscall.md) — the `strat9-syscall` crate used by native userspace
- [ABI Overview](./abi.md) · [ABI Changelog](./abi-changelog.md)
