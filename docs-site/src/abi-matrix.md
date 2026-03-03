# ABI Support Matrix

Status of relibc platform APIs on `x86_64-unknown-strat9`.

Legend: **OK** = implemented, **Stub** = returns ENOSYS, **Partial** = limited.

## POSIX File I/O

| API | Status | Notes |
|-----|--------|-------|
| open / openat | OK | Via SYS_OPEN |
| read | OK | Via SYS_READ |
| write | OK | Via SYS_WRITE |
| close | OK | Via SYS_CLOSE |
| lseek | OK | Via SYS_LSEEK |
| pread | OK | Via SYS_PREAD |
| pwrite | OK | Via SYS_PWRITE |
| fstat / fstatat | OK | Via SYS_FSTAT / SYS_STAT |
| dup / dup2 | OK | Via SYS_DUP / SYS_DUP2 |
| pipe / pipe2 | OK | Via SYS_PIPE |
| fcntl | OK | Via SYS_FCNTL |
| mkdir / mkdirat | OK | Via SYS_MKDIR |
| unlink | OK | Via SYS_UNLINK |
| rmdir | OK | Via SYS_RMDIR |
| rename / renameat | OK | Via SYS_RENAME |
| link | OK | Via SYS_LINK |
| symlink | OK | Via SYS_SYMLINK |
| readlink | OK | Via SYS_READLINK |
| chmod / fchmod | OK | Via SYS_CHMOD / SYS_FCHMOD |
| truncate / ftruncate | OK | Via SYS_TRUNCATE / SYS_FTRUNCATE |
| chdir / fchdir | OK | Via SYS_CHDIR / SYS_FCHDIR |
| getcwd | OK | Via SYS_GETCWD |
| getdents | OK | Via SYS_GETDENTS |
| access | OK | Open + close probe |
| umask | OK | Via SYS_UMASK |
| fsync / fdatasync | Stub | ENOSYS |
| flock | Stub | ENOSYS |
| chown / fchown / lchown | Stub | ENOSYS |
| statvfs / fstatvfs | Stub | ENOSYS |
| mknod / mknodat / mkfifoat | Stub | ENOSYS |

## Process Management

| API | Status | Notes |
|-----|--------|-------|
| exit | OK | Via SYS_PROC_EXIT |
| fork | OK | Via SYS_PROC_FORK |
| execve | OK | Via SYS_PROC_EXEC |
| waitpid | OK | Via SYS_PROC_WAITPID |
| getpid / getppid / gettid | OK | |
| setsid / setpgid / getpgid / getsid | OK | |
| sched_yield | OK | Via SYS_PROC_YIELD |
| nanosleep | OK | Via SYS_NANOSLEEP |
| clock_gettime | OK | Via SYS_CLOCK_GETTIME |
| brk | OK | Via SYS_BRK |
| mmap / munmap | OK | Via SYS_MMAP / SYS_MUNMAP |
| uname | OK | Via SYS_PROC_UNAME |
| getuid / geteuid / getgid / getegid | Partial | Returns 0 (no UID model) |
| mprotect / mlock / munlock | Stub | ENOSYS |
| getrandom | Stub | ENOSYS |

## Signals

| API | Status | Notes |
|-----|--------|-------|
| kill | OK | Via SYS_KILL |
| sigaction | OK | Via SYS_SIGACTION |
| sigprocmask | OK | Via SYS_SIGPROCMASK |
| sigsuspend | OK | Via SYS_SIGSUSPEND |
| sigtimedwait | OK | Via SYS_SIGTIMEDWAIT |
| getitimer / setitimer | OK | Via SYS_GETITIMER / SYS_SETITIMER |
| sigaltstack | OK | Via SYS_SIGALTSTACK |

## Network / Sockets

| API | Status | Notes |
|-----|--------|-------|
| socketpair (AF_UNIX) | Partial | Backed by pipe (unidirectional) |
| recvfrom / sendto | Partial | Delegates to read/write |
| socket / bind / listen / accept / connect | Stub | ENOSYS |
| setsockopt / getsockopt | Stub | ENOSYS |
| shutdown | Stub | ENOSYS |

## Epoll

| API | Status | Notes |
|-----|--------|-------|
| epoll_create1 | Partial | Backed by pipe fd |
| epoll_ctl | Stub | No-op |
| epoll_pwait | Partial | Sleeps, no real multiplexing |
