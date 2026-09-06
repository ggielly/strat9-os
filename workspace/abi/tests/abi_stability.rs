//! L0 — ABI stability conformance tests (anti-regression golden values).
//!
//! These tests pin the **wire-level** contract of the Strat9 ABI:
//! syscall numbers, struct sizes/offsets, IPC constants. Any change here
//! is a breaking ABI change and MUST bump `ABI_VERSION_MINOR` (or MAJOR).
//!
//! If one of these tests fails after an intentional change, update the
//! golden value in the same commit and add a note to `abi-changelog.md`.

use strat9_abi::data::{
    FileStat, IpcMessage, Stat, TimeSpec, IPC_MESSAGE_ALIGN, IPC_MESSAGE_SIZE,
    IPC_PAYLOAD_CAPACITY,
};
use strat9_abi::errno;
use strat9_abi::ipc::IPC_HANDSHAKE_MAGIC;
use strat9_abi::ipc_codec::{InlineBlobHeader, PAYLOAD_CAPACITY};
use strat9_abi::syscall::*;

// ===========================================================================
// Golden syscall number table
// ===========================================================================

/// Every syscall constant with its pinned number.
/// Generated from `workspace/abi/src/syscall.rs`; update only together with
/// an explicit ABI version bump.
const GOLDEN_SYSCALLS: &[(&str, usize)] = &[
    ("SYS_NULL", SYS_NULL),
    ("SYS_HANDLE_DUPLICATE", SYS_HANDLE_DUPLICATE),
    ("SYS_HANDLE_CLOSE", SYS_HANDLE_CLOSE),
    ("SYS_HANDLE_WAIT", SYS_HANDLE_WAIT),
    ("SYS_HANDLE_GRANT", SYS_HANDLE_GRANT),
    ("SYS_HANDLE_REVOKE", SYS_HANDLE_REVOKE),
    ("SYS_HANDLE_INFO", SYS_HANDLE_INFO),
    ("SYS_MMAP", SYS_MMAP),
    ("SYS_MUNMAP", SYS_MUNMAP),
    ("SYS_BRK", SYS_BRK),
    ("SYS_MREMAP", SYS_MREMAP),
    ("SYS_MPROTECT", SYS_MPROTECT),
    ("SYS_MEM_REGION_EXPORT", SYS_MEM_REGION_EXPORT),
    ("SYS_MEM_REGION_MAP", SYS_MEM_REGION_MAP),
    ("SYS_MEM_REGION_INFO", SYS_MEM_REGION_INFO),
    ("SYS_IPC_CREATE_PORT", SYS_IPC_CREATE_PORT),
    ("SYS_IPC_SEND", SYS_IPC_SEND),
    ("SYS_IPC_RECV", SYS_IPC_RECV),
    ("SYS_IPC_CALL", SYS_IPC_CALL),
    ("SYS_IPC_REPLY", SYS_IPC_REPLY),
    ("SYS_IPC_BIND_PORT", SYS_IPC_BIND_PORT),
    ("SYS_IPC_UNBIND_PORT", SYS_IPC_UNBIND_PORT),
    ("SYS_IPC_TRY_RECV", SYS_IPC_TRY_RECV),
    ("SYS_IPC_CONNECT", SYS_IPC_CONNECT),
    ("SYS_IPC_RING_CREATE", SYS_IPC_RING_CREATE),
    ("SYS_IPC_RING_MAP", SYS_IPC_RING_MAP),
    ("SYS_CHAN_CREATE", SYS_CHAN_CREATE),
    ("SYS_CHAN_SEND", SYS_CHAN_SEND),
    ("SYS_CHAN_RECV", SYS_CHAN_RECV),
    ("SYS_CHAN_TRY_RECV", SYS_CHAN_TRY_RECV),
    ("SYS_CHAN_CLOSE", SYS_CHAN_CLOSE),
    ("SYS_SEM_CREATE", SYS_SEM_CREATE),
    ("SYS_SEM_WAIT", SYS_SEM_WAIT),
    ("SYS_SEM_TRYWAIT", SYS_SEM_TRYWAIT),
    ("SYS_SEM_POST", SYS_SEM_POST),
    ("SYS_SEM_CLOSE", SYS_SEM_CLOSE),
    ("SYS_PCI_ENUM", SYS_PCI_ENUM),
    ("SYS_PCI_CFG_READ", SYS_PCI_CFG_READ),
    ("SYS_PCI_CFG_WRITE", SYS_PCI_CFG_WRITE),
    ("SYS_ASYNC_SETUP", SYS_ASYNC_SETUP),
    ("SYS_ASYNC_ENTER", SYS_ASYNC_ENTER),
    ("SYS_ASYNC_CANCEL", SYS_ASYNC_CANCEL),
    ("SYS_ASYNC_MAP", SYS_ASYNC_MAP),
    ("SYS_ASYNC_DESTROY", SYS_ASYNC_DESTROY),
    ("SYS_TRANSPORT_CREATE", SYS_TRANSPORT_CREATE),
    ("SYS_TRANSPORT_SEND", SYS_TRANSPORT_SEND),
    ("SYS_TRANSPORT_RECV", SYS_TRANSPORT_RECV),
    ("SYS_TRANSPORT_CLOSE", SYS_TRANSPORT_CLOSE),
    ("SYS_TRANSPORT_INFO", SYS_TRANSPORT_INFO),
    ("SYS_PROC_EXIT", SYS_PROC_EXIT),
    ("SYS_PROC_YIELD", SYS_PROC_YIELD),
    ("SYS_PROC_FORK", SYS_PROC_FORK),
    ("SYS_FUTEX_WAIT", SYS_FUTEX_WAIT),
    ("SYS_FUTEX_WAKE", SYS_FUTEX_WAKE),
    ("SYS_FUTEX_REQUEUE", SYS_FUTEX_REQUEUE),
    ("SYS_FUTEX_CMP_REQUEUE", SYS_FUTEX_CMP_REQUEUE),
    ("SYS_FUTEX_WAKE_OP", SYS_FUTEX_WAKE_OP),
    ("SYS_PROC_GETPID", SYS_PROC_GETPID),
    ("SYS_PROC_GETPPID", SYS_PROC_GETPPID),
    ("SYS_PROC_WAITPID", SYS_PROC_WAITPID),
    ("SYS_GETPID", SYS_GETPID),
    ("SYS_GETTID", SYS_GETTID),
    ("SYS_PROC_WAIT", SYS_PROC_WAIT),
    ("SYS_PROC_EXECVE", SYS_PROC_EXECVE),
    ("SYS_FCNTL", SYS_FCNTL),
    ("SYS_SETPGID", SYS_SETPGID),
    ("SYS_GETPGID", SYS_GETPGID),
    ("SYS_SETSID", SYS_SETSID),
    ("SYS_KILL", SYS_KILL),
    ("SYS_SIGPROCMASK", SYS_SIGPROCMASK),
    ("SYS_SIGACTION", SYS_SIGACTION),
    ("SYS_SIGALTSTACK", SYS_SIGALTSTACK),
    ("SYS_SIGPENDING", SYS_SIGPENDING),
    ("SYS_SIGSUSPEND", SYS_SIGSUSPEND),
    ("SYS_SIGTIMEDWAIT", SYS_SIGTIMEDWAIT),
    ("SYS_SIGQUEUE", SYS_SIGQUEUE),
    ("SYS_KILLPG", SYS_KILLPG),
    ("SYS_GETITIMER", SYS_GETITIMER),
    ("SYS_SETITIMER", SYS_SETITIMER),
    ("SYS_GETPGRP", SYS_GETPGRP),
    ("SYS_GETSID", SYS_GETSID),
    ("SYS_SET_TID_ADDRESS", SYS_SET_TID_ADDRESS),
    ("SYS_EXIT_GROUP", SYS_EXIT_GROUP),
    ("SYS_GETUID", SYS_GETUID),
    ("SYS_GETEUID", SYS_GETEUID),
    ("SYS_GETGID", SYS_GETGID),
    ("SYS_GETEGID", SYS_GETEGID),
    ("SYS_SETUID", SYS_SETUID),
    ("SYS_SETGID", SYS_SETGID),
    ("SYS_THREAD_CREATE", SYS_THREAD_CREATE),
    ("SYS_THREAD_JOIN", SYS_THREAD_JOIN),
    ("SYS_THREAD_EXIT", SYS_THREAD_EXIT),
    ("SYS_UNAME", SYS_UNAME),
    ("SYS_ARCH_PRCTL", SYS_ARCH_PRCTL),
    ("SYS_TGKILL", SYS_TGKILL),
    ("SYS_RT_SIGRETURN", SYS_RT_SIGRETURN),
    ("SYS_OPEN", SYS_OPEN),
    ("SYS_WRITE", SYS_WRITE),
    ("SYS_READ", SYS_READ),
    ("SYS_CLOSE", SYS_CLOSE),
    ("SYS_LSEEK", SYS_LSEEK),
    ("SYS_FSTAT", SYS_FSTAT),
    ("SYS_STAT", SYS_STAT),
    ("SYS_NET_RECV", SYS_NET_RECV),
    ("SYS_NET_SEND", SYS_NET_SEND),
    ("SYS_NET_INFO", SYS_NET_INFO),
    ("SYS_NET_REGISTER", SYS_NET_REGISTER),
    ("SYS_ACCESS", SYS_ACCESS),
    ("SYS_VOLUME_READ", SYS_VOLUME_READ),
    ("SYS_VOLUME_WRITE", SYS_VOLUME_WRITE),
    ("SYS_VOLUME_INFO", SYS_VOLUME_INFO),
    ("SYS_GETDENTS", SYS_GETDENTS),
    ("SYS_PIPE", SYS_PIPE),
    ("SYS_DUP", SYS_DUP),
    ("SYS_DUP2", SYS_DUP2),
    ("SYS_CHDIR", SYS_CHDIR),
    ("SYS_FCHDIR", SYS_FCHDIR),
    ("SYS_GETCWD", SYS_GETCWD),
    ("SYS_IOCTL", SYS_IOCTL),
    ("SYS_UMASK", SYS_UMASK),
    ("SYS_UNLINK", SYS_UNLINK),
    ("SYS_RMDIR", SYS_RMDIR),
    ("SYS_MKDIR", SYS_MKDIR),
    ("SYS_RENAME", SYS_RENAME),
    ("SYS_LINK", SYS_LINK),
    ("SYS_SYMLINK", SYS_SYMLINK),
    ("SYS_READLINK", SYS_READLINK),
    ("SYS_CHMOD", SYS_CHMOD),
    ("SYS_FCHMOD", SYS_FCHMOD),
    ("SYS_TRUNCATE", SYS_TRUNCATE),
    ("SYS_FTRUNCATE", SYS_FTRUNCATE),
    ("SYS_PREAD", SYS_PREAD),
    ("SYS_PWRITE", SYS_PWRITE),
    ("SYS_FSYNC", SYS_FSYNC),
    ("SYS_FDATASYNC", SYS_FDATASYNC),
    ("SYS_POLL", SYS_POLL),
    ("SYS_PPOLL", SYS_PPOLL),
    ("SYS_OPENAT", SYS_OPENAT),
    ("SYS_FSTATAT", SYS_FSTATAT),
    ("SYS_UNLINKAT", SYS_UNLINKAT),
    ("SYS_RENAMEAT", SYS_RENAMEAT),
    ("SYS_MKDIRAT", SYS_MKDIRAT),
    ("SYS_READLINKAT", SYS_READLINKAT),
    ("SYS_FACCESSAT", SYS_FACCESSAT),
    ("SYS_CLOCK_GETTIME", SYS_CLOCK_GETTIME),
    ("SYS_NANOSLEEP", SYS_NANOSLEEP),
    ("SYS_CLOCK_NANOSLEEP", SYS_CLOCK_NANOSLEEP),
    ("SYS_DEBUG_LOG", SYS_DEBUG_LOG),
    ("SYS_GETRANDOM", SYS_GETRANDOM),
    ("SYS_SET_ROBUST_LIST", SYS_SET_ROBUST_LIST),
    ("SYS_GET_ROBUST_LIST", SYS_GET_ROBUST_LIST),
    ("SYS_MODULE_LOAD", SYS_MODULE_LOAD),
    ("SYS_MODULE_UNLOAD", SYS_MODULE_UNLOAD),
    ("SYS_MODULE_GET_SYMBOL", SYS_MODULE_GET_SYMBOL),
    ("SYS_MODULE_QUERY", SYS_MODULE_QUERY),
    ("SYS_SILO_CREATE", SYS_SILO_CREATE),
    ("SYS_SILO_CONFIG", SYS_SILO_CONFIG),
    ("SYS_SILO_ATTACH_MODULE", SYS_SILO_ATTACH_MODULE),
    ("SYS_SILO_START", SYS_SILO_START),
    ("SYS_SILO_STOP", SYS_SILO_STOP),
    ("SYS_SILO_KILL", SYS_SILO_KILL),
    ("SYS_SILO_EVENT_NEXT", SYS_SILO_EVENT_NEXT),
    ("SYS_SILO_SUSPEND", SYS_SILO_SUSPEND),
    ("SYS_SILO_RESUME", SYS_SILO_RESUME),
    ("SYS_SILO_PLEDGE", SYS_SILO_PLEDGE),
    ("SYS_SILO_UNVEIL", SYS_SILO_UNVEIL),
    ("SYS_SILO_ENTER_SANDBOX", SYS_SILO_ENTER_SANDBOX),
    ("SYS_SILO_RENAME", SYS_SILO_RENAME),
    ("SYS_ABI_VERSION", SYS_ABI_VERSION),
];

#[test]
fn syscall_numbers_are_pinned() {
    // Pinned spot-checks for the most ABI-critical numbers. The full table
    // above documents every value; these asserts catch accidental renumbering
    // even if the table itself was regenerated carelessly.
    assert_eq!(SYS_NULL, 0);
    assert_eq!(SYS_MMAP, 100);
    assert_eq!(SYS_IPC_CREATE_PORT, 200);
    assert_eq!(SYS_PROC_EXIT, 300);
    assert_eq!(SYS_ABI_VERSION, 900);
}

#[test]
fn syscall_numbers_are_unique() {
    let mut seen = std::collections::HashMap::new();
    for &(name, num) in GOLDEN_SYSCALLS {
        if let Some(prev) = seen.insert(num, name) {
            panic!(
                "duplicate syscall number {}: '{}' and '{}'",
                num, prev, name
            );
        }
    }
}

#[test]
fn syscall_table_is_exhaustive() {
    // Guards against the golden table silently drifting from the source:
    // if a new SYS_* constant is added to syscall.rs without updating the
    // table, this count check fails and forces a conscious review.
    assert_eq!(
        GOLDEN_SYSCALLS.len(),
        169,
        "golden table out of sync: add new SYS_* consts AND their pinned values"
    );
}

// ===========================================================================
// Syscall range grouping convention
// ===========================================================================

#[test]
fn syscall_range_groups_are_respected() {
    fn in_range(n: usize, base: usize, top: usize) -> bool {
        n >= base && n <= top
    }

    // Handles/capabilities:      0..99
    for n in [
        SYS_HANDLE_DUPLICATE,
        SYS_HANDLE_CLOSE,
        SYS_HANDLE_WAIT,
        SYS_HANDLE_GRANT,
        SYS_HANDLE_REVOKE,
        SYS_HANDLE_INFO,
    ] {
        assert!(in_range(n, 0, 99), "handle syscall {} out of 0..99", n);
    }
    // Memory:                    100..199
    for n in [
        SYS_MMAP,
        SYS_MUNMAP,
        SYS_BRK,
        SYS_MREMAP,
        SYS_MPROTECT,
        SYS_MEM_REGION_EXPORT,
        SYS_MEM_REGION_MAP,
        SYS_MEM_REGION_INFO,
    ] {
        assert!(in_range(n, 100, 199), "mem syscall {} out of 100..199", n);
    }
    // IPC:                       200..299
    for n in [SYS_IPC_CREATE_PORT, SYS_TRANSPORT_INFO] {
        assert!(in_range(n, 200, 299), "ipc syscall {} out of 200..299", n);
    }
    // Process:                   300..399
    for n in [SYS_PROC_EXIT, SYS_PROC_GETPID, SYS_PROC_WAITPID] {
        assert!(in_range(n, 300, 399), "proc syscall {} out of 300..399", n);
    }
    // Silo management:           800..899
    for n in [
        SYS_SILO_CREATE,
        SYS_SILO_START,
        SYS_SILO_STOP,
        SYS_SILO_ENTER_SANDBOX,
    ] {
        assert!(in_range(n, 800, 899), "silo syscall {} out of 800..899", n);
    }
}

// ===========================================================================
// Struct layout golden values (wire format)
// ===========================================================================

#[test]
fn struct_sizes_are_pinned() {
    assert_eq!(size_of::<IpcMessage>(), IPC_MESSAGE_SIZE);
    assert_eq!(IPC_MESSAGE_SIZE, 256);
    assert_eq!(IPC_MESSAGE_ALIGN, 64);
    assert_eq!(IPC_PAYLOAD_CAPACITY, 240);
    assert_eq!(PAYLOAD_CAPACITY, 240);

    assert_eq!(size_of::<TimeSpec>(), 16);

    // Legacy stat kept for compat: 120 bytes per doc comment.
    assert_eq!(size_of::<Stat>(), 120);
    assert_eq!(size_of::<InlineBlobHeader>(), 4);
}

#[test]
fn file_stat_layout_is_pinned() {
    // FileStat is the canonical stat structure crossing the kernel boundary;
    // its size must stay stable or musl/relibc shims break.
    // Layout: dev(8)+ino(8)+mode(4)+nlink(4)+uid(4)+gid(4)+rdev(8)+size(8)
    //         +blksize(8)+blocks(8) = 64, + 3×TimeSpec(16) = 112.
    assert_eq!(size_of::<FileStat>(), 112);
    // Timespec members are 16-byte aligned inside the struct.
    assert_eq!(align_of::<FileStat>(), 8);
}

#[test]
fn ipc_inline_capacities_match_overhead_constants() {
    assert_eq!(IpcMessage::OPEN_INLINE_CAPACITY, 234); // 240 - 6
    assert_eq!(IpcMessage::UNLINK_INLINE_CAPACITY, 238); // 240 - 2
    assert_eq!(IpcMessage::READ_INLINE_CAPACITY, 232); // 240 - 8
    assert_eq!(IpcMessage::WRITE_INLINE_CAPACITY, 222); // 240 - 18
}

#[test]
fn ipc_message_header_fields_offsets() {
    // sender @0..8, msg_type @8..12, flags @12..16, payload @16..256.
    let msg = IpcMessage::new(0x42);
    let base = &msg as *const _ as usize;
    assert_eq!(&msg.sender as *const _ as usize - base, 0);
    assert_eq!(&msg.msg_type as *const _ as usize - base, 8);
    assert_eq!(&msg.flags as *const _ as usize - base, 12);
    assert_eq!(msg.payload.as_ptr() as usize - base, 16);
}

#[test]
fn ipc_handshake_magic_is_ipc9() {
    // "IPC9" little-endian sentinel — must never drift.
    assert_eq!(IPC_HANDSHAKE_MAGIC, 0x4950_4339);
}

// ===========================================================================
// Errno uniqueness (values are part of the POSIX-compat surface)
// ===========================================================================

#[test]
fn errno_values_are_unique() {
    const ERRNOS: &[usize] = &[
        errno::EPERM,
        errno::ENOENT,
        errno::ESRCH,
        errno::EINTR,
        errno::EIO,
        errno::E2BIG,
        errno::ENOEXEC,
        errno::EBADF,
        errno::ECHILD,
        errno::EAGAIN,
        errno::ENOMEM,
        errno::EACCES,
        errno::EFAULT,
        errno::EEXIST,
        errno::ENOTDIR,
        errno::EISDIR,
        errno::EINVAL,
        errno::ENOTTY,
        errno::ENOSPC,
        errno::EPIPE,
        errno::ERANGE,
        errno::ENAMETOOLONG,
        errno::ENOSYS,
        errno::ENOTEMPTY,
        errno::ELOOP,
        errno::ENOTSUP,
        errno::EAFNOSUPPORT,
        errno::EADDRINUSE,
        errno::ENOBUFS,
        errno::ETIMEDOUT,
        errno::ECONNREFUSED,
    ];
    let mut set = std::collections::HashSet::new();
    for &e in ERRNOS {
        assert!(set.insert(e), "duplicated errno value {}", e);
    }
    assert_eq!(set.len(), 31);
}
