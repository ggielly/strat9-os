//! L1 — errno ABI convention tests.
//!
//! Syscalls return `usize` in RAX:
//! - success: any non-negative value,
//! - error: negative errno in two's complement, detected by userspace with
//!   `result > 0xFFFF_F000`.
//!
//! These tests pin the detection convention and the Linux-compatible values.

use strat9_abi::errno;

/// Userspace error-detection threshold documented in `errno.rs`.
const ERR_DETECT_THRESHOLD: usize = 0xFFFF_F000;

fn to_syscall_error(e: usize) -> usize {
    // Kernel side: -(errno as isize) as usize
    (-(e as isize)) as usize
}

fn from_syscall_result(r: usize) -> Option<usize> {
    if r > ERR_DETECT_THRESHOLD {
        Some((!(r)).wrapping_add(1)) // two's complement back to positive errno
    } else {
        None
    }
}

#[test]
fn errno_values_match_linux() {
    // Strat9 deliberately reuses Linux x86_64 errno numbering so that
    // musl/relibc shims can map 1:1. Pin the critical values.
    assert_eq!(errno::EPERM, 1);
    assert_eq!(errno::ENOENT, 2);
    assert_eq!(errno::ESRCH, 3);
    assert_eq!(errno::EINTR, 4);
    assert_eq!(errno::EIO, 5);
    assert_eq!(errno::E2BIG, 7);
    assert_eq!(errno::ENOEXEC, 8);
    assert_eq!(errno::EBADF, 9);
    assert_eq!(errno::ECHILD, 10);
    assert_eq!(errno::EAGAIN, 11);
    assert_eq!(errno::ENOMEM, 12);
    assert_eq!(errno::EACCES, 13);
    assert_eq!(errno::EFAULT, 14);
    assert_eq!(errno::EEXIST, 17);
    assert_eq!(errno::ENOTDIR, 20);
    assert_eq!(errno::EISDIR, 21);
    assert_eq!(errno::EINVAL, 22);
    assert_eq!(errno::ENOTTY, 25);
    assert_eq!(errno::ENOSPC, 28);
    assert_eq!(errno::EPIPE, 32);
    assert_eq!(errno::ERANGE, 34);
    assert_eq!(errno::ENAMETOOLONG, 36);
    assert_eq!(errno::ENOSYS, 38);
    assert_eq!(errno::ENOTEMPTY, 39);
    assert_eq!(errno::ELOOP, 40);
    assert_eq!(errno::ENOTSUP, 95); // F6 FIXED: now == Linux EOPNOTSUPP (was wrongly 52)
    assert_eq!(errno::EAFNOSUPPORT, 97);
    assert_eq!(errno::EADDRINUSE, 98);
    assert_eq!(errno::ENOBUFS, 105);
    assert_eq!(errno::ETIMEDOUT, 110);
    assert_eq!(errno::ECONNREFUSED, 111);
}

#[test]
fn all_errno_values_fit_detection_window() {
    const ALL: &[usize] = &[
        errno::EPERM, errno::ENOENT, errno::ESRCH, errno::EINTR, errno::EIO, errno::E2BIG,
        errno::ENOEXEC, errno::EBADF, errno::ECHILD, errno::EAGAIN, errno::ENOMEM,
        errno::EACCES, errno::EFAULT, errno::EEXIST, errno::ENOTDIR, errno::EISDIR,
        errno::EINVAL, errno::ENOTTY, errno::ENOSPC, errno::EPIPE, errno::ERANGE,
        errno::ENAMETOOLONG, errno::ENOSYS, errno::ENOTEMPTY, errno::ELOOP, errno::ENOTSUP,
        errno::EAFNOSUPPORT, errno::EADDRINUSE, errno::ENOBUFS, errno::ETIMEDOUT,
        errno::ECONNREFUSED,
    ];
    for &e in ALL {
        let wire = to_syscall_error(e);
        // Every defined errno must be detectable as an error by userspace.
        assert!(
            wire > ERR_DETECT_THRESHOLD,
            "errno {} encodes to {:#x}: NOT detectable by the > {:#x} convention",
            e,
            wire,
            ERR_DETECT_THRESHOLD
        );
        // And must survive a kernel->user->kernel roundtrip unchanged.
        assert_eq!(from_syscall_result(wire), Some(e));
    }
}

#[test]
fn success_results_are_not_mistaken_for_errors() {
    // Typical successful return values must never cross the error threshold:
    // file descriptors, byte counts, PIDs, addresses...
    for &ok in &[
        0usize,
        1,
        3,          // fd
        4096,       // page size read
        0x7FFF_FFFF,// INT_MAX
        0xFFFF_F000,// exactly at threshold: still "success" per doc (`>` not `>=`)
    ] {
        assert!(
            from_syscall_result(ok).is_none(),
            "{:#x} wrongly detected as errno",
            ok
        );
    }
}

#[test]
fn detection_convention_matches_documented_userspace_recipe() {
    // Doc says: `if result > 0xFFFF_F000` then `let errno = !result + 1`.
    let wire = to_syscall_result_style(errno::EBADF);
    assert!(wire > 0xFFFF_F000);
    let decoded = (!wire).wrapping_add(1);
    assert_eq!(decoded, errno::EBADF);
}

// Mirrors how the kernel actually negates (documented in errno.rs header).
fn to_syscall_result_style(e: usize) -> usize {
    (-(e as isize)) as usize
}
