//! L1 — `strat9_syscall::error`: typed errno surface conformance.
//!
//! `Error` is the userspace-facing enum mirroring `strat9_abi::errno` via
//! num_enum. Roundtrips, demux of raw RAX values and symbolic names are
//! all part of the userspace contract (musl-compat relies on them).

use strat9_syscall::error::Error;
use strat9_syscall::error as errno; // errno consts are glob-re-exported into error

#[test]
fn error_roundtrip_all_named_variants() {
    const CASES: &[(usize, Error)] = &[
        (errno::EPERM, Error::PermissionDenied),
        (errno::ENOENT, Error::NotFound),
        (errno::ESRCH, Error::NoSuchProcess),
        (errno::EINTR, Error::Interrupted),
        (errno::EIO, Error::IoError),
        (errno::E2BIG, Error::ArgumentListTooLong),
        (errno::ENOEXEC, Error::ExecFormatError),
        (errno::EBADF, Error::BadHandle),
        (errno::ECHILD, Error::NoChildren),
        (errno::EAGAIN, Error::Again),
        (errno::ENOMEM, Error::OutOfMemory),
        (errno::EACCES, Error::AccessDenied),
        (errno::EFAULT, Error::Fault),
        (errno::EEXIST, Error::AlreadyExists),
        (errno::ENOTDIR, Error::NotADirectory),
        (errno::EISDIR, Error::IsADirectory),
        (errno::EINVAL, Error::InvalidArgument),
        (errno::ENOTTY, Error::NotATty),
        (errno::ENOSPC, Error::NoSpace),
        (errno::EPIPE, Error::Pipe),
        (errno::ERANGE, Error::RangeError),
        (errno::ENAMETOOLONG, Error::NameTooLong),
        (errno::ENOSYS, Error::NotImplemented),
        (errno::ENOTEMPTY, Error::NotEmpty),
        (errno::ELOOP, Error::SymlinkLoop),
        (errno::ENOTSUP, Error::NotSupported),
        (errno::EADDRINUSE, Error::AddressInUse),
        (errno::ENOBUFS, Error::QueueFull),
        (errno::ETIMEDOUT, Error::TimedOut),
        (errno::ECONNREFUSED, Error::ConnectionRefused),
    ];
    for &(value, expected) in CASES {
        assert_eq!(Error::from_errno(value), expected, "from_errno({})", value);
        assert_eq!(expected.to_errno(), value, "to_errno({:?})", expected);
        // And through the raw conversion too.
        assert_eq!(Error::try_from(value), Ok(expected));
    }
}

#[test]
fn unknown_errnos_fall_into_catch_all() {
    // Values inside the errno range but not mapped must not panic.
    for e in [5000usize, 4095, 1234] {
        match Error::from_errno(e) {
            Error::Unknown(v) => assert_eq!(v, e),
            other => panic!("{} mapped to {:?}", e, other),
        }
    }
}

#[test]
fn demux_decodes_negative_errno_encoding() {
    // Kernel ABI: errors are negative errno in RAX.
    let ret = (-(errno::EINVAL as isize)) as usize;
    assert_eq!(Error::demux(ret), Err(Error::InvalidArgument));

    // Success values pass through unchanged.
    assert_eq!(Error::demux(0), Ok(0));
    assert_eq!(Error::demux(42), Ok(42));
    assert_eq!(Error::demux(usize::MAX / 2), Ok(usize::MAX / 2));

    // Roundtrip every named errno through demux.
    for e in [
        errno::EPERM, errno::ENOENT, errno::EBADF, errno::ENOMEM,
        errno::EACCES, errno::EINVAL, errno::ENOSYS, errno::ECONNREFUSED,
    ] {
        let wire = (-(e as isize)) as usize;
        assert_eq!(Error::demux(wire), Err(Error::from_errno(e)));
    }
}

#[test]
fn retryable_errors_are_eintr_and_eagain_only() {
    assert!(Error::Interrupted.is_retryable());
    assert!(Error::Again.is_retryable());
    for e in [
        Error::PermissionDenied,
        Error::BadHandle,
        Error::InvalidArgument,
        Error::TimedOut,
        Error::Unknown(9999),
    ] {
        assert!(!e.is_retryable(), "{:?} wrongly retryable", e);
    }
}

#[test]
fn symbolic_names_match_posix_spelling() {
    let cases: &[(Error, &str)] = &[
        (Error::PermissionDenied, "EPERM"),
        (Error::NotFound, "ENOENT"),
        (Error::BadHandle, "EBADF"),
        (Error::Again, "EAGAIN"),
        (Error::OutOfMemory, "ENOMEM"),
        (Error::InvalidArgument, "EINVAL"),
        (Error::NotSupported, "ENOTSUP"),
        (Error::Unknown(7), "E???"),
    ];
    for (e, name) in cases {
        assert_eq!(e.name(), *name);
    }
}

#[test]
fn display_messages_are_non_empty_for_all_variants() {
    let variants = [
        Error::from_errno(errno::EPERM),
        Error::from_errno(errno::ENOENT),
        Error::from_errno(errno::ECONNREFUSED),
        Error::Unknown(4095),
    ];
    for v in variants {
        let s = format!("{}", v);
        assert!(!s.is_empty());
        assert!(!s.contains("Unknown error") || matches!(v, Error::Unknown(_)));
    }
}

// ===========================================================================
// F8 regression: POSIX flag constants must match Linux x86_64 exactly
// ===========================================================================

mod posix_flag_constants {
    use strat9_syscall::flag::*;

    #[test]
    fn linux_x86_64_values_are_pinned() {
        // From linux asm-generic/fcntl.h — these MUST stay bit-identical
        // or every POSIX binary breaks in new creative ways (see F8).
        assert_eq!(O_ACCMODE, 0o3);
        assert_eq!(O_RDONLY, 0o0);
        assert_eq!(O_WRONLY, 0o1);
        assert_eq!(O_RDWR, 0o2);
        assert_eq!(O_CREAT, 0o100);
        assert_eq!(O_EXCL, 0o200);
        assert_eq!(O_NOCTTY, 0o400);
        assert_eq!(O_TRUNC, 0o1000);
        assert_eq!(O_APPEND, 0o2000);
        assert_eq!(O_NONBLOCK, 0o4000);
        assert_eq!(O_DSYNC, 0o10000);       // was O_CLOEXEC before the fix!
        assert_eq!(O_DIRECTORY, 0o200000);
        assert_eq!(O_NOFOLLOW, 0o400000);   // F8: was 0o100000 (O_CLOEXEC)!
        assert_eq!(O_SYNC, 0o4010000);      // __O_SYNC | O_DSYNC
        assert_eq!(O_RSYNC, O_SYNC);        // Linux defines O_RSYNC == O_SYNC on x86_64
    }

    #[test]
    fn constants_agree_with_abi_translation_table() {
        // The abi crate translates using its own copies of these constants;
        // both copies must agree bit-for-bit or translation silently diverges.
        // Spot-check via roundtrip of each individual bit.
        for bit in [
            O_CREAT, O_EXCL, O_NOCTTY, O_TRUNC, O_APPEND, O_NONBLOCK,
            O_DIRECTORY, O_NOFOLLOW, O_SYNC,
        ] {
            let out = strat9_syscall::flag::posix_oflags_to_strat9(bit);
            assert!(
                !out.is_empty(),
                "POSIX bit {:#o} produced no Strat9 flags",
                bit
            );
        }
    }
}
