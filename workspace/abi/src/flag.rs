//! ABI-level flags for syscalls and data structures.
//!
//! These are Strat9 OS native flags, NOT POSIX flags.
//! POSIX shims (relibc, musl-compat) must translate from POSIX `O_*`
//! to these flags using [`posix_oflags_to_strat9`].

use bitflags::bitflags;

// ── Open Flags ──────────────────────────────────────────────────────────────

bitflags! {
    /// File open flags for `SYS_OPEN` and `SYS_OPENAT`.
    ///
    /// These are **not** POSIX `O_*` values. Use [`posix_oflags_to_strat9`]
    /// to convert from POSIX flags when implementing a compatibility layer.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct OpenFlags: u32 {
        /// Open for reading.
        const READ      = 1 << 0;
        /// Open for writing.
        const WRITE     = 1 << 1;
        /// Create file if it does not exist (requires `WRITE` or `APPEND`).
        const CREATE    = 1 << 2;
        /// Truncate file to zero length on open.
        const TRUNCATE  = 1 << 3;
        /// Append all writes to the end of the file.
        const APPEND    = 1 << 4;
        /// Open as a directory (fails if path is not a directory).
        const DIRECTORY = 1 << 5;
        /// Fail if file already exists (only meaningful with `CREATE`).
        const EXCL      = 1 << 6;
        /// Non-blocking mode: return `EAGAIN` instead of blocking.
        const NONBLOCK  = 1 << 7;
        /// Do not follow symbolic links in the final path component.
        const NOFOLLOW  = 1 << 8;
        /// Do not allocate a controlling terminal.
        const NOCTTY    = 1 << 9;
        /// Synchronous writes: data + metadata flushed to disk before return.
        const SYNC      = 1 << 10;

        /// Open for reading only (alias for `READ`).
        const RDONLY = Self::READ.bits();
        /// Open for writing only (alias for `WRITE`).
        const WRONLY = Self::WRITE.bits();
        /// Open for reading and writing.
        const RDWR   = Self::READ.bits() | Self::WRITE.bits();
    }
}

// ── Memory Map Flags ────────────────────────────────────────────────────────

bitflags! {
    /// Memory mapping flags for `SYS_MMAP`.
    ///
    /// These are **not** POSIX `MAP_*` values. The kernel uses its own
    /// bit layout for efficiency.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct MapFlags: u32 {
        /// Shared mapping: writes are visible to other processes mapping the same region.
        const MAP_SHARED    = 0x01;
        /// Private mapping: copy-on-write semantics.
        const MAP_PRIVATE   = 0x02;
        /// Fixed mapping: place at the exact address specified (may overwrite existing mappings).
        const MAP_FIXED     = 0x10;
        /// Anonymous mapping: not backed by a file (requires `MAP_PRIVATE`).
        const MAP_ANONYMOUS = 0x0020;
        /// Do not reserve swap space for this mapping.
        const MAP_NORESERVE = 0x40;
        /// Populate pages on demand (prefault all pages).
        const MAP_POPULATE  = 0x8000;
        /// Lock the mapping in memory (cannot be swapped out).
        const MAP_LOCKED    = 0x2000;
        /// Automatically expand the mapping downward (stack growth).
        const MAP_GROWSDOWN = 0x0100;
    }
}

// ── IPC Call Flags ──────────────────────────────────────────────────────────

bitflags! {
    /// Flags for IPC call operations (used with `SYS_IPC_CALL`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct CallFlags: u32 {
        /// Read operation (receive data).
        const READ    = 0x01;
        /// Write operation (send data).
        const WRITE   = 0x02;
        /// Non-blocking: return immediately if no data available.
        const NONBLOCK = 0x04;
        /// Peek: read data without consuming it.
        const PEEK    = 0x08;
        /// Wait for data (blocking).
        const WAIT    = 0x10;
        /// Do not wait (return immediately).
        const NOWAIT  = 0x20;
    }
}

// ── Unlink Flags ────────────────────────────────────────────────────────────

bitflags! {
    /// Flags for `SYS_UNLINKAT`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct UnlinkFlags: u32 {
        /// Remove a directory instead of a file.
        const REMOVEDIR = 0o02000000;
    }
}

// ── POSIX to Strat9 Translation ─────────────────────────────────────────────

/// Translate POSIX `O_*` flags to Strat9 ABI `OpenFlags`.
///
/// This function is used by POSIX compatibility layers (relibc, musl-compat)
/// to convert standard Linux/POSIX open flags to the Strat9 native format.
///
/// # Example
///
/// ```ignore
/// let strat9_flags = posix_oflags_to_strat9(libc::O_RDONLY | libc::O_CREAT);
/// assert!(strat9_flags.contains(OpenFlags::READ));
/// assert!(strat9_flags.contains(OpenFlags::CREATE));
/// ```
pub fn posix_oflags_to_strat9(posix: u32) -> OpenFlags {
    const O_ACCMODE: u32 = 0o3;
    const O_RDONLY: u32 = 0o000000;
    const O_WRONLY: u32 = 0o000001;
    const O_RDWR: u32 = 0o000002;
    const O_CREAT: u32 = 0o000100;
    const O_EXCL: u32 = 0o000200;
    const O_NOCTTY: u32 = 0o000400;
    const O_TRUNC: u32 = 0o001000;
    const O_APPEND: u32 = 0o002000;
    const O_NONBLOCK: u32 = 0o004000;
    const O_DIRECTORY: u32 = 0o0200000;
    const O_NOFOLLOW: u32 = 0o0400000;
    const O_SYNC: u32 = 0o04000000;

    let access = posix & O_ACCMODE;
    let mut out = OpenFlags::empty();

    match access {
        O_RDONLY => {
            out |= OpenFlags::READ;
        }
        O_WRONLY => {
            out |= OpenFlags::WRITE;
        }
        O_RDWR => {
            out |= OpenFlags::READ | OpenFlags::WRITE;
        }
        _ => {}
    }

    if posix & O_CREAT != 0 {
        out |= OpenFlags::CREATE;
    }
    if posix & O_TRUNC != 0 {
        out |= OpenFlags::TRUNCATE;
    }
    if posix & O_APPEND != 0 {
        out |= OpenFlags::APPEND;
    }
    if posix & O_DIRECTORY != 0 {
        out |= OpenFlags::DIRECTORY;
    }
    if posix & O_EXCL != 0 {
        out |= OpenFlags::EXCL;
    }
    if posix & O_NONBLOCK != 0 {
        out |= OpenFlags::NONBLOCK;
    }
    if posix & O_NOFOLLOW != 0 {
        out |= OpenFlags::NOFOLLOW;
    }
    if posix & O_NOCTTY != 0 {
        out |= OpenFlags::NOCTTY;
    }
    if posix & O_SYNC != 0 {
        out |= OpenFlags::SYNC;
    }

    out
}
