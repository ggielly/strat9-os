use bitflags::bitflags;

bitflags! {
    /// Flags for openat
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct OpenFlags: u32 {
        /// Read only
        const RDONLY = 0o000000;
        /// Write only
        const WRONLY = 0o000001;
        /// Read write
        const RDWR = 0o000002;
        /// Create file if it does not exist
        const CREATE = 0o000100;
        /// Truncate file to zero length if it exists
        const TRUNC = 0o001000;
        /// Create file exclusively
        const EXCL = 0o000200;
        /// Append to file
        const APPEND = 0o002000;
        /// Non-blocking mode
        const NONBLOCK = 0o004000;
        /// Don't follow symlinks
        const NOFOLLOW = 0o0100000;
        /// Directory
        const DIRECTORY = 0o0200000;
        /// No controlling terminal
        const NOCTTY = 0o0400000;
        /// Synchronized I/O
        const SYNC = 0o04000000;
        /// Synchronized I/O data integrity
        const DSYNC = 0o02000000;
        /// Synchronized I/O read operations
        const RSYNC = 0o04010000;
    }
}

bitflags! {
    /// Flags for fmap
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct MapFlags: u32 {
        /// Share changes
        const MAP_SHARED = 0x01;
        /// Copy on write
        const MAP_PRIVATE = 0x02;
        /// Fixed address mapping
        const MAP_FIXED = 0x10;
        /// Do not reserve swap space
        const MAP_NORESERVE = 0x40;
        /// Populate page tables
        const MAP_POPULATE = 0x8000;
        /// Lock pages in memory
        const MAP_LOCKED = 0x2000;
        /// Execute in userspace
        const MAP_32BIT = 0x40;
        /// Stack allocation
        const MAP_GROWSDOWN = 0x0100;
        /// Ignore address
        const MAP_ANONYMOUS = 0x0020;
        /// Don't include in core dump
        const MAP_DENYWRITE = 0x0800;
        /// Mark read-only in core dump
        const MAP_EXECUTABLE = 0x1000;
        /// Lock the mapped region
        const MAP_LOCKED_NOREPLACE = 0x0010;
        /// Don't execute in userspace
        const MAP_UNINITIALIZED = 0x0040;
    }
}

bitflags! {
    /// Flags for call
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct CallFlags: u32 {
        /// Read access
        const READ = 0x01;
        /// Write access
        const WRITE = 0x02;
        /// Non-blocking
        const NONBLOCK = 0x04;
        /// Peek at data without consuming
        const PEEK = 0x08;
        /// Wait for data to arrive
        const WAIT = 0x10;
        /// Don't wait for data
        const NOWAIT = 0x20;
    }
}

bitflags! {
    /// Flags for lseek
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct SeekWhence: u32 {
        /// Beginning of file
        const SET = 0;
        /// Current position
        const CUR = 1;
        /// End of file
        const END = 2;
    }
}

bitflags! {
    /// Flags for unlinkat
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct UnlinkFlags: u32 {
        /// Remove directory
        const REMOVEDIR = 0o02000000;
    }
}
