use bitflags::bitflags;

bitflags! {
    /// Strat9 ABI open flags passed via SYS_OPEN.
    ///
    /// These are NOT POSIX O_* values. relibc and other POSIX shims must
    /// translate from O_* to these bits before invoking the syscall.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct OpenFlags: u32 {
        const READ      = 1 << 0;
        const WRITE     = 1 << 1;
        const CREATE    = 1 << 2;
        const TRUNCATE  = 1 << 3;
        const APPEND    = 1 << 4;
        const DIRECTORY = 1 << 5;
        const EXCL      = 1 << 6;
        const NONBLOCK  = 1 << 7;
        const NOFOLLOW  = 1 << 8;
        const NOCTTY    = 1 << 9;
        const SYNC      = 1 << 10;

        const RDONLY = Self::READ.bits();
        const WRONLY = Self::WRITE.bits();
        const RDWR   = Self::READ.bits() | Self::WRITE.bits();
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct MapFlags: u32 {
        const MAP_SHARED    = 0x01;
        const MAP_PRIVATE   = 0x02;
        const MAP_FIXED     = 0x10;
        const MAP_ANONYMOUS = 0x0020;
        const MAP_NORESERVE = 0x40;
        const MAP_POPULATE  = 0x8000;
        const MAP_LOCKED    = 0x2000;
        const MAP_GROWSDOWN = 0x0100;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct CallFlags: u32 {
        const READ    = 0x01;
        const WRITE   = 0x02;
        const NONBLOCK = 0x04;
        const PEEK    = 0x08;
        const WAIT    = 0x10;
        const NOWAIT  = 0x20;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct UnlinkFlags: u32 {
        const REMOVEDIR = 0o02000000;
    }
}

/// Translate POSIX O_* flags to Strat9 ABI `OpenFlags`.
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
