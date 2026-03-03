use bitflags::bitflags;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct OpenFlags: u32 {
        const RDONLY = 0o000000;
        const WRONLY = 0o000001;
        const RDWR = 0o000002;
        const CREATE = 0o000100;
        const TRUNC = 0o001000;
        const EXCL = 0o000200;
        const APPEND = 0o002000;
        const NONBLOCK = 0o004000;
        const NOFOLLOW = 0o0100000;
        const DIRECTORY = 0o0200000;
        const NOCTTY = 0o0400000;
        const SYNC = 0o04000000;
        const DSYNC = 0o02000000;
        const RSYNC = 0o04010000;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct MapFlags: u32 {
        const MAP_SHARED = 0x01;
        const MAP_PRIVATE = 0x02;
        const MAP_FIXED = 0x10;
        const MAP_ANONYMOUS = 0x0020;
        const MAP_NORESERVE = 0x40;
        const MAP_POPULATE = 0x8000;
        const MAP_LOCKED = 0x2000;
        const MAP_GROWSDOWN = 0x0100;
    }
}
