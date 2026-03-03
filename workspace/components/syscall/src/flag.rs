pub use strat9_abi::flag::{MapFlags, OpenFlags};

use bitflags::bitflags;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct CallFlags: u32 {
        const READ = 0x01;
        const WRITE = 0x02;
        const NONBLOCK = 0x04;
        const PEEK = 0x08;
        const WAIT = 0x10;
        const NOWAIT = 0x20;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct SeekWhence: u32 {
        const SET = 0;
        const CUR = 1;
        const END = 2;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct UnlinkFlags: u32 {
        const REMOVEDIR = 0o02000000;
    }
}
