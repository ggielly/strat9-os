use zerocopy::{AsBytes, FromBytes, FromZeroes};

#[derive(Debug, Clone, Copy, FromZeroes, FromBytes, AsBytes)]
#[repr(C)]
pub struct TimeSpec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_rdev: u64,
    pub st_size: u64,
    pub st_blksize: u64,
    pub st_blocks: u64,
    pub st_atime: TimeSpec,
    pub st_mtime: TimeSpec,
    pub st_ctime: TimeSpec,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct StatVfs {
    pub f_bsize: u64,
    pub f_frsize: u64,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_files: u64,
    pub f_ffree: u64,
    pub f_favail: u64,
    pub f_fsid: u64,
    pub f_flag: u64,
    pub f_namemax: u64,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Map {
    pub offset: usize,
    pub size: usize,
    pub flags: u64,
    pub addr: usize,
}

#[derive(Debug, Clone, Copy, FromZeroes, FromBytes, AsBytes)]
#[repr(C)]
pub struct HandleInfo {
    pub resource_type: u32,
    pub permissions: u32,
    pub resource: u64,
}

/// Kernel-level file metadata returned by fstat/stat syscalls.
///
/// Matches kernel `vfs::scheme::FileStat` layout exactly.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FileStat {
    pub st_ino: u64,
    pub st_mode: u32,
    pub st_nlink: u32,
    pub st_size: u64,
    pub st_blksize: u64,
    pub st_blocks: u64,
}

impl FileStat {
    pub const fn zeroed() -> Self {
        FileStat {
            st_ino: 0,
            st_mode: 0,
            st_nlink: 0,
            st_size: 0,
            st_blksize: 0,
            st_blocks: 0,
        }
    }

    pub fn is_dir(&self) -> bool {
        (self.st_mode & 0o170000) == 0o040000
    }

    pub fn is_file(&self) -> bool {
        (self.st_mode & 0o170000) == 0o100000
    }
}

/// POSIX lseek whence constants.
pub const SEEK_SET: usize = 0;
pub const SEEK_CUR: usize = 1;
pub const SEEK_END: usize = 2;

/// Canonical 64-byte IPC message (cache-line aligned).
///
/// Layout matches the kernel's `ipc::message::IpcMessage`:
/// ```text
///  0..  8  sender   (u64, filled by kernel)
///  8.. 12  msg_type (u32, opcode chosen by sender)
/// 12.. 16  flags    (u32, capability transfer handle or 0)
/// 16.. 64  payload  (48 bytes, opaque data)
/// ```
///
/// Derives `FromBytes`/`IntoBytes` via zerocopy so that conversions
/// to/from `&[u8; 64]` are safe and zero-cost.
#[derive(Clone, Copy, FromZeroes, FromBytes, AsBytes)]
#[repr(C, align(64))]
pub struct IpcMessage {
    pub sender: u64,
    pub msg_type: u32,
    pub flags: u32,
    pub payload: [u8; 48],
}

impl IpcMessage {
    /// Create a zeroed message with the given opcode.
    pub const fn new(msg_type: u32) -> Self {
        IpcMessage {
            sender: 0,
            msg_type,
            flags: 0,
            payload: [0u8; 48],
        }
    }

    /// Build a generic error reply.
    pub fn error_reply(sender: u64, status: i32) -> Self {
        let mut msg = IpcMessage::new(0x81);
        msg.sender = sender;
        msg.payload[0..4].copy_from_slice(&(status as u32).to_le_bytes());
        msg
    }
}

impl core::fmt::Debug for IpcMessage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IpcMessage")
            .field("sender", &self.sender)
            .field("msg_type", &format_args!("0x{:02x}", self.msg_type))
            .field("flags", &self.flags)
            .finish()
    }
}

// Compile-time layout guarantees
static_assertions::assert_eq_size!(IpcMessage, [u8; 64]);
static_assertions::const_assert_eq!(core::mem::align_of::<IpcMessage>(), 64);
static_assertions::assert_eq_size!(TimeSpec, [u8; 16]);
