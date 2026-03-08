pub use strat9_abi::flag::{posix_oflags_to_strat9, CallFlags, MapFlags, OpenFlags, UnlinkFlags};

// ============================================================================
// POSIX O_* constants for open()
// ============================================================================

/// Open for reading only
pub const O_RDONLY: u32 = 0o000000;
/// Open for writing only
pub const O_WRONLY: u32 = 0o000001;
/// Open for reading and writing
pub const O_RDWR: u32 = 0o000002;
/// Create file if it does not exist
pub const O_CREAT: u32 = 0o000100;
/// Truncate file to zero length if it exists
pub const O_TRUNC: u32 = 0o001000;
/// Create file exclusively (with O_CREAT)
pub const O_EXCL: u32 = 0o000200;
/// Append to file (writes always go to end)
pub const O_APPEND: u32 = 0o002000;
/// Non-blocking mode
pub const O_NONBLOCK: u32 = 0o004000;
/// Don't follow symbolic links
pub const O_NOFOLLOW: u32 = 0o100000;
/// Open directory only
pub const O_DIRECTORY: u32 = 0o200000;
/// Don't assign controlling terminal
pub const O_NOCTTY: u32 = 0o400000;
/// Synchronized I/O (data + metadata)
pub const O_SYNC: u32 = 0o4010000;
/// Synchronized I/O data integrity
pub const O_DSYNC: u32 = 0o02000000;
/// Synchronized I/O read operations
pub const O_RSYNC: u32 = 0o04010000;
/// Access mask for read/write mode
pub const O_ACCMODE: u32 = 0o3;
