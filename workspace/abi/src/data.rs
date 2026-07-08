//! ABI data structures shared between kernel and userspace.
//!
//! These types define the wire format for syscalls, IPC messages, and
//! file system operations. Both kernel and userspace must agree on the
//! exact memory layout (size, alignment, field ordering).

use zerocopy::{FromBytes, IntoBytes};

// ── IPC Message Constants ───────────────────────────────────────────────────

/// Total size of an IPC message in bytes (including header and payload).
pub const IPC_MESSAGE_SIZE: usize = 256;

/// Alignment requirement for IPC messages (64-byte aligned for cache line).
pub const IPC_MESSAGE_ALIGN: usize = 64;

/// Size of the IPC message header (sender + msg_type + flags).
pub const IPC_MESSAGE_HEADER_SIZE: usize = 16;

/// Maximum payload size in an IPC message (256 - 16 = 240 bytes).
pub const IPC_PAYLOAD_CAPACITY: usize = IPC_MESSAGE_SIZE - IPC_MESSAGE_HEADER_SIZE;

// ── IPC File Flags ──────────────────────────────────────────────────────────

/// Directory entry flag: this entry is a directory.
pub const IPC_FILE_FLAG_DIRECTORY: u32 = 1 << 0;

/// Directory entry flag: this entry is a device file.
pub const IPC_FILE_FLAG_DEVICE: u32 = 1 << 1;

/// Directory entry flag: this entry is a pipe.
pub const IPC_FILE_FLAG_PIPE: u32 = 1 << 2;

/// Directory entry flag: file is opened in append mode.
pub const IPC_FILE_FLAG_APPEND: u32 = 1 << 3;

/// Directory entry flag: supports chunked reads.
pub const IPC_FILE_FLAG_CHUNK_READ: u32 = 1 << 4;

/// Directory entry flag: supports chunked writes.
pub const IPC_FILE_FLAG_CHUNK_WRITE: u32 = 1 << 5;

// ── SiloMode ────────────────────────────────────────────────────────────────

/// 9-bit octal silo permission mode (3 control + 3 hardware + 3 registry).
///
/// Shared ABI type used by both kernel and userspace init.
/// The kernel's richer `OctalMode` (with typed bitflag fields)
/// is built from this via `OctalMode::from_octal(val.0)`.
///
/// Bit layout: `[control:3][hardware:3][registry:3]` (LSB = registry).
///
/// Example: `0o777` = full permissions in all groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes)]
#[repr(transparent)]
pub struct SiloMode(pub u16);

impl SiloMode {
    /// Return true if `self` bits are a subset of `other`'s bits
    /// (i.e. `self` does not request any permission `other` lacks).
    pub const fn is_subset_of(&self, other: &SiloMode) -> bool {
        let (s_c, s_h, s_r) = ((self.0 >> 6) & 0o7, (self.0 >> 3) & 0o7, self.0 & 0o7);
        let (o_c, o_h, o_r) = ((other.0 >> 6) & 0o7, (other.0 >> 3) & 0o7, other.0 & 0o7);
        (s_c & !o_c) == 0 && (s_h & !o_h) == 0 && (s_r & !o_r) == 0
    }
}

// ── TimeSpec ───────────────── saturating multiplication─────────────────────

/// POSIX-style timestamp: seconds + nanoseconds.
///
/// Used for `SYS_CLOCK_GETTIME`, `SYS_NANOSLEEP`, and file timestamps.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
#[repr(C)]
pub struct TimeSpec {
    /// Seconds since Unix epoch (or relative time for sleep).
    pub tv_sec: i64,
    /// Nanoseconds (0..999_999_999).
    pub tv_nsec: i64,
}

impl TimeSpec {
    /// Return a zero-initialized timestamp.
    pub const fn zero() -> Self {
        Self {
            tv_sec: 0,
            tv_nsec: 0,
        }
    }

    /// Convert the timestamp to nanoseconds with saturating arithmetic.
    pub fn to_nanos(&self) -> u64 {
        (self.tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(self.tv_nsec as u64)
    }

    /// Build a timestamp from a nanoseconds value.
    pub fn from_nanos(nanos: u64) -> Self {
        Self {
            tv_sec: (nanos / 1_000_000_000) as i64,
            tv_nsec: (nanos % 1_000_000_000) as i64,
        }
    }
}

// ── Stat (legacy, kept for compat) ─────────────────────────────────────────

/// Legacy stat structure (120 bytes). Prefer [`FileStat`] for new code.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
#[repr(C)]
pub struct Stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub _padding0: u32,
    pub st_rdev: u64,
    pub st_size: u64,
    pub st_blksize: u64,
    pub st_blocks: u64,
    pub st_atime: TimeSpec,
    pub st_mtime: TimeSpec,
    pub st_ctime: TimeSpec,
}

// ── StatVfs ────────────────────────────────────────────────────────────────

/// Filesystem statistics (for `SYS_STAT` on directories).
///
/// Similar to Linux `struct statfs`.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
#[repr(C)]
pub struct StatVfs {
    /// Preferred file system block size.
    pub f_bsize: u64,
    /// File system fragment size.
    pub f_frsize: u64,
    /// Total data blocks in the file system.
    pub f_blocks: u64,
    /// Free blocks available to unprivileged users.
    pub f_bfree: u64,
    /// Free blocks available to unprivileged users.
    pub f_bavail: u64,
    /// Total file nodes (inodes).
    pub f_files: u64,
    /// Free file nodes.
    pub f_ffree: u64,
    /// Free file nodes available to unprivileged users.
    pub f_favail: u64,
    /// File system ID.
    pub f_fsid: u64,
    /// File system flags (read-only, etc.).
    pub f_flag: u64,
    /// Maximum filename length.
    pub f_namemax: u64,
}

// ── Map (mmap) ─────────────────────────────────────────────────────────────

/// Memory mapping descriptor for `SYS_MMAP`.
///
/// Describes a region of virtual memory mapped into a process.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
#[repr(C)]
pub struct Map {
    /// Offset into the backing file (must be page-aligned).
    pub offset: usize,
    /// Size of the mapping in bytes.
    pub size: usize,
    /// Protection flags (`PROT_READ`, `PROT_WRITE`, `PROT_EXEC`).
    pub flags: u32,
    pub _reserved: u32,
    /// Virtual address of the mapping.
    pub addr: usize,
}

// ── HandleInfo ──────────────────────────────────────────────────────────────

/// Information about a capability handle (returned by `SYS_HANDLE_INFO`).
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
#[repr(C)]
pub struct HandleInfo {
    /// Resource type (file, memory, IPC, etc.).
    pub resource_type: u32,
    /// Permission bits (read, write, execute, grant, revoke).
    pub permissions: u32,
    /// Underlying resource identifier (fd, memory region ID, etc.).
    pub resource: u64,
}

// ── MemoryRegionInfo ────────────────────────────────────────────────────────

/// Information about an exported memory region (returned by `SYS_MEM_REGION_INFO`).
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
#[repr(C)]
pub struct MemoryRegionInfo {
    /// Total size of the region in bytes.
    pub size: u64,
    /// Page size used for mapping.
    pub page_size: u64,
    /// Region flags (read, write, execute).
    pub flags: u32,
    pub _reserved: u32,
}

// ── AsyncRingLayout ─────────────────────────────────────────────────────────

/// Layout descriptor for async I/O ring buffers.
///
/// Describes the submission and completion queue regions within
/// a shared memory page used by the async I/O subsystem.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
#[repr(C)]
pub struct AsyncRingLayout {
    /// Physical address of the submission queue base.
    pub sq_base: u64,
    /// Physical address of the completion queue base.
    pub cq_base: u64,
    /// Size of the submission queue in bytes.
    pub sq_size: u64,
    /// Size of the completion queue in bytes.
    pub cq_size: u64,
    /// Number of entries in each queue.
    pub entries: u32,
    pub _reserved: u32,
}

// ── PCI ─────────────────────────────────────────────────────────────────────

/// PCI match flag: match by vendor ID.
pub const PCI_MATCH_VENDOR_ID: u32 = 1 << 0;

/// PCI match flag: match by device ID.
pub const PCI_MATCH_DEVICE_ID: u32 = 1 << 1;

/// PCI match flag: match by class code.
pub const PCI_MATCH_CLASS_CODE: u32 = 1 << 2;

/// PCI match flag: match by subclass.
pub const PCI_MATCH_SUBCLASS: u32 = 1 << 3;

/// PCI match flag: match by programming interface.
pub const PCI_MATCH_PROG_IF: u32 = 1 << 4;

/// PCI device address (bus/device/function).
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
#[repr(C, align(4))]
pub struct PciAddress {
    /// PCI bus number (0-255).
    pub bus: u8,
    /// PCI device number (0-31).
    pub device: u8,
    /// PCI function number (0-7).
    pub function: u8,
    pub _reserved: u8,
}

/// PCI device search criteria for `SYS_PCI_ENUM`.
///
/// Set `match_flags` to indicate which fields to match. Fields not
/// flagged are ignored.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
#[repr(C)]
pub struct PciProbeCriteria {
    /// Bitmask of fields to match (see `PCI_MATCH_*` constants).
    pub match_flags: u32,
    /// Vendor ID to match (if `PCI_MATCH_VENDOR_ID` is set).
    pub vendor_id: u16,
    /// Device ID to match (if `PCI_MATCH_DEVICE_ID` is set).
    pub device_id: u16,
    /// Class code to match (if `PCI_MATCH_CLASS_CODE` is set).
    pub class_code: u8,
    /// Subclass to match (if `PCI_MATCH_SUBCLASS` is set).
    pub subclass: u8,
    /// Programming interface to match (if `PCI_MATCH_PROG_IF` is set).
    pub prog_if: u8,
    pub _reserved: u8,
}

/// PCI device information returned by `SYS_PCI_ENUM`.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
#[repr(C)]
pub struct PciDeviceInfo {
    /// PCI bus/device/function address.
    pub address: PciAddress,
    /// Vendor ID (e.g., 0x8086 for Intel).
    pub vendor_id: u16,
    /// Device ID (e.g., 0x100E for Intel E1000).
    pub device_id: u16,
    /// PCI class code (e.g., 0x02 for network controller).
    pub class_code: u8,
    /// PCI subclass (e.g., 0x00 for Ethernet controller).
    pub subclass: u8,
    /// Programming interface (e.g., 0x00 for E1000).
    pub prog_if: u8,
    /// PCI revision ID.
    pub revision: u8,
    /// Header type (0 = standard, 1 = PCI-to-PCI bridge).
    pub header_type: u8,
    /// Interrupt line (IRQ number, 0 = none).
    pub interrupt_line: u8,
    /// Interrupt pin (A=1, B=2, C=3, D=4, 0 = none).
    pub interrupt_pin: u8,
    pub _reserved: u8,
}

// ── FileStat ────────────────────────────────────────────────────────────────

/// File status information (returned by `SYS_FSTAT`, `SYS_STAT`, `SYS_FSTATAT`).
///
/// Equivalent to POSIX `struct stat` with 64-bit fields.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
#[repr(C)]
pub struct FileStat {
    /// Device ID containing this file.
    pub st_dev: u64,
    /// Inode number.
    pub st_ino: u64,
    /// File type and permissions (see `DT_*` and `0o7777` masks).
    pub st_mode: u32,
    /// Number of hard links.
    pub st_nlink: u32,
    /// Owner user ID.
    pub st_uid: u32,
    /// Owner group ID.
    pub st_gid: u32,
    /// Device ID (for special files).
    pub st_rdev: u64,
    /// Total size in bytes.
    pub st_size: u64,
    /// Preferred block size for I/O.
    pub st_blksize: u64,
    /// Number of 512-byte blocks allocated.
    pub st_blocks: u64,
    /// Last access time.
    pub st_atime: TimeSpec,
    /// Last modification time.
    pub st_mtime: TimeSpec,
    /// Last status change time.
    pub st_ctime: TimeSpec,
}

impl FileStat {
    /// Return a fully zeroed `FileStat`.
    pub const fn zeroed() -> Self {
        FileStat {
            st_dev: 0,
            st_ino: 0,
            st_mode: 0,
            st_nlink: 0,
            st_uid: 0,
            st_gid: 0,
            st_rdev: 0,
            st_size: 0,
            st_blksize: 0,
            st_blocks: 0,
            st_atime: TimeSpec::zero(),
            st_mtime: TimeSpec::zero(),
            st_ctime: TimeSpec::zero(),
        }
    }

    /// Return true when the mode encodes a directory.
    pub fn is_dir(&self) -> bool {
        (self.st_mode & 0o170000) == 0o040000
    }

    /// Return true when the mode encodes a regular file.
    pub fn is_file(&self) -> bool {
        (self.st_mode & 0o170000) == 0o100000
    }
}

// ── IpcMessage ─────────────────────────────────────────────────────────────

/// Fixed-size IPC message (256 bytes, 64-byte aligned).
///
/// Used by IPC ports, channels, and the transport layer.
/// The header occupies 16 bytes; the payload is 240 bytes.
#[derive(Clone, Copy, FromBytes, IntoBytes)]
#[repr(C, align(64))]
pub struct IpcMessage {
    /// PID/TID of the sending process.
    pub sender: u64,
    /// Message type identifier (protocol-specific).
    pub msg_type: u32,
    /// Message flags (protocol-specific).
    pub flags: u32,
    /// Payload data (up to 240 bytes).
    pub payload: [u8; IPC_PAYLOAD_CAPACITY],
}

impl IpcMessage {
    /// Total wire size of the message (including header).
    pub const WIRE_SIZE: usize = IPC_MESSAGE_SIZE;
    /// Alignment requirement.
    pub const ALIGN: usize = IPC_MESSAGE_ALIGN;
    /// Maximum payload bytes.
    pub const PAYLOAD_CAPACITY: usize = IPC_PAYLOAD_CAPACITY;

    /// Usable payload capacity for `OPEN` inline path (240 - 6 bytes overhead).
    pub const OPEN_INLINE_CAPACITY: usize = IPC_PAYLOAD_CAPACITY - 6;
    /// Usable payload capacity for `UNLINK` inline path (240 - 2 bytes overhead).
    pub const UNLINK_INLINE_CAPACITY: usize = IPC_PAYLOAD_CAPACITY - 2;
    /// Usable payload capacity for `READ` inline path (240 - 8 bytes overhead).
    pub const READ_INLINE_CAPACITY: usize = IPC_PAYLOAD_CAPACITY - 8;
    /// Usable payload capacity for `WRITE` inline path (240 - 18 bytes overhead).
    pub const WRITE_INLINE_CAPACITY: usize = IPC_PAYLOAD_CAPACITY - 18;

    /// Create an empty IPC message for `msg_type`.
    pub const fn new(msg_type: u32) -> Self {
        IpcMessage {
            sender: 0,
            msg_type,
            flags: 0,
            payload: [0u8; IPC_PAYLOAD_CAPACITY],
        }
    }

    /// Build a standard error reply carrying a status code in payload.
    ///
    /// The `msg_type` is set to `0x80` (error reply marker).
    /// The payload contains the error code as a little-endian `i32`.
    pub fn error_reply(sender: u64, status: i32) -> Self {
        let mut msg = IpcMessage::new(0x80);
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

// ── Seek constants ──────────────────────────────────────────────────────────

/// Seek relative to the beginning of the file.
pub const SEEK_SET: usize = 0;

/// Seek relative to the current file position.
pub const SEEK_CUR: usize = 1;

/// Seek relative to the end of the file.
pub const SEEK_END: usize = 2;

// ── File type constants ─────────────────────────────────────────────────────

/// Unknown file type.
pub const DT_UNKNOWN: u8 = 0;

/// FIFO (named pipe).
pub const DT_FIFO: u8 = 1;

/// Character device.
pub const DT_CHR: u8 = 2;

/// Directory.
pub const DT_DIR: u8 = 4;

/// Block device.
pub const DT_BLK: u8 = 6;

/// Regular file.
pub const DT_REG: u8 = 8;

/// Symbolic link.
pub const DT_LNK: u8 = 10;

/// Unix domain socket.
pub const DT_SOCK: u8 = 12;

// ── DirentHeader ────────────────────────────────────────────────────────────

/// Fixed-size header for each directory entry in the `SYS_GETDENTS` wire format.
///
/// Wire layout per entry: `DirentHeader` (12 bytes) followed by `name_len`
/// bytes of filename data and a trailing NUL byte.
///
/// Total entry size = 12 + name_len + 1 bytes.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
#[repr(C, packed)]
pub struct DirentHeader {
    /// Inode number of the entry.
    pub ino: u64,
    /// File type (see `DT_*` constants).
    pub file_type: u8,
    /// Length of the filename in bytes (excluding NUL).
    pub name_len: u16,
    pub _padding: u8,
}

impl DirentHeader {
    /// Size of the fixed header portion (12 bytes).
    pub const SIZE: usize = 12; // 8 + 1 + 2 + 1

    /// Return the total packed entry size (header + name + trailing NUL).
    pub const fn entry_size(&self) -> usize {
        Self::SIZE + self.name_len as usize + 1
    }
}

// ── SiloConfig ──────────────────────────────────────────────────────────────

/// Silo configuration block passed from init to `SYS_SILO_CREATE`.
///
/// Defines resource limits, capabilities, and scheduling parameters
/// for a new silo (process isolation container).
///
/// Layout must match the kernel's definition (ABI contract).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SiloConfig {
    /// Minimum memory reservation in bytes.
    pub mem_min: u64,
    /// Maximum memory limit in bytes (0 = unlimited).
    pub mem_max: u64,
    /// CPU scheduling weight (relative priority).
    pub cpu_shares: u32,
    /// CPU time quota per period in microseconds (0 = unlimited).
    pub cpu_quota_us: u64,
    /// CPU scheduling period in microseconds.
    pub cpu_period_us: u64,
    /// CPU affinity bitmask (0 = any CPU).
    pub cpu_affinity_mask: u64,
    /// Maximum number of threads/tasks in the silo.
    pub max_tasks: u32,
    /// Read bandwidth limit in bytes/sec (0 = unlimited).
    pub io_bw_read: u64,
    /// Write bandwidth limit in bytes/sec (0 = unlimited).
    pub io_bw_write: u64,
    /// Pointer to the initial capability list.
    pub caps_ptr: u64,
    /// Length of the capability list in bytes.
    pub caps_len: u64,
    /// Silo behavior flags.
    pub flags: u64,
    /// Silo ID (assigned by kernel, 0 = auto-assign).
    pub sid: u32,
    /// Octal permission mode (see `SiloMode`).
    pub mode: u16,
    /// Silo family/type identifier.
    pub family: u8,
    /// Required CPU features (bitmask from CPUID).
    pub cpu_features_required: u64,
    /// Allowed CPU features (bitmask, 0 = all allowed).
    pub cpu_features_allowed: u64,
    /// XCR0 register mask for FPU/SSE/AVX state.
    pub xcr0_mask: u64,
    /// Maximum concurrent graphics sessions (0 = no graphics).
    pub graphics_max_sessions: u16,
    /// Graphics session time-to-live in seconds.
    pub graphics_session_ttl_sec: u32,
    pub graphics_reserved: u16,
}

impl SiloConfig {
    /// Return a zero-initialized silo configuration.
    pub const fn zero() -> Self {
        Self {
            mem_min: 0,
            mem_max: 0,
            cpu_shares: 0,
            cpu_quota_us: 0,
            cpu_period_us: 0,
            cpu_affinity_mask: 0,
            max_tasks: 0,
            io_bw_read: 0,
            io_bw_write: 0,
            caps_ptr: 0,
            caps_len: 0,
            flags: 0,
            sid: 0,
            mode: 0,
            family: 0,
            cpu_features_required: 0,
            cpu_features_allowed: u64::MAX,
            xcr0_mask: 0,
            graphics_max_sessions: 0,
            graphics_session_ttl_sec: 0,
            graphics_reserved: 0,
        }
    }
}

// ── Static assertions ──────────────────────────────────────────────────────

macro_rules! assert_abi_struct {
    ($t:ty, $size:expr, $align:expr) => {
        static_assertions::assert_eq_size!($t, [u8; $size]);
        static_assertions::const_assert_eq!(core::mem::align_of::<$t>(), $align);
    };
}

assert_abi_struct!(DirentHeader, 12, 1);
assert_abi_struct!(Stat, 120, 8);
assert_abi_struct!(StatVfs, 88, 8);
assert_abi_struct!(Map, 32, 8);
assert_abi_struct!(FileStat, 112, 8);
assert_abi_struct!(IpcMessage, IPC_MESSAGE_SIZE, IPC_MESSAGE_ALIGN);
assert_abi_struct!(TimeSpec, 16, 8);
assert_abi_struct!(HandleInfo, 16, 8);
assert_abi_struct!(MemoryRegionInfo, 24, 8);
assert_abi_struct!(PciAddress, 4, 4);
assert_abi_struct!(PciProbeCriteria, 12, 4);
assert_abi_struct!(PciDeviceInfo, 16, 4);
