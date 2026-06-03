use zerocopy::{FromBytes, IntoBytes};

pub const IPC_MESSAGE_SIZE: usize = 256;
pub const IPC_MESSAGE_ALIGN: usize = 64;
pub const IPC_MESSAGE_HEADER_SIZE: usize = 16;
pub const IPC_PAYLOAD_CAPACITY: usize = IPC_MESSAGE_SIZE - IPC_MESSAGE_HEADER_SIZE;
pub const IPC_FILE_FLAG_DIRECTORY: u32 = 1 << 0;
pub const IPC_FILE_FLAG_DEVICE: u32 = 1 << 1;
pub const IPC_FILE_FLAG_PIPE: u32 = 1 << 2;
pub const IPC_FILE_FLAG_APPEND: u32 = 1 << 3;
pub const IPC_FILE_FLAG_CHUNK_READ: u32 = 1 << 4;
pub const IPC_FILE_FLAG_CHUNK_WRITE: u32 = 1 << 5;

/// 9-bit octal silo mode (3 control + 3 hardware + 3 registry).
///
/// Shared ABI type used by both kernel and userspace init.
/// The kernel's richer `OctalMode` (with typed bitflag fields)
/// is built from this via `OctalMode::from_octal(val.0)`.
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

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
#[repr(C)]
pub struct TimeSpec {
    pub tv_sec: i64,
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

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
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

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
#[repr(C)]
pub struct Map {
    pub offset: usize,
    pub size: usize,
    pub flags: u32,
    pub _reserved: u32,
    pub addr: usize,
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
#[repr(C)]
pub struct HandleInfo {
    pub resource_type: u32,
    pub permissions: u32,
    pub resource: u64,
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
#[repr(C)]
pub struct MemoryRegionInfo {
    pub size: u64,
    pub page_size: u64,
    pub flags: u32,
    pub _reserved: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
#[repr(C)]
pub struct AsyncRingLayout {
    pub sq_base: u64,
    pub cq_base: u64,
    pub sq_size: u64,
    pub cq_size: u64,
    pub entries: u32,
    pub _reserved: u32,
}

pub const PCI_MATCH_VENDOR_ID: u32 = 1 << 0;
pub const PCI_MATCH_DEVICE_ID: u32 = 1 << 1;
pub const PCI_MATCH_CLASS_CODE: u32 = 1 << 2;
pub const PCI_MATCH_SUBCLASS: u32 = 1 << 3;
pub const PCI_MATCH_PROG_IF: u32 = 1 << 4;

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
#[repr(C, align(4))]
pub struct PciAddress {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub _reserved: u8,
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
#[repr(C)]
pub struct PciProbeCriteria {
    pub match_flags: u32,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_code: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub _reserved: u8,
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
#[repr(C)]
pub struct PciDeviceInfo {
    pub address: PciAddress,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_code: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub revision: u8,
    pub header_type: u8,
    pub interrupt_line: u8,
    pub interrupt_pin: u8,
    pub _reserved: u8,
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
#[repr(C)]
pub struct FileStat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_mode: u32,
    pub st_nlink: u32,
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

#[derive(Clone, Copy, FromBytes, IntoBytes)]
#[repr(C, align(64))]
pub struct IpcMessage {
    pub sender: u64,
    pub msg_type: u32,
    pub flags: u32,
    pub payload: [u8; IPC_PAYLOAD_CAPACITY],
}

impl IpcMessage {
    pub const WIRE_SIZE: usize = IPC_MESSAGE_SIZE;
    pub const ALIGN: usize = IPC_MESSAGE_ALIGN;
    pub const PAYLOAD_CAPACITY: usize = IPC_PAYLOAD_CAPACITY;
    pub const OPEN_INLINE_CAPACITY: usize = IPC_PAYLOAD_CAPACITY - 6;
    pub const UNLINK_INLINE_CAPACITY: usize = IPC_PAYLOAD_CAPACITY - 2;
    pub const READ_INLINE_CAPACITY: usize = IPC_PAYLOAD_CAPACITY - 8;
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
    pub fn error_reply(sender: u64, status: i32) -> Self {
        let mut msg = IpcMessage::new(0x80);
        msg.sender = sender;
        msg.payload[0..4].copy_from_slice(&(status as u32).to_le_bytes());
        msg
    }
}

impl core::fmt::Debug for IpcMessage {
    /// Implements fmt.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IpcMessage")
            .field("sender", &self.sender)
            .field("msg_type", &format_args!("0x{:02x}", self.msg_type))
            .field("flags", &self.flags)
            .finish()
    }
}

pub const SEEK_SET: usize = 0;
pub const SEEK_CUR: usize = 1;
pub const SEEK_END: usize = 2;

// File type constants (matching Linux DT_* values)
pub const DT_UNKNOWN: u8 = 0;
pub const DT_FIFO: u8 = 1;
pub const DT_CHR: u8 = 2;
pub const DT_DIR: u8 = 4;
pub const DT_BLK: u8 = 6;
pub const DT_REG: u8 = 8;
pub const DT_LNK: u8 = 10;
pub const DT_SOCK: u8 = 12;

/// Fixed-size header for each directory entry in the SYS_GETDENTS wire format.
///
/// Wire layout per entry: `DirentHeader` (12 bytes) followed by `name_len`
/// bytes of filename data and a trailing NUL byte.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
#[repr(C, packed)]
pub struct DirentHeader {
    pub ino: u64,
    pub file_type: u8,
    pub name_len: u16,
    pub _padding: u8,
}

impl DirentHeader {
    pub const SIZE: usize = 12; // 8 + 1 + 2 + 1

    /// Return the total packed entry size (header + name + trailing NUL).
    pub const fn entry_size(&self) -> usize {
        Self::SIZE + self.name_len as usize + 1
    }
}

/// Silo configuration block passed from init to `silo_create()`.
///
/// Layout must match the kernel's definition (ABI contract).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SiloConfig {
    pub mem_min: u64,
    pub mem_max: u64,
    pub cpu_shares: u32,
    pub cpu_quota_us: u64,
    pub cpu_period_us: u64,
    pub cpu_affinity_mask: u64,
    pub max_tasks: u32,
    pub io_bw_read: u64,
    pub io_bw_write: u64,
    pub caps_ptr: u64,
    pub caps_len: u64,
    pub flags: u64,
    pub sid: u32,
    pub mode: u16,
    pub family: u8,
    pub cpu_features_required: u64,
    pub cpu_features_allowed: u64,
    pub xcr0_mask: u64,
    pub graphics_max_sessions: u16,
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
