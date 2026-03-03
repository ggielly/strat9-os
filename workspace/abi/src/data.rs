use zerocopy::{FromBytes, IntoBytes};

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
#[repr(C)]
pub struct TimeSpec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

impl TimeSpec {
    pub const fn zero() -> Self {
        Self { tv_sec: 0, tv_nsec: 0 }
    }

    pub fn to_nanos(&self) -> u64 {
        (self.tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(self.tv_nsec as u64)
    }

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

#[derive(Clone, Copy, FromBytes, IntoBytes)]
#[repr(C, align(64))]
pub struct IpcMessage {
    pub sender: u64,
    pub msg_type: u32,
    pub flags: u32,
    pub payload: [u8; 48],
}

impl IpcMessage {
    pub const fn new(msg_type: u32) -> Self {
        IpcMessage {
            sender: 0,
            msg_type,
            flags: 0,
            payload: [0u8; 48],
        }
    }

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

    pub const fn entry_size(&self) -> usize {
        Self::SIZE + self.name_len as usize + 1
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
assert_abi_struct!(FileStat, 40, 8);
assert_abi_struct!(IpcMessage, 64, 64);
assert_abi_struct!(TimeSpec, 16, 8);
assert_abi_struct!(HandleInfo, 16, 8);
assert_abi_struct!(PciAddress, 4, 4);
assert_abi_struct!(PciProbeCriteria, 12, 4);
assert_abi_struct!(PciDeviceInfo, 16, 4);
