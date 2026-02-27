// NVMe command structures
// Reference: NVM Express Base Specification 2.0

use bitflags::bitflags;

#[repr(u8)]
#[derive(Default, Copy, Clone)]
pub enum IdentifyCns {
    Namespace = 0x00,
    Controller = 0x01,
    NamespaceList = 0x02,
    #[default]
    Unknown = u8::MAX,
}

bitflags! {
    #[derive(Default, Clone, Copy)]
    pub struct CommandFlags: u16 {
        const QUEUE_PHYS_CONTIG = 1 << 0;
        const CQ_IRQ_ENABLED = 1 << 1;
    }
}

#[repr(u8)]
#[derive(Default, Copy, Clone)]
pub enum CommandOpcode {
    Write = 0x01,
    Read = 0x02,
    #[default]
    Unknown = u8::MAX,
}

#[repr(u8)]
#[derive(Default, Copy, Clone)]
pub enum AdminOpcode {
    DeleteSq = 0x00,
    CreateSq = 0x01,
    GetLogPage = 0x02,
    DeleteCq = 0x04,
    CreateCq = 0x05,
    Identify = 0x06,
    Abort = 0x08,
    SetFeatures = 0x09,
    GetFeatures = 0x0A,
    AsyncEvent = 0x0C,
    NvmSubsystemReset = 0x15,
    ControllerReset = 0x16,
    #[default]
    Unknown = u8::MAX,
}

#[derive(Debug, Default, Copy, Clone)]
#[repr(C)]
pub struct DataPointer {
    pub prp1: u64,
    pub prp2: u64,
}

#[derive(Default, Copy, Clone)]
#[repr(C)]
pub struct CommonCommand {
    pub opcode: u8,
    pub flags: u8,
    pub command_id: u16,
    pub namespace_id: u32,
    pub cdw2: [u32; 2],
    pub metadata: u64,
    pub data_ptr: DataPointer,
    pub cdw10: u32,
    pub cdw11: u32,
    pub cdw12: u32,
    pub cdw13: u32,
    pub cdw14: u32,
    pub cdw15: u32,
}

static_assertions::const_assert_eq!(core::mem::size_of::<CommonCommand>(), 64);

#[derive(Default, Copy, Clone)]
#[repr(C)]
pub struct IdentifyCommand {
    pub opcode: u8,
    pub flags: u8,
    pub command_id: u16,
    pub nsid: u32,
    pub reserved2: [u64; 2],
    pub data_ptr: DataPointer,
    pub cns: u8,
    pub reserved3: u8,
    pub controller_id: u16,
    pub reserved11: [u32; 5],
}

impl From<IdentifyCommand> for Command {
    fn from(val: IdentifyCommand) -> Self {
        Command { identify: val }
    }
}

static_assertions::const_assert_eq!(core::mem::size_of::<IdentifyCommand>(), 64);

#[derive(Debug, Default, Copy, Clone)]
#[repr(C)]
pub struct CreateSqCommand {
    pub opcode: u8,
    pub flags: u8,
    pub command_id: u16,
    pub reserved: [u32; 10],
    pub cqid: u16,
    pub sq_flags: u16,
    pub cqid_sqd: u16,
    pub sqid: u16,
    pub prp1: u64,
}

static_assertions::const_assert_eq!(core::mem::size_of::<CreateSqCommand>(), 64);

#[derive(Debug, Default, Copy, Clone)]
#[repr(C)]
pub struct CreateCqCommand {
    pub opcode: u8,
    pub flags: u8,
    pub command_id: u16,
    pub reserved: [u32; 10],
    pub cqid: u16,
    pub cq_flags: u16,
    pub irq_vector: u16,
    pub reserved2: u16,
    pub prp1: u64,
}

static_assertions::const_assert_eq!(core::mem::size_of::<CreateCqCommand>(), 64);

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct NvmCommand {
    pub opcode: u8,
    pub flags: u8,
    pub command_id: u16,
    pub nsid: u32,
    pub cdw2: u32,
    pub cdw3: u32,
    pub metadata: u64,
    pub prp1: u64,
    pub prp2: u64,
    pub cdw10: u32,
    pub cdw11: u32,
    pub cdw12: u32,
    pub cdw13: u32,
    pub cdw14: u32,
    pub cdw15: u32,
}

static_assertions::const_assert_eq!(core::mem::size_of::<NvmCommand>(), 64);

#[repr(C)]
pub union Command {
    pub common: CommonCommand,
    pub identify: IdentifyCommand,
    pub create_sq: CreateSqCommand,
    pub create_cq: CreateCqCommand,
    pub nvm: NvmCommand,
    pub raw: [u32; 16],
}

impl Default for Command {
    fn default() -> Self {
        Self {
            common: CommonCommand::default(),
        }
    }
}

impl Command {
    pub fn as_mut_ptr(&mut self) -> *mut u32 {
        unsafe { &mut self.raw as *mut [u32; 16] as *mut u32 }
    }
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct CompletionEntry {
    pub dw0: u32,
    pub dw1: u32,
    pub sq_head: u16,
    pub sq_id: u16,
    pub command_id: u16,
    pub status: u16,
}

static_assertions::const_assert_eq!(core::mem::size_of::<CompletionEntry>(), 16);

impl CompletionEntry {
    pub fn status_code(&self) -> u8 {
        ((self.status >> 1) & 0xFF) as u8
    }

    pub fn status_type(&self) -> u8 {
        (self.status >> 9) & 0x7
    }

    pub fn is_valid(&self, phase: bool) -> bool {
        ((self.status & 0x1) != 0) == phase
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct StatusType: u8 {
        const GENERIC = 0x0;
        const COMMAND_SPECIFIC = 0x1;
        const MEDIA_DATA = 0x2;
        const PATH = 0x3;
    }
}

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum GenericStatus {
    Success = 0x00,
    InvalidCommandOpcode = 0x01,
    InvalidField = 0x02,
    CommandIdConflict = 0x03,
    DataTransferError = 0x04,
    CommandsAborted = 0x05,
    InvalidNamespace = 0x0B,
    LbaOutOfRange = 0x80,
    CapacityExceeded = 0x81,
}
