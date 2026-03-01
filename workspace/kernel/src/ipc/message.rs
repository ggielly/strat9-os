//! IPC message type.
//!
//! Messages are 64 bytes (one cache line). The kernel fills in the `sender`
//! field before delivering the message to the receiver.

use zerocopy::FromBytes;

/// Structured IPC security label.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromBytes)]
pub struct IpcLabel {
    /// Trust tier: Critical(0), System(1), User(2).
    pub tier: u8,
    /// Strate family tag.
    pub family: u8,
    /// Sub-compartment within the family.
    pub compartment: u16,
}

/// A 64-byte inline IPC message.
///
/// Layout:
/// ```text
///  0..  8  sender   (u64, filled by kernel)
///  8.. 12  msg_type (u32, opcode chosen by sender)
/// 12.. 16  flags    (u32, security tag or handle transfer)
/// 16.. 64  payload  (48 bytes, opaque data)
/// ```
#[repr(C, align(64))]
#[derive(Clone, Copy, FromBytes)]
pub struct IpcMessage {
    pub sender: u64,
    pub msg_type: u32,
    pub flags: u32, // Re-renamed to flags for compatibility
    pub payload: [u8; 48],
}

static_assertions::assert_eq_size!(IpcMessage, [u8; 64]);
static_assertions::const_assert_eq!(core::mem::align_of::<IpcMessage>(), 64);

impl IpcMessage {
    pub fn new(msg_type: u32) -> Self {
        IpcMessage {
            sender: 0,
            msg_type,
            flags: 0,
            payload: [0u8; 48],
        }
    }

    /// Create a message from a raw 64-byte buffer (e.g. copied from userspace).
    ///
    /// Handles unaligned source buffers via bytewise copy.
    ///
    /// # Safety
    ///
    /// The caller must ensure `buf` points to at least 64 readable bytes.
    pub unsafe fn from_raw(buf: *const u8) -> Self {
        // SAFETY: `IpcMessage` is POD and fully initialized by the copy below.
        let mut msg: Self = unsafe { core::mem::zeroed() };
        // SAFETY: caller guarantees `buf` points to at least 64 readable bytes,
        // and `msg` points to a valid 64-byte destination.
        unsafe {
            core::ptr::copy_nonoverlapping(buf, &mut msg as *mut _ as *mut u8, 64);
        }
        msg
    }

    /// Write this message to a raw 64-byte buffer.
    ///
    /// # Safety
    ///
    /// The caller must ensure `buf` points to at least 64 writable bytes.
    pub unsafe fn to_raw(&self, buf: *mut u8) {
        // SAFETY: caller guarantees `buf` points to at least 64 writable bytes,
        // and `self` points to a valid 64-byte source.
        unsafe {
            core::ptr::copy_nonoverlapping(self as *const _ as *const u8, buf, 64);
        }
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
