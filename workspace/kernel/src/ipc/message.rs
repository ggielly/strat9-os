//! IPC message type.
//!
//! Messages are 64 bytes (one cache line), matching the ABI defined in
//! `components/api/src/lib.rs`. The kernel fills in the `sender` field
//! before delivering the message to the receiver.

/// A 64-byte inline IPC message.
///
/// Layout:
/// ```text
///  0..  8  sender   (u64, filled by kernel)
///  8.. 12  msg_type (u32, opcode chosen by sender)
/// 12.. 16  flags    (u32, reserved)
/// 16.. 64  payload  (48 bytes, opaque data)
/// ```
#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct IpcMessage {
    /// TaskId of the sender (set by the kernel on send).
    pub sender: u64,
    /// Application-defined message type / opcode.
    pub msg_type: u32,
    /// Reserved flags (must be 0 for now).
    pub flags: u32,
    /// Inline payload (up to 48 bytes).
    pub payload: [u8; 48],
}

// Compile-time check: IpcMessage must be exactly 64 bytes.
const _: () = assert!(core::mem::size_of::<IpcMessage>() == 64);

impl IpcMessage {
    /// Create a new message with the given type and zeroed payload.
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
    /// # Safety
    ///
    /// The caller must ensure `buf` points to at least 64 readable bytes.
    pub unsafe fn from_raw(buf: *const u8) -> Self {
        let mut msg = IpcMessage::new(0);
        // SAFETY: Caller guarantees buf is valid for 64 bytes.
        core::ptr::copy_nonoverlapping(buf, &mut msg as *mut IpcMessage as *mut u8, 64);
        msg
    }

    /// Write this message to a raw 64-byte buffer.
    ///
    /// # Safety
    ///
    /// The caller must ensure `buf` points to at least 64 writable bytes.
    pub unsafe fn to_raw(&self, buf: *mut u8) {
        // SAFETY: Caller guarantees buf is valid for 64 bytes.
        core::ptr::copy_nonoverlapping(self as *const IpcMessage as *const u8, buf, 64);
    }
}

impl core::fmt::Debug for IpcMessage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IpcMessage")
            .field("sender", &self.sender)
            .field("msg_type", &self.msg_type)
            .field("flags", &self.flags)
            .finish()
    }
}
