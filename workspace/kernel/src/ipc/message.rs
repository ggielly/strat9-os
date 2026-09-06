pub use strat9_abi::data::IpcMessage;
use strat9_abi::data::{IPC_MESSAGE_ALIGN, IPC_MESSAGE_SIZE};

use zerocopy::FromBytes;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromBytes)]
pub struct IpcLabel {
    pub tier: u8,
    pub family: u8,
    pub compartment: u16,
}

/// Performs the ipc message from raw operation.
pub fn ipc_message_from_raw(buf: &[u8; IPC_MESSAGE_SIZE]) -> IpcMessage {
    // SAFETY: `buf` has exactly `IPC_MESSAGE_SIZE` bytes, matching `IpcMessage` size.
    unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const IpcMessage) }
}

/// Performs the ipc message to raw operation.
pub fn ipc_message_to_raw(msg: &IpcMessage, out: &mut [u8; IPC_MESSAGE_SIZE]) {
    // SAFETY: `out` has exactly `IPC_MESSAGE_SIZE` bytes, matching `IpcMessage` size.
    unsafe {
        core::ptr::copy_nonoverlapping(
            msg as *const _ as *const u8,
            out.as_mut_ptr(),
            IPC_MESSAGE_SIZE,
        );
    }
}

static_assertions::assert_eq_size!(IpcMessage, [u8; IPC_MESSAGE_SIZE]);
static_assertions::const_assert_eq!(core::mem::align_of::<IpcMessage>(), IPC_MESSAGE_ALIGN);
