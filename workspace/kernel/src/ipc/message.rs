pub use strat9_abi::data::IpcMessage;

use zerocopy::FromBytes;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromBytes)]
pub struct IpcLabel {
    pub tier: u8,
    pub family: u8,
    pub compartment: u16,
}

pub fn ipc_message_from_raw(buf: &[u8; 64]) -> IpcMessage {
    // SAFETY: `buf` has exactly 64 bytes, matching `IpcMessage` size.
    unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const IpcMessage) }
}

pub fn ipc_message_to_raw(msg: &IpcMessage, out: &mut [u8; 64]) {
    // SAFETY: `out` has exactly 64 bytes, matching `IpcMessage` size.
    unsafe {
        core::ptr::copy_nonoverlapping(msg as *const _ as *const u8, out.as_mut_ptr(), 64);
    }
}

static_assertions::assert_eq_size!(IpcMessage, [u8; 64]);
static_assertions::const_assert_eq!(core::mem::align_of::<IpcMessage>(), 64);
