pub use strat9_abi::data::IpcMessage;

use zerocopy::FromBytes;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromBytes)]
pub struct IpcLabel {
    pub tier: u8,
    pub family: u8,
    pub compartment: u16,
}

impl IpcMessage {
    /// # Safety
    /// `buf` must point to at least 64 readable bytes.
    pub unsafe fn from_raw(buf: *const u8) -> Self {
        // SAFETY: IpcMessage is POD, fully initialized by copy.
        let mut msg: Self = unsafe { core::mem::zeroed() };
        // SAFETY: caller guarantees buf validity.
        unsafe {
            core::ptr::copy_nonoverlapping(buf, &mut msg as *mut _ as *mut u8, 64);
        }
        msg
    }

    /// # Safety
    /// `buf` must point to at least 64 writable bytes.
    pub unsafe fn to_raw(&self, buf: *mut u8) {
        // SAFETY: caller guarantees buf validity.
        unsafe {
            core::ptr::copy_nonoverlapping(self as *const _ as *const u8, buf, 64);
        }
    }
}

static_assertions::assert_eq_size!(IpcMessage, [u8; 64]);
static_assertions::const_assert_eq!(core::mem::align_of::<IpcMessage>(), 64);
