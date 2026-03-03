#[derive(Debug, Clone, Copy)]
#[repr(C)]
/// Shared-memory signal action descriptor used by the syscall ABI.
pub struct SigAbi {
    pub signal: u8,
    pub handler: usize,
    pub flags: u32,
    pub mask: u64,
}

impl SigAbi {
    /// Create a signal ABI descriptor from raw handler configuration.
    pub fn new(signal: u8, handler: usize, flags: u32, mask: u64) -> Self {
        Self {
            signal,
            handler,
            flags,
            mask,
        }
    }
}
