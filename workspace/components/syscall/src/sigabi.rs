

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SigAbi {
    pub signal: u8,
    pub handler: usize,
    pub flags: u32,
    pub mask: u64,
}

impl SigAbi {
    pub fn new(signal: u8, handler: usize, flags: u32, mask: u64) -> Self {
        Self {
            signal,
            handler,
            flags,
            mask,
        }
    }
}
