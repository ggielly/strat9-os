#![no_std]

pub const MTU: usize = 1514;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetError {
    NoPacket,
    TxQueueFull,
    BufferTooSmall,
    NotReady,
    LinkDown,
    DeviceNotFound,
}

impl core::fmt::Display for NetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoPacket => f.write_str("no packet available"),
            Self::TxQueueFull => f.write_str("transmit queue full"),
            Self::BufferTooSmall => f.write_str("buffer too small"),
            Self::NotReady => f.write_str("device not ready"),
            Self::LinkDown => f.write_str("link down"),
            Self::DeviceNotFound => f.write_str("device not found"),
        }
    }
}

/// Unified network device interface.
///
/// Kernel-resident drivers wrap their hardware-specific struct in a
/// `SpinLock` and implement this trait with interior mutability.
/// Future silo-hosted drivers expose the same interface via IPC.
pub trait NetworkDevice: Send + Sync {
    fn name(&self) -> &str;
    fn receive(&self, buf: &mut [u8]) -> Result<usize, NetError>;
    fn transmit(&self, buf: &[u8]) -> Result<(), NetError>;
    fn mac_address(&self) -> [u8; 6];
    fn link_up(&self) -> bool;
    fn handle_interrupt(&self) {}
}
