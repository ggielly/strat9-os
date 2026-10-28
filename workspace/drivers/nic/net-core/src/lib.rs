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

/// Link-layer media type, as reported by `ifconfig`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetMedia {
    /// Ethernet framing (Ethernet II header, 6-byte MAC).
    Ethernet,
    /// IEEE 802.3 framing without the Ethernet II type field.
    Ieee8023,
    /// Point-to-point serial link.
    Ppp,
    /// Fibre channel.
    FibreChannel,
    /// Loopback adapter.
    Loopback,
    /// Anything a driver cannot classify.
    Other,
}

impl NetMedia {
    /// Short lowercase name used by `ifconfig`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ethernet => "ethernet",
            Self::Ieee8023 => "ieee802.3",
            Self::Ppp => "ppp",
            Self::FibreChannel => "fibrechannel",
            Self::Loopback => "loopback",
            Self::Other => "other",
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

    /// Link-layer media. Ethernet is the only framing implemented today.
    fn media(&self) -> NetMedia {
        NetMedia::Ethernet
    }

    /// Periodic housekeeping called from the timer path (or interrupt
    /// context).  Default is a no-op; drivers that need a watchdog or
    /// buffer-reclamation cycle override this.
    fn poll(&self) {}

    /// Negotiated `strat9_abi::net::features::*` mask.
    ///
    /// Drivers return only the features they actually implement; the stack
    /// must never assume an offload is available.  Default is 0 (software
    /// fallback for everything).
    fn features(&self) -> u64 {
        0
    }

    /// IP MTU (without the Ethernet header).
    fn mtu(&self) -> usize {
        MTU - 14
    }

    /// Number of hardware queues exposed by the device.
    fn queue_count(&self) -> u16 {
        1
    }

    /// Current link speed in Mbps, or 0 when unknown.
    fn link_speed_mbps(&self) -> u32 {
        0
    }

    /// Device generation.  Bumped after reset/hotplug; consumers must reject
    /// operations carrying a stale epoch.
    fn epoch(&self) -> u32 {
        1
    }

    /// Stop DMA and interrupts, drain in-flight work.  Default no-op.
    fn quiesce(&self) -> Result<(), NetError> {
        Ok(())
    }

    /// Resume after `quiesce`.
    fn resume(&self) -> Result<(), NetError> {
        Ok(())
    }

    /// Reset the device.
    fn reset(&self) -> Result<(), NetError> {
        Ok(())
    }
}
