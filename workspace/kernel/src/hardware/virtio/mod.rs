//! VirtIO driver framework
//!
//! VirtIO provides a standard interface for virtual devices (disk, network, etc.)
//! in QEMU/KVM environments.
//!
//! References:
//! - VirtIO spec: https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html
//! - RedoxOS drivers: https://gitlab.redox-os.org/redox-os/drivers

pub mod common;
pub mod console;
pub mod gpu;
pub mod rng;

/// VirtIO device status flags
#[allow(dead_code)]
pub mod status {
    pub const ACKNOWLEDGE: u32 = 1;
    pub const DRIVER: u32 = 2;
    pub const DRIVER_OK: u32 = 4;
    pub const FEATURES_OK: u32 = 8;
    pub const DEVICE_NEEDS_RESET: u32 = 64;
    pub const FAILED: u32 = 128;
}

/// VirtIO device types (subsystem IDs)
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u16)]
pub enum DeviceType {
    Network = 1,
    Block = 2,
    Console = 3,
    Entropy = 4,
    Gpu = 16,
    Input = 18,
}

/// VirtIO MMIO register offsets
#[allow(dead_code)]
pub mod mmio {
    pub const MAGIC_VALUE: usize = 0x000;
    pub const VERSION: usize = 0x004;
    pub const DEVICE_ID: usize = 0x008;
    pub const VENDOR_ID: usize = 0x00C;
    pub const DEVICE_FEATURES: usize = 0x010;
    pub const DEVICE_FEATURES_SEL: usize = 0x014;
    pub const DRIVER_FEATURES: usize = 0x020;
    pub const DRIVER_FEATURES_SEL: usize = 0x024;
    pub const QUEUE_SEL: usize = 0x030;
    pub const QUEUE_NUM_MAX: usize = 0x034;
    pub const QUEUE_NUM: usize = 0x038;
    pub const QUEUE_READY: usize = 0x044;
    pub const QUEUE_NOTIFY: usize = 0x050;
    pub const INTERRUPT_STATUS: usize = 0x060;
    pub const INTERRUPT_ACK: usize = 0x064;
    pub const STATUS: usize = 0x070;
}

/// A VirtIO virtqueue descriptor
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtqDesc {
    /// Physical address of the buffer
    pub addr: u64,
    /// Length of the buffer
    pub len: u32,
    /// Flags (NEXT, WRITE, INDIRECT)
    pub flags: u16,
    /// Next descriptor index (if NEXT flag set)
    pub next: u16,
}

/// Virtqueue descriptor flags
#[allow(dead_code)]
pub mod vring_flags {
    pub const NEXT: u16 = 1;
    pub const WRITE: u16 = 2;
    pub const INDIRECT: u16 = 4;
}
