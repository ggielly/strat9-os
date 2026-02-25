//! Network driver framework
//!
//! Common traits, error types, and device registry shared by all network
//! drivers (VirtIO-net, Intel E1000, and future silo-hosted drivers).
//!
//! # Silo integration
//!
//! Kernel-resident drivers implement [`NetworkDevice`] directly.
//! When a "driver" silo is loaded, it communicates through IPC using
//! the opcodes defined in [`ipc_opcodes`].  The [`scheme`] module
//! provides a VFS scheme (`/dev/net/`) so both kernel and userspace
//! consumers use the same file-oriented interface.

pub mod e1000;
pub mod scheme;

use crate::sync::SpinLock;
use alloc::{format, string::String, sync::Arc, vec::Vec};

/// Maximum Ethernet frame payload (excluding FCS).
pub const MTU: usize = 1514;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// NetworkDevice trait
// ---------------------------------------------------------------------------

/// Unified interface for all network device drivers.
///
/// Kernel drivers implement this trait directly.  A future silo-based
/// driver will have a thin kernel shim that translates IPC messages
/// into calls on this trait, so the rest of the kernel (and the VFS
/// scheme) never needs to know where the driver actually lives.
pub trait NetworkDevice: Send + Sync {
    /// Human-readable driver name (e.g. `"e1000"`, `"virtio-net"`).
    fn name(&self) -> &str;

    /// Receive a single packet into `buf`.
    ///
    /// Returns the number of bytes written on success.
    fn receive(&self, buf: &mut [u8]) -> Result<usize, NetError>;

    /// Transmit a single packet from `buf`.
    fn transmit(&self, buf: &[u8]) -> Result<(), NetError>;

    /// Read the hardware MAC address.
    fn mac_address(&self) -> [u8; 6];

    /// `true` when the physical link is up.
    fn link_up(&self) -> bool;

    /// Called from the IRQ handler when this device's interrupt fires.
    fn handle_interrupt(&self) {}
}

// ---------------------------------------------------------------------------
// Device registry
// ---------------------------------------------------------------------------

struct NetDeviceEntry {
    iface: String,
    device: Arc<dyn NetworkDevice>,
}

static NET_DEVICES: SpinLock<Vec<NetDeviceEntry>> = SpinLock::new(Vec::new());

/// Register a network device; returns the auto-assigned interface name (`ethN`).
pub fn register_device(device: Arc<dyn NetworkDevice>) -> String {
    let mut devs = NET_DEVICES.lock();
    let idx = devs.len();
    let iface = format!("eth{}", idx);
    let mac = device.mac_address();
    log::info!(
        "[net] Registered {} as {} (MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})",
        device.name(),
        iface,
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5],
    );
    devs.push(NetDeviceEntry {
        iface: iface.clone(),
        device,
    });
    iface
}

/// Look up a device by its interface name.
pub fn get_device(name: &str) -> Option<Arc<dyn NetworkDevice>> {
    NET_DEVICES
        .lock()
        .iter()
        .find(|e| e.iface == name)
        .map(|e| e.device.clone())
}

/// Return the first registered device (convenience for single-NIC setups).
pub fn get_default_device() -> Option<Arc<dyn NetworkDevice>> {
    NET_DEVICES.lock().first().map(|e| e.device.clone())
}

/// List all registered interface names.
pub fn list_interfaces() -> Vec<String> {
    NET_DEVICES.lock().iter().map(|e| e.iface.clone()).collect()
}

// ---------------------------------------------------------------------------
// IPC opcodes for the driver silo protocol
// ---------------------------------------------------------------------------

/// Opcodes used by silo-hosted network drivers to communicate with the
/// kernel's network subsystem via IPC.  The kernel stub translates these
/// into [`NetworkDevice`] calls.
#[allow(dead_code)]
pub mod ipc_opcodes {
    pub const NET_SEND: u32 = 0x40;
    pub const NET_RECV: u32 = 0x41;
    pub const NET_MAC_ADDR: u32 = 0x42;
    pub const NET_LINK_STATUS: u32 = 0x43;
    pub const NET_LIST_IFACES: u32 = 0x44;
}

// ---------------------------------------------------------------------------
// Top-level init
// ---------------------------------------------------------------------------

/// Scan PCI for network hardware and register all discovered devices.
///
/// Called from [`crate::drivers::init`] during bootstrap.
/// VirtIO-net devices are registered separately (from their own init path)
/// because VirtIO probing is already handled in [`crate::drivers::virtio`].
pub fn init() {
    log::info!("[net] Scanning for network devices...");

    e1000::init();

    if let Err(e) = scheme::register_net_scheme() {
        log::warn!("[net] Failed to register net scheme: {:?}", e);
    }

    let ifaces = list_interfaces();
    if ifaces.is_empty() {
        log::info!("[net] No network devices found yet (VirtIO probed later)");
    } else {
        log::info!("[net] {} device(s) available: {:?}", ifaces.len(), ifaces);
    }
}
