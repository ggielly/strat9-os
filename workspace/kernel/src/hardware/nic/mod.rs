//! Network driver integration layer.
//!
//! Thin kernel glue that wires external crates (`net-core`, `e1000`, …)
//! to kernel services (PCI, DMA allocator, VFS schemes).

pub mod e1000_drv;
pub mod scheme;

pub use net_core::{MTU, NetError, NetworkDevice};

use crate::sync::SpinLock;
use alloc::{format, string::String, sync::Arc, vec::Vec};

struct NetDeviceEntry {
    iface: String,
    device: Arc<dyn NetworkDevice>,
}

static NET_DEVICES: SpinLock<Vec<NetDeviceEntry>> = SpinLock::new(Vec::new());

pub fn register_device(device: Arc<dyn NetworkDevice>) -> String {
    let mut devs = NET_DEVICES.lock();
    let idx = devs.len();
    let iface = format!("eth{}", idx);
    let mac = device.mac_address();
    log::info!(
        "[net] {} -> {} (MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})",
        device.name(), iface, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
    );
    devs.push(NetDeviceEntry { iface: iface.clone(), device });
    iface
}

pub fn get_device(name: &str) -> Option<Arc<dyn NetworkDevice>> {
    NET_DEVICES.lock().iter().find(|e| e.iface == name).map(|e| e.device.clone())
}

pub fn get_default_device() -> Option<Arc<dyn NetworkDevice>> {
    NET_DEVICES.lock().first().map(|e| e.device.clone())
}

pub fn list_interfaces() -> Vec<String> {
    NET_DEVICES.lock().iter().map(|e| e.iface.clone()).collect()
}

pub fn init() {
    log::info!("[net] Scanning for network devices...");
    e1000_drv::init();
    if let Err(e) = scheme::register_net_scheme() {
        log::warn!("[net] Failed to register net scheme: {:?}", e);
    }
}
