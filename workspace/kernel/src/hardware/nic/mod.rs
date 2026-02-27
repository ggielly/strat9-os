//! Network driver integration layer.
//!
//! Thin kernel glue that wires external crates (`net-core`, `e1000`, …)
//! to kernel services (PCI, DMA allocator, VFS schemes).

pub mod e1000_drv;
pub mod pcnet_drv;
pub mod rtl8139_drv;
pub mod scheme;
pub mod virtio_net;

pub use net_core::{NetError, NetworkDevice, MTU};

use alloc::{format, string::String, sync::Arc, vec::Vec};
use spin::RwLock;

struct NetDeviceEntry {
    iface: String,
    device: Arc<dyn NetworkDevice>,
}

static NET_DEVICES: RwLock<Vec<NetDeviceEntry>> = RwLock::new(Vec::new());

/// Map a driver name to a FreeBSD-style interface prefix.
///
/// | Driver          | Prefix   | Example |
/// |-----------------|----------|---------|
/// | e1000 / Intel   | `em`     | `em0`   |
/// | VirtIO-net      | `vtnet`  | `vtnet0`|
/// | (other)         | `net`    | `net0`  |
fn bsd_prefix(driver_name: &str) -> &'static str {
    let lower = driver_name.as_bytes();
    // Match common patterns without pulling in a full lowercase comparison
    if lower.len() >= 4
        && (lower[0] | 0x20) == b'e'
        && (lower[1] | 0x20) == b'1'
        && lower[2] == b'0'
        && lower[3] == b'0'
    {
        return "em"; // Intel PRO/1000 family
    }
    if lower.len() >= 6
        && (lower[0] | 0x20) == b'v'
        && (lower[1] | 0x20) == b'i'
        && (lower[2] | 0x20) == b'r'
        && (lower[3] | 0x20) == b't'
        && (lower[4] | 0x20) == b'i'
        && (lower[5] | 0x20) == b'o'
    {
        return "vtnet"; // VirtIO
    }
    "net" // fallback
}

/// Counters per-prefix so that `em0`, `em1`, `vtnet0` are independent.
static PREFIX_COUNTERS: RwLock<Vec<(String, usize)>> = RwLock::new(Vec::new());

fn next_index_for(prefix: &str) -> usize {
    let mut counters = PREFIX_COUNTERS.write();
    for entry in counters.iter_mut() {
        if entry.0 == prefix {
            let idx = entry.1;
            entry.1 += 1;
            return idx;
        }
    }
    counters.push((String::from(prefix), 1));
    0
}

pub fn register_device(device: Arc<dyn NetworkDevice>) -> String {
    let prefix = bsd_prefix(device.name());
    let idx = next_index_for(prefix);
    let iface = format!("{}{}", prefix, idx);
    let mac = device.mac_address();
    log::info!(
        "[net] {} -> {} (MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})",
        device.name(),
        iface,
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5],
    );
    let mut devs = NET_DEVICES.write();
    devs.push(NetDeviceEntry {
        iface: iface.clone(),
        device,
    });
    iface
}

pub fn get_device(name: &str) -> Option<Arc<dyn NetworkDevice>> {
    NET_DEVICES
        .read()
        .iter()
        .find(|e| e.iface == name)
        .map(|e| e.device.clone())
}

pub fn get_default_device() -> Option<Arc<dyn NetworkDevice>> {
    NET_DEVICES.read().first().map(|e| e.device.clone())
}

pub fn list_interfaces() -> Vec<String> {
    NET_DEVICES.read().iter().map(|e| e.iface.clone()).collect()
}

pub fn init() {
    log::info!("[net] Scanning for network devices...");
    e1000_drv::init();
    pcnet_drv::init();
    rtl8139_drv::init();
    virtio_net::init();
    if let Err(e) = scheme::register_net_scheme() {
        log::warn!("[net] Failed to register net scheme: {:?}", e);
    }
}
