//! Network driver integration layer.
//!
//! Thin kernel glue that wires external crates (`net-core`, `e1000`, …)
//! to kernel services (PCI, DMA allocator, VFS schemes).

pub mod common;
pub mod e1000_drv;
pub mod e1000e_drv;
pub mod igc_drv;
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

/// Performs the next index for operation.
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

// ---------------------------------------------------------------------------
// NIC interrupt dispatch (see idt.rs:nic_handler)
// ---------------------------------------------------------------------------

/// IRQ line of the first registered NIC.  Written once by the NIC driver's
/// `init()`; read by `nic_handler` in the IDT to send EOI.
pub static NIC_IRQ_LINE: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0xFF);

/// Global reference to the first NIC device, used by `nic_handler` to call
/// `handle_interrupt()`.  Set via `set_nic_device()` after PCI probe.
///
/// # TODO (multi-NIC)
///
/// This only supports a single NIC.  When multiple NICs are present the
/// handler should iterate all registered devices or use per-IRQ dispatch.
static NIC_DEVICE: spin::Mutex<Option<Arc<dyn NetworkDevice>>> = spin::Mutex::new(None);

/// Store a NIC device reference and its IRQ line for the IDT handler.
///
/// Called from NIC drivers (`e1000_drv`, `e1000e_drv`, …) after successful
/// initialisation.
pub fn set_nic_device(dev: Arc<dyn NetworkDevice>, irq: u8) {
    NIC_IRQ_LINE.store(irq, core::sync::atomic::Ordering::Relaxed);
    *NIC_DEVICE.lock() = Some(dev);
    log::info!("NIC dispatch set for IRQ {}", irq);
}

// ---------------------------------------------------------------------------
// strate-net wakeup on NIC IRQ (point 1)
// ---------------------------------------------------------------------------

/// Cached task ID of the strate-net process, registered from the boot
/// sequence after strate-net is spawned.  Zero = not yet known; the NIC
/// handler will skip the wakeup and rely on strate-net's periodic polling.
///
/// # TODO
///
/// Wire up registration — either via a syscall from strate-net itself or
/// by scanning `get_all_tasks()` from a safe (non-IRQ) context after init
/// spawns strate-net.
static STRATE_NET_TID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Register the strate-net task ID so the NIC IRQ handler can wake it.
pub fn register_strate_net_tid(tid: u64) {
    STRATE_NET_TID.store(tid, core::sync::atomic::Ordering::Relaxed);
    log::info!("NIC: strate-net task {} registered for IRQ wakeup", tid);
}

/// Called from `idt.rs:nic_handler`.  Dispatches to the registered NIC's
/// `handle_interrupt()` (reads ICR, coalescing, TX reclaim).
/// Wakes strate-net (if its TID is known) so it can call `receive()`
/// without waiting for the next polling timeout.
pub fn handle_interrupt() {
    if let Some(ref dev) = *NIC_DEVICE.lock() {
        dev.handle_interrupt();
    }
    let tid_u64 = STRATE_NET_TID.load(core::sync::atomic::Ordering::Relaxed);
    if tid_u64 != 0 {
        let _ = crate::process::scheduler::wake_task(crate::process::TaskId(tid_u64));
    }
}

/// Performs the register device operation.
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

/// Returns device.
pub fn get_device(name: &str) -> Option<Arc<dyn NetworkDevice>> {
    NET_DEVICES
        .read()
        .iter()
        .find(|e| e.iface == name)
        .map(|e| e.device.clone())
}

/// Returns default device.
pub fn get_default_device() -> Option<Arc<dyn NetworkDevice>> {
    NET_DEVICES.read().first().map(|e| e.device.clone())
}

/// Performs the list interfaces operation.
pub fn list_interfaces() -> Vec<String> {
    NET_DEVICES.read().iter().map(|e| e.iface.clone()).collect()
}

/// Call `poll()` on every registered NIC (watchdog + link check).
/// Safe to call from any non-IRQ context (allocates via get_all_tasks).
///
/// # TODO
///
/// Hook this into a kernel workqueue or periodic thread instead of
/// the APIC timer tick — SpinLock::lock reads percpu data (GS:[0])
/// which is unsafe during the swapgs→iretq window.
pub fn poll_all() {
    let guard = NET_DEVICES.read();
    for entry in guard.iter() {
        entry.device.poll();
    }
}

/// Try to discover strate-net and cache its task ID.
pub fn try_register_strate_net() {
    if STRATE_NET_TID.load(core::sync::atomic::Ordering::Relaxed) != 0 {
        return;
    }
    if let Some(tasks) = crate::process::get_all_tasks() {
        for t in &tasks {
            if t.name == "strate-net" {
                register_strate_net_tid(t.id.0);
                return;
            }
        }
    }
}

/// Performs the init operation.
pub fn init() {
    log::info!("[net] Scanning for network devices...");
    // Probe modern Intel first, then legacy fallback.
    e1000e_drv::init();
    igc_drv::init();
    e1000_drv::init();
    pcnet_drv::init();
    rtl8139_drv::init();
    virtio_net::init();
    if let Err(e) = scheme::register_net_scheme() {
        log::warn!("[net] Failed to register net scheme: {:?}", e);
    }
}
