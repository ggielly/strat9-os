//! Network driver integration layer.
//!
//! Thin kernel glue that wires external crates (`net-core`, `e1000`, …)
//! to kernel services (PCI, DMA allocator, VFS schemes).

pub mod common;
pub mod data_plane;
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
/// Wire up registration : either via a syscall from strate-net itself or
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
/// If the N2 data plane is active, drains received packets into the RX
/// ring before waking strate-net (zero-syscall data path).
pub fn handle_interrupt() {
    // Phase 1 : hardware interrupt handling (brief, must hold NIC_DEVICE lock).
    let dev = {
        let guard = NIC_DEVICE.lock();
        guard.as_ref().map(|d| {
            d.handle_interrupt();
            d.clone()
        })
    };
    let dev = match dev {
        Some(d) => d,
        None => {
            crate::serial_println!("[net] IRQ: no NIC device registered");
            return;
        }
    };

    // Phase 2 : drain N2 rings (no NIC_DEVICE lock held, IRQs may still be
    // disabled by the IDT entry). Holding only NIC_DATA_PLANE here.
    if let Some(ref dp) = *NIC_DATA_PLANE.lock() {
        // Drain pending RX packets from HW into the N2 RX ring.
        let mut buf = [0u8; 2048];
        let mut rx_count = 0usize;
        let mut backpressure = false;
        while let Ok(n) = dev.receive(&mut buf) {
            if n > 0 {
                rx_count += 1;
                if rx_count <= 3 {
                    crate::serial_println!("[net] IRQ rx {} bytes (slot {})", n, rx_count);
                }
            }
            if dp.push_rx(0, &buf[..n]).is_err() {
                crate::serial_println!("[net] IRQ RX ring full, backpressure");
                backpressure = true;
                break;
            }
        }
        if rx_count > 3 {
            crate::serial_println!("[net] IRQ rx total {} packets", rx_count);
        }
        if rx_count == 0 {
            crate::serial_println!("[net] IRQ rx: no packets received from HW");
        }

        // N1 : notify scheduler if the RX ring is full (backpressure).
        if backpressure {
            crate::ipc::n1::notify_scheduler(crate::ipc::n1::N1Event::NicBackpressure);
        }

        // Notify consumer (strate-net) that new RX data is available.
        if rx_count > 0 {
            dp.notify_rx_consumer(0);
        }

        // Drain pending TX packets from the N2 TX ring into HW.
        let mut tx_buf = [0u8; 2048];
        while let Ok(Some(n)) = dp.pop_tx(0, &mut tx_buf) {
            if dev.transmit(&tx_buf[..n]).is_err() {
                break;
            }
        }

        // N1 : check for scheduler flow-control hints (non-blocking).
        if let Some(event) = crate::ipc::n1::poll_nic_events() {
            log::trace!("[net] N1 sched→NIC event: {:?}", event);
        }
    } else {
        crate::serial_println!("[net] IRQ: N2 data plane not initialized");
    }

    let tid_u64 = STRATE_NET_TID.load(core::sync::atomic::Ordering::Relaxed);
    if tid_u64 != 0 {
        let _ = crate::process::scheduler::wake_task(crate::process::TaskId(tid_u64));
    } else {
        crate::serial_println!("[net] IRQ: strate-net not registered (TID=0)");
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
/// the APIC timer tick : SpinLock::lock reads percpu data (GS:[0])
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
    // Initialise the N2 data plane if any NIC was registered.
    init_data_plane();
}

// ── N2 data-plane global instance ─────────────────────────────────────────

use data_plane::NicDataPlane;
use spin::Mutex;

/// Global NIC data plane, lazily initialised after NIC detection.
static NIC_DATA_PLANE: Mutex<Option<NicDataPlane>> = Mutex::new(None);

/// Initialise the N2 data plane with one ring pair per registered device.
/// Each device gets a single RX/TX pair (RSS queues extend this).
fn init_data_plane() {
    let count = NET_DEVICES.read().len();
    if count == 0 {
        log::debug!("[net] No NIC devices found : skipping data plane init");
        return;
    }
    // One ring pair per NIC for now; RSS would create one per queue.
    match NicDataPlane::new(count, 256, 2048) {
        Ok(dp) => {
            *NIC_DATA_PLANE.lock() = Some(dp);
            log::info!("[net] N2 data plane initialised with {} queue(s)", count);
        }
        Err(e) => {
            log::warn!("[net] Failed to initialise N2 data plane: {}", e);
        }
    }
}

/// Access the global N2 data plane (returns None if not yet initialised).
pub fn data_plane() -> &'static Mutex<Option<NicDataPlane>> {
    &NIC_DATA_PLANE
}
