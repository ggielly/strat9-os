//! Network device hotplug events.
//!
//! The kernel does not perform PCIe hotplug by itself yet; this module is the
//! event bus between the bus/device manager and the networking strate.  Any
//! source (PCIe slot interrupt, ACPI GPE, `SYS_PCI_RESCAN`, manual quiesce)
//! publishes an event here, and `SYS_NET_DEVICE_EVENT` drains it.
//!
//! Events are deliberately small and allocation-free: a fixed ring of 64
//! entries, written from IRQ/control context and read by the strate.

use crate::{
    sync::{FixedQueue, SpinLock},
};
use strat9_abi::net::event;
use core::sync::atomic::{AtomicBool, Ordering};

/// One device lifecycle event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceEvent {
    pub kind: u32,
    pub resource: u64,
    pub epoch: u32,
    pub data: u64,
}

impl DeviceEvent {
    pub const fn new(kind: u32, resource: u64, epoch: u32, data: u64) -> Self {
        Self {
            kind,
            resource,
            epoch,
            data,
        }
    }
}

const EVENT_CAPACITY: usize = 64;
static EVENTS: SpinLock<FixedQueue<DeviceEvent, EVENT_CAPACITY>> =
    SpinLock::new(FixedQueue::new());

/// Last link state observed by the IRQ handler, used to emit transitions.
static LINK_UP: AtomicBool = AtomicBool::new(false);

/// Publish a device event.  Safe from IRQ context (fixed queue + spinlock).
pub fn push(event: DeviceEvent) {
    let _ = EVENTS.lock().push_back(event);
}

/// Non-blocking event pop.
pub fn pop() -> Option<DeviceEvent> {
    EVENTS.lock().pop_front()
}

/// Emit a link transition if the state changed.  Returns `true` on change.
pub fn update_link(resource: u64, up: bool, epoch: u32) -> bool {
    let previous = LINK_UP.swap(up, Ordering::AcqRel);
    if previous == up {
        return false;
    }
    let kind = if up { event::LINK_UP } else { event::LINK_DOWN };
    push(DeviceEvent::new(kind, resource, epoch, 0));
    true
}

/// Initialise the cached link state (called when the first device is added).
pub fn set_initial_link(up: bool) {
    LINK_UP.store(up, Ordering::Release);
}

/// Event count, for diagnostics.
pub fn pending() -> usize {
    EVENTS.lock().len()
}

/// Last PCI inventory seen by the hotplug thread.
static LAST_PCI: SpinLock<Option<alloc::vec::Vec<u64>>> = SpinLock::new(None);

fn pci_ids() -> alloc::vec::Vec<u64> {
    crate::arch::pci::all_devices()
        .into_iter()
        .map(|dev| {
            ((dev.address.bus as u64) << 16)
                | ((dev.address.device as u64) << 8)
                | dev.address.function as u64
        })
        .collect()
}

/// Poll the PCI bus and publish add/remove events.
///
/// This is the portable fallback when no PCIe slot interrupt / ACPI SCI is
/// wired: a 500 ms scan is enough for VM hot-add and avoids the complexity of
/// a GPE handler in the first iteration.  The scan is performed in a kernel
/// thread, never in the timer IRQ.
pub fn poll_pci() {
    let current = pci_ids();
    let mut previous = LAST_PCI.lock();
    let Some(old) = previous.as_mut() else {
        *previous = Some(current);
        return;
    };

    for id in current.iter() {
        if !old.contains(id) {
            push(DeviceEvent::new(
                event::DEVICE_ADD,
                *id,
                1,
                0,
            ));
        }
    }
    for id in old.iter() {
        if !current.contains(id) {
            push(DeviceEvent::new(
                event::DEVICE_REMOVE,
                *id,
                1,
                0,
            ));
        }
    }
    *old = current;

    // Refresh the cached inventory used by the probe paths.  This runs every
    // 500 ms, so use the quiet variant: the full PCI inventory must not be
    // printed on every poll.
    let _ = crate::arch::pci::rescan_quiet();
}

/// Start the polling watchdog.  Idempotent.
pub fn start_watchdog() {
    use core::sync::atomic::{AtomicBool, Ordering};
    static STARTED: AtomicBool = AtomicBool::new(false);
    if STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    let _ = crate::process::kthread::spawn("nic-hotplug", || loop {
        crate::hardware::timer::hpet::delay_ms(500);
        poll_pci();
    });
}

