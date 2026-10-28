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
