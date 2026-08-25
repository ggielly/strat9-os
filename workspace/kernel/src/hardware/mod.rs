//! Hardware integration layer.
//!
//! See also: [Driver Model Guide](https://strat9-os.org/strat9-os-docs/driver-model.html)
//! for component trait, PCI enumeration, and driver categories.

pub mod ec;
pub mod nic;
pub mod pci_client;
pub mod storage;
pub mod thermal;
pub mod timer;
pub mod usb;
pub mod video;
pub mod virtio;

/// Performs the init operation.
pub fn init() {
    ec::init();
    crate::arch::speaker::beep_phase(7); // EC
    thermal::init();
    crate::arch::speaker::beep_phase(8); // Thermal
    nic::init();
    crate::arch::speaker::beep_phase(9); // NIC
    storage::init();
    crate::arch::speaker::beep_phase(10); // Storage
    timer::init();
    crate::arch::speaker::beep_phase(11); // Timer
    usb::init();
    crate::arch::speaker::beep_phase(12); // USB
    virtio::gpu::init();
    crate::arch::speaker::beep_phase(13); // VirtIO GPU
    video::framebuffer::init();
    crate::arch::speaker::beep_phase(14); // Framebuffer
}
