//! Hardware integration layer.
//!
//! See also: [Driver Model Guide](https://strat9-os.org/strat9-os-docs/driver-model.html)
//! for component trait, PCI enumeration, and driver categories.

pub mod amdgpu;
pub mod ec;
pub mod iommu;
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
    // Parse DMAR/IVRS and record the discovery summary.  This never programs
    // translation: `iommu::activate()` stays false until the backend is ready.
    iommu::init();
    #[cfg(feature = "iommu-activate")]
    {
        // Must run before the NIC/storage probes: those drivers create their
        // domains only when `iommu::enabled()` is already true.
        if iommu::activate() {
            crate::serial_println!(
                "[IOMMU] translation active before device probe (pass-through for unmigrated devices)"
            );
        } else {
            crate::serial_println!(
                "[IOMMU] activation requested by feature but failed; DMA stays physical"
            );
        }
    }
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
    amdgpu::init();
    crate::arch::speaker::beep_phase(14); // AMDGPU
    video::framebuffer::init();
    crate::arch::speaker::beep_phase(15); // Framebuffer
}
