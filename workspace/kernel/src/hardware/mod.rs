//! Hardware integration layer.

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
    thermal::init();
    nic::init();
    storage::init();
    timer::init();
    usb::init();
    virtio::gpu::init();
    video::framebuffer::init();
}
