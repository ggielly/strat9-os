//! Hardware integration layer.

pub mod nic;
pub mod pci_client;
pub mod storage;
pub mod timer;
pub mod usb;
pub mod video;
pub mod virtio;

/// Performs the init operation.
pub fn init() {
    nic::init();
    timer::init();
    usb::init();
    virtio::gpu::init();
    video::framebuffer::init();
}
