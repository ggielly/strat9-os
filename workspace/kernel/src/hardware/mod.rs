//! Hardware integration layer.

pub mod nic;
pub mod storage;
pub mod timer;
pub mod usb;
pub mod video;
pub mod virtio;

pub fn init() {
    nic::init();
    timer::init();
    usb::init();
    video::framebuffer::init();
}
