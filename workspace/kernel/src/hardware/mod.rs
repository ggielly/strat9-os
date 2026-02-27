//! Hardware integration layer.

pub mod nic;
pub mod rng;
pub mod storage;
pub mod video;
pub mod virtio;

pub fn init() {
    nic::init();
}
