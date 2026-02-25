//! Driver integration layer.
//!
//! Wires external crates (`net-core`, `e1000`, `nic-buffers`, …) to
//! kernel services (PCI, DMA, VFS schemes).  Every network driver is
//! registered in `net::NET_DEVICES` and exposed at `/dev/net/`.

pub mod net;
pub mod virtio;

pub fn init() {
    net::init();
}
