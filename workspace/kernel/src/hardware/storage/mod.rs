//! Storage drivers namespace.

pub mod ahci;
pub mod ata_legacy;
pub mod nvme;
pub mod virtio_block;

/// Performs the init operation.
pub fn init() {
    ahci::init();
    nvme::init();
    ata_legacy::init();
    virtio_block::init();
}
