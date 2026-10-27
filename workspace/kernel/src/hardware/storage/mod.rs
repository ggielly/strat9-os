//! Storage drivers namespace.

pub mod ahci;
#[cfg(target_arch = "x86_64")]
pub mod ata_legacy;
pub mod nvme;
pub mod virtio_block;

/// Performs the init operation.
pub fn init() {
    ahci::init();
    nvme::init();
    #[cfg(target_arch = "x86_64")]
    ata_legacy::init();
    virtio_block::init();
}
