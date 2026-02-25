//! Kernel adapter for the `e1000` crate.
//!
//! Implements `DmaAllocator` via the buddy allocator and wraps
//! `e1000::E1000Nic` behind a `SpinLock` to satisfy `NetworkDevice`.

use super::register_device;
use crate::{
    arch::x86_64::pci::{self, Bar},
    memory::{self, get_allocator, FrameAllocator},
    sync::SpinLock,
};
use alloc::sync::Arc;
use e1000::E1000Nic;
use net_core::{NetError, NetworkDevice};
use nic_buffers::{DmaAllocator, DmaRegion};

struct KernelDma;

impl DmaAllocator for KernelDma {
    fn alloc_dma(&self, size: usize) -> Result<DmaRegion, ()> {
        let pages = (size + 4095) / 4096;
        let order = pages.next_power_of_two().trailing_zeros() as u8;
        let mut lock = get_allocator().lock();
        let alloc = lock.as_mut().ok_or(())?;
        let frame = alloc.alloc(order).map_err(|_| ())?;
        let phys = frame.start_address.as_u64();
        let virt = memory::phys_to_virt(phys) as *mut u8;
        Ok(DmaRegion { phys, virt, size: pages * 4096 })
    }

    unsafe fn free_dma(&self, region: DmaRegion) {
        let pages = (region.size + 4095) / 4096;
        let order = pages.next_power_of_two().trailing_zeros() as u8;
        let frame = crate::memory::PhysFrame::containing_address(
            x86_64::PhysAddr::new(region.phys),
        );
        let mut lock = get_allocator().lock();
        if let Some(alloc) = lock.as_mut() {
            alloc.free(frame, order);
        }
    }
}

pub struct KernelE1000 {
    inner: SpinLock<E1000Nic>,
    mac: [u8; 6],
}

impl NetworkDevice for KernelE1000 {
    fn name(&self) -> &str { "e1000" }
    fn mac_address(&self) -> [u8; 6] { self.mac }
    fn link_up(&self) -> bool { self.inner.lock().link_up() }

    fn receive(&self, buf: &mut [u8]) -> Result<usize, NetError> {
        self.inner.lock().receive(buf)
    }

    fn transmit(&self, buf: &[u8]) -> Result<(), NetError> {
        self.inner.lock().transmit(buf, &KernelDma)
    }

    fn handle_interrupt(&self) {
        self.inner.lock().handle_interrupt();
    }
}

pub fn init() {
    for &dev_id in e1000::E1000_DEVICE_IDS {
        if let Some(pci_dev) = pci::find_device(pci::vendor::INTEL, dev_id) {
            log::info!("E1000: PCI {:04x}:{:04x} at {:?}", pci_dev.vendor_id, pci_dev.device_id, pci_dev.address);
            pci_dev.enable_bus_master();
            pci_dev.enable_memory_space();

            let mmio_phys = match pci_dev.read_bar(0) {
                Some(Bar::Memory32 { addr, .. }) => addr as u64,
                Some(Bar::Memory64 { addr, .. }) => addr,
                _ => { log::error!("E1000: BAR0 not memory-mapped"); continue; }
            };

            memory::paging::ensure_identity_map_range(mmio_phys, 0x2_0000);
            let mmio_virt = memory::phys_to_virt(mmio_phys);

            match E1000Nic::init(mmio_virt, &KernelDma) {
                Ok(nic) => {
                    let mac = nic.mac_address();
                    let dev = Arc::new(KernelE1000 {
                        mac,
                        inner: SpinLock::new(nic),
                    });
                    register_device(dev);
                    return;
                }
                Err(e) => log::error!("E1000: init failed: {}", e),
            }
        }
    }
    log::info!("E1000: no compatible device found");
}
