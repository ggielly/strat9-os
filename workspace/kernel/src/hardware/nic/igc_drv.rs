use super::register_device;
use crate::{
    hardware::pci_client::{self as pci, Bar},
    memory::{self},
    sync::SpinLock,
};
use alloc::sync::Arc;
use e1000::E1000Nic;
use net_core::{NetError, NetworkDevice};
use nic_buffers::{DmaAllocator, DmaRegion};
use x86_64::VirtAddr;

const IGC_IDS: &[u16] = &[
    pci::intel_eth::I225_LM,
    pci::intel_eth::I225_V,
    pci::intel_eth::I226_LM,
    pci::intel_eth::I226_V,
];

struct KernelDma;

impl DmaAllocator for KernelDma {
    /// Allocates dma.
    fn alloc_dma(&self, size: usize) -> Result<DmaRegion, nic_buffers::DmaAllocError> {
        let pages = (size + 4095) / 4096;
        let order = pages.next_power_of_two().trailing_zeros() as u8;
        let frame =
            crate::memory::allocate_frames(order).map_err(|_| nic_buffers::DmaAllocError)?;
        let phys = frame.start_address.as_u64();
        let virt = memory::phys_to_virt(phys) as *mut u8;
        Ok(DmaRegion {
            phys,
            virt,
            size: pages * 4096,
        })
    }

    /// Releases dma.
    unsafe fn free_dma(&self, region: DmaRegion) {
        let pages = (region.size + 4095) / 4096;
        let order = pages.next_power_of_two().trailing_zeros() as u8;
        let frame =
            crate::memory::PhysFrame::containing_address(x86_64::PhysAddr::new(region.phys));
        crate::memory::free_frames(frame, order);
    }
}

pub struct KernelIgc {
    inner: SpinLock<E1000Nic>,
    mac: [u8; 6],
}

impl NetworkDevice for KernelIgc {
    /// Performs the name operation.
    fn name(&self) -> &str {
        "igc"
    }
    /// Performs the mac address operation.
    fn mac_address(&self) -> [u8; 6] {
        self.mac
    }
    /// Performs the link up operation.
    fn link_up(&self) -> bool {
        self.inner.lock().link_up()
    }
    /// Performs the receive operation.
    fn receive(&self, buf: &mut [u8]) -> Result<usize, NetError> {
        self.inner.lock().receive(buf)
    }
    /// Performs the transmit operation.
    fn transmit(&self, buf: &[u8]) -> Result<(), NetError> {
        self.inner.lock().transmit(buf, &KernelDma)
    }
    /// Handles interrupt.
    fn handle_interrupt(&self) {
        self.inner.lock().handle_interrupt();
    }
}

/// Performs the init operation.
pub fn init() {
    if !memory::paging::is_initialized() {
        log::warn!("IGC: paging not initialized, deferring probe");
        return;
    }

    let candidates = pci::probe_all(pci::ProbeCriteria {
        vendor_id: Some(pci::vendor::INTEL),
        device_id: None,
        class_code: Some(pci::class::NETWORK),
        subclass: None,
        prog_if: None,
    });

    for pci_dev in candidates.into_iter() {
        if !IGC_IDS.contains(&pci_dev.device_id) {
            continue;
        }

        log::info!(
            "IGC: PCI {:04x}:{:04x} at {:?}",
            pci_dev.vendor_id,
            pci_dev.device_id,
            pci_dev.address
        );

        pci_dev.enable_bus_master();
        pci_dev.enable_memory_space();
        let mut cmd = pci_dev.read_config_u16(pci::config::COMMAND);
        cmd &= !pci::command::INTERRUPT_DISABLE;
        pci_dev.write_config_u16(pci::config::COMMAND, cmd);

        let mmio_phys = match pci_dev.read_bar(0).or_else(|| pci_dev.read_bar(1)) {
            Some(Bar::Memory32 { addr, .. }) => addr as u64,
            Some(Bar::Memory64 { addr, .. }) => addr,
            _ => {
                log::error!("IGC: no MMIO BAR (BAR0/BAR1)");
                continue;
            }
        };

        memory::paging::ensure_identity_map_range(mmio_phys, 0x2_0000);
        let mmio_virt = memory::phys_to_virt(mmio_phys);
        let mmio_page_phys = mmio_phys & !0xFFF;
        let mmio_page_virt = mmio_virt & !0xFFF;
        let mapped = memory::paging::translate(VirtAddr::new(mmio_page_virt))
            .map(|p| p.as_u64())
            .unwrap_or(0);
        if mapped != mmio_page_phys {
            log::error!(
                "IGC: MMIO map mismatch phys={:#x} virt={:#x} mapped={:#x}",
                mmio_phys,
                mmio_virt,
                mapped
            );
            continue;
        }

        // Linux-like step: probe attempted with retries; if core init fails, keep going.
        let mut init_ok = None;
        for _ in 0..3 {
            if let Ok(nic) = E1000Nic::init(mmio_virt, &KernelDma) {
                init_ok = Some(nic);
                break;
            }
            let mut cmd_retry = pci_dev.read_config_u16(pci::config::COMMAND);
            cmd_retry |= pci::command::BUS_MASTER | pci::command::MEMORY_SPACE;
            cmd_retry &= !pci::command::INTERRUPT_DISABLE;
            pci_dev.write_config_u16(pci::config::COMMAND, cmd_retry);
            core::hint::spin_loop();
        }

        match init_ok {
            Some(nic) => {
                let mac = nic.mac_address();
                let dev = Arc::new(KernelIgc {
                    mac,
                    inner: SpinLock::new(nic),
                });
                register_device(dev);
                return;
            }
            None => {
                log::warn!("IGC: core init failed (likely requires dedicated igc register path)");
            }
        }
    }
}
