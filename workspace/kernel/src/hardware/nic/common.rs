//! Shared utilities for Intel E1000-family NIC drivers.
//!
//! Contains the kernel DMA allocator, the common PCI probe + MMIO
//! mapping logic, and a generic `KernelE1000Adapter` that implements
//! `NetworkDevice` for both the legacy e1000 and the e1000e drivers.

use crate::{
    hardware::pci_client::{self as pci, Bar, PciDevice},
    memory::{self},
    sync::SpinLock,
};
use alloc::sync::Arc;
use e1000::E1000Nic;
use net_core::{NetError, NetworkDevice};
use nic_buffers::{DmaAllocator, DmaRegion};
use x86_64::VirtAddr;

/// Kernel-side DMA allocator backed by the physical buddy allocator.
pub struct KernelDma;

impl DmaAllocator for KernelDma {
    /// Allocates a physically contiguous DMA region of at least `size` bytes.
    fn alloc_dma(&self, size: usize) -> Result<DmaRegion, nic_buffers::DmaAllocError> {
        let pages = (size + 4095) / 4096;
        let order = pages.next_power_of_two().trailing_zeros() as u8;
        let frame = crate::sync::with_irqs_disabled(|token| {
            crate::memory::allocate_phys_contiguous(token, order)
        })
        .map_err(|_| nic_buffers::DmaAllocError)?;
        let phys = frame.start_address.as_u64();
        let virt = memory::phys_to_virt(phys) as *mut u8;
        Ok(DmaRegion {
            phys,
            virt,
            size: pages * 4096,
        })
    }

    /// Releases a previously allocated DMA region back to the buddy allocator.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `region` was previously allocated by this
    /// allocator and has not already been freed.
    unsafe fn free_dma(&self, region: DmaRegion) {
        let pages = (region.size + 4095) / 4096;
        let order = pages.next_power_of_two().trailing_zeros() as u8;
        let frame =
            crate::memory::PhysFrame::containing_address(x86_64::PhysAddr::new(region.phys));
        crate::sync::with_irqs_disabled(|token| {
            crate::memory::free_phys_contiguous(token, frame, order);
        });
    }
}

/// Result of a successful PCI probe for an E1000-family device.
pub struct ProbeResult {
    /// The PCI device handle (already configured for bus-master + memory space).
    pub pci_dev: PciDevice,
    /// Identity-mapped virtual address of the MMIO BAR region.
    pub mmio_virt: u64,
    /// Physical address of the MMIO BAR region.
    pub mmio_phys: u64,
}

/// Probe PCI for an E1000-family NIC, map its MMIO BAR, and return a
/// `ProbeResult` ready for hardware init.
///
/// `device_ids` lists the PCI device IDs this driver supports.  Only devices
/// whose subclass is `ETHERNET` or `OTHER` are accepted.
///
/// Returns `None` when no matching device is found or when MMIO mapping fails
/// for every candidate.
pub fn probe_e1000_pci(device_ids: &[u16]) -> Option<ProbeResult> {
    if !memory::paging::is_initialized() {
        log::warn!("e1000-family: paging not initialized, deferring probe");
        return None;
    }

    let candidates = pci::probe_all(pci::ProbeCriteria {
        vendor_id: Some(pci::vendor::INTEL),
        device_id: None,
        class_code: Some(pci::class::NETWORK),
        subclass: None,
        prog_if: None,
    });

    for pci_dev in candidates.into_iter() {
        if pci_dev.subclass != pci::net_subclass::ETHERNET
            && pci_dev.subclass != pci::net_subclass::OTHER
        {
            continue;
        }
        if !device_ids.contains(&pci_dev.device_id) {
            continue;
        }

        log::info!(
            "e1000-family: PCI {:04x}:{:04x} at {:?}",
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
                log::error!(
                    "e1000-family: no MMIO BAR (BAR0/BAR1) for {:04x}:{:04x}",
                    pci_dev.vendor_id,
                    pci_dev.device_id
                );
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
                "e1000-family: MMIO not mapped for {:04x}:{:04x} phys={:#x} virt={:#x} mapped={:#x}",
                pci_dev.vendor_id,
                pci_dev.device_id,
                mmio_phys,
                mmio_virt,
                mapped
            );
            continue;
        }

        return Some(ProbeResult {
            pci_dev,
            mmio_virt,
            mmio_phys,
        });
    }

    None
}

// ---------------------------------------------------------------------------
// Generic kernel NIC adapter — removes duplication between e1000 and e1000e
// kernel drivers (point 4).
// ---------------------------------------------------------------------------

/// Wraps `E1000Nic` behind a `SpinLock` and implements `NetworkDevice`.
///
/// Both `e1000_drv` and `e1000e_drv` instantiate this adapter with their own
/// device ID list and driver name string instead of duplicating the trait impl.
pub struct KernelE1000Adapter {
    inner: SpinLock<E1000Nic>,
    mac: [u8; 6],
    name: &'static str,
}

impl KernelE1000Adapter {
    /// Wrap an initialised `E1000Nic` and produce an `Arc<dyn NetworkDevice>`.
    pub fn new(nic: E1000Nic, driver_name: &'static str) -> Arc<Self> {
        let mac = nic.mac_address();
        Arc::new(Self {
            inner: SpinLock::new(nic),
            mac,
            name: driver_name,
        })
    }
}

impl NetworkDevice for KernelE1000Adapter {
    fn name(&self) -> &str {
        self.name
    }

    fn mac_address(&self) -> [u8; 6] {
        self.mac
    }

    fn link_up(&self) -> bool {
        self.inner.lock().link_up()
    }

    fn receive(&self, buf: &mut [u8]) -> Result<usize, NetError> {
        self.inner.lock().receive(buf)
    }

    fn transmit(&self, buf: &[u8]) -> Result<(), NetError> {
        self.inner.lock().transmit(buf)
    }

    fn handle_interrupt(&self) {
        let _icr = self.inner.lock().handle_interrupt();
    }

    fn poll(&self) {
        let mut nic = self.inner.lock();
        nic.watchdog_tick(&KernelDma);
    }
}
