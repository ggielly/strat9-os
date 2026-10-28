//! Shared utilities for Intel E1000-family NIC drivers.
//!
//! Contains the kernel DMA allocator, the common PCI probe + MMIO
//! mapping logic, and a generic `KernelE1000Adapter` that implements
//! `NetworkDevice` for both the legacy e1000 and the e1000e drivers.

use crate::{
    arch::xshim::VirtAddr,
    hardware::{
        iommu::{self, DmaProt, Domain, Sbdf},
        pci_client::{self as pci, Bar, PciDevice},
    },
    memory::{self},
    sync::SpinLock,
};
use alloc::sync::Arc;
use e1000::E1000Nic;
use net_core::{NetError, NetworkDevice};
use nic_buffers::{DmaAllocator, DmaRegion};

/// Kernel-side DMA allocator backed by the physical buddy allocator.
///
/// When IOMMU translation is active, the allocator also creates/uses the
/// device domain and returns the IOVA in [`DmaRegion::device_addr`].  When
/// translation is inactive it behaves exactly as before and returns the
/// physical address.
pub struct KernelDma {
    domain: Option<Arc<Domain>>,
}

impl KernelDma {
    /// Untranslated allocator (boot-time default, tests).
    pub const fn new() -> Self {
        Self { domain: None }
    }

    /// Allocator bound to a device; only creates a domain when translation is
    /// actually enabled, so the boot path is unchanged.
    pub fn for_sbdf(sbdf: Sbdf) -> Self {
        if iommu::enabled() {
            Self {
                domain: iommu::find_domain(sbdf).or_else(|| {
                    iommu::domain_for_owned(sbdf, None, iommu::FaultPolicy::Log).ok()
                }),
            }
        } else {
            Self { domain: None }
        }
    }

    fn map(&self, phys: u64, len: usize) -> (u64, u16) {
        if let Some(domain) = &self.domain {
            if let Ok(iova) = domain.map_auto(phys, len as u64, DmaProt::READ_WRITE) {
                return (iova, domain.id().raw());
            }
        }
        (0, 0)
    }
}

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
        let size = pages * 4096;
        let (iova, domain_id) = self.map(phys, size);
        Ok(DmaRegion {
            phys,
            iova,
            domain_id,
            virt,
            size,
        })
    }

    /// Releases a previously allocated DMA region back to the buddy allocator.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `region` was previously allocated by this
    /// allocator and has not already been freed.
    unsafe fn free_dma(&self, region: DmaRegion) {
        if region.iova != 0 {
            // Prefer the region's own domain: the allocator handle used to
            // free may be a different short-lived instance.
            if let Some(domain) = iommu::get_domain(iommu::DomainId::from_raw(region.domain_id)) {
                let _ = domain.unmap(region.iova, region.size as u64);
            }
        }
        let pages = (region.size + 4095) / 4096;
        let order = pages.next_power_of_two().trailing_zeros() as u8;
        let frame = crate::memory::PhysFrame::containing_address(
            crate::arch::xshim::PhysAddr::new(region.phys),
        );
        crate::sync::with_irqs_disabled(|token| {
            crate::memory::free_phys_contiguous(token, frame, order);
        });
    }
}

/// Per-device DMA address translator.
///
/// Unlike [`KernelDma`], this does not allocate frames: it maps existing
/// physical ranges into the device's IOMMU domain and returns the address the
/// device must program.  When translation is inactive it returns the physical
/// address unchanged, so drivers can use it unconditionally.
pub struct DmaMapper {
    domain: Option<Arc<Domain>>,
}

impl DmaMapper {
    /// Build a translator for `sbdf`; creates a domain only when IOMMU
    /// translation is active.
    pub fn for_sbdf(sbdf: Sbdf) -> Self {
        if iommu::enabled() {
            Self {
                domain: iommu::find_domain(sbdf).or_else(|| {
                    iommu::domain_for_owned(sbdf, None, iommu::FaultPolicy::Log).ok()
                }),
            }
        } else {
            Self { domain: None }
        }
    }

    /// Map `[phys, phys + len)` and return the device address.
    pub fn translate(&self, phys: u64, len: usize, prot: DmaProt) -> u64 {
        if let Some(domain) = &self.domain {
            if let Ok(iova) = domain.map_auto(phys, len as u64, prot) {
                return iova;
            }
        }
        phys
    }

    /// Release a mapping previously returned by [`DmaMapper::translate`].
    pub fn release(&self, address: u64, len: usize) {
        if let Some(domain) = &self.domain {
            // A translated address lives above IOVA_BASE; physical addresses
            // from the buddy allocator may also be high, so only unmap when
            // we actually own the domain and the address belongs to it.
            if domain.translate(address).is_some() {
                let _ = domain.unmap(address, len as u64);
            }
        }
    }

    /// True when translation is active.
    pub fn is_translating(&self) -> bool {
        self.domain.is_some() && iommu::enabled()
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
// Generic kernel NIC adapter : removes duplication between e1000 and e1000e
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
    sbdf: Sbdf,
    epoch: core::sync::atomic::AtomicU32,
}

impl KernelE1000Adapter {
    /// Wrap an initialised `E1000Nic` and produce an `Arc<dyn NetworkDevice>`.
    pub fn new(nic: E1000Nic, driver_name: &'static str, sbdf: Sbdf) -> Arc<Self> {
        let mac = nic.mac_address();
        Arc::new(Self {
            inner: SpinLock::new(nic),
            mac,
            name: driver_name,
            sbdf,
            epoch: core::sync::atomic::AtomicU32::new(1),
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
        nic.check_link();
        nic.watchdog_tick(&KernelDma::for_sbdf(self.sbdf));
    }

    fn features(&self) -> u64 {
        // RX checksum validation is done by the 8254x (SECRC + IPCS/TCP
        // status); the driver drops frames with TCPE/IPE set.  TX checksum
        // stays in software because the legacy descriptor path does not
        // carry the L4 offset metadata.
        strat9_abi::net::features::CSUM_RX
    }

    fn mtu(&self) -> usize {
        1500
    }

    fn queue_count(&self) -> u16 {
        // One hardware ring, two software RSS queues: the IRQ path hashes the
        // frame and the stack polls both queues.
        2
    }

    fn epoch(&self) -> u32 {
        self.epoch.load(core::sync::atomic::Ordering::Acquire)
    }

    fn quiesce(&self) -> Result<(), NetError> {
        self.inner.lock().quiesce();
        Ok(())
    }

    fn resume(&self) -> Result<(), NetError> {
        self.inner.lock().reset(&KernelDma::for_sbdf(self.sbdf));
        self.epoch
            .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        Ok(())
    }

    fn reset(&self) -> Result<(), NetError> {
        self.inner.lock().reset(&KernelDma::for_sbdf(self.sbdf));
        self.epoch
            .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        Ok(())
    }
}
