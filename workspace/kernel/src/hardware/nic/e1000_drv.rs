//! Kernel adapter for the `e1000` crate.
//!
//! Implements `DmaAllocator` via the buddy allocator and wraps
//! `e1000::E1000Nic` behind a `SpinLock` to satisfy `NetworkDevice`.

use super::register_device;
use crate::{
    hardware::pci_client::{self as pci, Bar},
    memory::{self},
    serial_println,
    sync::SpinLock,
};
use alloc::sync::Arc;
use e1000::E1000Nic;
use net_core::{NetError, NetworkDevice};
use nic_buffers::{DmaAllocator, DmaRegion};
use x86_64::VirtAddr;

const LEGACY_E1000_IDS: &[u16] = &[pci::intel_eth::E1000_82540EM, pci::intel_eth::E1000_82545EM];

struct KernelDma;

impl DmaAllocator for KernelDma {
    /// Allocates dma.
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

    /// Releases dma.
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

pub struct KernelE1000 {
    inner: SpinLock<E1000Nic>,
    mac: [u8; 6],
}

impl NetworkDevice for KernelE1000 {
    /// Performs the name operation.
    fn name(&self) -> &str {
        "e1000"
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
    serial_println!("[E1000] init: probing for Intel NICs...");
    if !memory::paging::is_initialized() {
        serial_println!("[E1000] paging not initialized, deferring probe");
        return;
    }

    let candidates = pci::probe_all(pci::ProbeCriteria {
        vendor_id: Some(pci::vendor::INTEL),
        device_id: None,
        class_code: Some(pci::class::NETWORK),
        subclass: None,
        prog_if: None,
    });
    serial_println!("[E1000] PCI probe returned {} candidates", candidates.len());
    let mut found_intel_nic = false;
    let mut warned_modern_intel = false;
    for pci_dev in candidates.into_iter() {
        serial_println!("[E1000] Checking device {:04x}:{:04x} class={:02x} subclass={:02x}",
            pci_dev.vendor_id, pci_dev.device_id, pci_dev.class_code, pci_dev.subclass);
        // Accept standard Ethernet class and vendor-specific network subclass.
        if pci_dev.subclass != pci::net_subclass::ETHERNET
            && pci_dev.subclass != pci::net_subclass::OTHER
        {
            continue;
        }
        found_intel_nic = true;
        if !LEGACY_E1000_IDS.contains(&pci_dev.device_id) {
            if matches!(
                pci_dev.device_id,
                pci::intel_eth::I219_LM
                    | pci::intel_eth::I219_V
                    | pci::intel_eth::I225_LM
                    | pci::intel_eth::I225_V
                    | pci::intel_eth::I226_LM
                    | pci::intel_eth::I226_V
            ) {
                if !warned_modern_intel {
                    log::warn!(
                        "E1000: modern Intel NIC detected; add e1000e/igc for full laptop support"
                    );
                    warned_modern_intel = true;
                }
            }
            continue;
        }

        log::info!(
            "E1000: PCI {:04x}:{:04x} at {:?}",
            pci_dev.vendor_id,
            pci_dev.device_id,
            pci_dev.address
        );
        pci_dev.enable_bus_master();
        pci_dev.enable_memory_space();
        // Firmware may leave PCI interrupt disabled; clear bit 10.
        let mut cmd = pci_dev.read_config_u16(pci::config::COMMAND);
        cmd &= !pci::command::INTERRUPT_DISABLE;
        pci_dev.write_config_u16(pci::config::COMMAND, cmd);

        let mmio_phys = match pci_dev.read_bar(0).or_else(|| pci_dev.read_bar(1)) {
            Some(Bar::Memory32 { addr, .. }) => addr as u64,
            Some(Bar::Memory64 { addr, .. }) => addr,
            _ => {
                log::error!("E1000: no MMIO BAR (BAR0/BAR1)");
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
                "E1000: MMIO not mapped after ensure_identity_map_range phys={:#x} virt={:#x} mapped={:#x}; skipping device",
                mmio_phys,
                mmio_virt,
                mapped
            );
            continue;
        }

        // Some firmware leaves NIC in a stale power/reset state; retry once.
        let mut init_ok = None;
        for attempt in 0..2 {
            log::info!(
                "E1000: init attempt {} mmio_phys={:#x} mmio_virt={:#x}",
                attempt + 1,
                mmio_phys,
                mmio_virt
            );
            log::debug!("E1000: entering e1000::E1000Nic::init (reset, MAC, rings)…");
            match E1000Nic::init(mmio_virt, &KernelDma) {
                Ok(nic) => {
                    log::info!(
                        "E1000: core init ok on attempt {} (see trace=e1000::* for reset/EEPROM detail)",
                        attempt + 1
                    );
                    init_ok = Some(nic);
                    break;
                }
                Err(e) => {
                    log::warn!("E1000: core init attempt {} failed: {}", attempt + 1, e);
                    if attempt == 0 {
                        let mut cmd_retry = pci_dev.read_config_u16(pci::config::COMMAND);
                        cmd_retry |= pci::command::BUS_MASTER | pci::command::MEMORY_SPACE;
                        cmd_retry &= !pci::command::INTERRUPT_DISABLE;
                        pci_dev.write_config_u16(pci::config::COMMAND, cmd_retry);
                        continue;
                    }
                    log::error!("E1000: init failed: {}", e);
                }
            }
        }

        if let Some(nic) = init_ok {
            let mac = nic.mac_address();
            serial_println!("[E1000] Device initialized: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            let dev = Arc::new(KernelE1000 {
                mac,
                inner: SpinLock::new(nic),
            });
            register_device(dev);
            return;
        }
    }
    if found_intel_nic {
        serial_println!("[E1000] Intel NIC(s) found but no supported e1000 device initialized");
    }
    serial_println!("[E1000] no compatible device found");
}
