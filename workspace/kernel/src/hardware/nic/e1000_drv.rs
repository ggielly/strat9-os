//! Kernel adapter for the `e1000` crate (legacy 8254x family).
//!
//! Thin shim around the shared `KernelE1000Adapter`; only the device-ID
//! list and driver name differ from the e1000e variant.

use super::{
    common::{probe_e1000_pci, KernelDma, KernelE1000Adapter},
    register_device, set_nic_device,
};
use crate::{
    arch::{ioapic, msi},
    hardware::pci_client as pci,
    serial_println,
};
use e1000::E1000Nic;

const LEGACY_E1000_IDS: &[u16] = &[pci::intel_eth::E1000_82540EM, pci::intel_eth::E1000_82545EM];

pub fn init() {
    let Some(probe) = probe_e1000_pci(LEGACY_E1000_IDS) else {
        serial_println!("[E1000] no compatible device found");
        return;
    };

    log::info!(
        "E1000: PCI {:04x}:{:04x} at {:?}",
        probe.pci_dev.vendor_id,
        probe.pci_dev.device_id,
        probe.pci_dev.address
    );

    let mut init_ok = None;
    for attempt in 0..2 {
        log::info!(
            "E1000: init attempt {} mmio_phys={:#x} mmio_virt={:#x}",
            attempt + 1,
            probe.mmio_phys,
            probe.mmio_virt
        );
        match E1000Nic::init(probe.mmio_virt, &KernelDma) {
            Ok(nic) => {
                log::info!("E1000: core init ok on attempt {}", attempt + 1);
                init_ok = Some(nic);
                break;
            }
            Err(e) => {
                log::warn!("E1000: core init attempt {} failed: {}", attempt + 1, e);
                if attempt == 0 {
                    let mut cmd_retry = probe.pci_dev.read_config_u16(pci::config::COMMAND);
                    cmd_retry |= pci::command::BUS_MASTER | pci::command::MEMORY_SPACE;
                    cmd_retry &= !pci::command::INTERRUPT_DISABLE;
                    probe
                        .pci_dev
                        .write_config_u16(pci::config::COMMAND, cmd_retry);
                    continue;
                }
                log::error!("E1000: init failed: {}", e);
            }
        }
    }

    if let Some(nic) = init_ok {
        let mac = nic.mac_address();
        serial_println!(
            "[E1000] Device initialized: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5]
        );
        let dev = KernelE1000Adapter::new(nic, "e1000");
        let iface = register_device(dev.clone());

        // --- Wire up NIC interrupt: MSI → MSI-X → INTx fallback ---
        // Legacy E1000 (82540EM/82545EM) only support MSI, not MSI-X.
        // probe_and_enable tries MSI, falls back to INTx.
        let (irq, vector) = msi::probe_and_enable(&probe.pci_dev, false);

        if irq == 0 || irq == 0xFF {
            log::warn!(
                "[E1000] {}: no valid IRQ line, running in polling mode",
                iface
            );
        } else {
            // If MSI was enabled, INTx is disabled : skip IOAPIC routing.
            // Check whether MSI is active by reading the PCI command register.
            let cmd = probe.pci_dev.read_config_u16(pci::config::COMMAND);
            let msi_active = (cmd & pci::command::INTERRUPT_DISABLE) != 0;

            if !msi_active {
                // Fallback: route through I/O APIC (INTx).
                ioapic::route_nic_irq(irq, vector);
                log::info!("[E1000] {}: INTx IRQ {} → vector {:#x}", iface, irq, vector);
            } else {
                log::info!("[E1000] {}: MSI active on vector {:#x}", iface, vector);
            }

            crate::arch::idt::register_nic_irq(irq);
            set_nic_device(dev, irq);
        }
    }
}
