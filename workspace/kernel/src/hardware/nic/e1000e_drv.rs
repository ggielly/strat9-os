//! Kernel adapter for the `e1000` crate (e1000e / I217-I219 family).
//!
//! Thin shim around the shared `KernelE1000Adapter`; only the device-ID
//! list, retry count, and driver name differ from the legacy e1000 variant.

use super::{
    common::{probe_e1000_pci, KernelDma, KernelE1000Adapter},
    register_device, set_nic_device,
};
use crate::{
    arch::{ioapic, msi},
    hardware::pci_client as pci,
};
use e1000::E1000Nic;

const E1000E_IDS: &[u16] = &[
    pci::intel_eth::E1000E_82574L,
    pci::intel_eth::I217_LM,
    pci::intel_eth::I219_LM,
    pci::intel_eth::I219_V,
];

pub fn init() {
    let Some(probe) = probe_e1000_pci(E1000E_IDS) else {
        return;
    };

    log::info!(
        "E1000e: PCI {:04x}:{:04x} at {:?}",
        probe.pci_dev.vendor_id,
        probe.pci_dev.device_id,
        probe.pci_dev.address
    );

    let mut init_ok = None;
    for attempt in 0..3 {
        log::info!(
            "E1000e: init attempt {} mmio_phys={:#x} mmio_virt={:#x}",
            attempt + 1,
            probe.mmio_phys,
            probe.mmio_virt
        );
        if let Ok(nic) = E1000Nic::init(probe.mmio_virt, &KernelDma) {
            log::info!("E1000e: core init ok on attempt {}", attempt + 1);
            init_ok = Some(nic);
            break;
        }
        log::warn!("E1000e: core init attempt {} failed", attempt + 1);
        let mut cmd_retry = probe.pci_dev.read_config_u16(pci::config::COMMAND);
        cmd_retry |= pci::command::BUS_MASTER | pci::command::MEMORY_SPACE;
        cmd_retry &= !pci::command::INTERRUPT_DISABLE;
        probe
            .pci_dev
            .write_config_u16(pci::config::COMMAND, cmd_retry);
        core::hint::spin_loop();
    }

    match init_ok {
        Some(nic) => {
            let mac = nic.mac_address();
            log::info!(
                "E1000e: Device initialized: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0],
                mac[1],
                mac[2],
                mac[3],
                mac[4],
                mac[5]
            );
            let dev = KernelE1000Adapter::new(nic, "e1000e");
            let iface = register_device(dev.clone());

            // --- Wire up NIC interrupt: MSI-X → MSI → INTx fallback ---
            // e1000e supports both MSI and MSI-X; prefer MSI-X for future
            // multi-queue support.
            let (irq, vector) = msi::probe_and_enable(&probe.pci_dev, true);

            if irq == 0 || irq == 0xFF {
                log::warn!(
                    "[E1000e] {}: no valid IRQ line, running in polling mode",
                    iface
                );
            } else {
                let cmd = probe.pci_dev.read_config_u16(pci::config::COMMAND);
                let msi_active = (cmd & pci::command::INTERRUPT_DISABLE) != 0;

                if !msi_active {
                    ioapic::route_nic_irq(irq, vector);
                    log::info!(
                        "[E1000e] {}: INTx IRQ {} → vector {:#x}",
                        iface,
                        irq,
                        vector
                    );
                } else {
                    log::info!(
                        "[E1000e] {}: MSI/MSI-X active on vector {:#x}",
                        iface,
                        vector
                    );
                }

                crate::arch::idt::register_nic_irq(irq);
                set_nic_device(dev, irq);
            }
        }
        None => {
            log::error!("E1000e: init failed");
        }
    }
}
