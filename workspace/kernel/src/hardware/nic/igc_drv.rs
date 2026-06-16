use super::{
    common::{probe_e1000_pci, KernelDma},
    register_device,
};
use crate::{hardware::pci_client as pci, sync::SpinLock};
use alloc::sync::Arc;
use e1000::E1000Nic;
use net_core::{NetError, NetworkDevice};

const IGC_IDS: &[u16] = &[
    pci::intel_eth::I225_LM,
    pci::intel_eth::I225_V,
    pci::intel_eth::I226_LM,
    pci::intel_eth::I226_V,
];

pub struct KernelIgc {
    inner: SpinLock<E1000Nic>,
    mac: [u8; 6],
}

impl NetworkDevice for KernelIgc {
    fn name(&self) -> &str {
        "igc"
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
        self.inner.lock().handle_interrupt();
    }
    fn poll(&self) {
        let mut nic = self.inner.lock();
        nic.watchdog_tick(&KernelDma);
    }
}

pub fn init() {
    let Some(probe) = probe_e1000_pci(IGC_IDS) else {
        return;
    };

    log::info!(
        "IGC: PCI {:04x}:{:04x} at {:?}",
        probe.pci_dev.vendor_id,
        probe.pci_dev.device_id,
        probe.pci_dev.address
    );

    let mut init_ok = None;
    for attempt in 0..3 {
        log::info!(
            "IGC: init attempt {} mmio_phys={:#x} mmio_virt={:#x}",
            attempt + 1,
            probe.mmio_phys,
            probe.mmio_virt
        );
        if let Ok(nic) = E1000Nic::init(probe.mmio_virt, &KernelDma) {
            log::info!("IGC: core init ok on attempt {}", attempt + 1);
            init_ok = Some(nic);
            break;
        }
        log::warn!("IGC: core init attempt {} failed", attempt + 1);
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
            let dev = Arc::new(KernelIgc {
                mac,
                inner: SpinLock::new(nic),
            });
            register_device(dev);
        }
        None => {
            log::warn!("IGC: core init failed (likely requires dedicated igc register path)");
        }
    }
}
