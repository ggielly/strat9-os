use alloc::{string::String, vec::Vec};
use crate::{BusChild, BusDriver, BusError, PowerState};

const MAX_MODULES: usize = 6;

const COMPATIBLE: &[&str] = &["cznic,moxtet"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoxtetModuleId {
    Sfp,
    Pci,
    Topaz,
    Peridot,
    Usb3,
    PcieBridge,
    Unknown(u8),
}

impl MoxtetModuleId {
    pub fn from_raw(raw: u8) -> Self {
        match raw & 0x0F {
            0x01 => MoxtetModuleId::Sfp,
            0x02 => MoxtetModuleId::Pci,
            0x03 => MoxtetModuleId::Topaz,
            0x04 => MoxtetModuleId::Peridot,
            0x05 => MoxtetModuleId::Usb3,
            0x06 => MoxtetModuleId::PcieBridge,
            other => MoxtetModuleId::Unknown(other),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            MoxtetModuleId::Sfp => "sfp",
            MoxtetModuleId::Pci => "pci",
            MoxtetModuleId::Topaz => "topaz",
            MoxtetModuleId::Peridot => "peridot",
            MoxtetModuleId::Usb3 => "usb3",
            MoxtetModuleId::PcieBridge => "pcie-bridge",
            MoxtetModuleId::Unknown(_) => "unknown",
        }
    }
}

pub struct MoxtetModule {
    pub id: MoxtetModuleId,
    pub index: u8,
}

pub struct Moxtet {
    modules: Vec<MoxtetModule>,
    module_count: usize,
    tx_buf: [u8; MAX_MODULES + 1],
    rx_buf: [u8; MAX_MODULES + 1],
    irq_mask: [bool; MAX_MODULES],
    power_state: PowerState,
}

impl Moxtet {
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
            module_count: 0,
            tx_buf: [0; MAX_MODULES + 1],
            rx_buf: [0; MAX_MODULES + 1],
            irq_mask: [false; MAX_MODULES],
            power_state: PowerState::Off,
        }
    }

    pub fn discover_topology(&mut self, spi_data: &[u8]) {
        self.modules.clear();
        self.module_count = 0;

        for (i, &byte) in spi_data.iter().enumerate().skip(1) {
            if i > MAX_MODULES { break; }
            let id = MoxtetModuleId::from_raw(byte);
            self.modules.push(MoxtetModule {
                id,
                index: (i - 1) as u8,
            });
            self.module_count = i;
        }
    }

    pub fn module_read(&self, index: usize) -> Result<u8, BusError> {
        if index >= self.module_count {
            return Err(BusError::DeviceNotFound);
        }
        Ok(self.rx_buf[index + 1])
    }

    pub fn module_write(&mut self, index: usize, value: u8) -> Result<(), BusError> {
        if index >= self.module_count {
            return Err(BusError::DeviceNotFound);
        }
        self.tx_buf[index + 1] = value;
        Ok(())
    }

    pub fn set_irq_mask(&mut self, index: usize, masked: bool) {
        if index < MAX_MODULES {
            self.irq_mask[index] = masked;
        }
    }
}

impl BusDriver for Moxtet {
    fn name(&self) -> &str { "moxtet" }

    fn compatible(&self) -> &[&str] { COMPATIBLE }

    fn init(&mut self, _base: usize) -> Result<(), BusError> {
        self.power_state = PowerState::On;
        Ok(())
    }

    fn shutdown(&mut self) -> Result<(), BusError> {
        self.power_state = PowerState::Off;
        Ok(())
    }

    fn read_reg(&self, offset: usize) -> Result<u32, BusError> {
        self.module_read(offset).map(|v| v as u32)
    }

    fn write_reg(&mut self, offset: usize, value: u32) -> Result<(), BusError> {
        self.module_write(offset, value as u8)
    }

    fn children(&self) -> Vec<BusChild> {
        self.modules.iter().map(|m| {
            BusChild {
                name: String::from(m.id.name()),
                base_addr: m.index as u64,
                size: 1,
            }
        }).collect()
    }

    fn handle_irq(&mut self) -> bool {
        for i in 0..self.module_count {
            if self.irq_mask[i] { continue; }
            let status = self.rx_buf[i + 1];
            if status & 0xF0 != 0 {
                return true;
            }
        }
        false
    }
}
