use alloc::{string::String, vec::Vec};
use crate::{BusChild, BusDriver, BusError, PowerState};
use crate::mmio::MmioRegion;

const CCI_PORT_CTRL: usize = 0x00;
const CCI_CTRL_STATUS: usize = 0x0C;

const CCI_ENABLE_SNOOP_REQ: u32 = 0x1;
const CCI_ENABLE_DVM_REQ: u32 = 0x2;
const CCI_ENABLE_REQ: u32 = CCI_ENABLE_SNOOP_REQ | CCI_ENABLE_DVM_REQ;

const PORT_VALID_SHIFT: u32 = 31;
const PORT_VALID: u32 = 1 << PORT_VALID_SHIFT;

const MAX_PORTS: usize = 5;
const MAX_POLL: u32 = 10000;

const COMPATIBLE: &[&str] = &[
    "arm,cci-400",
    "arm,cci-500",
    "arm,cci-550",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CciPortType {
    Ace,
    AceLite,
}

#[derive(Clone)]
pub struct CciPort {
    pub port_type: CciPortType,
    pub base_offset: usize,
    pub enabled: bool,
}

pub struct ArmCci {
    regs: MmioRegion,
    ports: [Option<CciPort>; MAX_PORTS],
    nb_ace: usize,
    nb_ace_lite: usize,
    power_state: PowerState,
}

impl ArmCci {
    /// Creates a new instance.
    pub fn new() -> Self {
        Self {
            regs: MmioRegion::new(),
            ports: [const { None }; MAX_PORTS],
            nb_ace: 0,
            nb_ace_lite: 0,
            power_state: PowerState::Off,
        }
    }

    /// Sets port counts.
    pub fn set_port_counts(&mut self, ace: usize, ace_lite: usize) {
        self.nb_ace = ace;
        self.nb_ace_lite = ace_lite;
    }

    /// Performs the add port operation.
    pub fn add_port(&mut self, index: usize, port_type: CciPortType, base_offset: usize) {
        if index < MAX_PORTS {
            self.ports[index] = Some(CciPort {
                port_type,
                base_offset,
                enabled: false,
            });
        }
    }

    /// Enables port.
    pub fn enable_port(&mut self, index: usize) -> Result<(), BusError> {
        if index >= MAX_PORTS {
            return Err(BusError::InvalidArgument);
        }
        let base_offset = self.ports[index]
            .as_ref()
            .ok_or(BusError::DeviceNotFound)?
            .base_offset;
        self.regs.write32(base_offset + CCI_PORT_CTRL, CCI_ENABLE_REQ);
        self.wait_for_status_clear()?;
        let port = self.ports[index].as_mut().ok_or(BusError::DeviceNotFound)?;
        port.enabled = true;
        Ok(())
    }

    /// Disables port.
    pub fn disable_port(&mut self, index: usize) -> Result<(), BusError> {
        if index >= MAX_PORTS {
            return Err(BusError::InvalidArgument);
        }
        let base_offset = self.ports[index]
            .as_ref()
            .ok_or(BusError::DeviceNotFound)?
            .base_offset;
        self.regs.write32(base_offset + CCI_PORT_CTRL, 0);
        self.wait_for_status_clear()?;
        let port = self.ports[index].as_mut().ok_or(BusError::DeviceNotFound)?;
        port.enabled = false;
        Ok(())
    }

    /// Performs the wait for status clear operation.
    fn wait_for_status_clear(&self) -> Result<(), BusError> {
        for _ in 0..MAX_POLL {
            let status = self.regs.read32(CCI_CTRL_STATUS);
            if status & 1 == 0 {
                return Ok(());
            }
        }
        Err(BusError::Timeout)
    }
}

impl BusDriver for ArmCci {
    /// Performs the name operation.
    fn name(&self) -> &str { "arm-cci" }

    /// Performs the compatible operation.
    fn compatible(&self) -> &[&str] { COMPATIBLE }

    /// Performs the init operation.
    fn init(&mut self, base: usize) -> Result<(), BusError> {
        self.regs.init(base, 0x10000);
        self.power_state = PowerState::On;
        Ok(())
    }

    /// Performs the shutdown operation.
    fn shutdown(&mut self) -> Result<(), BusError> {
        for i in 0..MAX_PORTS {
            if self.ports[i].as_ref().map_or(false, |p| p.enabled) {
                let _ = self.disable_port(i);
            }
        }
        self.power_state = PowerState::Off;
        Ok(())
    }

    /// Reads reg.
    fn read_reg(&self, offset: usize) -> Result<u32, BusError> {
        if !self.regs.is_valid() {
            return Err(BusError::InitFailed);
        }
        Ok(self.regs.read32(offset))
    }

    /// Writes reg.
    fn write_reg(&mut self, offset: usize, value: u32) -> Result<(), BusError> {
        if !self.regs.is_valid() {
            return Err(BusError::InitFailed);
        }
        self.regs.write32(offset, value);
        Ok(())
    }

    /// Performs the children operation.
    fn children(&self) -> Vec<BusChild> {
        let mut children = Vec::new();
        for (i, port) in self.ports.iter().enumerate() {
            if let Some(p) = port {
                let type_name = match p.port_type {
                    CciPortType::Ace => "ace",
                    CciPortType::AceLite => "ace-lite",
                };
                children.push(BusChild {
                    name: String::from(type_name),
                    base_addr: p.base_offset as u64,
                    size: 0x1000,
                });
            }
        }
        children
    }
}
